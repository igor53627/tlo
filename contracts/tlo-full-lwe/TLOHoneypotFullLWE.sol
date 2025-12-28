// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/*****************************************************************************
 *                                                                           *
 *  TLO-FullLWE: True LWE-based Compute-and-Compare on-chain                 *
 *                                                                           *
 *  TRUE C&C security: evaluator computes <a, s> on-chain, s derived from    *
 *  input. Control function bits are computationally hidden.                 *
 *                                                                           *
 *  KEY PROPERTIES:                                                          *
 *  +-----------------+--------------------------------------------------+   *
 *  | Public Eval     | Anyone can call check(input) - NO secret key     |   *
 *  | True C&C        | CF bits hidden behind LWE assumption             |   *
 *  | Storage         | SSTORE2 for ~640KB circuit data                  |   *
 *  | Gas             | ~2M for 640 gates (inner products on-chain)      |   *
 *  +-----------------+--------------------------------------------------+   *
 *                                                                           *
 *  HOW TRUE C&C WORKS:                                                      *
 *  - Store full LWE ciphertext (a vector + b scalar) per truth table entry  *
 *  - Secret s is derived from input: s = keccak256(input)[0:n]              *
 *  - On-chain: compute <a, s> mod q, then extract bit from b - <a,s>        *
 *  - Without knowing s, CF bits are computationally hidden (LWE assumption) *
 *                                                                           *
 *  STORAGE FORMAT (per gate, n=32):                                         *
 *  - 3 bytes: pins (active, c1, c2)                                         *
 *  - 4 * (n * 2 + 2) bytes: 4 LWE ciphertexts (a: n*2 bytes, b: 2 bytes)    *
 *  - Total: 3 + 4 * (32*2 + 2) = 3 + 4 * 66 = 267 bytes per gate           *
 *  - 640 gates = 170,880 bytes (~167KB)                                     *
 *                                                                           *
 *  SECURITY:                                                                *
 *  - LWE dimension n=32 provides ~64-bit security (sufficient for honeypot) *
 *  - Combined with SixSix topology for structural attack resistance         *
 *  - True C&C: attacker cannot extract CF without solving LWE               *
 *                                                                           *
 *****************************************************************************/

/// @title TLOHoneypotFullLWE - True C&C with on-chain LWE evaluation
/// @notice Full LWE inner product computed on-chain for true CF hiding
/// @dev Uses SSTORE2 for large circuit data, ~2M gas for 640 gates
contract TLOHoneypotFullLWE is IHoneypot {
    /// @notice Minimum blocks between commit and reveal
    uint256 public constant COMMIT_DELAY = 2;
    
    /// @notice LWE modulus q (16-bit for gas efficiency)
    uint16 public constant Q = 65521;  // Largest 16-bit prime
    
    /// @notice LWE dimension n
    uint8 public constant LWE_N = 32;
    
    /// @notice Threshold for bit extraction (q/4)
    uint16 public constant THRESHOLD = Q / 4;
    
    /// @notice SSTORE2 pointer to circuit data
    address public immutable circuitDataPointer;
    
    /// @notice Number of wires in the circuit
    uint8 public immutable numWires;
    
    /// @notice Number of gates in the circuit
    uint32 public immutable numGates;
    
    /// @notice Expected output hash
    bytes32 public immutable expectedOutputHash;
    
    /// @notice Secret expiry timestamp
    uint256 public immutable secretExpiry;
    
    /// @notice The reward amount in wei
    uint256 private _reward;
    
    /// @notice Whether the honeypot has been claimed
    bool private _claimed;
    
    /// @notice Owner (for expiry reclaim)
    address public immutable owner;
    
    /// @notice Commitment storage
    struct Commitment {
        bytes32 hash;
        uint256 blockNumber;
    }
    mapping(address => Commitment) private _commits;
    
    /// @notice Bytes per LWE ciphertext: n * 2 (a vector) + 2 (b scalar)
    uint256 private constant CT_SIZE = LWE_N * 2 + 2;  // 66 bytes
    
    /// @notice Bytes per gate: 3 pins + 4 ciphertexts
    uint256 private constant GATE_SIZE = 3 + 4 * CT_SIZE;  // 267 bytes
    
    /// @notice Deploy with full LWE circuit data
    /// @param _circuitData The full LWE encoded circuit (267 bytes per gate)
    /// @param _numWires Number of wires (must be <= 64)
    /// @param _numGates Number of gates in the circuit
    /// @param _expectedOutputHash Hash of expected output
    /// @param _secretExpiry Timestamp after which secret expires
    constructor(
        bytes memory _circuitData,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        uint256 _secretExpiry
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitData.length == _numGates * GATE_SIZE, "Invalid circuit data length");
        require(_secretExpiry > block.timestamp, "Expiry must be in future");
        
        // Store circuit data via SSTORE2 (gas-efficient for large data)
        circuitDataPointer = SSTORE2.write(_circuitData);
        
        numWires = _numWires;
        numGates = _numGates;
        expectedOutputHash = _expectedOutputHash;
        secretExpiry = _secretExpiry;
        owner = msg.sender;
        _reward = msg.value;
    }
    
    /// @inheritdoc IHoneypot
    function commit(bytes32 commitHash) external override {
        require(block.timestamp < secretExpiry, "Secret expired");
        _commits[msg.sender] = Commitment({
            hash: commitHash,
            blockNumber: block.number
        });
        emit Committed(msg.sender, commitHash, block.number);
    }
    
    /// @inheritdoc IHoneypot
    function reveal(bytes32 input) external override {
        require(!_claimed, "Already claimed");
        require(block.timestamp < secretExpiry, "Secret expired");
        
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        
        bytes32 expectedHash = keccak256(abi.encode(msg.sender, input));
        require(expectedHash == c.hash, "Invalid reveal");
        
        require(_evaluateFullLWE(input), "Invalid input");
        
        _claimed = true;
        delete _commits[msg.sender];
        
        uint256 rewardAmount = _reward;
        _reward = 0;
        
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        
        emit Claimed(msg.sender, c.hash, rewardAmount);
    }
    
    /// @inheritdoc IHoneypot
    function check(bytes32 input) external view override returns (bool) {
        return _evaluateFullLWE(input);
    }
    
    /// @notice Reclaim reward after secret expires (owner only)
    function reclaimExpired() external {
        require(msg.sender == owner, "Only owner");
        require(block.timestamp >= secretExpiry, "Not expired yet");
        require(!_claimed, "Already claimed");
        
        _claimed = true;
        uint256 rewardAmount = _reward;
        _reward = 0;
        
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
    }
    
    /// @inheritdoc IHoneypot
    function getCommit(address committer) external view override returns (bytes32, uint256) {
        Commitment memory c = _commits[committer];
        return (c.hash, c.blockNumber);
    }
    
    /// @inheritdoc IHoneypot
    function commitDelay() external pure override returns (uint256) {
        return COMMIT_DELAY;
    }
    
    /// @inheritdoc IHoneypot
    function reward() external view override returns (uint256) {
        return _reward;
    }
    
    /// @inheritdoc IHoneypot
    function scheme() external pure override returns (string memory) {
        return "tlo-full-lwe";
    }
    
    /// @inheritdoc IHoneypot
    function encryptedGates() external pure override returns (uint256) {
        return 640;  // SixSix default
    }
    
    /// @inheritdoc IHoneypot
    function estimatedGas() external pure override returns (uint256) {
        return 2_000_000;  // ~2M for 640 gates with inner products
    }
    
    /// @notice Check if secret has expired
    function isExpired() external view returns (bool) {
        return block.timestamp >= secretExpiry;
    }
    
    /// @notice Time remaining until expiry
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    /// @notice Derive LWE secret vector from input
    /// @dev s = keccak256(input) expanded to n elements mod q
    function _deriveSecret(bytes32 input) internal pure returns (uint16[LWE_N] memory s) {
        bytes32 h = input;
        uint256 idx = 0;
        while (idx < LWE_N) {
            h = keccak256(abi.encodePacked(h, idx));
            // Extract up to 16 elements from each hash (2 bytes each)
            for (uint256 i = 0; i < 16 && idx < LWE_N; i++) {
                s[idx] = uint16(uint256(h) >> (i * 16)) % Q;
                idx++;
            }
        }
    }
    
    /// @notice Evaluate the full LWE circuit
    /// @param input The candidate input
    /// @return True if input matches the embedded secret
    function _evaluateFullLWE(bytes32 input) internal view returns (bool) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        
        // Read circuit data from SSTORE2
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        // Derive secret vector from input
        uint16[LWE_N] memory s = _deriveSecret(input);
        
        // Process each gate
        uint256 offset = 0;
        uint256 gateCount = numGates;
        
        for (uint256 g = 0; g < gateCount; g++) {
            // Read pins (3 bytes)
            uint8 active = uint8(cd[offset]) & 0x3F;
            uint8 c1pin = uint8(cd[offset + 1]) & 0x3F;
            uint8 c2pin = uint8(cd[offset + 2]) & 0x3F;
            offset += 3;
            
            // Get wire values
            uint256 c1Val = (wires >> c1pin) & 1;
            uint256 c2Val = (wires >> c2pin) & 1;
            
            // Calculate truth table index
            uint256 ttIdx = c1Val | (c2Val << 1);
            
            // Skip to correct ciphertext
            uint256 ctOffset = offset + ttIdx * CT_SIZE;
            
            // Compute inner product <a, s> mod q
            uint256 innerProd = 0;
            for (uint256 i = 0; i < LWE_N; i++) {
                uint16 ai = uint16(uint8(cd[ctOffset + i * 2])) << 8 | 
                            uint16(uint8(cd[ctOffset + i * 2 + 1]));
                innerProd = (innerProd + uint256(ai) * uint256(s[i])) % Q;
            }
            
            // Read b value
            uint16 b = uint16(uint8(cd[ctOffset + LWE_N * 2])) << 8 |
                       uint16(uint8(cd[ctOffset + LWE_N * 2 + 1]));
            
            // Compute diff = (b - <a,s>) mod q
            uint256 diff = (uint256(b) + Q - innerProd) % Q;
            
            // Extract bit: (diff > threshold) && (diff < 3*threshold)
            bool cfBit = diff > THRESHOLD && diff < 3 * THRESHOLD;
            
            // XOR active wire if cfBit is true
            if (cfBit) {
                wires ^= (1 << active);
            }
            
            // Move to next gate
            offset += 4 * CT_SIZE;
        }
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        return outputHash == expectedOutputHash;
    }
    
    /// @notice Allow receiving ETH to add to reward
    receive() external payable {
        _reward += msg.value;
    }
}
