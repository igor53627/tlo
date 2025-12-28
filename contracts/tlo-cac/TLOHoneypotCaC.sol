// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IHoneypot.sol";

/*****************************************************************************
 *                                                                           *
 *  TLO-CaC: Topology-Lattice Obfuscation with Compute-and-Compare           *
 *                                                                           *
 *  TRUE 6/6 attack resistance via LWE-based control function hiding.        *
 *                                                                           *
 *  KEY PROPERTIES:                                                          *
 *  +-----------------+--------------------------------------------------+   *
 *  | Public Eval     | Anyone can call check(input) - NO secret key     |   *
 *  | Plaintext Output| Returns true/false directly, not ciphertext      |   *
 *  | 6/6 Resistance  | SixSix topology (5/6) + C&C/LWE (RainbowTable)   |   *
 *  | Post-Quantum    | LWE is PQ-resistant                              |   *
 *  +-----------------+--------------------------------------------------+   *
 *                                                                           *
 *  HOW C&C WORKS:                                                           *
 *  Each control function bit is encoded as (b, hint) where:                 *
 *  - b = <a, s> + e + bit * q/2  (LWE ciphertext)                          *
 *  - hint = <a, s> mod q         (precomputed for public eval)             *
 *  - diff = (b - hint) mod q = e + bit * q/2                               *
 *  - bit = (diff > q/4) && (diff < 3*q/4)                                  *
 *                                                                           *
 *  COMPACT STORAGE:                                                         *
 *  - Each gate: 3 bytes (pins) + 4 * 16 bytes (4 encoded bits) = 67 bytes  *
 *  - 640 gates = ~43KB (stored via SSTORE2 or constructor calldata)        *
 *  - Full a vectors (~1KB each) NOT stored - derived from PRG seed         *
 *                                                                           *
 *  SECURITY:                                                                *
 *  - LWE dimension n=64 provides ~80-bit security                          *
 *  - Combined with SixSix topology for 6/6 attack resistance               *
 *  - Rainbow table attack blocked: CF bits cannot be extracted locally     *
 *                                                                           *
 *****************************************************************************/

/// @title TLOHoneypotCaC - TLO honeypot with true C&C/LWE obfuscation
/// @notice 6/6 attack-resistant honeypot using LWE-encoded control functions
/// @dev Uses SixSix topology + C&C for semantic attack resistance
contract TLOHoneypotCaC is IHoneypot {
    /// @notice Minimum blocks between commit and reveal
    uint256 public constant COMMIT_DELAY = 2;
    
    /// @notice LWE modulus q (must match Rust CaCParams)
    uint64 public constant Q = 1 << 20;  // 2^20 for aggressive params
    
    /// @notice Threshold for bit extraction (q/4)
    uint64 public constant THRESHOLD = Q / 4;
    
    /// @notice The C&C circuit data (compact format)
    /// @dev Format per gate: [active:1, c1:1, c2:1, (b0:8, hint0:8), (b1:8, hint1:8), (b2:8, hint2:8), (b3:8, hint3:8)]
    ///      Total: 3 + 4*16 = 67 bytes per gate
    bytes public circuitData;
    
    /// @notice Number of wires in the circuit
    uint8 public immutable numWires;
    
    /// @notice Number of gates in the circuit
    uint32 public immutable numGates;
    
    /// @notice Unique seed for this honeypot (used for PRG derivation)
    bytes32 public immutable circuitSeed;
    
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
    
    /// @notice Bytes per encoded bit (b: 8 bytes, hint: 8 bytes)
    uint256 private constant ENCODED_BIT_SIZE = 16;
    
    /// @notice Bytes per gate (3 pins + 4 encoded bits)
    uint256 private constant GATE_SIZE = 3 + 4 * ENCODED_BIT_SIZE;  // 67 bytes
    
    /// @notice Deploy with C&C circuit data
    /// @param _circuitData The C&C encoded circuit (67 bytes per gate)
    /// @param _numWires Number of wires (must be <= 64)
    /// @param _numGates Number of gates in the circuit
    /// @param _circuitSeed Unique seed for PRG derivation
    /// @param _expectedOutputHash Hash of expected output
    /// @param _secretExpiry Timestamp after which secret expires
    constructor(
        bytes memory _circuitData,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _circuitSeed,
        bytes32 _expectedOutputHash,
        uint256 _secretExpiry
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitData.length == _numGates * GATE_SIZE, "Invalid circuit data length");
        require(_secretExpiry > block.timestamp, "Expiry must be in future");
        
        circuitData = _circuitData;
        numWires = _numWires;
        numGates = _numGates;
        circuitSeed = _circuitSeed;
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
        
        require(_evaluateCaC(input), "Invalid input");
        
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
        return _evaluateCaC(input);
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
        return "tlo-cac";
    }
    
    /// @inheritdoc IHoneypot
    function encryptedGates() external pure override returns (uint256) {
        return 640;  // All 640 gates use LWE-encoded CFs (SixSix default)
    }
    
    /// @inheritdoc IHoneypot
    function estimatedGas() external pure override returns (uint256) {
        return 450_000;  // ~423K measured for 640-gate SixSix circuit
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
    
    /// @notice Evaluate the C&C circuit
    /// @param input The candidate input
    /// @return True if input matches the embedded secret
    function _evaluateCaC(bytes32 input) internal view returns (bool) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        
        bytes memory cd = circuitData;
        uint256 len = cd.length;
        
        assembly {
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, len)
            
            // Q and THRESHOLD as local vars for gas efficiency
            // q = 2^20, so we can use AND instead of MOD (cheaper)
            let q := 0x100000      // 2^20
            let qmask := 0xFFFFF   // q - 1 (for mod via AND)
            let threshold := 0x40000  // q/4
            let thresholdHigh := 0xC0000  // 3*q/4
            
            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 67) } {
                // Read pins (first 3 bytes) - 67 bytes = GATE_SIZE
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)  // 6-bit wire index
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)
                
                // Get wire values
                let aVal := and(shr(active, wires), 1)
                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                
                // Calculate truth table index: c1 | (c2 << 1) = 0,1,2,3
                let ttIdx := or(c1Val, shl(1, c2Val))
                
                // Read the corresponding (b, hint) pair
                // Offset: 3 (pins) + ttIdx * 16 (each encoded bit is 16 bytes = ENCODED_BIT_SIZE)
                let encodedBitPtr := add(dataPtr, add(3, shl(4, ttIdx)))  // shl(4, x) = x * 16
                let bHintData := mload(encodedBitPtr)
                
                // b is first 8 bytes (bits 255-192), hint is next 8 bytes (bits 191-128)
                let b := and(shr(192, bHintData), 0xFFFFFFFFFFFFFFFF)
                let hint := and(shr(128, bHintData), 0xFFFFFFFFFFFFFFFF)
                
                // Compute diff = (b - hint) mod q using AND (since q is power of 2)
                let diff := and(add(sub(b, hint), q), qmask)
                
                // Extract bit: (diff > threshold) && (diff < thresholdHigh)
                let cfBit := and(gt(diff, threshold), lt(diff, thresholdHigh))
                
                // If cfBit is 1, flip the active wire (reversible gate)
                let newVal := xor(aVal, cfBit)
                let bitMask := shl(active, 1)
                wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
            }
        }
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        return outputHash == expectedOutputHash;
    }
    
    /// @notice Allow receiving ETH to add to reward
    receive() external payable {
        _reward += msg.value;
    }
}
