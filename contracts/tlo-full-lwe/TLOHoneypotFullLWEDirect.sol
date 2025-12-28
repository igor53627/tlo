// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOHoneypotFullLWEDirect - Accepts pre-deployed SSTORE2 pointer
/// @notice Same as TLOHoneypotFullLWEOpt but takes SSTORE2 address directly
/// @dev Avoids initcode size limit by pre-deploying circuit data
contract TLOHoneypotFullLWEDirect is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LWE_N = 16;
    uint256 public constant THRESHOLD = Q / 4;
    
    address public immutable circuitDataPointer;
    uint8 public immutable numWires;
    uint32 public immutable numGates;
    bytes32 public immutable expectedOutputHash;
    uint256 public immutable secretExpiry;
    
    uint256 private _reward;
    bool private _claimed;
    address public immutable owner;
    
    struct Commitment { bytes32 hash; uint256 blockNumber; }
    mapping(address => Commitment) private _commits;
    
    uint256 private constant CT_SIZE = LWE_N * 2 + 2;
    uint256 private constant GATE_SIZE = 3 + 4 * CT_SIZE;
    
    /// @notice Deploy with pre-deployed SSTORE2 pointer
    /// @param _circuitDataPointer Address of SSTORE2-deployed circuit data
    constructor(
        address _circuitDataPointer,
        uint8 _numWires,
        uint32 _numGates,
        bytes32 _expectedOutputHash,
        uint256 _secretExpiry
    ) payable {
        require(_numWires > 0 && _numWires <= 64, "Wires must be 1-64");
        require(_numGates > 0, "Must have gates");
        require(_circuitDataPointer != address(0), "Invalid pointer");
        require(_secretExpiry > block.timestamp, "Expiry must be in future");
        
        circuitDataPointer = _circuitDataPointer;
        numWires = _numWires;
        numGates = _numGates;
        expectedOutputHash = _expectedOutputHash;
        secretExpiry = _secretExpiry;
        owner = msg.sender;
        _reward = msg.value;
    }
    
    function commit(bytes32 commitHash) external override {
        require(block.timestamp < secretExpiry, "Secret expired");
        _commits[msg.sender] = Commitment({hash: commitHash, blockNumber: block.number});
        emit Committed(msg.sender, commitHash, block.number);
    }
    
    function reveal(bytes32 input) external override {
        require(!_claimed, "Already claimed");
        require(block.timestamp < secretExpiry, "Secret expired");
        
        Commitment memory c = _commits[msg.sender];
        require(c.blockNumber > 0, "No commit found");
        require(block.number >= c.blockNumber + COMMIT_DELAY, "Reveal too early");
        require(keccak256(abi.encode(msg.sender, input)) == c.hash, "Invalid reveal");
        require(_evaluateOptimized(input), "Invalid input");
        
        _claimed = true;
        delete _commits[msg.sender];
        
        uint256 rewardAmount = _reward;
        _reward = 0;
        
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        
        emit Claimed(msg.sender, c.hash, rewardAmount);
    }
    
    function check(bytes32 input) external view override returns (bool) {
        return _evaluateOptimized(input);
    }
    
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
    
    function getCommit(address committer) external view override returns (bytes32, uint256) {
        Commitment memory c = _commits[committer];
        return (c.hash, c.blockNumber);
    }
    
    function commitDelay() external pure override returns (uint256) { return COMMIT_DELAY; }
    function reward() external view override returns (uint256) { return _reward; }
    function scheme() external pure override returns (string memory) { return "tlo-full-lwe-direct"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 750_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    function _evaluateOptimized(bytes32 input) internal view returns (bool) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        uint256 secret = _deriveSecretPacked(input);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        
        assembly {
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, mul(gateCount, 139))
            
            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 139) } {
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)
                
                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                let ttIdx := or(c1Val, shl(1, c2Val))
                
                let ctPtr := add(dataPtr, add(3, mul(ttIdx, 34)))
                let aVec := mload(ctPtr)
                let bWord := mload(add(ctPtr, 32))
                let b := and(shr(240, bWord), 0xFFFF)
                
                let innerProd := 0
                innerProd := mod(add(innerProd, mul(and(shr(240, aVec), 0xFFFF), and(shr(240, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, aVec), 0xFFFF), and(shr(224, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, aVec), 0xFFFF), and(shr(208, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, aVec), 0xFFFF), and(shr(192, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, aVec), 0xFFFF), and(shr(176, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, aVec), 0xFFFF), and(shr(160, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, aVec), 0xFFFF), and(shr(144, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, aVec), 0xFFFF), and(shr(128, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, aVec), 0xFFFF), and(shr(112, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, aVec), 0xFFFF), and(shr(96, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, aVec), 0xFFFF), and(shr(80, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, aVec), 0xFFFF), and(shr(64, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, aVec), 0xFFFF), and(shr(48, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, aVec), 0xFFFF), and(shr(32, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, aVec), 0xFFFF), and(shr(16, secret), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(aVec, 0xFFFF), and(secret, 0xFFFF))), q)
                
                let diff := mod(add(sub(b, innerProd), q), q)
                let cfBit := and(gt(diff, threshold), lt(diff, mul(3, threshold)))
                
                let newVal := xor(and(shr(active, wires), 1), cfBit)
                let bitMask := shl(active, 1)
                wires := or(and(wires, not(bitMask)), mul(newVal, bitMask))
            }
        }
        
        bytes32 outputHash = keccak256(abi.encodePacked(wires));
        return outputHash == expectedOutputHash;
    }
    
    function _deriveSecretPacked(bytes32 input) internal pure returns (uint256) {
        bytes32 h = keccak256(abi.encodePacked(input, uint256(0)));
        uint256 packed = 0;
        uint256 q = Q;
        
        assembly {
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let shift := mul(sub(15, i), 16)
                let val := and(shr(shift, h), 0xFFFF)
                val := mod(val, q)
                packed := or(packed, shl(shift, val))
            }
        }
        
        return packed;
    }
    
    receive() external payable { _reward += msg.value; }
}
