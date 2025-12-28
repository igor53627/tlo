// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOHoneypotFullLWE32 - n=32 LWE dimension (~64-bit security)
contract TLOHoneypotFullLWE32 is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LWE_N = 32;
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
    
    // n=32: CT_SIZE = 32*2 + 2 = 66 bytes, GATE_SIZE = 3 + 4*66 = 267 bytes
    uint256 private constant CT_SIZE = 66;
    uint256 private constant GATE_SIZE = 267;
    
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
        require(_evaluate(input), "Invalid input");
        _claimed = true;
        delete _commits[msg.sender];
        uint256 rewardAmount = _reward;
        _reward = 0;
        (bool success, ) = msg.sender.call{value: rewardAmount}("");
        require(success, "Transfer failed");
        emit Claimed(msg.sender, c.hash, rewardAmount);
    }
    
    function check(bytes32 input) external view override returns (bool) {
        return _evaluate(input);
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
    function scheme() external pure override returns (string memory) { return "tlo-full-lwe-32"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 1_500_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    function _evaluate(bytes32 input) internal view returns (bool) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        // Derive two 256-bit secrets for n=32 (32 x u16 = 512 bits = 2 x 256)
        (uint256 secret0, uint256 secret1) = _deriveSecret32(input);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        
        assembly {
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, mul(gateCount, 267))
            
            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 267) } {
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)
                
                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                let ttIdx := or(c1Val, shl(1, c2Val))
                
                // CT offset: 3 + ttIdx * 66
                let ctPtr := add(dataPtr, add(3, mul(ttIdx, 66)))
                
                // Read a vector: 64 bytes = 2 mloads
                let aVec0 := mload(ctPtr)
                let aVec1 := mload(add(ctPtr, 32))
                let bWord := mload(add(ctPtr, 64))
                let b := and(shr(240, bWord), 0xFFFF)
                
                // Inner product: 32 terms
                let innerProd := 0
                
                // First 16 terms (aVec0 x secret0)
                innerProd := mod(add(innerProd, mul(and(shr(240, aVec0), 0xFFFF), and(shr(240, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, aVec0), 0xFFFF), and(shr(224, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, aVec0), 0xFFFF), and(shr(208, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, aVec0), 0xFFFF), and(shr(192, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, aVec0), 0xFFFF), and(shr(176, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, aVec0), 0xFFFF), and(shr(160, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, aVec0), 0xFFFF), and(shr(144, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, aVec0), 0xFFFF), and(shr(128, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, aVec0), 0xFFFF), and(shr(112, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, aVec0), 0xFFFF), and(shr(96, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, aVec0), 0xFFFF), and(shr(80, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, aVec0), 0xFFFF), and(shr(64, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, aVec0), 0xFFFF), and(shr(48, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, aVec0), 0xFFFF), and(shr(32, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, aVec0), 0xFFFF), and(shr(16, secret0), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(aVec0, 0xFFFF), and(secret0, 0xFFFF))), q)
                
                // Next 16 terms (aVec1 x secret1)
                innerProd := mod(add(innerProd, mul(and(shr(240, aVec1), 0xFFFF), and(shr(240, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(224, aVec1), 0xFFFF), and(shr(224, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(208, aVec1), 0xFFFF), and(shr(208, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(192, aVec1), 0xFFFF), and(shr(192, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(176, aVec1), 0xFFFF), and(shr(176, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(160, aVec1), 0xFFFF), and(shr(160, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(144, aVec1), 0xFFFF), and(shr(144, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(128, aVec1), 0xFFFF), and(shr(128, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(112, aVec1), 0xFFFF), and(shr(112, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(96, aVec1), 0xFFFF), and(shr(96, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(80, aVec1), 0xFFFF), and(shr(80, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(64, aVec1), 0xFFFF), and(shr(64, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(48, aVec1), 0xFFFF), and(shr(48, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(32, aVec1), 0xFFFF), and(shr(32, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(shr(16, aVec1), 0xFFFF), and(shr(16, secret1), 0xFFFF))), q)
                innerProd := mod(add(innerProd, mul(and(aVec1, 0xFFFF), and(secret1, 0xFFFF))), q)
                
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
    
    function _deriveSecret32(bytes32 input) internal pure returns (uint256 s0, uint256 s1) {
        bytes32 h0 = keccak256(abi.encodePacked(input, uint256(0)));
        bytes32 h1 = keccak256(abi.encodePacked(input, uint256(1)));
        uint256 q = Q;
        
        assembly {
            // Pack h0 -> s0 (16 u16 values mod q)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let shift := mul(sub(15, i), 16)
                let val := mod(and(shr(shift, h0), 0xFFFF), q)
                s0 := or(s0, shl(shift, val))
            }
            // Pack h1 -> s1 (16 u16 values mod q)
            for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                let shift := mul(sub(15, i), 16)
                let val := mod(and(shr(shift, h1), 0xFFFF), q)
                s1 := or(s1, shl(shift, val))
            }
        }
    }
    
    receive() external payable { _reward += msg.value; }
}
