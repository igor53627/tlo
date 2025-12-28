// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../interfaces/IHoneypot.sol";
import {SSTORE2} from "solmate/utils/SSTORE2.sol";

/// @title TLOHoneypotFullLWE128 - n=128 LWE dimension (~81-bit security)
/// @notice Uses memory-based inner product to avoid EVM stack depth limits
contract TLOHoneypotFullLWE128 is IHoneypot {
    uint256 public constant COMMIT_DELAY = 2;
    uint256 public constant Q = 65521;
    uint256 public constant LWE_N = 128;
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
    
    // n=128: CT_SIZE = 128*2 + 2 = 258 bytes, GATE_SIZE = 3 + 4*258 = 1035 bytes
    uint256 private constant CT_SIZE = 258;
    uint256 private constant GATE_SIZE = 1035;
    
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
    function scheme() external pure override returns (string memory) { return "tlo-full-lwe-128"; }
    function encryptedGates() external pure override returns (uint256) { return 640; }
    function estimatedGas() external pure override returns (uint256) { return 5_100_000; }
    function isExpired() external view returns (bool) { return block.timestamp >= secretExpiry; }
    function timeRemaining() external view returns (uint256) {
        if (block.timestamp >= secretExpiry) return 0;
        return secretExpiry - block.timestamp;
    }
    
    function _evaluate(bytes32 input) internal view returns (bool) {
        uint256 wires = uint256(input) & ((1 << numWires) - 1);
        bytes memory cd = SSTORE2.read(circuitDataPointer);
        
        // Memory layout (using scratch space above free memory pointer):
        // We allocate 0x300 bytes starting at free memory pointer
        // [fmp+0x00 - fmp+0x100): 8 secret vectors (s0-s7)
        // [fmp+0x100 - fmp+0x200): 8 a vectors (a0-a7) - written per gate
        // [fmp+0x200 - fmp+0x220): innerProd accumulator
        uint256 scratchBase;
        assembly { scratchBase := mload(0x40) }
        _deriveSecret128ToMemory(input, scratchBase);
        
        uint256 gateCount = numGates;
        uint256 q = Q;
        uint256 threshold = THRESHOLD;
        
        assembly ("memory-safe") {
            let dataPtr := add(cd, 32)
            let endPtr := add(dataPtr, mul(gateCount, 1035))
            
            for { } lt(dataPtr, endPtr) { dataPtr := add(dataPtr, 1035) } {
                let gateData := mload(dataPtr)
                let active := and(shr(248, gateData), 0x3F)
                let c1 := and(shr(240, gateData), 0x3F)
                let c2 := and(shr(232, gateData), 0x3F)
                
                let c1Val := and(shr(c1, wires), 1)
                let c2Val := and(shr(c2, wires), 1)
                let ttIdx := or(c1Val, shl(1, c2Val))
                
                // CT offset: 3 + ttIdx * 258
                let ctPtr := add(dataPtr, add(3, mul(ttIdx, 258)))
                
                // Store a-vectors at scratchBase+0x100
                let aBase := add(scratchBase, 0x100)
                mstore(aBase, mload(ctPtr))
                mstore(add(aBase, 0x20), mload(add(ctPtr, 32)))
                mstore(add(aBase, 0x40), mload(add(ctPtr, 64)))
                mstore(add(aBase, 0x60), mload(add(ctPtr, 96)))
                mstore(add(aBase, 0x80), mload(add(ctPtr, 128)))
                mstore(add(aBase, 0xa0), mload(add(ctPtr, 160)))
                mstore(add(aBase, 0xc0), mload(add(ctPtr, 192)))
                mstore(add(aBase, 0xe0), mload(add(ctPtr, 224)))
                
                // Read b value
                let bWord := mload(add(ctPtr, 256))
                let b := and(shr(240, bWord), 0xFFFF)
                
                // Initialize accumulator at scratchBase+0x200
                let accPtr := add(scratchBase, 0x200)
                mstore(accPtr, 0)
                
                // Process 8 chunks, each adds 16 terms to innerProd
                // Use a loop to avoid stack depth issues
                for { let chunk := 0 } lt(chunk, 8) { chunk := add(chunk, 1) } {
                    let sPtr := add(scratchBase, mul(chunk, 0x20))
                    let aPtr := add(aBase, mul(chunk, 0x20))
                    
                    let s := mload(sPtr)
                    let a := mload(aPtr)
                    let acc := mload(accPtr)
                    
                    // 16 terms for this chunk
                    acc := mod(add(acc, mul(and(shr(240, a), 0xFFFF), and(shr(240, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(224, a), 0xFFFF), and(shr(224, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(208, a), 0xFFFF), and(shr(208, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(192, a), 0xFFFF), and(shr(192, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(176, a), 0xFFFF), and(shr(176, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(160, a), 0xFFFF), and(shr(160, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(144, a), 0xFFFF), and(shr(144, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(128, a), 0xFFFF), and(shr(128, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(112, a), 0xFFFF), and(shr(112, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(96, a), 0xFFFF), and(shr(96, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(80, a), 0xFFFF), and(shr(80, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(64, a), 0xFFFF), and(shr(64, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(48, a), 0xFFFF), and(shr(48, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(32, a), 0xFFFF), and(shr(32, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(shr(16, a), 0xFFFF), and(shr(16, s), 0xFFFF))), q)
                    acc := mod(add(acc, mul(and(a, 0xFFFF), and(s, 0xFFFF))), q)
                    
                    mstore(accPtr, acc)
                }
                
                let innerProd := mload(accPtr)
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
    
    function _deriveSecret128ToMemory(bytes32 input, uint256 scratchBase) internal pure {
        bytes32[8] memory hashes;
        hashes[0] = keccak256(abi.encodePacked(input, uint256(0)));
        hashes[1] = keccak256(abi.encodePacked(input, uint256(1)));
        hashes[2] = keccak256(abi.encodePacked(input, uint256(2)));
        hashes[3] = keccak256(abi.encodePacked(input, uint256(3)));
        hashes[4] = keccak256(abi.encodePacked(input, uint256(4)));
        hashes[5] = keccak256(abi.encodePacked(input, uint256(5)));
        hashes[6] = keccak256(abi.encodePacked(input, uint256(6)));
        hashes[7] = keccak256(abi.encodePacked(input, uint256(7)));
        
        uint256 q = Q;
        
        assembly ("memory-safe") {
            for { let idx := 0 } lt(idx, 8) { idx := add(idx, 1) } {
                let h := mload(add(hashes, mul(idx, 32)))
                let s := 0
                for { let i := 0 } lt(i, 16) { i := add(i, 1) } {
                    let shift := mul(sub(15, i), 16)
                    s := or(s, shl(shift, mod(and(shr(shift, h), 0xFFFF), q)))
                }
                mstore(add(scratchBase, mul(idx, 0x20)), s)
            }
        }
    }
    
    receive() external payable { _reward += msg.value; }
}
