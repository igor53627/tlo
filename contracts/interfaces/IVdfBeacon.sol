// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVdfBeacon - Shared VDF beacon for epoch-based circuit transformation
/// @notice Provides time-locked randomness via Verifiable Delay Functions
/// @dev Key insight: VDF output is PUBLIC once computed, but computing it takes
///      ~T_VDF time (non-parallelizable). Combined with epoch rotation, this
///      defeats semantic attacks (RainbowTable, LocalReversibility) because:
///      T_VDF + T_attack > T_epoch -> attacker is always one epoch behind
interface IVdfBeacon {
    /// @notice Emitted when an epoch's seed is finalized from blockhash
    event SeedFinalized(uint64 indexed epoch, bytes32 seed);
    
    /// @notice Emitted when a VDF proof is submitted and verified
    event VdfVerified(uint64 indexed epoch, bytes32 vdfOutput, address indexed submitter);
    
    /// @notice Get the epoch configuration
    /// @return blocksPerEpoch Number of blocks per epoch (~50 for 10 min on Ethereum)
    /// @return vdfIterations VDF iterations (calibrated for ~epoch duration)
    function config() external view returns (uint64 blocksPerEpoch, uint64 vdfIterations);
    
    /// @notice Get the current epoch number
    /// @return The current epoch index (block.number / blocksPerEpoch)
    function currentEpoch() external view returns (uint64);
    
    /// @notice Finalize the seed for an epoch from blockhash
    /// @dev Must be called within 256 blocks after the epoch boundary
    ///      The seed is derived from: keccak256("VDF_BEACON", address, epoch, blockhash)
    /// @param epoch The epoch to finalize seed for
    function finalizeEpochSeed(uint64 epoch) external;
    
    /// @notice Submit a VDF proof for an epoch
    /// @dev Anyone can submit a valid VDF proof (permissionless beacon)
    ///      Proof is verified on-chain (Wesolowski ~50k gas)
    /// @param epoch The epoch this VDF output is for
    /// @param vdfOutput The VDF output y = VDF(seed, iterations)
    /// @param vdfProof The verification proof (scheme-specific)
    function submitVdf(uint64 epoch, bytes32 vdfOutput, bytes calldata vdfProof) external;
    
    /// @notice Get the VDF output for circuit evaluation
    /// @dev Returns VDF for a lagged epoch (currentEpoch - 1) to ensure availability
    ///      Reverts if VDF not yet verified for that epoch
    /// @return epoch The epoch being used for evaluation
    /// @return vdfOutput The verified VDF output for deriving transforms
    function vdfForEvaluation() external view returns (uint64 epoch, bytes32 vdfOutput);
    
    /// @notice Check if an epoch has a verified VDF output
    /// @param epoch The epoch to check
    /// @return seedSet Whether the epoch's seed has been finalized
    /// @return vdfVerified Whether a valid VDF proof has been submitted
    function epochStatus(uint64 epoch) external view returns (bool seedSet, bool vdfVerified);
    
    /// @notice Get the seed for an epoch (if finalized)
    /// @param epoch The epoch to get seed for
    /// @return The epoch's seed (reverts if not set)
    function epochSeed(uint64 epoch) external view returns (bytes32);
    
    /// @notice Get the VDF output for an epoch (if verified)
    /// @param epoch The epoch to get VDF output for
    /// @return The epoch's VDF output (reverts if not verified)
    function epochVdfOutput(uint64 epoch) external view returns (bytes32);
}
