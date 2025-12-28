// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IKyberGate - Interface for Huff-based ML-KEM-512 decapsulation
/// @notice Called by MinCore for encrypted gate evaluation
interface IKyberGate {
    /// @notice Decrypt Kyber ciphertext
    /// @param ct 768-byte ciphertext
    /// @param sk 768-byte secret key
    /// @return 32-byte decrypted message
    function decrypt(bytes calldata ct, bytes calldata sk) external view returns (bytes32);
    
    /// @notice Evaluate encrypted gate
    /// @param gateData Combined ciphertext + secret key + gate params
    /// @return 32-byte result containing gate parameters
    function evaluateGate(bytes calldata gateData) external view returns (bytes32);
}
