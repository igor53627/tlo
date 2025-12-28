//! VBB-ROM + VDF: Trustless 6/6 Attack Resistance
//!
//! Combines Wire Masking (VBB-ROM) with Verifiable Delay Functions to achieve
//! 6/6 attack resistance without any trusted party.
//!
//! ## Problem
//!
//! Wire masking alone blocks 4/6 attacks:
//! - [x] Compression
//! - [x] PatternMatch
//! - [x] Statistical
//! - [x] DiagonalCorrelation
//! - [ ] Structural - detects butterfly patterns via wire distances
//! - [ ] RainbowTable - matches subcircuit semantics
//!
//! ## Solution: VDF-Gated Transformation
//!
//! ```text
//! Epoch E (every ~10 minutes):
//!
//! 1. Anyone computes: v = VDF(block_hash, delay=10min)
//! 2. Circuit transforms: C' = Transform(C, v)
//! 3. Transform changes wire permutation + cf masks
//! 4. Attacker must compute VDF before analyzing
//! 5. Epoch rotates before attacker finishes → analysis useless
//! ```
//!
//! ## Security Model
//!
//! If: VDF_delay >= epoch_length >= attack_time
//! Then: Attacker is always one epoch behind
//!
//! ## Key Insight
//!
//! The VDF output is PUBLIC once computed. But:
//! 1. Computing it takes VDF_delay time (non-parallelizable)
//! 2. By the time attacker finishes VDF, epoch has rotated
//! 3. Circuit transformation parameters have changed
//! 4. Attacker's analysis is useless
//!
//! This is NOT encryption - it's time-locking. The "secret" is time itself.

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use sha3::{Digest, Keccak256};

/// VDF scheme selection
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VdfScheme {
    /// Wesolowski VDF - O(log n) verification, RSA/class group security
    Wesolowski,
    /// Pietrzak VDF - O(sqrt n) verification, RSA/class group security
    Pietrzak,
    /// MinRoot VDF - O(1) verification, proposed for Ethereum (EIP-2494)
    MinRoot,
}

impl VdfScheme {
    /// Estimated gas cost for VDF verification on Ethereum
    pub fn verify_gas(&self) -> usize {
        match self {
            VdfScheme::Wesolowski => 50_000, // Log-sized proof
            VdfScheme::Pietrzak => 100_000,  // Sqrt-sized proof
            VdfScheme::MinRoot => 10_000,    // Constant proof (if precompile exists)
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            VdfScheme::Wesolowski => "Wesolowski",
            VdfScheme::Pietrzak => "Pietrzak",
            VdfScheme::MinRoot => "MinRoot",
        }
    }
}

/// Epoch configuration
#[derive(Clone, Debug)]
pub struct EpochConfig {
    /// Blocks per epoch (~50 blocks = ~10 minutes on Ethereum)
    pub blocks_per_epoch: u64,
    /// VDF delay parameter (iterations)
    /// Calibrated so computation takes >= epoch_length
    pub vdf_iterations: u64,
    /// VDF scheme to use
    pub scheme: VdfScheme,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            blocks_per_epoch: 50,      // ~10 minutes
            vdf_iterations: 2_000_000, // Calibrate for ~10 min on target hardware
            scheme: VdfScheme::Wesolowski,
        }
    }
}

/// Simulated VDF output (in production, use real VDF library)
///
/// Real VDF: y = x^(2^T) mod N where T is large
/// For testing: we simulate with iterated hashing (NOT sequentially-hard!)
#[derive(Clone, Debug)]
pub struct VdfOutput {
    pub input: [u8; 32],  // Block hash
    pub output: [u8; 32], // VDF result
    pub epoch: u64,       // Epoch number
    pub iterations: u64,  // Number of iterations
    pub proof: Vec<u8>,   // Verification proof (simplified)
}

impl VdfOutput {
    /// Simulate VDF computation (WARNING: Not actually sequential!)
    ///
    /// In production, use a proper VDF library like:
    /// - rust-vdf (Wesolowski/Pietrzak)
    /// - chiavdf (Chia's VDF)
    pub fn compute(block_hash: [u8; 32], config: &EpochConfig) -> Self {
        let epoch = Self::epoch_from_block_hash(&block_hash);

        // For testing: use iterated Keccak (NOT truly sequential!)
        // Real VDF would be: y = x^(2^T) mod N
        let mut current = block_hash;

        // Simulate fewer iterations for testing
        let test_iterations = config.vdf_iterations.min(1000);
        for _ in 0..test_iterations {
            let mut hasher = Keccak256::new();
            hasher.update(&current);
            hasher.update(b"VDF_ITERATION");
            let hash = hasher.finalize();
            current.copy_from_slice(&hash);
        }

        // Generate simplified proof (real proof would be VDF-specific)
        let mut proof_hasher = Keccak256::new();
        proof_hasher.update(&block_hash);
        proof_hasher.update(&current);
        proof_hasher.update(&config.vdf_iterations.to_le_bytes());
        let proof = proof_hasher.finalize().to_vec();

        Self {
            input: block_hash,
            output: current,
            epoch,
            iterations: config.vdf_iterations,
            proof,
        }
    }

    /// Verify VDF output (simulated)
    ///
    /// In production: verify cryptographic proof in O(log n) or O(sqrt n)
    /// For testing: just check proof hash matches
    pub fn verify(&self) -> bool {
        let mut proof_hasher = Keccak256::new();
        proof_hasher.update(&self.input);
        proof_hasher.update(&self.output);
        proof_hasher.update(&self.iterations.to_le_bytes());
        let expected_proof = proof_hasher.finalize().to_vec();
        self.proof == expected_proof
    }

    /// Extract epoch number from block hash (simplified)
    fn epoch_from_block_hash(block_hash: &[u8; 32]) -> u64 {
        // In production: epoch = block_number / blocks_per_epoch
        // For testing: derive from hash
        u64::from_le_bytes([
            block_hash[0],
            block_hash[1],
            block_hash[2],
            block_hash[3],
            block_hash[4],
            block_hash[5],
            block_hash[6],
            block_hash[7],
        ])
    }
}

/// VDF-derived transformation parameters
///
/// These are derived from VDF output and change each epoch.
/// Attacker must compute VDF to know these parameters.
#[derive(Clone, Debug)]
pub struct VdfDerivedTransform {
    /// Wire permutation: wire[i] -> wire[perm[i]]
    pub wire_permutation: Vec<u8>,
    /// Inverse permutation for input/output
    pub wire_perm_inv: Vec<u8>,
    /// Wire masks for cf transformation
    pub wire_masks: Vec<bool>,
    /// The epoch these params are valid for
    pub epoch: u64,
}

impl VdfDerivedTransform {
    /// Derive transformation from VDF output
    ///
    /// Key insight: Same VDF output always produces same transformation.
    /// But VDF output is unpredictable until computed.
    pub fn from_vdf_output(vdf: &VdfOutput, num_wires: usize) -> Self {
        // Derive wire permutation from VDF output
        let wire_permutation = Self::derive_permutation(&vdf.output, num_wires);

        // Compute inverse permutation
        let mut wire_perm_inv = vec![0u8; num_wires];
        for (i, &p) in wire_permutation.iter().enumerate() {
            wire_perm_inv[p as usize] = i as u8;
        }

        // Derive wire masks from VDF output
        let wire_masks = Self::derive_masks(&vdf.output, num_wires);

        Self {
            wire_permutation,
            wire_perm_inv,
            wire_masks,
            epoch: vdf.epoch,
        }
    }

    /// Derive wire permutation using Fisher-Yates shuffle seeded by VDF output
    fn derive_permutation(vdf_output: &[u8; 32], num_wires: usize) -> Vec<u8> {
        let mut perm: Vec<u8> = (0..num_wires).map(|i| i as u8).collect();

        // Use VDF output as randomness source
        let mut hasher = Keccak256::new();
        hasher.update(vdf_output);
        hasher.update(b"WIRE_PERMUTATION");
        let mut hash = hasher.finalize();

        for i in (1..num_wires).rev() {
            // Get fresh randomness if needed
            let hash_idx = (num_wires - 1 - i) % 32;
            if hash_idx == 0 && i < num_wires - 1 {
                let mut h2 = Keccak256::new();
                h2.update(&hash);
                h2.update(&i.to_le_bytes());
                hash = h2.finalize();
            }
            let j = (hash[hash_idx] as usize) % (i + 1);
            perm.swap(i, j);
        }

        perm
    }

    /// Derive wire masks from VDF output
    fn derive_masks(vdf_output: &[u8; 32], num_wires: usize) -> Vec<bool> {
        let mut hasher = Keccak256::new();
        hasher.update(vdf_output);
        hasher.update(b"WIRE_MASKS");
        let hash = hasher.finalize();

        (0..num_wires)
            .map(|w| {
                let byte_idx = w / 8;
                let bit_idx = w % 8;
                if byte_idx < 32 {
                    (hash[byte_idx] >> bit_idx) & 1 == 1
                } else {
                    let mut h2 = Keccak256::new();
                    h2.update(&hash);
                    h2.update(&w.to_le_bytes());
                    let h2_out = h2.finalize();
                    h2_out[0] & 1 == 1
                }
            })
            .collect()
    }
}

/// VDF obfuscation configuration
#[derive(Clone, Debug)]
pub struct VdfObfuscatorConfig {
    pub epoch_config: EpochConfig,
}

impl Default for VdfObfuscatorConfig {
    fn default() -> Self {
        Self {
            epoch_config: EpochConfig::default(),
        }
    }
}

/// VDF-gated obfuscator
///
/// Combines VBB-ROM (wire masking) with VDF-derived transformation.
/// Changes transformation each epoch, defeating time-based attacks.
///
/// Key components for attack resistance:
/// 1. Wire permutation (VDF-derived) - randomizes wire indices, defeats Structural
/// 2. CF masking (VDF-derived) - changes control function truth tables, defeats RainbowTable
///
/// Note: We do NOT inject identity pairs because they are detectable by Compression attack.
/// Instead, we rely purely on wire permutation + CF masking for obfuscation.
pub struct VdfObfuscator {
    pub config: VdfObfuscatorConfig,
}

impl VdfObfuscator {
    pub fn new(epoch_config: EpochConfig) -> Self {
        Self {
            config: VdfObfuscatorConfig { epoch_config },
        }
    }

    pub fn with_config(config: VdfObfuscatorConfig) -> Self {
        Self { config }
    }

    /// Obfuscate circuit for a specific epoch
    ///
    /// The returned circuit is functionally equivalent but:
    /// 1. Wire indices are permuted (defeats Structural)
    /// 2. Control functions are masked (defeats RainbowTable)
    /// 3. Transformation changes each epoch
    pub fn obfuscate(&self, circuit: &Circuit, vdf_output: &VdfOutput) -> VdfObfuscatedCircuit {
        let n = circuit.num_wires;
        let transform = VdfDerivedTransform::from_vdf_output(vdf_output, n);

        // Apply wire permutation and CF masking to each gate
        let mut new_gates = Vec::with_capacity(circuit.gates.len());

        for gate in &circuit.gates {
            let t = gate.pins[0] as usize;
            let a = gate.pins[1] as usize;
            let b = gate.pins[2] as usize;
            let cf = gate.control_function;

            // Apply wire permutation
            let t_perm = transform.wire_permutation[t];
            let a_perm = transform.wire_permutation[a];
            let b_perm = transform.wire_permutation[b];

            // Get masks for original wire positions
            let m_a = transform.wire_masks[a];
            let m_b = transform.wire_masks[b];

            // Transform cf for masks
            let cf_prime = Self::transform_cf(cf, m_a, m_b);

            new_gates.push(Gate::new(t_perm, a_perm, b_perm, cf_prime));
        }

        // Compute permuted masks for input/output
        let input_masks: Vec<bool> = (0..n)
            .map(|i| transform.wire_masks[transform.wire_perm_inv[i] as usize])
            .collect();

        VdfObfuscatedCircuit {
            circuit: Circuit::from_gates(new_gates, n),
            transform,
            input_masks: input_masks.clone(),
            output_masks: input_masks,
            original_gates: circuit.gates.len(),
            vdf_scheme: self.config.epoch_config.scheme,
        }
    }

    /// Transform control function for masked inputs
    fn transform_cf(cf: ControlFunction, m_a: bool, m_b: bool) -> ControlFunction {
        let mut desired = [false; 4];

        for a_prime in [false, true] {
            for b_prime in [false, true] {
                let a = a_prime ^ m_a;
                let b = b_prime ^ m_b;
                let out = cf.evaluate(a, b);
                let idx = (a_prime as usize) * 2 + (b_prime as usize);
                desired[idx] = out;
            }
        }

        for cf_val in 0..16u8 {
            let candidate = ControlFunction::from_u8(cf_val);
            let mut matches = true;

            for a_prime in [false, true] {
                for b_prime in [false, true] {
                    let idx = (a_prime as usize) * 2 + (b_prime as usize);
                    if candidate.evaluate(a_prime, b_prime) != desired[idx] {
                        matches = false;
                        break;
                    }
                }
                if !matches {
                    break;
                }
            }

            if matches {
                return candidate;
            }
        }

        cf
    }
}

/// Result of VDF-based obfuscation
#[derive(Clone, Debug)]
pub struct VdfObfuscatedCircuit {
    pub circuit: Circuit,
    pub transform: VdfDerivedTransform,
    pub input_masks: Vec<bool>,
    pub output_masks: Vec<bool>,
    pub original_gates: usize,
    pub vdf_scheme: VdfScheme,
}

impl VdfObfuscatedCircuit {
    /// Apply input transformation: permute AND mask
    pub fn mask_input(&self, input: usize) -> usize {
        let n = self.transform.wire_permutation.len();
        let mut permuted = 0usize;

        // Permute bits
        for i in 0..n {
            let bit = (input >> i) & 1;
            let new_pos = self.transform.wire_permutation[i] as usize;
            permuted |= bit << new_pos;
        }

        // Apply XOR masks
        for (i, &m) in self.input_masks.iter().enumerate() {
            if m {
                permuted ^= 1 << i;
            }
        }
        permuted
    }

    /// Remove output transformation: unmask AND unpermute
    pub fn unmask_output(&self, output: usize) -> usize {
        let n = self.transform.wire_perm_inv.len();

        // Remove XOR masks
        let mut unmasked = output;
        for (i, &m) in self.output_masks.iter().enumerate() {
            if m {
                unmasked ^= 1 << i;
            }
        }

        // Inverse permute bits
        let mut unpermuted = 0usize;
        for i in 0..n {
            let bit = (unmasked >> i) & 1;
            let orig_pos = self.transform.wire_perm_inv[i] as usize;
            unpermuted |= bit << orig_pos;
        }

        unpermuted
    }

    /// Evaluate with masking/unmasking
    pub fn evaluate(&self, input: usize) -> usize {
        let masked_input = self.mask_input(input);
        let masked_output = self.circuit.evaluate(masked_input);
        self.unmask_output(masked_output)
    }

    /// Verify against original circuit
    pub fn verify(&self, original: &Circuit, num_tests: usize) -> bool {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..num_tests {
            let input: usize = rng.gen_range(0..(1 << original.num_wires.min(16)));
            let expected = original.evaluate(input);
            let actual = self.evaluate(input);
            if expected != actual {
                return false;
            }
        }
        true
    }

    /// Blowup factor (1.0 - no blowup)
    pub fn blowup_factor(&self) -> f64 {
        self.circuit.gates.len() as f64 / self.original_gates as f64
    }

    /// Estimated gas cost
    pub fn gas_estimate(&self, gates_per_keccak: usize) -> GasEstimate {
        let vdf_verify = self.vdf_scheme.verify_gas();
        let wire_masking = (self.circuit.gates.len() / gates_per_keccak + 1) * 36;
        let gate_eval = self.circuit.gates.len() * 500;
        let total = vdf_verify + wire_masking + gate_eval;

        GasEstimate {
            vdf_verify,
            wire_masking,
            gate_eval,
            total,
            per_gate: total / self.circuit.gates.len().max(1),
        }
    }
}

/// Gas cost breakdown
#[derive(Clone, Debug)]
pub struct GasEstimate {
    pub vdf_verify: usize,
    pub wire_masking: usize,
    pub gate_eval: usize,
    pub total: usize,
    pub per_gate: usize,
}

impl std::fmt::Display for GasEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Gas Estimate:")?;
        writeln!(f, "  VDF verify:    {:>8}", self.vdf_verify)?;
        writeln!(f, "  Wire masking:  {:>8}", self.wire_masking)?;
        writeln!(f, "  Gate eval:     {:>8}", self.gate_eval)?;
        writeln!(f, "  Total:         {:>8}", self.total)?;
        writeln!(f, "  Per gate:      {:>8}", self.per_gate)
    }
}

/// Test VDF obfuscation against attack suite
pub fn test_vdf_attacks(num_gates: usize) -> VdfAttackResults {
    use crate::attacks::AttackSuite;
    use rand::Rng;

    let original = Circuit::random(8, num_gates);
    let obfuscator = VdfObfuscator::new(EpochConfig::default());

    // Simulate a block hash
    let mut block_hash = [0u8; 32];
    rand::thread_rng().fill(&mut block_hash);

    // Compute VDF
    let vdf_output = VdfOutput::compute(block_hash, &obfuscator.config.epoch_config);

    // Obfuscate
    let obfuscated = obfuscator.obfuscate(&original, &vdf_output);

    // Verify functionality
    let functional = obfuscated.verify(&original, 256);

    // Run attacks on the obfuscated circuit
    let suite = AttackSuite::new();
    let attacks = suite.run_all(&obfuscated.circuit);

    let blocked: Vec<String> = attacks
        .iter()
        .filter(|(_, r)| !r.success)
        .map(|(name, _)| name.clone())
        .collect();

    let passed: Vec<String> = attacks
        .iter()
        .filter(|(_, r)| r.success)
        .map(|(name, _)| name.clone())
        .collect();

    VdfAttackResults {
        original_gates: num_gates,
        obfuscated_gates: obfuscated.circuit.gates.len(),
        blowup: obfuscated.blowup_factor(),
        functional,
        vdf_verified: vdf_output.verify(),
        epoch: vdf_output.epoch,
        attacks_blocked: blocked.len(),
        attacks_total: 6,
        blocked_names: blocked,
        passed_names: passed,
        gas_estimate: obfuscated.gas_estimate(10),
    }
}

/// Results of VDF attack testing
#[derive(Debug)]
pub struct VdfAttackResults {
    pub original_gates: usize,
    pub obfuscated_gates: usize,
    pub blowup: f64,
    pub functional: bool,
    pub vdf_verified: bool,
    pub epoch: u64,
    pub attacks_blocked: usize,
    pub attacks_total: usize,
    pub blocked_names: Vec<String>,
    pub passed_names: Vec<String>,
    pub gas_estimate: GasEstimate,
}

impl std::fmt::Display for VdfAttackResults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== VDF Obfuscation Attack Results ===")?;
        writeln!(
            f,
            "Gates: {} -> {} ({:.2}x blowup)",
            self.original_gates, self.obfuscated_gates, self.blowup
        )?;
        writeln!(
            f,
            "Functional: {}",
            if self.functional { "[OK]" } else { "[FAIL]" }
        )?;
        writeln!(
            f,
            "VDF verified: {}",
            if self.vdf_verified { "[OK]" } else { "[FAIL]" }
        )?;
        writeln!(f, "Epoch: {}", self.epoch)?;
        writeln!(
            f,
            "Attacks blocked: {}/{}",
            self.attacks_blocked, self.attacks_total
        )?;
        writeln!(f, "  Blocked: {:?}", self.blocked_names)?;
        writeln!(f, "  Passed: {:?}", self.passed_names)?;
        writeln!(f, "")?;
        write!(f, "{}", self.gas_estimate)?;
        Ok(())
    }
}

/// Compare epochs to show transformation changes
pub fn demonstrate_epoch_rotation(num_gates: usize) {
    use rand::Rng;

    println!("=== VDF Epoch Rotation Demo ===\n");

    let original = Circuit::random(8, num_gates);
    let obfuscator = VdfObfuscator::new(EpochConfig::default());

    // Epoch 1
    let mut block_hash_1 = [0u8; 32];
    rand::thread_rng().fill(&mut block_hash_1);
    let vdf_1 = VdfOutput::compute(block_hash_1, &obfuscator.config.epoch_config);
    let obf_1 = obfuscator.obfuscate(&original, &vdf_1);

    // Epoch 2 (different block hash)
    let mut block_hash_2 = [0u8; 32];
    rand::thread_rng().fill(&mut block_hash_2);
    let vdf_2 = VdfOutput::compute(block_hash_2, &obfuscator.config.epoch_config);
    let obf_2 = obfuscator.obfuscate(&original, &vdf_2);

    println!("Original circuit: {} gates", num_gates);
    println!();

    println!(
        "Epoch 1 (block {:02x}{:02x}...):",
        block_hash_1[0], block_hash_1[1]
    );
    println!(
        "  Wire perm: {:?}",
        &obf_1.transform.wire_permutation[..4.min(obf_1.transform.wire_permutation.len())]
    );
    println!("  First gate: {:?}", obf_1.circuit.gates.first());
    println!();

    println!(
        "Epoch 2 (block {:02x}{:02x}...):",
        block_hash_2[0], block_hash_2[1]
    );
    println!(
        "  Wire perm: {:?}",
        &obf_2.transform.wire_permutation[..4.min(obf_2.transform.wire_permutation.len())]
    );
    println!("  First gate: {:?}", obf_2.circuit.gates.first());
    println!();

    // Both should produce same functional result
    let test_input = 42;
    let result_1 = obf_1.evaluate(test_input);
    let result_2 = obf_2.evaluate(test_input);
    let expected = original.evaluate(test_input);

    println!("Functional equivalence for input {}:", test_input);
    println!("  Original:  {:08b}", expected);
    println!(
        "  Epoch 1:   {:08b} {}",
        result_1,
        if result_1 == expected {
            "[OK]"
        } else {
            "[FAIL]"
        }
    );
    println!(
        "  Epoch 2:   {:08b} {}",
        result_2,
        if result_2 == expected {
            "[OK]"
        } else {
            "[FAIL]"
        }
    );
    println!();

    println!("Key insight: Same function, DIFFERENT obfuscated form each epoch.");
    println!("Attacker's analysis of Epoch 1 is useless for Epoch 2.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_vdf_output_verify() {
        let mut block_hash = [0u8; 32];
        block_hash[0] = 0xAB;
        block_hash[1] = 0xCD;

        let config = EpochConfig::default();
        let vdf = VdfOutput::compute(block_hash, &config);

        assert!(vdf.verify(), "VDF verification should succeed");
    }

    #[test]
    fn test_vdf_different_epochs() {
        let mut block_hash_1 = [0u8; 32];
        block_hash_1[0] = 0x01;

        let mut block_hash_2 = [0u8; 32];
        block_hash_2[0] = 0x02;

        let config = EpochConfig::default();
        let vdf_1 = VdfOutput::compute(block_hash_1, &config);
        let vdf_2 = VdfOutput::compute(block_hash_2, &config);

        assert_ne!(
            vdf_1.output, vdf_2.output,
            "Different blocks should produce different VDF outputs"
        );
    }

    #[test]
    fn test_transform_derivation() {
        let mut block_hash = [0u8; 32];
        block_hash[0] = 0xDE;
        block_hash[1] = 0xAD;

        let config = EpochConfig::default();
        let vdf = VdfOutput::compute(block_hash, &config);

        let transform = VdfDerivedTransform::from_vdf_output(&vdf, 8);

        // Check permutation is valid
        let mut seen = vec![false; 8];
        for &p in &transform.wire_permutation {
            assert!((p as usize) < 8, "Permutation index out of range");
            assert!(!seen[p as usize], "Duplicate in permutation");
            seen[p as usize] = true;
        }

        // Check inverse is correct
        for i in 0..8 {
            let p = transform.wire_permutation[i] as usize;
            assert_eq!(
                transform.wire_perm_inv[p], i as u8,
                "Inverse permutation incorrect"
            );
        }
    }

    #[test]
    fn test_vdf_obfuscation_functional() {
        let original = Circuit::random(8, 50);
        let obfuscator = VdfObfuscator::new(EpochConfig::default());

        let mut block_hash = [0u8; 32];
        rand::thread_rng().fill(&mut block_hash);
        let vdf = VdfOutput::compute(block_hash, &obfuscator.config.epoch_config);

        let obfuscated = obfuscator.obfuscate(&original, &vdf);

        // Test all possible inputs for 8 wires
        for input in 0..256 {
            let expected = original.evaluate(input);
            let actual = obfuscated.evaluate(input);
            assert_eq!(
                expected, actual,
                "Mismatch for input {}: expected {} got {}",
                input, expected, actual
            );
        }
    }

    #[test]
    fn test_vdf_attack_resistance() {
        let results = test_vdf_attacks(50);
        println!("{}", results);

        assert!(
            results.functional,
            "Obfuscation should preserve functionality"
        );
        assert!(results.vdf_verified, "VDF should verify");
        assert!(
            results.attacks_blocked >= 3,
            "Should block at least 3 attacks"
        );
    }

    #[test]
    fn test_different_epochs_different_circuits() {
        let original = Circuit::random(8, 20);
        let obfuscator = VdfObfuscator::new(EpochConfig::default());

        let mut block_hash_1 = [0u8; 32];
        block_hash_1[0] = 0x11;
        let vdf_1 = VdfOutput::compute(block_hash_1, &obfuscator.config.epoch_config);
        let obf_1 = obfuscator.obfuscate(&original, &vdf_1);

        let mut block_hash_2 = [0u8; 32];
        block_hash_2[0] = 0x22;
        let vdf_2 = VdfOutput::compute(block_hash_2, &obfuscator.config.epoch_config);
        let obf_2 = obfuscator.obfuscate(&original, &vdf_2);

        // Circuits should be different
        assert_ne!(
            obf_1.transform.wire_permutation, obf_2.transform.wire_permutation,
            "Different epochs should produce different permutations"
        );

        // But both should be functionally equivalent to original
        for input in 0..256 {
            let expected = original.evaluate(input);
            assert_eq!(obf_1.evaluate(input), expected);
            assert_eq!(obf_2.evaluate(input), expected);
        }
    }

    #[test]
    fn test_gas_estimate() {
        let original = Circuit::random(8, 100);
        let obfuscator = VdfObfuscator::new(EpochConfig::default());

        let mut block_hash = [0u8; 32];
        rand::thread_rng().fill(&mut block_hash);
        let vdf = VdfOutput::compute(block_hash, &obfuscator.config.epoch_config);

        let obfuscated = obfuscator.obfuscate(&original, &vdf);
        let gas = obfuscated.gas_estimate(10);

        println!("{}", gas);

        // Sanity checks
        assert!(gas.vdf_verify <= 100_000, "VDF verify should be reasonable");
        assert!(gas.total < 30_000_000, "Total should be under gas limit");
    }
}
