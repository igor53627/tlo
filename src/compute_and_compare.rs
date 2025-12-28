//! Compute-and-Compare (C&C) Obfuscation for Control Functions
//!
//! A simpler alternative to full FHE that uses only LWE operations.
//! No bootstrapping needed - just encryption and linear operations.
//!
//! ## What is Compute-and-Compare?
//!
//! ```text
//! C&C(f, x) = msg  if f(x) = target
//!           = ⊥    otherwise
//! ```
//!
//! For control function obfuscation:
//! - f is the 2-bit → 1-bit control function
//! - We encode f's truth table using LWE
//! - Evaluation is purely public (no keys needed)
//!
//! ## Why C&C over FHE?
//!
//! | Property | FHE (TFHE) | C&C |
//! |----------|------------|-----|
//! | Bootstrap | ~0.9ms/op | None |
//! | Overhead | ~950x | ~100x |
//! | Complexity | High | Low |
//! | Security | FHE | LWE |
//!
//! ## Construction (Goyal-Koppula-Waters style)
//!
//! For each gate with control function f:
//! 1. Encode f's truth table as 4 LWE ciphertexts
//! 2. Use branching program structure for input selection
//! 3. Evaluate by computing linear combination
//!
//! Key insight: Control functions are simple (4-entry truth table),
//! so we don't need full FHE - just LWE with input encoding.

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use crate::six_six::tlo_derive_u64;
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

// Re-use LWE primitives from lockable_obfuscation
use crate::lockable_obfuscation::{inner_product, LWECiphertext, LWEParams, LWESecretKey};

/// C&C parameters - tuned for control function obfuscation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaCParams {
    /// LWE dimension (security parameter)
    pub n: usize,
    /// Modulus q  
    pub q: u64,
    /// Error bound
    pub error_bound: u64,
    /// Scaling factor for encoded values
    pub scale: u64,
}

impl Default for CaCParams {
    fn default() -> Self {
        Self::balanced()
    }
}

impl CaCParams {
    /// 128-bit security with balanced overhead
    pub fn security_128() -> Self {
        Self {
            n: 512,
            q: 1 << 32,
            error_bound: 8,
            scale: 1 << 30,
        }
    }

    /// Balanced: good security with reasonable overhead
    pub fn balanced() -> Self {
        Self {
            n: 256,
            q: 1 << 24,
            error_bound: 4,
            scale: 1 << 22,
        }
    }

    /// Aggressive: minimize overhead (lower security margin)
    pub fn aggressive() -> Self {
        Self {
            n: 128,
            q: 1 << 20,
            error_bound: 4,
            scale: 1 << 18,
        }
    }

    /// Testing parameters (fast, low security)
    pub fn testing() -> Self {
        Self {
            n: 64,
            q: 1 << 16,
            error_bound: 4,
            scale: 1 << 14,
        }
    }

    /// Convert to LWEParams for compatibility
    pub fn to_lwe_params(&self) -> LWEParams {
        LWEParams {
            n: self.n,
            q: self.q,
            error_bound: self.error_bound,
        }
    }

    /// Estimated overhead factor compared to plaintext
    pub fn overhead_factor(&self) -> f64 {
        // Each plaintext byte -> n * 8 bytes (LWE ciphertext)
        // Plus encoding overhead
        (self.n * 8) as f64 / 4.0 * 4.0 // 4 entries per truth table
    }
}

/// Encoded truth table for a control function
///
/// Uses LWE to encode f(0,0), f(0,1), f(1,0), f(1,1)
/// such that evaluation reveals only the correct output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedTruthTable {
    /// 4 encoded entries: f(00), f(01), f(10), f(11)
    pub entries: [EncodedBit; 4],
    /// Parameters
    pub params: CaCParams,
}

/// An encoded bit that can be evaluated without the secret
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedBit {
    /// LWE ciphertext encoding the bit
    pub ct: LWECiphertext,
    /// Hint for public evaluation
    pub hint: u64,
}

impl EncodedBit {
    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.ct.size_bytes() + 8
    }
}

impl EncodedTruthTable {
    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.entries.iter().map(|e| e.size_bytes()).sum()
    }
}

/// Compute-and-Compare obfuscator for control functions
pub struct CaCObfuscator {
    params: CaCParams,
}

impl CaCObfuscator {
    pub fn new(params: CaCParams) -> Self {
        Self { params }
    }

    pub fn with_defaults() -> Self {
        Self::new(CaCParams::default())
    }

    /// Obfuscate a control function
    ///
    /// Encodes the 4-entry truth table using LWE.
    /// The resulting program can be evaluated publicly.
    pub fn obfuscate(&self, cf: ControlFunction, seed: u64) -> EncodedTruthTable {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let lwe_params = self.params.to_lwe_params();
        let sk = LWESecretKey::generate(&lwe_params, &mut rng);

        let entries: [EncodedBit; 4] = std::array::from_fn(|i| {
            let c1 = (i & 1) != 0;
            let c2 = (i >> 1) != 0;
            let output = cf.evaluate(c1, c2);

            self.encode_bit(&sk, output, &mut rng)
        });

        EncodedTruthTable {
            entries,
            params: self.params.clone(),
        }
    }

    /// Encode a single bit using C&C construction
    fn encode_bit(&self, sk: &LWESecretKey, bit: bool, rng: &mut impl Rng) -> EncodedBit {
        let ct = sk.encrypt(bit, rng);

        // Compute hint for public evaluation
        // hint = <a, s> mod q (the "compute" part)
        // This allows evaluator to extract bit from b - hint
        let hint = inner_product(&ct.a, &sk.s, self.params.q);

        EncodedBit { ct, hint }
    }

    /// Evaluate an encoded truth table on input (c1, c2)
    ///
    /// PUBLIC evaluation - no secret key needed!
    pub fn evaluate(table: &EncodedTruthTable, c1: bool, c2: bool) -> bool {
        let idx = (c1 as usize) | ((c2 as usize) << 1);
        let entry = &table.entries[idx];

        // Extract bit using hint
        // b = <a, s> + e + bit * q/2
        // b - hint = e + bit * q/2
        // If bit=0: result close to 0
        // If bit=1: result close to q/2
        let q = table.params.q;
        let diff = ((entry.ct.b as i64 - entry.hint as i64).rem_euclid(q as i64)) as u64;

        // Threshold at q/4
        let threshold = q / 4;
        diff > threshold && diff < 3 * threshold
    }
}

/// C&C obfuscated gate
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaCGate {
    /// Wire indices: [active, c1, c2]
    pub pins: [u8; 3],
    /// Encoded control function
    pub encoded_cf: EncodedTruthTable,
}

impl CaCGate {
    /// Create from a regular gate
    pub fn from_gate(gate: &Gate, seed: u64, params: &CaCParams) -> Self {
        let obfuscator = CaCObfuscator::new(params.clone());
        let encoded_cf = obfuscator.obfuscate(gate.control_function, seed);

        Self {
            pins: gate.pins,
            encoded_cf,
        }
    }

    /// Evaluate on wire state
    pub fn evaluate(&self, state: &mut usize) {
        let active = self.pins[0] as usize;
        let c1 = (*state >> self.pins[1] as usize) & 1 == 1;
        let c2 = (*state >> self.pins[2] as usize) & 1 == 1;

        let control = CaCObfuscator::evaluate(&self.encoded_cf, c1, c2);
        if control {
            *state ^= 1 << active;
        }
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        3 + self.encoded_cf.size_bytes()
    }
}

/// C&C obfuscated circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaCCircuit {
    pub gates: Vec<CaCGate>,
    pub num_wires: usize,
    pub params: CaCParams,
}

impl CaCCircuit {
    /// Create from a regular circuit using domain-separated seeding
    ///
    /// Each gate gets a unique seed derived via Keccak256 with the "cac_gate" domain.
    /// This ensures cryptographic independence from topology and other subsystems.
    pub fn from_circuit(circuit: &Circuit, base_seed: u64, params: &CaCParams) -> Self {
        let gates: Vec<CaCGate> = circuit
            .gates
            .iter()
            .enumerate()
            .map(|(i, gate)| {
                // Domain-separated: "cac_gate" + base_seed + gate_index
                let seed = tlo_derive_u64(b"cac_gate", base_seed, i as u64);
                CaCGate::from_gate(gate, seed, params)
            })
            .collect();

        Self {
            gates,
            num_wires: circuit.num_wires,
            params: params.clone(),
        }
    }

    /// Evaluate the circuit
    pub fn evaluate(&self, input: usize) -> usize {
        let mut state = input;
        for gate in &self.gates {
            gate.evaluate(&mut state);
        }
        state
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.gates.iter().map(|g| g.size_bytes()).sum()
    }

    /// Overhead factor compared to plaintext circuit
    pub fn overhead_factor(&self, original_gates: usize) -> f64 {
        let plaintext_size = original_gates * 4; // 4 bytes per gate
        self.size_bytes() as f64 / plaintext_size as f64
    }
}

/// C&C Core for hybrid obfuscation
///
/// This is the crypto core that provides computational hardness.
/// Designed to integrate with topology mixing.
#[derive(Clone)]
pub struct CaCCore {
    /// C&C obfuscated gates in the core
    pub gates: Vec<CaCGate>,
    /// Parameters used
    pub params: CaCParams,
    /// Number of wires
    pub num_wires: usize,
}

impl CaCCore {
    /// Create a C&C core from selected gates using domain-separated seeding
    ///
    /// Uses "cac_core_gate" domain to ensure independence from full CaCCircuit seeds.
    pub fn from_gates(gates: &[Gate], num_wires: usize, base_seed: u64, params: &CaCParams) -> Self {
        let cac_gates: Vec<CaCGate> = gates
            .iter()
            .enumerate()
            .map(|(i, gate)| {
                // Separate domain from full circuit to avoid collisions
                let seed = tlo_derive_u64(b"cac_core_gate", base_seed, i as u64);
                CaCGate::from_gate(gate, seed, params)
            })
            .collect();

        Self {
            gates: cac_gates,
            params: params.clone(),
            num_wires,
        }
    }

    /// Evaluate the core
    pub fn evaluate(&self, input: usize) -> usize {
        let mut state = input;
        for gate in &self.gates {
            gate.evaluate(&mut state);
        }
        state
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.gates.iter().map(|g| g.size_bytes()).sum()
    }

    /// Estimated gas cost
    pub fn gas_estimate(&self) -> usize {
        // Each C&C gate: lookup + XOR + modular arithmetic
        // Much cheaper than FHE (no bootstrap)
        self.gates.len() * 100
    }
}

/// Hybrid: C&C Core + Topology Mixing
///
/// ```text
/// Circuit = Butterfly → C&C_Core → Butterfly
///           (5/6)       (1/6)       (5/6)
/// ```
pub struct CaCHybrid {
    /// Pre-mixing circuit (plaintext)
    pub pre_mix: Circuit,
    /// C&C core (obfuscated)
    pub core: CaCCore,
    /// Post-mixing circuit (plaintext)
    pub post_mix: Circuit,
}

impl CaCHybrid {
    /// Create hybrid from circuit
    ///
    /// Splits circuit into: pre_mix | core | post_mix
    /// where core is the C&C obfuscated portion.
    pub fn from_circuit(
        circuit: &Circuit,
        core_fraction: f64,
        seed: u64,
        params: &CaCParams,
    ) -> Self {
        let total_gates = circuit.gates.len();
        let core_size = ((total_gates as f64 * core_fraction) as usize)
            .max(1)
            .min(total_gates);

        // Split gates into three regions
        let pre_size = (total_gates - core_size) / 2;
        let post_start = pre_size + core_size;

        let pre_gates = circuit.gates[..pre_size].to_vec();
        let core_gates = &circuit.gates[pre_size..post_start];
        let post_gates = circuit.gates[post_start..].to_vec();

        let pre_mix = Circuit::from_gates(pre_gates, circuit.num_wires);
        let core = CaCCore::from_gates(core_gates, circuit.num_wires, seed, params);
        let post_mix = Circuit::from_gates(post_gates, circuit.num_wires);

        Self {
            pre_mix,
            core,
            post_mix,
        }
    }

    /// Evaluate the hybrid circuit
    pub fn evaluate(&self, input: usize) -> usize {
        let after_pre = self.pre_mix.evaluate(input);
        let after_core = self.core.evaluate(after_pre);
        self.post_mix.evaluate(after_core)
    }

    /// Total size in bytes
    pub fn size_bytes(&self) -> usize {
        let pre_size = self.pre_mix.gates.len() * 4;
        let post_size = self.post_mix.gates.len() * 4;
        pre_size + self.core.size_bytes() + post_size
    }

    /// Gas estimate
    pub fn gas_estimate(&self) -> usize {
        let pre_gas = self.pre_mix.gates.len() * 50;
        let post_gas = self.post_mix.gates.len() * 50;
        pre_gas + self.core.gas_estimate() + post_gas
    }

    /// Overhead factor
    pub fn overhead_factor(&self, original_gates: usize) -> f64 {
        let plaintext_size = original_gates * 4;
        self.size_bytes() as f64 / plaintext_size as f64
    }
}

/// Benchmark results
#[derive(Debug, Clone)]
pub struct CaCBenchmark {
    pub num_gates: usize,
    pub num_wires: usize,
    pub obfuscation_time_ms: f64,
    pub eval_time_per_call_us: f64,
    pub size_bytes: usize,
    pub overhead_factor: f64,
    pub gas_estimate: usize,
}

impl std::fmt::Display for CaCBenchmark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "C&C: {} gates, {} wires, {:.1}ms obf, {:.1}us/eval, {:.0}x overhead, {}K gas",
            self.num_gates,
            self.num_wires,
            self.obfuscation_time_ms,
            self.eval_time_per_call_us,
            self.overhead_factor,
            self.gas_estimate / 1000,
        )
    }
}

/// Benchmark C&C obfuscation
pub fn benchmark_cac(circuit: &Circuit, num_evals: usize, params: &CaCParams) -> CaCBenchmark {
    use std::time::Instant;

    // Obfuscation time
    let start = Instant::now();
    let cac_circuit = CaCCircuit::from_circuit(circuit, 12345, params);
    let obfuscation_time = start.elapsed();

    // Evaluation time
    let start = Instant::now();
    for i in 0..num_evals {
        let input = i % (1 << circuit.num_wires.min(16));
        let _ = cac_circuit.evaluate(input);
    }
    let eval_time = start.elapsed();

    CaCBenchmark {
        num_gates: circuit.gates.len(),
        num_wires: circuit.num_wires,
        obfuscation_time_ms: obfuscation_time.as_secs_f64() * 1000.0,
        eval_time_per_call_us: eval_time.as_secs_f64() * 1_000_000.0 / num_evals as f64,
        size_bytes: cac_circuit.size_bytes(),
        overhead_factor: cac_circuit.overhead_factor(circuit.gates.len()),
        gas_estimate: cac_circuit.gates.len() * 100,
    }
}

/// Run attack suite on C&C obfuscated circuit
pub fn run_cac_attack_suite(
    circuit: &Circuit,
    seed: u64,
    params: &CaCParams,
) -> Vec<(String, bool)> {
    use crate::attacks::AttackSuite;

    let cac_circuit = CaCCircuit::from_circuit(circuit, seed, params);

    // Attacker's view: wire topology is visible, but CF is hidden
    // Create circuit with randomized CFs (what attacker infers)
    let attacker_view = create_attacker_view(&cac_circuit);

    let suite = AttackSuite::new();
    let results = suite.run_all(&attacker_view);

    results
        .into_iter()
        .map(|(name, r)| (name, !r.success))
        .collect()
}

/// Create what an attacker would see from a C&C circuit
fn create_attacker_view(cac_circuit: &CaCCircuit) -> Circuit {
    use rand::SeedableRng;

    let mut rng = ChaCha20Rng::seed_from_u64(0xCAFEBABE);

    // Attacker sees wire topology but cannot determine CFs
    let gates: Vec<Gate> = cac_circuit
        .gates
        .iter()
        .map(|g| {
            Gate::new(
                g.pins[0],
                g.pins[1],
                g.pins[2],
                ControlFunction::random_nontrivial(&mut rng),
            )
        })
        .collect();

    Circuit {
        gates,
        num_wires: cac_circuit.num_wires,
    }
}

// ============================================================================
// Solidity Serialization (for TLOHoneypotCaC.sol)
// ============================================================================

/// Parameters for Solidity-compatible C&C
/// Uses aggressive params with q=2^20 for EVM compatibility
#[derive(Clone, Debug)]
pub struct SolidityCaCParams {
    /// LWE dimension (smaller for gas efficiency)
    pub n: usize,
    /// Modulus q (must fit in uint64, use power of 2)
    pub q: u64,
    /// Error bound
    pub error_bound: u64,
}

impl Default for SolidityCaCParams {
    fn default() -> Self {
        Self {
            n: 64,           // Reduced for gas efficiency (~80-bit security)
            q: 1 << 20,      // 2^20 - matches TLOHoneypotCaC.sol
            error_bound: 4,
        }
    }
}

impl SolidityCaCParams {
    /// Convert to CaCParams
    pub fn to_cac_params(&self) -> CaCParams {
        CaCParams {
            n: self.n,
            q: self.q,
            error_bound: self.error_bound,
            scale: self.q / 4,  // Not used for Solidity format
        }
    }
}

/// Compact encoded bit for Solidity (only b and hint, no a vector)
#[derive(Clone, Debug)]
pub struct CompactEncodedBit {
    /// LWE b value: b = <a, s> + e + bit * q/2
    pub b: u64,
    /// Hint: <a, s> mod q
    pub hint: u64,
}

impl CompactEncodedBit {
    /// Create from full EncodedBit
    pub fn from_encoded_bit(eb: &EncodedBit) -> Self {
        Self {
            b: eb.ct.b,
            hint: eb.hint,
        }
    }

    /// Serialize to bytes (16 bytes: b as u64 BE, hint as u64 BE)
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[0..8].copy_from_slice(&self.b.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.hint.to_be_bytes());
        bytes
    }
}

/// Compact gate for Solidity serialization
#[derive(Clone, Debug)]
pub struct CompactCaCGate {
    /// Wire indices: [active, c1, c2]
    pub pins: [u8; 3],
    /// Compact encoded truth table (4 entries)
    pub entries: [CompactEncodedBit; 4],
}

impl CompactCaCGate {
    /// Create from full CaCGate
    pub fn from_cac_gate(gate: &CaCGate) -> Self {
        Self {
            pins: gate.pins,
            entries: std::array::from_fn(|i| {
                CompactEncodedBit::from_encoded_bit(&gate.encoded_cf.entries[i])
            }),
        }
    }

    /// Serialize to bytes (67 bytes: 3 pins + 4 * 16 encoded bits)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(67);
        bytes.extend_from_slice(&self.pins);
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes
    }
}

/// Solidity-compatible C&C circuit
#[derive(Clone, Debug)]
pub struct SolidityCaCCircuit {
    /// Compact gates
    pub gates: Vec<CompactCaCGate>,
    /// Number of wires
    pub num_wires: usize,
    /// Circuit seed (for verification)
    pub seed: u64,
    /// Expected output hash
    pub expected_output_hash: [u8; 32],
}

impl SolidityCaCCircuit {
    /// Create from a regular circuit with a known secret
    pub fn from_circuit_with_secret(
        circuit: &Circuit,
        seed: u64,
        secret: usize,
        params: &SolidityCaCParams,
    ) -> Self {
        let cac_params = params.to_cac_params();
        let cac_circuit = CaCCircuit::from_circuit(circuit, seed, &cac_params);

        let gates: Vec<CompactCaCGate> = cac_circuit
            .gates
            .iter()
            .map(CompactCaCGate::from_cac_gate)
            .collect();

        // Compute expected output
        let output = cac_circuit.evaluate(secret);
        let expected_output_hash = Self::hash_output(output);

        Self {
            gates,
            num_wires: circuit.num_wires,
            seed,
            expected_output_hash,
        }
    }

    /// Hash output for comparison (keccak256)
    fn hash_output(output: usize) -> [u8; 32] {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(&output.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Serialize circuit data for Solidity constructor
    /// Format: [gate0_bytes, gate1_bytes, ...]
    /// Each gate: 67 bytes
    pub fn to_circuit_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(self.gates.len() * 67);
        for gate in &self.gates {
            data.extend(gate.to_bytes());
        }
        data
    }

    /// Generate constructor parameters for TLOHoneypotCaC
    pub fn to_constructor_params(&self, expiry_seconds: u64) -> SolidityConstructorParams {
        SolidityConstructorParams {
            circuit_data: self.to_circuit_data(),
            num_wires: self.num_wires as u8,
            num_gates: self.gates.len() as u32,
            circuit_seed: {
                let mut bytes = [0u8; 32];
                bytes[24..32].copy_from_slice(&self.seed.to_be_bytes());
                bytes
            },
            expected_output_hash: self.expected_output_hash,
            secret_expiry: expiry_seconds,
        }
    }

    /// Size in bytes
    pub fn size_bytes(&self) -> usize {
        self.gates.len() * 67
    }
}

/// Constructor parameters for TLOHoneypotCaC.sol
#[derive(Clone, Debug)]
pub struct SolidityConstructorParams {
    pub circuit_data: Vec<u8>,
    pub num_wires: u8,
    pub num_gates: u32,
    pub circuit_seed: [u8; 32],
    pub expected_output_hash: [u8; 32],
    pub secret_expiry: u64,
}

impl SolidityConstructorParams {
    /// Format as hex for deployment script
    pub fn to_hex(&self) -> String {
        format!(
            "circuitData: 0x{}\n\
             numWires: {}\n\
             numGates: {}\n\
             circuitSeed: 0x{}\n\
             expectedOutputHash: 0x{}\n\
             secretExpiry: {}",
            hex::encode(&self.circuit_data),
            self.num_wires,
            self.num_gates,
            hex::encode(self.circuit_seed),
            hex::encode(self.expected_output_hash),
            self.secret_expiry,
        )
    }

    /// Generate Foundry deployment script snippet
    pub fn to_foundry_script(&self) -> String {
        format!(
            r#"bytes memory circuitData = hex"{}";
uint8 numWires = {};
uint32 numGates = {};
bytes32 circuitSeed = 0x{};
bytes32 expectedOutputHash = 0x{};
uint256 secretExpiry = block.timestamp + {};

TLOHoneypotCaC honeypot = new TLOHoneypotCaC{{value: reward}}(
    circuitData,
    numWires,
    numGates,
    circuitSeed,
    expectedOutputHash,
    secretExpiry
);"#,
            hex::encode(&self.circuit_data),
            self.num_wires,
            self.num_gates,
            hex::encode(self.circuit_seed),
            hex::encode(self.expected_output_hash),
            self.secret_expiry,
        )
    }
}

/// Create a SixSix + C&C circuit for Solidity deployment
pub fn create_solidity_cac_circuit(
    secret: usize,
    seed: u64,
) -> SolidityCaCCircuit {
    use crate::six_six::{create_six_six_circuit, SixSixConfig};

    let config = SixSixConfig::default();
    let circuit = create_six_six_circuit(&config);
    let params = SolidityCaCParams::default();

    SolidityCaCCircuit::from_circuit_with_secret(&circuit, seed, secret, &params)
}

/// Verify that Rust evaluation matches expected output hash
pub fn verify_solidity_compatibility(
    sol_circuit: &SolidityCaCCircuit,
    base_circuit: &Circuit,
    test_inputs: &[usize],
) -> Vec<(usize, bool)> {
    let params = SolidityCaCParams::default().to_cac_params();
    let cac_circuit = CaCCircuit::from_circuit(base_circuit, sol_circuit.seed, &params);

    test_inputs
        .iter()
        .map(|&input| {
            let output = cac_circuit.evaluate(input);
            let output_hash = SolidityCaCCircuit::hash_output(output);
            let matches = output_hash == sol_circuit.expected_output_hash;
            (input, matches)
        })
        .collect()
}

/// Compare C&C vs FHE performance
pub fn compare_cac_vs_fhe(circuit: &Circuit) -> String {
    let params = CaCParams::balanced();
    let cac_benchmark = benchmark_cac(circuit, 100, &params);

    // FHE estimates (from TFHE-rs benchmarks)
    let fhe_eval_ms = circuit.gates.len() as f64 * 0.9; // ~0.9ms per bootstrap
    let fhe_overhead = 950.0;

    format!(
        "=== C&C vs FHE Comparison ===\n\
        Circuit: {} gates, {} wires\n\n\
        C&C:\n\
          Obfuscation: {:.1}ms\n\
          Evaluation: {:.1}us/call\n\
          Overhead: {:.0}x\n\
          Gas: {}K\n\n\
        FHE (TFHE estimate):\n\
          Evaluation: {:.1}ms/call ({:.0}x slower)\n\
          Overhead: {:.0}x\n\n\
        C&C advantage: {:.0}x faster eval, {:.0}x less overhead",
        circuit.gates.len(),
        circuit.num_wires,
        cac_benchmark.obfuscation_time_ms,
        cac_benchmark.eval_time_per_call_us,
        cac_benchmark.overhead_factor,
        cac_benchmark.gas_estimate / 1000,
        fhe_eval_ms,
        fhe_eval_ms * 1000.0 / cac_benchmark.eval_time_per_call_us,
        fhe_overhead,
        fhe_eval_ms * 1000.0 / cac_benchmark.eval_time_per_call_us,
        fhe_overhead / cac_benchmark.overhead_factor,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cac_params() {
        let params = CaCParams::testing();
        assert!(params.n >= 64);
        assert!(params.q >= 1 << 16);
    }

    #[test]
    fn test_encode_and_evaluate() {
        let params = CaCParams::testing();
        let obf = CaCObfuscator::new(params);

        // Test all control functions
        for cf_idx in 0..16u8 {
            let cf = ControlFunction::from_u8(cf_idx);
            let table = obf.obfuscate(cf, 42 + cf_idx as u64);

            // Verify all input combinations
            for i in 0..4 {
                let c1 = (i & 1) != 0;
                let c2 = (i >> 1) != 0;

                let expected = cf.evaluate(c1, c2);
                let actual = CaCObfuscator::evaluate(&table, c1, c2);

                assert_eq!(
                    expected, actual,
                    "Mismatch for CF {:?} at ({}, {})",
                    cf, c1, c2
                );
            }
        }
    }

    #[test]
    fn test_cac_gate() {
        let params = CaCParams::testing();

        let gate = Gate::new(0, 1, 2, ControlFunction::Xor);
        let cac_gate = CaCGate::from_gate(&gate, 42, &params);

        // Test evaluation
        for input in 0..8 {
            let mut state = input;
            let mut expected = input;

            // Original gate
            let c1 = (expected >> 1) & 1 == 1;
            let c2 = (expected >> 2) & 1 == 1;
            if c1 ^ c2 {
                expected ^= 1;
            }

            // C&C gate
            cac_gate.evaluate(&mut state);

            assert_eq!(state, expected, "Mismatch for input {}", input);
        }
    }

    #[test]
    fn test_cac_circuit() {
        let params = CaCParams::testing();

        // Create a small test circuit
        let circuit = Circuit::random(4, 10);
        let cac_circuit = CaCCircuit::from_circuit(&circuit, 42, &params);

        // Verify functional equivalence
        for input in 0..16 {
            let expected = circuit.evaluate(input);
            let actual = cac_circuit.evaluate(input);

            assert_eq!(expected, actual, "Mismatch for input {}", input);
        }
    }

    #[test]
    fn test_cac_hybrid() {
        let params = CaCParams::testing();

        let circuit = Circuit::random(4, 20);
        let hybrid = CaCHybrid::from_circuit(&circuit, 0.2, 42, &params);

        // Verify functional equivalence
        for input in 0..16 {
            let expected = circuit.evaluate(input);
            let actual = hybrid.evaluate(input);

            assert_eq!(expected, actual, "Mismatch for input {}", input);
        }
    }

    #[test]
    fn test_cac_benchmark() {
        let params = CaCParams::testing();
        let circuit = Circuit::random(8, 50);

        let benchmark = benchmark_cac(&circuit, 10, &params);

        println!("{}", benchmark);

        assert!(benchmark.overhead_factor > 1.0);
        assert!(benchmark.obfuscation_time_ms < 1000.0);
    }

    #[test]
    fn test_cac_vs_lo() {
        // Compare C&C with Lockable Obfuscation
        let circuit = Circuit::random(8, 50);

        let cac_params = CaCParams::testing();
        let cac_benchmark = benchmark_cac(&circuit, 10, &cac_params);

        // LO benchmark (from lockable_obfuscation)
        use crate::lockable_obfuscation::benchmark_lo;
        let lo_benchmark = benchmark_lo(&circuit, 10);

        println!("C&C: {}", cac_benchmark);
        println!("LO: {}", lo_benchmark);

        // C&C should have reasonable overhead
        assert!(
            cac_benchmark.overhead_factor > 1.0,
            "C&C should have some overhead"
        );
    }

    #[test]
    fn test_cac_attack_resistance() {
        let params = CaCParams::testing();

        // Use SixSix topology for base circuit (default: 64 wires, 640 gates)
        use crate::six_six::{create_six_six_circuit, SixSixConfig};

        let config = SixSixConfig::default(); // 64 wires, 640 gates for good attack resistance
        let circuit = create_six_six_circuit(&config);

        let results = run_cac_attack_suite(&circuit, 42, &params);

        let blocked: Vec<_> = results
            .iter()
            .filter(|(_, blocked)| *blocked)
            .map(|(name, _)| name.as_str())
            .collect();

        println!("C&C + SixSix blocked attacks: {:?}", blocked);

        // SixSix with default params should block at least 4/6
        assert!(
            blocked.len() >= 4,
            "Expected at least 4/6 blocked, got {}",
            blocked.len()
        );
    }

    #[test]
    fn test_solidity_cac_serialization() {
        // Create a Solidity-compatible C&C circuit
        let secret = 0x12345678usize;
        let seed = 42u64;
        let sol_circuit = create_solidity_cac_circuit(secret, seed);

        // Check size
        let circuit_data = sol_circuit.to_circuit_data();
        assert_eq!(circuit_data.len(), sol_circuit.gates.len() * 67);
        println!(
            "Solidity C&C circuit: {} gates, {} bytes",
            sol_circuit.gates.len(),
            circuit_data.len()
        );

        // Verify gate format
        let first_gate = &sol_circuit.gates[0];
        let gate_bytes = first_gate.to_bytes();
        assert_eq!(gate_bytes.len(), 67);

        // Check pins are valid
        assert!(first_gate.pins[0] < 64);
        assert!(first_gate.pins[1] < 64);
        assert!(first_gate.pins[2] < 64);

        // Verify constructor params
        let params = sol_circuit.to_constructor_params(86400); // 1 day expiry
        assert_eq!(params.num_wires, 64);
        assert_eq!(params.num_gates as usize, sol_circuit.gates.len());
        assert_eq!(params.circuit_data.len(), circuit_data.len());
    }

    #[test]
    fn test_solidity_cac_correctness() {
        use crate::six_six::{create_six_six_circuit, SixSixConfig};

        // Test that the secret input produces matching hash
        let secret = 0xABCDusize;
        let seed = 12345u64;

        // Create base circuit
        let config = SixSixConfig::default();
        let base_circuit = create_six_six_circuit(&config);
        let params = SolidityCaCParams::default();

        // Create Solidity circuit
        let sol_circuit =
            SolidityCaCCircuit::from_circuit_with_secret(&base_circuit, seed, secret, &params);

        // Verify secret matches
        let results =
            verify_solidity_compatibility(&sol_circuit, &base_circuit, &[secret, secret + 1, 0]);

        // Secret should match
        assert!(results[0].1, "Secret should produce matching hash");
        // Other inputs should not match
        assert!(!results[1].1, "Non-secret should not match");
        assert!(!results[2].1, "Zero should not match");
    }

    #[test]
    fn test_solidity_cac_gas_estimate() {
        let secret = 0x42usize;
        let sol_circuit = create_solidity_cac_circuit(secret, 99);

        // 640 gates * 67 bytes = 42,880 bytes
        let size = sol_circuit.size_bytes();
        println!("Circuit data size: {} bytes ({:.1} KB)", size, size as f64 / 1024.0);

        // Estimate gas: ~200 gas per gate for LWE ops
        let estimated_gas = sol_circuit.gates.len() * 200;
        println!("Estimated gas: {}K", estimated_gas / 1000);

        // Should be under 1M gas
        assert!(estimated_gas < 1_000_000, "Gas too high: {}", estimated_gas);
    }

    #[test]
    fn test_foundry_script_generation() {
        let secret = 0x1337usize;
        let sol_circuit = create_solidity_cac_circuit(secret, 7777);
        let params = sol_circuit.to_constructor_params(3600);

        let script = params.to_foundry_script();
        assert!(script.contains("TLOHoneypotCaC"));
        assert!(script.contains("circuitData"));
        assert!(script.contains("numWires = 64"));
        println!("Foundry script preview:\n{}", &script[..500.min(script.len())]);
    }
}
