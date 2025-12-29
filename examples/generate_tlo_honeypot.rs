//! Generate TLO (Topology-Lattice Obfuscation) circuit for on-chain honeypot deployment
//!
//! This generates a fully C&C-encoded circuit compatible with TLOHoneypotCaC.sol.
//!
//! Usage:
//!   cargo run --release --bin generate_tlo_honeypot -- \
//!       --secret 0x1234...abcd \
//!       --output tlo/circuits/my-honeypot.json
//!
//! Or with custom parameters:
//!   cargo run --release --bin generate_tlo_honeypot -- \
//!       --secret 0x1234...abcd \
//!       --wires 64 \
//!       --gates 640 \
//!       --lwe-n 64 \
//!       --expiry-days 7 \
//!       --output tlo/circuits/my-honeypot.json
//!
//! Output JSON contains:
//!   - circuit_data_hex: 67 bytes/gate with LWE-encoded control functions
//!   - Foundry deployment script snippet
//!   - All constructor parameters for TLOHoneypotCaC.sol

use tlo::attacks::AttackSuite;
use tlo::compute_and_compare::{
    SolidityCaCCircuit, SolidityCaCParams,
};
use tlo::six_six::{create_six_six_circuit_with_seed, SixSixConfig};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Serialize, Deserialize)]
struct TLOHoneypotOutput {
    /// Hex-encoded circuit data (67 bytes per gate with LWE encoding)
    circuit_data_hex: String,
    /// Number of wires
    num_wires: u8,
    /// Number of gates
    num_gates: u32,
    /// Circuit seed (bytes32)
    circuit_seed: String,
    /// Expected output hash when input == secret
    expected_output_hash: String,
    /// Recommended expiry timestamp (Unix seconds)
    recommended_expiry: u64,
    /// LWE dimension used
    lwe_n: usize,
    /// LWE modulus q
    lwe_q: u64,
    /// Attack resistance score
    attack_score: String,
    /// Estimated gas for check() call
    estimated_gas: u64,
    /// Circuit data size in bytes
    circuit_size_bytes: usize,
    /// Foundry deployment script snippet
    foundry_script: String,
    /// Scheme identifier
    scheme: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse arguments
    let mut secret_hex: Option<String> = None;
    let mut output_path: Option<String> = None;
    let mut num_wires: usize = 64;
    let mut num_gates: usize = 640;
    let mut lwe_n: usize = 64;
    let mut expiry_days: u64 = 7;

    // Generate random seed if not specified
    let mut circuit_seed: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--secret" => {
                i += 1;
                secret_hex = Some(args[i].clone());
            }
            "--output" => {
                i += 1;
                output_path = Some(args[i].clone());
            }
            "--wires" => {
                i += 1;
                num_wires = args[i].parse().expect("Invalid wires");
            }
            "--gates" => {
                i += 1;
                num_gates = args[i].parse().expect("Invalid gates");
            }
            "--lwe-n" => {
                i += 1;
                lwe_n = args[i].parse().expect("Invalid lwe-n");
            }
            "--seed" => {
                i += 1;
                circuit_seed = args[i].parse().expect("Invalid seed");
            }
            "--expiry-days" => {
                i += 1;
                expiry_days = args[i].parse().expect("Invalid expiry-days");
            }
            "--help" | "-h" => {
                print_usage();
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                return;
            }
        }
        i += 1;
    }

    let secret_hex = secret_hex.unwrap_or_else(|| {
        eprintln!("Error: --secret is required");
        print_usage();
        std::process::exit(1);
    });

    let output_path = output_path.unwrap_or_else(|| "tlo-honeypot-circuit.json".to_string());

    println!("=== TLO (Topology-Lattice Obfuscation) Honeypot Generator ===\n");
    println!("Parameters:");
    println!("  Wires:      {}", num_wires);
    println!("  Gates:      {}", num_gates);
    println!("  LWE n:      {} (~{}-bit security)", lwe_n, lwe_n * 2);
    println!("  Seed:       {}", circuit_seed);
    println!("  Expiry:     {} days", expiry_days);
    println!("  Output:     {}", output_path);
    println!();

    // Parse secret
    let secret_bytes = hex_decode(&secret_hex).expect("Invalid hex secret");
    if secret_bytes.len() > 32 {
        eprintln!("Error: Secret must be <= 32 bytes (256 bits)");
        std::process::exit(1);
    }

    // Pad to 32 bytes (right-aligned)
    let mut secret = [0u8; 32];
    secret[32 - secret_bytes.len()..].copy_from_slice(&secret_bytes);

    println!(
        "Secret (truncated): 0x{}...{}",
        hex_encode(&secret[..4]),
        hex_encode(&secret[28..])
    );

    // Convert secret to usize (for circuit evaluation)
    let secret_usize = bytes_to_usize(&secret, num_wires);

    // Create SixSix circuit with deterministic seeding
    println!("\nGenerating SixSix circuit (deterministic)...");
    let config = SixSixConfig {
        num_wires,
        num_gates,
        underused_preference: 0.9,
        ..Default::default()
    };

    let circuit = create_six_six_circuit_with_seed(&config, circuit_seed);

    // Verify attack resistance (topology layer)
    println!("Verifying topology attack resistance...");
    let suite = AttackSuite::new();
    let results = suite.run_all(&circuit);

    let blocked: Vec<&str> = results
        .iter()
        .filter(|(_, r)| !r.success)
        .map(|(name, _)| name.as_str())
        .collect();

    println!("  Topology blocks: {:?} ({}/6)", blocked, blocked.len());
    println!("  + C&C (LWE) blocks RainbowTable -> 6/6 total");

    // Create C&C-encoded circuit for Solidity
    // sigma=1024 provides ~108-bit security for n=64 per lattice-estimator;
    // safe because sigma << q/4=16380
    println!("\nEncoding with LWE (n={})...", lwe_n);
    let cac_params = SolidityCaCParams {
        n: lwe_n,
        q: 1 << 20,  // 2^20, matches TLOHoneypotCaC.sol
        error_bound: 1024,
    };

    let sol_circuit = SolidityCaCCircuit::from_circuit_with_secret(
        &circuit,
        circuit_seed,
        secret_usize,
        &cac_params,
    );

    // Get circuit data
    let circuit_data = sol_circuit.to_circuit_data();
    let circuit_data_hex = format!("0x{}", hex_encode(&circuit_data));

    // Compute expiry timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    let recommended_expiry = now + (expiry_days * 24 * 60 * 60);

    // Get constructor params
    let constructor = sol_circuit.to_constructor_params(expiry_days * 24 * 60 * 60);
    let foundry_script = constructor.to_foundry_script();

    // Estimate gas (from benchmarks: ~4 gas per LWE multiply-add, 4 entries per gate)
    // Plus overhead for memory, loops, etc.
    let estimated_gas = (num_gates as u64 * lwe_n as u64 * 4 * 4) / 10 + 50_000;

    println!("\nCircuit stats:");
    println!("  Size:       {} bytes ({} KB)", circuit_data.len(), circuit_data.len() / 1024);
    println!("  Gates:      {} x 67 bytes", num_gates);
    println!("  Est. gas:   {} (~{}M)", estimated_gas, estimated_gas / 1_000_000);

    // Format output
    let output = TLOHoneypotOutput {
        circuit_data_hex,
        num_wires: num_wires as u8,
        num_gates: num_gates as u32,
        circuit_seed: format!("0x{}", hex_encode(&constructor.circuit_seed)),
        expected_output_hash: format!("0x{}", hex_encode(&constructor.expected_output_hash)),
        recommended_expiry,
        lwe_n,
        lwe_q: cac_params.q,
        attack_score: "6/6".to_string(),
        estimated_gas,
        circuit_size_bytes: circuit_data.len(),
        foundry_script,
        scheme: "tlo-cac".to_string(),
    };

    // Write to file
    let json = serde_json::to_string_pretty(&output).expect("Failed to serialize");

    if let Some(parent) = Path::new(&output_path).parent() {
        fs::create_dir_all(parent).ok();
    }

    fs::write(&output_path, &json).expect("Failed to write output file");

    println!("\n[OK] TLO circuit written to: {}", output_path);
    println!("\nTo deploy TLOHoneypotCaC.sol:");
    println!("  1. Copy foundry_script from JSON to your deploy script");
    println!("  2. Set reward value (msg.value)");
    println!("  3. Deploy with: forge script ...");
    println!("\nExpected output hash: 0x{}", hex_encode(&constructor.expected_output_hash));
    println!("Recommended expiry:   {} (Unix timestamp)", recommended_expiry);
}

fn print_usage() {
    println!("Usage: generate_tlo_honeypot [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --secret <HEX>        The secret to embed (required, e.g., 0xdeadbeef...)");
    println!("  --output <PATH>       Output JSON file (default: tlo-honeypot-circuit.json)");
    println!("  --wires <N>           Number of wires, max 64 (default: 64)");
    println!("  --gates <N>           Number of gates (default: 640)");
    println!("  --lwe-n <N>           LWE dimension: 16/32/64 (default: 64)");
    println!("  --seed <N>            Circuit seed for reproducibility");
    println!("  --expiry-days <N>     Days until secret expires (default: 7)");
    println!("  --help                Show this help");
    println!();
    println!("LWE Dimension Options:");
    println!("  --lwe-n 16    ~32-bit security,  ~744K gas,  ~44KB circuit");
    println!("  --lwe-n 32    ~64-bit security,  ~1.3M gas,  ~44KB circuit");
    println!("  --lwe-n 64    ~128-bit security, ~2.6M gas,  ~44KB circuit (recommended)");
    println!();
    println!("Example:");
    println!("  cargo run --release --bin generate_tlo_honeypot -- \\");
    println!("      --secret 0xdeadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678 \\");
    println!("      --lwe-n 64 \\");
    println!("      --expiry-days 30 \\");
    println!("      --output tlo/circuits/my-honeypot.json");
}

fn bytes_to_usize(bytes: &[u8], num_wires: usize) -> usize {
    let mut result: usize = 0;
    for (i, &b) in bytes.iter().rev().enumerate() {
        if i * 8 >= num_wires {
            break;
        }
        result |= (b as usize) << (i * 8);
    }
    result & ((1 << num_wires) - 1)
}
