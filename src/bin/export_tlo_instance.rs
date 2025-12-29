//! Export TLO Instance for Lattice Attack
//!
//! Generates a real TLO circuit and exports the LWE ciphertexts
//! in JSON format for the Python attack script.
//!
//! Usage:
//!     cargo run --release --bin export_tlo_instance -- --n 16 --gates 64 --output instance.json
//!     cargo run --release --bin export_tlo_instance -- --n 64 --gates 640 --output prod.json

use tlo::circuit::Circuit;
use tlo::six_six::{create_six_six_circuit_with_rng, SixSixConfig};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;

/// TLO LWE parameters
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TloParams {
    n: usize,      // LWE dimension
    q: u64,        // modulus (65521)
    sigma: f64,    // noise std dev
    num_gates: usize,
}

impl TloParams {
    fn new(n: usize, num_gates: usize) -> Self {
        let q = 65521u64; // largest 16-bit prime
        // sigma=1024 provides ~108-bit security for n=64 (validated via lattice-estimator)
        // Safe because sigma << q/4 = 16380, so decryption error is negligible
        let sigma = 1024.0;
        Self { n, q, sigma, num_gates }
    }
}

/// A single LWE ciphertext
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LweCiphertext {
    a: Vec<u64>,  // n elements
    b: u64,
}

/// Exported TLO instance for attack
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TloInstance {
    // Parameters
    n: usize,
    q: u64,
    sigma: f64,
    m: usize,  // total number of samples (4 * num_gates)
    num_gates: usize,
    num_wires: usize,
    
    // LWE data (flattened for easier JSON)
    // A is m x n matrix, stored row-major
    #[serde(rename = "A")]
    a_matrix: Vec<Vec<u64>>,
    b_vector: Vec<u64>,
    
    // Ground truth (for verification - would NOT be available to attacker)
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mu_bits: Option<Vec<u8>>,  // plaintext CF bits
    
    // Metadata
    seed: u64,
    secret_input: Option<u64>,
}

/// Generate LWE secret from input using hash
fn derive_secret(input: u64, n: usize, q: u64) -> Vec<u64> {
    let mut hasher = Sha256::new();
    hasher.update(input.to_le_bytes());
    let hash = hasher.finalize();
    
    // Expand hash to n elements using additional hashing
    let mut secret = Vec::with_capacity(n);
    let mut counter = 0u64;
    
    while secret.len() < n {
        let mut h = Sha256::new();
        h.update(&hash);
        h.update(counter.to_le_bytes());
        let expanded = h.finalize();
        
        // Extract u64 values from hash
        for chunk in expanded.chunks(8) {
            if secret.len() >= n {
                break;
            }
            let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            secret.push(val % q);
        }
        counter += 1;
    }
    
    secret.truncate(n);
    secret
}

/// Encrypt a single bit using LWE
fn encrypt_bit(
    bit: bool,
    secret: &[u64],
    params: &TloParams,
    rng: &mut impl rand::Rng,
) -> LweCiphertext {
    let n = params.n;
    let q = params.q;
    let sigma = params.sigma;
    
    // Random a vector
    let a: Vec<u64> = (0..n).map(|_| rng.gen_range(0..q)).collect();
    
    // Inner product <a, s>
    let inner: u64 = a.iter()
        .zip(secret.iter())
        .map(|(ai, si)| ((*ai as u128 * *si as u128) % q as u128) as u64)
        .fold(0u64, |acc, x| (acc + x) % q);
    
    // Gaussian noise (approximated via sum of uniforms)
    let noise_f: f64 = (rng.gen::<f64>() * 2.0 - 1.0 + 
                        rng.gen::<f64>() * 2.0 - 1.0 +
                        rng.gen::<f64>() * 2.0 - 1.0) * sigma / 1.732;
    let noise: i64 = noise_f.round() as i64;
    let noise_mod = ((noise % q as i64) + q as i64) as u64 % q;
    
    // b = <a, s> + e + bit * q/2
    let msg_contribution = if bit { q / 2 } else { 0 };
    let b = (inner + noise_mod + msg_contribution) % q;
    
    LweCiphertext { a, b }
}

/// Generate a complete TLO instance
fn generate_tlo_instance(
    params: &TloParams,
    secret_input: u64,
    seed: u64,
) -> TloInstance {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    
    // Create circuit with SixSix topology
    let circuit_config = SixSixConfig {
        num_wires: 64,  // Fixed for now
        num_gates: params.num_gates,
        ..SixSixConfig::default()
    };
    let circuit = create_six_six_circuit_with_rng(&circuit_config, &mut rng);
    
    // Derive LWE secret from the secret input
    let secret = derive_secret(secret_input, params.n, params.q);
    
    // Generate ciphertexts for each gate's control function
    let mut a_matrix = Vec::new();
    let mut b_vector = Vec::new();
    let mut mu_bits = Vec::new();
    
    for gate in &circuit.gates {
        // Each gate has 4 CF bits (truth table)
        let cf = gate.control_function;
        for i in 0..4 {
            let c1 = (i & 1) != 0;
            let c2 = (i >> 1) != 0;
            let bit = cf.evaluate(c1, c2);
            
            let ct = encrypt_bit(bit, &secret, params, &mut rng);
            a_matrix.push(ct.a);
            b_vector.push(ct.b);
            mu_bits.push(bit as u8);
        }
    }
    
    let m = a_matrix.len();
    
    TloInstance {
        n: params.n,
        q: params.q,
        sigma: params.sigma,
        m,
        num_gates: params.num_gates,
        num_wires: circuit.num_wires,
        a_matrix,
        b_vector,
        secret: Some(secret),
        mu_bits: Some(mu_bits),
        seed,
        secret_input: Some(secret_input),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Parse arguments
    let mut n = 64usize;
    let mut num_gates = 640usize;
    let mut output = "tlo_instance.json".to_string();
    let mut seed = 42u64;
    let mut secret_input = 0x1337u64;
    let mut include_secret = true;
    
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--n" => {
                n = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--gates" => {
                num_gates = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--output" | "-o" => {
                output = args[i + 1].clone();
                i += 2;
            }
            "--seed" => {
                seed = args[i + 1].parse().unwrap();
                i += 2;
            }
            "--secret" => {
                secret_input = u64::from_str_radix(&args[i + 1].trim_start_matches("0x"), 16)
                    .unwrap_or_else(|_| args[i + 1].parse().unwrap());
                i += 2;
            }
            "--no-ground-truth" => {
                include_secret = false;
                i += 1;
            }
            "--help" | "-h" => {
                println!("Export TLO Instance for Lattice Attack");
                println!();
                println!("Usage: export_tlo_instance [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --n <N>              LWE dimension (default: 64)");
                println!("  --gates <N>          Number of gates (default: 640)");
                println!("  --output <FILE>      Output JSON file (default: tlo_instance.json)");
                println!("  --seed <N>           Random seed (default: 42)");
                println!("  --secret <N>         Secret input value (default: 0x1337)");
                println!("  --no-ground-truth    Don't include secret/mu in output");
                println!();
                println!("Examples:");
                println!("  # Small instance for testing attack");
                println!("  export_tlo_instance --n 16 --gates 64 -o small.json");
                println!();
                println!("  # Production-size instance");
                println!("  export_tlo_instance --n 64 --gates 640 -o prod.json");
                println!();
                println!("  # Instance without ground truth (for blind testing)");
                println!("  export_tlo_instance --n 32 --gates 160 --no-ground-truth -o blind.json");
                return;
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                i += 1;
            }
        }
    }
    
    let params = TloParams::new(n, num_gates);
    
    println!("Generating TLO instance...");
    println!("  LWE dimension n: {}", n);
    println!("  Number of gates: {}", num_gates);
    println!("  Number of samples m: {}", 4 * num_gates);
    println!("  Modulus q: {}", params.q);
    println!("  Noise sigma: {:.2}", params.sigma);
    println!("  Seed: {}", seed);
    println!("  Secret input: 0x{:x}", secret_input);
    
    let mut instance = generate_tlo_instance(&params, secret_input, seed);
    
    if !include_secret {
        instance.secret = None;
        instance.mu_bits = None;
        instance.secret_input = None;
        println!("  Ground truth: EXCLUDED");
    } else {
        println!("  Ground truth: INCLUDED (for verification)");
    }
    
    // Write to file
    let json = serde_json::to_string_pretty(&instance).unwrap();
    let mut file = File::create(&output).unwrap();
    file.write_all(json.as_bytes()).unwrap();
    
    let size_kb = json.len() as f64 / 1024.0;
    println!();
    println!("Written to: {}", output);
    println!("File size: {:.1} KB", size_kb);
    
    // Print attack guidance
    println!();
    println!("To attack this instance:");
    println!("  python scripts/lattice_attack/break_tlo.py --instance {}", output);
}
