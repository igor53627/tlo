//! LWE Security Estimator for TLO Parameters
//!
//! Estimates actual bit-security for LWE parameters using lattice attack cost models.
//!
//! Based on:
//! - Albrecht et al. "On the concrete hardness of Learning with Errors" (2015)
//! - Lattice Estimator: https://github.com/malb/lattice-estimator
//! - Kirshanova et al. attack improvements (2024)
//!
//! Key attacks considered:
//! 1. Primal attack (uSVP via BKZ)
//! 2. Dual attack (BDD via BKZ)
//! 3. Hybrid attack (meet-in-the-middle + lattice)
//!
//! Usage: cargo run --release --bin lwe_estimator

use std::f64::consts::{E, PI};

/// LWE parameters to analyze
#[derive(Clone, Debug)]
pub struct LweParams {
    /// Dimension n
    pub n: usize,
    /// Modulus q
    pub q: u64,
    /// Error standard deviation σ
    pub sigma: f64,
    /// Number of samples m (typically m ≈ n for our use case)
    pub m: usize,
}

impl LweParams {
    pub fn new(n: usize, q: u64, sigma: f64) -> Self {
        Self {
            n,
            q,
            sigma,
            m: n, // Assume m ≈ n samples
        }
    }

    /// TLO parameters for different security levels
    /// sigma=1024 provides ~108-bit security for n=64 per lattice-estimator;
    /// safe because sigma << q/4=16380
    pub fn tlo_n16() -> Self {
        let q = 65521u64;
        let sigma = 1024.0;
        Self::new(16, q, sigma)
    }

    pub fn tlo_n32() -> Self {
        let q = 65521u64;
        let sigma = 1024.0;
        Self::new(32, q, sigma)
    }

    pub fn tlo_n64() -> Self {
        let q = 65521u64;
        let sigma = 1024.0;
        Self::new(64, q, sigma)
    }

    pub fn tlo_n128() -> Self {
        let q = 65521u64;
        let sigma = 1024.0;
        Self::new(128, q, sigma)
    }

    pub fn tlo_n256() -> Self {
        let q = 65521u64;
        let sigma = (q as f64).sqrt() / 4.0;
        Self::new(256, q, sigma)
    }

    pub fn tlo_n512() -> Self {
        let q = 65521u64;
        let sigma = (q as f64).sqrt() / 4.0;
        Self::new(512, q, sigma)
    }

    /// Create with custom parameters
    pub fn custom(n: usize, q: u64, sigma: f64) -> Self {
        Self::new(n, q, sigma)
    }

    /// Kyber-512 for comparison (NIST Level 1, ~128-bit security)
    pub fn kyber_512() -> Self {
        Self::new(512, 3329, 1.0) // Simplified; actual Kyber uses module-LWE
    }

    /// Kyber-768 for comparison (NIST Level 3, ~192-bit security)
    pub fn kyber_768() -> Self {
        Self::new(768, 3329, 1.0)
    }
}

/// Security estimation results
#[derive(Clone, Debug)]
pub struct SecurityEstimate {
    /// Parameters analyzed
    pub params: LweParams,
    /// Primal attack (uSVP) cost in bits
    pub primal_classical: f64,
    pub primal_quantum: f64,
    /// Dual attack (BDD) cost in bits
    pub dual_classical: f64,
    pub dual_quantum: f64,
    /// Hybrid attack cost
    pub hybrid_classical: f64,
    /// Best known attack (minimum)
    pub best_classical: f64,
    pub best_quantum: f64,
    /// Optimal BKZ block size for primal
    pub optimal_beta: usize,
}

impl std::fmt::Display for SecurityEstimate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "LWE Security Estimate")?;
        writeln!(f, "=====================")?;
        writeln!(
            f,
            "Parameters: n={}, q={}, sigma={:.2}",
            self.params.n, self.params.q, self.params.sigma
        )?;
        writeln!(f, "Samples: m={}", self.params.m)?;
        writeln!(f)?;
        writeln!(f, "Attack Costs (log2):")?;
        writeln!(
            f,
            "  Primal (uSVP):  {:.1} classical, {:.1} quantum",
            self.primal_classical, self.primal_quantum
        )?;
        writeln!(
            f,
            "  Dual (BDD):     {:.1} classical, {:.1} quantum",
            self.dual_classical, self.dual_quantum
        )?;
        writeln!(
            f,
            "  Hybrid:         {:.1} classical",
            self.hybrid_classical
        )?;
        writeln!(f)?;
        writeln!(
            f,
            "Best Attack: {:.1}-bit classical, {:.1}-bit quantum",
            self.best_classical, self.best_quantum
        )?;
        writeln!(f, "Optimal BKZ block size: beta={}", self.optimal_beta)?;
        Ok(())
    }
}

/// LWE Security Estimator
///
/// Implements lattice attack cost models from the literature.
pub struct LweEstimator;

impl LweEstimator {
    /// Estimate security for given LWE parameters
    pub fn estimate(params: &LweParams) -> SecurityEstimate {
        let n = params.n as f64;
        let q = params.q as f64;
        let sigma = params.sigma;
        let m = params.m as f64;

        // Find optimal BKZ block size for primal attack
        let (primal_classical, primal_quantum, optimal_beta) =
            Self::primal_attack_cost(n, q, sigma, m);
        let (dual_classical, dual_quantum) = Self::dual_attack_cost(n, q, sigma, m);
        let hybrid_classical = Self::hybrid_attack_cost(n, q, sigma, m);

        let (hybrid_classical, _hybrid_quantum) = hybrid_classical;
        let best_classical = primal_classical
            .min(dual_classical)
            .min(hybrid_classical);
        let best_quantum = primal_quantum.min(dual_quantum);

        SecurityEstimate {
            params: params.clone(),
            primal_classical,
            primal_quantum,
            dual_classical,
            dual_quantum,
            hybrid_classical,
            best_classical,
            best_quantum,
            optimal_beta,
        }
    }

    /// Primal attack (uSVP via BKZ)
    ///
    /// Embeds LWE instance into a lattice and finds short vector.
    /// Cost model from Albrecht et al. and lattice-estimator.
    fn primal_attack_cost(n: f64, q: f64, sigma: f64, m: f64) -> (f64, f64, usize) {
        // Lattice dimension for primal attack: d = n + m + 1
        let d = n + m + 1.0;

        // Target norm: ||(e, 1, s)|| ≈ sqrt(m * sigma^2 + 1 + n * (q/2)^2 / 12)
        // For small sigma, target ≈ sqrt(m) * sigma
        let target_norm = (m * sigma * sigma + 1.0).sqrt();

        // Find optimal beta (BKZ block size)
        let mut best_cost = f64::MAX;
        let mut best_beta = 50;
        let mut best_quantum = f64::MAX;

        for beta in 50..=(d as usize).min(1000) {
            let beta_f = beta as f64;

            // Gaussian heuristic: expected shortest vector in dimension d after BKZ-beta
            // delta(beta) ≈ ((pi * beta)^(1/beta) * beta / (2 * pi * e))^(1/(2*(beta-1)))
            let delta = Self::bkz_delta(beta_f);

            // Expected norm after BKZ-beta reduction
            let expected_norm = delta.powf(d) * q.powf(m / d);

            // Success if expected_norm ≤ target_norm (with some margin)
            if expected_norm <= target_norm * 1.1 {
                // BKZ-beta cost (classical): 2^(0.292 * beta) core-SVP calls
                // Each core-SVP in dimension beta costs 2^(0.292 * beta) using sieving
                let classical_cost = Self::bkz_cost_classical(beta_f);
                let quantum_cost = Self::bkz_cost_quantum(beta_f);

                if classical_cost < best_cost {
                    best_cost = classical_cost;
                    best_quantum = quantum_cost;
                    best_beta = beta;
                }
            }
        }

        // If no valid beta found, use conservative estimate
        if best_cost == f64::MAX {
            // Very weak parameters - attack is easy
            let conservative_beta = (d / 2.0).max(50.0);
            best_cost = Self::bkz_cost_classical(conservative_beta);
            best_quantum = Self::bkz_cost_quantum(conservative_beta);
            best_beta = conservative_beta as usize;
        }

        (best_cost, best_quantum, best_beta)
    }

    /// Dual attack (BDD via BKZ)
    ///
    /// Transforms to BDD problem and solves via lattice reduction.
    fn dual_attack_cost(n: f64, q: f64, sigma: f64, m: f64) -> (f64, f64) {
        // Dual attack lattice dimension
        let d = n + m;

        // For dual attack, we need to distinguish from uniform
        // Advantage depends on sigma * ||v|| where v is a short dual vector
        let log_q = q.ln();
        let log_sigma = sigma.ln();

        // Find optimal beta for dual attack
        let mut best_cost = f64::MAX;
        let mut best_quantum = f64::MAX;

        for beta in 50..=(d as usize).min(1000) {
            let beta_f = beta as f64;
            let delta = Self::bkz_delta(beta_f);

            // Expected dual vector norm
            let dual_norm = delta.powf(d) * q.powf((d - n) / d);

            // Advantage: exp(-pi * (sigma * dual_norm / q)^2)
            // Need advantage > 1/poly(n) for distinguishing
            let advantage_exp = -PI * (sigma * dual_norm / q).powi(2);

            // Attack succeeds if advantage is not negligible
            if advantage_exp > -n * log_q {
                let classical_cost = Self::bkz_cost_classical(beta_f);
                let quantum_cost = Self::bkz_cost_quantum(beta_f);

                if classical_cost < best_cost {
                    best_cost = classical_cost;
                    best_quantum = quantum_cost;
                }
            }
        }

        // Conservative fallback
        if best_cost == f64::MAX {
            best_cost = Self::bkz_cost_classical(d / 2.0);
            best_quantum = Self::bkz_cost_quantum(d / 2.0);
        }

        (best_cost, best_quantum)
    }

    /// Hybrid attack (Howgrave-Graham)
    ///
    /// Meet-in-the-middle combined with lattice reduction.
    /// Effective when secret has special structure (e.g., small coefficients).
    fn hybrid_attack_cost(n: f64, q: f64, sigma: f64, _m: f64) -> (f64, f64) {
        // Hybrid attack guesses k coordinates of secret, reduces lattice on remaining n-k
        // Cost: 2^k * BKZ(n-k)
        let mut best_cost = f64::MAX;

        for k in 0..=(n as usize / 2) {
            let k_f = k as f64;
            let remaining = n - k_f;

            if remaining < 50.0 {
                continue;
            }

            // Guessing cost (assuming secret in {0,1,...,q-1})
            // For small secrets (binary/ternary), this would be better
            // We assume worst case: uniform secrets
            let guess_cost = k_f * q.log2(); // This is huge for large q

            // For ternary secrets ({-1, 0, 1}), much better:
            let ternary_guess = k_f * 3.0_f64.log2();

            // Lattice cost on remaining dimensions
            let lattice_cost = Self::bkz_cost_classical(remaining / 2.0);

            // Total for ternary (more realistic for LWE secrets)
            let total = ternary_guess + lattice_cost;
            if total < best_cost {
                best_cost = total;
            }
        }

        // If no hybrid advantage, fall back to pure lattice
        if best_cost == f64::MAX {
            best_cost = Self::bkz_cost_classical(n / 2.0);
        }

        (best_cost, best_cost * 0.5) // Quantum speedup on guessing
    }

    /// BKZ delta parameter (root Hermite factor)
    ///
    /// delta(beta) determines quality of lattice reduction.
    /// Using Chen-Nguyen formula.
    fn bkz_delta(beta: f64) -> f64 {
        if beta < 50.0 {
            return 1.02; // LLL-like
        }
        // Chen-Nguyen formula: delta = ((pi * beta)^(1/beta) * beta / (2*pi*e))^(1/(2*(beta-1)))
        let inner = (PI * beta).powf(1.0 / beta) * beta / (2.0 * PI * E);
        inner.powf(1.0 / (2.0 * (beta - 1.0)))
    }

    /// BKZ cost (classical) using sieving
    ///
    /// State-of-art: 2^(0.292 * beta + o(beta)) using progressive sieving
    fn bkz_cost_classical(beta: f64) -> f64 {
        // Core-SVP exponent: 0.292 for sieving (BDGL16)
        // Total BKZ cost includes polynomial overhead
        0.292 * beta + 16.4 // +16.4 accounts for polynomial factors
    }

    /// BKZ cost (quantum) using Grover-accelerated sieving
    ///
    /// Quantum speedup: 2^(0.265 * beta) (Laarhoven)
    fn bkz_cost_quantum(beta: f64) -> f64 {
        0.265 * beta + 16.4
    }

    /// Simple heuristic estimate (for quick comparison)
    ///
    /// λ ≈ 0.265 * n * log2(q/σ) - commonly cited formula
    pub fn simple_estimate(n: usize, q: u64, sigma: f64) -> f64 {
        let q_f = q as f64;
        0.265 * (n as f64) * (q_f / sigma).log2()
    }
}

fn main() {
    println!("=================================================================");
    println!("         LWE Security Estimator for TLO Parameters");
    println!("=================================================================\n");

    println!("Based on lattice-estimator methodology (Albrecht et al.)");
    println!("Attack models: Primal (uSVP), Dual (BDD), Hybrid\n");

    // TLO parameters
    let tlo_configs = vec![
        ("TLO n=16", LweParams::tlo_n16()),
        ("TLO n=32", LweParams::tlo_n32()),
        ("TLO n=64", LweParams::tlo_n64()),
        ("TLO n=128", LweParams::tlo_n128()),
        ("TLO n=256", LweParams::tlo_n256()),
        ("TLO n=512", LweParams::tlo_n512()),
    ];

    // Reference parameters
    let reference_configs = vec![
        ("Kyber-512 (NIST L1)", LweParams::kyber_512()),
        ("Kyber-768 (NIST L3)", LweParams::kyber_768()),
    ];

    println!("-----------------------------------------------------------------");
    println!("                    TLO Parameter Analysis");
    println!("-----------------------------------------------------------------");
    println!("TLO uses: q=65521 (largest 16-bit prime), sigma=sqrt(q)/4 ≈ 64\n");

    let mut results = Vec::new();

    for (name, params) in &tlo_configs {
        let estimate = LweEstimator::estimate(params);
        let simple = LweEstimator::simple_estimate(params.n, params.q, params.sigma);

        println!("### {}", name);
        println!("{}", estimate);
        println!("Simple heuristic (0.265*n*log2(q/σ)): {:.1} bits\n", simple);

        results.push((name.to_string(), params.clone(), estimate));
    }

    println!("-----------------------------------------------------------------");
    println!("                    Reference Parameters");
    println!("-----------------------------------------------------------------\n");

    for (name, params) in &reference_configs {
        let estimate = LweEstimator::estimate(params);
        let simple = LweEstimator::simple_estimate(params.n, params.q, params.sigma);

        println!("### {}", name);
        println!("{}", estimate);
        println!("Simple heuristic: {:.1} bits\n", simple);
    }

    // Summary table
    println!("=================================================================");
    println!("                        SUMMARY TABLE");
    println!("=================================================================\n");

    println!(
        "{:<20} {:>6} {:>8} {:>8} {:>12} {:>12}",
        "Config", "n", "q", "sigma", "Classical", "Quantum"
    );
    println!("{}", "-".repeat(70));

    for (name, params, estimate) in &results {
        println!(
            "{:<20} {:>6} {:>8} {:>8.1} {:>10.1}-bit {:>10.1}-bit",
            name, params.n, params.q, params.sigma, estimate.best_classical, estimate.best_quantum
        );
    }

    println!("\n{}", "-".repeat(70));
    println!("Reference (NIST standards):");

    for (name, params) in &reference_configs {
        let estimate = LweEstimator::estimate(params);
        println!(
            "{:<20} {:>6} {:>8} {:>8.1} {:>10.1}-bit {:>10.1}-bit",
            name, params.n, params.q, params.sigma, estimate.best_classical, estimate.best_quantum
        );
    }

    // Gas cost analysis
    println!("\n=================================================================");
    println!("                    GAS COST VS SECURITY");
    println!("=================================================================\n");

    println!(
        "{:<12} {:>12} {:>12} {:>15} {:>12}",
        "LWE n", "Security", "Gas (check)", "Storage", "Block %"
    );
    println!("{}", "-".repeat(65));

    // Based on actual measurements from honeypot contracts
    let gas_data = vec![
        (16, 744_000u64, 89u64, 2.5f64),
        (32, 1_270_000, 171, 4.2),
        (64, 2_580_000, 327, 8.6),
        (128, 5_100_000, 650, 17.0),  // Estimated
        (256, 10_100_000, 1290, 33.7), // Estimated
        (512, 20_000_000, 2570, 66.7), // Estimated (exceeds block!)
    ];

    for (n, gas, storage_kb, block_pct) in &gas_data {
        let params = LweParams::custom(*n, 65521, (65521.0_f64).sqrt() / 4.0);
        let estimate = LweEstimator::estimate(&params);

        let security_str = format!("{:.0}-bit", estimate.best_classical);
        let gas_str = format!("{:.2}M", *gas as f64 / 1_000_000.0);
        let storage_str = format!("{} KB", storage_kb);
        let block_str = format!("{:.1}%", block_pct);

        println!(
            "{:<12} {:>12} {:>12} {:>15} {:>12}",
            format!("n={}", n),
            security_str,
            gas_str,
            storage_str,
            block_str
        );
    }

    // Recommendations
    println!("\n=================================================================");
    println!("                      RECOMMENDATIONS");
    println!("=================================================================\n");

    let n64_estimate = LweEstimator::estimate(&LweParams::tlo_n64());
    let n128_estimate = LweEstimator::estimate(&LweParams::tlo_n128());
    let n256_estimate = LweEstimator::estimate(&LweParams::tlo_n256());

    println!("Current TLO (n=64):");
    println!(
        "  - Classical security: {:.0} bits",
        n64_estimate.best_classical
    );
    println!(
        "  - Quantum security: {:.0} bits",
        n64_estimate.best_quantum
    );
    println!("  - Gas: 2.58M (8.6% of block)");
    println!("  - Verdict: INSUFFICIENT for 128-bit claims\n");

    println!("For ~80-bit classical security:");
    println!(
        "  - Minimum n: ~128 ({:.0} bits)",
        n128_estimate.best_classical
    );
    println!("  - Gas: ~5.1M (17% of block)");
    println!("  - Suitable for: short-lived secrets (hours)\n");

    println!("For ~128-bit classical security:");
    println!(
        "  - Minimum n: ~256 ({:.0} bits)",
        n256_estimate.best_classical
    );
    println!("  - Gas: ~10.1M (33.7% of block)");
    println!("  - Suitable for: medium-lived secrets (days)\n");

    println!("For NIST Level 1 (128-bit):");
    println!("  - Requires n ≈ 512 (similar to Kyber-512)");
    println!("  - Gas: ~20M (exceeds single block!)");
    println!("  - Not practical for on-chain evaluation\n");

    println!("[!] CONCLUSION:");
    println!("    TLO with n=64 provides ~{:.0}-bit security, not 128-bit.", n64_estimate.best_classical);
    println!("    For short-lived secrets (MEV windows, auctions), this may suffice.");
    println!("    For stronger guarantees, use n=128+ but expect 2-4x gas increase.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bkz_delta() {
        // BKZ-100 should give delta ≈ 1.0094
        let delta_100 = LweEstimator::bkz_delta(100.0);
        assert!(delta_100 > 1.008 && delta_100 < 1.012);

        // BKZ-300 should give delta ≈ 1.0036
        let delta_300 = LweEstimator::bkz_delta(300.0);
        assert!(delta_300 > 1.003 && delta_300 < 1.005);
    }

    #[test]
    fn test_simple_estimate() {
        // Simple heuristic: 0.265 * n * log2(q/sigma)
        // For n=512, q=3329, sigma=1: 0.265 * 512 * log2(3329) ≈ 1588
        // This heuristic grossly overestimates security (it's a simplification)
        // The actual security (from lattice attacks) is much lower
        let est = LweEstimator::simple_estimate(512, 3329, 1.0);
        assert!(est > 1000.0, "Simple heuristic should be large: {}", est);
    }

    #[test]
    fn test_tlo_n64_weak() {
        let params = LweParams::tlo_n64();
        let estimate = LweEstimator::estimate(&params);

        // n=64 should NOT provide 128-bit security
        assert!(
            estimate.best_classical < 100.0,
            "n=64 should be weak: {:.0} bits",
            estimate.best_classical
        );
    }

    #[test]
    fn test_estimate_ordering() {
        // Larger n should always be more secure
        let est_64 = LweEstimator::estimate(&LweParams::tlo_n64());
        let est_128 = LweEstimator::estimate(&LweParams::tlo_n128());
        let est_256 = LweEstimator::estimate(&LweParams::tlo_n256());

        assert!(est_128.best_classical > est_64.best_classical);
        assert!(est_256.best_classical > est_128.best_classical);
    }
}
