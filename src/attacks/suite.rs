//! Adversarial Attack Suite for Circuit Obfuscation
//!
//! Multiple attack methods that attempt to break or detect structure in
//! obfuscated circuits.
//!
//! ## Attack Classification
//!
//! | Attack | Type | Severity | Can Defeat with Topology? |
//! |--------|------|----------|---------------------------|
//! | Compression | Structural | High | Yes - avoid duplicate gates |
//! | PatternMatch | Structural | High | Yes - random CF cycling |
//! | DiagonalCorrelation | Statistical | Medium | Yes - scale to 256+ wires |
//! | Statistical | Statistical | Medium | Yes - uniform wire selection |
//! | Structural | Structural | Medium | Yes - irregular layers, non-pow2 |
//! | RainbowTable | **Semantic** | Low | **No** - requires time-locking |
//!
//! ## Note on RainbowTable Attack
//!
//! The RainbowTable attack is fundamentally different from other attacks:
//! - It is **semantic**: matches truth-table behavior, not structure
//! - It cannot be defeated by topology manipulation alone
//! - It only finds *reducible* subcircuits, not the original circuit
//! - It doesn't recover keys or reveal circuit intent
//!
//! For on-chain use, VDF time-locking defeats RainbowTable by making
//! any analysis obsolete before it can be exploited (epoch rotation).

use crate::circuit::Circuit;
use crate::rainbow::RainbowTable;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct AttackResult {
    pub success: bool,
    pub confidence: f64,
    pub details: String,
}

impl AttackResult {
    pub fn new(success: bool, confidence: f64, details: impl Into<String>) -> Self {
        Self {
            success,
            confidence: confidence.clamp(0.0, 1.0),
            details: details.into(),
        }
    }

    pub fn failed(details: impl Into<String>) -> Self {
        Self::new(false, 0.0, details)
    }

    pub fn success(confidence: f64, details: impl Into<String>) -> Self {
        Self::new(true, confidence.clamp(0.0, 1.0), details)
    }
}

pub struct AttackSuite {
    rainbow_table: Option<RainbowTable>,
}

impl Default for AttackSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl AttackSuite {
    pub fn new() -> Self {
        Self {
            rainbow_table: None,
        }
    }

    pub fn with_rainbow_table(table: RainbowTable) -> Self {
        Self {
            rainbow_table: Some(table),
        }
    }

    pub fn run_all(&self, circuit: &Circuit) -> Vec<(String, AttackResult)> {
        vec![
            ("Compression".to_string(), self.compression_attack(circuit)),
            (
                "PatternMatch".to_string(),
                self.pattern_match_attack(circuit),
            ),
            (
                "DiagonalCorrelation".to_string(),
                self.diagonal_correlation_attack(circuit),
            ),
            ("Statistical".to_string(), self.statistical_attack(circuit)),
            ("Structural".to_string(), self.structural_attack(circuit)),
            (
                "RainbowTable".to_string(),
                self.rainbow_table_attack(circuit),
            ),
        ]
    }

    pub fn compression_attack(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.is_empty() {
            return AttackResult::failed("Empty circuit");
        }

        let original_size = circuit.gates.len();
        let mut compressed = circuit.clone();

        let mut cancellations = 0;
        let mut i = 0;
        while i < compressed.gates.len().saturating_sub(1) {
            if compressed.gates[i].equals(&compressed.gates[i + 1]) {
                compressed.gates.drain(i..=i + 1);
                cancellations += 1;
                i = i.saturating_sub(1);
            } else {
                i += 1;
            }
        }

        compressed.canonicalize();

        i = 0;
        while i < compressed.gates.len().saturating_sub(1) {
            if compressed.gates[i].equals(&compressed.gates[i + 1]) {
                compressed.gates.drain(i..=i + 1);
                cancellations += 1;
                i = i.saturating_sub(1);
            } else {
                i += 1;
            }
        }

        let final_size = compressed.gates.len();
        let reduction = original_size - final_size;
        let reduction_ratio = reduction as f64 / original_size as f64;

        let success = reduction > 0;
        let confidence = reduction_ratio;
        let details = format!(
            "Reduced {} -> {} gates ({} cancellations, {:.1}% reduction)",
            original_size,
            final_size,
            cancellations,
            reduction_ratio * 100.0
        );

        AttackResult::new(success, confidence, details)
    }

    pub fn pattern_match_attack(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.len() < 4 {
            return AttackResult::failed("Circuit too small for pattern analysis");
        }

        let mut ngram_counts: HashMap<Vec<[u8; 3]>, usize> = HashMap::new();

        for n in 2..=4 {
            if circuit.gates.len() < n {
                continue;
            }
            for window in circuit.gates.windows(n) {
                let pattern: Vec<[u8; 3]> = window.iter().map(|g| g.pins).collect();
                *ngram_counts.entry(pattern).or_insert(0) += 1;
            }
        }

        let repeated_patterns: Vec<_> = ngram_counts
            .iter()
            .filter(|(_, &count)| count > 1)
            .collect();

        let total_repeats: usize = repeated_patterns.iter().map(|(_, &c)| c - 1).sum();
        let max_repeat = repeated_patterns.iter().map(|(_, &c)| c).max().unwrap_or(1);
        let unique_patterns = ngram_counts.len();

        let repeat_ratio = if unique_patterns > 0 {
            total_repeats as f64 / unique_patterns as f64
        } else {
            0.0
        };

        let success = !repeated_patterns.is_empty();
        let confidence = (repeat_ratio / 2.0).min(1.0);
        let details = format!(
            "Found {} repeated n-gram patterns (max repetition: {}x, {} unique patterns)",
            repeated_patterns.len(),
            max_repeat,
            unique_patterns
        );

        AttackResult::new(success, confidence, details)
    }

    pub fn diagonal_correlation_attack(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.is_empty() {
            return AttackResult::failed("Empty circuit");
        }

        let num_samples = 32.min(
            1usize
                .checked_shl(circuit.num_wires as u32)
                .unwrap_or(usize::MAX),
        );
        let mut correlations = Vec::new();

        for sample in 0..num_samples {
            let mut state = sample;

            for (idx, gate) in circuit.gates.iter().enumerate() {
                let input_bit = (sample >> (idx % circuit.num_wires)) & 1;
                state = gate.evaluate(state);
                let output_bit = (state >> (idx % circuit.num_wires)) & 1;

                correlations.push(if input_bit == output_bit { 1.0 } else { 0.0 });
            }
        }

        let mean_correlation = if correlations.is_empty() {
            0.5
        } else {
            correlations.iter().sum::<f64>() / correlations.len() as f64
        };

        let bias = (mean_correlation - 0.5).abs() * 2.0;

        let success = bias > 0.1;
        let confidence = bias;
        let details = format!(
            "Input/output diagonal correlation: {:.3} (bias from 0.5: {:.3})",
            mean_correlation, bias
        );

        AttackResult::new(success, confidence, details)
    }

    pub fn statistical_attack(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.is_empty() {
            return AttackResult::failed("Empty circuit");
        }

        let mut wire_counts = vec![0usize; circuit.num_wires];

        for gate in &circuit.gates {
            for &pin in &gate.pins {
                if (pin as usize) < circuit.num_wires {
                    wire_counts[pin as usize] += 1;
                }
            }
        }

        let total_uses: usize = wire_counts.iter().sum();
        let expected = total_uses as f64 / circuit.num_wires as f64;

        let chi_squared: f64 = wire_counts
            .iter()
            .map(|&observed| {
                let diff = observed as f64 - expected;
                diff * diff / expected
            })
            .sum();

        let df = (circuit.num_wires - 1) as f64;
        let normalized_chi = chi_squared / df;

        let success = normalized_chi > 2.0;
        let confidence = ((normalized_chi - 1.0) / 10.0).clamp(0.0, 1.0);
        let details = format!(
            "Chi-squared: {:.2} (df={}, normalized: {:.2}, expected uniform: ~1.0)",
            chi_squared, df as usize, normalized_chi
        );

        AttackResult::new(success, confidence, details)
    }

    pub fn structural_attack(&self, circuit: &Circuit) -> AttackResult {
        if circuit.gates.len() < 8 {
            return AttackResult::failed("Circuit too small for structural analysis");
        }

        let mut butterfly_score = 0.0;
        let mut fft_like_patterns = 0;

        let n = circuit.num_wires;
        let log_n = (n as f64).log2().ceil() as usize;

        for (idx, gate) in circuit.gates.iter().enumerate() {
            let active = gate.pins[0] as usize;
            let c1 = gate.pins[1] as usize;
            let c2 = gate.pins[2] as usize;

            for stride in (0..log_n).map(|i| 1 << i) {
                if active.abs_diff(c1) == stride || active.abs_diff(c2) == stride {
                    butterfly_score += 1.0;
                    if idx > 0 {
                        let prev = &circuit.gates[idx - 1];
                        let prev_active = prev.pins[0] as usize;
                        if prev_active.abs_diff(active) == stride {
                            fft_like_patterns += 1;
                        }
                    }
                    break;
                }
            }
        }

        let max_butterfly_score = circuit.gates.len() as f64;
        let normalized_butterfly = butterfly_score / max_butterfly_score;

        let regularity = detect_layer_regularity(circuit);

        let combined_score = (normalized_butterfly * 0.5 + regularity * 0.5).min(1.0);
        let success = combined_score > 0.3 || fft_like_patterns > circuit.gates.len() / 10;

        let details = format!(
            "Butterfly pattern score: {:.2}, FFT-like sequences: {}, layer regularity: {:.2}",
            normalized_butterfly, fft_like_patterns, regularity
        );

        AttackResult::new(success, combined_score, details)
    }

    pub fn rainbow_table_attack(&self, circuit: &Circuit) -> AttackResult {
        let table = match &self.rainbow_table {
            Some(t) => t,
            None => {
                let generated = RainbowTable::generate(circuit.num_wires.min(6), 2);
                return self.rainbow_attack_with_table(circuit, &generated);
            }
        };

        self.rainbow_attack_with_table(circuit, table)
    }

    fn rainbow_attack_with_table(&self, circuit: &Circuit, table: &RainbowTable) -> AttackResult {
        if circuit.gates.is_empty() {
            return AttackResult::failed("Empty circuit");
        }

        let mut matches = 0;
        let mut smaller_found = 0;

        for window_size in 2..=3.min(circuit.gates.len()) {
            for start in 0..=(circuit.gates.len() - window_size) {
                let subcircuit = Circuit::from_gates(
                    circuit.gates[start..start + window_size].to_vec(),
                    circuit.num_wires,
                );

                if table.find_equivalent(&subcircuit).is_some() {
                    matches += 1;
                }
                if table.find_smaller(&subcircuit).is_some() {
                    smaller_found += 1;
                }
            }
        }

        let total_windows =
            (circuit.gates.len().saturating_sub(1)) + circuit.gates.len().saturating_sub(2);
        let match_ratio = if total_windows > 0 {
            matches as f64 / total_windows as f64
        } else {
            0.0
        };

        let success = smaller_found > 0;
        let confidence = (smaller_found as f64 / total_windows.max(1) as f64).min(1.0);
        let details = format!(
            "Rainbow matches: {}/{} windows, {} reducible subcircuits found",
            matches, total_windows, smaller_found
        );

        AttackResult::new(success, confidence, details)
    }
}

fn detect_layer_regularity(circuit: &Circuit) -> f64 {
    if circuit.gates.len() < 4 {
        return 0.0;
    }

    let mut layer_sizes = Vec::new();
    let mut current_layer_start = 0;
    let mut last_active_set: std::collections::HashSet<u8> = std::collections::HashSet::new();

    for (idx, gate) in circuit.gates.iter().enumerate() {
        if last_active_set.contains(&gate.pins[0]) {
            if idx > current_layer_start {
                layer_sizes.push(idx - current_layer_start);
            }
            current_layer_start = idx;
            last_active_set.clear();
        }
        last_active_set.insert(gate.pins[0]);
    }

    if circuit.gates.len() > current_layer_start {
        layer_sizes.push(circuit.gates.len() - current_layer_start);
    }

    if layer_sizes.len() < 2 {
        return 0.0;
    }

    let mean = layer_sizes.iter().sum::<usize>() as f64 / layer_sizes.len() as f64;
    let variance = layer_sizes
        .iter()
        .map(|&s| (s as f64 - mean).powi(2))
        .sum::<f64>()
        / layer_sizes.len() as f64;
    let cv = if mean > 0.0 {
        variance.sqrt() / mean
    } else {
        1.0
    };

    (1.0 - cv.min(1.0)).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_attack_identity() {
        let identity = Circuit::random_identity(8, 20);
        let suite = AttackSuite::new();
        let result = suite.compression_attack(&identity);

        println!("Compression attack on identity: {:?}", result);
        assert!(
            result.success,
            "Should detect cancellations in identity circuit"
        );
    }

    #[test]
    fn test_compression_attack_random() {
        let random = Circuit::random(8, 50);
        let suite = AttackSuite::new();
        let result = suite.compression_attack(&random);

        println!("Compression attack on random: {:?}", result);
    }

    #[test]
    fn test_pattern_match_attack() {
        let mut circuit = Circuit::random(8, 10);
        circuit.gates.extend(circuit.gates.clone());

        let suite = AttackSuite::new();
        let result = suite.pattern_match_attack(&circuit);

        println!("Pattern match attack on repeated circuit: {:?}", result);
        assert!(result.success, "Should detect repeated patterns");
    }

    #[test]
    fn test_statistical_attack() {
        let circuit = Circuit::random(8, 100);
        let suite = AttackSuite::new();
        let result = suite.statistical_attack(&circuit);

        println!("Statistical attack on random: {:?}", result);
    }

    #[test]
    fn test_run_all() {
        let circuit = Circuit::random(8, 30);
        let suite = AttackSuite::new();
        let results = suite.run_all(&circuit);

        println!("\nAll attacks on random circuit:");
        for (name, result) in results {
            println!(
                "  {}: success={}, confidence={:.2}",
                name, result.success, result.confidence
            );
        }
    }
}
