//! Rainbow Table Attack Testing
//!
//! Precompute circuit equivalences and test if obfuscation methods
//! are vulnerable to subcircuit replacement attacks.

use crate::circuit::{Circuit, Gate};
use crate::control_function::ControlFunction;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct RainbowTable {
    entries: HashMap<u64, Vec<RainbowEntry>>,
    pub stats: TableStats,
}

#[derive(Debug, Clone)]
pub struct RainbowEntry {
    pub gates: Vec<Gate>,
    pub function_hash: u64,
    pub size: usize,
}

#[derive(Debug, Clone, Default)]
pub struct TableStats {
    pub total_entries: usize,
    pub unique_functions: usize,
    pub max_size: usize,
    pub collisions: usize,
}

impl RainbowTable {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            stats: TableStats::default(),
        }
    }

    pub fn generate(num_wires: usize, max_gates: usize) -> Self {
        let mut table = Self::new();

        for size in 1..=max_gates {
            table.generate_size(num_wires, size);
        }

        table.stats.unique_functions = table.entries.len();
        table
    }

    fn generate_size(&mut self, num_wires: usize, size: usize) {
        if size == 1 {
            for a in 0..num_wires {
                for b in 0..num_wires {
                    if b == a {
                        continue;
                    }
                    for c in 0..num_wires {
                        if c == a || c == b {
                            continue;
                        }
                        let gate = Gate::new(a as u8, b as u8, c as u8, ControlFunction::OrNb);
                        self.add_circuit(vec![gate], num_wires);
                    }
                }
            }
        } else if size == 2 {
            for a1 in 0..num_wires.min(6) {
                for b1 in 0..num_wires.min(6) {
                    if b1 == a1 {
                        continue;
                    }
                    for c1 in 0..num_wires.min(6) {
                        if c1 == a1 || c1 == b1 {
                            continue;
                        }
                        for a2 in 0..num_wires.min(6) {
                            for b2 in 0..num_wires.min(6) {
                                if b2 == a2 {
                                    continue;
                                }
                                for c2 in 0..num_wires.min(6) {
                                    if c2 == a2 || c2 == b2 {
                                        continue;
                                    }
                                    let gates = vec![
                                        Gate::new(
                                            a1 as u8,
                                            b1 as u8,
                                            c1 as u8,
                                            ControlFunction::OrNb,
                                        ),
                                        Gate::new(
                                            a2 as u8,
                                            b2 as u8,
                                            c2 as u8,
                                            ControlFunction::OrNb,
                                        ),
                                    ];
                                    self.add_circuit(gates, num_wires);
                                }
                            }
                        }
                    }
                }
            }
        }

        self.stats.max_size = self.stats.max_size.max(size);
    }

    fn add_circuit(&mut self, gates: Vec<Gate>, num_wires: usize) {
        let circuit = Circuit::from_gates(gates.clone(), num_wires);
        let hash = self.compute_function_hash(&circuit);

        let entry = RainbowEntry {
            gates: gates.clone(),
            function_hash: hash,
            size: gates.len(),
        };

        self.stats.total_entries += 1;

        let entries = self.entries.entry(hash).or_insert_with(Vec::new);
        if !entries.is_empty() {
            self.stats.collisions += 1;
        }
        entries.push(entry);
    }

    fn compute_function_hash(&self, circuit: &Circuit) -> u64 {
        let mut hash: u64 = 0;
        // Avoid overflow for large wire counts (num_wires >= 64)
        let samples = 16.min(
            1usize
                .checked_shl(circuit.num_wires as u32)
                .unwrap_or(usize::MAX),
        );

        for i in 0..samples {
            let output = circuit.evaluate(i);
            hash ^= (output as u64) << ((i % 8) * 8);
            hash = hash.rotate_left(7);
        }

        hash
    }

    pub fn find_equivalent(&self, subcircuit: &Circuit) -> Option<&RainbowEntry> {
        let hash = self.compute_function_hash(subcircuit);

        if let Some(entries) = self.entries.get(&hash) {
            for entry in entries {
                if self.circuits_equivalent(subcircuit, &entry.gates) {
                    return Some(entry);
                }
            }
        }
        None
    }

    pub fn find_smaller(&self, subcircuit: &Circuit) -> Option<&RainbowEntry> {
        let hash = self.compute_function_hash(subcircuit);
        let current_size = subcircuit.gates.len();

        if let Some(entries) = self.entries.get(&hash) {
            for entry in entries {
                if entry.size < current_size && self.circuits_equivalent(subcircuit, &entry.gates) {
                    return Some(entry);
                }
            }
        }
        None
    }

    fn circuits_equivalent(&self, circuit: &Circuit, gates: &[Gate]) -> bool {
        let other = Circuit::from_gates(gates.to_vec(), circuit.num_wires);
        let samples = 32.min(
            1usize
                .checked_shl(circuit.num_wires as u32)
                .unwrap_or(usize::MAX),
        );

        for i in 0..samples {
            if circuit.evaluate(i) != other.evaluate(i) {
                return false;
            }
        }
        true
    }
}

pub struct RainbowAttack {
    table: RainbowTable,
    window_sizes: Vec<usize>,
}

#[derive(Debug, Clone)]
pub struct AttackResult {
    pub original_size: usize,
    pub final_size: usize,
    pub replacements_found: usize,
    pub compression_ratio: f64,
}

impl RainbowAttack {
    pub fn new(table: RainbowTable) -> Self {
        Self {
            table,
            window_sizes: vec![2, 3, 4],
        }
    }

    pub fn attack(&self, circuit: &Circuit) -> AttackResult {
        let mut current = circuit.clone();
        let original_size = current.gates.len();
        let mut replacements = 0;

        let mut changed = true;
        while changed {
            changed = false;

            for &window_size in &self.window_sizes {
                if current.gates.len() < window_size {
                    continue;
                }

                for start in 0..=(current.gates.len() - window_size) {
                    let subcircuit = Circuit::from_gates(
                        current.gates[start..start + window_size].to_vec(),
                        current.num_wires,
                    );

                    if let Some(replacement) = self.table.find_smaller(&subcircuit) {
                        let mut new_gates = current.gates[..start].to_vec();
                        new_gates.extend_from_slice(&replacement.gates);
                        new_gates.extend_from_slice(&current.gates[start + window_size..]);
                        current = Circuit::from_gates(new_gates, current.num_wires);
                        replacements += 1;
                        changed = true;
                        break;
                    }
                }

                if changed {
                    break;
                }
            }
        }

        let final_size = current.gates.len();
        let compression_ratio = if original_size > 0 {
            final_size as f64 / original_size as f64
        } else {
            1.0
        };

        AttackResult {
            original_size,
            final_size,
            replacements_found: replacements,
            compression_ratio,
        }
    }
}

pub fn test_rainbow_resistance(circuit: &Circuit, table: &RainbowTable) -> f64 {
    let attack = RainbowAttack::new(table.clone());
    let result = attack.attack(circuit);
    result.compression_ratio
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table_generation() {
        let table = RainbowTable::generate(4, 2);

        println!("Table stats: {:?}", table.stats);
        assert!(table.stats.total_entries > 0);
        assert!(table.stats.unique_functions > 0);
    }

    #[test]
    fn test_identity_detection() {
        let table = RainbowTable::generate(4, 2);

        let identity = Circuit::from_gates(
            vec![
                Gate::new(0, 1, 2, ControlFunction::OrNb),
                Gate::new(0, 1, 2, ControlFunction::OrNb),
            ],
            4,
        );

        if let Some(smaller) = table.find_smaller(&identity) {
            println!("Found smaller: {} gates", smaller.size);
            assert!(smaller.size < 2);
        }
    }

    #[test]
    fn test_rainbow_attack() {
        let table = RainbowTable::generate(4, 2);
        let attack = RainbowAttack::new(table);

        let identity = Circuit::random_identity(4, 5);
        let result = attack.attack(&identity);

        println!("Attack result: {:?}", result);
        assert!(result.final_size <= result.original_size);
    }

    #[test]
    fn test_random_circuit_resistance() {
        let table = RainbowTable::generate(6, 2);
        let circuit = Circuit::random(6, 20);

        let resistance = test_rainbow_resistance(&circuit, &table);
        println!(
            "Random circuit rainbow resistance: {:.2}%",
            resistance * 100.0
        );
    }
}
