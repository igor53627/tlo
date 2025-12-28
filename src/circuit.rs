//! Circuit representation with multiple control functions
//! Compatible with local_mixing format, extended with 16 control functions

use crate::control_function::{ControlFunction, CONTROL_FUNC_TABLE};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A gate with active wire, two control wires, and a control function
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Gate {
    pub pins: [u8; 3], // [active, control1, control2]
    pub control_function: ControlFunction,
}

impl Gate {
    pub fn new(active: u8, c1: u8, c2: u8, cf: ControlFunction) -> Self {
        Self {
            pins: [active, c1, c2],
            control_function: cf,
        }
    }

    /// Create gate with default control function (OrNb/r57)
    pub fn new_r57(active: u8, c1: u8, c2: u8) -> Self {
        Self::new(active, c1, c2, ControlFunction::OrNb)
    }

    /// Create gate from [u8; 3] with default control function (for backward compatibility)
    pub fn from_pins(pins: [u8; 3]) -> Self {
        Self {
            pins,
            control_function: ControlFunction::OrNb,
        }
    }

    /// Check if two gates collide (can't be reordered)
    pub fn collides(&self, other: &Gate) -> bool {
        self.pins[0] == other.pins[1]
            || self.pins[0] == other.pins[2]
            || self.pins[1] == other.pins[0]
            || self.pins[2] == other.pins[0]
    }

    /// Check if this gate equals another (same pins and control function)
    pub fn equals(&self, other: &Gate) -> bool {
        self.pins == other.pins && self.control_function == other.control_function
    }

    /// Evaluate gate on a state using lookup table
    #[inline(always)]
    pub fn evaluate(&self, state: usize) -> usize {
        let a = (state >> self.pins[1]) & 1;
        let b = (state >> self.pins[2]) & 1;
        let idx = ((self.control_function as usize) << 2) | (a << 1) | b;
        state ^ ((CONTROL_FUNC_TABLE[idx] as usize) << self.pins[0])
    }
}

#[derive(Clone, Debug, Default)]
pub struct Circuit {
    pub gates: Vec<Gate>,
    pub num_wires: usize,
}

impl Circuit {
    pub fn new(num_wires: usize) -> Self {
        Self {
            gates: Vec::new(),
            num_wires,
        }
    }

    pub fn from_gates(gates: Vec<Gate>, num_wires: usize) -> Self {
        Self { gates, num_wires }
    }

    /// Create from old-style [u8; 3] gates (backward compatibility)
    pub fn from_pins(pins: Vec<[u8; 3]>, num_wires: usize) -> Self {
        let gates = pins.into_iter().map(Gate::from_pins).collect();
        Self { gates, num_wires }
    }

    /// Evaluate circuit on input state
    pub fn evaluate(&self, input: usize) -> usize {
        self.gates
            .iter()
            .fold(input, |state, gate| gate.evaluate(state))
    }

    /// Evaluate circuit as PRF (truncated output)
    /// Converts PRP to PRF by taking only the low `output_bits` of the result.
    /// This is cryptographically sound: PRP with truncated output is
    /// indistinguishable from PRF (PRP-PRF switching lemma).
    #[inline]
    pub fn evaluate_prf(&self, input: usize, output_bits: usize) -> usize {
        let full = self.evaluate(input);
        full & ((1 << output_bits) - 1)
    }

    /// Legacy evaluate_gate for backward compatibility
    #[inline(always)]
    pub fn evaluate_gate(state: usize, pins: [u8; 3]) -> usize {
        Gate::from_pins(pins).evaluate(state)
    }

    /// Check if two gates collide (legacy interface)
    pub fn gates_collide(a: &[u8; 3], b: &[u8; 3]) -> bool {
        Gate::from_pins(*a).collides(&Gate::from_pins(*b))
    }

    /// Generate random circuit with random control functions
    pub fn random(num_wires: usize, num_gates: usize) -> Self {
        Self::random_with_functions(num_wires, num_gates, true)
    }

    /// Generate random circuit, optionally with varied control functions
    pub fn random_with_functions(num_wires: usize, num_gates: usize, varied: bool) -> Self {
        let mut rng = rand::thread_rng();
        let mut gates = Vec::with_capacity(num_gates);

        for _ in 0..num_gates {
            let a = rng.gen_range(0..num_wires) as u8;
            let mut b = rng.gen_range(0..num_wires) as u8;
            while b == a {
                b = rng.gen_range(0..num_wires) as u8;
            }
            let mut c = rng.gen_range(0..num_wires) as u8;
            while c == a || c == b {
                c = rng.gen_range(0..num_wires) as u8;
            }

            let cf = if varied {
                ControlFunction::random_nontrivial(&mut rng)
            } else {
                ControlFunction::OrNb
            };

            gates.push(Gate::new(a, b, c, cf));
        }

        Self { gates, num_wires }
    }

    /// Generate random circuit with only r57 gates (original behavior)
    pub fn random_r57(num_wires: usize, num_gates: usize) -> Self {
        Self::random_with_functions(num_wires, num_gates, false)
    }

    /// Generate random circuit with only affine control functions
    /// Circuit becomes C(x) = Mx + c over GF(2) - VBB-friendly
    pub fn random_affine(num_wires: usize, num_gates: usize) -> Self {
        use crate::control_function::ControlFunctionSet;
        Self::random_from_set(num_wires, num_gates, ControlFunctionSet::AffineOnly)
    }

    /// Generate random circuit with only XOR-based control functions
    /// Strongest linearity - purely additive over GF(2)
    pub fn random_xor_only(num_wires: usize, num_gates: usize) -> Self {
        use crate::control_function::ControlFunctionSet;
        Self::random_from_set(num_wires, num_gates, ControlFunctionSet::XorOnly)
    }

    /// Generate random circuit from a specific control function set
    pub fn random_from_set(
        num_wires: usize,
        num_gates: usize,
        cf_set: crate::control_function::ControlFunctionSet,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut gates = Vec::with_capacity(num_gates);

        for _ in 0..num_gates {
            let a = rng.gen_range(0..num_wires) as u8;
            let mut b = rng.gen_range(0..num_wires) as u8;
            while b == a {
                b = rng.gen_range(0..num_wires) as u8;
            }
            let mut c = rng.gen_range(0..num_wires) as u8;
            while c == a || c == b {
                c = rng.gen_range(0..num_wires) as u8;
            }

            let cf = ControlFunction::random_nontrivial_from_set(&mut rng, cf_set);
            gates.push(Gate::new(a, b, c, cf));
        }

        Self { gates, num_wires }
    }

    /// Check if all control functions in the circuit are affine
    pub fn is_affine(&self) -> bool {
        self.gates.iter().all(|g| g.control_function.is_affine())
    }

    /// Check if all control functions in the circuit are XOR-only
    pub fn is_xor_only(&self) -> bool {
        self.gates.iter().all(|g| g.control_function.is_xor_only())
    }

    /// Generate a random identity circuit (circuit followed by its reverse)
    pub fn random_identity(num_wires: usize, half_gates: usize) -> Self {
        let forward = Self::random_r57(num_wires, half_gates);
        let mut gates = forward.gates.clone();
        gates.extend(forward.gates.iter().rev().cloned());
        Self { gates, num_wires }
    }

    /// Get wires used by this circuit
    pub fn used_wires(&self) -> HashSet<u8> {
        self.gates
            .iter()
            .flat_map(|g| g.pins.iter().cloned())
            .collect()
    }

    /// Get pins as Vec<[u8; 3]> for backward compatibility
    pub fn pins(&self) -> Vec<[u8; 3]> {
        self.gates.iter().map(|g| g.pins).collect()
    }

    /// Parse from local_mixing string format: "abc;def;..."
    /// Uses default control function (OrNb) for all gates
    pub fn from_string(s: &str) -> Self {
        let wire_map: HashMap<char, u8> =
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                .chars()
                .enumerate()
                .map(|(i, c)| (c, i as u8))
                .collect();

        let gates: Vec<Gate> = s
            .split(';')
            .filter(|g| !g.is_empty())
            .map(|g| {
                let chars: Vec<char> = g.chars().collect();
                let pins = [
                    *wire_map.get(&chars.get(0).unwrap_or(&'0')).unwrap_or(&0),
                    *wire_map.get(&chars.get(1).unwrap_or(&'0')).unwrap_or(&0),
                    *wire_map.get(&chars.get(2).unwrap_or(&'0')).unwrap_or(&0),
                ];
                // Check for control function suffix (e.g., "abc:6" for XOR)
                let cf = if chars.len() > 4 && chars[3] == ':' {
                    let cf_str: String = chars[4..].iter().collect();
                    cf_str
                        .parse::<u8>()
                        .ok()
                        .map(ControlFunction::from_u8)
                        .unwrap_or(ControlFunction::OrNb)
                } else {
                    ControlFunction::OrNb
                };
                Gate::new(pins[0], pins[1], pins[2], cf)
            })
            .collect();

        let num_wires = gates
            .iter()
            .flat_map(|g| g.pins.iter())
            .max()
            .map(|&m| m as usize + 1)
            .unwrap_or(0);
        Self { gates, num_wires }
    }

    /// Convert to local_mixing string format
    pub fn to_string(&self) -> String {
        let wire_chars: Vec<char> =
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                .chars()
                .collect();

        self.gates
            .iter()
            .map(|g| {
                let base = format!(
                    "{}{}{}",
                    wire_chars.get(g.pins[0] as usize).unwrap_or(&'?'),
                    wire_chars.get(g.pins[1] as usize).unwrap_or(&'?'),
                    wire_chars.get(g.pins[2] as usize).unwrap_or(&'?'),
                );
                // Include control function if not default
                if g.control_function != ControlFunction::OrNb {
                    format!("{}:{};", base, g.control_function as u8)
                } else {
                    format!("{};", base)
                }
            })
            .collect()
    }

    /// Canonicalize gate order (bubble sort non-colliding gates)
    pub fn canonicalize(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            for i in 0..self.gates.len().saturating_sub(1) {
                if !self.gates[i].collides(&self.gates[i + 1]) {
                    if !Self::gate_ordered(&self.gates[i], &self.gates[i + 1]) {
                        self.gates.swap(i, i + 1);
                        changed = true;
                    }
                }
            }
        }
    }

    fn gate_ordered(a: &Gate, b: &Gate) -> bool {
        (a.pins, a.control_function as u8) <= (b.pins, b.control_function as u8)
    }

    /// Remove adjacent duplicate gates (they cancel out if same pins AND control function)
    pub fn remove_duplicates(&mut self) {
        let mut i = 0;
        while i < self.gates.len().saturating_sub(1) {
            if self.gates[i].equals(&self.gates[i + 1]) {
                self.gates.drain(i..=i + 1);
                i = i.saturating_sub(1);
            } else {
                i += 1;
            }
        }
    }

    /// Count unique control functions used
    pub fn control_function_diversity(&self) -> usize {
        self.gates
            .iter()
            .map(|g| g.control_function)
            .collect::<HashSet<_>>()
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_circuit() {
        let circuit = Circuit::random_identity(8, 50);
        for input in 0..256 {
            assert_eq!(
                circuit.evaluate(input),
                input,
                "Identity failed for input {}",
                input
            );
        }
    }

    #[test]
    fn test_gate_evaluation_r57() {
        // Gate with OrNb (r57): state ^= (c1 | !c2) << active
        let gate = Gate::new_r57(0, 1, 2);
        let state = 0b110; // c1=1, c2=1 -> (1 | 0) = 1 -> flip bit 0
        let result = gate.evaluate(state);
        assert_eq!(result, 0b111);
    }

    #[test]
    fn test_gate_evaluation_xor() {
        // Gate with XOR: state ^= (c1 ^ c2) << active
        let gate = Gate::new(0, 1, 2, ControlFunction::Xor);

        // c1=1, c2=1 -> 1^1 = 0 -> no flip
        assert_eq!(gate.evaluate(0b110), 0b110);

        // c1=1, c2=0 -> 1^0 = 1 -> flip bit 0
        assert_eq!(gate.evaluate(0b010), 0b011);
    }

    #[test]
    fn test_control_function_diversity() {
        let circuit = Circuit::random(16, 50);
        let diversity = circuit.control_function_diversity();
        // With 50 random gates, we should have multiple control functions
        assert!(
            diversity > 1,
            "Expected diverse control functions, got {}",
            diversity
        );
    }

    #[test]
    fn test_backward_compatibility() {
        // Old-style evaluation should still work
        let state = 0b110;
        let result = Circuit::evaluate_gate(state, [0, 1, 2]);
        assert_eq!(result, 0b111);
    }

    #[test]
    fn test_evaluate_prf() {
        // PRF mode should truncate output to specified bits
        let circuit = Circuit::random(8, 50);

        for input in 0..256 {
            let full = circuit.evaluate(input);
            let prf_4 = circuit.evaluate_prf(input, 4);
            let prf_6 = circuit.evaluate_prf(input, 6);

            // Truncated output should match low bits of full output
            assert_eq!(prf_4, full & 0xF, "PRF 4-bit mismatch");
            assert_eq!(prf_6, full & 0x3F, "PRF 6-bit mismatch");

            // PRF output should be within expected range
            assert!(prf_4 < 16, "PRF 4-bit out of range");
            assert!(prf_6 < 64, "PRF 6-bit out of range");
        }
    }

    #[test]
    fn test_prf_uniformity() {
        // Truncated PRF output should be uniform (for permutation circuits)
        let circuit = Circuit::random(8, 50);
        let output_bits = 4;
        let output_space = 1 << output_bits;

        let mut counts = vec![0usize; output_space];
        for input in 0..256 {
            let output = circuit.evaluate_prf(input, output_bits);
            counts[output] += 1;
        }

        // Each bucket should have exactly 256/16 = 16 entries (perfect uniformity for PRP)
        let expected = 256 / output_space;
        for (i, &count) in counts.iter().enumerate() {
            assert_eq!(
                count, expected,
                "Bucket {} has {} entries, expected {}",
                i, count, expected
            );
        }
    }
}
