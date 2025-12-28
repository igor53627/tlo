//! 16 Control Functions from local_mixing
//! Each gate can use any of these boolean functions on its two control wires

use rand::Rng;
use serde::{Deserialize, Serialize};

/// Control function set restriction for VBB-friendly circuits
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ControlFunctionSet {
    /// All 16 control functions (universal, non-VBB)
    #[default]
    All,
    /// Only 8 affine functions over GF(2) - circuit becomes C(x) = Mx + c
    /// Functions: F, T, A, B, Na, Nb, Xor, Equiv
    AffineOnly,
    /// Only XOR-based functions (strongest linearity)
    /// Functions: F, T, Xor, Equiv
    XorOnly,
}

/// The 8 affine control functions (degree <= 1 over GF(2))
pub const AFFINE_FUNCTIONS: [ControlFunction; 8] = [
    ControlFunction::F,     // 0
    ControlFunction::T,     // 1
    ControlFunction::A,     // a
    ControlFunction::B,     // b
    ControlFunction::Na,    // !a = 1 + a
    ControlFunction::Nb,    // !b = 1 + b
    ControlFunction::Xor,   // a ^ b = a + b
    ControlFunction::Equiv, // a == b = 1 + a + b
];

/// The 4 XOR-only functions (purely additive)
pub const XOR_FUNCTIONS: [ControlFunction; 4] = [
    ControlFunction::F,     // 0
    ControlFunction::T,     // 1
    ControlFunction::Xor,   // a + b
    ControlFunction::Equiv, // 1 + a + b
];

/// All 16 possible boolean functions of two variables
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ControlFunction {
    F = 0,     // false (constant 0)
    And = 1,   // a & b
    AndNb = 2, // a & !b
    A = 3,     // a (ignore b)
    AndNa = 4, // !a & b
    B = 5,     // b (ignore a)
    Xor = 6,   // a ^ b
    Or = 7,    // a | b
    Nor = 8,   // !(a | b)
    Equiv = 9, // a == b (XNOR)
    Nb = 10,   // !b
    #[default]
    OrNb = 11, // a | !b  (this is r57, our original default)
    Na = 12,   // !a
    OrNa = 13, // !a | b
    Nand = 14, // !(a & b)
    T = 15,    // true (constant 1)
}

impl ControlFunction {
    /// Create from u8 value
    pub const fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::F,
            1 => Self::And,
            2 => Self::AndNb,
            3 => Self::A,
            4 => Self::AndNa,
            5 => Self::B,
            6 => Self::Xor,
            7 => Self::Or,
            8 => Self::Nor,
            9 => Self::Equiv,
            10 => Self::Nb,
            11 => Self::OrNb,
            12 => Self::Na,
            13 => Self::OrNa,
            14 => Self::Nand,
            15 => Self::T,
            _ => Self::OrNb, // default to r57
        }
    }

    /// Evaluate the control function on two boolean inputs
    #[inline(always)]
    pub const fn evaluate(&self, a: bool, b: bool) -> bool {
        match self {
            Self::F => false,
            Self::And => a & b,
            Self::AndNb => a & !b,
            Self::A => a,
            Self::AndNa => !a & b,
            Self::B => b,
            Self::Xor => a ^ b,
            Self::Or => a | b,
            Self::Nor => !(a | b),
            Self::Equiv => a == b,
            Self::Nb => !b,
            Self::OrNb => a | !b,
            Self::Na => !a,
            Self::OrNa => !a | b,
            Self::Nand => !(a & b),
            Self::T => true,
        }
    }

    /// Evaluate using bit values (0 or 1)
    #[inline(always)]
    pub fn evaluate_bits(&self, a: usize, b: usize) -> usize {
        self.evaluate(a != 0, b != 0) as usize
    }

    /// Get the logical NOT of this function
    pub const fn not(&self) -> Self {
        match self {
            Self::F => Self::T,
            Self::And => Self::Nand,
            Self::AndNb => Self::OrNa,
            Self::A => Self::Na,
            Self::AndNa => Self::OrNb,
            Self::B => Self::Nb,
            Self::Xor => Self::Equiv,
            Self::Or => Self::Nor,
            Self::Nor => Self::Or,
            Self::Equiv => Self::Xor,
            Self::Nb => Self::B,
            Self::OrNb => Self::AndNa,
            Self::Na => Self::A,
            Self::OrNa => Self::AndNb,
            Self::Nand => Self::And,
            Self::T => Self::F,
        }
    }

    /// Check if this function is self-inverse (applying twice = identity)
    /// Only XOR-based functions are self-inverse
    pub const fn is_self_inverse(&self) -> bool {
        matches!(self, Self::F | Self::Xor | Self::Equiv | Self::T)
    }

    /// Get a random control function
    pub fn random(rng: &mut impl Rng) -> Self {
        Self::from_u8(rng.gen_range(0..16))
    }

    /// Get a random control function from a specific set
    pub fn random_from_set(rng: &mut impl Rng, set: ControlFunctionSet) -> Self {
        match set {
            ControlFunctionSet::All => Self::from_u8(rng.gen_range(0..16)),
            ControlFunctionSet::AffineOnly => AFFINE_FUNCTIONS[rng.gen_range(0..8)],
            ControlFunctionSet::XorOnly => XOR_FUNCTIONS[rng.gen_range(0..4)],
        }
    }

    /// Get a random non-trivial control function (excludes F, A, B, T)
    pub fn random_nontrivial(rng: &mut impl Rng) -> Self {
        loop {
            let f = Self::from_u8(rng.gen_range(0..16));
            if !matches!(f, Self::F | Self::A | Self::B | Self::T) {
                return f;
            }
        }
    }

    /// Get a random non-trivial control function from a specific set
    pub fn random_nontrivial_from_set(rng: &mut impl Rng, set: ControlFunctionSet) -> Self {
        match set {
            ControlFunctionSet::All => Self::random_nontrivial(rng),
            ControlFunctionSet::AffineOnly => {
                // Non-trivial affine: Na, Nb, Xor, Equiv (indices 4-7 in AFFINE_FUNCTIONS)
                AFFINE_FUNCTIONS[rng.gen_range(4..8)]
            }
            ControlFunctionSet::XorOnly => {
                // Non-trivial XOR: Xor, Equiv (indices 2-3 in XOR_FUNCTIONS)
                XOR_FUNCTIONS[rng.gen_range(2..4)]
            }
        }
    }

    /// Check if this control function is affine (degree <= 1 over GF(2))
    pub const fn is_affine(&self) -> bool {
        matches!(
            self,
            Self::F | Self::T | Self::A | Self::B | Self::Na | Self::Nb | Self::Xor | Self::Equiv
        )
    }

    /// Check if this control function is XOR-only (purely additive)
    pub const fn is_xor_only(&self) -> bool {
        matches!(self, Self::F | Self::T | Self::Xor | Self::Equiv)
    }

    /// Short name for display
    pub fn name(&self) -> &'static str {
        match self {
            Self::F => "0",
            Self::And => "a&b",
            Self::AndNb => "a&!b",
            Self::A => "a",
            Self::AndNa => "!a&b",
            Self::B => "b",
            Self::Xor => "a^b",
            Self::Or => "a|b",
            Self::Nor => "!(a|b)",
            Self::Equiv => "a==b",
            Self::Nb => "!b",
            Self::OrNb => "a|!b",
            Self::Na => "!a",
            Self::OrNa => "!a|b",
            Self::Nand => "!(a&b)",
            Self::T => "1",
        }
    }
}

/// Precomputed lookup table for fast evaluation
/// Index: (control_function << 2) | (a << 1) | b
pub const CONTROL_FUNC_TABLE: [bool; 64] = {
    let mut table = [false; 64];
    let mut idx = 0;
    while idx < 64 {
        let b = idx & 1 != 0;
        let a = (idx >> 1) & 1 != 0;
        let cf = ControlFunction::from_u8((idx >> 2) as u8);
        table[idx] = cf.evaluate(a, b);
        idx += 1;
    }
    table
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_function_evaluation() {
        // Test OrNb (r57): a | !b
        assert!(ControlFunction::OrNb.evaluate(false, false)); // 0 | 1 = 1
        assert!(ControlFunction::OrNb.evaluate(true, false)); // 1 | 1 = 1
        assert!(!ControlFunction::OrNb.evaluate(false, true)); // 0 | 0 = 0
        assert!(ControlFunction::OrNb.evaluate(true, true)); // 1 | 0 = 1
    }

    #[test]
    fn test_lookup_table() {
        for cf in 0..16u8 {
            for a in 0..2 {
                for b in 0..2 {
                    let idx = ((cf as usize) << 2) | (a << 1) | b;
                    let expected = ControlFunction::from_u8(cf).evaluate(a != 0, b != 0);
                    assert_eq!(CONTROL_FUNC_TABLE[idx], expected);
                }
            }
        }
    }

    #[test]
    fn test_not_is_inverse() {
        for cf in 0..16u8 {
            let f = ControlFunction::from_u8(cf);
            let not_f = f.not();
            for a in [false, true] {
                for b in [false, true] {
                    assert_eq!(f.evaluate(a, b), !not_f.evaluate(a, b));
                }
            }
        }
    }
}
