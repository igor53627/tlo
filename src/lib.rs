//! TLO: Topology-Lattice Obfuscation
//!
//! Practical circuit obfuscation for smart contracts combining topology mixing
//! with lattice-based cryptography (LWE).

pub mod attacks;
pub mod circuit;
pub mod compute_and_compare;
pub mod control_function;
pub mod lockable_obfuscation;
pub mod rainbow;
pub mod six_six;
pub mod vdf_obfuscation;

pub use circuit::{Circuit, Gate};
pub use control_function::ControlFunction;
pub use six_six::{create_six_six_circuit, SixSixConfig};
