//! Attack Suite for TLO Circuit Obfuscation
//!
//! Implements the 6-attack evaluation matrix used to validate TLO security.
//!
//! ## Attack Classification
//!
//! | Attack | Type | Blocked By |
//! |--------|------|------------|
//! | Compression | Structural | Topology |
//! | PatternMatch | Structural | Topology |
//! | DiagonalCorrelation | Statistical | Topology |
//! | Statistical | Statistical | Topology |
//! | Structural | Structural | Topology |
//! | RainbowTable | Semantic | LWE |

mod suite;

pub use suite::{AttackResult, AttackSuite};
