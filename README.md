# TLO: Topology-Lattice Obfuscation

Practical circuit obfuscation for smart contracts combining topology mixing with lattice-based cryptography (LWE).

## Overview

TLO provides a two-layer security model:

1. **Topology Layer**: Structural mixing defeats structural/statistical attacks (empirically validated)
2. **LWE Layer**: On-chain inner products hide control functions (~49-bit security with n=64)

**Important**: TLO provides *representation hiding*, not semantic security. Attackers can evaluate the locked predicate offline; unlocking security reduces to secret search.

## Repository Structure

```
tlo/
├── paper/                    # Academic papers (LaTeX + PDFs)
│   ├── tlo-paper.tex         # Full paper
│   ├── tlo-conference.tex    # Conference version (honest claims)
│   └── *.pdf                 # Built PDFs
├── docs/                     # Security documentation
│   ├── security-model-v3.md  # Current security model
│   └── security-model-v2.md  # Previous version
├── src/                      # Rust implementation
│   ├── six_six.rs            # Topology layer (SixSix mixing)
│   ├── compute_and_compare.rs # LWE layer (C&C obfuscation)
│   ├── circuit.rs            # Core circuit types
│   └── attacks/              # Attack suite (6 classes)
├── contracts/                # Solidity honeypot contracts
│   ├── tlo-cac/              # Compute-and-Compare variant
│   ├── tlo-full-lwe/         # Full LWE variant
│   └── interfaces/           # Contract interfaces
├── scripts/
│   └── lattice_attack/       # LWE attack scripts and analysis
├── examples/                 # Usage examples
└── tests/                    # Test suite
```

## Security Estimates (Uniform-Secret LWE)

TLO uses **uniform secrets**: `s_enc = H(secret)` expanded to n elements mod q. This is harder to attack than small-secret LWE.

| LWE n | Classical | Quantum | Gas | Notes |
|-------|-----------|---------|-----|-------|
| 16 | ~22-bit | ~20-bit | 744K | Toy |
| 32 | ~22-bit | ~20-bit | 1.27M | Low |
| **64** | **~49-bit** | **~45-bit** | **2.58M** | Short-lived secrets |
| 128 | ~81-bit | ~74-bit | 5.1M | Medium-lived |
| 256 | ~132-bit | ~120-bit | 10.1M | NIST-level |

## Attack Resistance Matrix

| Attack | Type | Blocked By | Status |
|--------|------|------------|--------|
| Compression | Structural | Topology | Blocked |
| PatternMatch | Structural | Topology | Blocked |
| DiagonalCorrelation | Statistical | Topology | Blocked |
| Statistical | Statistical | Topology | Blocked |
| Structural | Structural | Topology | Blocked |
| RainbowTable | Semantic | LWE | Blocked* |

*Blocks structural rainbow-table matching; does not prevent black-box evaluation.

## Quick Start

### Rust Library

```bash
cargo add tlo
```

```rust
use tlo::{SixSixConfig, create_six_six_circuit};
use tlo::attacks::AttackSuite;

// Create topology-optimized circuit
let config = SixSixConfig::default(); // 64 wires, 640 gates
let circuit = create_six_six_circuit(&config);

// Verify attack resistance
let suite = AttackSuite::new();
let results = suite.run_all(&circuit);
for (name, result) in results {
    println!("{}: {}", name, if result.success { "PASSED" } else { "BLOCKED" });
}
```

### Lattice Attack Scripts

```bash
cd scripts/lattice_attack

# Run security estimator (uniform-secret model)
python3 uniform_secret_estimator.py

# Run BKZ attack on TLO instance (requires fpylll)
python3 break_tlo.py --n 64 --gates 640 --block-size 100
```

### Solidity Contracts

```bash
cd contracts
forge build
forge test
```

## Valid Applications

TLO is designed for predicates with **eventually-expiring secrets**:

- Cryptographic honeypots
- Sealed-bid auctions
- Lotteries/prediction markets
- MEV protection
- Dark pools

## Invalid Applications

TLO is NOT intended for:

- Long-term decryption keys
- Permanent signing keys
- Static liquidation thresholds
- Applications requiring semantic security

## Papers

- **Full paper**: [paper/tlo-paper.pdf](paper/tlo-paper.pdf)
- **Conference version**: [paper/tlo-conference.pdf](paper/tlo-conference.pdf)
- **Security model**: [docs/security-model-v3.md](docs/security-model-v3.md)

## Related

- Main research repo: [circuit-mixing-research](https://github.com/igor53627/circuit-mixing-research)

## License

MIT
