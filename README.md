# TLO: Topology-Lattice Obfuscation

Practical circuit obfuscation for smart contracts combining topology mixing with lattice-based cryptography.

## Repository Structure

```
tlo/
├── paper/                    # Academic paper and documentation (coming soon)
├── src/                      # Rust implementation (coming soon)
├── contracts/                # Solidity honeypot contracts (coming soon)
├── scripts/
│   └── lattice_attack/       # LWE attack scripts and security analysis
├── examples/                 # Usage examples (coming soon)
└── tests/                    # Test suite (coming soon)
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

## Available Now

### Lattice Attack Scripts

```bash
cd scripts/lattice_attack

# Run security estimator (uniform-secret model)
python3 uniform_secret_estimator.py

# Run BKZ attack on TLO instance (requires fpylll)
python3 break_tlo.py
```

See [scripts/lattice_attack/README.md](scripts/lattice_attack/README.md) for details.

## Coming Soon

- Full paper (LaTeX source)
- Rust implementation (`src/`)
- Solidity contracts (`contracts/`)
- Examples and tests

## Related

- Main research repo: [circuit-mixing-research](https://github.com/igor53627/circuit-mixing-research)

## License

MIT
