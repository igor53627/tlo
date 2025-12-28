# TLO Security Model (Revised)

## Terminology Note

We use "obfuscation" informally, in the tradition of code obfuscation and heuristic obfuscation (e.g., Canetti et al. 2024/006 "Local Mixing"), to denote **representation hiding** and **attack-surface hardening**. We do NOT claim indistinguishability obfuscation (iO), virtual-black-box (VBB) security, or any standard strong obfuscation definition.

## Two-Layer Security

| Layer | Component | Provides | Security Basis |
|-------|-----------|----------|----------------|
| **Topology** | Wire selection | Empirical resistance to structural/statistical attacks | Heuristic (empirical) |
| **LWE** | On-chain inner products | Representation hiding (CF bits hidden) | Computational (LWE) |

**Key property:** Unlocking reduces to secret search, not to preventing offline evaluation.

## Critical Clarification: What LWE Does and Does NOT Provide

### What LWE Provides
- **Representation hiding**: Control function bits are not directly readable from the static artifact without choosing an input x and computing H(x)
- **Wrong-key-gives-garbage**: Incorrect keys yield random CF bits, producing garbage outputs

### What LWE Does NOT Provide
- **Prevention of offline evaluation**: Since s(x) = H(x) is publicly computable, anyone can evaluate the locked predicate for arbitrary inputs x
- **Semantic security**: We do not hide the black-box functionality
- **Security beyond hash-compare for unlocking**: Unlocking difficulty is governed by secret entropy, not LWE

```
ATTACKER CAN:
  1. Pick any input x
  2. Compute s(x) = H(x)           ← Public, anyone can do this
  3. Compute b - <a, s(x)> mod q   ← Same math as contract
  4. Run circuit with decoded CF bits
  
  If x = secret → correct output (1)
  If x ≠ secret → garbage output (0/random)

SECURITY: Depends on secret entropy (e.g., 256-bit for bytes32)
          NOT on LWE hardness for unlocking
```

## Attack Resistance Matrix

| Attack | Type | Blocked By | Mechanism | Notes |
|--------|------|------------|-----------|-------|
| Compression | Structural | Topology | No duplicate gates | Empirical |
| PatternMatch | Structural | Topology | Random CF cycling | Empirical |
| DiagonalCorrelation | Statistical | Topology | 64+ wires spread changes | Empirical |
| Statistical | Statistical | Topology | Uniform wire selection | Empirical |
| Structural | Structural | Topology | Irregular layers + non-pow2 | Empirical |
| **RainbowTable** | **Semantic** | **LWE** | **Representation hiding** | Does NOT prevent black-box evaluation |

**Note on RainbowTable**: LWE blocks *structural* rainbow-table matching (extracting CF bits to identify circuit structure). It does NOT prevent an attacker from evaluating the circuit as a black-box for arbitrary inputs.

## Comparison with Hash-Compare

| Property | Hash-Compare | TLO |
|----------|--------------|-----|
| Unlocking difficulty | Secret entropy | Secret entropy |
| Offline evaluation | Yes (anyone can test) | Yes (anyone can test) |
| Representation hiding | No (predicate visible) | Yes (CF bits hidden) |
| Gas cost | ~45K | ~2.58M (57x) |
| Attack matrix resistance | 0/6 | 6/6 |

**Key insight**: In both designs, an attacker can evaluate the predicate on arbitrary inputs (on-chain or off-chain). The difficulty of finding a satisfying input before expiry depends on the secret's entropy and application-level constraints, NOT on LWE. TLO's advantage is hiding the internal predicate representation.

## Implementation

TLO computes LWE inner products on-chain for representation hiding:

| LWE n | Security | check() Gas | Use Case |
|-------|----------|-------------|----------|
| 16 | ~22-bit | ~744K | Low-value, short-lived |
| 32 | ~22-bit | ~1.27M | Medium-value |
| **64** | **~49-bit** | **~2.58M** | **Recommended** |
| 128 | ~81-bit | ~4.9M | High-value |

```solidity
// On-chain inner product computation
s = keccak256(input) expanded to n u16 elements mod q
innerProd = sum(a[i] * s[i]) mod q  // computed per gate
diff = (b - innerProd) mod q
cfBit = (diff > q/4) && (diff < 3*q/4)
```

**Security note**: The ~49-bit estimate bounds the cost of attacking LWE directly (recovering s_enc or distinguishing from uniform). In practice, a rational attacker will brute-force x and compare hashes instead. Practical security = min(LWE hardness, secret entropy).

## Security Assumptions

1. **LWE hardness**: Learning With Errors problem is computationally hard (for representation hiding)
2. **Topology empirical security**: Wire selection defeats structural attacks (heuristic, not proven)
3. **Secret entropy**: Application provides high-entropy secrets (e.g., 256-bit)
4. **Contract correctness**: Expiry logic is implemented correctly

## Threat Model

**Adversary capabilities:**
- Full access to bytecode and circuit data (public on-chain)
- Unlimited offline evaluation: can call check(x) simulation for any x
- PPT (probabilistic polynomial-time) with substantial offline compute resources
- Knowledge of obfuscation scheme (Kerckhoffs's principle)

**What adversary CANNOT do efficiently:**
- Recover CF bits without choosing an input x (LWE hardness)
- Find structural patterns in topology (empirical)
- Find satisfying input faster than brute-force (secret entropy)

**What adversary CAN do:**
- Evaluate the locked predicate for arbitrary inputs offline
- Build input/output tables by exhaustive evaluation
- Eventually find the secret by brute force (if entropy is low)

**Out of scope:**
- EVM side channels (gas timing, storage patterns)
- Multi-instance attacks
- Protocol logic bugs

## Post-Quantum Security

TLO's LWE layer provides **post-quantum representation hiding**:

| Component | PQ Status |
|-----------|-----------|
| Topology | N/A (no cryptographic assumptions) |
| **LWE** | **PQ-secure** - LWE resists quantum attacks |
| Unlocking | Depends on hash (Keccak is PQ-resistant) |

## What TLO Does NOT Provide

- **Prevention of offline evaluation**: Attackers can evaluate for arbitrary inputs
- **Indistinguishability (iO)**: Two circuits have distinguishable obfuscations
- **Semantic security**: Black-box functionality is available to anyone
- **Universal security**: Only resists our 6-class attack matrix
- **Forward secrecy**: Expired secrets may be analyzed retroactively
- **Security beyond hash-compare for unlocking**: Secret entropy governs unlocking difficulty

## Valid Applications

TLO is designed for predicates with **eventually-expiring secrets** where **representation hiding** (not semantic security) provides value:

- Cryptographic honeypots (reward burned once triggered)
- Sealed-bid auctions (bids revealed at settlement)
- Lotteries/prediction markets (outcomes revealed after close)
- MEV protection (order flow is short-lived)
- Dark pools (trade conditions expire quickly)

## Invalid Applications

TLO is NOT suitable for:

- Long-term decryption keys
- Permanent signing keys
- Static liquidation thresholds (attacker can simulate offline)
- Any application requiring semantic security (hiding what the predicate computes)
- Low-entropy secrets (brute-forceable regardless of LWE)

## Epoch Rotation (Archived)

**Note**: The epoch rotation model described previously (governance secret + state mutation) was analyzed and found to provide NO additional security beyond personalization. Since `private` variables are readable via `eth_getStorageAt`, and all inputs to the epoch seed derivation become public, an attacker can simulate any user's evaluation.

For applications requiring true secret-based computation, use:
- Threshold cryptography
- MPC (Multi-Party Computation)
- TEE (Trusted Execution Environments)

These are outside TLO's "no secret keys" constraint.
