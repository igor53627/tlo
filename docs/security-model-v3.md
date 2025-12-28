# TLO Security Model v3 (Post-Critical Review)

## Executive Summary

TLO is a **representation-hiding point function lock**. The observable predicate on user input `x` is functionally equivalent to a hash equality check (`H(x) == target`). The 57x gas premium over hash commitment buys **structure obfuscation**, not stronger unlocking security.

This document honestly addresses critiques from adversarial review and clarifies TLO's narrow but real value proposition.

## What TLO Is

TLO (Topology-Lattice Obfuscation) combines:
- **Topology layer**: Wire selection patterns that resist structural/statistical analysis
- **LWE layer**: Control function encoding via Learning With Errors

The result is a circuit artifact where:
- Internal structure (control functions, wiring) is computationally hidden
- The observable predicate on input `x` is a point function

## The Point-Function Reality

### How TLO Works

```
User submits: x
Derive key:   s(x) = H(x)
Decrypt CF:   diff = (b - <a, s(x)>) mod q
              cfBit = Threshold(diff)
Evaluate:     circuit with decoded CF bits
Compare:      output vs expected_output_hash
```

### The Point-Function Collapse

Because the decryption key is derived from `H(x)`:
- If `x = secret`: `s(x) = s_secret` → CF bits decode correctly → circuit produces expected output
- If `x ≠ secret`: `s(x)` is essentially random → CF bits are garbage → output is random

**Observable behavior:**
```
P(x) = 1   if x = secret
     = 0   otherwise (with overwhelming probability)
```

This is **logically equivalent** to:
```solidity
function check(bytes32 x) view returns (bool) {
    return keccak256(abi.encodePacked(x)) == expected_hash;
}
```

### What This Means

| Property | Hash Commitment | TLO |
|----------|-----------------|-----|
| Unlocking difficulty | Secret entropy (256-bit) | Secret entropy (256-bit) |
| Offline evaluation | Yes | Yes |
| Observable predicate | Equality check | Equality check |
| Structure visible | Yes | **No** |
| Gas cost | ~45K | ~2.58M |

**TLO does not provide stronger unlocking security than a hash commitment.**

## What TLO Does Provide

### Multi-Bit Output: The Key Distinction

A critical difference between hash-compare and TLO:

| Approach | Output | What's Hidden |
|----------|--------|---------------|
| Hash-compare | 1 bit (true/false) | Secret value only |
| TLO circuit | N bits (multi-bit) | Secret value + hidden computation |

**Hash-compare** returns only a boolean: "does your input match?" The output conveys nothing beyond this binary answer.

**TLO circuits compute a function.** When the correct input is provided, the circuit evaluates to a multi-bit output that can encode:
- Hidden parameters (e.g., threshold offsets, multipliers)
- Computed results (e.g., PID controller outputs)
- Encoded payloads (revealed only on correct input)

Both implement **point functions** (meaningful only at x = secret), but:
- Hash-compare: 1-bit output ("yes, you found it")
- TLO: N-bit output ("here's the hidden result")

**The 57x gas premium buys multi-bit hidden computation, not stronger unlocking security.**

### Representation Hiding

TLO hides the **internal structure** of the circuit:
- Control function truth tables are LWE-encoded
- Gate topology is randomized via SixSix mixing
- Embedded payload (if any) requires LWE break to extract statically

An attacker cannot:
- Read CF bits directly from the artifact (requires LWE break)
- Identify circuit patterns via structural analysis (topology mixing)
- Build rainbow tables of known circuit templates

An attacker CAN:
- Evaluate the predicate on any input `x` (black-box access)
- Eventually find the secret via brute-force search

### Post-Quantum Properties

| Component | PQ Security |
|-----------|-------------|
| Topology | N/A (heuristic) |
| LWE layer | Yes (~49-bit for n=64) |
| Unlocking | Hash preimage (Keccak is PQ-resistant) |

## Limitations TLO Cannot Overcome

### 1. No Complex Predicates

TLO with `s(x) = H(x)` **cannot** support:
- Range queries (`x < threshold`)
- Fuzzy matching
- Multi-input conditions

The key derivation ensures only exact equality works. Any bit difference in `x` produces a completely different key, yielding garbage CF bits.

**To support richer predicates**, you would need:
- A fixed secret key not derived from `x` (violates "no on-chain secrets")
- Off-chain key management (MPC, TEE, threshold crypto)

### 2. No Semantic Security

TLO does NOT hide the black-box functionality:
- Anyone can simulate `check(x)` for arbitrary inputs
- Input/output tables can be built by exhaustive evaluation
- The predicate IS publicly known (it's an equality check)

### 3. No Cost-Effectiveness for Standard Use Cases

| Use Case | Best Tool | Reason |
|----------|-----------|--------|
| Equality check | Hash commitment | 57x cheaper |
| Range query | Not TLO | TLO cannot express |
| Long-lived secret | TEE/MPC | 49-bit LWE too weak |
| **Structure hiding + equality** | **TLO** | **Only valid niche** |

## The Payload Dilemma

If TLO is used to hide a payload (not just check equality):

| Attack Path | Cost | Outcome |
|-------------|------|---------|
| Find secret x | 2^256 | Full access |
| Break LWE (n=64) | ~2^49 | Extract structure/payload |

For **high-value, long-lived payloads**, 49-bit LWE is insufficient. Options:
- Increase `n` (gas explodes: n=512 would cost ~10M+ gas)
- Accept that TLO is for **short-lived, moderate-value** secrets only
- Use proper confidential compute (MPC/TEE) instead

## Valid Applications (Narrow)

TLO is justified ONLY when **representation hiding is the primary objective**:

| Application | Justification |
|-------------|---------------|
| Crypto puzzles / CTF | Mystery of artifact is the product |
| Honeypots | Structure hiding deters casual analysis |
| On-chain art | Obfuscation as aesthetic choice |
| Research prototype | Demonstrating keyless C&C on EVM |

## Invalid Applications

| Application | Why TLO is Wrong |
|-------------|------------------|
| Sealed-bid auctions | No semantic security; bids are evaluable |
| MEV protection | Strategies are evaluable offline |
| Dark pools | Order conditions are point functions only |
| Long-term secrets | 49-bit LWE is inadequate |
| Any range/threshold check | Point-function limitation |

## Comparison with Alternatives

| Approach | Predicates | Security | Gas | Secrets |
|----------|------------|----------|-----|---------|
| Hash commitment | Equality only | 256-bit | ~45K | None |
| **TLO** | **Equality only** | **256-bit unlock / 49-bit structure** | **~2.58M** | **None** |
| Commit-reveal | Any | 256-bit | ~50K | User-held |
| TEE/SGX | Any | Hardware trust | Off-chain | Enclave |
| MPC | Any | Threshold trust | Off-chain | Distributed |

## Novel Contributions (Honest Assessment)

TLO's contributions are **engineering/systems**, not cryptographic breakthroughs:

1. **Practical keyless C&C on EVM**: First implementation of LWE-based compute-and-compare that runs entirely on-chain without secret keys

2. **Topology mixing integration**: SixSix patterns + attack suite demonstrating empirical resistance to 6 attack classes

3. **Design space exploration**: Concrete gas/size benchmarks for LWE parameters (n=16/32/64/128)

4. **Honest security modeling**: Clear separation of unlocking security (hash) vs. representation hiding (LWE)

## Conclusion

TLO is NOT:
- Indistinguishability obfuscation
- Stronger than hash commitment for unlocking
- Suitable for complex predicates or high-value secrets

TLO IS:
- A representation-hiding point function
- Post-quantum structure obfuscation for equality checks
- Justified only when artifact obfuscation is the goal

The 57x gas premium over hash commitment is **not justified for security-driven applications**. It is justified only for niche use cases where structure hiding itself is valuable.

---

## Response to Specific Critiques

### "Point-Function Paradox"
**Acknowledged.** With `s(x) = H(x)`, TLO is mathematically restricted to equality checks. This is inherent to the keyless design.

### "Constant-Function Collapse"
**Acknowledged.** The observable predicate is equivalent to hash commitment. TLO's value is in representation hiding, not predicate expressiveness.

### "Functional Redundancy (57x gas)"
**Acknowledged for security use cases.** The premium is justified only when structure hiding is the objective.

### "Payload Dilemma"
**Acknowledged.** 49-bit LWE is insufficient for high-value payloads. TLO targets short-lived, moderate-value secrets.

### "Security Theater"
**Partially rejected.** Representation hiding IS a real property; it's just narrow in scope. TLO should not be oversold as general obfuscation.

---

*Revision: v3 (Post-adversarial review)*
*Date: December 2025*
