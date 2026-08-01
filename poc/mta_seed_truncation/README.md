# Legacy MTA Fiat-Shamir Seed Truncation Bug

## Summary

The function `generate_mta_range_zkp_seed()` in `src/common/cosigner/mta.cpp` hashes `proof.A` into the Fiat-Shamir challenge seed but incorrectly uses `BN_num_bytes(proof.S)` as the length parameter instead of `BN_num_bytes(proof.A)`. Since `proof.S` is typically 128 bytes while `proof.A` is 512 bytes, only 25% of A's representation is included in the challenge computation. Two distinct proof.A values sharing the same first 128 bytes will produce identical Fiat-Shamir challenges, potentially enabling proof forgery in the legacy MTA range ZKP.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.cpp` |
| **Function** | `generate_mta_range_zkp_seed()` (static inline, line ~115) |
| **Bug line** | Line 130 |
| **CWE** | CWE-327: Use of a Broken or Risky Cryptographic Algorithm (weakened Fiat-Shamir) |
| **Also applies** | CWE-131: Incorrect Calculation of Buffer Size |
| **Reachability** | Legacy path only; requires `MPC_PROTOCOL_VERSION < MPC_EXTENDED_MTA (11)` |

## Root Cause Analysis

Here is the vulnerable code from mta.cpp (lines 126-130):

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // BUG: uses S's size for A
```

The buffer `n` is correctly allocated to hold all of `proof.A` (512 bytes for a 2048-bit Paillier key). The `BN_bn2bin` call correctly serializes the full value of A into the buffer. But the `SHA256_Update` call passes `BN_num_bytes(proof.S)` as the length, which is only 128 bytes (the ring Pedersen modulus size).

This means bytes 128 through 511 of proof.A's big-endian representation are never fed into the hash.

**Contrast with the corrected extended path** (used when `MPC_PROTOCOL_VERSION >= 11`):

```cpp
// Extended seed path (correct):
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

The extended path uses `BN_bn2binpad` with the full expected size, ensuring the entire value is hashed. The legacy path was never updated to match.

### Size relationship in practice

| Component | Size formula | Typical value |
|-----------|-------------|---------------|
| `proof.A` | `2 * verifier_paillier_pub_n_size` | 512 bytes (2048-bit key) |
| `proof.S` | `ring_pedersen_n_size` | 128 bytes (1024-bit modulus) |
| **Bytes hashed** | `BN_num_bytes(proof.S)` | 128 of 512 |
| **Bytes ignored** | `BN_num_bytes(proof.A) - BN_num_bytes(proof.S)` | 384 bytes |

## Attack Scenario

**Adversary model:** A malicious party in the MPC signing protocol who interacts with a peer running a legacy protocol version (< 11). The attacker is a co-signer who wants to forge an MTA range proof to manipulate the signing process.

**Attack mechanics:**

1. The attacker generates a valid MTA range ZKP with some proof.A value (call it A1).
2. The attacker constructs A2, a different value that shares the same first 128 bytes as A1 in big-endian encoding but differs in bytes 128-511.
3. Because `generate_mta_range_zkp_seed` only hashes the first 128 bytes of A, both A1 and A2 produce the same Fiat-Shamir challenge `e`.
4. The attacker can now use the proof components computed for A1 but substitute A2, since the verifier will derive the same challenge and accept the proof.

**What property is broken:**

The Fiat-Shamir transform requires that the challenge `e` is cryptographically bound to ALL public proof elements, including the full value of A. When only a fraction of A determines the challenge, the proof's soundness guarantee weakens: the effective soundness parameter no longer covers variations in the high-order 384 bytes of A.

In the context of the MTA protocol, A is the Paillier encryption of the prover's masked input. Being able to substitute different A values while keeping the same challenge means the prover can potentially present different encrypted inputs to different verifiers, or manipulate the relationship between the proof and the underlying ciphertext.

**Reachability caveat:** The current default protocol version is `MPC_BAM_ECDSA = 13`, which is above the `MPC_EXTENDED_MTA = 11` threshold. The legacy path is used only when communicating with peers running protocol version < 11. However, the code explicitly maintains backward compatibility for this path, and version downgrade scenarios (key migration, mixed deployments) are realistic in production environments.

## Proof of Concept

### Building

```bash
cd poc/mta_seed_truncation/
g++ -std=c++17 -O2 poc.cpp -o poc -lcrypto
```

### Running

```bash
./poc
```

### Expected Output

```
=== PoC: Legacy MTA Fiat-Shamir Seed Truncation ===

[*] proof.A size: 512 bytes (4096 bits)
[*] proof.S size: 128 bytes (1024 bits)
[*] Bytes of A hashed into challenge: 128 (only 25.0%)
[*] Bytes of A IGNORED by challenge:  384

[+] Confirmed: A1 != A2 (they differ in bytes 128..511)

--- Vulnerable (legacy) seed generation ---
[*] Seed with A1: <32 hex bytes>
[*] Seed with A2: <32 hex bytes>

[!] COLLISION: Both A values produce IDENTICAL Fiat-Shamir seeds!
[!] This means the challenge e = H(seed) is the same for both.
[!] An attacker can substitute A2 for A1 without changing the challenge.

--- Correct (extended) seed generation ---
[*] Seed with A1: <32 hex bytes - different>
[*] Seed with A2: <32 hex bytes - different>

[+] CORRECT: Different A values produce different seeds.
[+] The extended seed path (MPC_PROTOCOL_VERSION >= 11) is not affected.
```

The PoC constructs two BIGNUM values A1 and A2 that share the same first 128 bytes but differ in the remaining 384 bytes. It then shows that the vulnerable seed function produces identical SHA-256 digests for both, while the corrected version does not.

## Impact Assessment

| Dimension | Assessment |
|-----------|------------|
| **Soundness** | Weakened. The Fiat-Shamir challenge does not fully bind to proof.A. |
| **Forgery risk** | An attacker can find A values that produce the same challenge, since 384 bytes of freedom are unconstrained. |
| **Reachability** | Legacy path only (protocol version < 11). Current default is version 13. |
| **Deployment risk** | Mixed-version deployments, backward-compatible sessions, or forced downgrades could trigger the legacy path. |
| **Bugcrowd category** | Cryptographic implementation flaw (weakened zero-knowledge proof) |
| **Suggested rating** | P4 (Low) due to legacy-only reachability; P3 (Medium) if version downgrade is feasible |

## Recommended Fix

Replace `BN_num_bytes(proof.S)` with `BN_num_bytes(proof.A)` on line 130:

```diff
--- a/src/common/cosigner/mta.cpp
+++ b/src/common/cosigner/mta.cpp
@@ -127,7 +127,7 @@ static inline void generate_mta_range_zkp_seed(const cmp_mta_message& response,
 
     std::vector<uint8_t> n(BN_num_bytes(proof.A));
     BN_bn2bin(proof.A, n.data());
-    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // right size of S is ensured during serialization
+    SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.A)); // hash full A value
 
     SHA256_Update(&ctx, proof.Bx, sizeof(elliptic_curve256_point_t));
```

Alternatively, for consistency with the extended path, use `BN_bn2binpad` with an explicit expected size:

```cpp
const uint32_t a_expected_size = 2 * verifier_paillier_pub_n_size;
std::vector<uint8_t> n(a_expected_size);
BN_bn2binpad(proof.A, n.data(), a_expected_size);
SHA256_Update(&ctx, n.data(), a_expected_size);
```

This matches the approach used in `generate_mta_range_zkp_extended_seed` and ensures constant-size encoding regardless of the actual magnitude of A.

**Note on the misleading comment:** The original code has the comment `// right size of S is ensured during serialization` on the buggy line. This comment appears to have been added to justify the use of `BN_num_bytes(proof.S)`, but it refers to a different concern (serialization validation) and does not address the fact that the wrong field's size is being used for the hash length.

## References

- [Fiat-Shamir Heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) - Requires ALL public values to be included in the hash for soundness
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- Fireblocks MPC Library, `src/common/cosigner/mta.cpp`, function `generate_mta_range_zkp_seed`
- Fireblocks MPC Library, `include/cosigner/mpc_globals.h`, `MPC_EXTENDED_MTA = 11`
- CMP-ECDSA Protocol Specification, MTA Range ZKP construction
