# Security Audit Report: Fireblocks MPC Cryptographic Library

**Date:** 2024  
**Scope:** Full source code review of `mpc-lib` - threshold MPC signing protocols (CMP-ECDSA, BAM, EdDSA, FROST)  
**Methodology:** Manual code review with focus on cryptographic implementation correctness, side-channel resistance, memory safety, and protocol-level soundness  

---

## Executive Summary

This report documents findings from a comprehensive security audit of the Fireblocks MPC cryptographic library. The audit focused on identifying subtle implementation issues that could affect the security guarantees described in the library's threat model (SECURITY-MODEL.md SS1.2). The review covered all cryptographic primitives, zero-knowledge proof implementations, key derivation paths, and protocol-level code.

The audit identified **20 findings** spanning multiple categories:
- Non-constant-time comparisons in ZKP verifiers (potential timing side-channels)
- Missing secret zeroing on stack and heap (sensitive data memory persistence)
- Inconsistent use of secure memory allocation patterns
- Fiat-Shamir transcript ambiguity in legacy code paths
- Missing input validation in proof verification routines
- Defense-in-depth gaps in error handling

Most findings are Medium to Low severity under the project's own severity framework (SS5), as they require specific conditions or co-located attacker capabilities to exploit. No Critical (P1) findings were identified.

---

## Methodology

1. **Static Analysis:** Manual review of all C/C++ source files under `src/common/crypto/` and `src/common/cosigner/`
2. **Pattern Matching:** Identification of inconsistent security patterns (e.g., `CRYPTO_memcmp` vs `memcmp`, `BN_clear_free` vs `BN_free`, `BN_CTX_secure_new` vs `BN_CTX_new`)
3. **Data Flow Analysis:** Tracing secret material through computation paths to identify exposure windows
4. **Protocol Analysis:** Reviewing Fiat-Shamir challenge derivation for transcript binding completeness
5. **Threat Model Alignment:** Each finding evaluated against SS1.2 guarantees and SS4.5/SS5 severity criteria

**Out of Scope (per SECURITY-MODEL.md):**
- ZKP verifier accepting point at infinity (SS3.2, SS6.6)
- DRNG determinism (SS2.5, SS6.2)
- `is_coprime_fast` timing (SS6.5)
- Integrator contract violations (SS2)
- Small key sizes at the primitive layer (SS6.1)
- Test code (SS2.6)

---

## Findings Summary

| # | Severity | Category | Location | Title |
|---|----------|----------|----------|-------|
| 1 | Medium | Side-Channel | `paillier_zkp.c:468` | Non-constant-time `memcmp` in Paillier factorization ZKP verification |
| 2 | Medium | Side-Channel | `diffie_hellman_log.c:168,181,200` | Non-constant-time `memcmp` in DH-log ZKP verification |
| 3 | Medium | Side-Channel | `range_proofs.c:796,1312,1325` | Non-constant-time `memcmp` in range proof EC point verification |
| 4 | Low | Memory Safety | `ring_pedersen.c:207-210` | Missing secret zeroing in key pair generation error path |
| 5 | Medium | Memory Safety | `hd_derive.cpp:85-100` | HMAC key material not zeroed on stack after HD derivation |
| 6 | Low | Memory Safety | `hd_derive.cpp:103-130` | Stack-based `PrivKey unused` never zeroed in `derive_public_key_generic` |
| 7 | Low | Side-Channel | `ed25519_algebra.c:113` | Non-constant-time `memcmp` in `ed25519_is_valid_point` |
| 8 | Low | Arithmetic | `paillier_zkp.c:838-844` | Potential integer overflow in `paillier_blum_zkp_serialized_size` |
| 9 | Low | Input Validation | `range_proofs.c:750-796` | Missing coprimality check on deserialized proof element z2 |
| 10 | Low | Memory Safety | `paillier.c (multiple)` | Inconsistent use of `BN_CTX_secure_new` vs `BN_CTX_new` for secret operations |
| 11 | Low | Memory Safety | `paillier.c:104-170` | Missing `BN_clear` on BN_CTX pool entries in error paths |
| 12 | Low | Side-Channel | `diffie_hellman_log.c:14-27` | Variable-time `cmp_uint256` scalar comparison |
| 13 | Low | Input Validation | `mta.cpp:196-226` | MTA proof deserialization size slack allows leading-zero manipulation |
| 14 | Informational | Correctness | `GFp_curve_algebra.c:237-299` | Potential use of uninitialized EC_POINT in `verify_sum` |
| 15 | Informational | Correctness | `ring_pedersen.c:119` | Lambda not checked for zero after `BN_rand_range` |
| 16 | Informational | Input Validation | `verifiable_secret_sharing.c:400-420` | VSS share IDs not validated against group order |
| 17 | Informational | Input Validation | `schnorr.c:152-187` | Missing explicit validation of `proof->R` point before use |
| 18 | Low | Correctness | `paillier.c:455` | `assert` for p/q size equality removed in release builds |
| 19 | Medium | Protocol | `mta.cpp:107-128` | Fiat-Shamir transcript length ambiguity in non-extended MTA mode |
| 20 | Medium | Side-Channel | Multiple files | Inconsistent constant-time comparison patterns across ZKP verifiers |

---

## Detailed Findings


### Finding 1: Non-constant-time `memcmp` in Paillier Factorization ZKP Verification

**Severity:** Medium (P3)  
**Category:** Side-Channel (SS4.5)  
**File:** `src/common/crypto/paillier/paillier_zkp.c`  
**Line:** 468  

**Description:**

The function `paillier_verify_factorization_zkpok` uses standard `memcmp` to compare a computed SHA-256 hash against the proof's committed value:

```c
ret = (memcmp(x, sha256_md, PAILLIER_SHA256_LEN) == 0) ? PAILLIER_SUCCESS : PAILLIER_ERROR_INVALID_PROOF;
```

Standard `memcmp` performs byte-by-byte comparison and returns early on the first mismatch. In the context of ZKP verification, this creates an oracle: an attacker who can measure verification time learns how many leading bytes of their forged hash match the expected value. This information could aid incremental construction of a valid proof hash.

**Impact:**

An attacker with co-located timing capabilities (e.g., co-tenant on shared infrastructure) could potentially determine partial hash match lengths during proof verification. While exploiting this to forge a complete valid proof would require breaking SHA-256 preimage resistance, the timing signal reduces the effective search space for certain byte positions.

**Comparison with Codebase Patterns:**

The codebase uses `CRYPTO_memcmp` correctly in `commitments.c:39,123` and `GFp_curve_algebra.c:228` for analogous hash/point comparisons, demonstrating awareness of the requirement. This specific site appears to be an oversight.

**Recommendation:**

Replace `memcmp` with `CRYPTO_memcmp`:
```c
ret = (CRYPTO_memcmp(x, sha256_md, PAILLIER_SHA256_LEN) == 0) ? PAILLIER_SUCCESS : PAILLIER_ERROR_INVALID_PROOF;
```

---

### Finding 2: Non-constant-time `memcmp` in DH-log ZKP Verification

**Severity:** Medium (P3)  
**Category:** Side-Channel (SS4.5)  
**File:** `src/common/crypto/zero_knowledge_proof/diffie_hellman_log.c`  
**Lines:** 168, 181, 200  

**Description:**

The Diffie-Hellman log ZKP verifier (`diffie_hellman_log_verify`) performs three sequential EC point comparisons using plain `memcmp`:

```c
if (memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
    return ZKP_VERIFICATION_FAILED;
```

Each comparison occurs at a different stage of the multi-equation verification (verifying g^z = B^e * D, base^w = X^e * Y, and A^z * g^w = C^e * V). The early-return pattern combined with non-constant-time comparison allows an attacker observing verification timing to determine:
1. Which verification equation failed
2. How many bytes of the computed point matched before divergence

**Impact:**

In a protocol context where a malicious prover submits proofs to an honest verifier and can observe timing (SS4.5 attacker model), the three-stage leak reveals which part of the proof equation is failing. This structural information could guide iterative proof forgery attempts, reducing the search space for valid proof components.

**Comparison with Codebase Patterns:**

The GFp algebra layer uses `EC_POINT_cmp` (via OpenSSL) for point comparison in `GFp_curve_algebra.c:289`, and `CRYPTO_memcmp` in `GFp_curve_algebra.c:228`. The ZKP code bypasses these patterns by comparing serialized point representations directly.

**Recommendation:**

Replace all three `memcmp` calls with `CRYPTO_memcmp`:
```c
if (CRYPTO_memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) != 0)
    return ZKP_VERIFICATION_FAILED;
```

---

### Finding 3: Non-constant-time `memcmp` in Range Proof EC Point Verification

**Severity:** Medium (P3)  
**Category:** Side-Channel (SS4.5)  
**File:** `src/common/crypto/zero_knowledge_proof/range_proofs.c`  
**Lines:** 796, 1312, 1325  

**Description:**

Multiple range proof verification functions use plain `memcmp` for EC point comparison during the final verification step:

```c
status = memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0 ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
```

These occur in:
- `range_proof_exponent_zkpok_verify` (line 796): comparing computed points in the exponent proof
- `range_proof_diffie_hellman_zkpok_verify` (lines 1312, 1325): two separate point comparisons in the DH variant

**Impact:**

The timing variation from early-return `memcmp` is observable by a co-located attacker. In range proofs specifically, the comparison reveals whether the prover's claimed range relationship holds for the EC component. Since range proofs are used to prove that MtA shares lie within acceptable bounds, any information leakage about partial verification success could assist in crafting proofs that narrowly miss detection.

**Inconsistency:**

This is inconsistent with the same codebase's use of `CRYPTO_memcmp` in `GFp_curve_algebra.c:228` and the ed25519 algebra layer (`ed25519_algebra.c:203,257`), which perform constant-time point comparisons for identical logical operations.

**Recommendation:**

Replace all instances with `CRYPTO_memcmp`:
```c
status = CRYPTO_memcmp(p1, p2, sizeof(elliptic_curve256_point_t)) == 0 ? ZKP_SUCCESS : ZKP_VERIFICATION_FAILED;
```

---

### Finding 4: Missing Secret Zeroing in `ring_pedersen_generate_key_pair` Error Path

**Severity:** Low (P4)  
**Category:** Sensitive-Data Memory Persistence (SS4.2)  
**File:** `src/common/crypto/commitments/ring_pedersen.c`  
**Lines:** 207-210  

**Description:**

When key generation fails after the `local_priv` structure has been allocated but before success, the error path calls:

```c
if (local_priv)
{
    free(local_priv);
}
```

This `free()` does not zero the structure's contents before releasing the memory. If `local_priv` was partially populated with pointers to sensitive BIGNUMs (n, s, t, lambda, phi_n), the freed memory retains these pointer values. More critically, the BIGNUMs pointed to by `local_priv->pub.n`, `local_priv->pub.s`, `local_priv->pub.t` are freed with `BN_free` (not `BN_clear_free`), and `local_priv->lambda` and `local_priv->phi_n` are freed with `BN_clear_free`.

The inconsistency means `n`, `s`, and `t` (which contain values derived from secret primes p and q) are not securely zeroed before deallocation.

**Impact:**

On error paths during Ring-Pedersen key generation, secret-derived values (particularly `n = p*q` and commitment parameters) may persist in freed heap memory. If a separate memory disclosure primitive exists (SS4.2), these values could be recovered.

**Recommendation:**

Use `BN_clear_free` for all BIGNUMs containing secret-derived material:
```c
BN_clear_free(n);
BN_clear_free(s);
BN_clear_free(t);
```

Additionally, zero the `local_priv` structure with `OPENSSL_cleanse(local_priv, sizeof(*local_priv))` before `free()`.

---

### Finding 5: HMAC Key Material Not Zeroed on Stack After HD Derivation

**Severity:** Medium (P3)  
**Category:** Sensitive-Data Memory Persistence (SS4.2)  
**File:** `src/common/blockchain/mpc/hd_derive.cpp`  
**Lines:** 85-100  

**Description:**

In `derive_next_key_level_`, the `hash` buffer (64 bytes) holds the HMAC-SHA512 output used for BIP-32 key derivation:

```cpp
uint8_t hash[64];
hd_derive_status retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
```

The first 32 bytes of `hash` become the child key tweak (added to the parent private key to produce the child key), and the last 32 bytes become the derived chain code. Neither the `hash` buffer nor the intermediate values are zeroed with `OPENSSL_cleanse` before the function returns.

This leaves 64 bytes of key derivation material on the stack. If the stack frame is later reused without initialization (common in C/C++), or if a memory disclosure vulnerability exists, an attacker could recover:
- The key tweak value (enabling reconstruction of the child private key from the parent)
- The derived chain code (enabling derivation of all subsequent child keys in the BIP-32 hierarchy)

**Impact:**

Recovery of a single HD derivation hash output enables full reconstruction of the child key and all descendant keys in that BIP-32 subtree. This directly threatens long-term key secrecy (SS1.2.1) if combined with a memory disclosure primitive.

**Recommendation:**

Add `OPENSSL_cleanse(hash, sizeof(hash))` before every return path in `derive_next_key_level_`.

---

### Finding 6: Stack-based `PrivKey unused` Never Zeroed in `derive_public_key_generic`

**Severity:** Low (P4)  
**Category:** Sensitive-Data Memory Persistence (SS4.2)  
**File:** `src/common/blockchain/mpc/hd_derive.cpp`  
**Lines:** 103-130  

**Description:**

The function `derive_public_key_generic` declares a `PrivKey unused` on the stack:

```cpp
PrivKey unused;
```

This buffer is passed to `derive_next_key_level_` with `derive_private=false`. While the function is not supposed to write a meaningful private key in this mode, the `unused` parameter is still passed as the `derived_privkey` output parameter. The buffer is never zeroed with `OPENSSL_cleanse` before the function returns, and its stack contents persist.

Additionally, `derive_next_key_level_` may write to this buffer in some code paths (e.g., if the `derive_private` flag logic changes or if the compiler optimizes differently). The lack of explicit cleanup means any stale stack data in the `PrivKey`-sized region remains accessible.

**Impact:**

If `unused` contains stale key material from a prior call in the same stack frame (stack reuse), or if a memory disclosure primitive reads the stack, private key data could be exposed.

**Recommendation:**

Add `OPENSSL_cleanse(unused, sizeof(unused))` before return in `derive_public_key_generic`.

---

### Finding 7: Non-constant-time `memcmp` in `ed25519_is_valid_point`

**Severity:** Low (P4)  
**Category:** Side-Channel (SS4.5)  
**File:** `src/common/crypto/ed25519_algebra/ed25519_algebra.c`  
**Line:** 113  

**Description:**

The point validity check performs:

```c
return memcmp(point, p2, sizeof(ed25519_point_t)) == 0 ? 1 : 0;
```

This checks whether `point == 8 * (8^-1 * point)` to validate that the point has order in the main subgroup (not a small-order point). The comparison is not constant-time.

**Impact:**

If `ed25519_is_valid_point` is called during key import, point validation before signing, or protocol message processing where an attacker can observe timing, the non-constant-time comparison leaks information about how many bytes of the input point match the expected valid-point representation. This is a lower-severity finding because:
1. The ed25519 algebra layer uses `CRYPTO_memcmp` correctly in other functions (lines 203, 257, 749, 828)
2. The input point is typically public in protocol contexts

However, in scenarios where point validation timing reveals whether a specific point was accepted or rejected (and how close it was to valid), this could assist in probing the verifier's behavior.

**Recommendation:**

Replace with `CRYPTO_memcmp` for consistency with the rest of the ed25519 module:
```c
return CRYPTO_memcmp(point, p2, sizeof(ed25519_point_t)) == 0 ? 1 : 0;
```

---

### Finding 8: Potential Integer Overflow in `paillier_blum_zkp_serialized_size`

**Severity:** Low (P4)  
**Category:** Arithmetic Safety  
**File:** `src/common/crypto/paillier/paillier_zkp.c`  
**Lines:** 838-844  

**Description:**

The serialized size computation uses `uint64_t` arithmetic:

```c
static inline uint64_t paillier_blum_zkp_serialized_size(const paillier_public_key_t *pub, const uint8_t use_all_nth_roots)
{
    uint64_t n_len = (uint64_t)BN_num_bytes(pub->n);
    return sizeof(uint32_t) +
          n_len +
          (n_len + sizeof(uint8_t) * 2) * PAILLIER_BLUM_STATISTICAL_SECURITY +
          (MINIMUM_NUMBER_OF_NTH_ROOTS + use_all_nth_roots * (PAILLIER_BLUM_STATISTICAL_SECURITY - MINIMUM_NUMBER_OF_NTH_ROOTS)) * n_len;
}
```

While the cast to `uint64_t` prevents overflow for all reasonable key sizes (up to ~2^32 bytes), there is no explicit bounds check on `n_len` before the multiplication. The caller eventually casts the result to a buffer allocation size. If the public key's `n` were corrupted or maliciously crafted with an extremely large byte representation (e.g., via deserialization of untrusted data), the intermediate computation could produce an unexpectedly large or wrapped value.

**Impact:**

In practice, key sizes are bounded by the protocol layer. However, if a malformed serialized key with a huge `n` reaches this code, the allocation size could wrap or produce a heap allocation much smaller than needed, leading to heap buffer overflow during subsequent serialization writes.

**Recommendation:**

Add explicit bounds checking on `n_len` before the computation:
```c
if (n_len > MAX_PAILLIER_KEY_BYTES)
    return 0; // or error
```

---

### Finding 9: Missing Coprimality Check on Deserialized z2 in Range Proof Verification

**Severity:** Low (P4)  
**Category:** Input Validation  
**File:** `src/common/crypto/zero_knowledge_proof/range_proofs.c`  
**Lines:** 750-796  

**Description:**

In `range_proof_exponent_zkpok_verify`, the verifier checks coprimality for several proof elements against the appropriate moduli (D and ciphertext against `paillier->n`, S and T against `ring_pedersen->n`). However, the `z2` value, which is used as a randomness input to `paillier_encrypt_openssl_internal`, has no explicit coprimality check before use.

The `paillier_encrypt_openssl_internal` function internally performs the coprimality check and returns an error. However, this error propagates as a generic "unknown error" rather than a clear "verification failed" result, because the calling code treats any Paillier operation failure as an internal error rather than a proof validation failure.

**Impact:**

A malicious prover could submit a proof with `z2` not coprime to `n`, causing the verifier to return an ambiguous error code rather than a definitive verification failure. While this does not bypass the proof check (the proof still fails), it could confuse error-handling logic in the calling protocol code that distinguishes between "invalid proof" and "internal error" states.

**Recommendation:**

Add an explicit coprimality check for `z2` before passing it to Paillier operations, and map the result to `ZKP_VERIFICATION_FAILED`:
```c
if (!is_coprime_fast(z2, paillier->n))
{
    status = ZKP_VERIFICATION_FAILED;
    goto cleanup;
}
```

---

### Finding 10: Inconsistent Use of `BN_CTX_secure_new` vs `BN_CTX_new`

**Severity:** Low (P4)  
**Category:** Sensitive-Data Memory Persistence (SS4.2)  
**File:** Multiple files across `src/common/crypto/`  

**Description:**

The codebase demonstrates awareness of OpenSSL's secure heap through `BN_CTX_secure_new()` in `paillier_generate_private` (which correctly uses the secure allocation pool for prime generation). However, many other functions handling secret material use plain `BN_CTX_new()`:

- `paillier_decrypt` (handles plaintext of encrypted secrets)
- `ring_pedersen_generate_key_pair` (handles secret primes p, q and lambda)
- Various ZKP generation functions (handle witness values)

`BN_CTX_secure_new` ensures that all temporary BIGNUMs allocated from the context reside in mlock'd memory that is guaranteed to be zeroed on free and never paged to disk. Plain `BN_CTX_new` allocations may be paged to swap, leaving secret material in persistent storage.

**Impact:**

Intermediate computation values derived from secrets (decrypted plaintexts, key generation intermediates, ZKP witness computations) may reside in pageable memory. On systems without encrypted swap or memory locking, these values could persist on disk after process termination.

**Recommendation:**

Audit all `BN_CTX_new()` call sites that handle secret-derived values and replace with `BN_CTX_secure_new()`. Priority sites:
1. `ring_pedersen_generate_key_pair` - handles p, q, lambda
2. `paillier_decrypt` - handles decrypted secrets
3. ZKP generation functions that compute witness-dependent intermediates

---

### Finding 11: Missing `BN_clear` on BN_CTX Pool Entries in Paillier Key Generation Error Paths

**Severity:** Low (P4)  
**Category:** Sensitive-Data Memory Persistence (SS4.2)  
**File:** `src/common/crypto/paillier/paillier.c`  
**Lines:** 104-170  

**Description:**

In `paillier_generate_private`, the key generation loop uses `BN_CTX_get` to obtain temporary BIGNUMs (`tmp`) from the context pool. If an intermediate operation (e.g., `BN_mul`, `BN_sub`) fails mid-loop, execution jumps to the cleanup label. The cleanup calls `BN_CTX_end(ctx)` followed by `BN_CTX_free(ctx)`.

However, `BN_CTX_end`/`BN_CTX_free` does NOT guarantee secure zeroing of the BN_CTX pool entries. The `tmp` variable may have held intermediate products of the secret primes (e.g., `p*q`, `(p-1)*(q-1)`) before the failure, and these values persist in the freed BN_CTX pool memory.

Note: The function does use `BN_CTX_secure_new()`, which mitigates this for the secure heap path. However, if the secure heap is exhausted and OpenSSL falls back to regular allocation, or if the platform does not support mlock, the intermediates are exposed.

**Impact:**

On error paths, secret prime products may persist in freed memory. Combined with a memory disclosure primitive, this could reveal factorization of the Paillier modulus.

**Recommendation:**

Explicitly call `BN_clear(tmp)` on all BN_CTX-obtained BIGNUMs that have held secret-derived values before calling `BN_CTX_end`. Alternatively, ensure `BN_CTX_secure_new` is verified to have succeeded (not fallen back) by checking the return value.

---

### Finding 12: Variable-time `cmp_uint256` Scalar Comparison

**Severity:** Low (P4)  
**Category:** Side-Channel (SS4.5)  
**File:** `src/common/crypto/zero_knowledge_proof/diffie_hellman_log.c`  
**Lines:** 14-27  

**Description:**

The static helper function `cmp_uint256` implements a variable-time comparison with early return:

```c
static inline int cmp_uint256(const uint8_t *a, const uint8_t *b)
{
    const uint64_t *aptr = (const uint64_t*)a;
    const uint64_t *bptr = (const uint64_t*)b;

    for (size_t i = 0; i < sizeof(elliptic_curve256_scalar_t) / sizeof(uint64_t); i++)
    {
        uint64_t n1 = bswap_64(*aptr);
        uint64_t n2 = bswap_64(*bptr);
        if (n1 > n2)
            return 1;
        else if (n1 < n2)
            return -1;
        aptr++;
        bptr++;
    }
    return 0;
}
```

This function is used in `diffie_hellman_log_generate_e` (line 82) to compare the derived Fiat-Shamir challenge `e` against the curve order. The early-return behavior leaks information about the most-significant limbs of the challenge value relative to the curve order.

**Impact:**

Since this runs during ZKP *generation* on the prover side, the timing leak is primarily observable by the prover's own environment. In a scenario where the prover's execution is monitored (e.g., SGX side-channels, hypervisor-level timing), the comparison timing reveals the position of the first differing limb between the challenge and the order. This could assist in reconstructing the Fiat-Shamir challenge, though the challenge is derived from public transcript data and is itself public once the proof is complete.

The severity is Low because the compared values (challenge and curve order) are either public or derivable from public data. The concern is primarily about defense-in-depth consistency.

**Recommendation:**

Replace with a constant-time comparison or use OpenSSL's `BN_ucmp` after converting to BIGNUMs (which is already done later in the function for modular reduction).

---

### Finding 13: MTA Proof Deserialization Size Slack Allows Leading-Zero Manipulation

**Severity:** Low (P4)  
**Category:** Input Validation  
**File:** `src/common/cosigner/mta.cpp`  
**Lines:** 196-226  

**Description:**

In `deserialize_mta_range_zkp`, the deserialization routine reads the first field (proof.A) using `paillier_priv_n_size * 2` as the expected size. The validation logic then checks against `paillier_priv_n_size * 2 - EPSILON_BYTES` where `EPSILON_BYTES = 8`.

This 8-byte slack means a proof element A that is up to 8 bytes shorter than the maximum expected size will still pass the size validation. An attacker could submit proofs with leading zeros in the A field that pass the size check but represent numerically smaller values than the verifier expects.

**Impact:**

While the mathematical verification should catch any semantically invalid proof regardless of leading zeros (since the BIGNUM operations normalize the value), the size slack creates an inconsistency between what the serialization format expects and what it accepts. In edge cases, a smaller-than-expected A value combined with specific algebraic relationships could produce false negatives in verification (proof incorrectly rejected) rather than false positives (proof incorrectly accepted), so the security impact is limited to potential availability issues rather than soundness breaks.

**Recommendation:**

Tighten the size validation to require exact padding, or document the EPSILON_BYTES tolerance with a security rationale explaining why the slack does not affect soundness.

---

### Finding 14: Potential Use of Uninitialized EC_POINT in `GFp_curve_algebra_verify_sum`

**Severity:** Informational (P5)  
**Category:** Correctness / Undefined Behavior  
**File:** `src/common/crypto/GFp_curve_algebra/GFp_curve_algebra.c`  
**Lines:** 237-299  

**Description:**

In `GFp_curve_algebra_verify_sum`, the EC_POINT `point` is created with `EC_POINT_new()`:

```c
point = EC_POINT_new(ctx->curve);
```

`EC_POINT_new` returns a newly allocated point but does not guarantee initialization to the point at infinity. The subsequent loop accumulates points via `EC_POINT_add(ctx->curve, point, point, tmp, bn_ctx)`. The correctness of this accumulation depends on `point` starting as the identity element.

In current OpenSSL implementations (1.1.1+), `EC_POINT_new` does zero-initialize the internal coordinates, which effectively represents the point at infinity. However, this is implementation-dependent behavior, not a documented API guarantee.

**Impact:**

If a future OpenSSL version changes the initialization behavior of `EC_POINT_new`, or if the code is ported to a different EC library, the accumulation loop would produce incorrect results. In the current deployment, this is not exploitable.

**Recommendation:**

Explicitly initialize `point` to the identity:
```c
point = EC_POINT_new(ctx->curve);
if (!point) goto cleanup;
EC_POINT_set_to_infinity(ctx->curve, point);
```

---

### Finding 15: Lambda Not Checked for Zero After `BN_rand_range` in Ring-Pedersen Key Generation

**Severity:** Informational (P5)  
**Category:** Correctness / Edge Case  
**File:** `src/common/crypto/commitments/ring_pedersen.c`  
**Line:** 119  

**Description:**

After generating the secret exponent lambda:

```c
if (!BN_rand_range(lambda, phi))
{
    goto cleanup;
}
```

There is no check that `lambda != 0`. `BN_rand_range` produces a value in `[0, phi)`. If lambda is zero, then `s = t^lambda = t^0 = 1`, making the Ring-Pedersen commitment scheme trivially insecure: all commitments `C(x, r) = s^x * t^r = 1^x * t^r = t^r` become independent of the committed value x.

**Impact:**

The probability of lambda being exactly zero is `1/phi`, which is astronomically small for any reasonable key size (phi is approximately 2^4096 for a 4096-bit modulus). This is a theoretical correctness concern, not a practical vulnerability.

**Recommendation:**

Add a zero-check for defense in depth:
```c
do {
    if (!BN_rand_range(lambda, phi))
        goto cleanup;
} while (BN_is_zero(lambda));
```

---

### Finding 16: VSS Share IDs Not Validated Against Group Order

**Severity:** Informational (P5)  
**Category:** Input Validation  
**File:** `src/common/crypto/shamir_secret_sharing/verifiable_secret_sharing.c`  
**Lines:** 400-420  

**Description:**

In `lagrange_interpolate`, share IDs are loaded into BIGNUMs with:

```c
BN_set_word(x, shares[index].id)
```

Share IDs are `uint64_t` values. The function performs modular arithmetic in the field (mod group order), so large IDs are mathematically valid. However, the IDs are never validated to be:
1. Non-zero (a share evaluated at x=0 reveals the secret directly)
2. Distinct (duplicate IDs cause division by zero in Lagrange basis computation)
3. Within the group order (IDs >= order would collide with IDs reduced mod order)

**Impact:**

If an attacker can influence share ID assignment (which is typically an integrator responsibility per SS2), they could:
- Submit a share with ID=0 that trivially reveals the secret
- Submit duplicate IDs causing Lagrange interpolation to fail or produce incorrect results

Under the integrator contract (SS2), share ID assignment is the integrator's responsibility. This finding is informational because it identifies a defense-in-depth gap rather than a library vulnerability.

**Recommendation:**

Add validation at the library level as defense in depth:
```c
if (shares[index].id == 0) return VERIFIABLE_SECRET_SHARING_INVALID_PARAMETER;
```

Additionally, check for duplicate IDs before interpolation.

---

### Finding 17: Missing Explicit Validation of `proof->R` in Schnorr ZKP Verify

**Severity:** Informational (P5)  
**Category:** Input Validation / Defense in Depth  
**File:** `src/common/crypto/zero_knowledge_proof/schnorr.c`  
**Lines:** 152-187  

**Description:**

The Schnorr ZKP verifier `schnorr_zkp_verify` uses `proof->R` in the verification equation without first validating that it represents a valid curve point:

```c
SHA256_Update(&sha_ctx, proof->R, sizeof(proof->R));
// ... later ...
status = algebra->verify_linear_combination(algebra, &proof->R, points, ones, 2, &res);
```

The `verify_linear_combination` function internally deserializes the point (which performs format validation through OpenSSL's `EC_POINT_oct2point`), so invalid point encodings would be caught. However, the point is first hashed into the challenge derivation without validation.

**Impact:**

If `proof->R` contains an invalid point encoding, the challenge `c` is derived from potentially garbage data, and the verification will fail at the `verify_linear_combination` step. The concern is that the error mode is "verification returns error/failed" rather than "invalid input parameter" - this is a minor API contract issue rather than a security vulnerability.

The deeper concern is whether a malformed `R` that happens to pass OpenSSL's point deserialization but represents a point not on the curve (or on a twist) could produce a valid verification. OpenSSL's `EC_POINT_oct2point` does validate curve membership, so this is mitigated by the underlying library.

**Recommendation:**

Add explicit point validation before use for defense in depth:
```c
if (algebra->verify_point(algebra, &proof->R) != ELLIPTIC_CURVE_ALGEBRA_SUCCESS)
    return ZKP_INVALID_PARAMETER;
```

---

### Finding 18: `assert` for p/q Size Equality Removed in Release Builds

**Severity:** Low (P4)  
**Category:** Correctness / Robustness  
**File:** `src/common/crypto/paillier/paillier.c`  
**Line:** 455 (approximately)  

**Description:**

The private key serialization function uses `assert` to validate a critical invariant:

```c
p_len = (uint32_t)BN_num_bytes(priv->p);
assert(p_len == (uint32_t)BN_num_bytes(priv->q));
needed_len = sizeof(uint32_t) + 2 * p_len;
```

In release builds compiled with `NDEBUG` defined, `assert` is a no-op. If `p` and `q` have different byte lengths (possible due to memory corruption, deserialization bugs, or edge cases in prime generation where one prime has fewer significant bits), the serialization would:
1. Compute `needed_len` based only on `p_len`
2. Serialize `q` into a buffer sized for `p_len` bytes
3. If `q` is larger than `p`, cause a buffer overwrite

**Impact:**

Under normal operation, p and q are generated to have equal bit lengths. However, if this invariant is violated (e.g., through deserialization of a corrupted key, or via a key imported from an external source), release builds would silently produce malformed serialized output or trigger undefined behavior.

**Recommendation:**

Replace `assert` with a runtime check that returns an error:
```c
p_len = (uint32_t)BN_num_bytes(priv->p);
if (p_len != (uint32_t)BN_num_bytes(priv->q))
    return NULL; // or appropriate error
```

---

### Finding 19: Fiat-Shamir Transcript Length Ambiguity in Non-Extended MTA Mode

**Severity:** Medium (P3)  
**Category:** Protocol / Cryptographic Failure (SS4.2)  
**File:** `src/common/cosigner/mta.cpp`  
**Lines:** 107-128 (non-extended `generate_mta_range_zkp_seed`)  

**Description:**

In the non-extended (legacy) mode of `generate_mta_range_zkp_seed`, hash inputs are fed into SHA-256 without explicit length prefixes:

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // uses S's size for A's data

// ...
n.resize(BN_num_bytes(proof.By));
BN_bn2bin(proof.By, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.By));

n.resize(BN_num_bytes(proof.E));
BN_bn2bin(proof.E, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.E));
```

Multiple issues:
1. **Length ambiguity:** Different (A, By, E, F, S, T) tuples could hash identically if their byte representations concatenate to the same stream. Without length separators, `A || By` and `A' || By'` could collide if `A` ends with bytes that are `By'`'s prefix.
2. **Suspicious size mismatch:** The comment `// right size of S is ensured during serialization` suggests using `BN_num_bytes(proof.S)` to hash A's data, which may hash a truncated or over-read buffer depending on relative sizes.

The extended mode (used in newer protocol versions) fixes this by using fixed-size padded representations via `hash_bn()` with explicit size parameters. However, the legacy non-extended mode remains in the codebase and is reachable.

**Impact:**

If an attacker can craft two different proof tuples that produce the same Fiat-Shamir challenge (due to the length ambiguity), they could potentially reuse a proof across different statements. This would break the binding property of the Fiat-Shamir transformation and could allow proof reuse or statement substitution in the MTA protocol.

The practical exploitability depends on whether the attacker can find meaningful proof tuples that concatenate identically. Given the constraints on valid proof elements (they must pass mathematical verification), this is difficult but not provably impossible.

**Recommendation:**

1. Deprecate the non-extended seed generation mode
2. If backward compatibility requires keeping it, add explicit length prefixes:
```cpp
uint32_t len = BN_num_bytes(proof.A);
SHA256_Update(&ctx, &len, sizeof(len));
SHA256_Update(&ctx, n.data(), len);
```

---

### Finding 20: Inconsistent Constant-Time Comparison Patterns Across ZKP Verifiers (Systemic)

**Severity:** Medium (P3)  
**Category:** Side-Channel / Code Quality (SS4.5)  
**Files:** Multiple across `src/common/crypto/`  

**Description:**

The codebase exhibits an inconsistent pattern regarding constant-time comparisons in security-sensitive contexts:

**Uses `CRYPTO_memcmp` (correct):**
- `GFp_curve_algebra.c:228` - `verify_mul_data`
- `ed25519_algebra.c:203` - `verify_mul_data`
- `ed25519_algebra.c:257` - `verify_sum`
- `commitments.c:39,123` - commitment verification
- `pedersen.c:133` - Pedersen commitment verification

**Uses plain `memcmp` (inconsistent):**
- `paillier_zkp.c:468` - Paillier factorization ZKP verification
- `diffie_hellman_log.c:168,181,200` - DH-log ZKP verification (3 instances)
- `range_proofs.c:796,1312,1325` - Range proof verification (3 instances)
- `ed25519_algebra.c:113` - `ed25519_is_valid_point`

This inconsistency suggests that the constant-time requirement was applied to some modules but missed in others, likely due to different authors or development phases. The pattern creates a systemic risk: code reviewers may assume all comparisons in the crypto layer are constant-time (based on the correct examples) and miss the vulnerable sites.

**Aggregate Impact:**

Individually, each non-constant-time comparison is Low to Medium severity. In aggregate, they create a broader side-channel surface across the ZKP verification layer. An attacker with timing observation capability (SS4.5) could probe multiple ZKP verifiers simultaneously to maximize information leakage. The total information leaked across all verification steps in a single protocol round could exceed what any individual comparison reveals.

**Recommendation:**

1. Perform a codebase-wide audit replacing all `memcmp` in cryptographic verification paths with `CRYPTO_memcmp`
2. Add a coding standard rule or static analysis check to flag `memcmp` usage in files under `src/common/crypto/`
3. Consider a wrapper macro (e.g., `SECURE_COMPARE`) that is easier to grep for in code review

---


## Recommendations Summary

### High Priority (Address in Next Release)

1. **Constant-time comparisons:** Replace all `memcmp` in ZKP verification paths with `CRYPTO_memcmp` (Findings 1-3, 7, 20). This is a low-effort, high-value change.

2. **HD derivation secret cleanup:** Add `OPENSSL_cleanse` for the `hash` buffer and `unused` PrivKey in `hd_derive.cpp` (Findings 5-6). These are direct key-material exposure paths.

3. **Fiat-Shamir transcript fix:** Deprecate or fix the non-extended MTA seed generation to include explicit length prefixes (Finding 19). This has the highest theoretical severity among the findings.

### Medium Priority (Address in Subsequent Release)

4. **Secure memory allocation consistency:** Replace `BN_CTX_new` with `BN_CTX_secure_new` in all functions handling secrets (Finding 10). Audit `BN_free` vs `BN_clear_free` usage for secret-derived values (Findings 4, 11).

5. **Runtime assertions:** Replace all `assert` statements on security-critical invariants with runtime error returns (Finding 18).

6. **Input validation hardening:** Add explicit coprimality checks before Paillier operations in proof verification (Finding 9). Add bounds checks in size computation functions (Finding 8).

### Low Priority (Defense in Depth)

7. **Edge case guards:** Add zero-checks for lambda (Finding 15), share ID validation (Finding 16), and explicit EC_POINT initialization (Finding 14).

8. **Proof point validation:** Add explicit point-on-curve checks before ZKP verification uses proof elements (Finding 17).

9. **Coding standards:** Establish and enforce a rule requiring `CRYPTO_memcmp` for all comparisons in `src/common/crypto/`. Consider a pre-commit hook or CI check.

---

## Conclusion

The Fireblocks MPC library demonstrates strong cryptographic engineering practices in many areas, including proper use of `BN_FLG_CONSTTIME` for sensitive BIGNUMs, `BN_CTX_secure_new` for key generation, and `OPENSSL_cleanse` in several hot paths. The findings in this report represent inconsistencies and gaps in applying these patterns uniformly across the codebase.

No Critical (P1) or High (P2) findings were identified. The most significant findings are the systemic non-constant-time comparisons in ZKP verifiers (Medium) and the Fiat-Shamir transcript ambiguity in legacy MTA code (Medium). All findings require either co-located timing access or a separate memory disclosure primitive to exploit, placing them in the Medium/Low range under the project's severity framework.

The codebase would benefit from a systematic pass to enforce constant-time comparisons in all verification paths and ensure secret material is properly zeroed in all code paths (success and error).

