# Batch MTA Verification Uses Only 8-bit Random Scalars (40 bits total security)

## Summary

The function `batch_response_verifier::process_paillier()` in `src/common/cosigner/mta.cpp` generates random blinding scalars (`gamma`) for batch verification using single bytes from a `uint8_t` array. Each gamma value ranges from 0 to 255, providing only 8 bits of entropy. With `BATCH_STATISTICAL_SECURITY = 5` independent verification slots, the total statistical security of the batch check is 5 * 8 = 40 bits. The CMP protocol paper (IACR ePrint 2020/492) specifies a minimum of 80 bits for batch verification soundness, meaning the implementation achieves only half the required security level.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **File** | `src/common/cosigner/mta.cpp` |
| **Function** | `batch_response_verifier::process_paillier()` (line ~1140) |
| **Constant** | `mta.h` line 123: `BATCH_STATISTICAL_SECURITY = 5` |
| **CWE** | CWE-331: Insufficient Entropy |
| **Also applies** | CWE-330: Use of Insufficiently Random Values |
| **Reachability** | Any signing request with 3+ blocks (triggers batch mode via MIN_BATCH_SIZE = 6) |

## Root Cause Analysis

Here is the vulnerable code from mta.cpp (lines 1140-1175):

```cpp
uint8_t random[2 * BATCH_STATISTICAL_SECURITY];  // 10 bytes total
if (RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t)) != 1)
{
    // ... error handling ...
}

// ... (first MTA verification setup) ...

for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
{
    if (!BN_set_word(gamma, random[i * 2]))   // gamma = single byte (0-255)!
    {
        // ... error handling ...
    }
    if (!BN_mod_exp_mont(tmp1, B, gamma, _my_paillier->pub.n2, _ctx.get(), _my_mont.get()))
    {
        // ... B raised to the power of an 8-bit value ...
    }
    // ... accumulate into _mta_B[i] and _mta_ro[i] ...
}
```

The root cause is twofold:

1. **The random buffer is typed as `uint8_t`**, meaning each element holds exactly one byte (0-255).
2. **`BN_set_word(gamma, random[i * 2])`** sets gamma to the numeric value of a single byte. Since `random[i * 2]` is a `uint8_t`, gamma can only take values in [0, 255].

The same pattern repeats for the second MTA verification (commitment check), using odd-indexed bytes: `BN_set_word(gamma, random[i * 2 + 1])`.

### Why 40 bits is insufficient

In batch verification, the verifier computes a random linear combination of individual verification equations. The soundness guarantee relies on the blinding scalars having enough entropy that a cheating prover cannot predict or brute-force the combination.

| Parameter | Current value | Required minimum (CMP paper) | Recommended |
|-----------|---------------|------------------------------|-------------|
| Bits per gamma | 8 | 16 (for 80-bit total with 5 slots) | 26+ (for 128-bit total) |
| Number of slots | 5 | 5 | 5 |
| Total security | 40 bits | 80 bits | 128 bits |
| Forgery probability | 2^{-40} | 2^{-80} | 2^{-128} |

### Additional issue: gamma = 0 is accepted without validation

When `random[i * 2] == 0`, the code sets gamma = 0 via `BN_set_word(gamma, 0)`. There is no check rejecting this value. The consequences are severe for the affected slot:

- `BN_mod_exp_mont(tmp1, B, gamma, ...)` computes `B^0 = 1`
- The accumulated product `_mta_B[i] *= 1` is unchanged
- That slot contributes NOTHING to the batch verification for that particular proof
- ANY value of B (even a completely invalid one) will pass that slot's check

**Probability analysis for production workloads:**

| Metric | Calculation | Value |
|--------|-------------|-------|
| P(gamma=0) for one slot, one proof | 1/256 | 0.39% |
| P(at least one gamma=0 in 5 slots) per proof | 1 - (255/256)^5 | ~1.9% |
| Expected gamma=0 events for 100 proofs (50 blocks x 2 MTAs) | 100 * 5 / 256 | ~1.95 |
| Expected gamma=0 events for 1000 proofs (500 blocks x 2 MTAs) | 1000 * 5 / 256 | ~19.5 |

When gamma=0 occurs for a slot, that slot's security contribution for that specific proof drops to zero. While the other 4 slots still provide 32 bits of security for that proof, the aggregate guarantee degrades below the already-insufficient 40-bit target.

## Ring Pedersen Single Accumulator Architecture

The Ring Pedersen batch check uses a fundamentally different (and independently weak) architecture:

```cpp
// mta.cpp:1248-1345, batch_response_verifier::process_ring_pedersen()
uint64_t gamma[2];
RAND_bytes(reinterpret_cast<uint8_t*>(&gamma[0]), 2 * sizeof(uint64_t));  // 16 random bytes
gamma[0] &= 0xffffffffffULL;  // Truncate to 40 bits
gamma[1] &= 0xffffffffffULL;  // Truncate to 40 bits
```

The structure:
- `gamma[0]` (40 bits): used for the `s^z1 * t^z3 == E * S^e` check
- `gamma[1]` (40 bits): used for the `s^z2 * t^z4 == F * T^e` check
- Both accumulate into ONE `_pedersen_t_exp` value for ALL proofs in the batch
- Both accumulate into ONE `_pedersen_B` value for ALL proofs in the batch

**Final verification (a single check for ALL proofs combined):**
```
t^(_pedersen_t_exp mod phi_n) == _pedersen_B mod n
```

This is ONE modular exponentiation check that covers ALL proofs in the batch simultaneously. An attacker submitting one invalid proof among many valid ones needs their invalid contribution to cancel out in the accumulated product, which succeeds with probability exactly 2^{-40} (the entropy of the gamma assigned to their proof).

## No Fallback to Individual Verification

This is a critical architectural decision that maximizes the impact of a successful forgery:

```cpp
// batch_response_verifier::verify() at mta.cpp:~1052
void batch_response_verifier::verify()
{
    // checks accumulated products
    // if any check fails:
    throw cosigner_exception(cosigner_exception::INVALID_PARAMETERS);
}
```

If batch verification **passes** (honestly or fraudulently), ALL proofs are accepted. There is no second pass, no individual re-check, no opportunity to catch the invalid proof. The attack succeeds completely.

If batch verification **fails**, the entire signing operation is aborted (all proofs rejected). There is NO "retry with individual verification" path that might catch which specific proof was bad.

**Contrast with the single-proof verifier:**
```cpp
// single_response_verifier::process() checks each proof individually during processing
// single_response_verifier::verify() is empty - checks already done
virtual void verify() override {} // empty
```

The `single_response_verifier` (used for < 6 blocks) checks each proof individually during `process()`, immediately rejecting invalid proofs with no probabilistic element. The batch verifier trades this certainty for performance, accepting a probabilistic guarantee that is far too weak at 40 bits.

## Attack Scenario

**Adversary model:** A malicious co-signer participating in the CMP-ECDSA signing protocol. The attacker wants to submit invalid MTA range proofs that bypass verification, allowing manipulation of the additive shares used in signing.

**Trigger conditions:**

The batch verification path activates when `num_of_blocks >= MIN_BATCH_SIZE` (defined as `BATCH_STATISTICAL_SECURITY + 1 = 6` in mta.h). Since there are 2 MTA operations per ECDSA signature block, a signing request with 3 or more blocks generates 6+ MTA verifications and triggers batch mode.

**Production trigger analysis:**
- 3+ signature blocks = 6 MTA operations (2 per block) = triggers batch mode
- `MAX_BLOCKS_TO_SIGN = 1000` (defined in `mpc_globals.h:10`)
- Multi-signature wallet operations routinely use 3+ blocks (batch payouts, exchange withdrawals, treasury operations)
- A malicious co-signer can request up to 1000 blocks in a single session, all processed through the same batch verifier with only 40-bit security

**Attack steps:**

1. The attacker initiates or participates in a multi-block signing session (3+ blocks) to ensure batch verification is used instead of individual verification.

2. The attacker submits a crafted MTA response containing an invalid range proof. The proof violates the range constraint on the MTA additive share, but this violation is hidden behind the batch verification.

3. The batch verifier generates 5 gamma scalars, each only 8 bits. The combined statistical security is 40 bits.

4. With probability 2^{-40} (approximately 9.1 * 10^{-13}), the invalid proof passes the batch check.

5. If accepted, the invalid additive share allows the attacker to bias or recover the signing nonce, potentially enabling key extraction.

**Comparison to intended security:**

At 80-bit security (what the CMP paper requires), the forgery probability would be 2^{-80}, approximately 8.3 * 10^{-25}. The actual implementation is 2^{40} times weaker than intended.

## Proof of Concept

### Building

```bash
cd poc/batch_mta_40bit_security/
g++ -std=c++17 -O2 poc.cpp -o poc -lcrypto
```

### Running

```bash
./poc
```

### Expected Output

```
=== PoC: Batch MTA Verification 8-bit Gamma Scalars ===

=== Trigger Conditions ===

From mta.h:
  BATCH_STATISTICAL_SECURITY = 5
  MIN_BATCH_SIZE = BATCH_STATISTICAL_SECURITY + 1 = 6

The batch path activates when num_of_blocks >= MIN_BATCH_SIZE = 6.
Since there are 2 MTA operations per ECDSA signature block,
a signing request with 3 blocks triggers 6 MTA verifications,
which equals MIN_BATCH_SIZE and activates batch mode.

--- Vulnerable gamma generation (reproduces mta.cpp logic) ---

Raw random buffer (10 bytes): <hex>

Generated gamma values (first MTA verification, even-indexed bytes):
  gamma[0] = <1-2 hex digits> (8 bits)
  gamma[1] = <1-2 hex digits> (8 bits)
  gamma[2] = <1-2 hex digits> (8 bits)
  gamma[3] = <1-2 hex digits> (8 bits)
  gamma[4] = <1-2 hex digits> (8 bits)

[!] Maximum possible gamma value: 255 (0xFF)
[!] Bit-length of any gamma:      at most 8 bits
[!] Effective entropy per gamma:   8 bits (uniform over 0-255)

[!] CRITICAL: gamma = 0 occurs with probability 1/256 per slot.
    ...

--- Correct gamma generation (128-bit scalars) ---

Generated gamma values with proper 128-bit entropy:
  gamma[0] = <32 hex digits> (128 bits)
  gamma[1] = <32 hex digits> (128 bits)
  ...

=== Security Analysis ===

Vulnerable implementation:
  Gamma bit-length:         8 bits (uint8_t, values 0-255)
  Independent slots:        5 (BATCH_STATISTICAL_SECURITY)
  Total statistical security: 5 * 8 = 40 bits
  Forgery probability:      2^{-40} per batch

CMP paper requirement (IACR ePrint 2020/492):
  Minimum statistical security: 80 bits
  ...
```

The PoC reproduces the gamma generation logic from `process_paillier()`, demonstrates that each gamma is limited to 8 bits, computes the resulting security level, and contrasts it with proper 128-bit gamma values.

## Impact Assessment

| Dimension | Assessment |
|-----------|------------|
| **Soundness** | Batch verification provides 40 bits of statistical security instead of the required 128 bits (or minimum 80 bits) |
| **Forgery probability** | 2^{-40} per batch, which is 2^{88} times weaker than the 128-bit standard |
| **Reachability** | Active on any signing session with 3+ blocks (common in production multi-signature operations) |
| **Maximum batch size** | Up to 1000 blocks (2000 MTA operations), all verified with the same 40-bit security |
| **What it bypasses** | MTA range proofs that constrain additive shares to safe ranges |
| **No fallback** | If batch verification passes fraudulently, attack succeeds with no second chance. No individual re-verification path exists. |
| **gamma=0 degradation** | ~1.9% of proofs have at least one dead verification slot, further degrading below 40 bits |
| **Downstream impact** | Invalid additive shares can bias the signing nonce, potentially enabling key extraction |
| **Bugcrowd category** | Section 4.2 bullet 3: "Incomplete ZKP generation... does not achieve the soundness level its parameters claim" |
| **Suggested rating** | P3 (Medium): achievable security is less than one-third of the protocol specification; batch mode is the default path for multi-block signing; no verification fallback |

## Recommended Fix

### Fix 1: Use proper multi-byte random scalars for gamma

Replace the `uint8_t` random buffer with proper multi-byte random scalars. Each gamma should have at least 128 bits of entropy:

```diff
--- a/src/common/cosigner/mta.cpp
+++ b/src/common/cosigner/mta.cpp
@@ -1140,8 +1140,10 @@ void batch_response_verifier::process_paillier(...)
     }
 
-    uint8_t random[2 * BATCH_STATISTICAL_SECURITY];
-    if (RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t)) != 1)
+    // Each gamma needs at least 128 bits of entropy for adequate statistical security.
+    static constexpr size_t GAMMA_BYTE_LEN = 16;  // 128 bits per scalar
+    uint8_t random[2 * BATCH_STATISTICAL_SECURITY * GAMMA_BYTE_LEN];
+    if (RAND_bytes(random, sizeof(random)) != 1)
     {
         LOG_ERROR("Failed to get random number, error %lu", ERR_get_error());
         throw_cosigner_exception(cosigner_exception::INTERNAL_ERROR);
@@ -1170,7 +1172,7 @@ void batch_response_verifier::process_paillier(...)
 
     for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
     {
-        if (!BN_set_word(gamma, random[i * 2]))
+        if (!BN_bin2bn(&random[i * 2 * GAMMA_BYTE_LEN], GAMMA_BYTE_LEN, gamma) == NULL)
         {
             LOG_ERROR("Failed to set random number, error %lu", ERR_get_error());
             throw_cosigner_exception(cosigner_exception::NO_MEM);
```

And similarly for the second loop (commitment verification) using the odd-indexed blocks.

### Fix 2: Reject gamma = 0 values

Add validation after generating each gamma to ensure it is non-zero:

```diff
+    // Ensure gamma is non-zero (B^0 = 1 contributes nothing to batch check)
+    if (BN_is_zero(gamma))
+    {
+        // Resample or set to 1; with 128-bit gammas this is astronomically unlikely
+        // but defense-in-depth requires the check
+        BN_one(gamma);
+    }
```

With 128-bit gamma values, the probability of gamma=0 is negligible (2^{-128}). However, the explicit check provides defense-in-depth and documents the requirement clearly.

### Fix 3: Update Ring Pedersen gamma to 128 bits

```diff
--- a/src/common/cosigner/mta.cpp
+++ b/src/common/cosigner/mta.cpp
@@ Ring Pedersen batch check
-    uint64_t gamma[2];
-    RAND_bytes(reinterpret_cast<uint8_t*>(&gamma[0]), 2 * sizeof(uint64_t));
-    gamma[0] &= 0xffffffffffULL;  // 40 bits
-    gamma[1] &= 0xffffffffffULL;  // 40 bits
+    // Use 128-bit random coefficients for Ring Pedersen batch check
+    uint8_t gamma_bytes[2][16];
+    RAND_bytes(gamma_bytes[0], 16);
+    RAND_bytes(gamma_bytes[1], 16);
+    BIGNUM *gamma_rp[2] = {BN_new(), BN_new()};
+    BN_bin2bn(gamma_bytes[0], 16, gamma_rp[0]);
+    BN_bin2bn(gamma_bytes[1], 16, gamma_rp[1]);
```

Alternatively, increase `BATCH_STATISTICAL_SECURITY` to compensate, but fixing the gamma bit-length is the correct approach since it addresses the root cause without adding computational overhead from extra modular exponentiations:

```diff
--- a/src/common/cosigner/mta.h
+++ b/src/common/cosigner/mta.h
@@ -123,1 +123,2 @@
-    static constexpr const size_t BATCH_STATISTICAL_SECURITY = 5;
+    static constexpr const size_t BATCH_STATISTICAL_SECURITY = 5;
+    static constexpr const size_t GAMMA_BIT_LENGTH = 128;  // bits of entropy per gamma scalar
```

The key insight is that `BATCH_STATISTICAL_SECURITY` controls the number of independent slots (affecting computational cost), while the per-gamma entropy is what actually determines soundness. Fixing the gamma bit-length is strictly better than adding more slots.

## References

- [CMP Protocol Paper](https://eprint.iacr.org/2020/492) (IACR ePrint 2020/492), Section 6: Batch verification requires statistical security parameter of at least 80 bits
- [CWE-331: Insufficient Entropy](https://cwe.mitre.org/data/definitions/331.html)
- Fireblocks MPC Library, `src/common/cosigner/mta.cpp`, function `batch_response_verifier::process_paillier()`
- Fireblocks MPC Library, `src/common/cosigner/mta.h`, line 123: `BATCH_STATISTICAL_SECURITY = 5`
- SECURITY-MODEL.md, Section 4.2 bullet 3: "Incomplete ZKP generation"
