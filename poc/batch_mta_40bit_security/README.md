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

### Additional issue: gamma = 0 is possible

When `random[i * 2] == 0`, the code sets gamma = 0. Then `B^gamma = B^0 = 1`, which means that verification slot contributes nothing to the batch check. This occurs with probability 1/256 per slot, and with 5 slots the probability of at least one dead slot per batch is approximately 1.9%.

## Attack Scenario

**Adversary model:** A malicious co-signer participating in the CMP-ECDSA signing protocol. The attacker wants to submit invalid MTA range proofs that bypass verification, allowing manipulation of the additive shares used in signing.

**Trigger conditions:**

The batch verification path activates when `num_of_blocks >= MIN_BATCH_SIZE` (defined as `BATCH_STATISTICAL_SECURITY + 1 = 6` in mta.h). Since there are 2 MTA operations per ECDSA signature block, a signing request with 3 or more blocks generates 6+ MTA verifications and triggers batch mode.

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
| **Soundness** | Batch verification provides 40 bits of statistical security instead of the required 80 bits |
| **Forgery probability** | 2^{-40} per batch, which is 2^{40} times higher than intended |
| **Reachability** | Active on any signing session with 3+ blocks (common in production) |
| **What it bypasses** | MTA range proofs that constrain additive shares to safe ranges |
| **Downstream impact** | Invalid additive shares can bias the signing nonce, potentially enabling key extraction |
| **Bugcrowd category** | Section 4.2 bullet 3: "Incomplete ZKP generation... does not achieve the soundness level its parameters claim" |
| **Suggested rating** | P3 (Medium): achievable security is half the protocol specification; batch mode is the default path for multi-block signing |

## Recommended Fix

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
