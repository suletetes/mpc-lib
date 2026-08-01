# HD Derivation Secret Material Left on Stack

## Summary

The function `derive_next_key_level_()` in `src/common/blockchain/mpc/hd_derive.cpp` computes an HMAC-SHA512 into a 64-byte stack buffer (`hmac_sha_result hash`) that contains the BIP-32 child key tweak and derived chain code. This buffer is never zeroed with `OPENSSL_cleanse` before the function returns. An attacker who can read process memory (via cold boot, core dump, swap file, or co-resident side channel) can recover the secret derivation material and reconstruct the entire child key subtree.

## Vulnerability Details

| Field | Value |
|-------|-------|
| **File** | `src/common/blockchain/mpc/hd_derive.cpp` |
| **Function** | `derive_next_key_level_()` (static, line 82) |
| **Line** | 83 (declaration), return at line 97 |
| **CWE** | CWE-316: Cleartext Storage of Sensitive Information in Memory |
| **Also applies** | CWE-226: Sensitive Information in Resource Not Removed Before Reuse |

## Root Cause Analysis

Here is the vulnerable code (lines 72-101 of hd_derive.cpp):

```cpp
static hd_derive_status derive_next_key_level_(
    const elliptic_curve256_algebra_ctx_t* ctx,
    PubKey derived_pubkey, PrivKey derived_privkey,
    HDChaincode derived_chaincode,
    const PubKey *pubkey, const PrivKey privkey,
    const HDChaincode chaincode, uint32_t child_num, bool derive_private)
{
    hmac_sha_result hash;          // <-- 64 bytes of secret material
    elliptic_curve256_point_t tmp_point;

    if (is_hardened(child_num) && !derive_private) {
        return HD_DERIVE_ERROR_HARDENED_PUBLIC;       // RETURN PATH 1
    }

    hd_derive_status retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
    if (HD_DERIVE_SUCCESS != retval){
        return retval;                               // RETURN PATH 2
    }
    memcpy(derived_chaincode, &(hash[32]), 32);
    memcpy(tmp_point, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->generator_mul_data(ctx, hash, 32, &tmp_point))
        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;  // RETURN PATH 3
    if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_points(ctx, &tmp_point, pubkey, &tmp_point))
        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;  // RETURN PATH 4
    memcpy(derived_pubkey, tmp_point, COMPRESSED_PUBLIC_KEY_SIZE);

    if (derive_private) {
        elliptic_curve256_scalar_t tmp_priv;
        if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_scalars(ctx, &tmp_priv, privkey, PRIVATE_KEY_SIZE, hash, 32))
            return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV;  // RETURN PATH 5
        memcpy(derived_privkey, tmp_priv, PRIVATE_KEY_SIZE);
        OPENSSL_cleanse(tmp_priv, PRIVATE_KEY_SIZE);   // tmp_priv IS cleansed
    }
    return HD_DERIVE_SUCCESS;                          // RETURN PATH 6
    // hash is NEVER cleansed - 64 bytes of key material left on stack
}
```

The inconsistency is clear: `tmp_priv` is properly cleansed at line 99, but the `hash` buffer (which contains equally sensitive material) is simply abandoned on the stack. This is an oversight, not a design choice. The caller `derive_private_and_public_keys()` (line 168) also demonstrates the pattern of cleansing secret buffers before return, further confirming that `hash` was simply missed.

### 6 Return Paths, All Leave Hash Uncleansed

| Return Path | Line | Hash State | Cleansed? |
|-------------|------|------------|-----------|
| `HD_DERIVE_ERROR_HARDENED_PUBLIC` | ~78 | Uninitialized (allocated on stack) | NO |
| `retval` (hash_for_derive failure) | ~82 | Partially/fully written by HMAC | NO |
| `HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB` (generator_mul) | ~87 | Fully populated | NO |
| `HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB` (add_points) | ~89 | Fully populated | NO |
| `HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV` | ~95 | Fully populated | NO |
| `HD_DERIVE_SUCCESS` | ~100 | Fully populated | NO |

Every single return path after `hash_for_derive()` succeeds leaves 64 bytes of secret material on the stack. The 4 error-path returns are especially dangerous because they are not obvious candidates for security review.

### What the buffer contains

| Byte Range | Content | Sensitivity |
|------------|---------|-------------|
| `hash[0..31]` | BIP-32 child key tweak (IL) | Secret scalar. Knowledge of parent private key + tweak = child private key |
| `hash[32..63]` | Derived chain code | Combined with child public key, enables derivation of all grandchild keys |

### Additional Uncleansed Buffers in Callers

The problem extends beyond `derive_next_key_level_()` into both of its callers:

**In `derive_public_key_generic()` (hd_derive.cpp:104-130):**

| Buffer | Size | Status |
|--------|------|--------|
| `current_chain_code` (32 bytes) | Contains final derived chain code at exit | NEVER cleansed |
| `next_chain_code` (32 bytes) | Contains final derived chain code at exit | NEVER cleansed |
| `unused` PrivKey (32 bytes) | Declared but uninitialized; may hold residual stack data | NEVER cleansed |

**In `derive_private_and_public_keys()` (hd_derive.cpp:136-175):**

| Buffer | Size | Status |
|--------|------|--------|
| `current_chain_code` (32 bytes) | Contains final derived chain code at exit | NEVER cleansed |
| `next_chain_code` (32 bytes) | Contains final derived chain code at exit | NEVER cleansed |
| `temp_privkey` (32 bytes) | Properly cleansed at line 169 | OK |
| `temp_pubkey` (33 bytes) | Properly cleansed at line 170 | OK |

The selective cleansing in `derive_private_and_public_keys()` is telling: the developer correctly cleanses `temp_privkey` and `temp_pubkey` but completely misses the chain code buffers. The chain code is arguably MORE sensitive than any single key because it enables derivation of the entire non-hardened subtree below that point.

### Note on HMAC_CTX Internal State

The `BIP32Hash()` function calls `HMAC_CTX_free(ctx)`, which internally invokes `OPENSSL_cleanse()` on the HMAC ipad/opad and intermediate hash state. So the HMAC context itself IS properly cleaned up. The bug is specifically that the OUTPUT buffer (`hash`) written by `HMAC_Final()` on the caller's stack frame is never cleansed. The HMAC context cleanup is irrelevant because the secret material has already been copied to the output buffer.

## Attack Scenario

**Adversary capability:** Read access to process memory after derivation completes. This is realistic in several contexts:

1. **Core dumps / crash dumps** - If the signing process crashes (or is crashed deliberately), the core dump will contain unreleased stack frames with the hash buffer intact.

2. **Cold boot attack** - Physical access to the machine running the MPC signer allows DRAM content to be recovered. Stack variables without explicit cleansing persist in physical memory.

3. **Swap file recovery** - On systems without locked memory (no `mlock`), stack pages can be swapped to disk. The hash buffer contents will persist in the swap partition.

4. **Co-tenant side channels** - In cloud HSM or SGX enclave scenarios, a co-resident attacker exploiting speculative execution or memory safety bugs can read stale stack data.

**What property is broken:** Given the recovered `hash` buffer:

- `hash[0..31]` is the child key tweak IL
- The attacker computes: `child_privkey = parent_privkey + IL (mod n)`
- With `hash[32..63]` (the chain code), the attacker can continue derivation to ALL descendant keys in the BIP-32 subtree

This means a single stack leak from one `derive_next_key_level_` call exposes not just that child key, but the entire subtree below it.

## Proof of Concept

### Building

```bash
cd poc/hd_derive_stack_secret/
g++ -std=c++17 -O0 -fno-stack-protector poc.cpp -o poc -lcrypto
```

The `-O0` flag prevents the compiler from optimizing away the dead stack data. The `-fno-stack-protector` removes canaries that might overwrite the region. These flags simulate environments where optimization is limited (debug builds, certain embedded targets, WASM runtimes).

### Running

```bash
./poc
```

### Expected Output

```
=== PoC: HD Derivation Stack Secret Leak ===

[*] Expected HMAC-SHA512 output (first 32 bytes = key tweak):
    <hex bytes>
[*] Expected HMAC-SHA512 output (last 32 bytes = chain code):
    <hex bytes>

[*] Derivation complete. Probing stack residue...

[!] FOUND key tweak (first 32 bytes of HMAC) at stack offset +<N>
[!] FOUND derived chain code (last 32 bytes of HMAC) at stack offset +<N>

--- Demonstrating the fix ---

[*] After OPENSSL_cleanse(hash, 64), buffer contents:
    000000000000...
[*] All zeros confirm proper cleansing.
```

Note: Stack probing results are platform-dependent. On some compilers/architectures the exact offset will differ, or partial matches will be found instead. The core point is that the source code never invokes OPENSSL_cleanse on the buffer, so the secret material remains available until the stack frame is overwritten by a subsequent call.

## Affected Protocol Flows

Every protocol in the library that performs HD derivation is affected. The following call sites all reach `derive_next_key_level_()` and leave secret material on the stack:

| Caller File | Line | Protocol |
|-------------|------|----------|
| `cmp_ecdsa_signing_service.cpp` | 286 | CMP ECDSA signing |
| `bam_ecdsa_cosigner.cpp` | 274 | BAM ECDSA signing |
| `frost_cosigner.cpp` | 210 | FROST Schnorr signing |
| `asymmetric_eddsa_cosigner.cpp` | 34 | EdDSA signing |
| `eddsa_online_signing_service.cpp` | 269 | EdDSA online signing |
| `cmp_ecdsa_online_signing_service.cpp` | 370, 486 | CMP ECDSA verification |
| `cmp_ecdsa_offline_signing_service.cpp` | 359 | CMP offline signing |
| `asymmetric_eddsa_cosigner_server.cpp` | 488 | EdDSA server |

This means the vulnerability is triggered on every single signing operation across all supported signature schemes (ECDSA, Schnorr/FROST, EdDSA), not just a niche code path.

## Impact Assessment

### Quantified Exposure Per Signing Operation

BIP-44 paths have exactly 5 levels (`BIP44_PATH_LENGTH = 5`, defined in `hd_derive.h` line 21). Each signing operation triggers one call to `derive_private_key_generic()` or `derive_private_and_public_keys()`, which loops 5 times calling `derive_next_key_level_()` once per iteration.

| Source | Calculation | Bytes |
|--------|-------------|-------|
| 5 uncleansed `hash` buffers (64 bytes each) | 5 x 64 | 320 |
| `current_chain_code` + `next_chain_code` in caller | 32 + 32 | 64 |
| **Total per signing operation** | | **384 bytes** |

Each of the 5 hash buffers contains a DIFFERENT intermediate key tweak and chain code, representing a different level of the BIP-44 derivation path. Recovery of any single level's chain code (combined with the corresponding public key, which is typically public) allows derivation of the entire non-hardened subtree below that point.

### Risk Matrix

| Dimension | Assessment |
|-----------|------------|
| **Confidentiality** | High. Full BIP-32 child key tweak and chain code exposed at every derivation level. |
| **Key equivalence** | The tweak + parent key = child private key. Chain code enables full subtree derivation. |
| **Exploitability** | Requires memory read access (post-crash, cold boot, swap, side channel). |
| **Scope** | All keys derived through the leaked derivation level, plus all descendants. Affects all protocol flows (ECDSA, FROST, EdDSA). |
| **Exposure volume** | 384 bytes of secret cryptographic material left on stack per signing operation. |
| **Bugcrowd category** | Section 4.2, Category 4: "Sensitive-data memory persistency" |
| **Suggested rating** | P4 (Low), potentially P3 (Medium) given that the leaked material is key-equivalent and the scope spans all protocol flows |

## Recommended Fix

### Fix 1: Cleanse `hash` on all return paths in `derive_next_key_level_()`

```diff
--- a/src/common/blockchain/mpc/hd_derive.cpp
+++ b/src/common/blockchain/mpc/hd_derive.cpp
@@ -82,6 +82,7 @@ static hd_derive_status derive_next_key_level_(const elliptic_curve256_algebra_c
     const HDChaincode chaincode, uint32_t child_num, bool derive_private) {
     hmac_sha_result hash;
     elliptic_curve256_point_t tmp_point;
+    hd_derive_status retval;
 
     if (is_hardened(child_num) && !derive_private) {
         return HD_DERIVE_ERROR_HARDENED_PUBLIC;
@@ -89,22 +90,27 @@ static hd_derive_status derive_next_key_level_(const elliptic_curve256_algebra_c
 
-    hd_derive_status retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
-    if (HD_DERIVE_SUCCESS != retval){
-        return retval;
-    }
+    retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
+    if (HD_DERIVE_SUCCESS != retval)
+        goto cleanup;
+
     memcpy(derived_chaincode, &(hash[32]), 32);
     memcpy(tmp_point, pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
     if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->generator_mul_data(ctx, hash, 32, &tmp_point))
-        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;
+    { retval = HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB; goto cleanup; }
     if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_points(ctx, &tmp_point, pubkey, &tmp_point))
-        return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB;
+    { retval = HD_DERIVE_ERROR_ADDING_TWEAK_TO_PUB; goto cleanup; }
     memcpy(derived_pubkey, tmp_point, COMPRESSED_PUBLIC_KEY_SIZE);
 
-    // derive next private key level, if we're deriving private keys
     if (derive_private) {
         elliptic_curve256_scalar_t tmp_priv;
         if (ELLIPTIC_CURVE_ALGEBRA_SUCCESS != ctx->add_scalars(ctx, &tmp_priv, privkey, PRIVATE_KEY_SIZE, hash, 32))
-            return HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV;
+        { retval = HD_DERIVE_ERROR_ADDING_TWEAK_TO_PRIV; OPENSSL_cleanse(tmp_priv, PRIVATE_KEY_SIZE); goto cleanup; }
         memcpy(derived_privkey, tmp_priv, PRIVATE_KEY_SIZE);
         OPENSSL_cleanse(tmp_priv, PRIVATE_KEY_SIZE);
     }
-    return HD_DERIVE_SUCCESS;
+    retval = HD_DERIVE_SUCCESS;
+
+cleanup:
+    OPENSSL_cleanse(hash, sizeof(hmac_sha_result));
+    return retval;
 }
```

### Fix 2: Cleanse chain codes in `derive_public_key_generic()`

```diff
--- a/src/common/blockchain/mpc/hd_derive.cpp
+++ b/src/common/blockchain/mpc/hd_derive.cpp
@@ derive_public_key_generic() near return
     }
 
+    OPENSSL_cleanse(current_chain_code, CHAIN_CODE_SIZE_BYTES);
+    OPENSSL_cleanse(next_chain_code, CHAIN_CODE_SIZE_BYTES);
     return HD_DERIVE_SUCCESS;
 }
```

### Fix 3: Cleanse chain codes in `derive_private_and_public_keys()`

```diff
--- a/src/common/blockchain/mpc/hd_derive.cpp
+++ b/src/common/blockchain/mpc/hd_derive.cpp
@@ derive_private_and_public_keys() cleanup section (line ~169)
 cleanup:
     OPENSSL_cleanse(temp_privkey, PRIVATE_KEY_SIZE);
     OPENSSL_cleanse(temp_pubkey, COMPRESSED_PUBLIC_KEY_SIZE);
+    OPENSSL_cleanse(current_chain_code, CHAIN_CODE_SIZE_BYTES);
+    OPENSSL_cleanse(next_chain_code, CHAIN_CODE_SIZE_BYTES);
     return retval;
 }
```

These three fixes together ensure that ALL secret derivation material (HMAC output, intermediate chain codes) is cleansed before the stack frames are abandoned. The pattern matches the existing cleansing approach already used for `temp_privkey` and `tmp_priv` in the same codebase.

## References

- [BIP-32 Specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) - Describes the key derivation scheme and the sensitivity of the IL/IR values
- [CWE-316: Cleartext Storage of Sensitive Information in Memory](https://cwe.mitre.org/data/definitions/316.html)
- [CWE-226: Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html)
- OpenSSL `OPENSSL_cleanse()` documentation - Guaranteed not to be optimized away by the compiler
- Fireblocks MPC Library, `src/common/blockchain/mpc/hd_derive.cpp`, commit `00ae08b`
