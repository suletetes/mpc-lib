/**
 * PoC: HD Derivation Secret Material Left on Stack
 * 
 * Demonstrates that derive_next_key_level_() in hd_derive.cpp leaves the
 * 64-byte HMAC-SHA512 result (containing child key tweak and chain code)
 * on the stack after returning, since OPENSSL_cleanse is never called on it.
 *
 * Build:
 *   g++ -std=c++17 -O0 -fno-stack-protector -I../../include \
 *       poc.cpp -o poc -lcrypto
 *
 * The -O0 and -fno-stack-protector flags ensure the compiler does not
 * optimize away the stack contents or insert canaries that would mask the
 * leaked data. This simulates realistic conditions on embedded/HSM targets
 * where aggressive optimization is disabled for debugging.
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

/* Reproduce the relevant constants and types from hd_derive.h */
static const unsigned int CHAIN_CODE_SIZE_BYTES = 32;
static const unsigned int PRIVATE_KEY_SIZE = 32;
static const unsigned int COMPRESSED_PUBLIC_KEY_SIZE = 33;

typedef unsigned char HDChaincode[CHAIN_CODE_SIZE_BYTES];
typedef unsigned char PubKey[COMPRESSED_PUBLIC_KEY_SIZE];
typedef unsigned char PrivKey[PRIVATE_KEY_SIZE];
typedef unsigned char hmac_sha_result[64];

/**
 * Simplified BIP32Hash matching the real implementation's logic.
 * Computes HMAC-SHA512(chainCode, header || data || child_num).
 */
static int BIP32Hash(hmac_sha_result output, const HDChaincode chainCode,
                     unsigned int nChild, unsigned char header,
                     const unsigned char data[32])
{
    unsigned int output_len = 64;
    unsigned char num[4];

    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;

    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) return -1;

    HMAC_Init_ex(ctx, chainCode, CHAIN_CODE_SIZE_BYTES, EVP_sha512(), NULL);
    HMAC_Update(ctx, &header, 1);
    HMAC_Update(ctx, data, 32);
    HMAC_Update(ctx, num, 4);
    HMAC_Final(ctx, output, &output_len);
    HMAC_CTX_free(ctx);
    return 0;
}

/**
 * This function mirrors derive_next_key_level_() from hd_derive.cpp.
 * Notice that `hash` (the hmac_sha_result) is NEVER cleansed before return.
 * The real code cleanse tmp_priv but forgets to cleanse `hash`.
 */
static void __attribute__((noinline))
vulnerable_derive_next_key_level(const PubKey pubkey, const PrivKey privkey,
                                  const HDChaincode chaincode, uint32_t child_num,
                                  PrivKey derived_privkey, HDChaincode derived_chaincode)
{
    hmac_sha_result hash;  /* 64 bytes on stack - THIS IS THE BUG */

    /* Non-hardened derivation: HMAC-SHA512(chaincode, 0x02||pubkey_x||child_num) */
    BIP32Hash(hash, chaincode, child_num, pubkey[0], &pubkey[1]);

    /* First 32 bytes = child key tweak, last 32 bytes = derived chain code */
    memcpy(derived_chaincode, &hash[32], 32);

    /* Simulate private key derivation: derived = parent + tweak (mod n) */
    /* For demonstration we just XOR, real code uses ec scalar addition */
    for (int i = 0; i < PRIVATE_KEY_SIZE; i++) {
        derived_privkey[i] = privkey[i] ^ hash[i];
    }

    /* Real code cleanses tmp_priv here (line 95), but NOT hash. */
    /* OPENSSL_cleanse(hash, sizeof(hash));  <-- THIS LINE IS MISSING */
}

/**
 * Probe the stack frame left behind by the derivation function.
 * After vulnerable_derive_next_key_level returns, its stack frame is released
 * but not zeroed. We allocate a same-sized buffer and read whatever is there.
 */
static void __attribute__((noinline))
probe_stack_residue(uint8_t* captured, size_t len)
{
    /* Volatile to prevent the compiler from optimizing this away */
    volatile uint8_t probe[256];
    memcpy(captured, (const void*)probe, len);
}

/**
 * Reference: compute what hash SHOULD have been, so we can check
 * whether it persists on the stack.
 */
static void compute_expected_hash(const PubKey pubkey, const HDChaincode chaincode,
                                   uint32_t child_num, hmac_sha_result expected)
{
    BIP32Hash(expected, chaincode, child_num, pubkey[0], &pubkey[1]);
}

int main()
{
    printf("=== PoC: HD Derivation Stack Secret Leak ===\n\n");

    /* Set up test keys (non-random for reproducibility) */
    PubKey pubkey;
    PrivKey privkey;
    HDChaincode chaincode;
    memset(pubkey, 0x02, 1);  /* compressed key prefix */
    memset(pubkey + 1, 0xAA, 32);
    memset(privkey, 0xBB, PRIVATE_KEY_SIZE);
    memset(chaincode, 0xCC, CHAIN_CODE_SIZE_BYTES);

    uint32_t child_num = 0;  /* BIP-32 child index 0 (non-hardened) */

    /* Compute the expected HMAC output for later comparison */
    hmac_sha_result expected_hash;
    compute_expected_hash(pubkey, chaincode, child_num, expected_hash);

    printf("[*] Expected HMAC-SHA512 output (first 32 bytes = key tweak):\n    ");
    for (int i = 0; i < 32; i++) printf("%02x", expected_hash[i]);
    printf("\n[*] Expected HMAC-SHA512 output (last 32 bytes = chain code):\n    ");
    for (int i = 32; i < 64; i++) printf("%02x", expected_hash[i]);
    printf("\n\n");

    /* Call the vulnerable function */
    PrivKey derived_priv;
    HDChaincode derived_chain;
    vulnerable_derive_next_key_level(pubkey, privkey, chaincode, child_num,
                                      derived_priv, derived_chain);

    printf("[*] Derivation complete. Probing stack residue...\n\n");

    /* Probe the stack region that was previously used by the function */
    uint8_t stack_capture[256];
    probe_stack_residue(stack_capture, sizeof(stack_capture));

    /* Search for the expected hash bytes in the captured stack region */
    int found_tweak = 0;
    int found_chain = 0;

    for (size_t offset = 0; offset <= sizeof(stack_capture) - 64; offset++) {
        if (memcmp(&stack_capture[offset], expected_hash, 32) == 0) {
            found_tweak = 1;
            printf("[!] FOUND key tweak (first 32 bytes of HMAC) at stack offset +%zu\n", offset);
        }
        if (memcmp(&stack_capture[offset], &expected_hash[32], 32) == 0) {
            found_chain = 1;
            printf("[!] FOUND derived chain code (last 32 bytes of HMAC) at stack offset +%zu\n", offset);
        }
    }

    /* Even if exact match fails (due to alignment), show partial matches */
    if (!found_tweak && !found_chain) {
        printf("[*] Exact 32-byte match not found at current stack depth.\n");
        printf("[*] This can happen due to compiler frame layout. Checking 8-byte subsequences...\n\n");

        int partial_matches = 0;
        for (size_t offset = 0; offset <= sizeof(stack_capture) - 8; offset++) {
            if (memcmp(&stack_capture[offset], expected_hash, 8) == 0 ||
                memcmp(&stack_capture[offset], &expected_hash[32], 8) == 0) {
                printf("[!] Partial match (8 bytes) at stack offset +%zu: ", offset);
                for (int i = 0; i < 8; i++) printf("%02x", stack_capture[offset + i]);
                printf("\n");
                partial_matches++;
            }
        }
        if (partial_matches == 0) {
            printf("[*] No residue detected in this stack probe window.\n");
            printf("[*] Note: Stack layout is compiler/platform dependent.\n");
            printf("[*] The vulnerability still exists in the source - hash buffer is never cleansed.\n");
        }
    }

    printf("\n--- Demonstrating the fix ---\n\n");

    /* Show what the FIXED version would do */
    {
        hmac_sha_result hash;
        BIP32Hash(hash, chaincode, child_num, pubkey[0], &pubkey[1]);

        /* ... use hash for derivation ... */

        /* FIX: cleanse the hash buffer before returning */
        OPENSSL_cleanse(hash, sizeof(hash));

        printf("[*] After OPENSSL_cleanse(hash, 64), buffer contents:\n    ");
        for (int i = 0; i < 64; i++) printf("%02x", hash[i]);
        printf("\n[*] All zeros confirm proper cleansing.\n");
    }

    printf("\n=== Conclusion ===\n");
    printf("The hmac_sha_result buffer in derive_next_key_level_() contains:\n");
    printf("  - Bytes [0..31]:  BIP-32 child key tweak (secret scalar)\n");
    printf("  - Bytes [32..63]: Derived chain code\n");
    printf("Both are left on the stack without OPENSSL_cleanse.\n");
    printf("An attacker with stack read access can recover the full BIP-32 subtree.\n");

    return 0;
}
