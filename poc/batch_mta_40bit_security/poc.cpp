/**
 * PoC: Batch MTA Verification Uses Only 8-bit Random Scalars
 *
 * Demonstrates that batch_response_verifier::process_paillier() in mta.cpp
 * generates gamma blinding scalars from single bytes (uint8_t), giving each
 * scalar only 8 bits of entropy. With BATCH_STATISTICAL_SECURITY = 5
 * independent verification slots, the total statistical security is
 * 5 * 8 = 40 bits, far below the 80-bit minimum specified by the CMP
 * protocol paper (IACR ePrint 2020/492).
 *
 * Build:
 *   g++ -std=c++17 -O2 poc.cpp -o poc -lcrypto
 *
 * No special flags needed; this demonstrates a logic/parameter bug.
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <openssl/bn.h>
#include <openssl/rand.h>

/*
 * Constants from mta.h, reproduced here for standalone compilation.
 */
static constexpr size_t BATCH_STATISTICAL_SECURITY = 5;
static constexpr size_t MIN_BATCH_SIZE = BATCH_STATISTICAL_SECURITY + 1;  /* = 6 */

/**
 * Reproduce the vulnerable gamma generation from mta.cpp lines 1140-1175.
 *
 * The code allocates:
 *   uint8_t random[2 * BATCH_STATISTICAL_SECURITY];   // 10 bytes total
 *   RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t));
 *
 * Then for each slot i:
 *   BN_set_word(gamma, random[i * 2]);  // gamma = single byte value 0-255
 *
 * The even-indexed bytes are used for the first MTA verification (Paillier),
 * the odd-indexed bytes for the second (commitment).
 */
static void vulnerable_generate_gammas(BIGNUM* gammas[], size_t count)
{
    uint8_t random[2 * BATCH_STATISTICAL_SECURITY];
    RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t));

    printf("[*] Raw random buffer (%zu bytes): ", sizeof(random));
    for (size_t i = 0; i < sizeof(random); i++)
        printf("%02x", random[i]);
    printf("\n\n");

    for (size_t i = 0; i < count; i++)
    {
        /* This is what the real code does: BN_set_word(gamma, random[i * 2]) */
        BN_set_word(gammas[i], random[i * 2]);
    }
}

/**
 * What the code SHOULD do: generate gamma values with at least 128 bits
 * of entropy per scalar. This matches the CMP paper's requirement for
 * batch verification security (minimum 80 bits; 128 bits recommended
 * for modern parameters).
 */
static void correct_generate_gammas(BIGNUM* gammas[], size_t count)
{
    /* Each gamma should be a random 128-bit value */
    uint8_t random_buf[16];  /* 128 bits per gamma */

    for (size_t i = 0; i < count; i++)
    {
        RAND_bytes(random_buf, sizeof(random_buf));
        BN_bin2bn(random_buf, sizeof(random_buf), gammas[i]);
    }
}

/**
 * Print a BIGNUM in hex with its bit length.
 */
static void print_bn(const char* label, const BIGNUM* bn)
{
    char* hex = BN_bn2hex(bn);
    printf("%s%s (%d bits)\n", label, hex, BN_num_bits(bn));
    OPENSSL_free(hex);
}

/**
 * Simulate the batch verification attack probability.
 *
 * In batch verification, the verifier computes a random linear combination
 * of individual checks. If B_j is the "error term" for the j-th MTA
 * operation, the verifier checks:
 *
 *   Product_{j} B_j^{gamma_j} == expected
 *
 * A cheating prover needs to find B_j values (with at least one B_j != 1)
 * such that the product still equals the expected value. If gamma values
 * have k bits of entropy each, the probability of the adversary succeeding
 * on a single slot is 2^{-k}.
 *
 * With `n` independent slots (BATCH_STATISTICAL_SECURITY), total security
 * is n * k bits, assuming the checks are independent.
 */
static void analyze_security()
{
    printf("=== Security Analysis ===\n\n");

    int bits_per_gamma_vulnerable = 8;  /* single uint8_t */
    int slots = BATCH_STATISTICAL_SECURITY;
    int total_vulnerable = bits_per_gamma_vulnerable * slots;

    int bits_per_gamma_correct = 128;
    int total_correct = bits_per_gamma_correct * slots;

    int cmp_paper_minimum = 80;

    printf("Vulnerable implementation:\n");
    printf("  Gamma bit-length:         %d bits (uint8_t, values 0-255)\n",
           bits_per_gamma_vulnerable);
    printf("  Independent slots:        %d (BATCH_STATISTICAL_SECURITY)\n", slots);
    printf("  Total statistical security: %d * %d = %d bits\n",
           slots, bits_per_gamma_vulnerable, total_vulnerable);
    printf("  Forgery probability:      2^{-%d} per batch\n", total_vulnerable);
    printf("  Concrete probability:     ~%.2e\n", pow(2.0, -total_vulnerable));
    printf("\n");

    printf("CMP paper requirement (IACR ePrint 2020/492):\n");
    printf("  Minimum statistical security: %d bits\n", cmp_paper_minimum);
    printf("  Recommended for modern params: 128 bits\n\n");

    printf("Correct implementation (128-bit gammas):\n");
    printf("  Gamma bit-length:         %d bits\n", bits_per_gamma_correct);
    printf("  Independent slots:        %d\n", slots);
    printf("  Total statistical security: %d * %d = %d bits\n",
           slots, bits_per_gamma_correct, total_correct);
    printf("  Forgery probability:      2^{-%d} per batch\n", total_correct);
    printf("\n");

    printf("Security gap: %d bits (vulnerable) vs %d bits (minimum required)\n",
           total_vulnerable, cmp_paper_minimum);
    printf("The implementation provides HALF the minimum security level.\n\n");
}

/**
 * Demonstrate how the batch path is triggered.
 */
static void explain_trigger_conditions()
{
    printf("=== Trigger Conditions ===\n\n");
    printf("From mta.h:\n");
    printf("  BATCH_STATISTICAL_SECURITY = %zu\n", BATCH_STATISTICAL_SECURITY);
    printf("  MIN_BATCH_SIZE = BATCH_STATISTICAL_SECURITY + 1 = %zu\n", MIN_BATCH_SIZE);
    printf("\n");
    printf("The batch path activates when num_of_blocks >= MIN_BATCH_SIZE = %zu.\n",
           MIN_BATCH_SIZE);
    printf("Since there are 2 MTA operations per ECDSA signature block,\n");
    printf("a signing request with 3 blocks triggers 6 MTA verifications,\n");
    printf("which equals MIN_BATCH_SIZE and activates batch mode.\n\n");
    printf("In practice, any multi-signature request (3+ blocks) uses\n");
    printf("the vulnerable batch verification path.\n\n");
}

/**
 * Demonstrate the birthday bound implications.
 * With 40-bit security, an attacker making repeated attempts has
 * non-negligible success probability.
 */
static void demonstrate_attack_feasibility()
{
    printf("=== Attack Feasibility ===\n\n");

    double prob_per_attempt = pow(2.0, -40.0);
    printf("Probability of forgery per batch: 2^{-40} = %.4e\n", prob_per_attempt);
    printf("\n");

    /* Calculate attempts needed for various success probabilities */
    double targets[] = {0.01, 0.10, 0.50, 0.99};
    printf("Attempts needed for target success probability:\n");
    printf("  %-20s  %-20s\n", "Target P(success)", "Attempts needed");
    printf("  %-20s  %-20s\n", "---", "---");

    for (double target : targets)
    {
        /* P(at least one success in N trials) = 1 - (1 - p)^N */
        /* N = log(1 - target) / log(1 - p) */
        double N = log(1.0 - target) / log(1.0 - prob_per_attempt);
        printf("  %-20.2f  %.2e (~2^{%.1f})\n", target, N, log2(N));
    }
    printf("\n");

    printf("At 40-bit security, an attacker submitting ~2^{40} = ~1.1 trillion\n");
    printf("forged batch verifications expects one success. While this sounds\n");
    printf("large, consider:\n");
    printf("  - Automated signing services may process millions of requests/day\n");
    printf("  - The CMP paper sets 80 bits as the floor specifically because\n");
    printf("    40 bits is within reach of motivated attackers\n");
    printf("  - Cost of each attempt is just a signing request, not a full key ceremony\n\n");

    /* Contrast with proper 80-bit security */
    printf("With proper 80-bit security: need ~2^{80} attempts for 50%% success\n");
    printf("  That is ~6.0e+23 attempts (computationally infeasible)\n\n");
}

int main()
{
    printf("=== PoC: Batch MTA Verification 8-bit Gamma Scalars ===\n\n");

    explain_trigger_conditions();

    /* Allocate BIGNUMs for gamma values */
    BIGNUM* vuln_gammas[BATCH_STATISTICAL_SECURITY];
    BIGNUM* correct_gammas[BATCH_STATISTICAL_SECURITY];

    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        vuln_gammas[i] = BN_new();
        correct_gammas[i] = BN_new();
    }

    /* Generate gamma values using the vulnerable method */
    printf("--- Vulnerable gamma generation (reproduces mta.cpp logic) ---\n\n");
    vulnerable_generate_gammas(vuln_gammas, BATCH_STATISTICAL_SECURITY);

    printf("Generated gamma values (first MTA verification, even-indexed bytes):\n");
    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        char label[64];
        snprintf(label, sizeof(label), "  gamma[%zu] = ", i);
        print_bn(label, vuln_gammas[i]);
    }
    printf("\n");

    /* Verify the maximum possible value */
    printf("[!] Maximum possible gamma value: 255 (0xFF)\n");
    printf("[!] Bit-length of any gamma:      at most 8 bits\n");
    printf("[!] Effective entropy per gamma:   8 bits (uniform over 0-255)\n\n");

    /* Show that gamma = 0 is possible (catastrophic: B^0 = 1, check becomes trivial) */
    printf("[!] CRITICAL: gamma = 0 occurs with probability 1/256 per slot.\n");
    printf("    When gamma = 0, the check B^gamma = B^0 = 1, which means\n");
    printf("    that slot contributes NO verification at all.\n");
    printf("    P(at least one gamma=0 in %zu slots) = 1 - (255/256)^%zu = %.4f\n\n",
           BATCH_STATISTICAL_SECURITY, BATCH_STATISTICAL_SECURITY,
           1.0 - pow(255.0/256.0, BATCH_STATISTICAL_SECURITY));

    /* Generate correct gamma values */
    printf("--- Correct gamma generation (128-bit scalars) ---\n\n");
    correct_generate_gammas(correct_gammas, BATCH_STATISTICAL_SECURITY);

    printf("Generated gamma values with proper 128-bit entropy:\n");
    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        char label[64];
        snprintf(label, sizeof(label), "  gamma[%zu] = ", i);
        print_bn(label, correct_gammas[i]);
    }
    printf("\n");

    /* Analyze security levels */
    analyze_security();

    /* Show attack feasibility */
    demonstrate_attack_feasibility();

    /* Demonstrate the structural issue: run multiple rounds and observe
       how often we get gamma = 0 (which negates a verification slot entirely) */
    printf("=== Empirical gamma=0 frequency (1000 rounds) ===\n\n");
    int zero_count = 0;
    int rounds_with_zero = 0;
    int total_rounds = 1000;

    for (int round = 0; round < total_rounds; round++)
    {
        uint8_t random[2 * BATCH_STATISTICAL_SECURITY];
        RAND_bytes(random, sizeof(random));
        bool has_zero = false;
        for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
        {
            if (random[i * 2] == 0)
            {
                zero_count++;
                has_zero = true;
            }
        }
        if (has_zero)
            rounds_with_zero++;
    }

    printf("Out of %d rounds (%d gamma values per round):\n", total_rounds,
           (int)BATCH_STATISTICAL_SECURITY);
    printf("  Total gamma=0 occurrences: %d / %d (expected: ~%d)\n",
           zero_count, total_rounds * (int)BATCH_STATISTICAL_SECURITY,
           (int)(total_rounds * BATCH_STATISTICAL_SECURITY / 256));
    printf("  Rounds with at least one gamma=0: %d / %d (expected: ~%d)\n",
           rounds_with_zero, total_rounds,
           (int)(total_rounds * (1.0 - pow(255.0/256.0, BATCH_STATISTICAL_SECURITY))));
    printf("\n");

    printf("=== Conclusion ===\n\n");
    printf("The batch verification in process_paillier() uses BN_set_word(gamma, random[i*2])\n");
    printf("where random[] is a uint8_t array. Each gamma is therefore a single byte (0-255),\n");
    printf("providing only 8 bits of entropy per verification slot.\n\n");
    printf("With BATCH_STATISTICAL_SECURITY = %zu slots, total security = %zu * 8 = %zu bits.\n",
           BATCH_STATISTICAL_SECURITY, BATCH_STATISTICAL_SECURITY,
           BATCH_STATISTICAL_SECURITY * 8);
    printf("The CMP protocol (ePrint 2020/492) requires minimum 80 bits.\n\n");
    printf("The implementation achieves only HALF the specified security level.\n");
    printf("A malicious co-signer can submit invalid MTA range proofs that pass\n");
    printf("batch verification with probability 2^{-40} instead of 2^{-80}.\n");

    /* Cleanup */
    for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
    {
        BN_free(vuln_gammas[i]);
        BN_free(correct_gammas[i]);
    }

    return 0;
}
