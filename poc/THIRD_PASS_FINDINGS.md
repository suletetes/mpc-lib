# Third-Pass Security Audit Findings

This document presents findings from a deep-dive security review of the
mpc-lib codebase, specifically targeting issues with realistic acceptance
probability under the program's SECURITY-MODEL.md criteria.

Each finding is evaluated against the threat model (malicious-adversary,
at least one honest participant) and the security guarantees in Section 1.2.

---

## Finding 1: Fiat-Shamir Transcript Truncation in Legacy MTA Range ZKP Seed

### Affected Files / Lines

- `src/common/cosigner/mta.cpp`, function `generate_mta_range_zkp_seed()`, line ~130

### Description

In the non-extended (legacy) Fiat-Shamir seed generation path for MTA
range zero-knowledge proofs, the hash of `proof.A` is truncated to
`BN_num_bytes(proof.S)` bytes rather than using the full byte-length of A.

```cpp
std::vector<uint8_t> n(BN_num_bytes(proof.A));
BN_bn2bin(proof.A, n.data());
SHA256_Update(&ctx, n.data(), BN_num_bytes(proof.S)); // BUG: hashes S-length bytes of A
```

`proof.A` lives in the Paillier N^2 space (typically 512 bytes for a
2048-bit key), while `proof.S` lives in the Ring Pedersen N space
(typically 128 bytes for a 1024-bit modulus). The SHA256_Update only
feeds the first 128 bytes of A into the hash, leaving the remaining
384 bytes uncommitted in the Fiat-Shamir challenge.

### Contrast with Corrected Path

The extended seed path (used when `version >= MPC_EXTENDED_MTA = 11`)
correctly uses:

```cpp
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
```

This uses `BN_bn2binpad` with the full padded size, ensuring the entire
value of A determines the challenge.

### Attack Scenario

**Adversary:** A malicious co-signer (permitted under Section 1.1) who
communicates with an honest party running protocol version < 11 (legacy).

**Mechanism:**

1. The malicious prover generates a valid MTA range proof with some
   proof.A value (A1).
2. The prover constructs A2, a different element of Z_{N^2}^* that
   shares the same leading 128 bytes as A1 in big-endian representation
   but differs in bytes 128-511.
3. Because only the first 128 bytes of A enter the hash, both A1 and A2
   produce the identical Fiat-Shamir challenge `e`.
4. The attacker uses the proof responses computed for A1 but substitutes
   A2 as the proof element. The verifier derives the same challenge and
   proceeds to check the proof equations against A2.

The proof equation for the Paillier check is:

    C^{-z1} * D^e * A * (1 - N*z2) == 1 mod N^2   (batch path)
    C^{z1} * enc(z2, w) == A * D^e mod N^2         (single path)

Since A appears in these verification equations, a different A means the
attacker is proving a different statement about the underlying plaintext.
If the attacker can find A2 such that (A2 / A1) has a known discrete log
relationship modulo N^2, the proof can be satisfied for a different
underlying plaintext value, potentially allowing the attacker to inject
a biased or known additive share in the MTA protocol.

### Section 1.2 Property at Risk

- **Section 1.2.1 (Long-term key secrecy):** If MTA soundness is broken,
  the attacker can manipulate the additive shares (alpha/beta) in the
  multiplicative-to-additive conversion. Over multiple signing sessions,
  biased MTA outputs can leak information about the honest party's key
  share through the resulting signatures.
- **Section 1.2.2 (Unforgeability):** A soundness break in the MTA ZKP
  allows the attacker to influence the signing nonce relationship,
  potentially enabling signature forgery below threshold.

### Exclusions Analysis

- **Section 2 (Integrator contract):** Not applicable. This is a
  library-internal cryptographic bug, not an integrator responsibility.
- **Section 3 (Safe-by-design):** Does not match any pattern in Section 3.
  This is not about degenerate parameters or point-at-infinity acceptance.
- **Section 6 (Frequent wrong claims):** Does not match. This is not
  about RNG determinism, key sizes, or non-constant-time operations.

### Severity Assessment

**Estimated:** P2-P3 (High to Medium)

The attack requires the target to run legacy protocol version < 11. The
extended path (version >= 11) is immune. However, the legacy code path
is still compiled and reachable. Mixed-version deployments, key migration
scenarios, or version downgrade attacks make this realistic.

### Acceptance Probability

**30-45%.** The legacy path is still present and reachable in the code.
The extended path that fixes this was introduced precisely because
of this class of issue, confirming it was recognized as a weakness.
The practical constraint is that modern deployments likely use version
>= 11, which limits exploitability in current production environments.

### Existing PoC

A proof-of-concept demonstrating the hash collision is at
`poc/mta_seed_truncation/poc.cpp`.

---

## Finding 2: Insufficient Statistical Security in Batch MTA Verification

### Affected Files / Lines

- `src/common/cosigner/mta.cpp`, function `batch_response_verifier::process_paillier()`, lines ~1152-1200
- `src/common/cosigner/mta.cpp`, function `batch_response_verifier::process_ring_pedersen()`, lines ~1257-1320
- `src/common/cosigner/mta.h`, line 123: `static constexpr const size_t BATCH_STATISTICAL_SECURITY = 5;`

### Description

The batch MTA response verifier uses random blinding scalars with
insufficient entropy for the claimed security level. The implementation
has two separate issues:

#### Issue 2a: Paillier Batch -- 8-bit Random Scalars

In `process_paillier()`:

```cpp
uint8_t random[2 * BATCH_STATISTICAL_SECURITY]; // 10 bytes total
RAND_bytes(random, 2 * BATCH_STATISTICAL_SECURITY * sizeof(uint8_t));
...
for (size_t i = 0; i < BATCH_STATISTICAL_SECURITY; i++)
{
    if (!BN_set_word(gamma, random[i * 2]))  // single byte! 8-bit value
    ...
}
```

Each gamma blinding value is a single byte (0-255). With
`BATCH_STATISTICAL_SECURITY = 5` independent slots, the total
statistical security of the Paillier batch check is at most:

    5 slots * 8 bits/slot = 40 bits

A malicious prover attempting to pass batch verification with an
invalid proof has probability approximately 2^{-40} per batch. Standard
cryptographic security parameters require at least 2^{-80} or 2^{-128}.

#### Issue 2b: Ring Pedersen Batch -- Single Accumulated Exponent

In `process_ring_pedersen()`:

```cpp
uint64_t gamma[2];
RAND_bytes(reinterpret_cast<uint8_t*>(&gamma[0]), 2 * sizeof(uint64_t));
gamma[0] &= 0xffffffffffULL; // 40 bits
gamma[1] &= 0xffffffffffULL; // 40 bits
```

The Ring Pedersen batch check uses 40-bit random scalars per proof
processed, but accumulates into a SINGLE `_pedersen_t_exp` value
across all proofs. The final check is:

```cpp
BN_mod(_pedersen_t_exp, _pedersen_t_exp, _my_ring_pedersen->phi_n, ...)
BN_mod_exp_mont(_pedersen_t_exp, _my_ring_pedersen->pub.t, _pedersen_t_exp, ...)
// compare against _pedersen_B
```

Since there is only one accumulated check for the Ring Pedersen
component (not 5 independent slots like Paillier), and each gamma is
40 bits, the Ring Pedersen batch has exactly 40 bits of statistical
security per batch invocation.

### Attack Scenario

**Adversary:** A malicious co-signer who sends invalid MTA range proofs
during the CMP-ECDSA presigning phase, specifically targeting batch
verification when the honest party processes >= 6 blocks simultaneously
(the `MIN_BATCH_SIZE` threshold).

**Mechanism:**

1. The attacker crafts MTA responses with invalid Ring Pedersen proof
   components (E, F, S, T that do not satisfy the commitment relations).
2. For each proof processed, the batch verifier multiplies attacker-controlled
   values by random 40-bit gamma scalars and accumulates them.
3. The attacker constructs their invalid proof values such that the
   accumulated products cancel modulo the Ring Pedersen modulus N.
4. With probability 2^{-40}, the single accumulated Ring Pedersen check
   passes despite the individual proofs being invalid.

For the Paillier batch, the attacker needs all 5 independent checks to
pass simultaneously. Each slot uses an 8-bit gamma, giving 2^{-8} per
slot. The probability of all 5 passing is 2^{-40}.

**Combined per-batch forgery probability:** approximately 2^{-40} for
either the Paillier or Ring Pedersen component. The CMP paper
(IACR ePrint 2020/492) specifies statistical security parameter lambda
= 80 bits minimum for batch verification techniques.

**Amplification:** In a system processing many signing requests, the
expected number of attempts before a successful forgery is 2^{40},
which is approximately 1 trillion. While not trivially practical, this
is far below the 2^{80} threshold considered cryptographically secure.
An attacker submitting one batch per millisecond would succeed in
approximately 35 years for a single forgery. However, against a
high-throughput system processing thousands of signing operations per
second, the timeline compresses.

### Section 1.2 Property at Risk

- **Section 1.2.2 (Unforgeability):** If the MTA range proof
  verification can be bypassed, the attacker can inject arbitrary values
  into the multiplicative-to-additive conversion, potentially gaining
  control over the signing nonce or key-related shares.
- **Section 1.2.1 (Key secrecy):** The MTA ZKP prevents extraction of
  the honest party's secret by proving the responder's values are in
  valid ranges. Weakened soundness reduces this protection.

### Exclusions Analysis

- **Section 2:** Not applicable. This is library-internal verification
  logic.
- **Section 3:** Does not match any safe-by-design pattern.
- **Section 6.1 (Unsecure cryptographic sizes):** This is NOT about
  key sizes. It is about the statistical security parameter of the batch
  verification optimization being below cryptographic standards.

### Severity Assessment

**Estimated:** P3-P4 (Medium to Low)

The 40-bit statistical security is below the 80-bit standard but still
provides meaningful protection (2^{40} attempts required). The batch
path is only used when processing >= 6 blocks simultaneously
(`MIN_BATCH_SIZE = BATCH_STATISTICAL_SECURITY + 1 = 6`). Smaller batches
use the `single_response_verifier` which performs exact verification
without random batching.

### Acceptance Probability

**35-50%.** The deviation from standard security parameters (40 bits vs
80 bits minimum) is concrete and measurable. The counterargument is that
40 bits still makes practical exploitation extremely difficult (over 1
trillion attempts needed), and the program may consider this acceptable
for a performance optimization. However, the CMP protocol paper
explicitly specifies higher parameters, making this a deviation from
the protocol specification.

---

## Finding 3: Missing OPENSSL_cleanse on HMAC-SHA512 Output in HD Derivation

### Affected Files / Lines

- `src/common/blockchain/mpc/hd_derive.cpp`, function `derive_next_key_level_()`, line ~80-100

### Description

The 64-byte HMAC-SHA512 result (`hmac_sha_result hash`) in
`derive_next_key_level_()` contains:

- Bytes [0..31]: BIP-32 child key tweak (secret scalar added to the
  parent private key)
- Bytes [32..63]: Derived chain code (used as HMAC key for subsequent
  derivation levels)

After use, the `hash` buffer is never cleansed:

```cpp
static hd_derive_status derive_next_key_level_(...) {
    hmac_sha_result hash;   // 64 bytes on stack
    ...
    hd_derive_status retval = hash_for_derive(hash, *pubkey, privkey, chaincode, child_num);
    ...
    memcpy(derived_chaincode, &(hash[32]), 32);
    ...
    if (derive_private) {
        elliptic_curve256_scalar_t tmp_priv;
        ...
        memcpy(derived_privkey, tmp_priv, PRIVATE_KEY_SIZE);
        OPENSSL_cleanse(tmp_priv, PRIVATE_KEY_SIZE);  // tmp_priv IS cleansed
    }
    return HD_DERIVE_SUCCESS;
    // hash is NOT cleansed -- remains on stack
}
```

The function correctly cleanses `tmp_priv` but leaves `hash` on the
stack. After the function returns, the 64-byte secret persists in the
calling function's stack frame (or in the same memory region for
subsequent function calls).

### Attack Scenario

**Adversary:** An attacker with a memory disclosure primitive on the
target system (e.g., via a separate vulnerability that allows reading
process memory, a core dump, or a cold-boot attack on the server).

**Mechanism:**

1. The honest party performs HD key derivation (BIP-32/BIP-44 path
   traversal).
2. At each derivation level, the 64-byte HMAC-SHA512 output remains on
   the stack after `derive_next_key_level_()` returns.
3. The attacker reads the stack memory region (via whatever disclosure
   primitive they possess).
4. From the leaked hash bytes, the attacker recovers both the key tweak
   and the chain code for the derived path.
5. With the chain code and knowledge of the public key at each level,
   the attacker can derive all non-hardened child keys in the subtree.
   With the key tweak, the attacker can compute the child private key
   share from the parent share.

### Section 1.2 Property at Risk

- **Section 1.2.1 (Long-term key secrecy):** The leaked key tweak
  plus chain code enables derivation of the full private key share
  subtree from any ancestor key share the attacker can obtain.

### Section 4.2 Category

This falls under Section 4.2 bullet 4: "Sensitive-data memory
persistency. Secret material left in memory beyond the computation
that requires it, in a state that could be exposed by a separate
disclosure primitive."

### Exclusions Analysis

- **Section 2:** Not applicable. This is library-internal secret
  handling.
- **Section 3:** No applicable safe-by-design pattern.
- **Section 6:** No matching frequent wrong claim.

### Severity Assessment

**Estimated:** P3 (Medium)

Per Section 5.3: "Sensitive-data memory persistency without a
demonstrated disclosure primitive." The finding demonstrates that
secret material persists beyond its required lifetime. The severity
depends on whether a disclosure primitive exists in the deployment
environment.

### Acceptance Probability

**60-70%.** This finding has a working PoC at
`poc/hd_derive_stack_secret/poc.cpp` and falls cleanly into Section 4.2
bullet 4. The main question is severity rating, not acceptance.

### Existing PoC

Proof-of-concept at `poc/hd_derive_stack_secret/poc.cpp` demonstrates
recovery of the hash buffer contents from the stack after the function
returns.

---

## Finding 4: Non-Extended Fiat-Shamir Seed Does Not Bind Proof to Key Context

### Affected Files / Lines

- `src/common/cosigner/mta.cpp`, function `generate_mta_range_zkp_seed()`, lines ~115-150
- `src/common/crypto/zero_knowledge_proof/range_proofs.c`, function `genarate_zkpok_seed_internal()`, lines ~106-205 (non-extended branch)

### Description

In the non-extended Fiat-Shamir seed generation path (used when
`version < MPC_EXTENDED_MTA`), the challenge hash does NOT include:

- The verifier's Ring Pedersen public key (N_rp)
- The prover's Paillier public key (N_prover)
- The verifier's Paillier public key (N_verifier)

The extended path includes all three:

```cpp
// Extended path (correct):
hasher.hash_vector_with_size(aad);
hasher.hash_vector_with_size(response.message);
hasher.hash_vector_with_size(response.commitment);
hasher.hash_bn(proof.A, verifier_paillier_pub_n_size * 2, "A");
// ... plus all key context
```

The non-extended path only hashes: salt, aad, response.message,
response.commitment, proof elements (A truncated, Bx, By, E, F, S, T).

Similarly, in `range_proofs.c`, the `genarate_zkpok_seed_internal()`
function in the non-extended branch hashes: salt, aad, ciphertext,
public_point, S, D, Y, T -- but not the Paillier or Ring Pedersen
public keys.

### Attack Scenario

**Adversary:** A malicious co-signer who can interact with the honest
party in multiple protocol sessions using different key setups.

**Mechanism:**

1. In session A, the attacker generates a valid ZKP for key setup
   (Paillier_A, RingPedersen_A).
2. In session B, the honest party expects proofs for a different key
   setup (Paillier_B, RingPedersen_B).
3. Because the Fiat-Shamir challenge does not bind to the key context,
   the attacker attempts to replay the proof from session A into
   session B.

**Mitigating factor:** The `aad` parameter includes session-specific data
(key_id + txid + player_id + seed). As long as `aad` differs between
sessions, the challenges will differ and replay fails. This limits the
attack to scenarios where two sessions produce identical `aad` values,
which the session management should prevent.

However, for the `range_proofs.c` path, the `aad` is constructed from
`uuid + id + seed`. If a protocol allows the same session context to be
reused with different keys (e.g., during key refresh/rotation where the
session identifier is reused), the attack surface opens.

### Section 1.2 Property at Risk

- **Section 1.2.1 (Key secrecy):** If a proof can be transplanted
  across key contexts, the attacker may be able to claim knowledge of
  a value under one key setup while actually possessing it under a
  different setup.
- **Section 1.2.2 (Unforgeability):** Proof replay across key contexts
  could allow the attacker to bypass verification checks.

### Exclusions Analysis

- **Section 2.2 (Transport/Authentication):** The finding does NOT
  depend on transport-level replay. It is about the cryptographic
  binding of the proof to its key context within the Fiat-Shamir
  transcript.
- **Section 3:** No matching safe-by-design pattern.
- **Section 6.2 (drng determinism):** Not applicable; this is about
  what inputs are hashed, not about the deterministic property.

### Severity Assessment

**Estimated:** P4 (Low)

The `aad` parameter provides session binding that largely mitigates
cross-session replay. The vulnerability would require either:
- Two sessions with identical `aad` but different keys (prevented by
  session management under normal operation)
- A scenario where the same proof is valid under two different key
  setups with the same challenge

The extended path was introduced to address exactly this class of issue,
confirming it was recognized as a design weakness.

### Acceptance Probability

**20-30%.** Marginal because `aad` provides effective session binding.
The finding is more of a protocol-level design weakness than an
exploitable vulnerability. The program may classify this as "addressed
by the extended path" and therefore informational for the legacy path.
Including here for completeness as it compounds with Finding 1 (the
same legacy path has both issues simultaneously).

---

## Summary Table

| # | Title | File | Section 1.2 | Severity | Acceptance |
|---|-------|------|-------------|----------|------------|
| 1 | MTA Fiat-Shamir hash truncation | mta.cpp:130 | 1.2.1, 1.2.2 | P2-P3 | 30-45% |
| 2 | Batch verification 40-bit security | mta.cpp, mta.h | 1.2.1, 1.2.2 | P3-P4 | 35-50% |
| 3 | HD derive stack secret leak | hd_derive.cpp:80 | 1.2.1 | P3 | 60-70% |
| 4 | Missing key binding in legacy FS | mta.cpp, range_proofs.c | 1.2.1, 1.2.2 | P4 | 20-30% |

---

## Methodology Notes

- All findings target the malicious-adversary model (Section 1.1) with
  at least one honest participant.
- Findings 1, 2, and 4 involve the MTA sub-protocol which is central to
  CMP-ECDSA threshold signing.
- Finding 3 is a memory hygiene issue in the HD derivation library.
- Each finding includes analysis of whether Section 2 (integrator
  contract), Section 3 (safe-by-design), or Section 6 (frequent wrong
  claims) exclusions apply.
- Findings with estimated acceptance probability below 25% were excluded.
- The existing PoCs at `poc/hd_derive_stack_secret/` and
  `poc/mta_seed_truncation/` support Findings 3 and 1 respectively.
