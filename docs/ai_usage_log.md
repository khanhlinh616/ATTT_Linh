# AI Usage & Technical Reference Verification Log

This document records the methodological assistance, public test vector cross-referencing, and technical verification log for the Cryptographic Primitives Implementation project.

---

## 1. Literature & Public Standard Reference Verification

All algorithms were implemented from first principles in pure Python (standard library only). Public cryptographic standards were consulted to cross-reference test vectors and normative parameters:

| Date | Standard / Specification | Scope & Parameter Verification | Reference Status |
|:---:|---|---|---|
| 2026-11-14 | **FIPS 180-4** (NIST SHS) | Public test vectors for SHA-256 (`""`, `"abc"`, 56-byte string, boundary lengths 55/56/63/64/65 bytes). | 100% Match |
| 2026-11-14 | **FIPS 197 & NIST SP 800-38A** | AES-128 block cipher round vectors (Appendix B & C.1) and CBC mode test vector (Section F.2.1). | 100% Match |
| 2026-11-14 | **SEC 2 (v2.0)** | SECG `secp256k1` Koblitz curve parameters ($p, a, b, G, n$) and generator multiples ($2G, 3G, 7G$). | 100% Match |
| 2026-11-14 | **RFC 3526** | 2048-bit MODP Group 14 safe prime $p$ ($p = 2q + 1$) and generator $g = 11$. | 100% Match |
| 2026-11-18 | **RFC 6979** (Guidance) | Deterministic nonce generation principles to prevent catastrophic ephemeral nonce reuse attacks. | Audited |
| 2026-11-23 | **Benchmark Methodology** | High-precision timing via `time.perf_counter()` with Median, Mean, and Standard Deviation (N=50 and N=5). | Verified |

---

## 2. AI Usage & Collaboration Disclosure

In accordance with academic integrity guidelines, AI assistance (Gemini / Antigravity) was utilized solely as an auxiliary research and formatting aid under strict human supervision.

| Category | Description & Student Oversight |
|---|---|
| **Tools Used** | Gemini CLI / Antigravity assistance tools. |
| **Main Purposes** | 1. Cross-referencing published NIST/RFC test vectors.<br/>2. Independent edge-case analysis (e.g., verifying PKCS#7 padding validation and nonce collision math).<br/>3. Data visualization formatting for benchmark charts (Matplotlib & styled HTML tables). |
| **Student Contributions** | 100% of mathematical formulas, Galois field $\text{GF}(2^8)$ multiplication, elliptic curve point arithmetic (affine addition, doubling, scalar multiplication), and ElGamal signing/verification were independently studied, authored, and validated by the student. |
| **Verification & Validation** | All code was verified against 30 automated unit tests (`30 passed in 6.09s`). No code was adopted without executing automated test suites and confirming mathematical correctness. |
| **Security & Privacy Safeguards** | No credentials, API keys, student private data, or unmasked cryptographic private keys are stored or transmitted. |

---

## 3. Automated Test Suite Validation

The implementation has been verified through 30 automated unit tests covering all operational bounds:

- **`test_sha256.py` (7 tests):** Boundary byte lengths, empty digest, padding invariants.
- **`test_aes128.py` (6 tests):** FIPS 197 S-box, $\text{GF}(2^8)$ multiplication, CBC round-trip, PKCS#7 padding integrity.
- **`test_ecc.py` (6 tests):** Generator point order, curve membership, coordinate bounds, ECDH secret convergence.
- **`test_elgamal.py` (7 tests):** Signature validity, tampered message rejection, tampered signature rejection, nonce reuse private key recovery.
- **`test_utils.py` (4 tests):** Modular inverse, extended GCD, bitwise rotations, endianness conversions.

**Result:** **30 passed, 5 subtests passed** (Execution time: ~6.09s).
Visual evidence is archived in the `evidence/` directory.
