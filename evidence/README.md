# Experimental Evidence Catalog

This directory contains photographic and visual evidence captured directly from running the implementation in the experimental execution environment.

## Execution Environment
- **Platform:** Windows 11 (Windows-11-10.0.26100-SP0)
- **Python Version:** Python 3.14.7 (CPython)
- **CPU / Processor:** Intel64 Family 6 Model 140 Stepping 1, GenuineIntel
- **Student ID:** 064306xxxx08 (Last digit: 8)

---

## Evidence Index

| No. | File Name | Command Executed | Purpose & Scope | Embedded Location |
|:---:|---|---|---|---|
| 1 | `test_results_part1.jpg` | `python -m pytest tests/ -v` | Unit tests execution (part 1): AES-128, ECC, ElGamal, SHA-256 test cases PASSED | `README.md`, `docs/*.md` |
| 2 | `test_results_part2.png` | `python -m pytest tests/ -v` | Unit tests execution (part 2): SHA-256 boundary subtests, utils, summary: **30 passed, 5 subtests passed in 6.12s** | `README.md`, `docs/*.md` |
| 3 | `demo_sha256_output.jpg` | `python demo/main.py sha256` | SHA-256 demo: NIST test vectors (empty string, "abc"), key derivation, and avalanche effect | `README.md`, `docs/sha256.md` |
| 4 | `demo_aes128_ecdh_start.jpg` | `python demo/main.py` | Demo execution (part 1): Student identity header, AES-128 CBC encryption/decryption with key derived from name, Alice & Bob ECC key generation | `README.md`, `docs/aes128.md`, `docs/ecc.md` |
| 5 | `demo_ecdh_elgamal_start.jpg` | `python demo/main.py` | Demo execution (part 2): ECDH public key exchange, shared secret point $S$ convergence, AES session key derivation, secure channel transmission, ElGamal key generation | `README.md`, `docs/ecc.md`, `docs/elgamal.md` |
| 6 | `demo_elgamal_nonce_start.jpg` | `python demo/main.py` | Demo execution (part 3): ElGamal contract signature generation $(r, s)$, signature verification (True), tampered contract detection (False), nonce reuse attack initiation | `README.md`, `docs/elgamal.md` |
| 7 | `demo_nonce_attack_complete.jpg` | `python demo/main.py` | Demo execution (part 4): Nonce collision observation ($r_1 == r_2$), solving linear system to recover 100% of signer private key $x$, security warning, execution completion | `README.md`, `docs/elgamal.md` |
| 8 | `benchmark_output.png` | `python benchmarks/run_bench.py` | Benchmark execution: Hardware and OS specifications, timing measurements for SHA-256 (1 KB, 1 MB) and AES-128 CBC (1 KB, 1 MB) | `README.md`, `docs/*.md` |
| 9 | `benchmark_results_table.jpg` | `python benchmarks/run_bench.py` | Benchmark results: Completed measurement summary table across all cryptographic primitives | `README.md`, `docs/*.md` |

---

## Verification & Integrity
All evidence captures reflect actual unmodified console outputs verifying:
1. 100% test passing rate across all NIST and RFC standards.
2. Complete end-to-end integration of all implemented cryptographic primitives.
3. Successful experimental validation of the nonce-reuse attack on ElGamal.
