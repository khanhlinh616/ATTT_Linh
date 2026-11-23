# Project Rules & Technical Constraints

## 1. Scope and Deliverables
- Implement **four cryptographic primitives** from first principles in pure Python (no external crypto libraries):
  1. **AES‑128** in **CBC mode** with **PKCS#7 padding** (FIPS 197, NIST SP 800‑38A).
  2. **Elliptic Curve Cryptography (secp256k1)** with **ECDH key exchange** (SEC 2).
  3. **SHA‑256** hash function (FIPS 180‑4).
  4. **ElGamal digital signature** (RFC 3526 Group 14 – 2048‑bit).
- All code resides in `src/crypto_lab/` and is written **without third‑party cryptographic packages** (`cryptography`, `PyCryptodome`, `PyNaCl`, `hashlib`, `hmac`, `ssl`).
- Standard library modules utilized: `secrets`, `unittest`, `time`, `statistics`, `csv`, `json`, `dataclasses`, `typing`, `struct`.

## 2. Project Layout
```
ATTT/
├── README.md                 # Project manual, architecture, and verification
├── IS.ipynb                  # Experimental notebook and visual analysis
├── docs/                     # Technical specifications & literature verification logs
│   ├── ai_usage_log.md
│   ├── aes128.md
│   ├── sha256.md
│   ├── ecc.md
│   └── elgamal.md
├── src/crypto_lab/           # Core algorithm implementations
├── tests/                    # Unit test suite (30 tests)
├── demo/                     # Integration demo script
├── benchmarks/               # Performance measurement scripts
└── evidence/                 # Visual test & benchmark execution evidence
```

## 3. Security Standards & Privacy Safeguards
- **Confidentiality:** Private keys and sensitive material are masked in console outputs and documentation (`[PROTECTED_PRIVATE_KEY]`).
- **AES‑128:** A fresh, random 16‑byte IV is generated for every CBC encryption operation.
- **ElGamal:** The ephemeral nonce $k$ is sampled with a CSPRNG (`secrets.randbits`) and never reused across signatures.
- **ECDH:** Points are validated against the curve equation prior to group operations.
- **Error Handling:** Descriptive `ValueError` exceptions are raised for invalid input lengths, malformed parameters, and padding corruptions.

## 4. Verification Requirements
- All 30 automated unit tests must pass without failures:
  ```bash
  python -m unittest discover -s tests
  ```
- All documentation and codebase are maintained according to clean code standards.
