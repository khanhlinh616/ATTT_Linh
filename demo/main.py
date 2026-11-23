import os
import sys
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.sha256 import sha256_bytes, sha256_hex
from crypto_lab.aes128 import (
    aes_key_from_name,
    aes_encrypt_cbc,
    aes_decrypt_cbc,
)
from crypto_lab.ecc import (
    G,
    generate_keypair as ecc_generate_keypair,
    ecdh_shared_secret,
    derive_session_key,
)
from crypto_lab.elgamal import (
    DEFAULT_P,
    DEFAULT_G,
    generate_keypair as elgamal_generate_keypair,
    elgamal_sign,
    elgamal_verify,
    recover_private_key_reused_nonce,
)
from crypto_lab.utils import gcd


def print_header(title: str) -> None:
    """Print a section header."""
    print("\n" + "=" * 75)
    print(f" {title.upper()} ")
    print("=" * 75)


def mask_secret(value: int, prefix_len: int = 4, suffix_len: int = 4) -> str:
    """Mask sensitive private key value for secure logging and console output."""
    hex_str = f"{value:x}"
    if len(hex_str) <= prefix_len + suffix_len:
        return "[PROTECTED_PRIVATE_KEY]"
    return f"0x{hex_str[:prefix_len]}...[PROTECTED_PRIVATE_KEY]...{hex_str[-suffix_len:]}"


def demo_sha256() -> None:
    """Demo SHA-256 hash function against NIST vectors and Avalanche property."""
    print_header("1. Secure Hash Algorithm SHA-256 (FIPS 180-4)")

    # 1. NIST test vectors
    digest_empty = sha256_hex(b"")
    print("[*] NIST Test Vector 1 (Empty String):")
    print(f"    Input : \"\"")
    print(f"    Digest: {digest_empty}")
    assert digest_empty == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    print("    -> Match NIST FIPS 180-4 standard vector: PASS")

    digest_abc = sha256_hex(b"abc")
    print("\n[*] NIST Test Vector 2 (\"abc\"):")
    print(f"    Input : \"abc\"")
    print(f"    Digest: {digest_abc}")
    assert digest_abc == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    print("    -> Match NIST FIPS 180-4 standard vector: PASS")

    # 2. Key derivation hash
    student_id_str = "Nguyen Thi Khanh Linh"
    digest_name = sha256_hex(student_id_str.encode("utf-8"))
    aes_key_preview = digest_name[:32]
    print(f"\n[*] Key Derivation Digest (SHA-256 of Identifier):")
    print(f"    Input : \"{student_id_str}\"")
    print(f"    Digest: {digest_name}")
    print(f"    Derived AES-128 Key (first 16 bytes): {aes_key_preview}")

    # 3. Avalanche effect demonstration
    modified_str = "Nguyen Thi Khanh Linh."
    digest_modified = sha256_hex(modified_str.encode("utf-8"))
    print(f"\n[*] Avalanche Effect Demonstration (1 byte modified):")
    print(f"    Original : \"{student_id_str}\" -> {digest_name}")
    print(f"    Modified : \"{modified_str}\" -> {digest_modified}")
    diff_bits = sum(bin(a ^ b).count("1") for a, b in zip(bytes.fromhex(digest_name), bytes.fromhex(digest_modified)))
    print(f"    Bit Difference: {diff_bits}/256 bits changed (~{diff_bits/256*100:.1f}%)")
    print("[+] RESULT: SHA-256 hashing strictly conforms to FIPS 180-4 standard!")


def demo_aes_from_name(full_name: str) -> None:
    """Demo AES-128 CBC encryption with key derived from student name via SHA-256."""
    print_header("2. Symmetric Cipher AES-128 CBC & Key Derivation from Name")

    print(f"[*] Student full name     : {full_name}")
    full_hash = sha256_hex(full_name.encode("utf-8"))
    print(f"[*] SHA-256(Name)         : {full_hash}")

    aes_key = aes_key_from_name(full_name)
    print(f"[*] AES-128 Key (16 bytes): {aes_key.hex()} ({len(aes_key) * 8} bit)")

    iv = os.urandom(16)
    print(f"[*] Initialization Vector : {iv.hex()}")

    plaintext = (
        f"Hello Professor and classmates. "
        f"Full name: {full_name}. AES-128 CBC."
    ).encode("utf-8")
    print(f"[*] Plaintext:\n    \"{plaintext.decode('utf-8')}\"")

    ciphertext = aes_encrypt_cbc(plaintext, aes_key, iv)
    print(f"[*] Ciphertext (hex, {len(ciphertext)} bytes):\n    {ciphertext.hex()}")

    decrypted = aes_decrypt_cbc(ciphertext, aes_key, iv)
    print(f"[*] Decrypted plaintext:\n    \"{decrypted.decode('utf-8')}\"")

    assert decrypted == plaintext, "AES-128 decryption mismatch"
    print(" - RESULT: AES-128 CBC encryption and decryption successful!")


def demo_ecdh_key_exchange() -> None:
    """Demo ECDH key exchange on secp256k1."""
    print_header("3. Asymmetric Cryptography ECC (secp256k1) & ECDH Key Exchange")

    # 1. Generate key pairs for Alice & Bob
    alice_priv, alice_pub = ecc_generate_keypair()
    bob_priv, bob_pub = ecc_generate_keypair()

    print("[*] Alice's side:")
    print(f"    - Private key d_A : {mask_secret(alice_priv)}")
    print(f"    - Public key  Q_A : x=0x{alice_pub.x:064x}...")

    print("[*] Bob's side:")
    print(f"    - Private key d_B : {mask_secret(bob_priv)}")
    print(f"    - Public key  Q_B : x=0x{bob_pub.x:064x}...")

    # 2. Exchange public keys and compute shared secret
    alice_shared = ecdh_shared_secret(alice_priv, bob_pub)
    bob_shared = ecdh_shared_secret(bob_priv, alice_pub)

    print("\n[*] Public key exchange over public channel:")
    print(f"    - Alice computes S = d_A * Q_B: x=0x{alice_shared.x:064x}")
    print(f"    - Bob computes   S = d_B * Q_A: x=0x{bob_shared.x:064x}")

    assert alice_shared == bob_shared, "ECDH error: both parties did not arrive at the same shared secret!"
    print("[+] Match: Alice and Bob computed the exact same secret point S on the curve!")

    # 3. Derive AES-128 session key from S via derive_session_key
    session_key = derive_session_key(alice_shared)
    print(f"[*] Derived session key: {session_key.hex()}")

    # 4. Secure channel: Alice sends encrypted data to Bob
    secret_channel_msg = b"Secret data transmitted between Alice and Bob via ECDH session key."
    channel_iv = os.urandom(16)
    encrypted_msg = aes_encrypt_cbc(secret_channel_msg, session_key, channel_iv)
    decrypted_msg = aes_decrypt_cbc(encrypted_msg, session_key, channel_iv)

    assert decrypted_msg == secret_channel_msg
    print(f"[*] Alice encrypts and sends: \"{secret_channel_msg.decode('utf-8')}\"")
    print(f"[*] Bob decrypts and receives: \"{decrypted_msg.decode('utf-8')}\"")
    print("[+] RESULT: Integrated secure channel ECC-ECDH + SHA-256 + AES-128 works correctly!")


def demo_elgamal_signature() -> None:
    """Demo ElGamal digital signature and verification on a 2048-bit group."""
    print_header("4. ElGamal Digital Signature (RFC 3526 2048-bit Group 14)")

    # 1. Generate ElGamal key pair
    priv_key, pub_key = elgamal_generate_keypair()
    print(f"[*] Group parameters: p ({DEFAULT_P.bit_length()} bit), generator g = {DEFAULT_G}")
    print(f"[*] Signer private key x: {mask_secret(priv_key)}")
    print(f"[*] Public key y = g^x mod p: 0x{pub_key:064x}...")

    # 2. Sign the message
    contract_doc = b"Electronic contract No. 2026/ATTT: Cryptographic procedure handover."
    print(f"\n[*] Message to sign:\n    \"{contract_doc.decode('utf-8')}\"")

    r, s = elgamal_sign(contract_doc, DEFAULT_P, DEFAULT_G, priv_key)
    print(f"[*] Digital signature (r, s):")
    print(f"    - r = 0x{r:064x}...")
    print(f"    - s = 0x{s:064x}...")

    # 3. Recipient verifies the signature
    is_valid = elgamal_verify(contract_doc, DEFAULT_P, DEFAULT_G, pub_key, (r, s))
    print(f"[*] Original signature verification result: {is_valid}")
    assert is_valid, "Error: Valid signature failed verification!"

    # 4. Simulate message tampering
    tampered_doc = contract_doc[:-1] + b"X"
    is_tampered_valid = elgamal_verify(tampered_doc, DEFAULT_P, DEFAULT_G, pub_key, (r, s))
    print(f"[*] Tampered message -> Verification result: {is_tampered_valid}")
    assert not is_tampered_valid, "Error: Failed to detect tampered message!"
    print("[+] RESULT: ElGamal digital signature ensures integrity and origin authentication!")


def demo_nonce_reuse_attack() -> None:
    """Demo private key recovery attack when nonce k is reused in ElGamal."""
    print_header("5. Security Experiment: Nonce k Reuse Attack on ElGamal")

    priv_key, pub_key = elgamal_generate_keypair()
    print(f"[*] Victim's initial private key x: {mask_secret(priv_key)}")

    msg1 = b"Transaction order 1: Transfer 1,000 USD to supplier A."
    msg2 = b"Transaction order 2: Transfer 5,000 USD to supplier B."

    # Reuse the same nonce k for two signatures
    reused_k = 100003
    while gcd(reused_k, DEFAULT_P - 1) != 1:
        reused_k += 2

    sig1 = elgamal_sign(msg1, DEFAULT_P, DEFAULT_G, priv_key, nonce_k=reused_k)
    sig2 = elgamal_sign(msg2, DEFAULT_P, DEFAULT_G, priv_key, nonce_k=reused_k)

    print("[*] Victim signs 2 different messages with the SAME nonce k:")
    print(f"    - Signature 1: r1 = 0x{sig1[0]:064x}..., s1 = 0x{sig1[1]:064x}...")
    print(f"    - Signature 2: r2 = 0x{sig2[0]:064x}..., s2 = 0x{sig2[1]:064x}...")
    print(f"    -> Note: r1 == r2 == 0x{sig1[0]:064x}... (Nonce leak indicator!)")

    print("\n[*] Attacker collects 2 signatures and solves the system of linear congruences:")
    recovered_x = recover_private_key_reused_nonce(
        msg1, sig1, msg2, sig2, p=DEFAULT_P, g=DEFAULT_G, public_key=pub_key
    )
    print(f"    - Recovered private key: {mask_secret(recovered_x)}")

    assert recovered_x == priv_key, "Private key recovery failed!"
    print("[+] ATTACK RESULT: Successfully recovered 100% of the signer's private key!")
    print("[!] SECURITY WARNING: Nonce k must be a secret random value used ONLY ONCE.")


def main() -> None:
    """Main demo entry point."""
    if len(sys.argv) > 1 and sys.argv[1].lower() == "sha256":
        demo_sha256()
        return

    print("*" * 75)
    print("   EXPERIMENTAL REPORT — INFORMATION SECURITY PROJECT")
    print("   Student ID (SID): 064306xxxx08 (Last digit: 8)")
    print("   Algorithm assignment: ECC (8 mod 3 = 2) & ElGamal (8 mod 4 = 0)")
    print("*" * 75)

    demo_sha256()
    student_name = "Nguyen Thi Khanh Linh"
    demo_aes_from_name(student_name)
    demo_ecdh_key_exchange()
    demo_elgamal_signature()
    demo_nonce_reuse_attack()

    print("\n" + "=" * 75)
    print(" COMPLETE! ")
    print("=" * 75)


if __name__ == "__main__":
    main()
