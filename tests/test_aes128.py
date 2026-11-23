"""
Unit tests for the AES-128 module (FIPS 197 and NIST SP 800-38A).
"""

import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.aes128 import (
    gf_mul,
    sbox,
    inv_sbox,
    key_expansion,
    aes_encrypt_block,
    aes_decrypt_block,
    pkcs7_pad,
    pkcs7_unpad,
    aes_encrypt_cbc,
    aes_decrypt_cbc,
    aes_key_from_name,
)
from crypto_lab.sha256 import sha256_bytes
from crypto_lab.utils import xor_bytes


class TestAES128(unittest.TestCase):
    """Test suite for AES-128 block cipher and CBC mode."""

    def test_gf_mul_and_sbox(self):
        """Test finite field multiplication over GF(2^8) and S-box lookup tables."""
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)
        self.assertEqual(sbox(0x53), 0xED)
        self.assertEqual(sbox(0x00), 0x63)
        for b in [0x00, 0x01, 0x53, 0x80, 0xFF]:
            self.assertEqual(inv_sbox(sbox(b)), b)

    def test_fips197_c1(self):
        """Test FIPS 197 Appendix C.1 test vector."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        ciphertext = aes_encrypt_block(plaintext, key)
        self.assertEqual(ciphertext, expected_ciphertext)

        # Test encryption/decryption with pre-expanded round keys
        round_keys = key_expansion(key)
        ciphertext_pre = aes_encrypt_block(plaintext, key, round_keys=round_keys)
        self.assertEqual(ciphertext_pre, expected_ciphertext)
        decrypted_pre = aes_decrypt_block(ciphertext_pre, key, round_keys=round_keys)
        self.assertEqual(decrypted_pre, plaintext)

        decrypted = aes_decrypt_block(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_fips197_appendix_b(self):
        """Test FIPS 197 Appendix B test vector and round keys."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ciphertext = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        round_keys = key_expansion(key)
        self.assertEqual(len(round_keys), 11)
        self.assertEqual(round_keys[1], bytes.fromhex("a0fafe1788542cb123a339392a6c7605"))
        self.assertEqual(round_keys[10], bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6"))

        ciphertext = aes_encrypt_block(plaintext, key)
        self.assertEqual(ciphertext, expected_ciphertext)

        # Test encryption/decryption with pre-expanded round keys
        round_keys = key_expansion(key)
        ciphertext_pre = aes_encrypt_block(plaintext, key, round_keys=round_keys)
        self.assertEqual(ciphertext_pre, expected_ciphertext)
        decrypted_pre = aes_decrypt_block(ciphertext_pre, key, round_keys=round_keys)
        self.assertEqual(decrypted_pre, plaintext)

        decrypted = aes_decrypt_block(ciphertext, key)
        self.assertEqual(decrypted, plaintext)

    def test_cbc_mode(self):
        """Test NIST SP 800-38A Section F.2.1 CBC mode vector and plaintext round-trip."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        
        block1 = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        expected_ct_block1 = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        ct_block1 = aes_encrypt_block(xor_bytes(block1, iv), key)
        self.assertEqual(ct_block1, expected_ct_block1)

        message = b"Chuc mung ban da cai dat thanh cong che do CBC voi dem PKCS#7!"
        ciphertext = aes_encrypt_cbc(message, key, iv)
        decrypted = aes_decrypt_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, message)

    def test_pkcs7_padding(self):
        """Test PKCS#7 padding invariants and rejection of malformed paddings."""
        test_lengths = [0, 1, 15, 16, 17, 31, 32, 33]
        for l in test_lengths:
            data = b"X" * l
            padded = pkcs7_pad(data, 16)
            self.assertEqual(len(padded) % 16, 0)
            self.assertEqual(pkcs7_unpad(padded, 16), data)

        with self.assertRaises(ValueError):
            pkcs7_unpad(b"")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"0123456789abcdef\x00")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"0123456789abcde\x00")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"0123456789abcdef" + b"\x01\x02")
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"0123456789abcdef" + bytes([16] * 15 + [15]))

    def test_key_from_name(self):
        """Test AES-128 key derivation from identifier string."""
        name = "Nguyen Thi Khanh Linh"
        key = aes_key_from_name(name)
        expected_full_hash = sha256_bytes(name.encode("utf-8"))
        expected_key = bytes.fromhex("5d7a3db0c1a37df54fe437bd2cfaf35e")
        self.assertEqual(len(key), 16)
        self.assertEqual(key, expected_full_hash[:16])
        self.assertEqual(key, expected_key)


if __name__ == "__main__":
    unittest.main()
