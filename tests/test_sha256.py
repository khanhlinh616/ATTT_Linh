"""
Unit tests for the SHA-256 module (FIPS 180-4).
"""

import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.sha256 import sha256_hex, sha256_bytes, pad_message


class TestSHA256(unittest.TestCase):
    """Test suite for the SHA-256 cryptographic hash function."""

    def test_empty_string(self):
        """Test hash of empty byte string b''."""
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(sha256_hex(b""), expected)

    def test_abc(self):
        """Test hash of ASCII string b'abc'."""
        expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        self.assertEqual(sha256_hex(b"abc"), expected)

    def test_long_string_56_bytes(self):
        """Test hash of standardized 56-byte string."""
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        self.assertEqual(sha256_hex(msg), expected)

    def test_one_million_a(self):
        """Test hash of 1,000,000 repetitions of character 'a' (1 MB)."""
        msg = b"a" * 1_000_000
        expected = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        self.assertEqual(sha256_hex(msg), expected)

    def test_boundary_lengths(self):
        """Test boundary lengths: 55, 56, 63, 64, 65 bytes."""
        vectors = {
            55: "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
            56: "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
            63: "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
            64: "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
            65: "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        }
        for length, expected in vectors.items():
            with self.subTest(length=length):
                data = b"a" * length
                self.assertEqual(sha256_hex(data), expected)

    def test_pad_message_properties(self):
        """Test structural invariants of the pad_message function."""
        for length in [0, 1, 55, 56, 63, 64, 65, 120]:
            padded = pad_message(b"x" * length)
            self.assertEqual(len(padded) % 64, 0)
            self.assertEqual(padded[length], 0x80)
            orig_bits = int.from_bytes(padded[-8:], "big")
            self.assertEqual(orig_bits, length * 8)

    def test_type_validation(self):
        """Test rejection of non-bytes/bytearray inputs."""
        with self.assertRaises(TypeError):
            sha256_hex("string input")
        with self.assertRaises(TypeError):
            sha256_bytes(12345)
        with self.assertRaises(TypeError):
            pad_message("string input")


if __name__ == "__main__":
    unittest.main()
