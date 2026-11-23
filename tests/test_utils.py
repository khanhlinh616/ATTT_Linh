"""
Unit tests for the utils module.
"""

import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.utils import (
    int_to_bytes,
    bytes_to_int,
    rotr32,
    rotl32,
    xor_bytes,
    gcd,
    mod_inverse,
)


class TestUtils(unittest.TestCase):
    """Test suite for utility functions in utils.py."""

    def test_int_and_bytes_conversion(self):
        """Test conversions between integers and byte strings."""
        num = 0x12345678
        b = int_to_bytes(num, 4, "big")
        self.assertEqual(b, b"\x12\x34\x56\x78")
        self.assertEqual(bytes_to_int(b, "big"), num)

    def test_bit_rotations(self):
        """Test 32-bit circular rotations (rotr32, rotl32)."""
        x = 0x80000001
        self.assertEqual(rotr32(x, 1), 0xC0000000)
        self.assertEqual(rotl32(x, 1), 0x00000003)
        self.assertEqual(rotr32(x, 32), x)

    def test_xor_bytes(self):
        """Test byte-by-byte XOR operations."""
        a = b"\xaa\x55\xff\x00"
        b = b"\x55\xaa\xff\x00"
        self.assertEqual(xor_bytes(a, b), b"\xff\xff\x00\x00")
        with self.assertRaises(ValueError):
            xor_bytes(b"\x01", b"\x01\x02")

    def test_gcd_and_mod_inverse(self):
        """Test greatest common divisor and modular inverse via Extended Euclidean Algorithm."""
        self.assertEqual(gcd(54, 24), 6)
        self.assertEqual(gcd(17, 31), 1)

        self.assertEqual(mod_inverse(3, 10), 7)
        self.assertEqual(mod_inverse(3, 26), 9)

        with self.assertRaises(ValueError):
            mod_inverse(6, 9)


if __name__ == "__main__":
    unittest.main()
