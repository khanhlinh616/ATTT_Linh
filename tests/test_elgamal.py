"""
Unit tests for the ElGamal Digital Signature Scheme module.
"""

import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.elgamal import (
    DEFAULT_P,
    DEFAULT_G,
    generate_keypair,
    elgamal_sign,
    elgamal_verify,
    recover_private_key_reused_nonce,
)
from crypto_lab.utils import gcd


class TestElGamal(unittest.TestCase):
    """Test suite for the ElGamal digital signature scheme."""

    def setUp(self):
        """Initialize test keypair with standard RFC 3526 parameters."""
        self.p = DEFAULT_P
        self.g = DEFAULT_G
        self.priv_key, self.pub_key = generate_keypair(self.p, self.g)
        self.message = b"Thong diep kiem thu chu ky so ElGamal mon ATTT."

    def test_sign_and_verify_valid(self):
        """Test signing and verifying a valid digital signature."""
        sig = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        self.assertTrue(elgamal_verify(self.message, self.p, self.g, self.pub_key, sig))

    def test_verify_tampered_message(self):
        """Test signature verification fails when message payload is modified."""
        sig = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        tampered_msg = self.message[:-1] + bytes([self.message[-1] ^ 1])
        self.assertFalse(elgamal_verify(tampered_msg, self.p, self.g, self.pub_key, sig))

    def test_verify_tampered_signature(self):
        """Test signature verification fails when signature components are modified."""
        r, s = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        
        tampered_sig_r = ((r + 1) % self.p, s)
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, tampered_sig_r))

        tampered_sig_s = (r, (s + 1) % (self.p - 1))
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, tampered_sig_s))

    def test_verify_wrong_public_key(self):
        """Test signature created by key A fails verification with key B."""
        sig = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        _, other_pub_key = generate_keypair(self.p, self.g)
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, other_pub_key, sig))

    def test_invalid_signature_range(self):
        """Test rejection when signature components r or s fall outside valid range."""
        sig = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        r, s = sig

        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, (0, s)))
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, (self.p, s)))

        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, (r, 0)))
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, self.pub_key, (r, self.p - 1)))

    def test_parameter_validation(self):
        """Test parameter bounds validation for sign and verify."""
        # Invalid private_key in sign
        with self.assertRaises(ValueError):
            elgamal_sign(self.message, self.p, self.g, private_key=1)
        with self.assertRaises(ValueError):
            elgamal_sign(self.message, self.p, self.g, private_key=self.p - 1)

        # Invalid nonce_k in sign
        with self.assertRaises(ValueError):
            elgamal_sign(self.message, self.p, self.g, self.priv_key, nonce_k=1)
        with self.assertRaises(ValueError):
            elgamal_sign(self.message, self.p, self.g, self.priv_key, nonce_k=self.p - 1)

        # Specified nonce_k producing s == 0 must raise ValueError
        # Using small parameters: p=23, g=5, x=2, k=7 for which h=12, r=17, x*r mod 22 = 12 => s=0
        with self.assertRaises(ValueError):
            elgamal_sign(b"test", p=23, g=5, private_key=2, nonce_k=7)

        # Invalid public_key in verify
        sig = elgamal_sign(self.message, self.p, self.g, self.priv_key)
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, public_key=0, signature=sig))
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, public_key=1, signature=sig))
        self.assertFalse(elgamal_verify(self.message, self.p, self.g, public_key=self.p, signature=sig))

    def test_nonce_reuse_attack(self):
        """Test private key recovery attack when ephemeral nonce k is reused."""
        msg1 = b"Transfer order 1: Send 100 USD to account A."
        msg2 = b"Transfer order 2: Send 500 USD to account B."

        fixed_k = 65537
        while gcd(fixed_k, self.p - 1) != 1:
            fixed_k += 2

        sig1 = elgamal_sign(msg1, self.p, self.g, self.priv_key, nonce_k=fixed_k)
        sig2 = elgamal_sign(msg2, self.p, self.g, self.priv_key, nonce_k=fixed_k)

        self.assertEqual(sig1[0], sig2[0])

        recovered_priv_key = recover_private_key_reused_nonce(
            msg1, sig1, msg2, sig2, p=self.p, g=self.g, public_key=self.pub_key
        )
        self.assertEqual(recovered_priv_key, self.priv_key)


if __name__ == "__main__":
    unittest.main()
