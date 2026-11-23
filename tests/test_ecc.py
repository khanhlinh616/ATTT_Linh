"""
Unit tests for the ECC module (secp256k1 and ECDH).
"""

import sys
import unittest
from pathlib import Path

src_path = str(Path(__file__).resolve().parent.parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

from crypto_lab.ecc import (
    Point,
    INFINITY,
    G,
    P,
    ORDER_N,
    is_on_curve,
    point_add,
    point_double,
    point_negate,
    scalar_mul,
    generate_keypair,
    ecdh_shared_secret,
    derive_session_key,
)


class TestECC(unittest.TestCase):
    """Test suite for secp256k1 elliptic curve arithmetic and ECDH."""

    def test_base_point_on_curve(self):
        """Test base point G lies on the curve and n * G == O."""
        self.assertTrue(is_on_curve(G))
        self.assertEqual(scalar_mul(ORDER_N, G), INFINITY)
        self.assertTrue(scalar_mul(ORDER_N, G).is_infinity)

    def test_known_multiples_of_g(self):
        """Test multiples 2G, 3G, 7G against standard SEC 2 reference coordinates."""
        # Test vector 2G
        g2 = scalar_mul(2, G)
        self.assertEqual(
            g2.x,
            0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
        )
        self.assertEqual(
            g2.y,
            0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A,
        )
        self.assertTrue(is_on_curve(g2))

        # Test vector 3G
        g3 = scalar_mul(3, G)
        self.assertEqual(
            g3.x,
            0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9,
        )
        self.assertEqual(
            g3.y,
            0x388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672,
        )
        self.assertTrue(is_on_curve(g3))

        # Test vector 7G
        g7 = scalar_mul(7, G)
        self.assertEqual(
            g7.x,
            0x5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC,
        )
        self.assertEqual(
            g7.y,
            0x6AEBCA40BA255960A3178D6D861A54DBA813D0B813FDE7B5A5082628087264DA,
        )
        self.assertTrue(is_on_curve(g7))

    def test_group_axioms(self):
        """Test abelian group axioms (negation, identity, associativity)."""
        p_neg = point_negate(G)
        self.assertTrue(is_on_curve(p_neg))
        self.assertEqual(point_add(G, p_neg), INFINITY)
        self.assertEqual(point_add(G, INFINITY), G)
        self.assertEqual(point_add(INFINITY, G), G)
        self.assertEqual(scalar_mul(5, INFINITY), INFINITY)

        g5_direct = scalar_mul(5, G)
        g5_added = point_add(scalar_mul(2, G), scalar_mul(3, G))
        self.assertEqual(g5_direct, g5_added)

    def test_ecdh_shared_secret(self):
        """Test ECDH key exchange convergence across 20 random keypairs."""
        for _ in range(20):
            alice_priv, alice_pub = generate_keypair()
            bob_priv, bob_pub = generate_keypair()

            alice_shared = ecdh_shared_secret(alice_priv, bob_pub)
            bob_shared = ecdh_shared_secret(bob_priv, alice_pub)

            self.assertEqual(alice_shared, bob_shared)
            self.assertTrue(is_on_curve(alice_shared))
            self.assertFalse(alice_shared.is_infinity)

    def test_invalid_points(self):
        """Test rejection of off-curve points and points at infinity."""
        invalid_pt = Point(x=1, y=1)
        self.assertFalse(is_on_curve(invalid_pt))

        # Test coordinates outside field bounds [0, P - 1]
        out_of_bounds_x = Point(x=P + 1, y=1)
        self.assertFalse(is_on_curve(out_of_bounds_x))
        out_of_bounds_y = Point(x=1, y=P)
        self.assertFalse(is_on_curve(out_of_bounds_y))
        negative_coord = Point(x=-1, y=1)
        self.assertFalse(is_on_curve(negative_coord))

        priv, _ = generate_keypair()
        with self.assertRaises(ValueError):
            ecdh_shared_secret(priv, invalid_pt)

        with self.assertRaises(ValueError):
            ecdh_shared_secret(priv, out_of_bounds_x)

        with self.assertRaises(ValueError):
            ecdh_shared_secret(priv, INFINITY)

        with self.assertRaises(ValueError):
            scalar_mul(5, invalid_pt)

    def test_derive_session_key(self):
        """Test session key derivation from ECDH shared secret point."""
        alice_priv, alice_pub = generate_keypair()
        bob_priv, bob_pub = generate_keypair()

        alice_shared = ecdh_shared_secret(alice_priv, bob_pub)
        bob_shared = ecdh_shared_secret(bob_priv, alice_pub)

        key_alice = derive_session_key(alice_shared)
        key_bob = derive_session_key(bob_shared)

        self.assertEqual(key_alice, key_bob)
        self.assertEqual(len(key_alice), 16)
        self.assertIsInstance(key_alice, bytes)

        with self.assertRaises(ValueError):
            derive_session_key(INFINITY)


if __name__ == "__main__":
    unittest.main()
