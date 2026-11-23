# ecc.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Tuple, Optional
import os
from crypto_lab.utils import mod_inverse
from crypto_lab.sha256 import sha256_bytes

# ---------------------------------------------------------------------------
# Domain parameters for secp256k1 (SEC 2)
# ---------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # prime field
A = 0  # curve coefficient a
B = 7  # curve coefficient b

# Generator point as an immutable dataclass instance
@dataclass(frozen=True)
class Point:
    """Elliptic curve point.

    ``is_infinity`` is ``True`` for the point at infinity; ``x`` and ``y`` are ignored in that case.
    """
    x: Optional[int] = None
    y: Optional[int] = None
    is_infinity: bool = False

    def __post_init__(self) -> None:
        if self.is_infinity:
            object.__setattr__(self, "x", None)
            object.__setattr__(self, "y", None)

# The generator point G and its order N
G = Point(
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order of G
H = 1  # cofactor

# Compatibility alias expected by the test suite
ORDER_N = N

# Point at infinity (the identity element of the group)
INFINITY = Point(is_infinity=True)

# ---------------------------------------------------------------------------
# Helper arithmetic
# ---------------------------------------------------------------------------
# Use mod_inverse from utils.py to maintain DRY and single source of truth
inv_mod = mod_inverse

def is_on_curve(point: Point) -> bool:
    """Check whether *point* lies on the curve ``y^2 = x^3 + ax + b`` (mod ``P``)."""
    if point.is_infinity:
        return True
    x, y = point.x, point.y  # type: ignore
    if x is None or y is None or not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0

# ---------------------------------------------------------------------------
# Point operations
# ---------------------------------------------------------------------------
def point_add(p1: Point, p2: Point) -> Point:
    """Add two points ``p1`` and ``p2`` on the curve.

    Returns the resulting point, or ``INFINITY`` if the result is the identity.
    """
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    x1, y1 = p1.x, p1.y  # type: ignore
    x2, y2 = p2.x, p2.y  # type: ignore
    if x1 == x2 and (y1 + y2) % P == 0:
        return INFINITY
    if p1 == p2:
        # Point doubling
        m = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        # Point addition
        m = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return Point(x3, y3)

def point_double(p: Point) -> Point:
    """Double a point on the curve (wrapper for clarity)."""
    return point_add(p, p)

def point_negate(p: Point) -> Point:
    """Negate a point (reflect over the x-axis)."""
    if p.is_infinity:
        return INFINITY
    return Point(p.x, (-p.y) % P)

def scalar_mul(k: int, point: Point) -> Point:
    """Multiply ``point`` by integer ``k`` using double-and-add (binary method)."""
    if not is_on_curve(point):
        raise ValueError("Point is not on the secp256k1 curve.")
    if k % N == 0 or point.is_infinity:
        return INFINITY
    if k < 0:
        # k * P = -k * (-P)
        return scalar_mul(-k, point_negate(point))
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result

# ---------------------------------------------------------------------------
# Key generation & ECDH
# ---------------------------------------------------------------------------
def gen_private_key() -> int:
    """Generate a random private key in the interval ``[1, N-1]``."""
    while True:
        candidate = int.from_bytes(os.urandom(32), "big")
        if 1 <= candidate < N:
            return candidate

def gen_public_key(priv: int) -> Point:
    """Compute the public key ``Q = priv * G``."""
    return scalar_mul(priv, G)

def generate_keypair() -> Tuple[int, Point]:
    """Return a ``(private, public)`` key pair."""
    priv = gen_private_key()
    pub = gen_public_key(priv)
    return priv, pub

def ecdh_shared_secret(priv: int, peer_pub: Point) -> Point:
    """Derive the shared secret point from a private key and a peer's public key.

    The secret is the full elliptic-curve point (both ``x`` and ``y``). The test suite
    expects this function to return a ``Point`` instance.
    """
    if peer_pub.is_infinity:
        raise ValueError("Peer public key must not be the point at infinity.")
    if not is_on_curve(peer_pub):
        raise ValueError("Peer public key is not on the secp256k1 curve.")
    point = scalar_mul(priv, peer_pub)
    if point.is_infinity:
        raise ValueError("Invalid shared point (point at infinity)")
    return point


def derive_session_key(shared_point: Point) -> bytes:
    """Derive a 16-byte AES session key from the x-coordinate of an ECDH shared secret point."""
    if shared_point.is_infinity or shared_point.x is None:
        raise ValueError("Cannot derive session key from the point at infinity.")
    x_bytes = shared_point.x.to_bytes(32, byteorder="big")
    return sha256_bytes(x_bytes)[:16]

# ---------------------------------------------------------------------------
# Compatibility shim -- original code used a function named ``scalar_mul`` that
# performed the multiplication.  We expose the same name for the tests.
# ---------------------------------------------------------------------------
# (The implementation above already uses the name ``scalar_mul``.)

if __name__ == "__main__":
    # Simple sanity check when the module is executed directly.
    a_priv, a_pub = generate_keypair()
    b_priv, b_pub = generate_keypair()
    assert ecdh_shared_secret(a_priv, b_pub) == ecdh_shared_secret(b_priv, a_pub)
    print("ECC self-test passed.")
