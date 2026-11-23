"""
Arithmetic and byte/bit manipulation utilities for the cryptographic system.
"""


def int_to_bytes(n: int, length: int, byteorder: str = "big") -> bytes:
    """Convert an integer to a byte string."""
    return n.to_bytes(length, byteorder=byteorder)


def bytes_to_int(b: bytes, byteorder: str = "big") -> int:
    """Convert a byte string to an integer."""
    return int.from_bytes(b, byteorder=byteorder)


def rotr32(x: int, n: int) -> int:
    """Right-rotate a 32-bit integer by n bits."""
    n = n % 32
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def rotl32(x: int, n: int) -> int:
    """Left-rotate a 32-bit integer by n bits."""
    n = n % 32
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(a) != len(b):
        raise ValueError(f"Byte strings must have equal length: {len(a)} != {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def gcd(a: int, b: int) -> int:
    """Greatest common divisor (Euclidean algorithm)."""
    while b != 0:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm: returns gcd(a, b) and Bezout coefficients x, y such that a*x + b*y = gcd(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q = a // b
        a, b = b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(a: int, m: int) -> int:
    """Compute the modular inverse of a modulo m using the Extended Euclidean algorithm."""
    if m <= 1:
        raise ValueError("Modulus m must be greater than 1.")
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Modular inverse of {a} modulo {m} does not exist")
    return (x % m + m) % m
