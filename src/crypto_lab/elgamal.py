"""
ElGamal Digital Signature Scheme (RFC 3526 Group 14 - 2048-bit).
"""

import secrets
from typing import List, Optional, Tuple
from crypto_lab.utils import gcd, mod_inverse
from crypto_lab.sha256 import sha256_bytes

# Default parameters: RFC 3526 Group 14 (2048-bit Safe Prime)
_RFC3526_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DEFAULT_P = int(_RFC3526_P_HEX, 16)
DEFAULT_G = 11


def _hash_to_int(msg: bytes, modulus: int) -> int:
    """Hash the message with SHA-256 and convert to an integer mod modulus."""
    digest = sha256_bytes(msg)
    h = int.from_bytes(digest, byteorder="big") % modulus
    return h if h != 0 else 1


def generate_keypair(p: Optional[int] = None, g: Optional[int] = None) -> Tuple[int, int]:
    """Generate an ElGamal key pair (private_key, public_key)."""
    p = p or DEFAULT_P
    g = g or DEFAULT_G

    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return x, y


def elgamal_sign(
    msg: bytes,
    p: Optional[int] = None,
    g: Optional[int] = None,
    private_key: Optional[int] = None,
    nonce_k: Optional[int] = None,
) -> Tuple[int, int]:
    """Sign a message using the ElGamal signature algorithm."""
    p = p or DEFAULT_P
    g = g or DEFAULT_G
    if private_key is None:
        raise ValueError("private_key must be provided for signing.")
    if not (1 < private_key < p - 1):
        raise ValueError("private_key must be in range [2, p - 2].")

    p_minus_1 = p - 1
    h = _hash_to_int(msg, p_minus_1)

    while True:
        if nonce_k is not None:
            k = nonce_k
            if not (1 < k < p_minus_1):
                raise ValueError("nonce_k must be in range [2, p - 2].")
            if gcd(k, p_minus_1) != 1:
                raise ValueError("The specified nonce_k is not coprime with (p - 1).")
        else:
            k = secrets.randbelow(p - 3) + 2
            if gcd(k, p_minus_1) != 1:
                continue

        r = pow(g, k, p)
        k_inv = mod_inverse(k, p_minus_1)
        s = (k_inv * (h - private_key * r)) % p_minus_1

        if s == 0:
            if nonce_k is not None:
                raise ValueError("Specified nonce_k results in invalid signature component s == 0.")
            continue
        break

    return r, s


def elgamal_verify(
    msg: bytes,
    p: Optional[int] = None,
    g: Optional[int] = None,
    public_key: Optional[int] = None,
    signature: Optional[Tuple[int, int]] = None,
) -> bool:
    """Verify the validity of an ElGamal digital signature."""
    p = p or DEFAULT_P
    g = g or DEFAULT_G
    if public_key is None or signature is None:
        raise ValueError("Both public_key and signature must be provided for verification.")

    if not (1 < public_key < p):
        return False

    r, s = signature

    if not (0 < r < p and 0 < s < (p - 1)):
        return False

    p_minus_1 = p - 1
    h = _hash_to_int(msg, p_minus_1)

    v1 = pow(g, h, p)
    v2 = (pow(public_key, r, p) * pow(r, s, p)) % p

    return v1 == v2


def _solve_linear_congruence(a: int, b: int, m: int, max_solutions: int = 1000) -> List[int]:
    """Solve the linear congruence a * x = b (mod m)."""
    d = gcd(a, m)
    if b % d != 0:
        return []
    if d > max_solutions:
        raise RuntimeError(f"Too many solutions ({d} > {max_solutions}), potential memory exhaustion.")
    a_prime = a // d
    b_prime = b // d
    m_prime = m // d
    x0 = (mod_inverse(a_prime, m_prime) * b_prime) % m_prime
    return [(x0 + i * m_prime) % m for i in range(d)]


def recover_private_key_reused_nonce(
    msg1: bytes,
    sig1: Tuple[int, int],
    msg2: bytes,
    sig2: Tuple[int, int],
    p: Optional[int] = None,
    g: Optional[int] = None,
    public_key: Optional[int] = None,
) -> int:
    """Recover the private key when the nonce k is reused across two signatures."""
    p = p or DEFAULT_P
    g = g or DEFAULT_G
    if public_key is None:
        raise ValueError("public_key must be provided to verify the recovered private key.")

    r1, s1 = sig1
    r2, s2 = sig2

    if r1 != r2:
        raise ValueError("The two signatures do not share the same r value (nonce was not reused).")

    r = r1
    p_minus_1 = p - 1
    h1 = _hash_to_int(msg1, p_minus_1)
    h2 = _hash_to_int(msg2, p_minus_1)

    diff_s = (s1 - s2) % p_minus_1
    diff_h = (h1 - h2) % p_minus_1

    k_candidates = _solve_linear_congruence(diff_s, diff_h, p_minus_1)
    found_k = None
    for cand in k_candidates:
        if pow(g, cand, p) == r:
            found_k = cand
            break

    if found_k is None:
        raise RuntimeError("Could not find a matching nonce k value.")

    rhs = (h1 - found_k * s1) % p_minus_1
    x_candidates = _solve_linear_congruence(r, rhs, p_minus_1)
    for cand in x_candidates:
        if pow(g, cand, p) == public_key:
            return cand

    raise RuntimeError("Could not recover the private key from the candidates found.")
