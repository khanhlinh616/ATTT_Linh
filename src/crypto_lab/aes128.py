"""
AES-128 symmetric cipher (FIPS 197) with CBC mode (NIST SP 800-38A).
"""

from typing import List, Optional
from crypto_lab.utils import xor_bytes
from crypto_lab.sha256 import sha256_bytes

# Rcon constants for Key Expansion
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def gf_mul(a: int, b: int) -> int:
    """Multiply two elements in the finite field GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p


def _gf_inv(b: int) -> int:
    """Multiplicative inverse of byte b in GF(2^8). Convention: 0^(-1) = 0."""
    if b == 0:
        return 0
    res, base, exp = 1, b, 254
    while exp > 0:
        if exp & 1:
            res = gf_mul(res, base)
        base = gf_mul(base, base)
        exp >>= 1
    return res


def _build_sboxes():
    """Generate S-box and Inverse S-box via the Affine transformation."""
    s_box = [0] * 256
    inv_s_box = [0] * 256
    for val in range(256):
        inv = _gf_inv(val)
        res = 0
        for i in range(8):
            bit = (
                ((inv >> i) & 1)
                ^ ((inv >> ((i + 4) % 8)) & 1)
                ^ ((inv >> ((i + 5) % 8)) & 1)
                ^ ((inv >> ((i + 6) % 8)) & 1)
                ^ ((inv >> ((i + 7) % 8)) & 1)
                ^ ((0x63 >> i) & 1)
            )
            res |= bit << i
        s_box[val] = res
        inv_s_box[res] = val
    return s_box, inv_s_box

_SBOX, _INV_SBOX = _build_sboxes()

def sbox(b: int) -> int:
    """Look up the S-box value."""
    return _SBOX[b & 0xFF]

def inv_sbox(b: int) -> int:
    """Look up the Inverse S-box value."""
    return _INV_SBOX[b & 0xFF]


def key_expansion(key: bytes) -> List[bytes]:
    """Expand a 128-bit key into 11 round keys."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes (128 bits).")
    words = []
    for i in range(4):
        words.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
    for i in range(4, 44):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_SBOX[x] for x in temp]
            temp[0] ^= RCON[i // 4]
        word = [words[i - 4][j] ^ temp[j] for j in range(4)]
        words.append(word)
    round_keys = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk.extend(words[r * 4 + c])
        round_keys.append(bytes(rk))
    return round_keys


def _sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte of the state matrix using the S-box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]

def _inv_sub_bytes(state: List[List[int]]) -> None:
    """Substitute each byte of the state matrix using the Inverse S-box."""
    for r in range(4):
        for c in range(4):
            state[r][c] = _INV_SBOX[state[r][c]]

def _shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the left."""
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def _inv_shift_rows(state: List[List[int]]) -> None:
    """Cyclically shift rows to the right."""
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]

def _mix_columns(state: List[List[int]]) -> None:
    """MixColumns transformation over GF(2^8)."""
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = gf_mul(2, s0) ^ gf_mul(3, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ gf_mul(2, s1) ^ gf_mul(3, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ gf_mul(2, s2) ^ gf_mul(3, s3)
        state[3][c] = gf_mul(3, s0) ^ s1 ^ s2 ^ gf_mul(2, s3)

def _inv_mix_columns(state: List[List[int]]) -> None:
    """Inverse MixColumns transformation."""
    for c in range(4):
        col = [state[0][c], state[1][c], state[2][c], state[3][c]]
        state[0][c] = gf_mul(0x0E, col[0]) ^ gf_mul(0x0B, col[1]) ^ gf_mul(0x0D, col[2]) ^ gf_mul(0x09, col[3])
        state[1][c] = gf_mul(0x09, col[0]) ^ gf_mul(0x0E, col[1]) ^ gf_mul(0x0B, col[2]) ^ gf_mul(0x0D, col[3])
        state[2][c] = gf_mul(0x0D, col[0]) ^ gf_mul(0x09, col[1]) ^ gf_mul(0x0E, col[2]) ^ gf_mul(0x0B, col[3])
        state[3][c] = gf_mul(0x0B, col[0]) ^ gf_mul(0x0D, col[1]) ^ gf_mul(0x09, col[2]) ^ gf_mul(0x0E, col[3])

def _add_round_key(state: List[List[int]], round_key: bytes) -> None:
    """XOR the round key into the state matrix."""
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[c * 4 + r]

def aes_encrypt_block(block: bytes, key: bytes, round_keys: Optional[List[bytes]] = None) -> bytes:
    """Encrypt a single 16-byte block using AES-128."""
    if len(block) != 16:
        raise ValueError("AES data block must be exactly 16 bytes.")
    if round_keys is None:
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes.")
        round_keys = key_expansion(key)
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[0])
    for rnd in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[rnd])
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)

def aes_decrypt_block(block: bytes, key: bytes, round_keys: Optional[List[bytes]] = None) -> bytes:
    """Decrypt a single 16-byte block using AES-128."""
    if len(block) != 16:
        raise ValueError("AES data block must be exactly 16 bytes.")
    if round_keys is None:
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes.")
        round_keys = key_expansion(key)
    state = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_round_key(state, round_keys[10])
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    for rnd in range(9, 0, -1):
        _add_round_key(state, round_keys[rnd])
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    out = bytearray(16)
    for c in range(4):
        for r in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Pad data according to the PKCS#7 standard."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(padded: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS#7 padding from data."""
    if not padded or len(padded) % block_size != 0:
        raise ValueError("Input data is empty or not correctly padded")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if padded[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]

def aes_encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt arbitrary-length data using AES-128 in CBC mode (PKCS#7 padding)."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    round_keys = key_expansion(key)
    padded = pkcs7_pad(plaintext, 16)
    ciphertext = b""
    prev = iv
    for i in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[i:i+16], prev))
        enc = aes_encrypt_block(block, key, round_keys=round_keys)
        ciphertext += enc
        prev = enc
    return ciphertext

def aes_decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-128 CBC ciphertext and remove PKCS#7 padding."""
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext length must be multiple of 16")
    round_keys = key_expansion(key)
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = aes_decrypt_block(block, key, round_keys=round_keys)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        plaintext += plain_block
        prev = block
    return pkcs7_unpad(plaintext, 16)

def aes_key_from_name(full_name: str) -> bytes:
    """Derive an AES-128 key (first 16 bytes of SHA-256(full_name))."""
    name_bytes = full_name.encode("utf-8")
    digest = sha256_bytes(name_bytes)
    return digest[:16]

if __name__ == "__main__":
    import os
    name = "Nguyen Thi Khanh Linh"
    key = aes_key_from_name(name)
    iv = os.urandom(16)
    msg = b"Hello, AES-128 CBC with PKCS#7!"
    ct = aes_encrypt_cbc(msg, key, iv)
    pt = aes_decrypt_cbc(ct, key, iv)
    assert pt == msg
    print("Self-test passed.")
