from __future__ import annotations
import os
import random
from typing import Callable

from Crypto.Cipher import AES
BLOCK_SIZE = 16
def random_bytes(length: int) -> bytes:
    return os.urandom(length)

def chunks(data: bytes, size: int) -> list[bytes]:
    return [data[index:index + size] for index in range(0, len(data), size)]

def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("xor_bytes requires equal-length inputs")
    return bytes(a ^ b for a, b in zip(left, right))

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("input length must be a positive multiple of the block size")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding bytes")
    return data[:-pad_len]

def aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB encryption requires aligned input")
    return AES.new(key, AES.MODE_ECB).encrypt(data)

def aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("ECB decryption requires aligned input")
    return AES.new(key, AES.MODE_ECB).decrypt(data)

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be one block long")
    plaintext = pkcs7_pad(data, BLOCK_SIZE) if pad else data
    if len(plaintext) % BLOCK_SIZE != 0:
        raise ValueError("CBC encryption requires aligned input")

    ciphertext_blocks: list[bytes] = []
    previous = iv
    for block in chunks(plaintext, BLOCK_SIZE):
        encrypted = aes_ecb_encrypt(xor_bytes(block, previous), key)
        ciphertext_blocks.append(encrypted)
        previous = encrypted
    return b"".join(ciphertext_blocks)

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes, unpad: bool = False) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be one block long")
    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("CBC decryption requires aligned input")

    plaintext_blocks: list[bytes] = []
    previous = iv
    for block in chunks(data, BLOCK_SIZE):
        decrypted = aes_ecb_decrypt(block, key)
        plaintext_blocks.append(xor_bytes(decrypted, previous))
        previous = block
    plaintext = b"".join(plaintext_blocks)
    return pkcs7_unpad(plaintext, BLOCK_SIZE) if unpad else plaintext

def is_ecb(ciphertext: bytes, block_size: int = BLOCK_SIZE) -> bool:
    block_list = chunks(ciphertext, block_size)
    return len(block_list) != len(set(block_list))

def detect_block_size(oracle: Callable[[bytes], bytes]) -> int:
    baseline = len(oracle(b""))
    for extra in range(1, 256):
        candidate = len(oracle(b"A" * extra))
        if candidate > baseline:
            return candidate - baseline
    raise RuntimeError("failed to detect block size")

def detect_secret_length(
    oracle: Callable[[bytes], bytes],
    alignment_pad: int = 0,
    prefix_len: int = 0,
) -> int:
    block_size = detect_block_size(oracle)
    attacker_offset = prefix_len + alignment_pad
    baseline = len(oracle(b"A" * alignment_pad))
    for extra in range(1, block_size + 1):
        candidate = len(oracle(b"A" * (alignment_pad + extra)))
        if candidate > baseline:
            return baseline - attacker_offset - extra
    raise RuntimeError("failed to detect secret length")

def decrypt_ecb_suffix(
    oracle: Callable[[bytes], bytes],
    alignment_pad: int = 0,
    prefix_len: int = 0,
) -> bytes:
    block_size = detect_block_size(oracle)
    secret_len = detect_secret_length(oracle, alignment_pad=alignment_pad, prefix_len=prefix_len)
    recovered = bytearray()
    attacker_offset = prefix_len + alignment_pad

    for _ in range(secret_len):
        short_pad = block_size - 1 - (len(recovered) % block_size)
        probe_prefix = b"A" * (alignment_pad + short_pad)
        block_index = (attacker_offset + len(recovered)) // block_size
        start = block_index * block_size
        end = start + block_size
        target = oracle(probe_prefix)[start:end]

        dictionary: dict[bytes, int] = {}
        known = probe_prefix + recovered
        for candidate in range(256):
            probe = oracle(known + bytes([candidate]))
            dictionary[probe[start:end]] = candidate

        if target not in dictionary:
            raise RuntimeError("failed to recover the next secret byte")
        recovered.append(dictionary[target])
    return bytes(recovered)

def find_ecb_prefix_length(oracle: Callable[[bytes], bytes]) -> tuple[int, int]:
    block_size = detect_block_size(oracle)
    marker = b"B" * (block_size * 3)

    for pad in range(block_size):
        ciphertext = oracle(b"A" * pad + marker)
        block_list = chunks(ciphertext, block_size)
        for index in range(len(block_list) - 2):
            if block_list[index] == block_list[index + 1] == block_list[index + 2]:
                prefix_len = index * block_size - pad
                alignment_pad = (-prefix_len) % block_size
                return prefix_len, alignment_pad
    raise RuntimeError("failed to detect random prefix length")

def random_prefix_suffix() -> tuple[bytes, bytes]:
    return random_bytes(random.randint(5, 10)), random_bytes(random.randint(5, 10))
