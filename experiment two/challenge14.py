from __future__ import annotations
import random
from base64 import b64decode

from utils import (
    BLOCK_SIZE,
    aes_ecb_encrypt,
    decrypt_ecb_suffix,
    detect_block_size,
    find_ecb_prefix_length,
    is_ecb,
    pkcs7_pad,
    random_bytes,
)
UNKNOWN_SUFFIX_B64 = (
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
    "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
    "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
    "YnkK"
)
UNKNOWN_SUFFIX = b64decode(UNKNOWN_SUFFIX_B64)
class Oracle:
    def __init__(self) -> None:
        self.key = random_bytes(BLOCK_SIZE)
        self.prefix = random_bytes(random.randint(1, 64))
    def encrypt(self, attacker_input: bytes) -> bytes:
        payload = self.prefix + attacker_input + UNKNOWN_SUFFIX
        return aes_ecb_encrypt(pkcs7_pad(payload), self.key)
def solve() -> tuple[int, bytes]:
    oracle = Oracle()
    if detect_block_size(oracle.encrypt) != BLOCK_SIZE:
        raise AssertionError("unexpected block size")
    if not is_ecb(oracle.encrypt(b"A" * (BLOCK_SIZE * 8))):
        raise AssertionError("oracle is not ECB")
    prefix_len, alignment_pad = find_ecb_prefix_length(oracle.encrypt)
    plaintext = decrypt_ecb_suffix(oracle.encrypt, alignment_pad=alignment_pad, prefix_len=prefix_len)
    return prefix_len, plaintext
def main() -> None:
    prefix_len, plaintext = solve()
    print(f"Random prefix length: {prefix_len}")
    print(plaintext.decode("utf-8"))
if __name__ == "__main__":
    main()
