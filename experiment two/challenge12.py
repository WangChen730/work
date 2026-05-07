from __future__ import annotations
from base64 import b64decode

from utils import BLOCK_SIZE, aes_ecb_encrypt, decrypt_ecb_suffix, detect_block_size, is_ecb, pkcs7_pad, random_bytes
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
    def encrypt(self, attacker_input: bytes) -> bytes:
        return aes_ecb_encrypt(pkcs7_pad(attacker_input + UNKNOWN_SUFFIX), self.key)
def solve() -> bytes:
    oracle = Oracle()
    if detect_block_size(oracle.encrypt) != BLOCK_SIZE:
        raise AssertionError("unexpected block size")
    if not is_ecb(oracle.encrypt(b"A" * (BLOCK_SIZE * 4))):
        raise AssertionError("oracle is not ECB")
    return decrypt_ecb_suffix(oracle.encrypt)
def main() -> None:
    print(solve().decode("utf-8"))
if __name__ == "__main__":
    main()
