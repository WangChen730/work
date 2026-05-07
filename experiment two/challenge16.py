from __future__ import annotations
from utils import BLOCK_SIZE, aes_cbc_decrypt, aes_cbc_encrypt, random_bytes
class Oracle:
    PREFIX = b"comment1=cooking%20MCs;userdata="
    SUFFIX = b";comment2=%20like%20a%20pound%20of%20bacon"
    def __init__(self) -> None:
        self.key = random_bytes(BLOCK_SIZE)
        self.iv = random_bytes(BLOCK_SIZE)
    @staticmethod
    def sanitize(userdata: bytes) -> bytes:
        return userdata.replace(b";", b"").replace(b"=", b"")
    def encrypt(self, userdata: bytes) -> bytes:
        plaintext = self.PREFIX + self.sanitize(userdata) + self.SUFFIX
        return aes_cbc_encrypt(plaintext, self.key, self.iv)
    def is_admin(self, ciphertext: bytes) -> bool:
        plaintext = aes_cbc_decrypt(ciphertext, self.key, self.iv, unpad=True)
        return b";admin=true;" in plaintext
def forge_admin_ciphertext(oracle: Oracle) -> bytes:
    controlled = b"A" * BLOCK_SIZE
    ciphertext = bytearray(oracle.encrypt(controlled))
    desired = b";admin=true;AAAA"
    prefix_blocks = len(oracle.PREFIX) // BLOCK_SIZE
    previous_block_start = (prefix_blocks - 1) * BLOCK_SIZE
    for index, target_byte in enumerate(desired):
        ciphertext[previous_block_start + index] ^= ord("A") ^ target_byte
    return bytes(ciphertext)
def solve() -> bool:
    oracle = Oracle()
    forged = forge_admin_ciphertext(oracle)
    return oracle.is_admin(forged)
def main() -> None:
    print(solve())
if __name__ == "__main__":
    main()
