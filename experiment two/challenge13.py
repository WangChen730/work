from __future__ import annotations
from utils import BLOCK_SIZE, aes_ecb_decrypt, aes_ecb_encrypt, pkcs7_pad, pkcs7_unpad, random_bytes
def parse_kv(encoded: str) -> dict[str, str]:
    pairs = (item.split("=", 1) for item in encoded.split("&"))
    return {key: value for key, value in pairs}
class Oracle:
    def __init__(self) -> None:
        self.key = random_bytes(BLOCK_SIZE)
    @staticmethod
    def profile_for(email: str) -> str:
        sanitized = email.replace("&", "").replace("=", "")
        return f"email={sanitized}&uid=10&role=user"

    def encrypt_profile(self, email: str) -> bytes:
        profile = self.profile_for(email).encode("latin1")
        return aes_ecb_encrypt(pkcs7_pad(profile), self.key)

    def decrypt_profile(self, ciphertext: bytes) -> dict[str, str]:
        profile = pkcs7_unpad(aes_ecb_decrypt(ciphertext, self.key)).decode("latin1")
        return parse_kv(profile)
def solve() -> dict[str, str]:
    oracle = Oracle()
    admin_block_email = "A" * 10 + "admin" + chr(11) * 11
    admin_block = oracle.encrypt_profile(admin_block_email)[BLOCK_SIZE:BLOCK_SIZE * 2]
    aligned_email = "A" * 13
    base_ciphertext = oracle.encrypt_profile(aligned_email)
    forged = base_ciphertext[:BLOCK_SIZE * 2] + admin_block
    return oracle.decrypt_profile(forged)
def main() -> None:
    print(solve())
if __name__ == "__main__":
    main()
