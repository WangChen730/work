from __future__ import annotations
import random

from utils import BLOCK_SIZE, aes_cbc_encrypt, aes_ecb_encrypt, is_ecb, pkcs7_pad, random_bytes
def encryption_oracle(plaintext: bytes) -> tuple[str, bytes]:
    key = random_bytes(BLOCK_SIZE)
    prefix = random_bytes(random.randint(5, 10))
    suffix = random_bytes(random.randint(5, 10))
    payload = pkcs7_pad(prefix + plaintext + suffix)
    if random.choice([True, False]):
        return "ECB", aes_ecb_encrypt(payload, key)
    iv = random_bytes(BLOCK_SIZE)
    return "CBC", aes_cbc_encrypt(payload, key, iv, pad=False)
def detect_oracle_mode(ciphertext: bytes) -> str:
    return "ECB" if is_ecb(ciphertext) else "CBC"
def solve(trials: int = 100) -> int:
    correct = 0
    probe = b"A" * (BLOCK_SIZE * 8)
    for _ in range(trials):
        expected_mode, ciphertext = encryption_oracle(probe)
        if detect_oracle_mode(ciphertext) == expected_mode:
            correct += 1
    return correct
def main() -> None:
    correct = solve()
    print(f"{correct}/100 detections correct")
if __name__ == "__main__":
    main()
