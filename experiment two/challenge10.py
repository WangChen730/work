from __future__ import annotations
from base64 import b64decode
from pathlib import Path

from utils import BLOCK_SIZE, aes_cbc_decrypt
def input_path() -> Path:
    return Path(__file__).parent / "inputs" / "10.txt"
def solve() -> bytes:
    ciphertext = b64decode(input_path().read_text(encoding="ascii"))
    key = b"YELLOW SUBMARINE"
    iv = bytes(BLOCK_SIZE)
    return aes_cbc_decrypt(ciphertext, key, iv, unpad=True)
def main() -> None:
    print(solve().decode("utf-8"))
if __name__ == "__main__":
    main()
