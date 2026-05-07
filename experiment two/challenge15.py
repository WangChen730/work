from __future__ import annotations
from utils import pkcs7_unpad
def solve() -> bytes:
    return pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04")
def main() -> None:
    print(solve().decode("utf-8"))
if __name__ == "__main__":
    main()
