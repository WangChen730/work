import hashlib
import base64
from Crypto.Cipher import AES
ciphertext_b64 = (
    "9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jx"
    "aa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2N"
    "fNnWFBTXyf7SDI"
)
# 题目给的 MRZ，? 是丢失字符
mrz = "12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4"
def mrz_value(ch: str) -> int:
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "A" <= ch <= "Z":
        return ord(ch) - ord("A") + 10
    if ch == "<":
        return 0
    raise ValueError(f"invalid MRZ char: {ch}")
def check_digit(s: str) -> str:
    weights = [7, 3, 1]
    total = 0
    for i, ch in enumerate(s):
        total += mrz_value(ch) * weights[i % 3]
    return str(total % 10)
def set_odd_parity(block: bytes) -> bytes:
    out = bytearray()
    for b in block:
        x = b & 0xFE
        ones = bin(x).count("1")
        if ones % 2 == 0:
            x |= 1
        out.append(x)
    return bytes(out)
# 1. 补出丢失字符
missing = check_digit("111116")
full_mrz = mrz.replace("?", missing)
# 2. 构造 BAC 的 MRZ_info
# 文档号(9)+校验位(1) + 出生日期(6)+校验位(1) + 有效期(6)+校验位(1)
mrz_info = full_mrz[0:10] + full_mrz[13:20] + full_mrz[21:28]
# 3. Kseed = SHA1(MRZ_info) 前 16 字节
kseed = hashlib.sha1(mrz_info.encode("ascii")).digest()[:16]
# 4. KENC = SHA1(Kseed || 00000001) 前 16 字节，再做奇校验
d = hashlib.sha1(kseed + bytes.fromhex("00000001")).digest()
kenc = set_odd_parity(d[:8]) + set_odd_parity(d[8:16])
# 5. AES-128-CBC 解密，IV = 16 字节 0
ciphertext = base64.b64decode(ciphertext_b64)
cipher = AES.new(kenc, AES.MODE_CBC, iv=bytes(16))
plaintext = cipher.decrypt(ciphertext)
print("missing char =", missing)
print("full MRZ     =", full_mrz)
print("MRZ_info     =", mrz_info)
print("Kseed        =", kseed.hex())
print("KENC         =", kenc.hex())
print("plaintext    =", plaintext.decode("utf-8", errors="replace"))
