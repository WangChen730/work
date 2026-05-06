from rsa_core import generate_rsa_keys, rsa_encrypt, rsa_decrypt
from rsa_math import invmod
# 小素数RSA基础测试
def test_small_prime_rsa():
    # 更换p、q参数，确保φ(n)与e=3互质
    p_small = 59
    q_small = 53
    e = 3
    n_small = p_small * q_small
    phi_small = (p_small - 1) * (q_small - 1)
    d_small = invmod(e, phi_small)
    pub_key_small = (e, n_small)
    pri_key_small = (d_small, n_small)
    m_test = 42
    c_test = rsa_encrypt(m_test, pub_key_small)
    decrypted_test = rsa_decrypt(c_test, pri_key_small)
    assert decrypted_test == m_test, "小素数RSA加解密结果不一致"
    print(f"小素数测试通过：明文={m_test}, 密文={c_test}, 解密结果={decrypted_test}")
# 大素数RSA测试（固定e=3）
def test_big_prime_rsa():
    m_test = 42
    pub_key, pri_key, p_big, q_big = generate_rsa_keys(bits=16, e=3)
    c_big = rsa_encrypt(m_test, pub_key)
    decrypted_big = rsa_decrypt(c_big, pri_key)
    assert decrypted_big == m_test, "大素数RSA加解密结果不一致"
    print(f"大素数测试通过：p={p_big}, q={q_big}, 明文={m_test}, 密文={c_big}, 解密结果={decrypted_big}")
# 字符串加解密测试
def test_string_rsa():
    s = "Hello RSA!"
    m_str = int.from_bytes(s.encode('utf-8'), byteorder='big')
    pub_key_str, pri_key_str, _, _ = generate_rsa_keys(bits=64, e=3)
    e_str, n_str = pub_key_str
    assert m_str < n_str, "素数位数不足，n无法容纳字符串转换后的明文"
    c_str = rsa_encrypt(m_str, pub_key_str)
    decrypted_m_str = rsa_decrypt(c_str, pri_key_str)
    decrypted_s = decrypted_m_str.to_bytes((decrypted_m_str.bit_length() + 7) // 8, byteorder='big').decode('utf-8')
    assert decrypted_s == s, "字符串RSA加解密结果不一致"
    print(f"字符串测试通过：原始字符串={s}, 解密后字符串={decrypted_s}")
if __name__ == "__main__":
    test_small_prime_rsa()
    print("-" * 50)
    test_big_prime_rsa()
    print("-" * 50)
    test_string_rsa()
    print("\n所有测试全部通过！")