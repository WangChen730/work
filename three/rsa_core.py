from rsa_math import invmod, egcd
from prime_generator import generate_prime

def generate_rsa_keys(bits=16, e=3):
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # 确保e和phi互质
        if egcd(e, phi)[0] == 1:
            break
    d = invmod(e, phi)
    return (e, n), (d, n), p, q
# RSA加密
def rsa_encrypt(m, public_key):
    e, n = public_key
    if m >= n:
        raise Exception('明文m必须小于n')
    return pow(m, e, n)
# RSA解密
def rsa_decrypt(c, private_key):
    d, n = private_key
    return pow(c, d, n)