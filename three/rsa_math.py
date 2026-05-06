# 扩展欧几里得算法 EGCD
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
# 模逆元 invmod
def invmod(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('模逆元不存在，a和m不互质')
    else:
        return x % m