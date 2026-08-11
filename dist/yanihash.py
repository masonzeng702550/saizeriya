"""
YaniHash-40 —— 306 號房電子鎖用的自製雜湊。
(從房東的舊筆電裡撈出來的，程式碼是完整的，但那四顆種子他寫在便條紙上，紙不見了。)
"""

MASK = 0xFFFFFFFF
M40 = (1 << 40) - 1

CHARSET = "yaniko"
PWLEN = 12
N = len(CHARSET) ** PWLEN

RSTEP = 0x9E3779B9


# TODO: 這四個數字寫在 306 號房牆上的便條紙，房東說是「這棟樓的門牌」。
K1 = None
K2 = None
K3 = None
K4 = None


def rotl32(v, r):
    v &= MASK
    return ((v << r) | (v >> (32 - r))) & MASK


def yani40(msg: bytes, K) -> bytes:
    k1, k2, k3, k4 = K
    a = (k1 ^ 0x9E3779B9) & MASK
    b = (k2 + 0x85EBCA6B) & MASK
    c = (k3 ^ 0xC2B2AE35) & MASK
    d = (k4 + 0x27D4EB2F) & MASK
    for x in msg:
        a = ((a ^ x) * 0x01000193) & MASK
        b = rotl32(b + a, 13) ^ c
        c = (((c * 5 + 0xF00D) & MASK) ^ b) & MASK
        d = (rotl32(d ^ a, 7) + b) & MASK
        a = (a + d) & MASK
    for _ in range(4):
        a = ((a ^ (b >> 15)) * 0x2545F491) & MASK
        b = ((b ^ (c >> 13)) * 0x9E3779B1) & MASK
        c = ((c ^ (d >> 11)) * 0x85EBCA77) & MASK
        d = ((d ^ (a >> 16)) * 0xC2B2AE3D) & MASK
    v = (((a ^ c) << 32) | (b ^ d)) & 0xFFFFFFFFFFFFFFFF
    return v.to_bytes(8, "big")[3:]


def reduce_at(h: bytes, i: int) -> str:
    n = (int.from_bytes(h, "big") ^ ((i * RSTEP) & M40)) % N
    out = []
    for _ in range(PWLEN):
        out.append(CHARSET[n % 6])
        n //= 6
    return "".join(out)
