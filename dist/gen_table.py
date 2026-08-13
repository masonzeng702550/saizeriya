"""
房東的產表程式。

當年就是跑這支程式，產出 nyan.tbl、shadow.txt 和 flag.enc。
四顆種子他寫在便條紙上，紙被拿去捲菸了；flag.txt 也早就不在了。
"""

import hashlib
import hmac
import random

MASK = 0xFFFFFFFF
M40 = (1 << 40) - 1

CHARSET = "yaniko"
PWLEN = 14
N = len(CHARSET) ** PWLEN

CHAIN_LEN = 16384
NUM_CHAINS = N // CHAIN_LEN
TRUNC = 8

RSTEP = 0x9E3779B9

RESIDENTS = ["yaniko", "yakuko", "hameko", "kaoruko", "aruko"]

# TODO: 這四個數字寫在便條紙上，紙不見了。
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


def idx_to_pw(idx: int) -> str:
    out = []
    for _ in range(PWLEN):
        out.append(CHARSET[idx % 6])
        idx //= 6
    return "".join(out)


def walk(pw: str, steps: int, K, i0: int = 0) -> str:
    for i in range(i0, i0 + steps):
        pw = reduce_at(yani40(pw.encode(), K), i)
    return pw


def build_table(K, path="nyan.tbl"):
    with open(path, "w") as f:
        for c in range(NUM_CHAINS):
            f.write(walk(idx_to_pw(c), CHAIN_LEN, K)[:TRUNC] + "\n")


def pick_targets(K, rng):
    out, used = [], set()
    while len(out) < len(RESIDENTS):
        pw = walk(idx_to_pw(rng.randrange(NUM_CHAINS)),
                  rng.randrange(CHAIN_LEN), K)
        if pw not in used:
            used.add(pw)
            out.append(pw)
    return out


def keystream(key: bytes, n: int) -> bytes:
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + b"YANI-CTR" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def seal(key: bytes, plaintext: bytes) -> bytes:
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream(key, len(plaintext))))
    tag = hmac.new(key, b"YANI-TAG" + ct, hashlib.sha256).digest()[:16]
    return tag + ct


def main():
    K = (K1, K2, K3, K4)
    build_table(K)

    plaintexts = pick_targets(K, random.Random())
    with open("shadow.txt", "w") as f:
        f.write("# 306 號房 電子鎖 密語雜湊 (YaniHash-40)\n")
        f.write("# 格式: 住戶:hash(hex,5bytes)\n")
        for user, pw in zip(RESIDENTS, plaintexts):
            f.write(f"{user}:{yani40(pw.encode(), K).hex()}\n")

    key = hashlib.sha256("|".join(plaintexts).encode()).digest()
    with open("flag.enc", "wb") as f:
        f.write(seal(key, open("flag.txt", "rb").read().strip()))


if __name__ == "__main__":
    main()
