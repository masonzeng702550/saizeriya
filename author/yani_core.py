"""
YaniHash-40 / 彩虹表核心 —— 作者側參考實作。

v1.5 的三項改動（C/D/E）：
  C  表改 bit-packed 二進位：每列 ENDBITS bits，不再是純文字
  D  reduce_at 改掉 `h ^ (i * GOLDEN)` 這種教科書寫法
  E  yani40 的訊息迴圈跑 PASSES 遍 —— 暴力成本 ×PASSES

參數（PoC 規模）:
    CHARSET = "yaniko"   (6)
    PWLEN   = 8          -> N = 6^8 = 1,679,616
    t       = 256
    m       = N / t = 6561
    TRUNC   = 4          -> ENDBITS = 11
"""

import hashlib
import hmac

MASK = 0xFFFFFFFF
M40 = (1 << 40) - 1

CHARSET = "yaniko"
PWLEN = 8
N = len(CHARSET) ** PWLEN

CHAIN_LEN = 256
NUM_CHAINS = N // CHAIN_LEN
TRUNC = 4

# E：訊息迴圈的遍數。暴力枚舉整個密語空間的成本正比於此。
PASSES = 3

# D：reduce_at 的混合常數（公開，與 K 無關）
RMIX1 = 0x5851F42D4C95
RMIX2 = 0xF1357AEA2E63

# ---- 梗常數 --------------------------------------------------------------
# 真值放在 challenge_secrets.py（不進版控）。
# 複製 challenge_secrets.example.py 並填入。
try:
    from challenge_secrets import K_TRUE, CANDIDATE_POOL, FLAG  # noqa: F401
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "缺少 author/challenge_secrets.py — 請 "
        "cp challenge_secrets.example.py challenge_secrets.py 並填入 "
        "K_TRUE / CANDIDATE_POOL / FLAG"
    ) from exc
# -----------------------------------------------------------------------------


def end_bits(trunc=None):
    """截斷 endpoint 需要幾個 bit。"""
    return (6 ** (TRUNC if trunc is None else trunc) - 1).bit_length()


def rotl32(v, r):
    v &= MASK
    return ((v << r) | (v >> (32 - r))) & MASK


def yani40(msg: bytes, K) -> bytes:
    """自創 40-bit 雜湊。四個 K 從第一個 byte 起就全部參與混合，
    無法逐個常數分治驗證。訊息迴圈跑 PASSES 遍。"""
    k1, k2, k3, k4 = K
    a = (k1 ^ 0x9E3779B9) & MASK
    b = (k2 + 0x85EBCA6B) & MASK
    c = (k3 ^ 0xC2B2AE35) & MASK
    d = (k4 + 0x27D4EB2F) & MASK
    for p in range(PASSES):
        for x in msg:
            a = ((a ^ x) * 0x01000193) & MASK
            b = rotl32(b + a, 13) ^ c
            c = (((c * 5 + 0xF00D) & MASK) ^ b) & MASK
            d = (rotl32(d ^ a, 7) + b) & MASK
            a = (a + d) & MASK
        a = (a ^ (p * 0x7FEB352D)) & MASK
    for _ in range(4):
        a = ((a ^ (b >> 15)) * 0x2545F491) & MASK
        b = ((b ^ (c >> 13)) * 0x9E3779B1) & MASK
        c = ((c ^ (d >> 11)) * 0x85EBCA77) & MASK
        d = ((d ^ (a >> 16)) * 0xC2B2AE3D) & MASK
    v = (((a ^ c) << 32) | (b ^ d)) & 0xFFFFFFFFFFFFFFFF
    return v.to_bytes(8, "big")[3:]  # 低 40 bits


def reduce_at(h: bytes, i: int) -> str:
    """index-dependent reduction。寫成與 i 無關是經典錯誤，
    且錯了不會報錯、只會永遠對不上 endpoint。"""
    x = int.from_bytes(h, "big")
    x = (x + i * RMIX1) & M40
    x = ((x << 21) | (x >> 19)) & M40
    x = (x * RMIX2) & M40
    x ^= x >> 23
    n = x % N
    out = []
    for _ in range(PWLEN):
        out.append(CHARSET[n % 6])
        n //= 6
    return "".join(out)


def walk(start: str, steps: int, K, start_index: int = 0) -> str:
    pw = start
    for i in range(start_index, start_index + steps):
        pw = reduce_at(yani40(pw.encode(), K), i)
    return pw


def idx_to_pw(idx: int) -> str:
    out = []
    for _ in range(PWLEN):
        out.append(CHARSET[idx % 6])
        idx //= 6
    return "".join(out)


def pw_to_val(pw: str, trunc=None) -> int:
    """截斷 endpoint -> 整數（base-6 小端，pw[0] 是最低位）。"""
    t = TRUNC if trunc is None else trunc
    v, p = 0, 1
    for k in range(t):
        v += CHARSET.index(pw[k]) * p
        p *= 6
    return v


def pack_ends(vals, nbits) -> bytes:
    """C：把每列 nbits bits 緊密打包成位元流（低位在前）。"""
    buf = bytearray()
    acc = 0
    n = 0
    for v in vals:
        acc |= v << n
        n += nbits
        while n >= 8:
            buf.append(acc & 0xFF)
            acc >>= 8
            n -= 8
    if n:
        buf.append(acc & 0xFF)
    return bytes(buf)


def unpack_end(blob: bytes, c: int, nbits: int) -> int:
    bit = c * nbits
    byte = bit >> 3
    chunk = int.from_bytes(blob[byte:byte + 8].ljust(8, b"\0"), "little")
    return (chunk >> (bit & 7)) & ((1 << nbits) - 1)


# ---- flag 容器：純 hashlib，零外部相依 --------------------------------------

def derive_key(plaintexts) -> bytes:
    return hashlib.sha256("|".join(plaintexts).encode()).digest()


def keystream(key: bytes, n: int) -> bytes:
    out = b""
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + b"YANI-CTR" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def seal(key: bytes, plaintext: bytes) -> bytes:
    ct = bytes(a ^ b for a, b in zip(plaintext, keystream(key, len(plaintext))))
    tag = hmac.new(key, b"YANI-TAG" + ct, hashlib.sha256).digest()[:16]
    return tag + ct


def unseal(key: bytes, blob: bytes):
    tag, ct = blob[:16], blob[16:]
    want = hmac.new(key, b"YANI-TAG" + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, want):
        return None
    return bytes(a ^ b for a, b in zip(ct, keystream(key, len(ct))))
