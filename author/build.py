"""建題腳本：產彩虹表、shadow、flag.enc，並輸出玩家用的 dist/。"""

import os
import random
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yani_core as C

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(os.path.dirname(HERE), "dist")

FLAG = C.FLAG  # 來自 challenge_secrets.py

# 306 號房五位住戶
RESIDENTS = ["yaniko", "yakuko", "hameko", "kaoruko", "aruko"]


def build_table():
    """chain: pw_0 = start ; pw_{i+1} = R_i(H(pw_i)) ; end = pw_t"""
    rows = []
    for c in range(C.NUM_CHAINS):
        start = C.idx_to_pw(c)
        end = C.walk(start, C.CHAIN_LEN, C.K_TRUE, 0)
        rows.append((start, end))
        if c % 1000 == 0:
            print(f"  chain {c}/{C.NUM_CHAINS}", file=sys.stderr)
    return rows


def pick_targets(rows, rng):
    """挑 5 個保證被表覆蓋的明文：從隨機鏈的隨機位置 p (0<=p<=t-1) 取出。"""
    out = []
    used = set()
    while len(out) < len(RESIDENTS):
        c = rng.randrange(C.NUM_CHAINS)
        p = rng.randrange(C.CHAIN_LEN)
        pw = C.walk(rows[c][0], p, C.K_TRUE, 0)
        if pw in used:
            continue
        used.add(pw)
        out.append((pw, c, p))
    return out


def main():
    rng = random.Random(20260811)

    print("[*] building rainbow table ...", file=sys.stderr)
    rows = build_table()

    print("[*] picking covered targets ...", file=sys.stderr)
    targets = pick_targets(rows, rng)
    plaintexts = [t[0] for t in targets]

    os.makedirs(DIST, exist_ok=True)

    # nyan.tbl
    with open(os.path.join(DIST, "nyan.tbl"), "w") as f:
        for s, e in rows:
            f.write(f"{s}\t{e}\n")

    # shadow.txt
    with open(os.path.join(DIST, "shadow.txt"), "w") as f:
        f.write("# 306 號房 電子鎖 密語雜湊 (YaniHash-40)\n")
        f.write("# 格式: 住戶:hash(hex,5bytes)\n")
        for user, pw in zip(RESIDENTS, plaintexts):
            h = C.yani40(pw.encode(), C.K_TRUE)
            f.write(f"{user}:{h.hex()}\n")

    # flag.enc
    key = C.derive_key(plaintexts)
    with open(os.path.join(DIST, "flag.enc"), "wb") as f:
        f.write(C.seal(key, FLAG))

    # 玩家版 yanihash.py：K 挖空
    src = open(os.path.join(HERE, "yani_core.py")).read()
    player = build_player_source()
    with open(os.path.join(DIST, "yanihash.py"), "w") as f:
        f.write(player)

    shutil.copy(os.path.join(HERE, "README.dist.md"), os.path.join(DIST, "README.md"))

    # 作者紀錄（不進 dist）
    with open(os.path.join(HERE, "ANSWERS.txt"), "w") as f:
        f.write(f"K = {C.K_TRUE}\n")
        for user, (pw, c, p) in zip(RESIDENTS, targets):
            f.write(f"{user}: {pw}   (chain {c}, pos {p})\n")
        f.write(f"key = {key.hex()}\n")
        f.write(f"FLAG = {FLAG.decode()}\n")

    print(f"[+] dist ready: {DIST}", file=sys.stderr)
    for user, (pw, c, p) in zip(RESIDENTS, targets):
        print(f"    {user:8s} {pw}  chain={c} pos={p}", file=sys.stderr)


def build_player_source():
    return '''"""
YaniHash-40 —— 306 號房電子鎖用的自製雜湊。
(從房東的舊筆電裡撈出來的，程式碼是完整的，但那四顆種子他寫在便條紙上，紙不見了。)
"""

MASK = 0xFFFFFFFF
M40 = (1 << 40) - 1

CHARSET = "yaniko"
PWLEN = 8
N = len(CHARSET) ** PWLEN

RSTEP = 0x9E3779B9

# TODO: 這四個數字寫在 306 號房牆上的便條紙，房東說是「這棟樓的人」。
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
'''


if __name__ == "__main__":
    main()
