"""建題腳本：產彩虹表、shadow、flag.enc，並輸出玩家用的 dist/。

    python3 build.py            # PoC 規模 (PWLEN=8,  t=256)，純 Python 建表
    python3 build.py prod       # 正式規模 (PWLEN=12, t=1024)，呼叫 ./build_table

正式規模的表有 2,125,764 條鏈、55.3 MB，純 Python 需 5.2 小時，
因此 prod 模式強制使用 C 建表器（12 緒實測 13.75 s）。
"""

import os
import random
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yani_core as C

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(os.path.dirname(HERE), "dist")

FLAG = C.FLAG  # 來自 challenge_secrets.py

# 306 號房五位住戶
RESIDENTS = ["yaniko", "yakuko", "hameko", "kaoruko", "aruko"]

PARAMS = {
    "poc": dict(PWLEN=8, CHAIN_LEN=256),
    "prod": dict(PWLEN=12, CHAIN_LEN=1024),
}


def apply_params(mode):
    p = PARAMS[mode]
    C.PWLEN = p["PWLEN"]
    C.N = len(C.CHARSET) ** C.PWLEN
    C.CHAIN_LEN = p["CHAIN_LEN"]
    if C.N % C.CHAIN_LEN:
        raise SystemExit(f"N={C.N} 不能被 t={C.CHAIN_LEN} 整除")
    C.NUM_CHAINS = C.N // C.CHAIN_LEN


def build_table_python():
    rows = []
    for c in range(C.NUM_CHAINS):
        start = C.idx_to_pw(c)
        rows.append((start, C.walk(start, C.CHAIN_LEN, C.K_TRUE, 0)))
        if c % 1000 == 0:
            print(f"  chain {c}/{C.NUM_CHAINS}", file=sys.stderr)
    with open(os.path.join(DIST, "nyan.tbl"), "w") as f:
        for s, e in rows:
            f.write(f"{s}\t{e}\n")


def build_table_c():
    exe = os.path.join(HERE, "build_table")
    if not os.path.exists(exe):
        print("[*] compiling build_table.c ...", file=sys.stderr)
        subprocess.run(
            ["cc", "-O3", "-pthread", "-o", exe, os.path.join(HERE, "build_table.c")],
            check=True,
        )
    subprocess.run(
        [exe, str(C.PWLEN), str(C.CHAIN_LEN), str(C.NUM_CHAINS)]
        + [str(k) for k in C.K_TRUE]
        + [os.path.join(DIST, "nyan.tbl"), str(os.cpu_count() or 4)],
        check=True,
    )


def pick_targets(rng):
    """挑 5 個保證被表覆蓋的明文：從隨機鏈的隨機位置 p (0<=p<=t-1) 取出。
    只需要鏈的起點，起點就是索引的 base-6 編碼，不必讀回整張表。"""
    out, used = [], set()
    while len(out) < len(RESIDENTS):
        c = rng.randrange(C.NUM_CHAINS)
        p = rng.randrange(C.CHAIN_LEN)
        pw = C.walk(C.idx_to_pw(c), p, C.K_TRUE, 0)
        if pw in used:
            continue
        used.add(pw)
        out.append((pw, c, p))
    return out


def render_readme(mode):
    tpl = open(os.path.join(HERE, "README.dist.md")).read()
    subs = {
        "@PWLEN@": str(C.PWLEN),
        "@N@": f"{C.N:,}",
        "@CHAIN_LEN@": str(C.CHAIN_LEN),
        "@LAST@": str(C.CHAIN_LEN - 1),
        "@NPW@": str(C.CHAIN_LEN + 1),
        "@NMID@": str(C.CHAIN_LEN - 1),
        "@NCHAINS@": f"{C.NUM_CHAINS:,}",
    }
    for k, v in subs.items():
        tpl = tpl.replace(k, v)
    leftover = re.findall(r"@[A-Z_]+@", tpl)
    if leftover:
        raise SystemExit(f"README 模板有未替換的佔位符: {sorted(set(leftover))}")
    with open(os.path.join(DIST, "README.md"), "w") as f:
        f.write(tpl)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "poc"
    if mode not in PARAMS:
        raise SystemExit(f"mode 必須是 {list(PARAMS)}")
    apply_params(mode)
    os.makedirs(DIST, exist_ok=True)

    print(
        f"[*] mode={mode}  PWLEN={C.PWLEN}  N=6^{C.PWLEN}={C.N:,}  "
        f"t={C.CHAIN_LEN}  m={C.NUM_CHAINS:,}",
        file=sys.stderr,
    )

    print("[*] building rainbow table ...", file=sys.stderr)
    (build_table_c if mode == "prod" else build_table_python)()

    print("[*] picking covered targets ...", file=sys.stderr)
    rng = random.Random(20260811)
    targets = pick_targets(rng)
    plaintexts = [t[0] for t in targets]

    with open(os.path.join(DIST, "shadow.txt"), "w") as f:
        f.write("# 306 號房 電子鎖 密語雜湊 (YaniHash-40)\n")
        f.write("# 格式: 住戶:hash(hex,5bytes)\n")
        for user, pw in zip(RESIDENTS, plaintexts):
            f.write(f"{user}:{C.yani40(pw.encode(), C.K_TRUE).hex()}\n")

    key = C.derive_key(plaintexts)
    with open(os.path.join(DIST, "flag.enc"), "wb") as f:
        f.write(C.seal(key, FLAG))

    with open(os.path.join(DIST, "yanihash.py"), "w") as f:
        f.write(build_player_source())

    render_readme(mode)

    with open(os.path.join(HERE, "ANSWERS.txt"), "w") as f:
        f.write(f"mode = {mode}  PWLEN={C.PWLEN} t={C.CHAIN_LEN} m={C.NUM_CHAINS}\n")
        f.write(f"K = {C.K_TRUE}\n")
        for user, (pw, c, p) in zip(RESIDENTS, targets):
            f.write(f"{user}: {pw}   (chain {c}, pos {p})\n")
        f.write(f"key = {key.hex()}\n")
        f.write(f"FLAG = {FLAG.decode()}\n")

    print(f"[+] dist ready: {DIST}", file=sys.stderr)
    for user, (pw, c, p) in zip(RESIDENTS, targets):
        print(f"    {user:8s} {pw}  chain={c} pos={p}", file=sys.stderr)


def build_player_source():
    return f'''"""
YaniHash-40 —— 306 號房電子鎖用的自製雜湊。
(從房東的舊筆電裡撈出來的，程式碼是完整的，但那四顆種子他寫在便條紙上，紙不見了。)
"""

MASK = 0xFFFFFFFF
M40 = (1 << 40) - 1

CHARSET = "yaniko"
PWLEN = {C.PWLEN}
N = len(CHARSET) ** PWLEN

RSTEP = 0x9E3779B9


# TODO: 這四個數字房東寫在便條紙上，紙不見了。
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
