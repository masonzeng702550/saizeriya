"""官方解 / 驗收 —— 只讀 dist/ 的檔案，模擬玩家視角。

Step 1  從 dist/ 自我推導參數（PWLEN 讀 gen_table.py；m/TRUNC 讀表；t = N/m）
Step 2  用 3 條鏈驗證 K（單鏈只有 ~20.7 bit 約束，會有偽陽性）
Step 3  呼叫 ./solve_ref（C）做彩虹表查詢
Step 4  推導金鑰、驗 HMAC tag、解出 flag

    python3 solve_official.py                  # K 讀 challenge_secrets.py
    python3 solve_official.py 21 20 24 108000  # 或由命令列指定

v1.4 起查詢量約 2.6e9 次雜湊，CPython 需數小時，故重運算交給 solve_ref.c。
"""

import hashlib
import hmac
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.abspath(os.path.join(HERE, "..", "dist"))
sys.path.insert(0, DIST)

import gen_table as Y  # noqa: E402

VERIFY_CHAINS = 3


def idx_to_pw(idx):
    out = []
    for _ in range(Y.PWLEN):
        out.append(Y.CHARSET[idx % 6])
        idx //= 6
    return "".join(out)


def walk(pw, steps, K, i0=0):
    for i in range(i0, i0 + steps):
        pw = Y.reduce_at(Y.yani40(pw.encode(), K), i)
    return pw


def table_params():
    """參數全部來自 gen_table.py（玩家拿到的產表程式），並用檔案大小交叉驗證。"""
    m, t, trunc = Y.NUM_CHAINS, Y.CHAIN_LEN, Y.TRUNC
    want = (m * Y.ENDBITS + 7) // 8
    size = os.path.getsize(os.path.join(DIST, "nyan.tbl"))
    if size != want:
        raise SystemExit(f"表大小 {size} != ceil(m*{Y.ENDBITS}/8) = {want}")
    return m, t, trunc


def unpack_end(blob, c):
    bit = c * Y.ENDBITS
    byte = bit >> 3
    chunk = int.from_bytes(blob[byte:byte + 8].ljust(8, b"\0"), "little")
    return (chunk >> (bit & 7)) & ((1 << Y.ENDBITS) - 1)


def keystream(key, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + b"YANI-CTR" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def main():
    t0 = time.time()

    if len(sys.argv) > 1:
        K = tuple(int(x, 0) for x in sys.argv[1:5])
    else:
        sys.path.insert(0, HERE)
        from challenge_secrets import K_TRUE as K

    m, t, trunc = table_params()
    print(f"[*] PWLEN={Y.PWLEN}  N={Y.N:,}  m={m:,}  t={t}  TRUNC={trunc}")
    print(f"[*] 截斷造成的平均重複： {m / 6 ** trunc:.2f} 條鏈/桶")

    # --- 驗證 K：第 c 列的 start 是 idx_to_pw(c)，走 t 步應等於該列的截斷 endpoint
    blob = open(os.path.join(DIST, "nyan.tbl"), "rb").read()
    for c in range(VERIFY_CHAINS):
        got = Y.pw_to_val(walk(idx_to_pw(c), t, K))
        want = unpack_end(blob, c)
        if got != want:
            raise SystemExit(f"[!] K={K} 驗證失敗：chain {c} 得到 {got}，表上是 {want}")
    print(f"[+] K = {K} 通過 {VERIFY_CHAINS} 條鏈驗證  ({time.time()-t0:.2f}s)")

    # --- 讀 shadow
    users, hashes = [], []
    with open(os.path.join(DIST, "shadow.txt")) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            u, hx = line.strip().split(":")
            users.append(u)
            hashes.append(hx)

    # --- 呼叫 C 查詢器
    exe = os.path.join(HERE, "solve_ref")
    if not os.path.exists(exe) or os.path.getmtime(exe) < os.path.getmtime(
        os.path.join(HERE, "solve_ref.c")
    ):
        print("[*] compiling solve_ref.c ...")
        subprocess.run(
            ["cc", "-O3", "-pthread", "-o", exe, os.path.join(HERE, "solve_ref.c")],
            check=True,
        )
    t1 = time.time()
    res = subprocess.run(
        [exe, str(Y.PWLEN), str(trunc), str(t), str(m)]
        + [str(k) for k in K]
        + [os.path.join(DIST, "nyan.tbl")]
        + hashes
        + [str(os.cpu_count() or 4)],
        check=True,
        capture_output=True,
        text=True,
    )
    plaintexts = res.stdout.split()
    print(res.stderr.rstrip())
    if len(plaintexts) != len(users):
        raise SystemExit(f"[!] solve_ref 只回了 {len(plaintexts)} 個明文")
    print(f"[+] 5 個目標還原完成 ({time.time()-t1:.2f}s)")
    for u, pw in zip(users, plaintexts):
        print(f"    {u:8s} {pw}")

    # --- 解 flag
    key = hashlib.sha256("|".join(plaintexts).encode()).digest()
    blob = open(os.path.join(DIST, "flag.enc"), "rb").read()
    tag, ct = blob[:16], blob[16:]
    if not hmac.compare_digest(
        tag, hmac.new(key, b"YANI-TAG" + ct, hashlib.sha256).digest()[:16]
    ):
        raise SystemExit("[!] HMAC tag 不符")
    flag = bytes(a ^ b for a, b in zip(ct, keystream(key, len(ct))))
    print(f"\n[FLAG] {flag.decode()}")
    print(f"[*] total {time.time()-t0:.2f}s")


if __name__ == "__main__":
    main()
