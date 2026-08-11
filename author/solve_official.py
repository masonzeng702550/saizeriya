"""官方解 —— 只讀 dist/ 的檔案，模擬玩家視角。

Step 1  用 nyan.tbl 的任一條鏈當 oracle，還原 K1..K4（候選只有梗裡那幾個數字）
Step 2  標準彩虹表查詢還原五個明文（t^2/2 次雜湊，不是爆破 keyspace）
Step 3  解 flag.enc
"""

import hashlib
import hmac
import itertools
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.abspath(os.path.join(HERE, "..", "dist"))
sys.path.insert(0, DIST)

import yanihash as Y  # noqa: E402

CHAIN_LEN = 256

# 候選數字池 = 玩家從作品蒐集到的數字。
#   1) 命令列指定：solve_official.py N1 N2 N3 ... （從作品蒐集到的數字）
#   2) 否則讀 author/challenge_secrets.py 的 CANDIDATE_POOL
if len(sys.argv) > 1:
    POOL = [int(x, 0) for x in sys.argv[1:]]
else:
    sys.path.insert(0, HERE)
    from challenge_secrets import CANDIDATE_POOL as POOL  # noqa: E402

VERIFY_CHAINS = 3  # 單鏈僅 ~20.7 bit 約束，必須多鏈交叉驗證


def load_table():
    rows = []
    with open(os.path.join(DIST, "nyan.tbl")) as f:
        for line in f:
            s, e = line.rstrip("\n").split("\t")
            rows.append((s, e))
    return rows


def walk(pw, steps, K, i0=0):
    for i in range(i0, i0 + steps):
        pw = Y.reduce_at(Y.yani40(pw.encode(), K), i)
    return pw


def recover_K(rows):
    """用前 VERIFY_CHAINS 條鏈當 oracle。一條鏈只有 ~20.7 bit 約束，
    單鏈驗證會出現大量偽陽性（實測：2.7e8 候選撞出 64 個）。"""
    probes = rows[:VERIFY_CHAINS]
    tried = 0
    for K in itertools.permutations(POOL, 4):
        tried += 1
        if all(walk(s, CHAIN_LEN, K) == e for s, e in probes):
            return K, tried
    return None, tried


def lookup(h, rows, endmap, K):
    for j in range(CHAIN_LEN - 1, -1, -1):
        cand = Y.reduce_at(h, j)
        cand = walk(cand, CHAIN_LEN - 1 - j, K, j + 1)
        for c in endmap.get(cand, ()):
            pw = walk(rows[c][0], j, K)
            if Y.yani40(pw.encode(), K) == h:
                return pw
    return None


def keystream(key, n):
    out, ctr = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + b"YANI-CTR" + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:n]


def main():
    t0 = time.time()
    rows = load_table()
    print(f"[*] table: {len(rows)} chains")

    K, tried = recover_K(rows)
    assert K, "K not recovered"
    print(f"[+] K = {K}   (tried {tried} permutations, {time.time()-t0:.2f}s)")

    endmap = {}
    for i, (_, e) in enumerate(rows):
        endmap.setdefault(e, []).append(i)

    users, hashes = [], []
    with open(os.path.join(DIST, "shadow.txt")) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            u, hx = line.strip().split(":")
            users.append(u)
            hashes.append(bytes.fromhex(hx))

    plaintexts = []
    for u, h in zip(users, hashes):
        t1 = time.time()
        pw = lookup(h, rows, endmap, K)
        assert pw, f"lookup failed for {u}"
        plaintexts.append(pw)
        print(f"[+] {u:8s} {pw}   ({time.time()-t1:.2f}s)")

    key = hashlib.sha256("|".join(plaintexts).encode()).digest()
    blob = open(os.path.join(DIST, "flag.enc"), "rb").read()
    tag, ct = blob[:16], blob[16:]
    assert hmac.compare_digest(
        tag, hmac.new(key, b"YANI-TAG" + ct, hashlib.sha256).digest()[:16]
    ), "tag mismatch"
    flag = bytes(a ^ b for a, b in zip(ct, keystream(key, len(ct))))
    print(f"\n[FLAG] {flag.decode()}")
    print(f"[*] total {time.time()-t0:.2f}s")


if __name__ == "__main__":
    main()
