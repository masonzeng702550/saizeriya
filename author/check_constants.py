"""常數 K 的檢核器 —— 建題前必跑。

規則來源：隔離 agent 實測。C1/C2/C4/C5 自動檢，C3/C6 人工複核。

    python3 check_constants.py                 # 檢 challenge_secrets.py 的 K_TRUE
    python3 check_constants.py 11 22 33 44
"""

import hashlib
import os
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
M32 = 0xFFFFFFFF

# 攻擊者預算牆（推導，取代早期「兩顆 > 65535」的粗略啟發式）：
#   一次 K 測試 = t 次雜湊（正式參數 t = 1024）
#   實測 build_table.c：158 MH/s @ 12 緒  ->  154k K-tests/s
#   假想攻擊者：100 倍硬體 × 24 小時      ->  1.33e12 K-tests
#   安全係數 100 倍                        ->  牆設在 1.3e14
BUDGET = 13 * 10**13

# C1：至少一顆 Ki 必須大到讓「等寬方盒掃描」直接失效。
BIG_MIN = 1 << 24

# C4：yanihash.py 內出現過的所有常數
FILE_CONSTS = [
    0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F, 0x01000193, 0xF00D,
    0x2545F491, 0x9E3779B1, 0x85EBCA77, 0xC2B2AE3D,
    5, 7, 11, 13, 15, 16, 6, 8, 12, 40, 32, 256, 306, M32,
]

# C5：主題字串
NAMES = [
    "yaniko", "yakuko", "hameko", "kaoruko", "aruko", "yani", "yaku", "hame",
    "kaor", "nyan", "ooya", "ouya", "otani", "ootani", "neko", "306",
    "yanineko", "nikoyani", "satou", "sato",
]


def enc_variants(s: str):
    """名字 -> 32-bit 值的常見編碼（與 Agent B 掃過的集合對齊）。"""
    b = s.encode()
    out = {}
    if len(b) >= 4:
        out["pack_be"] = int.from_bytes(b[:4], "big")
        out["pack_le"] = int.from_bytes(b[:4], "little")
    out["ordsum"] = sum(b) & M32
    out["crc32"] = zlib.crc32(b) & M32
    out["adler32"] = zlib.adler32(b) & M32
    h = 0x811C9DC5
    for x in b:
        h = ((h ^ x) * 0x01000193) & M32
    out["fnv1a"] = h
    h = 5381
    for x in b:
        h = (h * 33 + x) & M32
    out["djb2"] = h
    h = 0
    for x in b:
        h = (x + (h << 6) + (h << 16) - h) & M32
    out["sdbm"] = h
    for name, fn in (("md5", hashlib.md5), ("sha1", hashlib.sha1),
                     ("sha256", hashlib.sha256), ("sha512", hashlib.sha512)):
        d = fn(b).digest()
        out[name + "_be"] = int.from_bytes(d[:4], "big")
        out[name + "_le"] = int.from_bytes(d[:4], "little")
    return out


def check(K):
    ok = True
    print(f"K = {tuple(K)}")
    print(f"    hex = {tuple(hex(k) for k in K)}\n")

    # C1
    big = [k for k in K if k >= BIG_MIN]
    r = len(big) >= 1
    ok &= r
    print(f"[{'PASS' if r else 'FAIL'}] C1  至少一顆 >= 2^24 —— 實際 {len(big)} 顆 {big}")
    if not r:
        print("        依據：Agent B 兩次窮盡 0..127^4。等寬方盒掃描必須直接失效。")

    # C2
    vol = 1
    for k in K:
        vol *= (k + 1)
    r = vol > BUDGET
    ok &= r
    print(f"[{'PASS' if r else 'FAIL'}] C2  最小包圍盒 prod(Ki+1) = {vol:.3e} > {BUDGET:.1e}")
    if not r:
        print(f"        依據：攻擊者可對 [0,Ki] 逐維設不同上界，成本僅 {vol:.3e} 組。")
    box = (max(K) + 1) ** 4
    print(f"        (等寬盒 (max+1)^4 = {box:.3e}；牆 = 154k K-tests/s × 100x硬體 × 24h × 100x安全係數)")

    # C4
    bad = [k for k in K if k in FILE_CONSTS or ((-k) & M32) in FILE_CONSTS]
    r = not bad
    ok &= r
    print(f"[{'PASS' if r else 'FAIL'}] C4  不得等於 yanihash.py 內常數或其負值 —— 命中 {bad}")

    # C5
    hits = []
    for n in NAMES:
        for tag, v in enc_variants(n).items():
            if v in K:
                hits.append(f"{n}/{tag}={v}")
    r = not hits
    ok &= r
    print(f"[{'PASS' if r else 'FAIL'}] C5  不得由名字經常見編碼導出 —— 命中 {hits}")

    print("\n[MANUAL] C3  至少一顆數值只能從作品畫面取得（維基／百科／文字資料庫查不到）")
    print("             → 對每顆 Ki 實際搜尋一次，確認至少一顆搜不到。")
    print("[MANUAL] C6  四顆的順序由 note.png 的標籤鎖定，不留排列不確定性")

    print(f"\n==> 自動檢核 {'全部通過' if ok else '未通過'}（C3/C6 仍需人工複核）")
    return ok


def main():
    if len(sys.argv) > 1:
        K = [int(x, 0) for x in sys.argv[1:]]
    else:
        sys.path.insert(0, HERE)
        from challenge_secrets import K_TRUE as K
    if len(K) != 4:
        raise SystemExit("K 必須是四個整數")
    sys.exit(0 if check(list(K)) else 1)


if __name__ == "__main__":
    main()
