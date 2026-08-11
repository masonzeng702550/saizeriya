"""常數 K 的檢核器 —— 建題前必跑。

規則來源：隔離 agent 實測。C1/C2/C3/C4/C5 自動檢，C6 人工複核。

    python3 check_constants.py                 # 檢 challenge_secrets.py 的 K_TRUE
    python3 check_constants.py 11 22 33 44     # 只檢值域類規則（C3 仍讀 K_SOURCES）
    python3 check_constants.py --shapes        # 列出各種 K 形狀的攻擊成本對照表

C3 是這裡最重要的一條，也是 v1.1 被攻破的原因：攻擊者不需要知道常數的「值」，
只要知道它的「範圍」就能掃。因此安全性等於攻擊者未知部分的熵，而不是常數
本身有多大——C2 可以全過而 C3 全倒，v1.1 正是如此。
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

    ok &= check_c3()

    print("\n[MANUAL] C6  四顆的順序由 note.png 的標籤鎖定，不留排列不確定性")

    print(f"\n==> 自動檢核 {'全部通過' if ok else '未通過'}（C6 仍需人工複核）")
    return ok


def fmt_time(secs):
    if secs < 90:
        return f"{secs:.0f} 秒"
    if secs < 5400:
        return f"{secs/60:.0f} 分鐘"
    if secs < 172800:
        return f"{secs/3600:.1f} 小時"
    if secs < 3.15e7:
        return f"{secs/86400:.0f} 天"
    return f"{secs/3.15e7:.0f} 年"


def check_c3(sources=None):
    """C3 —— 攻擊者熵記帳。

    關鍵：攻擊者不需要知道某顆常數的「值」，只要知道它的「範圍」就能掃。
    把畫面數字丟進任何公式都不會增加熵——掃的是原像空間，不是常數空間。
    因此凡是能從附件推導出來的常數，對攻擊成本的貢獻是 1（零熵）。

    每顆常數宣告 (描述, 種類, 攻擊者需列舉的可能數)：
        public  附件內線索可推導            -> 1
        derived 由 public 經常見運算導出     -> 該運算池大小（通常 ~50）
        screen  只能從作品畫面取得           -> 該數值的合理範圍大小
    """
    if sources is None:
        try:
            sys.path.insert(0, HERE)
            from challenge_secrets import K_SOURCES as sources
        except ImportError:
            print("\n[FAIL] C3  challenge_secrets.py 未宣告 K_SOURCES —— 無法記帳")
            print("        每顆常數必須宣告 (描述, 種類, 攻擊者需列舉的可能數)")
            return False

    print("\n[----] C3  攻擊者熵記帳")
    cost = 1
    for desc, kind, space in sources:
        cost *= space
        print(f"        {desc:<28} {kind:<8} x{space:>12,}")
    bits = 0 if cost <= 1 else round(cost.bit_length() - 1 + 0.0, 1)
    r = cost > BUDGET
    print(f"[{'PASS' if r else 'FAIL'}] C3  攻擊者需列舉 {cost:.3e} 組 (~{bits} bit) > {BUDGET:.1e}")
    if not r:
        print(f"        以實測 154,000 次 K 測試/秒計，攻擊者約需 {fmt_time(cost / 154_000)}。")
        print("        提高熵的唯一方法是增加『附件推導不出來』的維度數或其範圍；")
        print("        把已知數字丟進公式沒有用。")
    return r


SHAPES = {
    "v1.1 現況 (3301,3401,串接,串接)": [("derived", 24)] * 4,
    "3301,3401 + 兩顆畫面四位數": [("public", 1), ("public", 1)] + [("screen", 10**4)] * 2,
    "3301,3401 + 兩顆畫面四位數再混公式": [("public", 1), ("public", 1)] + [("screen", 10**4)] * 2,
    "3301 + 三顆畫面四位數": [("public", 1)] + [("screen", 10**4)] * 3,
    "四顆都是畫面四位數": [("screen", 10**4)] * 4,
    "四顆都是畫面三位數": [("screen", 10**3)] * 4,
    "兩顆畫面七位數": [("public", 1), ("public", 1)] + [("screen", 10**7)] * 2,
}


def print_shapes():
    print(f"攻擊者預算牆 = {BUDGET:.1e} 組 K 測試（154,000 組/秒 實測）\n")
    print(f"{'形狀':<38} {'需列舉':>12}  {'時間':>12}  結果")
    print("-" * 78)
    for name, dims in SHAPES.items():
        cost = 1
        for _, space in dims:
            cost *= space
        print(f"{name:<38} {cost:>12.2e}  {fmt_time(cost/154_000):>12}  "
              f"{'PASS' if cost > BUDGET else 'FAIL'}")
    print("\n注意第 2 與第 3 列相同：把已知數字丟進任何公式都不會增加熵，")
    print("攻擊者掃的是原像空間，不是常數空間。")


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--shapes":
        print_shapes()
        return
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
