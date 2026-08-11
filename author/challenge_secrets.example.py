"""複製成 challenge_secrets.py 並填入實際值。challenge_secrets.py 不進版控。

常數選擇必須通過 check_constants.py，未全 PASS 不得出題：

  C1  至少一顆 Ki >= 2^24
  C2  最小包圍盒 prod(Ki+1) > 1.3e14
  C3  ★ 攻擊者熵記帳 > 1.3e14 —— 由 K_SOURCES 宣告，見下
  C4  不得等於 yanihash.py 內已出現的常數或其負值
  C5  不得由住戶／房東名字經常見編碼導出
  C6  順序由 note.png 的標籤鎖定（人工複核）

C3 是最重要的一條。攻擊者不需要知道常數的「值」，只要知道它的「範圍」
就能掃；把已知數字丟進任何公式都不會增加熵，因為掃的是原像空間。
v1.1 的 (3301, 3401, 33013401, 34013301) C1/C2/C4/C5 全過但 C3 慘敗
（攻擊者只需列舉 3.3e5 組 = 2 秒），兩隻隔離 agent 分別在 6 分鐘與
105 秒內攻破。

跑 `python3 check_constants.py --shapes` 看各種形狀的成本對照。
目前唯一 PASS 的形狀是「四顆都是只能從作品畫面取得的四位數」。
"""

K_TRUE = (0, 0, 0, 0)

# (描述, 種類, 攻擊者需列舉的可能數)
#   public  = 附件內線索可推導            -> 1
#   derived = 由 public 經常見運算導出     -> 該運算池大小（通常 ~24-50）
#   screen  = 只能從作品畫面取得           -> 該數值的合理範圍大小
K_SOURCES = (
    ("", "screen", 10**4),
    ("", "screen", 10**4),
    ("", "screen", 10**4),
    ("", "screen", 10**4),
)

CANDIDATE_POOL = ()

FLAG = b"THJCC{replace_me}"
