"""複製成 challenge_secrets.py 並填入實際值。challenge_secrets.py 不進版控。

常數選擇必須通過 check_constants.py 的檢核，摘要：
  C1  至少兩顆 Ki > 65535
  C2  四元組不得落在任何 size <= 1e10 的小整數積空間內
  C3  至少一顆數值只能從作品畫面取得（維基／百科查不到）
  C4  不得等於 yanihash.py 內已出現的常數或其負值
  C5  不得是住戶／房東名字經常見編碼（pack/CRC32/FNV/djb2/MD5 前綴…）導出的值
  C6  順序由 note.png 的標籤鎖定
"""

K_TRUE = (0, 0, 0, 0)

CANDIDATE_POOL = ()

FLAG = b"THJCC{replace_me}"
