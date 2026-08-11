# room306 — 「306 號房的菸味」

THJCC 2026 Summer · Crypto · 離線題（無遠端靶機）

自製 40-bit 雜湊 `YaniHash-40` + 彩虹表。玩家拿到完整的雜湊原始碼，但四顆種子
`K1..K4` 空著；彩虹表是唯一能驗證種子猜測的管道。

## 目錄

```
author/     出題側工具（不隨題目發布給玩家）
dist/       ★ 發布給玩家的附件
```

## 環境需求

- Python 3.9+（僅用標準庫）
- C 編譯器（正式規模建表用）

## 建題

```bash
cd author
cp challenge_secrets.example.py challenge_secrets.py   # 填入 K_TRUE / CANDIDATE_POOL / FLAG
python3 check_constants.py                             # 常數檢核，必須全 PASS
python3 build.py prod                                  # 產 dist/（正式規模）
python3 solve_official.py                              # 驗收，應印出 flag
```

`build.py` 有兩種規模：

| mode | PWLEN | t | m | 表大小 | 建表 | 官方解 |
|---|---|---|---|---|---|---|
| `poc` (預設) | 8 | 256 | 6,561 | 118 KB | 17 s (Python) | 0.6 s |
| `prod` | 12 | 1024 | 2,125,764 | 55.3 MB | 13.8 s (C, 12 緒) | 21.1 s |

`prod` 會自動編譯並呼叫 `build_table`。官方解為純 CPython、零外部相依。

`check_constants.py` 自動檢查四顆種子是否落在可被暴力掃描覆蓋的範圍內，
以及是否可由題目內既有常數或角色名字的常見編碼導出。未通過不得出題。

## C 建表器

`build_table.c` 與 `author/yani_core.py` 位元級一致；`--selftest` 以中性種子
`(1,2,3,4)` 印出四組測試向量供對拍。也可獨立使用：

```bash
cc -O3 -pthread -o build_table build_table.c
./build_table --selftest
./build_table 12 1024 2125764 K1 K2 K3 K4 ../dist/nyan.tbl 12
```

## 玩家附件

| 檔案 | 說明 |
|---|---|
| `README.md` | 題目敘述與格式規格 |
| `yanihash.py` | `YaniHash-40` 完整原始碼，`K1..K4` 留空 |
| `shadow.txt` | 五位住戶的密語雜湊 |
| `nyan.tbl` | 彩虹表，每行 `start<TAB>end` |
| `flag.enc` | `tag(16) \|\| ciphertext`，HMAC 自帶正確性驗證 |
| `note.png` | 房東的便條紙，鎖定 K1–K4 的順序，數值被菸燙穿 |
| `note.txt` | 同上，純文字無障礙版（與 PNG 同一支腳本產生）|

`nyan.tbl` 不進版控：它由 `K` 與參數決定性產生，`build.py prod` 13.8 秒可重建。

## 注意

- 出題前必須跑 `check_constants.py`，未全 PASS 不得發布。
- 發布給玩家的是 `dist/` 整個目錄（含 55 MB 的 `nyan.tbl`），建議打包成 zip。
