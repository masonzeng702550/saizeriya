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
python3 build.py                                       # 產 dist/
python3 solve_official.py                              # 驗收，應印出 flag
```

`check_constants.py` 自動檢查四顆種子是否落在可被暴力掃描覆蓋的範圍內，
以及是否可由題目內既有常數或角色名字的常見編碼導出。未通過不得出題。

## 正式規模建表

`build.py` 的內建建表器是純 Python，只適合 PoC 規模。正式參數
（`PWLEN=12, t=1024, m=2125764`）請用 C 版：

```bash
cc -O3 -pthread -o build_table build_table.c
./build_table --selftest                               # 與 Python 參考實作對拍
./build_table 12 1024 2125764 K1 K2 K3 K4 ../dist/nyan.tbl 12
```

實測（12 執行緒）：13.75 秒，158 MH/s，輸出 55.3 MB。

`build_table.c` 與 `author/yani_core.py` 位元級一致，`--selftest` 會印出
四組測試向量供對拍。

## 玩家附件

| 檔案 | 說明 |
|---|---|
| `README.md` | 題目敘述與格式規格 |
| `yanihash.py` | `YaniHash-40` 完整原始碼，`K1..K4` 留空 |
| `shadow.txt` | 五位住戶的密語雜湊 |
| `nyan.tbl` | 彩虹表，每行 `start<TAB>end` |
| `flag.enc` | `tag(16) \|\| ciphertext`，HMAC 自帶正確性驗證 |
| `note.png` | 便條紙（只寫標籤、不寫數值）— 待製作 |

## 注意

- `dist/` 目前是 PoC 規模（`PWLEN=8, t=256, m=6561`），出題前需以正式參數重建。
- 正式規模的 `nyan.tbl` 為 55 MB，若要進版控需改用 Git LFS。
