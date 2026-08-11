# 306 號房的菸味

> 喵上原市，某棟只租給獸人的老公寓。房東大谷応也把 306 號房五個住戶的
> 電子鎖密語，用自己寫的雜湊 `YaniHash-40` 存了起來——然後把種子寫在
> 牆上的便條紙，紙被ヤニ子拿去捲菸了。
>
> 他倒是還留著一份「預先算好的表」。他說那玩意兒他也看不懂。

## 附件

| 檔案 | 說明 |
|---|---|
| `yanihash.py` | `YaniHash-40` 完整原始碼。四顆種子 `K1..K4` 空著。 |
| `shadow.txt` | 五位住戶的密語雜湊（5 bytes / 40-bit，無 salt）。 |
| `nyan.tbl` | 房東那份「預先算好的表」。每行 `start<TAB>end`。 |
| `flag.enc` | 加密的 flag。 |

## 規格

**密語空間**：`CHARSET = "yaniko"`，長度 `PWLEN = @PWLEN@` → `6^@PWLEN@ = @N@`。

**`nyan.tbl`**：共 @NCHAINS@ 行，每行一條鏈的頭尾。鏈的定義是

```
CHAIN_LEN = @CHAIN_LEN@

pw_0     = start
pw_{i+1} = reduce_at( yani40(pw_i, K), i )    for i = 0, 1, ..., @LAST@
end      = pw_@CHAIN_LEN@
```

一條鏈共 @CHAIN_LEN@ 步、產生 `pw_0 .. pw_@CHAIN_LEN@` 這 @NPW@ 個密語，但檔案裡只存頭 (`pw_0`) 和尾 (`pw_@CHAIN_LEN@`)，中間 @NMID@ 個值沒有存。

> 驗證你猜的 `K` 時請**至少比對 3 條鏈**。單獨一條鏈只給約 20.7 bit 的約束，會出現大量偽陽性。

**`flag.enc`**：`tag(16) || ciphertext`

```python
key = sha256("|".join(五個明文, 依 shadow.txt 由上到下的順序)).digest()
tag = hmac_sha256(key, b"YANI-TAG" + ct)[:16]
pt  = ct XOR keystream,  keystream = sha256(key + b"YANI-CTR" + ctr_be32) 串接
```

## 房東的話

「那四個數字啊……都是門牌。這棟樓的門牌怎麼看，你瞧 306 就懂了，三樓六號。

前兩個是樓上那兩間長期空著的，三十三樓和三十四樓，都是 01 室。
後兩個嘛，我嫌一組數字太短不好記，就把那兩個門牌兜成一個，你來我往各兜一次。

順序我忘了。反正你要是填對了，那張表自己會告訴你。」
