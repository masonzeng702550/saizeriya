"""產生 dist/note.png 與 dist/note.txt —— 房東貼在牆上的便條紙。

功能性任務只有一個：**鎖定四顆常數的順序**（規則 C6），且不洩漏任何數值。
數值的位置被菸燒穿了，只剩標籤。

    python3 make_note.py

note.txt 是同內容的無障礙備援，兩者必須一致。
"""

import math
import os
import random

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(os.path.dirname(HERE), "dist")

FONT = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_L = "/System/Library/Fonts/STHeiti Light.ttc"

# 四個槽位：(標籤, 是誰, 哪個屬性)。順序即 K1..K4，這就是 C6。
SLOTS = [
    ("K1", "yaniko", "的年紀"),
    ("K2", "yakuko", "的年紀"),
    ("K3", "aruko", "的年紀"),
    ("K4", "hameko", "的訂閱數"),
]
EXCLUDED = "kaoruko"

W, H = 980, 700
PAPER = (232, 220, 190)
INK = (48, 42, 38)


def paper_bg(rng):
    img = Image.new("RGB", (W, H), PAPER)
    d = ImageDraw.Draw(img)
    # 紙纖維雜訊
    for _ in range(14000):
        x, y = rng.randrange(W), rng.randrange(H)
        v = rng.randint(-14, 10)
        p = img.getpixel((x, y))
        d.point((x, y), tuple(max(0, min(255, c + v)) for c in p))
    # 邊緣暈影（畫在 RGBA 疊層，否則 alpha 會被忽略而變成實心框）
    ov = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    od = ImageDraw.Draw(ov)
    for i in range(30):
        a = int(20 * (1 - i / 30))
        od.rectangle([i, i, W - 1 - i, H - 1 - i], outline=(92, 78, 58, a))
    img = Image.alpha_composite(img.convert("RGBA"), ov).convert("RGB")
    return img


def burn_hole(img, cx, cy, r, rng):
    """菸燙出來的洞：外圈焦黃、中圈焦黑、中心燒穿。"""
    ov = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(ov)
    layers = [
        (1.45, (166, 128, 78), 55),    # 焦黃暈
        (1.12, (108, 74, 44), 130),    # 焦褐
        (0.86, (54, 36, 24), 205),     # 焦黑
        (0.60, (24, 18, 14), 255),     # 燒穿
    ]
    for scale, rgb, alpha in layers:
        rr = r * scale
        pts = []
        n = 30
        for i in range(n):
            ang = 2 * math.pi * i / n
            j = 1 + rng.uniform(-0.13, 0.13)
            pts.append((cx + rr * j * math.cos(ang),
                        cy + rr * 0.82 * j * math.sin(ang)))
        d.polygon(pts, fill=rgb + (alpha,))
    ov = ov.filter(ImageFilter.GaussianBlur(2.2))
    img.paste(Image.alpha_composite(img.convert("RGBA"), ov).convert("RGB"), (0, 0))


def main():
    rng = random.Random(306)
    img = paper_bg(rng)
    d = ImageDraw.Draw(img)

    f_title = ImageFont.truetype(FONT, 46)
    f_memo = ImageFont.truetype(FONT_L, 26)
    f_key = ImageFont.truetype(FONT, 40)
    f_name = ImageFont.truetype(FONT, 40)
    f_attr = ImageFont.truetype(FONT_L, 34)
    f_foot = ImageFont.truetype(FONT_L, 28)

    d.text((72, 58), "電子鎖 種子", font=f_title, fill=INK)
    d.text((392, 74), "※ 別再忘了", font=f_memo, fill=(126, 66, 52))
    d.line([(72, 122), (W - 72, 122)], fill=(120, 104, 84), width=3)

    y = 176
    for tag, who, attr in SLOTS:
        d.text((84, y), tag, font=f_key, fill=(112, 66, 48))
        d.text((176, y), who, font=f_name, fill=INK)
        d.text((430, y + 6), attr, font=f_attr, fill=INK)
        # 數值原本寫在這條虛線上（燒痕只吃掉中段，兩端仍看得見）
        for x in range(636, 912, 16):
            d.line([(x, y + 46), (x + 9, y + 46)], fill=(120, 104, 84), width=2)
        y += 92

    d.line([(72, y + 18), (W - 72, y + 18)], fill=(120, 104, 84), width=3)
    d.text((84, y + 40), f"（沒有 {EXCLUDED}，那時還沒搬來）", font=f_foot, fill=(96, 84, 68))

    # 每一列的數值位置各燙一個洞
    for i in range(len(SLOTS)):
        burn_hole(img, 784 + rng.randint(-16, 16), 202 + i * 92, 44, rng)

    img = img.filter(ImageFilter.GaussianBlur(0.4))
    img = img.rotate(-0.7, resample=Image.BICUBIC, expand=False, fillcolor=PAPER)

    os.makedirs(DIST, exist_ok=True)
    img.save(os.path.join(DIST, "note.png"))

    lines = [
        "電子鎖 種子   ※ 別再忘了",
        "-" * 46,
    ]
    for tag, who, attr in SLOTS:
        lines.append(f"{tag}   {who:<10}{attr:<8}  [ 燒掉了 ]")
    lines += ["-" * 46, f"（沒有 {EXCLUDED}，那時還沒搬來）", ""]
    with open(os.path.join(DIST, "note.txt"), "w") as f:
        f.write("\n".join(lines))

    print(f"[+] {DIST}/note.png")
    print(f"[+] {DIST}/note.txt")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
