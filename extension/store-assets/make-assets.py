#!/usr/bin/env python3
"""Build Chrome Web Store screenshots from the docs screenshots.

    python3 extension/store-assets/make-assets.py

The store accepts screenshots at EXACTLY 1280x800 or 640x400 and nothing else,
while the sources in docs/img are whatever size the window happened to be. This
letterboxes each one onto a 1280x800 canvas with a caption, rather than
stretching it — a distorted UI screenshot reads as a careless listing.

Sources are never modified. Re-run after replacing anything in docs/img.
"""
import pathlib
import sys

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 800
BG = (245, 247, 250)
INK = (17, 24, 39)
SUB = (100, 116, 139)
EDGE = (214, 221, 230)

MARGIN_X, TOP, BOTTOM = 90, 150, 70
MAX_UPSCALE = 1.6          # past this, a UI screenshot just looks soft

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = ROOT / "docs" / "img"
OUT = pathlib.Path(__file__).resolve().parent

# Order matters: this is the order they appear in the listing carousel. The
# store allows at most FIVE, so the four extension shots are the budget.
#
# crop is (top, bottom) in source pixels, or None for the whole image. The
# options page is 1560x1776 — letterboxing all of it onto a 1280x800 canvas
# shrinks it to a third of size and the body text stops being readable, so it is
# cropped to the part that carries the point.
SHOTS = [
    ("01-locked.png", "ext-popup-locked.png", None,
     "Protected sites stay dark", "The toolbar shows what this tab's state actually is"),
    ("02-unlocked.png", "ext-popup-unlocked.png", None,
     "One knock, and it opens", "No login form, no code to copy, nothing to click"),
    ("03-enroll.png", "ext-enroll.png", None,
     "You see exactly what you're granting", "Enrollment names the sites, and asks for those sites only"),
    ("04-options.png", "ext-options.png", (1098, 1750),
     "Manage this browser's enrolled devices", "Keys are stored non-extractable and are never synced"),
    # Server side, not the extension. Chrome asks that screenshots demonstrate
    # the extension itself, so these are built but prefixed as optional.
    ("optional-05-admin-overview.png", "plugin-overview.png", None,
     "Administrators issue device tokens", "Server-side UI — not part of the extension"),
    ("optional-06-admin-create.png", "plugin-create.png", None,
     "Each token names the sites it may open", "Server-side UI — not part of the extension"),
    ("optional-07-admin-link.png", "plugin-enroll-link.png", None,
     "Enrollment links carry a one-time code", "The secret is never in the link"),
]


def load_font(size, bold=False):
    names = (["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"] if bold
             else ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"])
    for n in names:
        for p in (pathlib.Path("C:/Windows/Fonts") / n, pathlib.Path("/usr/share/fonts/truetype/dejavu") / n):
            if p.exists():
                try:
                    return ImageFont.truetype(str(p), size)
                except OSError:
                    pass
    return None


def centered(draw, text, y, font, fill):
    if font is None:
        return
    w = draw.textbbox((0, 0), text, font=font)[2]
    draw.text(((W - w) // 2, y), text, font=font, fill=fill)


def build(out_name, src_name, crop, title, subtitle):
    src = SRC / src_name
    if not src.exists():
        print(f"  SKIP {out_name}: {src} not found")
        return False

    shot = Image.open(src).convert("RGB")
    if crop:
        top, bottom = crop
        shot = shot.crop((0, top, shot.width, min(bottom, shot.height)))
    box_w, box_h = W - 2 * MARGIN_X, H - TOP - BOTTOM
    scale = min(box_w / shot.width, box_h / shot.height, MAX_UPSCALE)
    new = (max(1, round(shot.width * scale)), max(1, round(shot.height * scale)))
    shot = shot.resize(new, Image.LANCZOS)

    canvas = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(canvas)
    centered(draw, title, 46, load_font(40, bold=True), INK)
    centered(draw, subtitle, 100, load_font(23), SUB)

    x = (W - shot.width) // 2
    y = TOP + (box_h - shot.height) // 2
    # Hairline so a white UI does not bleed into the canvas.
    draw.rectangle([x - 1, y - 1, x + shot.width, y + shot.height], outline=EDGE)
    canvas.paste(shot, (x, y))

    canvas.save(OUT / out_name, "PNG", optimize=True)
    print(f"  {out_name:34} <- {src_name:24} {new[0]}x{new[1]} @ {scale:.2f}x")
    return True


def main():
    if not SRC.exists():
        sys.exit(f"no source directory: {SRC}")
    print(f"building {W}x{H} store screenshots into {OUT}")
    made = sum(build(*s) for s in SHOTS)
    print(f"{made} screenshot(s) written")
    if load_font(40, bold=True) is None:
        print("NOTE: no TrueType font found — captions were omitted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
