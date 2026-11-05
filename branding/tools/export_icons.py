#!/usr/bin/env python3
"""Genera los PNG y el .ico del icono de Cercano desde branding/logo/cercano-icon.svg.

Uso (desde la raíz del repo):
    pip install playwright pillow && playwright install chromium
    python3 branding/tools/export_icons.py

Solo exporta el icono (no usa fuentes). El wordmark se exporta desde el lienzo de
diseño porque depende de la fuente Manrope.
"""
import io
import pathlib
import sys

from PIL import Image
from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parents[1]
SVG = (ROOT / "logo" / "cercano-icon.svg").read_text(encoding="utf-8")
OUT = ROOT / "png"
SIZES = [16, 24, 32, 48, 64, 128, 256, 512, 1024]
ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]


def main() -> int:
    OUT.mkdir(exist_ok=True)
    frames = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for size in SIZES:
            page = browser.new_page(viewport={"width": size, "height": size}, device_scale_factor=1)
            html = (
                "<!doctype html><meta charset=utf-8>"
                "<style>html,body{margin:0;background:transparent}svg{display:block;width:%dpx;height:%dpx}</style>%s"
                % (size, size, SVG)
            )
            page.set_content(html)
            png = page.screenshot(omit_background=True, clip={"x": 0, "y": 0, "width": size, "height": size})
            (OUT / f"cercano-icon-{size}.png").write_bytes(png)
            frames[size] = Image.open(io.BytesIO(png)).convert("RGBA")
            page.close()
        browser.close()
    frames[256].save(OUT / "cercano-icon.ico", format="ICO", sizes=[(s, s) for s in ICO_SIZES], append_images=[])
    print("OK:", ", ".join(f"{s}px" for s in SIZES), "+ cercano-icon.ico")
    return 0


if __name__ == "__main__":
    sys.exit(main())
