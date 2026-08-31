#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import cairosvg

ROOT = Path(__file__).resolve().parents[1]
BRAND = ROOT / "brand"
SITE = ROOT / "site"


def main() -> None:
    outputs: list[dict[str, object]] = []
    for svg in sorted(BRAND.glob("*.svg")):
        png = svg.with_suffix(".png")
        cairosvg.svg2png(url=str(svg), write_to=str(png), output_width=None, output_height=None)
        outputs.append({"source": str(svg.relative_to(ROOT)), "output": str(png.relative_to(ROOT)), "bytes": png.stat().st_size})
    social_source = SITE / "og-card.svg"
    social_output = SITE / "og-card.png"
    cairosvg.svg2png(
        url=str(social_source),
        write_to=str(social_output),
        output_width=1200,
        output_height=630,
    )
    outputs.append(
        {
            "source": str(social_source.relative_to(ROOT)),
            "output": str(social_output.relative_to(ROOT)),
            "bytes": social_output.stat().st_size,
        }
    )
    manifest = BRAND / "render-manifest.json"
    manifest.write_text(json.dumps(outputs, indent=2) + "\n", encoding="utf-8")
    print(f"rendered {len(outputs)} brand assets")
    for item in outputs:
        print(f"  {item['output']} ({item['bytes']:,} bytes)")


if __name__ == "__main__":
    main()
