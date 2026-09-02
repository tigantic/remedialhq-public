#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "artifacts/launch"
WIDTH, HEIGHT, FPS = 1080, 1920, 30
BG = "#050706"
SURFACE = "#111713"
TEXT = "#F2F7F3"
MUTED = "#829087"
ACCENT = "#B8FF3D"
CYAN = "#2FD7FF"
AMBER = "#FFB020"
VIOLET = "#A58BFF"


def font(
    size: int, bold: bool = False
) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size=size)
    return ImageFont.load_default()


def wrapped(
    draw: ImageDraw.ImageDraw,
    text: str,
    fnt: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    width: int,
) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        test = f"{current} {word}".strip()
        if draw.textbbox((0, 0), test, font=fnt)[2] <= width:
            current = test
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


def center_text(
    draw: ImageDraw.ImageDraw,
    y: int,
    text: str,
    fnt: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    fill: str,
    max_width: int = 880,
    gap: int = 15,
) -> int:
    lines = wrapped(draw, text, fnt, max_width)
    for line in lines:
        box = draw.textbbox((0, 0), line, font=fnt)
        draw.text(((WIDTH - (box[2] - box[0])) / 2, y), line, font=fnt, fill=fill)
        y += int(box[3] - box[1] + gap)
    return y


def base_frame() -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    for x in range(0, WIDTH, 54):
        draw.line((x, 0, x, HEIGHT), fill="#111812", width=1)
    for y in range(0, HEIGHT, 54):
        draw.line((0, y, WIDTH, y), fill="#111812", width=1)
    draw.rounded_rectangle((160, 130, 920, 214), radius=42, fill="#18221A")
    label = "REMEDIAL HQ"
    lf = font(34, True)
    box = draw.textbbox((0, 0), label, font=lf)
    draw.text(((WIDTH - (box[2]-box[0]))/2, 154), label, font=lf, fill=ACCENT)
    draw.text((130, 1780), "SIGNAL OVER HYPE.  ·  INDEPENDENT EDITORIAL", font=font(25, True), fill=MUTED)
    draw.line((130, 1740, 950, 1740), fill="#29342B", width=2)
    return image, draw


def save_scene(path: Path, kicker: str, hero: str, sub: str, color: str = ACCENT, pills: list[tuple[str, str]] | None = None) -> None:
    image, draw = base_frame()
    center_text(draw, 405, kicker.upper(), font(39, True), MUTED)
    hero_font = font(150 if len(hero) <= 8 else 104, True)
    y = center_text(draw, 585, hero, hero_font, color, 920, 10)
    y = max(y + 65, 920)
    center_text(draw, y, sub, font(50, True), TEXT, 870, 22)
    if pills:
        py = 1390
        total = len(pills)
        gap = 18
        pill_width = min(240, (820 - gap * (total - 1)) // total)
        start = (WIDTH - (pill_width * total + gap * (total - 1))) // 2
        for index, (label, pill_color) in enumerate(pills):
            x = start + index * (pill_width + gap)
            draw.rounded_rectangle((x, py, x + pill_width, py + 70), radius=35, fill=SURFACE, outline=pill_color, width=3)
            pf = font(22, True)
            box = draw.textbbox((0, 0), label, font=pf)
            draw.text((x + (pill_width - (box[2]-box[0]))/2, py + 22), label, font=pf, fill=pill_color)
    path.parent.mkdir(parents=True, exist_ok=True)
    image.save(path, optimize=True)


def run(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main() -> None:
    if shutil.which("ffmpeg") is None:
        raise SystemExit("ffmpeg is required")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    scenes = [
        (
            "THE COUNTDOWN",
            "82 DAYS",
            "Until GTA VI's currently scheduled November 19 launch.",
            ACCENT,
            None,
            ["CLM-0001", "CLM-0015"],
        ),
        (
            "CURRENT DEMAND",
            "~21M",
            "Provider estimate of monthly searches for GTA 6 - rounded, not audited.",
            ACCENT,
            None,
            ["CLM-0014"],
        ),
        (
            "THE DISTORTION",
            "STATE ≠ CERTAINTY",
            "Official material can show behavior without confirming final mechanics.",
            AMBER,
            None,
            ["CLM-0006", "CLM-0007"],
        ),
        ("THE PROBLEM", "HYPE ≠ FACT", "Keep confirmed, observed, reported, and inferred claims visibly separate.", TEXT, None, []),
        ("THE METHOD", "CLAIM STATES", "Every factual line is bound to reviewed evidence.", CYAN, [("CONFIRMED", ACCENT), ("OBSERVED", CYAN)], []),
        ("ATTRIBUTED", "REPORTED", "Third-party claims stay attributed; inference stays labeled.", AMBER, [("REPORTED", AMBER), ("INFERRED", VIOLET)], []),
        ("THE BOUNDARY", "NO LEAKS", "No stolen builds. No trailer dumps. No fake certainty.", "#FF5A63", None, ["CLM-0010", "CLM-0011"]),
        ("THE PRODUCT", "LIVING LEDGER", "Sources, claim states, and visible corrections.", ACCENT, None, []),
        ("SUBSCRIBE", "BUILD THE RECORD", "Before the hype becomes history.", ACCENT, None, []),
    ]
    storyboard = []
    frames_dir = OUT_DIR / "frames"
    if frames_dir.exists():
        shutil.rmtree(frames_dir)
    frames_dir.mkdir(parents=True, exist_ok=True)
    scene_images: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)
        clip_paths: list[Path] = []
        for index, scene in enumerate(scenes, 1):
            png = temp / f"scene-{index:02d}.png"
            save_scene(png, *scene[:5])
            retained = frames_dir / f"scene-{index:02d}.png"
            shutil.copy2(png, retained)
            scene_images.append(retained)
            clip = temp / f"clip-{index:02d}.mp4"
            run([
                "ffmpeg", "-y", "-loop", "1", "-framerate", str(FPS), "-i", str(png), "-t", "4",
                "-vf", f"scale={WIDTH}:{HEIGHT},fade=t=in:st=0:d=0.22,fade=t=out:st=3.78:d=0.22",
                "-an", "-c:v", "libx264", "-preset", "ultrafast", "-crf", "21", "-pix_fmt", "yuv420p", str(clip),
            ])
            clip_paths.append(clip)
            storyboard.append(
                {
                    "scene": index,
                    "duration_seconds": 4,
                    "kicker": scene[0],
                    "hero": scene[1],
                    "sub": scene[2],
                    "claim_ids": scene[5],
                }
            )
        concat = temp / "concat.txt"
        concat.write_text("".join(f"file '{path}'\n" for path in clip_paths), encoding="utf-8")
        silent = temp / "silent.mp4"
        run(["ffmpeg", "-y", "-f", "concat", "-safe", "0", "-i", str(concat), "-c", "copy", str(silent)])
        duration = len(scenes) * 4
        audio = temp / "soundbed.wav"
        run([
            "ffmpeg", "-y",
            "-f", "lavfi", "-i", f"anoisesrc=color=pink:amplitude=0.018:duration={duration}:seed=8675309",
            "-f", "lavfi", "-i", f"sine=frequency=55:sample_rate=48000:duration={duration}",
            "-filter_complex", "[0:a]lowpass=f=900,highpass=f=45[a0];[1:a]volume=0.035[a1];[a0][a1]amix=inputs=2:normalize=0,afade=t=in:st=0:d=1.5,afade=t=out:st=34:d=2,loudnorm=I=-24:LRA=8:TP=-3[a]",
            "-map", "[a]", "-ar", "48000", str(audio),
        ])
        output = OUT_DIR / "remedialhq-launch-short-visual-prototype.mp4"
        run([
            "ffmpeg", "-y", "-i", str(silent), "-i", str(audio), "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-shortest", "-movflags", "+faststart", str(output),
        ])
    (OUT_DIR / "short-001-storyboard.json").write_text(json.dumps(storyboard, indent=2) + "\n", encoding="utf-8")

    thumb_w, thumb_h = 270, 480
    cols = 3
    rows = math.ceil(len(scene_images) / cols)
    sheet = Image.new("RGB", (cols * thumb_w, rows * thumb_h), BG)
    for index, scene_path in enumerate(scene_images):
        with Image.open(scene_path) as scene_image:
            tile = scene_image.resize((thumb_w, thumb_h), Image.Resampling.LANCZOS)
            x = (index % cols) * thumb_w
            y = (index // cols) * thumb_h
            sheet.paste(tile, (x, y))
    sheet.save(OUT_DIR / "short-contact-sheet.png", optimize=True)
    print(f"built {output} ({output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    main()
