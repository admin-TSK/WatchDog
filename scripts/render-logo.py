#!/usr/bin/env python3
"""Rasterize the WatchDog mark to transparent PNGs and an .icns."""
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / 'assets'
LIME = (182, 243, 107, 255)
DOG = (11, 18, 32, 255)
APP_BG = (11, 18, 32, 255)
MASTER = 1024


def cubic(start, c1, c2, end, steps=64):
    points = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        points.append((
            u**3 * start[0] + 3 * u**2 * t * c1[0] + 3 * u * t**2 * c2[0] + t**3 * end[0],
            u**3 * start[1] + 3 * u**2 * t * c1[1] + 3 * u * t**2 * c2[1] + t**3 * end[1],
        ))
    return points


def map_point(x, y, scale, offset):
    return (offset[0] + (x - 50) * scale, offset[1] + (y - 20) * scale)


def render(size, opaque=False):
    image = Image.new('RGBA', (size, size), APP_BG if opaque else (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    scale = size / 200
    width = 160 * scale
    offset = ((size - width) / 2, 0)

    def pt(x, y):
        return map_point(x, y, scale, offset)

    shield = [pt(62, 54), pt(130, 32), pt(198, 54)]
    shield += [pt(*p) for p in cubic((198, 120), (198, 161), (171, 189), (130, 208))]
    shield += [pt(*p) for p in cubic((130, 208), (89, 189), (62, 161), (62, 120))]
    draw.polygon(shield, fill=LIME)

    dog = [pt(*p) for p in (
        (92, 78), (109, 92), (151, 92), (168, 78), (174, 126), (154, 158), (106, 158), (86, 126)
    )]
    draw.polygon(dog, fill=DOG)

    stroke = max(2, round(7 * scale))

    def eye(a, b):
        start, end = pt(*a), pt(*b)
        draw.line([start, end], fill=LIME, width=stroke)
        radius = stroke / 2
        for x, y in (start, end):
            draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=LIME)

    eye((107, 117), (117, 120))
    eye((143, 120), (153, 117))
    draw.polygon([pt(120, 139), pt(130, 147), pt(140, 139)], fill=LIME)
    return image


def save_png(image, path, size):
    scaled = image.resize((size, size), Image.Resampling.LANCZOS)
    path.parent.mkdir(parents=True, exist_ok=True)
    scaled.save(path, 'PNG')


def main():
    mark = render(MASTER * 2).resize((MASTER, MASTER), Image.Resampling.LANCZOS)
    app_icon = render(MASTER * 2, opaque=True).resize((MASTER, MASTER), Image.Resampling.LANCZOS)
    save_png(mark, ASSETS / 'logo-mark.png', MASTER)
    for name, sizes in (
        ('Logo', (32, 64, 96)),
        ('MenuBarIcon', (18, 36, 54)),
    ):
        save_png(mark, ASSETS / f'{name}.png', sizes[0])
        save_png(mark, ASSETS / f'{name}@2x.png', sizes[1])
        save_png(mark, ASSETS / f'{name}@3x.png', sizes[2])
    save_png(app_icon, ASSETS / 'AppIcon.png', 256)
    save_png(app_icon, ASSETS / 'AppIcon@2x.png', 512)
    iconset = Path(tempfile.mkdtemp(prefix='watchdog-iconset-')) / 'WatchDog.iconset'
    iconset.mkdir()
    mapping = {
        'icon_16x16.png': 16, 'icon_16x16@2x.png': 32,
        'icon_32x32.png': 32, 'icon_32x32@2x.png': 64,
        'icon_128x128.png': 128, 'icon_128x128@2x.png': 256,
        'icon_256x256.png': 256, 'icon_256x256@2x.png': 512,
        'icon_512x512.png': 512, 'icon_512x512@2x.png': 1024,
    }
    for name, size in mapping.items():
        save_png(app_icon, iconset / name, size)
    icns = ASSETS / 'WatchDog.icns'
    subprocess.run(['/usr/bin/iconutil', '-c', 'icns', '-o', str(icns), str(iconset)], check=True)
    shutil.rmtree(iconset.parent)
    print(f'Rendered WatchDog mark into {ASSETS}')


if __name__ == '__main__':
    main()
