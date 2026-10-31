# SPDX-License-Identifier: Apache-2.0
"""Render the AI 通行证 app icon (original artwork) as a 1024x1024 RGBA PNG.

Pure standard library (zlib) so it runs anywhere: an indigo rounded square with a
white shield and a teal key slot. `pnpm tauri icon app-icon.png` derives every size.
"""
import struct
import sys
import zlib

N = 1024
INDIGO = (79, 70, 229)
TEAL = (14, 165, 164)
WHITE = (255, 255, 255)


def inside_rounded(x, y, r=200, m=40):
    lo, hi = m, N - m
    if x < lo or x >= hi or y < lo or y >= hi:
        return False
    cx = min(max(x, lo + r), hi - r)
    cy = min(max(y, lo + r), hi - r)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def inside_shield(x, y):
    # Upper half: rectangle with rounded top corners; lower half: tapering to a point.
    top, mid, bottom = 250, 560, 830
    half = 250
    cx = N / 2
    if y < top or y > bottom:
        return False
    if y <= mid:
        return abs(x - cx) <= half
    t = (y - mid) / (bottom - mid)
    return abs(x - cx) <= half * (1 - t) ** 0.8


def inside_slot(x, y):
    cx = N / 2
    if (x - cx) ** 2 + (y - 470) ** 2 <= 70 ** 2:
        return True
    return abs(x - cx) <= 30 and 470 <= y <= 650


def pixel(x, y):
    if not inside_rounded(x, y):
        return (0, 0, 0, 0)
    if inside_slot(x, y):
        return TEAL + (255,)
    if inside_shield(x, y):
        return WHITE + (255,)
    return INDIGO + (255,)


def main(path):
    rows = bytearray()
    for y in range(N):
        rows.append(0)
        for x in range(N):
            rows.extend(pixel(x, y))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", N, N, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(rows), 9))
    png += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(png)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "app-icon.png")
