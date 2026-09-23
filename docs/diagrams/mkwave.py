"""Generate the SPI / QSPI read timing diagrams used in the README.

Each diagram is drawn as two WaveDrom halves - the command/address phase and
the data phase - stacked into one image, so the labels stay readable when the
image is scaled down to page width.

    python mkwave.py          # writes *_a.json / *_b.json, then renders
                              # spi_read.svg, qspi_read.svg (+ .png if
                              # rsvg-convert is installed)

Rendering needs wavedrom-cli on PATH (npm i -g wavedrom-cli), or set
WAVEDROM_CLI to its path. Without it, only the JSON files are written.
"""

import json
import os
import re
import shutil
import subprocess

B = lambda n: "=" + "." * (n - 1)          # one multi-cycle bus value
DATA = [0x68, 0x73, 0x71, 0x73]            # "hsqs" - SquashFS magic at 0x2D0000
ADDR = ["0x2D", "0x00", "0x00"]
CFG = {"hscale": 1}
FONT_PT = 14                               # WaveDrom default is 11pt
GAP = 30                                   # vertical gap between halves (px)


def bits(byte):                             # MSB-first, '.' for repeats
    out, prev = "", None
    for b in f"{byte:08b}":
        out += "." if b == prev else b; prev = b
    return out


nib = [n for b in DATA for n in (b >> 4, b & 0xF)]


def lane(bit):                              # one QSPI IO line across all nibbles
    out, prev = "", None
    for n in nib:
        v = str((n >> bit) & 1); out += "." if v == prev else v; prev = v
    return out


# --- single-lane SPI: 0x03 READ, 1-1-1, 8 cmd + 24 addr | 3x8 data ----------
spi_a = {"signal": [
    {"name": "CS#",  "wave": "10" + "." * 32},
    {"name": "SCK",  "wave": "l" + "p" * 33},
    {"name": "MOSI", "wave": "x" + bits(0x03) + B(8) * 3 + "x", "data": ADDR},
    {"name": "MISO", "wave": "z" + "." * 33},
    {},
    {"name": "phase", "wave": "x" + B(8) + B(24) + "x",
     "data": ["cmd 0x03 READ", "addr 0x2D0000 (24-bit)"]},
],
 "head": {"text": "Single-lane SPI read — 0x03 READ (1-1-1)", "tick": -1},
 "config": CFG}

spi_b = {"signal": [
    {"name": "CS#",  "wave": "0" + "." * 24 + "1"},
    {"name": "SCK",  "wave": "l" + "p" * 24 + "l"},
    {"name": "MOSI", "wave": "x" + "." * 25},
    {"name": "MISO", "wave": "z" + B(8) * 3 + "z",
     "data": [f"0x{b:02X} '{chr(b)}'" for b in DATA[:3]]},
    {},
    {"name": "phase", "wave": "x" + B(24) + "x", "data": ["data (MISO, 1 bit/clk)"]},
],
 "head": {"tick": 31},
 "foot": {"text": "SquashFS superblock read at 0x2D0000"},
 "config": CFG}

# --- QSPI: 0x6B Fast Read Quad Output, 1-1-4, 8 cmd + 24 addr | 8 dummy + 8 data
qspi_a = {"signal": [
    {"name": "CS#", "wave": "10" + "." * 32},
    {"name": "SCK", "wave": "l" + "p" * 33},
    {"name": "IO0 (SI/SO)", "wave": "x" + bits(0x6B) + B(8) * 3 + "z", "data": ADDR},
    {"name": "IO1 (SO)",    "wave": "z" + "." * 33},
    {"name": "IO2 (WP#)",   "wave": "z" + "." * 33},
    {"name": "IO3 (HOLD#)", "wave": "z" + "." * 33},
    {},
    {"name": "phase", "wave": "x" + B(8) + B(24) + "x",
     "data": ["cmd 0x6B", "addr 0x2D0000 (IO0 only)"]},
],
 "head": {"text": "Quad SPI read — 0x6B FAST_READ_QUAD_OUT (1-1-4)", "tick": -1},
 "config": CFG}

qspi_b = {"signal": [
    {"name": "CS#", "wave": "0" + "." * 16 + "1"},
    {"name": "SCK", "wave": "l" + "p" * 16 + "l"},
    {"name": "IO0 (SI/SO)", "wave": "x" + "z" + "." * 7 + lane(0) + "z"},
    {"name": "IO1 (SO)",    "wave": "z" + "." * 8 + lane(1) + "z"},
    {"name": "IO2 (WP#)",   "wave": "z" + "." * 8 + lane(2) + "z"},
    {"name": "IO3 (HOLD#)", "wave": "z" + "." * 8 + lane(3) + "z"},
    {},
    {"name": "byte", "wave": "x" + "." * 8 + B(2) * 4 + "x",
     "data": [f"0x{b:02X}" for b in DATA]},
    {"name": "phase", "wave": "x" + B(8) + B(8) + "x", "data": ["8 dummy clk", "data ×4"]},
],
 "head": {"tick": 31},
 "foot": {"text": "Same 4 bytes (\"hsqs\") in 8 clocks instead of 32 — IO3..IO0 carry bits 7..4 then 3..0"},
 "config": CFG}

DIAGRAMS = {"spi_read": (spi_a, spi_b), "qspi_read": (qspi_a, qspi_b)}


def check(d):
    lens = {s["name"]: len(s["wave"]) for s in d["signal"] if s}
    assert len(set(lens.values())) == 1, lens


def svg_size(svg):
    root = re.match(r"<svg[^>]*>", svg).group(0)
    return tuple(int(re.search(rf'\b{a}="(\d+)"', root).group(1)) for a in ("width", "height"))


def stack(svgs):
    """Nest rendered SVGs vertically into one document (identical WaveDrom
    defs/styles in each half, so duplicate ids resolve to the same thing)."""
    parts, y, width = [], 0, 0
    for s in svgs:
        s = s[s.index("<svg"):]
        w, h = svg_size(s)
        s = s.replace(f"text{{font-size:11pt;", f"text{{font-size:{FONT_PT}pt;", 1)
        parts.append(re.sub(r"^<svg", f'<svg x="0" y="{y}"', s, count=1))
        y += h + GAP
        width = max(width, w)
    height = y - GAP
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}">'
            f'<rect width="100%" height="100%" fill="#fff"/>' + "".join(parts) + "</svg>\n")


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.chdir(here)
    cli = os.environ.get("WAVEDROM_CLI") or shutil.which("wavedrom-cli")
    rsvg = shutil.which("rsvg-convert")

    for name, halves in DIAGRAMS.items():
        rendered = []
        for suffix, d in zip("ab", halves):
            check(d)
            src = f"{name}_{suffix}.json"
            json.dump(d, open(src, "w"), indent=2)
            if cli:
                out = f"{name}_{suffix}.svg"
                subprocess.run([cli, "-i", src, "-s", out], check=True)
                rendered.append(open(out).read())
                os.remove(out)
        if not cli:
            continue
        with open(f"{name}.svg", "w") as f:
            f.write(stack(rendered))
        if rsvg:
            subprocess.run([rsvg, "-z", "2", "-b", "white", f"{name}.svg",
                            "-o", f"{name}.png"], check=True)
        print(f"wrote {name}.svg" + (f", {name}.png" if rsvg else ""))

    if not cli:
        print("wavedrom-cli not found: wrote JSON only (set WAVEDROM_CLI to render)")


if __name__ == "__main__":
    main()
