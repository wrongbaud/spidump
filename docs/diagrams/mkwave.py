import json
B = lambda n: "=" + "." * (n - 1)          # one multi-cycle bus value
DATA = [0x68, 0x73, 0x71, 0x73]            # "hsqs" — SquashFS magic at 0x2D0000
ADDR = ["0x2D", "0x00", "0x00"]

def bits(byte):                             # MSB-first, '.' for repeats
    out, prev = "", None
    for b in f"{byte:08b}":
        out += "." if b == prev else b; prev = b
    return out

def check(d):
    lens = {s["name"]: len(s["wave"]) for s in d["signal"] if isinstance(s, dict) and "wave" in s}
    assert len(set(lens.values())) == 1, lens
    return d

# --- single-lane SPI: 0x03 READ, 1-1-1, 8 cmd + 24 addr + 3x8 data ---------
n_data = 3
spi = {"signal": [
    {"name": "CS#",  "wave": "10" + "." * (8 + 24 + 8 * n_data - 1) + "1"},
    {"name": "SCK",  "wave": "l" + "p" * (8 + 24 + 8 * n_data) + "l"},
    {"name": "MOSI", "wave": "x" + bits(0x03) + B(8) * 3 + "x" + "." * (8 * n_data - 1) + ".",
     "data": ADDR},
    {"name": "MISO", "wave": "z" + "." * 32 + B(8) * n_data + "z",
     "data": [f"0x{b:02X} '{chr(b)}'" for b in DATA[:n_data]]},
    {},
    {"name": "phase", "wave": "x" + B(8) + B(24) + B(8 * n_data) + "x",
     "data": ["cmd 0x03 READ", "addr 0x2D0000 (24-bit)", "data (MISO, 1 bit/clk)"]},
],
 "head": {"text": "Single-lane SPI read — 0x03 READ (1-1-1)", "tick": -1},
 "foot": {"text": "SquashFS superblock read from bigger-boot.csv"},
 "config": {"hscale": 1}}

# --- QSPI: 0x6B Fast Read Quad Output, 1-1-4, 8 cmd + 24 addr + 8 dummy + 8 data
nib = [n for b in DATA for n in (b >> 4, b & 0xF)]
def lane(bit):
    out, prev = "", None
    for n in nib:
        v = str((n >> bit) & 1); out += "." if v == prev else v; prev = v
    return out
pre = 8 + 24 + 8
qspi = {"signal": [
    {"name": "CS#", "wave": "10" + "." * (pre + 8 - 1) + "1"},
    {"name": "SCK", "wave": "l" + "p" * (pre + 8) + "l"},
    {"name": "IO0 (SI/SO)",   "wave": "x" + bits(0x6B) + B(8) * 3 + "z" + "." * 7 + lane(0) + "z",
      "data": ADDR},
    {"name": "IO1 (SO)",   "wave": "z" + "." * pre + lane(1) + "z"},
    {"name": "IO2 (WP#)",  "wave": "z" + "." * pre + lane(2) + "z"},
    {"name": "IO3 (HOLD#)", "wave": "z" + "." * pre + lane(3) + "z"},
    {},
    {"name": "byte", "wave": "x" + "." * pre + B(2) * 4 + "x",
     "data": [f"0x{b:02X}" for b in DATA]},
    {"name": "phase", "wave": "x" + B(8) + B(24) + B(8) + B(8) + "x",
     "data": ["cmd 0x6B", "addr 0x2D0000 (IO0 only)", "8 dummy clk", "data ×4"]},
],
 "head": {"text": "Quad SPI read — 0x6B FAST_READ_QUAD_OUT (1-1-4)", "tick": -1},
 "foot": {"text": "Same 4 bytes (\"hsqs\") in 8 clocks instead of 32 — IO3..IO0 carry bits 7..4 then 3..0"},
 "config": {"hscale": 1}}

# flatten groups for length check
def flat(d):
    out = []
    for s in d["signal"]:
        out += [x for x in s if isinstance(x, dict)] if isinstance(s, list) else [s]
    return {"signal": out}
check(flat(spi)); check(flat(qspi))
for name, d in [("spi_read", spi), ("qspi_read", qspi)]:
    json.dump(d, open(f"{name}.json", "w"), indent=2)
print("ok")
