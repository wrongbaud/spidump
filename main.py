"""spidump — parse SPI/QSPI logic-analyzer captures and reconstruct flash images.

The protocol is modelled with Scapy (see ``SPIFlashCmd``); the actual bytes are
fed in from one of three logic-analyzer export formats, auto-detected by header:

1. Saleae Logic 2 "SPI" analyzer data table   (name,type,start_time,...,mosi,miso)
   - rows of type enable / result / disable, one ``result`` per clocked byte.
2. Saleae raw per-byte table                  (Time [s],Packet ID,MOSI,MISO)
   - one row per byte, transactions grouped by Packet ID.
3. QSPI-Analyzer export                        (Time [s],Packet ID, Transaction State, DATA, Lines Used)
   - state machine: 1=command, 2=address, 3=dummy, 4=data byte.

Whatever the wire width (single-lane SPI or 4-lane QSPI), a *logical* flash read
is the same thing — an opcode, an address, and a run of data bytes — so the same
Scapy model and the same ``reconstruct_image`` routine handle all three.
"""

import argparse
import sys
import logging
from collections import Counter

from scapy.packet import Packet, bind_layers
from scapy.fields import (
    ByteEnumField,
    ByteField,
    ThreeBytesField,
    ConditionalField,
    FieldLenField,
    StrLenField,
    FlagsField,
)

logger = logging.getLogger("spidump")


# ---------------------------------------------------------------------------
# Scapy protocol model
# ---------------------------------------------------------------------------
class SPI(Packet):
    """Base layer — which chip-select line a transaction belonged to."""

    name = "SPI"
    fields_desc = [
        ByteEnumField("cs", 0, {0: "flash"}),  # add more CS lines as needed
    ]


class SPIFlashCmd(Packet):
    """A single SPI/QSPI NOR flash command header (the request side)."""

    name = "SPIFlashCmd"

    COMMANDS = {
        0x03: "READ",                 # 1-1-1
        0x0B: "FAST_READ",            # 1-1-1, +1 dummy byte
        0x3B: "FAST_READ_DUAL_OUT",   # 1-1-2, +dummy
        0x6B: "FAST_READ_QUAD_OUT",   # 1-1-4, +dummy
        0xEB: "FAST_READ_QUAD_IO",    # 1-4-4, +dummy
        0x0C: "FAST_READ_4B",         # 1-1-1, 32-bit addr, +dummy
        0x6C: "FAST_READ_QUAD_OUT_4B",  # 1-1-4, 32-bit addr, +dummy
        0x02: "PAGE_PROGRAM",
        0x20: "SECTOR_ERASE",
        0x05: "RDSR1",
        0x35: "RDSR2",
        0x06: "WREN",
        0x04: "WRDI",
        0x9F: "JEDEC_ID",
    }

    # Commands whose data we can place back into the image at an address.
    READ_COMMANDS = {0x03, 0x0B, 0x3B, 0x6B, 0xEB, 0x0C, 0x6C}
    # Commands that clock out an address after the opcode.
    CMD_HAS_ADDR = {0x03, 0x0B, 0x3B, 0x6B, 0xEB, 0x0C, 0x6C, 0x02, 0x20}
    # ...and of those, which insert dummy cycles before data starts.
    CMD_HAS_DUMMY = {0x0B, 0x3B, 0x6B, 0xEB, 0x0C, 0x6C}
    # Commands using a 32-bit (4-byte) address instead of the usual 24-bit.
    CMD_4B_ADDR = {0x0C, 0x6C}

    # Lane width of the DATA phase per read opcode (1=single, 2=dual, 4=quad).
    # Used to reject reads decoded at the wrong width — e.g. a 0x6B quad read
    # that a *single-lane* analyzer mis-decoded as 1-bit data (garbage). This is
    # what makes merging a single-lane leg with a quad leg safe and automatic.
    DATA_LANES = {
        0x03: 1, 0x0B: 1, 0x0C: 1, 0x13: 1,
        0x3B: 2,
        0x6B: 4, 0xEB: 4, 0x6C: 4, 0xEC: 4,
    }

    CMD_READ = 0x03

    # NOTE: lane width (1/2/4) is *metadata*, not part of the logical byte
    # stream, so it is deliberately not a Scapy field — it lives on .lines.
    fields_desc = [
        ByteEnumField("cmd", CMD_READ, COMMANDS),
        ConditionalField(
            ThreeBytesField("addr", 0),
            lambda p: p.cmd in p.CMD_HAS_ADDR,
        ),
        ConditionalField(
            ByteField("dummy", 0),
            lambda p: p.cmd in p.CMD_HAS_DUMMY,
        ),
    ]


class SPIFlashReadResp(Packet):
    name = "SPIFlashReadResp"
    fields_desc = [
        # length_of (not count_of): count_of counts list elements and yields 1
        # for a bytes field. 32-bit because a single boot read can exceed 64 KiB.
        FieldLenField("dlen", None, length_of="data", fmt="I"),
        StrLenField("data", b"", length_from=lambda p: p.dlen),
    ]


class SPIFlashStatusResp(Packet):
    name = "SPIFlashStatusResp"
    fields_desc = [
        FlagsField("sr", 0, 8, {
            0x01: "BUSY",
            0x02: "WEL",
            0x04: "BP0",
            0x08: "BP1",
            0x10: "BP2",
            0x20: "TB",
            0x40: "SEC",
            0x80: "SRP0",
        })
    ]


bind_layers(SPI, SPIFlashCmd, cs=0)


# ---------------------------------------------------------------------------
# Normalized transaction
# ---------------------------------------------------------------------------
# Every parser below yields plain dicts of the same shape so the rest of the
# tool never has to care which capture format produced them:
#
#   {"cmd": int, "addr": int | None, "data": bytes, "lines": int}
#
# ``data`` is the read payload (MISO / quad-data); ``lines`` is the lane width
# used for the data phase (1 for single SPI, 4 for quad), purely informational.
# ---------------------------------------------------------------------------


def _read_record(cmd, addr, data, lines=1):
    return {"cmd": cmd, "addr": addr, "data": bytes(data), "lines": lines}


def parse_saleae_spi(path):
    """Saleae 'SPI' analyzer data table: enable / result / disable rows."""
    import csv

    cur = None
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            ttype = (row.get("type") or "").strip('"')
            if ttype == "enable":
                cur = {"mosi": bytearray(), "miso": bytearray()}
            elif ttype == "result" and cur is not None:
                mo = row.get("mosi") or ""
                mi = row.get("miso") or ""
                cur["mosi"].append(int(mo, 16) if mo.startswith("0x") else 0)
                cur["miso"].append(int(mi, 16) if mi.startswith("0x") else 0)
            elif ttype == "disable" and cur is not None:
                if cur["mosi"]:
                    yield _saleae_to_record(cur["mosi"], cur["miso"])
                cur = None


# Idle time (in byte periods) that marks a chip-select boundary when a raw
# export has no usable Packet IDs. Overridden by --gap.
GAP_FACTOR = 4


def _raw_gap_threshold(path, probe_rows=10000):
    """Decide whether a raw export needs timing-gap splitting, and at what gap.

    If the capture was exported without chip-select framing, every row carries
    the same Packet ID and grouping by it collapses the whole boot into one
    transaction. Probe the first rows: if the Packet ID never changes, fall back
    to splitting on idle gaps longer than GAP_FACTOR x the median byte period.
    Returns the gap in seconds, or None if Packet IDs are usable.
    """
    import csv
    import itertools
    import statistics

    with open(path, newline="") as f:
        rows = list(itertools.islice(csv.DictReader(f), probe_rows))
    if len({r.get("Packet ID") for r in rows}) > 1:
        return None
    times = [float(r["Time [s]"]) for r in rows]
    deltas = [b - a for a, b in zip(times, times[1:]) if b > a]
    if not deltas:
        return None
    return GAP_FACTOR * statistics.median(deltas)


def parse_saleae_raw(path, gap=None):
    """Saleae raw per-byte table: Time,Packet ID,MOSI,MISO. Group by Packet ID.

    Falls back to splitting on timing gaps when Packet IDs are missing or
    constant (see ``_raw_gap_threshold``). ``gap`` forces a threshold in seconds.
    """
    import csv

    if gap is None:
        gap = _raw_gap_threshold(path)
        if gap is not None:
            logger.warning("%s: Packet ID is constant (no chip-select framing); "
                           "splitting transactions on idle gaps > %.3g s",
                           path, gap)
    elif gap:
        logger.info("splitting transactions on idle gaps > %.3g s", gap)

    cur_id = None
    prev_t = None
    mosi = bytearray()
    miso = bytearray()
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            pid = row.get("Packet ID")
            if gap:
                t = float(row["Time [s]"])
                boundary = prev_t is not None and t - prev_t > gap
                prev_t = t
            else:
                boundary = pid != cur_id
            if boundary and mosi:
                yield _saleae_to_record(mosi, miso)
                mosi, miso = bytearray(), bytearray()
            cur_id = pid
            mo = (row.get("MOSI") or "").strip()
            mi = (row.get("MISO") or "").strip()
            mosi.append(int(mo, 16) if mo.startswith("0x") else 0)
            miso.append(int(mi, 16) if mi.startswith("0x") else 0)
    if mosi:
        yield _saleae_to_record(mosi, miso)


def _saleae_to_record(mosi, miso):
    """Turn a single-lane MOSI/MISO transaction into a normalized record.

    Header = opcode (1) + address (3 or 4 if present) + dummy (1 if present);
    everything after the header on MISO is read data.
    """
    cmd = mosi[0]
    hdr = 1
    addr = None
    if cmd in SPIFlashCmd.CMD_HAS_ADDR:
        nbytes = 4 if cmd in SPIFlashCmd.CMD_4B_ADDR else 3
        if len(mosi) >= 1 + nbytes:
            addr = int.from_bytes(bytes(mosi[1:1 + nbytes]), "big")
            hdr += nbytes
    if cmd in SPIFlashCmd.CMD_HAS_DUMMY:
        hdr += 1
    data = bytes(miso[hdr:]) if cmd in SPIFlashCmd.READ_COMMANDS else b""
    return _read_record(cmd, addr, data, lines=1)


def parse_qspi_analyzer(path):
    """QSPI-Analyzer export: state machine (1=cmd, 2=addr, 3=dummy, 4=data).

    Columns: Time [s], Packet ID, Transaction State, DATA, Lines Used.
    A new state-1 row starts a new transaction (there is no explicit 'disable').
    Data bytes are accumulated per transaction so the image can be filled with
    one slice assignment instead of 38M single-byte writes.
    """
    cur = None
    with open(path) as f:
        header = f.readline()  # skip header
        for line in f:
            # Fast positional parse: time, pid, state, data, lines
            parts = line.split(",")
            if len(parts) < 4:
                continue
            state = parts[2]
            val = parts[3]
            if state == "1":  # command
                if cur is not None:
                    yield _qspi_finish(cur)
                cur = {"cmd": int(val, 16), "addr": None,
                       "data": bytearray(), "lines": 1}
            elif cur is None:
                continue
            elif state == "2":  # address (pre-assembled by the analyzer)
                cur["addr"] = int(val, 16)
            elif state == "3":  # dummy cycles — nothing to store
                pass
            elif state == "4":  # one data byte
                cur["data"].append(int(val, 16))
                cur["lines"] = int(parts[4]) if len(parts) > 4 else cur["lines"]
    if cur is not None:
        yield _qspi_finish(cur)


def _qspi_finish(cur):
    return _read_record(cur["cmd"], cur["addr"], cur["data"], cur["lines"])


# ---------------------------------------------------------------------------
# Format detection + dispatch
# ---------------------------------------------------------------------------
def detect_parser(path):
    with open(path) as f:
        header = f.readline()
    low = header.lower()
    if "transaction state" in low:
        return parse_qspi_analyzer, "qspi-analyzer"
    if "type" in low and "mosi" in low:
        return parse_saleae_spi, "saleae-spi"
    if "packet id" in low and "mosi" in low:
        return parse_saleae_raw, "saleae-raw"
    raise ValueError(f"Unrecognized capture header: {header!r}")


def iter_transactions(path, gap=None):
    parser, fmt = detect_parser(path)
    logger.info("detected capture format: %s", fmt)
    if parser is parse_saleae_raw:
        yield from parser(path, gap=gap)
    else:
        yield from parser(path)


# ---------------------------------------------------------------------------
# Scapy helpers + reconstruction
# ---------------------------------------------------------------------------
def to_packet(rec):
    """Build a Scapy SPI()/SPIFlashCmd()[/resp] from a normalized record."""
    req = SPIFlashCmd(cmd=rec["cmd"])
    if rec["addr"] is not None:
        req.addr = rec["addr"]
    req.lines = rec["lines"]
    pkt = SPI(cs=0) / req

    resp = None
    if rec["cmd"] in SPIFlashCmd.READ_COMMANDS and rec["data"]:
        resp = SPIFlashReadResp(data=rec["data"])
    elif rec["cmd"] == 0x05 and rec["data"]:
        resp = SPIFlashStatusResp(sr=rec["data"][0])
    return pkt, resp


def _data_lanes_ok(rec):
    """True if a read's data was captured at the lane width its opcode uses.

    A single-lane analyzer reports lines=1 for everything; for a quad opcode
    (0x6B/0xEB/...) that means the data phase was mis-decoded, so we drop it.
    """
    req = SPIFlashCmd.DATA_LANES.get(rec["cmd"])
    return req is None or rec["lines"] == req


# Smallest flash we'll auto-size to (64 KiB, e.g. a 25x05). Guards against a
# capture whose reads all start at 0 producing a nonsensical 1-byte image.
MIN_FLASH_SIZE = 0x10000


def reconstruct_image(paths, flash_size=None, fill=0xFF, gap=None):
    """Replay read transactions from one or more captures into a flash image.

    ``paths`` may be a single path or a list. Multiple captures are *merged* in
    order — later captures overwrite earlier ones where they overlap — which is
    how a single-lane U-Boot leg and a QSPI rootfs leg combine into one image.
    Reads whose data lane width doesn't match the opcode are dropped (see
    ``_data_lanes_ok``), so a single-lane capture's mis-decoded quad reads can't
    poison the result. ``gap`` forces timing-gap splitting for raw exports
    (see ``parse_saleae_raw``).
    """
    if isinstance(paths, (str, bytes)):
        paths = [paths]

    segments = []      # (addr, data) in application order
    cmd_counts = Counter()
    per_file = Counter()
    dropped = 0
    max_addr = 0

    for path in paths:
        for rec in iter_transactions(path, gap=gap):
            cmd_counts[rec["cmd"]] += 1
            if rec["cmd"] not in SPIFlashCmd.READ_COMMANDS:
                continue
            if rec["addr"] is None or not rec["data"]:
                continue
            if not _data_lanes_ok(rec):
                dropped += 1
                continue
            max_addr = max(max_addr, rec["addr"])
            segments.append((rec["addr"], rec["data"]))
            per_file[path] += 1

    if not segments:
        raise ValueError("No usable read transactions found.")

    if flash_size is None:
        # Size from the highest *start* address (real flash is power-of-two
        # sized). A read near the top can spill a few bytes past the boundary;
        # those get clipped below rather than bumping us to the next size up.
        flash_size = max(1 << max_addr.bit_length(), MIN_FLASH_SIZE)

    image = bytearray([fill]) * flash_size
    coverage = bytearray(flash_size)
    for addr, data in segments:
        if addr >= flash_size:
            continue
        end = min(addr + len(data), flash_size)
        image[addr:end] = data[:end - addr]
        coverage[addr:end] = b"\x01" * (end - addr)

    # Reads running well past the end mean the size is wrong or transactions
    # were mis-framed (e.g. a raw export with no chip-select boundaries).
    clipped = sum(max(0, a + len(d) - flash_size) for a, d in segments)
    if clipped > 0x1000:
        logger.warning("clipped %d bytes of read data past flash_size=0x%x; "
                       "check --flash-size or transaction framing (--gap)",
                       clipped, flash_size)

    covered = sum(coverage)
    logger.info("commands seen: %s",
                {SPIFlashCmd.COMMANDS.get(c, hex(c)): n
                 for c, n in cmd_counts.most_common()})
    if dropped:
        logger.info("dropped %d reads with wrong data-lane width "
                    "(quad reads mis-decoded by a single-lane analyzer)", dropped)
    if len(paths) > 1:
        for p in paths:
            logger.info("  merged %-50s %d reads", p, per_file[p])
    logger.info("flash_size=0x%x  read_txns=%d  covered=%d (%.1f%%)",
                flash_size, len(segments), covered, 100 * covered / flash_size)
    return bytes(image), coverage


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("capture", help="logic-analyzer export (SPI or QSPI)")
    ap.add_argument("--merge", nargs="+", default=[], metavar="CAPTURE",
                    help="additional capture(s) to merge in, applied after (and "
                         "overwriting) the primary one. Use to splice a "
                         "single-lane U-Boot leg with a QSPI rootfs leg; "
                         "lane-inconsistent reads are dropped automatically.")
    ap.add_argument("-o", "--output", default="recovered_flash.bin",
                    help="output image path (default: recovered_flash.bin)")
    ap.add_argument("--flash-size", type=lambda s: int(s, 0), default=None,
                    help="force flash size in bytes (e.g. 0x1000000); "
                         "default rounds up to next power of two")
    ap.add_argument("--fill", type=lambda s: int(s, 0), default=0xFF,
                    help="fill byte for un-read regions (default 0xFF)")
    ap.add_argument("--gap", type=float, default=None, metavar="SECONDS",
                    help="split raw (Time,Packet ID,MOSI,MISO) exports into "
                         "transactions on idle gaps longer than this; 0 forces "
                         "Packet ID grouping. Default: auto, used only when "
                         "Packet ID is constant (%dx median byte period)"
                         % GAP_FACTOR)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )

    paths = [args.capture] + args.merge
    image, _ = reconstruct_image(paths,
                                 flash_size=args.flash_size, fill=args.fill,
                                 gap=args.gap)
    with open(args.output, "wb") as f:
        f.write(image)
    print(f"wrote {len(image)} bytes -> {args.output}")


if __name__ == "__main__":
    sys.exit(main())
