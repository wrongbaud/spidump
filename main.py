import csv
import argparse
import sys
import logging
import csv
from collections import OrderedDict
from scapy.packet import Packet
from scapy.fields import (
    ByteEnumField,
    ThreeBytesField,
    ConditionalField,
    FieldLenField,
    StrLenField,
)
from scapy.all import bind_layers



logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
CMD_OUT=0
CMD_IN=1

class SPICmd:

    def __init__(self,cmd_code,name,expected_resp_len,direction):
        self.name = name
        self.len = expected_resp_len
        self.resp = None
        self.direction = direction

READ = SPICmd(0x3,"READ",0,CMD_IN)
READ_SR = SPICmd(0x5,"READ_STATUS_REGISTER",1,CMD_IN)
WRITE_DISABLE = SPICmd(0x2,"WRITE_DISABLE",0,CMD_OUT)
WRITE_SR_1 = SPICmd(0x01,"Write Staus Register 1",1,CMD_OUT)
READ_SR_2 = SPICmd(0x35 ,"Read Status Register 2",1,CMD_IN)


class SPI(Packet):
    name = "SPI"
    fields_desc = [
        ByteEnumField("cs", 0, {0: "eeprom"}),  # you can add more CS lines here
    ]

class EEPROMReq(Packet):
    name = "EEPROMReq"
    COMMANDS = {
        0x03: "READ",
        0x02: "WRITE",
        0x06: "WREN",
        0x04: "WRDI",
        0x05: "RDSR",
    }

    CMD_READ = 0x03
    CMD_WRITE = 0x02
    CMD_RDSR = 0x05

    CMD_HAS_ADDR = {
        CMD_READ,
        CMD_WRITE,
    }

    CMD_HAS_DATA = {
        CMD_WRITE,
        0x01,
        0x5,
    }

    fields_desc = [
        # First byte: opcode
        ByteEnumField("cmd", CMD_READ, COMMANDS),

        # 24-bit address for address-carrying commands
        ConditionalField(
            ThreeBytesField("addr", 0x000000),
            lambda pkt: pkt.cmd in pkt.CMD_HAS_ADDR,
        ),

        # For write-like commands, include a data length + data
        ConditionalField(
            FieldLenField("dlen", None, count_of="data", fmt="H"),
            lambda pkt: pkt.cmd in pkt.CMD_HAS_DATA,
        ),
        ConditionalField(
            StrLenField("data", b"", length_from=lambda pkt: pkt.dlen),
            lambda pkt: pkt.cmd in pkt.CMD_HAS_DATA,
        ),
    ]


class EEPROMResp(Packet):
    name = "EEPROMResp"

    fields_desc = [
        FieldLenField("dlen", None, count_of="data", fmt="H"),
        StrLenField("data", b"", length_from=lambda pkt: pkt.dlen),
    ]


# Bind SPI -> EEPROMReq so SPI()/EEPROMReq() stacks nicely
bind_layers(SPI, EEPROMReq, cs=0)

from scapy.fields import FlagsField

class EEPROMStatusResp(Packet):
    name = "EEPROMStatusResp"

    fields_desc = [
        FlagsField(
            "sr", 0, 8,
            {
                0x01: "WIP",
                0x02: "WEL",
                0x04: "BP0",
                0x08: "BP1",
                0x10: "BP2",
                0x20: "TB",
                0x40: "SEC",
                0x80: "SRP0",
            },
        )
    ]

def parse_spi_log(path):

    transactions = []
    current = None

    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ttype = row["type"].strip('"') if row["type"] else ""
            name = row["name"].strip('"') if row["name"] else ""

            if ttype == "enable":
                current = {
                    "start_time": float(row["start_time"]),
                    "mosi": [],
                    "miso": [],
                    "times": [],
                }

            elif ttype == "result":
                if current is None:
                    continue

                mosi_str = row["mosi"] or ""
                miso_str = row["miso"] or ""

                mosi_val = int(mosi_str, 16) if mosi_str.startswith("0x") else 0
                miso_val = int(miso_str, 16) if miso_str.startswith("0x") else 0

                current["mosi"].append(mosi_val)
                current["miso"].append(miso_val)
                current["times"].append(float(row["start_time"]))

            elif ttype == "disable":
                if current is not None:
                    current["end_time"] = float(row["start_time"])
                    if current["mosi"]:
                        transactions.append(current)
                    current = None

    return transactions
    

def build_packets_from_spi_log(path, cs=0):

    transactions = parse_spi_log(path)
    results = []

    for idx, tx in enumerate(transactions):
        mosi = tx["mosi"]
        miso = tx["miso"]

        req, resp = build_eeprom_req_resp_from_bytes(mosi, miso)
        if req is None:
            continue

        spi_req = SPI(cs=cs) / req

        results.append({
            "index": idx,
            "spi_req": spi_req,
            "req": req,
            "resp": resp,
            "mosi": bytes(mosi),
            "miso": bytes(miso),
            "start_time": tx["start_time"],
            "end_time": tx.get("end_time"),
            "times": tx["times"],
        })

    return results


def build_eeprom_req_resp_from_bytes(mosi_bytes, miso_bytes):

    if not mosi_bytes:
        return None, None

    cmd = mosi_bytes[0]
    req = EEPROMReq(cmd=cmd)
    offset = 1

    if cmd in EEPROMReq.CMD_HAS_ADDR and len(mosi_bytes) >= offset + 3:
        addr = (
            (mosi_bytes[offset] << 16)
            | (mosi_bytes[offset + 1] << 8)
            | (mosi_bytes[offset + 2])
        )
        req.addr = addr
        offset += 3

    if cmd in EEPROMReq.CMD_HAS_DATA and len(mosi_bytes) > offset:
        data_out = bytes(mosi_bytes[offset:])
        req.dlen = len(data_out)
        req.data = data_out

    resp = None
    if cmd == EEPROMReq.CMD_READ and len(miso_bytes) > offset:
        data_in = bytes(miso_bytes[offset:])
        resp = EEPROMResp(data=data_in)
    elif cmd == EEPROMReq.CMD_RDSR and len(miso_bytes) > offset:
        sr_val = miso_bytes[offset]
        resp = EEPROMStatusResp(sr=sr_val)
    return req, resp


def reconstruct_flash_image(packets, flash_size=None, fill=0xFF):
    read_segments = []

    for info in packets:
        req = info["req"]
        resp = info.get("resp")

        if req.cmd != EEPROMReq.CMD_READ or resp is None:
            continue

        addr = getattr(req, "addr", None)
        if addr is None:
            continue

        data = resp.data or b""
        if not data:
            continue

        start = addr
        end = addr + len(data)
        read_segments.append((start, end, data))

    if not read_segments:
        raise ValueError("No READ transactions with data found; cannot reconstruct image.")

    max_end = max(end for (_, end, _) in read_segments)
    if flash_size is None:
        flash_size = max_end

    image = bytearray([fill] * flash_size)
    coverage = bytearray([0] * flash_size)

    for start, end, data in read_segments:
        if start >= flash_size:
            continue
        if end > flash_size:
            data = data[: flash_size - start]
            end = flash_size

        image[start:end] = data
        for i in range(start, end):
            coverage[i] = 1

    return bytes(image), coverage

if __name__ == "__main__":
    path = "/home/wrongbaud/projects/tt-spi-reconstruction/spidump/examples/bigger-boot.csv"

    packets = build_packets_from_spi_log(path)
    print(f"Decoded {len(packets)} SPI transactions")
    
    for info in packets:
        req = info["req"]
        if req.cmd == EEPROMReq.CMD_RDSR:
            print(f"\n=== RDSR transaction #{info['index']} ===")
            print(f"Time: {info['start_time']} -> {info['end_time']}")
            info["spi_req"].show()
            resp = info.get("resp")
            if resp is not None:
                print("Decoded status register:")
                resp.show()
            else:
                print("No status response captured.")
    image, coverage = reconstruct_flash_image(packets, flash_size=None)

    with open("recovered_flash.bin", "wb") as f:
        f.write(image)
