#!/usr/bin/env python3
"""Offline/live AWG wire-level stealth self-test for a public worker."""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass


WG_MAGIC = {1, 2, 3, 4}
LINKTYPE_ETHERNET = 1
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
DEFAULT_DIALECT_PATH = "/worker-state/awg/awg-gw.json"


@dataclass
class Packet:
    ts: float
    port: int
    sport: int
    dport: int
    src: str
    dst: str
    payload_len: int
    first4_le: int | None
    payload: bytes


def main() -> int:
    args = parse_args()
    dialect, dialect_port = load_public_dialect(args.dialect)
    awg_port = args.awg_port or dialect_port
    if not awg_port:
        raise SystemExit("--awg-port is required when dialect JSON has no listen_port")

    pcap_path = args.pcap
    cleanup = False
    if not pcap_path:
        if not args.interface:
            raise SystemExit("--interface is required for live capture")
        fd, pcap_path = tempfile.mkstemp(prefix="tw-worker-dpi-", suffix=".pcap")
        os.close(fd)
        cleanup = True
        capture(args.interface, awg_port, args.duration, pcap_path)

    packets = list(read_pcap(pcap_path, {awg_port}))
    report = build_report(packets, dialect, awg_port)
    report["pcap"] = pcap_path
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print_text_report(report)
    if cleanup and not args.keep_pcap:
        os.unlink(pcap_path)
    return 0 if report["awg"]["verdict"]["obfuscated"] else 2


def parse_args():
    parser = argparse.ArgumentParser(description="AWG DPI/wire-level self-test")
    parser.add_argument("--dialect", default=DEFAULT_DIALECT_PATH, help="public worker awg-gw JSON envelope")
    parser.add_argument("--awg-port", type=int, help="AWG UDP port; defaults to dialect listen_port")
    parser.add_argument("--interface", help="capture interface for live tcpdump mode")
    parser.add_argument("--pcap", help="analyze an existing pcap instead of capturing")
    parser.add_argument("--duration", type=int, default=12, help="live capture duration in seconds")
    parser.add_argument("--keep-pcap", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def capture(interface: str, awg_port: int, duration: int, pcap_path: str):
    cmd = ["tcpdump", "-i", interface, "-nn", "-s", "256", "-w", pcap_path, f"udp port {awg_port}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(duration)
    proc.send_signal(signal.SIGTERM)
    try:
        _, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        _, stderr = proc.communicate()
    if proc.returncode not in (0, -signal.SIGTERM, 124):
        raise RuntimeError(f"tcpdump failed with {proc.returncode}: {stderr.strip()}")


def load_public_dialect(path: str) -> tuple[dict, int | None]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    listen_port = int(data["listen_port"]) if str(data.get("listen_port", "")).strip() else None
    if "dialect" in data:
        return data["dialect"], listen_port
    return data, listen_port


def read_pcap(path: str, ports: set[int]):
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) != 24:
            return
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("unsupported pcap format")
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        while True:
            record_header = fh.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                raise ValueError("truncated pcap record header")
            ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + "IIII", record_header)
            frame = fh.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError("truncated pcap frame")
            parsed = parse_frame(frame, linktype)
            if not parsed:
                continue
            src, dst, sport, dport, payload = parsed
            if sport not in ports and dport not in ports:
                continue
            port = sport if sport in ports else dport
            first4 = struct.unpack("<I", payload[:4])[0] if len(payload) >= 4 else None
            yield Packet(
                ts=ts_sec + ts_usec / 1_000_000,
                port=port,
                sport=sport,
                dport=dport,
                src=src,
                dst=dst,
                payload_len=len(payload),
                first4_le=first4,
                payload=payload,
            )


def parse_frame(frame: bytes, linktype: int):
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        eth_type = struct.unpack("!H", frame[12:14])[0]
        offset = 14
        while eth_type in (0x8100, 0x88A8, 0x9100):
            if len(frame) < offset + 4:
                return None
            eth_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
            offset += 4
        if eth_type != 0x0800:
            return None
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        eth_type = struct.unpack("!H", frame[14:16])[0]
        if eth_type != 0x0800:
            return None
        offset = 16
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        eth_type = struct.unpack("!H", frame[0:2])[0]
        if eth_type != 0x0800:
            return None
        offset = 20
    else:
        raise ValueError(f"unsupported pcap linktype {linktype}")

    if len(frame) < offset + 20:
        return None
    version_ihl = frame[offset]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(frame) < offset + ihl + 8:
        return None
    if frame[offset + 9] != 17:
        return None
    frag = struct.unpack("!H", frame[offset + 6:offset + 8])[0]
    if frag & 0x1FFF:
        return None
    src = ".".join(str(x) for x in frame[offset + 12:offset + 16])
    dst = ".".join(str(x) for x in frame[offset + 16:offset + 20])
    udp_offset = offset + ihl
    sport, dport, udp_len, _ = struct.unpack("!HHHH", frame[udp_offset:udp_offset + 8])
    payload = frame[udp_offset + 8:udp_offset + min(udp_len, len(frame) - udp_offset)]
    return src, dst, sport, dport, payload


def build_report(packets: list[Packet], dialect: dict, awg_port: int) -> dict:
    h_ranges = {
        "h1": parse_range(dialect["h1"]),
        "h2": parse_range(dialect["h2"]),
        "h3": parse_range(dialect["h3"]),
        "h4": parse_range(dialect["h4"]),
    }
    return {
        "dialect": dialect,
        "awg_port": awg_port,
        "awg": summarize_awg(packets, dialect, awg_port, h_ranges),
    }


def summarize_awg(packets: list[Packet], dialect: dict, awg_port: int, h_ranges: dict):
    by_first4_h_range = Counter()
    by_expected_header = Counter()
    wg_magic = Counter()
    lengths = Counter()
    for packet in packets:
        lengths[packet.payload_len] += 1
        if packet.first4_le in WG_MAGIC:
            wg_magic[packet.first4_le] += 1
        name = header_name(packet.first4_le, h_ranges)
        if name:
            by_first4_h_range[name] += 1

    s1 = int(dialect["s1"])
    s2 = int(dialect["s2"])
    s3 = int(dialect["s3"])
    s4 = int(dialect["s4"])
    expected_init_len = 148 + s1
    expected_resp_len = 92 + s2
    expected_cookie_len = 64 + s3
    for packet in packets:
        if packet.payload_len == expected_init_len and header_at(packet.payload, s1, h_ranges["h1"]):
            by_expected_header["h1"] += 1
        if packet.payload_len == expected_resp_len and header_at(packet.payload, s2, h_ranges["h2"]):
            by_expected_header["h2"] += 1
        if packet.payload_len == expected_cookie_len and header_at(packet.payload, s3, h_ranges["h3"]):
            by_expected_header["h3"] += 1
        if packet.payload_len >= 16 + s4 and header_at(packet.payload, s4, h_ranges["h4"]):
            by_expected_header["h4"] += 1

    first_init = next(
        (
            i for i, packet in enumerate(packets)
            if packet.dport == awg_port
            and packet.payload_len == expected_init_len
            and header_at(packet.payload, s1, h_ranges["h1"])
        ),
        None,
    )
    if first_init is None:
        junk_before = 0
        pre_init_packets = []
    else:
        jmin = int(dialect["jmin"])
        jmax = int(dialect["jmax"])
        pre_init_packets = [packet for packet in packets[:first_init] if packet.dport == awg_port]
        junk_before = sum(1 for packet in pre_init_packets if jmin <= packet.payload_len <= jmax)
    pre_init_bytes = sum(packet.payload_len for packet in pre_init_packets)
    pre_init_wg_magic = sum(1 for packet in pre_init_packets if packet.first4_le in WG_MAGIC)
    jc = int(dialect["jc"])
    jmin = int(dialect["jmin"])
    jmax = int(dialect["jmax"])
    junk_exact = junk_before >= jc
    junk_tolerant = (
        not junk_exact
        and len(pre_init_packets) >= max(1, jc // 2)
        and pre_init_wg_magic == 0
        and jc * jmin <= pre_init_bytes <= jc * jmax
    )
    junk_mode = "exact" if junk_exact else ("gso_or_gro_tolerant" if junk_tolerant else "failed")

    vanilla_handshake = lengths[148] + lengths[92]
    padded_handshake = lengths[expected_init_len] + lengths[expected_resp_len]
    verdict = {
        "no_wg_magic": sum(wg_magic.values()) == 0,
        "h_ranges_seen": sum(by_expected_header.values()) > 0,
        "padded_handshake_seen": padded_handshake > 0,
        "vanilla_handshake_absent": vanilla_handshake == 0,
        "junk_before_handshake_ok": junk_exact or junk_tolerant,
    }
    verdict["obfuscated"] = all(verdict.values())
    return {
        "packets": len(packets),
        "lengths": dict(sorted(lengths.items())),
        "first4_in_h_ranges": dict(by_first4_h_range),
        "headers_at_expected_offsets": dict(by_expected_header),
        "first4_wg_magic": dict(wg_magic),
        "expected_init_len": expected_init_len,
        "expected_response_len": expected_resp_len,
        "expected_cookie_len": expected_cookie_len,
        "junk_before_first_init": junk_before,
        "pre_init_packets_observed": len(pre_init_packets),
        "pre_init_bytes": pre_init_bytes,
        "pre_init_wg_magic": pre_init_wg_magic,
        "junk_before_handshake_mode": junk_mode,
        "verdict": verdict,
    }


def parse_range(value: str):
    if "-" not in str(value):
        parsed = int(value)
        return parsed, parsed
    start, end = str(value).split("-", 1)
    return int(start), int(end)


def header_name(value: int | None, ranges: dict):
    if value is None:
        return None
    for name, (start, end) in ranges.items():
        if start <= value <= end:
            return name
    return None


def header_at(payload: bytes, offset: int, header_range: tuple[int, int]) -> bool:
    if offset < 0 or len(payload) < offset + 4:
        return False
    value = struct.unpack("<I", payload[offset:offset + 4])[0]
    start, end = header_range
    return start <= value <= end


def print_text_report(report: dict):
    awg = report["awg"]
    print("AWG DPI probe")
    print(f"pcap={report.get('pcap', '')}")
    print(f"awg_port={report['awg_port']}")
    print(f"awg_packets={awg['packets']}")
    print(f"awg_first4_in_h_ranges={awg['first4_in_h_ranges']}")
    print(f"awg_headers_at_expected_offsets={awg['headers_at_expected_offsets']}")
    print(f"awg_first4_wg_magic={awg['first4_wg_magic']}")
    print(f"awg_lengths={awg['lengths']}")
    print("awg_expected_handshake_lengths=" f"{awg['expected_init_len']}/{awg['expected_response_len']}")
    print(f"awg_junk_before_first_init={awg['junk_before_first_init']}")
    print(f"awg_verdict={awg['verdict']}")


if __name__ == "__main__":
    sys.exit(main())
