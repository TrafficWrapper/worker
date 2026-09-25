"""Unit tests for dpi_probe packet lengths: python3 -m unittest discover -s tools"""

import os
import struct
import tempfile
import unittest

import dpi_probe

AWG_PORT = 51820
DIALECT = {
    "jc": 0, "jmin": 0, "jmax": 0,
    "s1": 40, "s2": 50, "s3": 20, "s4": 16,
    "h1": "100-200", "h2": "300-400", "h3": "500-600", "h4": "700-800",
}


def udp_frame(payload: bytes, sport: int, dport: int) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     bytes([192, 0, 2, 1]), bytes([198, 51, 100, 7]))
    eth = b"\x00" * 12 + struct.pack("!H", 0x0800)
    return eth + ip + udp


def write_pcap(path: str, frames: list[bytes], snaplen: int):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, dpi_probe.LINKTYPE_ETHERNET))
        for i, frame in enumerate(frames):
            captured = frame[:snaplen]
            fh.write(struct.pack("<IIII", i, 0, len(captured), len(frame)))
            fh.write(captured)


def awg_packet(pad: int, header: int, body: int) -> bytes:
    return b"\x11" * pad + struct.pack("<I", header) + b"\x22" * (body - 4)


class UDPPayloadLenTest(unittest.TestCase):
    def test_uses_header_length_over_truncated_capture(self):
        self.assertEqual(dpi_probe.udp_payload_len(8 + 1200, 214), 1200)

    def test_full_capture(self):
        self.assertEqual(dpi_probe.udp_payload_len(8 + 188, 188), 188)

    def test_never_below_captured_bytes(self):
        self.assertEqual(dpi_probe.udp_payload_len(0, 0), 0)
        self.assertEqual(dpi_probe.udp_payload_len(4, 0), 0)


class TruncatedCaptureTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        self.addCleanup(os.unlink, self.path)

    def test_lengths_and_verdict_survive_short_snaplen(self):
        init = awg_packet(DIALECT["s1"], 150, 148)   # 188 bytes
        resp = awg_packet(DIALECT["s2"], 350, 92)    # 142 bytes
        data = awg_packet(DIALECT["s4"], 750, 1200)  # 1216 bytes
        write_pcap(self.path, [
            udp_frame(init, 40000, AWG_PORT),
            udp_frame(resp, AWG_PORT, 40000),
            udp_frame(data, 40000, AWG_PORT),
        ], snaplen=96)
        packets = list(dpi_probe.read_pcap(self.path, {AWG_PORT}))
        self.assertEqual([p.payload_len for p in packets], [188, 142, 1216])
        self.assertTrue(all(len(p.payload) < p.payload_len for p in packets))
        awg = dpi_probe.build_report(packets, DIALECT, AWG_PORT)["awg"]
        self.assertEqual(awg["lengths"], {142: 1, 188: 1, 1216: 1})
        self.assertTrue(awg["verdict"]["padded_handshake_seen"])
        self.assertTrue(awg["verdict"]["obfuscated"], awg["verdict"])


if __name__ == "__main__":
    unittest.main()
