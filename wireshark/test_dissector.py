#!/usr/bin/env python3
"""End-to-end tests for the TraceFox Wireshark Lua dissector."""

import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

TSHARK = shutil.which("tshark")
DISSECTOR = Path(__file__).with_name("tracefox.lua").resolve()


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet_udp_packet(payload: bytes) -> bytes:
    source_ip = socket.inet_aton("192.168.188.189")
    destination_ip = socket.inet_aton("192.168.188.188")
    udp = struct.pack("!HHHH", 49152, 9000, 8 + len(payload), 0) + payload

    ip_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0x4000,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    checksum = _internet_checksum(ip_without_checksum)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0x4000,
        64,
        17,
        checksum,
        source_ip,
        destination_ip,
    )
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    return ethernet + ip + udp


def _tracefox_frame(timestamp: int, sequence: int) -> bytes:
    host = b"edge-a"
    return (
        struct.pack(">HBBII", 0x5446, 2, 0, timestamp, sequence)
        + struct.pack(">BB", 0x03, len(host))
        + host
    )


def _write_test_capture(path: Path) -> None:
    base = 1_700_000_000
    frames = (
        (base, 100, base),
        (base + 5, 101, base + 5),
        (base + 45, 109, base + 45),
        (base + 85, 110, base + 85),
    )

    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for capture_timestamp, sequence, agent_timestamp in frames:
            packet = _ethernet_udp_packet(_tracefox_frame(agent_timestamp, sequence))
            handle.write(
                struct.pack(
                    "<IIII",
                    capture_timestamp,
                    0,
                    len(packet),
                    len(packet),
                )
            )
            handle.write(packet)


def _run_tshark(
    capture: Path,
    display_filter: str,
    fields: tuple[str, ...],
) -> tuple[list[list[str]], str]:
    command = [
        TSHARK,
        "-n",
        "-X",
        f"lua_script:{DISSECTOR}",
        "-r",
        str(capture),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        command.extend(("-e", field))

    result = subprocess.run(command, check=False, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    rows = [line.split(",") for line in result.stdout.splitlines() if line]
    return rows, result.stderr


def _field_is_true(value: str) -> bool:
    return value.lower() in {"1", "true", "yes"}


@unittest.skipUnless(TSHARK, "tshark is not installed")
class TraceFoxDissectorTests(unittest.TestCase):
    def test_tracks_arrival_and_sequence_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            capture = Path(temporary_directory) / "tracefox-gap.pcap"
            _write_test_capture(capture)

            udp_rows, udp_stderr = _run_tshark(
                capture,
                "udp.dstport == 9000",
                ("frame.number",),
            )
            self.assertEqual(
                udp_rows,
                [["1"], ["2"], ["3"], ["4"]],
                f"synthetic capture did not contain the expected UDP packets:\n{udp_stderr}",
            )

            rows, tracefox_stderr = _run_tshark(
                capture,
                "tracefox",
                (
                    "frame.number",
                    "tracefox.seq",
                    "tracefox.arrival_delta_seconds",
                    "tracefox.sequence_delta",
                    "tracefox.missing_packets",
                    "tracefox.arrival_gap",
                    "tracefox.sequence_gap",
                    "tracefox.sequence_regression",
                    "tracefox.host_label",
                ),
            )

            self.assertEqual(
                len(rows),
                4,
                f"TraceFox dissector did not decode every UDP packet:\n{tracefox_stderr}",
            )
            self.assertEqual(rows[0][0:2], ["1", "100"])
            self.assertEqual(rows[0][8], "edge-a")

            self.assertAlmostEqual(float(rows[1][2]), 5.0)
            self.assertEqual([int(rows[1][3]), int(rows[1][4])], [1, 0])
            self.assertFalse(_field_is_true(rows[1][5]))
            self.assertFalse(_field_is_true(rows[1][6]))

            self.assertAlmostEqual(float(rows[2][2]), 40.0)
            self.assertEqual([int(rows[2][3]), int(rows[2][4])], [8, 7])
            self.assertTrue(_field_is_true(rows[2][5]))
            self.assertTrue(_field_is_true(rows[2][6]))

            self.assertAlmostEqual(float(rows[3][2]), 40.0)
            self.assertEqual([int(rows[3][3]), int(rows[3][4])], [1, 0])
            self.assertTrue(_field_is_true(rows[3][5]))
            self.assertFalse(_field_is_true(rows[3][6]))

            missing, missing_stderr = _run_tshark(
                capture,
                "tracefox.missing_packets > 0",
                ("frame.number",),
            )
            self.assertEqual(missing, [["3"]], missing_stderr)

            stalled, stalled_stderr = _run_tshark(
                capture,
                "tracefox.arrival_delta_seconds > 6 && tracefox.sequence_delta == 1",
                ("frame.number",),
            )
            self.assertEqual(stalled, [["4"]], stalled_stderr)


if __name__ == "__main__":
    unittest.main()
