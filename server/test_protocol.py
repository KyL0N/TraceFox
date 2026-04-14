#!/usr/bin/env python3
"""
Tests for TraceFox TLV v2 protocol parser and Prometheus label escaping.

Run: python3 -m pytest test_protocol.py -v
  or: python3 test_protocol.py
"""

import struct
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from tracefox_protocol import parse_frame, TF_MAGIC, TF_VERSION
from tracefox_protocol import TF_TYPE_CPU, TF_TYPE_MEM, TF_TYPE_NET
from tracefox_protocol import TF_TYPE_DISK, TF_TYPE_FS, TF_TYPE_HOST_LABEL, TF_TYPE_PROC


def _make_header(ts=1000000, seq=1):
    return struct.pack(">HBB II", TF_MAGIC, TF_VERSION, 0x00, ts, seq)


def _make_tlv(typ, payload):
    return struct.pack(">BB", typ, len(payload)) + payload


def test_empty_payload():
    assert parse_frame(b"") == {}


def test_short_payload():
    assert parse_frame(b"\x00" * 5) == {}


def test_bad_magic():
    payload = struct.pack(">HBB II", 0xDEAD, TF_VERSION, 0, 100, 1)
    assert parse_frame(payload) == {}


def test_bad_version():
    payload = struct.pack(">HBB II", TF_MAGIC, 99, 0, 100, 1)
    assert parse_frame(payload) == {}


def test_header_only():
    frame = _make_header(ts=1234567890, seq=42)
    result = parse_frame(frame)
    assert result["ts"] == 1234567890
    assert result["seq"] == 42
    assert result["version"] == TF_VERSION


def test_cpu_tlv():
    cpu_payload = struct.pack(">HHHHH", 150, 50, 780, 10, 10)
    frame = _make_header() + _make_tlv(TF_TYPE_CPU, cpu_payload)
    result = parse_frame(frame)
    assert "cpu" in result
    assert result["cpu"]["user_pct"] == 15.0
    assert result["cpu"]["system_pct"] == 5.0
    assert result["cpu"]["idle_pct"] == 78.0
    assert result["cpu"]["iowait_pct"] == 1.0
    assert result["cpu"]["irq_pct"] == 1.0


def test_mem_and_load_tlv():
    mem_payload = struct.pack(
        ">IIIHHH",
        8000000,   # total_kb
        2000000,   # free_kb
        5000000,   # avail_kb
        125,       # load1 x100
        200,       # load5 x100
        150,       # load15 x100
    )
    frame = _make_header() + _make_tlv(TF_TYPE_MEM, mem_payload)
    result = parse_frame(frame)
    assert result["mem"]["total_kb"] == 8000000
    assert result["mem"]["free_kb"] == 2000000
    assert result["mem"]["avail_kb"] == 5000000
    assert result["mem"]["used_kb"] == 6000000
    assert result["load"]["load1"] == 1.25
    assert result["load"]["load5"] == 2.0
    assert result["load"]["load15"] == 1.5


def test_host_label_tlv():
    host_label = b"sunrise-edge"
    frame = _make_header() + _make_tlv(TF_TYPE_HOST_LABEL, host_label)
    result = parse_frame(frame)
    assert result["host_label"] == "sunrise-edge"


def test_net_tlv():
    name = b"eth0\x00\x00\x00\x00"
    rx = struct.pack(">Q", 123456789)
    tx = struct.pack(">Q", 987654321)
    net_payload = b"\x01" + name + rx + tx
    frame = _make_header() + _make_tlv(TF_TYPE_NET, net_payload)
    result = parse_frame(frame)
    assert len(result["net"]) == 1
    assert result["net"][0]["name"] == "eth0"
    assert result["net"][0]["rx_bytes"] == 123456789
    assert result["net"][0]["tx_bytes"] == 987654321


def test_disk_tlv_64bit():
    name = b"nvme0n1\x00"
    cum = struct.pack(">QQQQQQ", 100000, 200000, 300000, 400000, 50000, 60000)
    delta = struct.pack(">II", 150, 250)
    util = struct.pack(">H", 455)
    disk_payload = b"\x01" + name + cum + delta + util
    frame = _make_header() + _make_tlv(TF_TYPE_DISK, disk_payload)
    result = parse_frame(frame)
    assert len(result["disk"]) == 1
    d = result["disk"][0]
    assert d["name"] == "nvme0n1"
    assert d["reads_completed"] == 100000
    assert d["writes_completed"] == 200000
    assert d["sectors_read"] == 300000
    assert d["sectors_written"] == 400000
    assert d["read_ms"] == 50000
    assert d["write_ms"] == 60000
    assert d["read_iops_delta"] == 150
    assert d["write_iops_delta"] == 250
    assert d["io_util_pct"] == 45.5


def test_disk_tlv_32bit_compat():
    name = b"sda\x00\x00\x00\x00\x00"
    fields = struct.pack(">IIIIIIII", 1000, 2000, 3000, 4000, 500, 600, 10, 20)
    util = struct.pack(">H", 100)
    disk_payload = b"\x01" + name + fields + util
    frame = _make_header() + _make_tlv(TF_TYPE_DISK, disk_payload)
    result = parse_frame(frame)
    assert len(result["disk"]) == 1
    d = result["disk"][0]
    assert d["name"] == "sda"
    assert d["reads_completed"] == 1000
    assert d["io_util_pct"] == 10.0


def test_fs_tlv_64bit():
    mount = b"/\x00" + b"\x00" * 14
    total_kb = struct.pack(">Q", 5_000_000_000)
    used_pct = struct.pack(">H", 723)
    fs_payload = b"\x01" + mount + total_kb + used_pct
    frame = _make_header() + _make_tlv(TF_TYPE_FS, fs_payload)
    result = parse_frame(frame)
    assert len(result["fs"]) == 1
    assert result["fs"][0]["mount"] == "/"
    assert result["fs"][0]["total_kb"] == 5_000_000_000
    assert result["fs"][0]["used_pct"] == 723


def test_fs_tlv_32bit_compat():
    mount = b"/data\x00" + b"\x00" * 10
    total_kb = struct.pack(">I", 1000000)
    used_pct = struct.pack(">H", 500)
    fs_payload = b"\x01" + mount + total_kb + used_pct
    frame = _make_header() + _make_tlv(TF_TYPE_FS, fs_payload)
    result = parse_frame(frame)
    assert len(result["fs"]) == 1
    assert result["fs"][0]["total_kb"] == 1000000
    assert result["fs"][0]["used_pct"] == 500


def test_proc_tlv():
    name = b"python3\x00" + b"\x00" * 8
    group = name + struct.pack(">HH", 3, 125) + struct.pack(">I", 65536)
    proc_payload = b"\x01" + group
    frame = _make_header() + _make_tlv(TF_TYPE_PROC, proc_payload)
    result = parse_frame(frame)
    assert len(result["proc_groups"]) == 1
    pg = result["proc_groups"][0]
    assert pg["name"] == "python3"
    assert pg["inst_count"] == 3
    assert pg["cpu_pct"] == 12.5
    assert pg["rss_kb_sum"] == 65536


def test_multiple_tlvs():
    cpu = struct.pack(">HHHHH", 100, 50, 800, 30, 20)
    mem = struct.pack(">IIIHHH", 4000000, 1000000, 3000000, 50, 40, 30)
    frame = _make_header() + _make_tlv(TF_TYPE_CPU, cpu) + _make_tlv(TF_TYPE_MEM, mem)
    result = parse_frame(frame)
    assert "cpu" in result
    assert "mem" in result
    assert "load" in result


def test_truncated_tlv_value():
    frame = _make_header() + struct.pack(">BB", TF_TYPE_CPU, 10) + b"\x00" * 5
    result = parse_frame(frame)
    assert "cpu" not in result


def test_malformed_frame_returns_empty():
    header = _make_header()
    bad_tlv = struct.pack(">BB", TF_TYPE_DISK, 20) + b"\x01" + b"\xff" * 19
    frame = header + bad_tlv
    result = parse_frame(frame)
    assert isinstance(result, dict)


def test_zero_count_entries():
    frame = _make_header() + _make_tlv(TF_TYPE_NET, b"\x00")
    result = parse_frame(frame)
    assert result["net"] == []


def test_label_escaping():
    from metrics_forwarder import frame_to_prometheus

    cpu = struct.pack(">HHHHH", 500, 200, 200, 50, 50)
    frame_data = _make_header(ts=1000) + _make_tlv(TF_TYPE_CPU, cpu)
    frame = parse_frame(frame_data)
    host = 'test"host\nwith\\special'
    body = frame_to_prometheus(frame, host)
    assert r'host="test\"host\nwith\\special"' in body
    assert "\n" in body


def test_forwarder_uses_frame_host_label():
    from metrics_forwarder import resolve_frame_host

    frame = {"host_label": "edge-a"}
    assert resolve_frame_host(frame, ("10.1.2.3", 9000)) == "edge-a"


def test_forwarder_falls_back_to_source_ip_without_dns():
    import socket
    from metrics_forwarder import resolve_frame_host

    def _unexpected_lookup(_ip):
        raise AssertionError("reverse DNS should not be used")

    original_lookup = socket.gethostbyaddr
    socket.gethostbyaddr = _unexpected_lookup
    try:
        assert resolve_frame_host({}, ("10.1.2.3", 9000)) == "10.1.2.3"
    finally:
        socket.gethostbyaddr = original_lookup


def test_sender_retries_same_payload_before_dequeueing_next():
    import queue
    import metrics_forwarder

    q = queue.Queue()
    q.put("body-1")
    q.put("body-2")

    calls = []
    outcomes = [False, True, True]
    original_push = metrics_forwarder.push_to_vm
    original_sleep = metrics_forwarder.time.sleep
    original_running = metrics_forwarder._running
    original_stats = metrics_forwarder._stats.copy()

    def _push(body):
        calls.append(body)
        return outcomes.pop(0)

    metrics_forwarder.push_to_vm = _push
    metrics_forwarder.time.sleep = lambda _seconds: None
    metrics_forwarder._running = False
    metrics_forwarder._stats.update(
        forwarded=0, errors=0, drops=0, push_failures=0
    )
    try:
        metrics_forwarder.sender_thread(q)
    finally:
        metrics_forwarder.push_to_vm = original_push
        metrics_forwarder.time.sleep = original_sleep
        metrics_forwarder._running = original_running
        metrics_forwarder._stats.update(original_stats)

    assert calls == ["body-1", "body-1", "body-2"]


if __name__ == "__main__":
    test_funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    failed = 0
    for fn in test_funcs:
        try:
            fn()
            passed += 1
            print(f"  PASS  {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {e}")
    print(f"\n{passed} passed, {failed} failed, {passed + failed} total")
    sys.exit(1 if failed else 0)
