#!/usr/bin/env python3
"""
Minimal TraceFox UDP server for validating the agent.

Usage:
  python3 test_server.py [host] [port]

Defaults:
  host = 0.0.0.0
  port = 9000

Decodes TLV v2 payloads from tracefox-agent and prints a human-readable
summary. Useful for debugging without the full VM+Grafana stack.
"""

import socket
import sys
from typing import Dict, Any

from tracefox_protocol import parse_frame


_PREV_DISK_STATE: Dict[str, Dict[str, int]] = {}


def print_summary(frame: Dict[str, Any]) -> None:
    """Pretty-print a short summary for a parsed frame."""
    ts = frame.get("ts", 0)
    seq = frame.get("seq", 0)
    cpu = frame.get("cpu", {})
    mem = frame.get("mem", {})
    load = frame.get("load", {})
    net = frame.get("net", [])
    disks = frame.get("disk", [])
    fs_list = frame.get("fs", [])
    proc_groups = frame.get("proc_groups", [])
    thread_groups = frame.get("thread_groups", [])

    print(f"==== frame ts={ts} seq={seq} ====")

    if cpu:
        print(
            "CPU : user={user_pct:.1f}% sys={system_pct:.1f}% idle={idle_pct:.1f}% "
            "iowait={iowait_pct:.1f}% irq={irq_pct:.1f}%".format(**cpu)
        )

    if mem:
        print(
            f"MEM : total={mem.get('total_kb',0)} kB "
            f"free={mem.get('free_kb',0)} kB "
            f"avail={mem.get('avail_kb',0)} kB "
            f"used={mem.get('used_kb',0)} kB"
        )

    if load:
        print(
            f"LOAD: 1m={load.get('load1',0):.2f} "
            f"5m={load.get('load5',0):.2f} "
            f"15m={load.get('load15',0):.2f}"
        )

    if net:
        for iface in net:
            print(
                f"NET : {iface['name']}: rx_bytes={iface['rx_bytes']} "
                f"tx_bytes={iface['tx_bytes']}"
            )

    if disks:
        for d in disks:
            name = d["name"]
            prev = _PREV_DISK_STATE.get(name)

            await_ms = None
            if prev is not None:
                d_reads = d["reads_completed"] - prev["reads_completed"]
                d_writes = d["writes_completed"] - prev["writes_completed"]
                d_read_ms = d["read_ms"] - prev["read_ms"]
                d_write_ms = d["write_ms"] - prev["write_ms"]
                ios = d_reads + d_writes
                if ios > 0:
                    total_ms = max(0, d_read_ms + d_write_ms)
                    await_ms = total_ms / float(ios)

            _PREV_DISK_STATE[name] = {
                "reads_completed": d["reads_completed"],
                "writes_completed": d["writes_completed"],
                "read_ms": d["read_ms"],
                "write_ms": d["write_ms"],
            }

            if await_ms is not None:
                await_str = f"{await_ms:.1f} ms"
            else:
                await_str = "n/a"

            print(
                "DISK: {name}: cum(r={reads_completed},w={writes_completed},"
                "sr={sectors_read},sw={sectors_written},rm={read_ms},wm={write_ms}) "
                "delta(iops_r={read_iops_delta},iops_w={write_iops_delta}) "
                "util={io_util_pct:.1f}% await={await_str}".format(
                    await_str=await_str, **d
                )
            )

    if fs_list:
        for m in fs_list:
            print(
                f"FS  : {m['mount']}: total={m['total_kb']} kB "
                f"used={m['used_pct']:.1f}%"
            )

    if proc_groups:
        print(f"PROC: groups={len(proc_groups)}")
        for g in proc_groups:
            print(
                f"  - {g['name']}: inst={g['inst_count']} "
                f"cpu={g['cpu_pct']:.1f}% rss_sum={g['rss_kb_sum']} kB"
            )

    if thread_groups:
        print(f"THREAD: groups={len(thread_groups)}")
        for group in thread_groups:
            states = ",".join(
                f"{state}={count}" for state, count in group["states"].items()
            )
            print(
                f"  - {group['name']}: total={group['total_threads']} "
                f"states({states}) truncated={group['truncated']}"
            )
            for thread in group["top_threads"]:
                identity = ""
                if group["include_tid"]:
                    identity = f" pid={thread['pid']} tid={thread['tid']}"
                print(
                    f"      {thread['name']}: inst={thread['inst_count']} "
                    f"cpu={thread['cpu_pct']:.1f}%{identity}"
                )


def main() -> None:
    host = "0.0.0.0"
    port = 9000
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"Listening on {host}:{port} (UDP) ...")

    try:
        while True:
            data, addr = sock.recvfrom(2048)
            frame = parse_frame(data)
            print(f"\nFrom {addr[0]}:{addr[1]}")
            if frame:
                print_summary(frame)
            else:
                print("Received invalid / short frame")
    except KeyboardInterrupt:
        print("\nExiting.")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
