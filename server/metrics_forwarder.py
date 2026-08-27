#!/usr/bin/env python3
"""
TraceFox Metrics Forwarder

Receives TLV v2 frames via UDP from tracefox-agent, converts them to
Prometheus exposition format, and pushes to VictoriaMetrics via HTTP.

Architecture: receive thread -> bounded queue -> sender thread
This decoupling prevents downstream slowness from blocking UDP ingestion.

Configuration (environment variables):
  TRACEFOX_UDP_HOST    UDP listen address   (default: 0.0.0.0)
  TRACEFOX_UDP_PORT    UDP listen port      (default: 9000)
  TRACEFOX_VM_URL      VictoriaMetrics URL  (default: http://localhost:8428)
  TRACEFOX_VERBOSE     Enable debug logs    (default: 0)
  TRACEFOX_QUEUE_SIZE  Max queued frames    (default: 1000)

Usage:
  python3 metrics_forwarder.py
  TRACEFOX_VM_URL=http://vm:8428 python3 metrics_forwarder.py
"""

import logging
import os
import queue
import signal
import socket
import sys
import threading
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

from tracefox_protocol import parse_frame

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("tracefox-forwarder")

VM_URL = os.environ.get("TRACEFOX_VM_URL", "http://localhost:8428")
VM_IMPORT_PATH = "/api/v1/import/prometheus"
UDP_HOST = os.environ.get("TRACEFOX_UDP_HOST", "0.0.0.0")
UDP_PORT = int(os.environ.get("TRACEFOX_UDP_PORT", "9000"))
VERBOSE = os.environ.get("TRACEFOX_VERBOSE", "0") == "1"
QUEUE_SIZE = int(os.environ.get("TRACEFOX_QUEUE_SIZE", "1000"))

if sys.version_info >= (3, 10):
    from typing import Dict
else:
    from typing_extensions import Dict

_host_first_seen: Dict[str, int] = {}
_running = True

_stats_lock = threading.Lock()
_stats = {
    "forwarded": 0,
    "errors": 0,
    "drops": 0,
    "push_failures": 0,
}


def _handle_signal(signum, frame):
    global _running
    _running = False


def resolve_frame_host(frame: dict, addr: tuple) -> str:
    host_label = str(frame.get("host_label", "")).strip()
    if host_label:
        return host_label
    return addr[0]


def frame_to_prometheus(frame: dict, host: str) -> str:
    """Convert a parsed TLV frame dict into Prometheus exposition text."""
    lines: list[str] = []
    ts_ms = frame.get("ts", int(time.time())) * 1000

    def escape_label_value(s) -> str:
        s = str(s)
        s = s.replace("\\", "\\\\")
        s = s.replace('"', '\\"')
        s = s.replace("\n", "\\n")
        return s

    def emit(name: str, labels: dict, value):
        lbl = ",".join(f'{k}="{escape_label_value(v)}"' for k, v in labels.items())
        lines.append(f"{name}{{{lbl}}} {value} {ts_ms}")

    hl = {"host": host}

    emit("tracefox_up", hl, 1)

    if host not in _host_first_seen:
        _host_first_seen[host] = frame.get("ts", int(time.time()))
    uptime_s = frame.get("ts", int(time.time())) - _host_first_seen[host]
    emit("tracefox_uptime_seconds", hl, uptime_s)

    cpu = frame.get("cpu")
    if cpu:
        emit("tracefox_cpu_user_pct", hl, cpu["user_pct"])
        emit("tracefox_cpu_system_pct", hl, cpu["system_pct"])
        emit("tracefox_cpu_idle_pct", hl, cpu["idle_pct"])
        emit("tracefox_cpu_iowait_pct", hl, cpu["iowait_pct"])
        emit("tracefox_cpu_irq_pct", hl, cpu["irq_pct"])

    mem = frame.get("mem")
    if mem:
        emit("tracefox_mem_total_kb", hl, mem["total_kb"])
        emit("tracefox_mem_free_kb", hl, mem["free_kb"])
        emit("tracefox_mem_available_kb", hl, mem["avail_kb"])
        used_kb = max(mem["total_kb"] - mem["avail_kb"], 0)
        emit("tracefox_mem_used_kb", hl, used_kb)
        if mem["total_kb"] > 0:
            pct = round(used_kb / mem["total_kb"] * 100, 1)
            emit("tracefox_mem_used_pct", hl, pct)

    load = frame.get("load")
    if load:
        emit("tracefox_load_1m", hl, load["load1"])
        emit("tracefox_load_5m", hl, load["load5"])
        emit("tracefox_load_15m", hl, load["load15"])

    for iface in frame.get("net", []):
        nl = {**hl, "interface": iface["name"]}
        emit("tracefox_net_rx_bytes_total", nl, iface["rx_bytes"])
        emit("tracefox_net_tx_bytes_total", nl, iface["tx_bytes"])

    for d in frame.get("disk", []):
        dl = {**hl, "device": d["name"]}
        emit("tracefox_disk_reads_completed_total", dl, d["reads_completed"])
        emit("tracefox_disk_writes_completed_total", dl, d["writes_completed"])
        emit("tracefox_disk_sectors_read_total", dl, d["sectors_read"])
        emit("tracefox_disk_sectors_written_total", dl, d["sectors_written"])
        emit("tracefox_disk_read_ms_total", dl, d["read_ms"])
        emit("tracefox_disk_write_ms_total", dl, d["write_ms"])
        emit("tracefox_disk_read_iops", dl, d["read_iops_delta"])
        emit("tracefox_disk_write_iops", dl, d["write_iops_delta"])
        emit("tracefox_disk_io_util_pct", dl, d["io_util_pct"])

    for fs in frame.get("fs", []):
        fl = {**hl, "mount": fs["mount"]}
        emit("tracefox_fs_total_kb", fl, fs["total_kb"])
        emit("tracefox_fs_used_pct", fl, fs["used_pct"] / 10.0)

    for pg in frame.get("proc_groups", []):
        pl = {**hl, "group": pg["name"]}
        emit("tracefox_proc_instances", pl, pg["inst_count"])
        emit("tracefox_proc_cpu_pct", pl, pg["cpu_pct"])
        emit("tracefox_proc_rss_kb", pl, pg["rss_kb_sum"])

    for tg in frame.get("thread_groups", []):
        gl = {**hl, "group": tg["name"]}
        emit("tracefox_proc_threads", gl, tg["total_threads"])
        emit("tracefox_thread_collection_truncated", gl, int(tg["truncated"]))

        for state, count in tg["states"].items():
            sl = {**gl, "state": state}
            emit("tracefox_thread_state_count", sl, count)

        for thread in tg["top_threads"]:
            tl = {**gl, "thread": thread["name"]}
            if tg["include_tid"]:
                tl["pid"] = thread["pid"]
                tl["tid"] = thread["tid"]
            emit("tracefox_thread_instances", tl, thread["inst_count"])
            emit("tracefox_thread_cpu_pct", tl, thread["cpu_pct"])

    return "\n".join(lines) + "\n"


def push_to_vm(body: str) -> bool:
    url = f"{VM_URL}{VM_IMPORT_PATH}"
    try:
        req = Request(url, data=body.encode("utf-8"), method="POST")
        req.add_header("Content-Type", "text/plain")
        with urlopen(req, timeout=5) as resp:
            if resp.status not in (200, 204):
                log.warning("VictoriaMetrics returned HTTP %d", resp.status)
                return False
        return True
    except URLError as exc:
        log.error("Push failed (%s): %s", url, exc)
        return False
    except Exception as exc:
        log.error("Unexpected push error: %s", exc)
        return False


def receiver_thread(sock: socket.socket, q: queue.Queue) -> None:
    """Receive UDP frames, parse, and enqueue (host, body) tuples."""
    global _running
    while _running:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break

        frame = parse_frame(data)
        if not frame:
            log.debug("Ignoring invalid frame from %s:%d", *addr)
            continue

        host = resolve_frame_host(frame, addr)
        body = frame_to_prometheus(frame, host)

        if VERBOSE:
            log.debug(
                "seq=%d host=%s bytes=%d metrics=%d",
                frame.get("seq", 0),
                host,
                len(data),
                body.count("\n"),
            )

        enqueue_latest(q, body)


def enqueue_latest(q: queue.Queue, body: str) -> None:
    """Keep the newest telemetry when the bounded queue is full."""
    try:
        q.put_nowait(body)
        return
    except queue.Full:
        pass

    evicted = False
    try:
        q.get_nowait()
        evicted = True
    except queue.Empty:
        pass

    q.put_nowait(body)

    if not evicted:
        return

    with _stats_lock:
        _stats["drops"] += 1
        drops = _stats["drops"]
    if drops % 100 == 1:
        log.warning(
            "Queue full (size=%d), evicting oldest frame (total drops=%d)",
            q.maxsize,
            drops,
        )


def sender_thread(q: queue.Queue) -> None:
    """Dequeue and push to VictoriaMetrics with exponential backoff on failure."""
    global _running
    backoff = 0.0
    max_backoff = 30.0
    current_body = None

    while _running or current_body is not None or not q.empty():
        if current_body is None:
            try:
                current_body = q.get(timeout=1.0)
            except queue.Empty:
                continue

        if push_to_vm(current_body):
            backoff = 0.0
            current_body = None
            with _stats_lock:
                _stats["forwarded"] += 1
                if _stats["forwarded"] % 100 == 0:
                    log.info(
                        "Forwarded %d frames (%d errors, %d drops, queue=%d)",
                        _stats["forwarded"],
                        _stats["errors"],
                        _stats["drops"],
                        q.qsize(),
                    )
        else:
            with _stats_lock:
                _stats["errors"] += 1
                _stats["push_failures"] += 1
            if backoff == 0.0:
                backoff = 0.5
            else:
                backoff = min(backoff * 2, max_backoff)
            log.debug("Push failed, backing off %.1fs", backoff)
            time.sleep(backoff)


def main() -> None:
    global _running
    if VERBOSE:
        log.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind((UDP_HOST, UDP_PORT))
    log.info("Listening on %s:%d (UDP)", UDP_HOST, UDP_PORT)
    log.info("Forwarding to VictoriaMetrics at %s", VM_URL)
    log.info("Queue size: %d", QUEUE_SIZE)

    q: queue.Queue = queue.Queue(maxsize=QUEUE_SIZE)

    rx = threading.Thread(target=receiver_thread, args=(sock, q), daemon=True)
    tx = threading.Thread(target=sender_thread, args=(q,), daemon=True)
    rx.start()
    tx.start()

    while _running:
        try:
            time.sleep(1.0)
        except (KeyboardInterrupt, SystemExit):
            _running = False
            break

    log.info(
        "Shutting down. Forwarded %d, errors %d, drops %d.",
        _stats["forwarded"],
        _stats["errors"],
        _stats["drops"],
    )
    rx.join(timeout=3.0)
    tx.join(timeout=5.0)
    sock.close()


if __name__ == "__main__":
    main()
