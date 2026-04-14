"""
TraceFox TLV v2 frame parser.

Shared by metrics_forwarder.py, data_server.py, and test_server.py.
"""

import struct
from typing import Dict, Any

TF_MAGIC = 0x5446
TF_VERSION = 2

TF_TYPE_CPU = 0x01
TF_TYPE_MEM = 0x02
TF_TYPE_HOST_LABEL = 0x03
TF_TYPE_NET = 0x04
TF_TYPE_DISK = 0x05
TF_TYPE_FS = 0x06
TF_TYPE_PROC = 0x07


def parse_frame(payload: bytes) -> Dict[str, Any]:
    """Parse a single TLV frame from tracefox-agent."""
    result: Dict[str, Any] = {}

    if len(payload) < 12:
        return result

    magic = struct.unpack(">H", payload[0:2])[0]
    version = payload[2]
    if magic != TF_MAGIC or version != TF_VERSION:
        return result

    ts, seq = struct.unpack(">II", payload[4:12])
    result.update(magic=f"{magic:04x}", version=version, ts=ts, seq=seq)

    offset = 12
    try:
        return _parse_tlv_entries(payload, offset, result)
    except (struct.error, ValueError, IndexError):
        return {}


def _parse_tlv_entries(
    payload: bytes, offset: int, result: Dict[str, Any]
) -> Dict[str, Any]:
    """Parse TLV entries from the payload starting at offset."""
    while offset + 2 <= len(payload):
        t, length = struct.unpack(">BB", payload[offset : offset + 2])
        offset += 2
        if offset + length > len(payload):
            break
        val = payload[offset : offset + length]
        offset += length

        if t == TF_TYPE_CPU and length == 10:
            user, system, idle, iowait, irq = struct.unpack(">HHHHH", val)
            result["cpu"] = {
                "user_pct": user / 10.0,
                "system_pct": system / 10.0,
                "idle_pct": idle / 10.0,
                "iowait_pct": iowait / 10.0,
                "irq_pct": irq / 10.0,
            }

        elif t == TF_TYPE_MEM and length == 18:
            mem_total, mem_free, mem_avail, l1, l5, l15 = struct.unpack(
                ">IIIHHH", val
            )
            used = mem_total - mem_free if mem_total >= mem_free else 0
            result["mem"] = {
                "total_kb": mem_total,
                "free_kb": mem_free,
                "avail_kb": mem_avail,
                "used_kb": used,
            }
            result["load"] = {
                "load1": l1 / 100.0,
                "load5": l5 / 100.0,
                "load15": l15 / 100.0,
            }

        elif t == TF_TYPE_HOST_LABEL and length >= 1:
            result["host_label"] = val.decode("ascii", "ignore").strip()

        elif t == TF_TYPE_NET and length >= 1:
            count = val[0]
            p = 1
            ifaces = []
            for _ in range(count):
                if p + 24 > len(val):
                    break
                name = val[p : p + 8].split(b"\x00", 1)[0].decode("ascii", "ignore")
                p += 8
                rx = int.from_bytes(val[p : p + 8], "big")
                p += 8
                tx = int.from_bytes(val[p : p + 8], "big")
                p += 8
                ifaces.append({"name": name, "rx_bytes": rx, "tx_bytes": tx})
            result["net"] = ifaces

        elif t == TF_TYPE_DISK and length >= 1:
            count = val[0]
            p = 1
            disks = []
            entry_size = ((length - 1) // count) if count > 0 else 0
            for _ in range(count):
                if entry_size >= 66 and p + 66 <= len(val):
                    name = val[p : p + 8].split(b"\x00", 1)[0].decode("ascii", "ignore")
                    p += 8
                    cum = struct.unpack(">QQQQQQ", val[p : p + 48])
                    p += 48
                    delta = struct.unpack(">II", val[p : p + 8])
                    p += 8
                    util_x10 = struct.unpack(">H", val[p : p + 2])[0]
                    p += 2
                    disks.append({
                        "name": name,
                        "reads_completed": cum[0], "writes_completed": cum[1],
                        "sectors_read": cum[2], "sectors_written": cum[3],
                        "read_ms": cum[4], "write_ms": cum[5],
                        "read_iops_delta": delta[0], "write_iops_delta": delta[1],
                        "io_util_pct": util_x10 / 10.0,
                    })
                elif p + 42 <= len(val):
                    name = val[p : p + 8].split(b"\x00", 1)[0].decode("ascii", "ignore")
                    p += 8
                    fields = struct.unpack(">IIIIIIII", val[p : p + 32])
                    p += 32
                    util_x10 = struct.unpack(">H", val[p : p + 2])[0]
                    p += 2
                    disks.append({
                        "name": name,
                        "reads_completed": fields[0], "writes_completed": fields[1],
                        "sectors_read": fields[2], "sectors_written": fields[3],
                        "read_ms": fields[4], "write_ms": fields[5],
                        "read_iops_delta": fields[6], "write_iops_delta": fields[7],
                        "io_util_pct": util_x10 / 10.0,
                    })
                else:
                    break
            result["disk"] = disks

        elif t == TF_TYPE_FS and length >= 1:
            count = val[0]
            p = 1
            mounts = []
            entry_size = ((length - 1) // count) if count > 0 else 0
            for _ in range(count):
                if entry_size >= 26 and p + 26 <= len(val):
                    name = val[p : p + 16].split(b"\x00", 1)[0].decode("ascii", "ignore")
                    p += 16
                    total_kb = struct.unpack(">Q", val[p : p + 8])[0]
                    p += 8
                    used_x10 = struct.unpack(">H", val[p : p + 2])[0]
                    p += 2
                    mounts.append({"mount": name, "total_kb": total_kb, "used_pct": used_x10})
                elif p + 22 <= len(val):
                    name = val[p : p + 16].split(b"\x00", 1)[0].decode("ascii", "ignore")
                    p += 16
                    total_kb = struct.unpack(">I", val[p : p + 4])[0]
                    p += 4
                    used_x10 = struct.unpack(">H", val[p : p + 2])[0]
                    p += 2
                    mounts.append({"mount": name, "total_kb": total_kb, "used_pct": used_x10})
                else:
                    break
            result["fs"] = mounts

        elif t == TF_TYPE_PROC and length >= 1:
            group_count = val[0]
            p = 1
            groups = []
            for _ in range(group_count):
                if p + 24 > len(val):
                    break
                name = (
                    val[p : p + 16].split(b"\x00", 1)[0].decode("ascii", "ignore")
                )
                p += 16
                inst_count, cpu_x10 = struct.unpack(">HH", val[p : p + 4])
                p += 4
                rss_sum = struct.unpack(">I", val[p : p + 4])[0]
                p += 4
                groups.append(
                    {
                        "name": name,
                        "inst_count": inst_count,
                        "cpu_pct": cpu_x10 / 10.0,
                        "rss_kb_sum": rss_sum,
                    }
                )
            result["proc_groups"] = groups

    return result
