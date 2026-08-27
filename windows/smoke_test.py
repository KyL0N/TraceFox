#!/usr/bin/env python3
"""End-to-end smoke test for the Windows portable server."""

import json
import socket
import struct
import time
from urllib.parse import urlencode
from urllib.request import urlopen


HOST_LABEL = "windows-portable-smoke"


def make_frame() -> bytes:
    header = struct.pack(">HBBII", 0x5446, 2, 0, int(time.time()), 1)
    host = HOST_LABEL.encode("ascii")
    host_tlv = struct.pack(">BB", 0x03, len(host)) + host
    cpu = struct.pack(">HHHHH", 150, 50, 780, 10, 10)
    cpu_tlv = struct.pack(">BB", 0x01, len(cpu)) + cpu
    return header + host_tlv + cpu_tlv


def get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as response:
        return json.load(response)


def wait_for_metric(timeout: float = 30.0) -> None:
    query = f'tracefox_up{{host="{HOST_LABEL}"}}'
    url = "http://127.0.0.1:8428/api/v1/query?" + urlencode(
        {"query": query, "latency_offset": "1s"}
    )
    deadline = time.monotonic() + timeout
    last_payload = None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        while time.monotonic() < deadline:
            sock.sendto(make_frame(), ("127.0.0.1", 9000))
            try:
                last_payload = get_json(url)
                results = last_payload.get("data", {}).get("result", [])
                if results and results[0].get("value", [None, None])[1] == "1":
                    return
            except OSError:
                pass
            time.sleep(1)
    raise RuntimeError(
        "TraceFox smoke metric did not reach VictoriaMetrics; "
        f"last query response: {last_payload!r}"
    )


def main() -> None:
    health = get_json("http://127.0.0.1:3000/api/health")
    if health.get("database") != "ok":
        raise RuntimeError(f"Grafana is unhealthy: {health}")

    wait_for_metric()
    print("Windows portable smoke test passed")


if __name__ == "__main__":
    main()
