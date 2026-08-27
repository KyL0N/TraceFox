#!/usr/bin/env python3
"""End-to-end smoke tests for the Linux thread collector."""

from __future__ import annotations

import signal
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
AGENT = ROOT / "agent" / "bin" / "tracefox-agent"
sys.path.insert(0, str(ROOT / "server"))

from tracefox_protocol import parse_frame  # noqa: E402


def read_frames(path: Path) -> list[dict]:
    raw = path.read_bytes()
    if len(raw) < 8 or raw[:5] != b"TFOX\x01":
        raise AssertionError("missing TraceFox file header")

    frames = []
    offset = 8
    while offset + 2 <= len(raw):
        frame_len = struct.unpack(">H", raw[offset : offset + 2])[0]
        offset += 2
        if offset + frame_len > len(raw):
            raise AssertionError("truncated frame in capture file")
        frame = parse_frame(raw[offset : offset + frame_len])
        offset += frame_len
        if frame:
            frames.append(frame)
    return frames


def capture(mode: str | None, include_tid: bool) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="tracefox-thread-test-") as temp_dir:
        temp = Path(temp_dir)
        config_path = temp / "agent.conf"
        output_path = temp / "capture.tfox"
        settings = [
            "interval=1",
            "proc_prefix=tracefox-agent",
            "thread_top_n=3",
            f"thread_include_tid={'true' if include_tid else 'false'}",
        ]
        if mode is not None:
            settings.append(f"thread_mode={mode}")
        config_path.write_text("\n".join((*settings, "")), encoding="ascii")

        process = subprocess.Popen(
            (str(AGENT), "-c", str(config_path), "-f", str(output_path)),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            time.sleep(1.5)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=5)
        except BaseException:
            process.kill()
            process.wait(timeout=5)
            raise

        if process.returncode != 0:
            raise AssertionError(
                f"tracefox-agent exited with {process.returncode}: {stderr}"
            )
        return read_frames(output_path)


def find_self_groups(frames: list[dict]) -> list[dict]:
    return [
        group
        for frame in frames
        for group in frame.get("thread_groups", [])
        if group["name"] == "tracefox-agent"
    ]


def test_default_top_aggregates_without_tid() -> None:
    groups = find_self_groups(capture(None, include_tid=False))
    assert groups
    assert max(group["total_threads"] for group in groups) >= 1
    entries = [entry for group in groups for entry in group["top_threads"]]
    assert any(entry["name"] == "tracefox-agent" for entry in entries)
    assert all(entry["pid"] == 0 and entry["tid"] == 0 for entry in entries)


def test_summary_omits_top_threads() -> None:
    groups = find_self_groups(capture("summary", include_tid=False))
    assert groups
    assert max(group["total_threads"] for group in groups) >= 1
    assert all(group["top_threads"] == [] for group in groups)


def test_tid_diagnostic_mode_includes_identity() -> None:
    groups = find_self_groups(capture("top", include_tid=True))
    assert groups
    assert all(group["include_tid"] for group in groups)
    entries = [entry for group in groups for entry in group["top_threads"]]
    assert entries
    assert all(entry["pid"] > 0 and entry["tid"] > 0 for entry in entries)


def test_off_mode_emits_no_thread_tlv() -> None:
    frames = capture("off", include_tid=False)
    assert frames
    assert all("thread_groups" not in frame for frame in frames)


if __name__ == "__main__":
    tests = (
        test_default_top_aggregates_without_tid,
        test_summary_omits_top_threads,
        test_tid_diagnostic_mode_includes_identity,
        test_off_mode_emits_no_thread_tlv,
    )
    for test in tests:
        test()
        print(f"PASS {test.__name__}")
