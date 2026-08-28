# TraceFox Wireshark dissector

`tracefox.lua` parses TraceFox TLV v2 UDP frames and tracks each Agent stream. It
decodes the frame header and generic TLVs, exposes the Agent timestamp and
sequence number, and marks arrival gaps, sequence gaps, duplicates, and sequence
regressions/resets.

## Install

1. In Wireshark, open **Help → About Wireshark → Folders**.
2. Open the **Personal Lua Plugins** directory. Create it if it does not exist.
3. Copy `tracefox.lua` into that directory.
4. Restart Wireshark.

UDP port `9000` is decoded automatically. For a custom Agent port, select one of
its packets and use **Analyze → Decode As… → UDP port → TraceFox Telemetry**.

## Useful filters

```wireshark
# All TraceFox packets
tracefox

# Any capture-time gap longer than the configured threshold (default: 6 seconds)
tracefox.arrival_gap == 1

# The exact gap observed in seconds
tracefox.arrival_delta_seconds > 6

# One or more Agent sequence numbers were not captured
tracefox.missing_packets > 0

# Agent stopped producing frames: long arrival gap but the sequence only advanced once
tracefox.arrival_delta_seconds > 6 && tracefox.sequence_delta == 1

# Agent generated intermediate frames, but they did not reach this capture point
tracefox.arrival_delta_seconds > 6 && tracefox.missing_packets > 0

# Agent restart, sequence reset, or UDP reordering
tracefox.sequence_regression == 1
```

For the reported `17:31:07 → 17:31:47` gap:

- `sequence_delta == 1` means the Agent loop was blocked or suspended for about
  35 seconds beyond its normal five-second interval.
- `sequence_delta == 8` and `missing_packets == 7` means seven frames were built
  but failed to reach the capture point.

Right-click `Sequence`, `Arrival delta`, `Sequence delta`, and `Missing packets`
in the packet details pane and choose **Apply as Column** for a compact diagnostic
view. The arrival-gap threshold can be changed under
**Preferences → Protocols → TraceFox Telemetry**.

Tracking is keyed by `host_label` when present, otherwise by source IP. Source
UDP ports are intentionally ignored so an Agent restart remains visible.
