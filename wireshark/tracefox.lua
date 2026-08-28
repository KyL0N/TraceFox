-- TraceFox TLV v2 dissector for Wireshark.
-- SPDX-License-Identifier: MIT

local DEFAULT_UDP_PORT = 9000
local HEADER_LENGTH = 12
local MAGIC = 0x5446
local VERSION = 2
local UINT32_MODULUS = 4294967296
local WRAP_WINDOW = 65536

local TLV_TYPES = {
    [0x01] = "CPU",
    [0x02] = "Memory and load",
    [0x03] = "Host label",
    [0x04] = "Network",
    [0x05] = "Disk",
    [0x06] = "Filesystem",
    [0x07] = "Process group",
    [0x08] = "Thread group",
}

local tracefox = Proto("tracefox", "TraceFox Telemetry")

local f_magic = ProtoField.uint16("tracefox.magic", "Magic", base.HEX)
local f_version = ProtoField.uint8("tracefox.version", "Version", base.DEC)
local f_reserved = ProtoField.uint8("tracefox.reserved", "Reserved", base.HEX)
local f_timestamp = ProtoField.uint32("tracefox.timestamp", "Agent timestamp", base.DEC)
local f_timestamp_utc = ProtoField.absolute_time("tracefox.timestamp_utc", "Agent timestamp (UTC)", base.UTC)
local f_sequence = ProtoField.uint32("tracefox.seq", "Sequence", base.DEC)
local f_host_label = ProtoField.string("tracefox.host_label", "Host label", base.ASCII)
local f_tlv_type = ProtoField.uint8("tracefox.tlv.type", "TLV type", base.HEX, TLV_TYPES)
local f_tlv_length = ProtoField.uint8("tracefox.tlv.length", "TLV length", base.DEC)
local f_tlv_value = ProtoField.bytes("tracefox.tlv.value", "TLV value")

local f_stream = ProtoField.string("tracefox.stream", "Tracking stream")
local f_previous_frame = ProtoField.framenum("tracefox.previous_frame", "Previous TraceFox frame")
local f_arrival_delta = ProtoField.double("tracefox.arrival_delta_seconds", "Arrival delta (seconds)")
local f_timestamp_delta = ProtoField.double("tracefox.timestamp_delta_seconds", "Agent timestamp delta (seconds)")
local f_sequence_delta = ProtoField.uint32("tracefox.sequence_delta", "Sequence delta", base.DEC)
local f_missing_packets = ProtoField.uint32("tracefox.missing_packets", "Missing packets", base.DEC)
local f_sequence_gap = ProtoField.bool("tracefox.sequence_gap", "Sequence gap")
local f_sequence_regression = ProtoField.bool("tracefox.sequence_regression", "Sequence regression or reset")
local f_duplicate_sequence = ProtoField.bool("tracefox.duplicate_sequence", "Duplicate sequence")
local f_arrival_gap = ProtoField.bool("tracefox.arrival_gap", "Arrival gap")

tracefox.fields = {
    f_magic,
    f_version,
    f_reserved,
    f_timestamp,
    f_timestamp_utc,
    f_sequence,
    f_host_label,
    f_tlv_type,
    f_tlv_length,
    f_tlv_value,
    f_stream,
    f_previous_frame,
    f_arrival_delta,
    f_timestamp_delta,
    f_sequence_delta,
    f_missing_packets,
    f_sequence_gap,
    f_sequence_regression,
    f_duplicate_sequence,
    f_arrival_gap,
}

local ex_malformed_tlv = ProtoExpert.new(
    "tracefox.expert.malformed_tlv",
    "Malformed TraceFox TLV",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local ex_sequence_gap = ProtoExpert.new(
    "tracefox.expert.sequence_gap",
    "TraceFox sequence gap",
    expert.group.SEQUENCE,
    expert.severity.WARN
)
local ex_sequence_regression = ProtoExpert.new(
    "tracefox.expert.sequence_regression",
    "TraceFox sequence regression or reset",
    expert.group.SEQUENCE,
    expert.severity.WARN
)
local ex_arrival_gap = ProtoExpert.new(
    "tracefox.expert.arrival_gap",
    "TraceFox arrival gap",
    expert.group.SEQUENCE,
    expert.severity.WARN
)

tracefox.experts = {
    ex_malformed_tlv,
    ex_sequence_gap,
    ex_sequence_regression,
    ex_arrival_gap,
}

tracefox.prefs.gap_threshold_seconds = Pref.uint(
    "Arrival gap threshold (seconds)",
    6,
    "Mark a packet when the previous TraceFox packet for the same stream arrived more than this many seconds earlier"
)

local stream_states = {}
local frame_analyses = {}

local function reset_tracking()
    stream_states = {}
    frame_analyses = {}
end

function tracefox.init()
    reset_tracking()
end

function tracefox.prefs_changed()
    reset_tracking()
end

local function add_generated(parent, field, value)
    return parent:add(field, value):set_generated()
end

local function scan_tlvs(buffer)
    local entries = {}
    local host_label = nil
    local offset = HEADER_LENGTH
    local buffer_length = buffer:len()

    while offset < buffer_length do
        local remaining = buffer_length - offset
        if remaining < 2 then
            table.insert(entries, {
                offset = offset,
                total_length = remaining,
                malformed = "truncated TLV header",
            })
            break
        end

        local tlv_type = buffer(offset, 1):uint()
        local tlv_length = buffer(offset + 1, 1):uint()
        local available = remaining - 2
        local value_length = math.min(tlv_length, available)
        local entry = {
            offset = offset,
            type = tlv_type,
            length = tlv_length,
            value_offset = offset + 2,
            value_length = value_length,
            total_length = 2 + value_length,
        }

        if tlv_length > available then
            entry.malformed = string.format(
                "TLV declares %d value bytes, but only %d remain",
                tlv_length,
                available
            )
        elseif tlv_type == 0x03 and tlv_length > 0 then
            host_label = buffer(entry.value_offset, tlv_length):string()
        end

        table.insert(entries, entry)
        if entry.malformed then
            break
        end
        offset = offset + 2 + tlv_length
    end

    return entries, host_label
end

local function make_stream_key(pinfo, host_label)
    local identity = host_label
    if identity == nil or identity == "" then
        identity = tostring(pinfo.src)
    end
    return string.format("%s -> %s:%d", identity, tostring(pinfo.dst), pinfo.dst_port)
end

local function forward_sequence_delta(previous, current)
    if current >= previous then
        return current - previous, false
    end

    if previous >= UINT32_MODULUS - WRAP_WINDOW and current < WRAP_WINDOW then
        return (UINT32_MODULUS - previous) + current, false
    end

    return nil, true
end

local function analyse_frame(pinfo, stream_key, timestamp, sequence)
    local frame_number = tonumber(pinfo.number)
    local cached = frame_analyses[frame_number]
    if cached ~= nil then
        return cached
    end

    local analysis = {
        stream = stream_key,
        missing_packets = 0,
        sequence_gap = false,
        sequence_regression = false,
        duplicate_sequence = false,
        arrival_gap = false,
    }
    local capture_time = pinfo.abs_ts:tonumber()
    local previous = stream_states[stream_key]

    if previous ~= nil and frame_number > previous.frame_number then
        analysis.previous_frame = previous.frame_number
        analysis.arrival_delta = capture_time - previous.capture_time
        analysis.timestamp_delta = timestamp - previous.timestamp

        local sequence_delta, sequence_regression = forward_sequence_delta(previous.sequence, sequence)
        analysis.sequence_delta = sequence_delta
        analysis.sequence_regression = sequence_regression

        if sequence_delta ~= nil then
            analysis.duplicate_sequence = sequence_delta == 0
            if sequence_delta > 1 then
                analysis.missing_packets = sequence_delta - 1
                analysis.sequence_gap = true
            end
        end

        local gap_threshold = tonumber(tracefox.prefs.gap_threshold_seconds) or 6
        analysis.arrival_gap = analysis.arrival_delta > gap_threshold
    end

    frame_analyses[frame_number] = analysis
    if previous == nil or frame_number > previous.frame_number then
        stream_states[stream_key] = {
            frame_number = frame_number,
            capture_time = capture_time,
            timestamp = timestamp,
            sequence = sequence,
        }
    end

    return analysis
end

local function add_tlv_tree(root, buffer, entry)
    if entry.type == nil then
        local trailing = root:add(buffer(entry.offset, entry.total_length), "Malformed TLV")
        trailing:add_proto_expert_info(ex_malformed_tlv, entry.malformed)
        return
    end

    local type_name = TLV_TYPES[entry.type] or string.format("Unknown 0x%02x", entry.type)
    local label = string.format("%s TLV (%d bytes)", type_name, entry.length)
    local tlv_tree = root:add(buffer(entry.offset, entry.total_length), label)
    tlv_tree:add(f_tlv_type, buffer(entry.offset, 1))
    tlv_tree:add(f_tlv_length, buffer(entry.offset + 1, 1))
    if entry.value_length > 0 then
        tlv_tree:add(f_tlv_value, buffer(entry.value_offset, entry.value_length))
    end
    if entry.type == 0x03 and entry.malformed == nil and entry.length > 0 then
        tlv_tree:add(f_host_label, buffer(entry.value_offset, entry.length))
    end
    if entry.malformed ~= nil then
        tlv_tree:add_proto_expert_info(ex_malformed_tlv, entry.malformed)
    end
end

function tracefox.dissector(buffer, pinfo, tree)
    if buffer:len() < HEADER_LENGTH then
        return 0
    end

    local magic = buffer(0, 2):uint()
    local version = buffer(2, 1):uint()
    if magic ~= MAGIC or version ~= VERSION then
        return 0
    end

    local timestamp = buffer(4, 4):uint()
    local sequence = buffer(8, 4):uint()
    local tlvs, host_label = scan_tlvs(buffer)
    local stream_key = make_stream_key(pinfo, host_label)
    local analysis = analyse_frame(pinfo, stream_key, timestamp, sequence)

    pinfo.cols.protocol = "TFOX"
    local info = { string.format("v%d seq=%d", version, sequence) }
    if host_label ~= nil and host_label ~= "" then
        table.insert(info, "host=" .. host_label)
    end
    if analysis.missing_packets > 0 then
        table.insert(info, string.format("MISSING=%d", analysis.missing_packets))
    end
    if analysis.sequence_regression then
        table.insert(info, "SEQ-REGRESSION/RESET")
    elseif analysis.duplicate_sequence then
        table.insert(info, "DUPLICATE-SEQ")
    end
    if analysis.arrival_gap and analysis.arrival_delta ~= nil then
        table.insert(info, string.format("GAP=%.3fs", analysis.arrival_delta))
    end
    pinfo.cols.info = table.concat(info, " ")

    local root = tree:add(tracefox, buffer())
    root:append_text(string.format(", seq=%d", sequence))
    root:add(f_magic, buffer(0, 2))
    root:add(f_version, buffer(2, 1))
    root:add(f_reserved, buffer(3, 1))
    root:add(f_timestamp, buffer(4, 4))
    add_generated(root, f_timestamp_utc, NSTime.new(timestamp, 0))
    root:add(f_sequence, buffer(8, 4))

    for _, entry in ipairs(tlvs) do
        add_tlv_tree(root, buffer, entry)
    end

    add_generated(root, f_stream, analysis.stream)
    if analysis.previous_frame ~= nil then
        add_generated(root, f_previous_frame, analysis.previous_frame)
    end
    if analysis.arrival_delta ~= nil then
        add_generated(root, f_arrival_delta, analysis.arrival_delta)
    end
    if analysis.timestamp_delta ~= nil then
        add_generated(root, f_timestamp_delta, analysis.timestamp_delta)
    end
    if analysis.sequence_delta ~= nil then
        add_generated(root, f_sequence_delta, analysis.sequence_delta)
    end
    add_generated(root, f_missing_packets, analysis.missing_packets)
    add_generated(root, f_sequence_gap, analysis.sequence_gap)
    add_generated(root, f_sequence_regression, analysis.sequence_regression)
    add_generated(root, f_duplicate_sequence, analysis.duplicate_sequence)
    add_generated(root, f_arrival_gap, analysis.arrival_gap)

    if analysis.sequence_gap then
        root:add_proto_expert_info(
            ex_sequence_gap,
            string.format(
                "Sequence advanced by %d; %d packet(s) are missing",
                analysis.sequence_delta,
                analysis.missing_packets
            )
        )
    end
    if analysis.sequence_regression then
        root:add_proto_expert_info(
            ex_sequence_regression,
            "Sequence moved backwards; the Agent may have restarted or packets may be reordered"
        )
    end
    if analysis.arrival_gap then
        root:add_proto_expert_info(
            ex_arrival_gap,
            string.format("%.3f seconds since the previous TraceFox packet", analysis.arrival_delta)
        )
    end

    return buffer:len()
end

local udp_port_table = DissectorTable.get("udp.port")
udp_port_table:add(DEFAULT_UDP_PORT, tracefox)
udp_port_table:add_for_decode_as(tracefox)
