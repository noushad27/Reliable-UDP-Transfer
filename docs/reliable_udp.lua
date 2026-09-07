-- Custom Reliable UDP Protocol Dissector for Wireshark
-- File: reliable_udp.lua
-- Place in %APPDATA%/Wireshark/plugins/ or load via Wireshark -> Analyze -> Reload Lua Plugins (Ctrl+Shift+L)

local reliable_udp_proto = Proto("reliable_udp", "Custom Reliable UDP File Transfer Protocol")

-- Header Fields
local f_magic       = ProtoField.string("reliable_udp.magic", "Magic Identifier")
local f_version     = ProtoField.uint8("reliable_udp.version", "Version", base.DEC)
local f_pkt_type    = ProtoField.uint8("reliable_udp.pkt_type", "Packet Type", base.HEX, {
    [1] = "START (0x01)",
    [2] = "DATA (0x02)",
    [3] = "ACK (0x03)",
    [4] = "START_ACK (0x04)",
    [5] = "FIN (0x05)",
    [6] = "FIN_ACK (0x06)",
    [7] = "ERROR (0x07)"
})
local f_session_id  = ProtoField.uint32("reliable_udp.session_id", "Session ID", base.DEC)
local f_seq_num     = ProtoField.uint32("reliable_udp.seq_num", "Sequence Number", base.DEC)
local f_ack_num     = ProtoField.uint32("reliable_udp.ack_num", "Acknowledgment Number", base.DEC)
local f_payload_len = ProtoField.uint16("reliable_udp.payload_len", "Payload Length (Bytes)", base.DEC)
local f_checksum    = ProtoField.uint32("reliable_udp.checksum", "CRC32 Checksum", base.HEX)
local f_payload     = ProtoField.bytes("reliable_udp.payload", "Payload Data")

reliable_udp_proto.fields = {
    f_magic, f_version, f_pkt_type, f_session_id,
    f_seq_num, f_ack_num, f_payload_len, f_checksum, f_payload
}

local PKT_TYPE_NAMES = {
    [1] = "START",
    [2] = "DATA",
    [3] = "ACK",
    [4] = "START_ACK",
    [5] = "FIN",
    [6] = "FIN_ACK",
    [7] = "ERROR"
}

function reliable_udp_proto.dissector(buffer, pinfo, tree)
    local length = buffer:len()
    if length < 22 then return end

    -- Check Magic 'RD' (0x52 0x44)
    local magic_val = buffer(0, 2):string()
    if magic_val ~= "RD" then return end

    pinfo.cols.protocol = "RELIABLE-UDP"

    local subtree = tree:add(reliable_udp_proto, buffer(), "Custom Reliable UDP Header")

    local version = buffer(2, 1):uint()
    local pkt_type = buffer(3, 1):uint()
    local session_id = buffer(4, 4):uint()
    local seq_num = buffer(8, 4):uint()
    local ack_num = buffer(12, 4):uint()
    local payload_len = buffer(16, 2):uint()
    local checksum = buffer(18, 4):uint()

    local type_name = PKT_TYPE_NAMES[pkt_type] or string.format("UNKNOWN(0x%02X)", pkt_type)

    subtree:add(f_magic, buffer(0, 2))
    subtree:add(f_version, buffer(2, 1))
    subtree:add(f_pkt_type, buffer(3, 1))
    subtree:add(f_session_id, buffer(4, 4))
    subtree:add(f_seq_num, buffer(8, 4))
    subtree:add(f_ack_num, buffer(12, 4))
    subtree:add(f_payload_len, buffer(16, 2))
    subtree:add(f_checksum, buffer(18, 4))

    if length > 22 then
        subtree:add(f_payload, buffer(22, length - 22))
    end

    -- Update Wireshark Info column
    if pkt_type == 2 then -- DATA
        pinfo.cols.info = string.format("[%s] Seq=#%d, Len=%d B (Session %d)", type_name, seq_num, payload_len, session_id)
    elseif pkt_type == 3 then -- ACK
        pinfo.cols.info = string.format("[%s] Ack=#%d (Session %d)", type_name, ack_num, session_id)
    elseif pkt_type == 1 then -- START
        pinfo.cols.info = string.format("[%s] New Session %d Handshake", type_name, session_id)
    elseif pkt_type == 4 then -- START_ACK
        pinfo.cols.info = string.format("[%s] Session %d Confirmed", type_name, session_id)
    elseif pkt_type == 5 then -- FIN
        pinfo.cols.info = string.format("[%s] Session %d Teardown", type_name, session_id)
    elseif pkt_type == 6 then -- FIN_ACK
        pinfo.cols.info = string.format("[%s] Session %d Complete", type_name, session_id)
    else
        pinfo.cols.info = string.format("[%s] Session %d", type_name, session_id)
    end
end

-- Register dissector for default port 9000
local udp_port = DissectorTable.get("udp.port")
udp_port:add(9000, reliable_udp_proto)
