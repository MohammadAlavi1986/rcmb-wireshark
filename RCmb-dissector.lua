rcmb_protocol = Proto("RCmb", "RCmb Protocol")

version_F = ProtoField.uint16("rcmb.version", "Version")
port_F = ProtoField.uint16("rcmb.port", "Port")
type_F = ProtoField.string("rcmb.type", "Type")
count_F = ProtoField.uint16("rcmb.count", "Count")
currentEpoch_F = ProtoField.uint64("rcmb.current_epoch", "CurrentEpoch")
configEpoch_F = ProtoField.uint64("rcmb.config_epoch", "ConfigEpoch")
replicationOffset_F = ProtoField.uint64("rcmb.replication_offset", "ReplicationOffset")
sender_F = ProtoField.string("rcmb.sender", "Sender")
hashSlots_F = ProtoField.string("rcmb.hash_slots", "HashSlots")
slaveOf_F = ProtoField.string("rcmb.slave_of", "SlaveOf")
myIP_F = ProtoField.string("rcmb.my_ip", "MyIP")
ip_F = ProtoField.string("rcmb.ip", "IP")
extensions_F = ProtoField.uint16("rcmb.extensions", "Extensions")
pport_F = ProtoField.uint16("rcmb.pport", "SecondaryPort")
cport_F = ProtoField.uint16("rcmb.cport", "ClusterBusPort")
flags_F = ProtoField.string("rcmb.flags", "Flags")
state_F = ProtoField.string("rcmb.state", "ClusterState")
mflags_F = ProtoField.string("rcmb.mflags", "MessageFlags")
nodeName_F = ProtoField.string("rcmb.node_name", "NodeName")
pingSent_F = ProtoField.uint32("rcmb.ping_sent", "PingSent")
pingReceived_F = ProtoField.uint32("rcmb.pong_received", "PingReceived")
channel_F = ProtoField.string("rcmb.channel", "Channel")
message_F = ProtoField.string("rcmb.message", "Message")

CLUSTERMSG_TYPE_PING = 0
CLUSTERMSG_TYPE_PONG = 1
CLUSTERMSG_TYPE_MEET = 2
CLUSTERMSG_TYPE_FAIL = 3
CLUSTERMSG_TYPE_PUBLISH = 4
CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST = 5
CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK = 6
CLUSTERMSG_TYPE_UPDATE = 7
CLUSTERMSG_TYPE_MFSTART = 8
CLUSTERMSG_TYPE_MODULE = 9
CLUSTERMSG_TYPE_PUBLISHSHARD = 10
CLUSTERMSG_TYPE_COUNT = 11

CLUSTER_NODE_MASTER = 1
CLUSTER_NODE_SLAVE = 2
CLUSTER_NODE_PFAIL = 4
CLUSTER_NODE_FAIL = 8
CLUSTER_NODE_MYSELF = 16
CLUSTER_NODE_HANDSHAKE = 32
CLUSTER_NODE_NOADDR = 64
CLUSTER_NODE_MEET = 128
CLUSTER_NODE_MIGRATE_TO = 256
CLUSTER_NODE_NOFAILOVER = 512

CLUSTERMSG_FLAG0_PAUSED = 1
CLUSTERMSG_FLAG0_FORCEACK = 2
CLUSTERMSG_FLAG0_EXT_DATA = 4

local msg_types = {
    [CLUSTERMSG_TYPE_PING] = "PING",
    [CLUSTERMSG_TYPE_PONG] = "PONG",
    [CLUSTERMSG_TYPE_MEET] = "MEET",
    [CLUSTERMSG_TYPE_FAIL] = "FAIL",
    [CLUSTERMSG_TYPE_PUBLISH] = "PUBLISH",
    [CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST] = "FAILOVER_AUTH_REQUEST",
    [CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK] = "FAILOVER_AUTH_ACK",
    [CLUSTERMSG_TYPE_UPDATE] = "UPDATE",
    [CLUSTERMSG_TYPE_MFSTART] = "MFSTART",
    [CLUSTERMSG_TYPE_MODULE] = "MODULE",
    [CLUSTERMSG_TYPE_PUBLISHSHARD] = "PUBLISHSHARD",
    [CLUSTERMSG_TYPE_COUNT] = "COUNT"
}
hashSlotsCache = {}

tcp_src_f = Field.new("tcp.srcport")
tcp_dst_f = Field.new("tcp.dstport")

rcmb_protocol.fields = { channel_F, message_F, ip_F, nodeName_F, pingSent_F, pingReceived_F, version_F, port_F, type_F, count_F, currentEpoch_F, configEpoch_F, replicationOffset_F, sender_F, hashSlots_F, slaveOf_F, extensions_F, pport_F, cport_F, flags_F, state_F, mflags_F }

local function flags_to_string(flags)
    local flags_str = ""

    if bit.band(flags, CLUSTER_NODE_MASTER) ~= 0 then
        flags_str = flags_str .. "MASTER | "
    end
    if bit.band(flags, CLUSTER_NODE_SLAVE) ~= 0 then
        flags_str = flags_str .. "SLAVE | "
    end
    if bit.band(flags, CLUSTER_NODE_PFAIL) ~= 0 then
        flags_str = flags_str .. "PFAIL | "
    end
    if bit.band(flags, CLUSTER_NODE_FAIL) ~= 0 then
        flags_str = flags_str .. "FAIL | "
    end
    if bit.band(flags, CLUSTER_NODE_MYSELF) ~= 0 then
        flags_str = flags_str .. "MYSELF | "
    end
    if bit.band(flags, CLUSTER_NODE_HANDSHAKE) ~= 0 then
        flags_str = flags_str .. "HANDSHAKE | "
    end
    if bit.band(flags, CLUSTER_NODE_NOADDR) ~= 0 then
        flags_str = flags_str .. "NOADDR | "
    end
    if bit.band(flags, CLUSTER_NODE_MEET) ~= 0 then
        flags_str = flags_str .. "MEET | "
    end
    if bit.band(flags, CLUSTER_NODE_MIGRATE_TO) ~= 0 then
        flags_str = flags_str .. "MIGRATE_TO | "
    end
    if bit.band(flags, CLUSTER_NODE_NOFAILOVER) ~= 0 then
        flags_str = flags_str .. "NOFAILOVER | "
    end
    if string.len(flags_str) > 0 then
        flags_str = string.sub(flags_str, 1, string.len(flags_str) - 3)
    end

    return string.format("0x%04X (%s)", flags, flags_str)
end

local function mflags_to_string(mflags)
    local mflags_str = ""

    if bit.band(mflags, CLUSTERMSG_FLAG0_PAUSED) ~= 0 then
        mflags_str = mflags_str .. "PAUSED | "
    end
    if bit.band(mflags, CLUSTERMSG_FLAG0_FORCEACK) ~= 0 then
        mflags_str = mflags_str .. "FORCEACK | "
    end
    if bit.band(mflags, CLUSTERMSG_FLAG0_EXT_DATA) ~= 0 then
        mflags_str = mflags_str .. "EXT_DATA | "
    end
    if string.len(mflags_str) > 0 then
        mflags_str = string.sub(mflags_str, 1, string.len(mflags_str) - 3)
        return string.format("0x%02X (%s)", mflags, mflags_str)
    else
        return string.format("0x%02X", mflags)
    end
end

local function hash_slots_to_string(slots)
    local s, e = -1, -1 -- start, end
    local str = ""

    local hashSlotsCacheKey = slots:tohex()
    if hashSlotsCache[hashSlotsCacheKey] == nil then
        for i = 0, 16384 do
            -- if (slots[i>>3] & (1 << (i % 8)))
            if i < 16384 and bit.band(slots:get_index(bit.rshift(i, 3)), bit.lshift(1, i % 8)) ~= 0 then
                if s == -1 then
                    s = i
                    e = i
                else
                    e = i
                end
            else
                if s ~= -1 then
                    if str ~= "" then
                        str = str .. ", "
                    end
                    if s == e then
                        str = str .. tostring(s)
                    else
                        str = str .. tostring(s) .. "-" .. tostring(e)
                    end
                    s, e = -1, -1
                end
            end
        end
        str = "[" .. str .. "]"
        hashSlotsCache[hashSlotsCacheKey] = str
    else
        str = hashSlotsCache[hashSlotsCacheKey]
    end
    return str
end
sourcePortToClusterPort = {}
function rcmb_protocol.dissector(buffer, pinfo, tree)
    local buf_len = buffer:len()
    if buf_len < 8 then
        return
    end
    if buffer(0, 4):string() ~= "RCmb" then
        return
    end
    local msg_len = buffer(4, 4):uint()
    if buf_len < msg_len then
        pinfo.desegment_offset = 0
        pinfo.desegment_len = msg_len
        return
    end

    pinfo.cols.protocol = "RCmb"
    local subtree = tree:add(rcmb_protocol, buffer(), "RCmb Protocol Data")
    local offset = 8
    subtree:add(version_F, buffer(offset, 2))
    offset = offset + 2
    subtree:add(port_F, buffer(offset, 2))
    offset = offset + 2
    local msg_type = buffer(offset, 2):uint()
    subtree:add(type_F, buffer(offset, 2), msg_types[msg_type])
    offset = offset + 2
    local msg_count = buffer(offset, 2):uint()
    subtree:add(count_F, buffer(offset, 2))
    offset = offset + 2
    current_epoch = buffer(offset, 8):uint64()
    subtree:add(currentEpoch_F, buffer(offset, 8))
    offset = offset + 8
    config_epoch = buffer(offset, 8):uint64()
    subtree:add(configEpoch_F, buffer(offset, 8))
    offset = offset + 8
    subtree:add(replicationOffset_F, buffer(offset, 8))
    offset = offset + 8
    subtree:add(sender_F, buffer(offset, 40), buffer(offset, 40):string())
    offset = offset + 40

    subtree:add(hashSlots_F, buffer(offset, 16384 / 8), hash_slots_to_string(buffer(offset, 16384 / 8):bytes()))
    offset = offset + 16384 / 8

    subtree:add(slaveOf_F, buffer(offset, 40), buffer(offset, 40):string())
    offset = offset + 40
    subtree:add(ip_F, buffer(offset, 46), buffer(offset, 46):string())
    offset = offset + 46
    subtree:add(extensions_F, buffer(offset, 2))
    offset = offset + 2
    offset = offset + 30
    subtree:add(pport_F, buffer(offset, 2))
    offset = offset + 2
    cluster_port = buffer(offset, 2):uint()
    subtree:add(cport_F, buffer(offset, 2))
    if msg_type == CLUSTERMSG_TYPE_PING then
        sourcePortToClusterPort[tostring(tcp_src_f())] = cluster_port
    end

    offset = offset + 2
    flags = buffer(offset, 2):uint()
    is_master = bit.band(flags, CLUSTER_NODE_MASTER) ~= 0
    is_slave = bit.band(flags, CLUSTER_NODE_SLAVE) ~= 0
    subtree:add(flags_F, buffer(offset, 2), flags_to_string(flags))
    offset = offset + 2

    local clusterState = "OK"
    if buffer(offset, 1):uint() == 1 then
        clusterState = "FAIL"
    end
    subtree:add(state_F, buffer(offset, 1), clusterState)
    offset = offset + 1

    subtree:add(mflags_F, buffer(offset, 3), mflags_to_string(buffer(offset, 1):uint()))
    offset = offset + 3

    if msg_count == 0 and msg_type ~= CLUSTERMSG_TYPE_PING and msg_type ~= CLUSTERMSG_TYPE_PONG and msg_type ~= CLUSTERMSG_TYPE_MEET then
        msg_count = 1
    end
    for i = 1, msg_count do
        if msg_type == CLUSTERMSG_TYPE_PING or msg_type == CLUSTERMSG_TYPE_PONG or msg_type == CLUSTERMSG_TYPE_MEET then
            local data_tree = subtree:add(buffer(offset, 40 + 4 + 4 + 46 + 2 + 2 + 2 + 2 + 2), "MsgDataGossip")
            data_tree:add(nodeName_F, buffer(offset, 40), buffer(offset, 40):string())
            offset = offset + 40
            data_tree:add(pingSent_F, buffer(offset, 4))
            offset = offset + 4
            data_tree:add(pingReceived_F, buffer(offset, 4))
            offset = offset + 4
            data_tree:add(ip_F, buffer(offset, 46), buffer(offset, 46):string())
            offset = offset + 46
            data_tree:add(port_F, buffer(offset, 2))
            offset = offset + 2
            data_tree:add(cport_F, buffer(offset, 2))
            offset = offset + 2
            data_tree:add(flags_F, buffer(offset, 2), flags_to_string(buffer(offset, 2):uint()))
            offset = offset + 2
            data_tree:add(pport_F, buffer(offset, 2))
            offset = offset + 2
            offset = offset + 2
        elseif msg_type == CLUSTERMSG_TYPE_FAIL then
            -- fail
            local data_tree = subtree:add(buffer(offset, 40), "MsgDataFail")
            data_tree:add(nodeName_F, buffer(offset, 40), buffer(offset, 40):string())
            offset = offset + 40
        elseif msg_type == CLUSTERMSG_TYPE_PUBLISH or msg_type == CLUSTERMSG_TYPE_PUBLISHSHARD then
            -- publish
            local channel_len = buffer(offset, 4):uint()
            local message_len = buffer(offset + 4, 4):uint()
            local data_tree = subtree:add(buffer(offset, 4 + 4 + channel_len + message_len), "MsgDataPublish")
            offset = offset + 4
            offset = offset + 4
            data_tree:add(channel_F, buffer(offset, channel_len), buffer(offset, channel_len):string())
            offset = offset + channel_len
            data_tree:add(message_F, buffer(offset, message_len), buffer(offset, message_len):string())
            offset = offset + message_len
        elseif msg_type == CLUSTERMSG_TYPE_UPDATE then
            -- update
            local data_tree = subtree:add(buffer(offset, 8 + 40 + 16384 / 8), "MsgDataUpdate")
            data_tree:add(configEpoch_F, buffer(offset, 8))
            offset = offset + 8
            data_tree:add(nodeName_F, buffer(offset, 40), buffer(offset, 40):string())
            offset = offset + 40
            data_tree:add(hashSlots_F, buffer(offset, 16384 / 8), hash_slots_to_string(buffer(offset, 16384 / 8):bytes()))
            offset = offset + 16384 / 8
        elseif msg_type == CLUSTERMSG_TYPE_MODULE then
            -- module
            local data_tree = subtree:add(buffer(offset, 8 + 4 + 4 + 3), "MsgModule")
            offset = offset + 8 + 4 + 4 + 3
        end
    end
    local src_port_str = tostring(tcp_src_f())
    local dst_port_str = tostring(tcp_dst_f())
    if tostring(cluster_port) ~= src_port_str then
        src_port_str = src_port_str .. "[" .. cluster_port .. "]"
    end
    local target_cluster_port = sourcePortToClusterPort[tostring(tcp_dst_f())]
    if target_cluster_port ~= nil then
        dst_port_str = dst_port_str .. "[" .. target_cluster_port .. "]"
    end
    info_str = msg_types[msg_type] .. " (" .. src_port_str .. "->" .. dst_port_str .. ")"
    info_str = info_str ..  " CurrentEpoch=" .. current_epoch .. " ConfigEpoch=" .. config_epoch
    if is_master then
        info_str = info_str .. " MASTER"
    end
    if is_slave then
        info_str = info_str .. " SLAVE"
    end
    pinfo.cols.info = info_str
end


-- load the tcp.port table
tcp_table = DissectorTable.get("tcp.port")
-- register rcmb protocol to handle tcp port 17000, 17001, 17002, 17003, 17004, 17005
tcp_table:add(17000, rcmb_protocol)
tcp_table:add(17001, rcmb_protocol)
tcp_table:add(17002, rcmb_protocol)
tcp_table:add(17003, rcmb_protocol)
tcp_table:add(17004, rcmb_protocol)
tcp_table:add(17005, rcmb_protocol)
