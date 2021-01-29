local neo_protocol = Proto("neo3", "NEO3 Blockchain")

local dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

local message_type_table = {
    [0x00] = "VERSION",
    [0x01] = "VERACK",
    [0x10] = "GETADDR",
    [0x11] = "ADDR",
    [0x18] = "PING",
    [0x19] = "PONG",
    [0x20] = "GETHEADERS",
    [0x21] = "HEADERS",
    [0x24] = "GETBLOCKS",
    [0x25] = "MEMPOOL",
    [0x27] = "INV",
    [0x28] = "GETDATA",
    [0x29] = "GETBLOCKBYINDEX",
    [0x2A] = "NOTFOUND",
    [0x2B] = "TRANSACTION",
    [0x2C] = "BLOCK",
    [0x2D] = "CONSENSUS",
    [0x2F] = "REJECT",
    [0x30] = "FILTERLOAD",
    [0x31] = "FILTERADD",
    [0x32] = "FILTERCLEAR",
    [0x38] = "MERKLEBLOCK",
    [0x40] = "ALERT"
}

local message_config_table = {
    [0] = "NONE",
    [1] = "COMPRESSED"
}

local node_capabilities = {
    [0x01] = "TCPSERVER",
    [0x02] = "WSSERVER",
    [0x10] = "FULLNODE"
}

local inventory_type = {
    [0x2b] = "TX",
    [0x2c] = "BLOCK",
    [0x2d] = "CONSENSUS"
}

local pf_message_config = ProtoField.uint8("neo3.message.config","Config", base.HEX, message_config_table)
local pf_message_type   = ProtoField.uint8("neo3.message.type","Type", base.HEX, message_type_table)
local pf_payload        = ProtoField.new("Payload", "neo3.message.payload", ftypes.STRING)
local pf_payload_size   = ProtoField.new("Size", "neo3.payload.size", ftypes.UINT32)

local ef_message_too_short = ProtoExpert.new("neo3.too_short.message.expert", "Message too short", expert.group.MALFORMED, expert.severity.ERROR)
local ef_payload_too_short = ProtoExpert.new("neo3.too_short.payload.expert", "Payload too short", expert.group.MALFORMED, expert.severity.ERROR)

local pf_version_magic      = ProtoField.uint32("neo3.payload.version.magic", "Network magic", base.DEC)
local pf_version_version    = ProtoField.uint32("neo3.payload.version.version", "Network version", base.HEX)
local pf_version_timestamp  = ProtoField.absolute_time("neo3.payload.version.timestamp", "Timestamp", base.LOCAL)
local pf_version_nonce      = ProtoField.uint32("neo3.payload.version.nonce", "Nonce", base.HEX)
local pf_version_useragent  = ProtoField.string("neo3.payload.version.useragent", "User agent", base.ASCII)
local pf_version_capabilities = ProtoField.uint8("neo3.payload.version.capabilities", "Capabilities", base.DEC)
local pf_version_capabilities_type = ProtoField.uint8("neo3.payload.version.capabilities.type", "Type", base.HEX, node_capabilities)
local pf_version_capabilities_start_height = ProtoField.uint32("neo3.payload.version.capabilities.start_height", "Start Height", base.DEC)
local pf_version_capabilities_port = ProtoField.uint16("neo3.payload.version.capabilities.port", "Port", base.DEC)
local MAX_NODE_CAPABILITIES = 32

local pf_getheaders_start_hash = ProtoField.new("Start Hash","neo3.payload.getheaders.start_hash",ftypes.BYTES, base.HEX)
local pf_getheaders_count = ProtoField.int16("neo3.payload.getheaders.count", "Count", base.DEC)
local MAX_GETHEADERS = 2000

local pf_inventory_type = ProtoField.uint8("neo3.payload.inventory.type","Type", base.HEX, inventory_type)
local pf_hashes_label = ProtoField.uint8("neo3.payload.hashes", "Hashes", base.DEC)
local pf_hash_with_idx = ProtoField.new("Hash", "neo3.payload", ftypes.BYTES)
local MAX_INVENTORY_HASHES = 500

local pf_getblockbyindex_index_start = ProtoField.uint32("neo3.payload.getblockbyindex.indexstart", "Index start", base.DEC)
local pf_getblockbyindex_count = ProtoField.uint16("neo3.payload.getblockbyindex.count", "Count", base.DEC)

local pf_ping_lastblockindex = ProtoField.uint32("neo3.payload.ping.lastblockindex", "Last block index", base.DEC)
local pf_ping_nonce      = ProtoField.uint32("neo3.payload.ping.nonce", "Nonce", base.HEX)
local pf_ping_timestamp  = ProtoField.absolute_time("neo3.payload.ping.timestamp", "Timestamp", base.LOCAL)

local pf_block_version = ProtoField.uint32("neo3.payload.block.version", "Version", base.DEC)
local pf_block_prev_hash = ProtoField.new("PrevHash", "neo3.payload.block.prevhash", ftypes.BYTES)
local pf_block_merkle_root = ProtoField.new("MerkleRoot", "neo3.payload.block.merkleroot", ftypes.BYTES)
local pf_block_timestamp = ProtoField.uint64("neo3.payload.block.timestamp", "Timestamp", base.DEC)
local pf_block_index = ProtoField.uint32("neo3.payload.block.index", "Index", base.DEC)
local pf_block_nextconsensus = ProtoField.new("PrevHash", "neo3.payload.block.nextconsensus", ftypes.BYTES)

local function read_var_int(tvbuf, start_idx, max)
    -- max is max bytes to read
    -- return (payload length, variable length byte count)
    local fb = tvbuf(start_idx, 1):uint()
    dprint("fb: "..fb.." max "..max.." reported_length_remaining: "..tvbuf:reported_length_remaining().." start_idx: "..start_idx)
    local value = nil
    local offset = 1

    if fb == 0 then
        value = fb
    elseif fb == 0xfd then
        dprint("read_var fd")
        -- test for enough data remaining to take out a uint16
        if tvbuf:reported_length_remaining()-start_idx < 3 then
            return nil, nil
        end
        
        value = tvbuf(start_idx+offset, 2):le_uint()
        offset = offset + 2
    elseif fb == 0xfe then
        dprint("read_var fe")
        -- test for enough data remaining to take out a uint32
        if tvbuf:reported_length_remaining()-start_idx < 5 then
            return nil, nil
        end
        value = tvbuf(start_idx+offset, 4):le_uint()
        offset = offset + 4
    elseif fb == 0xff then
        dprint("read_var ff")
        -- test for enough data remaining to take out a uint64
        if tvbuf:reported_length_remaining()-start_idx < 9 then
            return nil, nil
        end
        value = tvbuf(start_idx+offset, 8):le_uint64()
        offset = offset + 8
    else
        dprint("read_var else"..fb)
        value = fb
    end

    if value > max then
        dprint("value:"..value.." > max: "..max)
        return nil, nil
    end
    return value, offset
end

neo_protocol.fields = {
    pf_message_config,
    pf_message_type,
    pf_payload,
    pf_payload_size,
    pf_version_magic,
    pf_version_version,
    pf_version_timestamp,
    pf_version_nonce,
    pf_version_useragent,
    pf_version_capabilities,
    pf_version_capabilities_type,
    pf_version_capabilities_start_height,
    pf_version_capabilities_port,
    pf_getheaders_start_hash,
    pf_getheaders_count,
    pf_inventory_type,
    pf_hashes_label,
    pf_hash_with_idx,
    pf_block_version,
    pf_block_prev_hash,
    pf_block_merkle_root,
    pf_block_timestamp,
    pf_block_index,
    pf_block_nextconsensus,
    pf_getblockbyindex_index_start,
    pf_getblockbyindex_count,
    pf_ping_lastblockindex,
    pf_ping_nonce,
    pf_ping_timestamp
}

function dissect_version(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "VERSION")
    local magic = tvbuf(offset,4):le_uint()
    payload_tree:add_le(pf_version_magic, tvbuf(offset, 4))
    offset = offset + 4

    if magic == 1951352142 then
        pktinfo.cols.info:append(" (TestNet)")
    elseif magic == 5195086 then
        pktinfo.cols.info:append(" (MainNet)")
    else
        pktinfo.cols.info:append(" (Unknown network)")
    end

    payload_tree:add(pf_version_version, tvbuf(offset, 4))
    offset = offset + 4

    local usecs = tvbuf(offset, 4):le_uint()
    local nstime = NSTime.new(usecs, 0)
    payload_tree:add(pf_version_timestamp, tvbuf(offset, 4), nstime)
    offset = offset + 4

    payload_tree:add(pf_version_nonce, tvbuf(offset, 4))
    offset = offset + 4

    size, len_byte_count = read_var_int(tvbuf, offset, 1024)
    if size == nil then
        return nil
    end

    local user_agent = tvbuf(offset+len_byte_count, size)
    payload_tree:add(pf_version_useragent, user_agent)
    offset = offset + len_byte_count + size
    pktinfo.cols.info:append(" "..user_agent:string())

    local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_NODE_CAPABILITIES)
    if cnt == nil then
        return nil
    end
    local capabilities = payload_tree:add(pf_version_capabilities, tvbuf(offset, len_byte_count))
    offset = offset + len_byte_count
    for i=0,cnt-1 do
        local type = capabilities:add(pf_version_capabilities_type, tvbuf(offset, 1))
        local type_name = node_capabilities[tvbuf(offset, 1):uint()]
        offset = offset + 1
        if type_name == "FULLNODE" then
            type:add(pf_version_capabilities_start_height, tvbuf(offset, 4))
            offset = offset + 4
        elseif (type_name == "TCPSERVER" or type_name == "WSSERVER") then
            type:add_le(pf_version_capabilities_port, tvbuf(offset, 2))
            offset = offset + 2
        end
    end
end

function dissect_getblocks(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "GETBLOCKS")
    payload_tree:add(pf_getheaders_start_hash, tvbuf(offset, 32))
    offset = offset + 32
    local count = tvbuf(offset, 2):le_int()
    if count == -1 then
        count = MAX_GETHEADERS
    end
    pktinfo.cols.info:append(" ("..count..")")
    payload_tree:add_le(pf_getheaders_count, tvbuf(offset, 2), MAX_GETHEADERS)
end

function dissect_getblockbyindex(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "GETBLOCKBYINDEX")
    payload_tree:add_le(pf_getblockbyindex_index_start, tvbuf(offset, 4))
    local start_idx = tvbuf(offset, 4):le_int()
    offset = offset + 4
    payload_tree:add_le(pf_getblockbyindex_count, tvbuf(offset, 2))
    local count = tvbuf(offset, 2):le_int()
    pktinfo.cols.info:append(" (s:"..start_idx.." c:"..count..")")
end

function dissect_inventory(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "INVENTORY")
    local type_string = inventory_type[tvbuf(offset, 1):uint()]
    payload_tree:add(pf_inventory_type, tvbuf(offset, 1))
    offset = offset + 1

    local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_INVENTORY_HASHES)
    if cnt == nil then
        pktinfo.cols.info:append(" ("..type_string..", ERR)")
        return nil
    end
    pktinfo.cols.info:append(" ("..type_string..", "..cnt..")")

    local hashes = payload_tree:add(pf_hashes_label, tvbuf(offset, len_byte_count))
    offset = offset + len_byte_count
    for i=0,cnt-1 do
        local h = hashes:add(pf_hash_with_idx, tvbuf(offset, 32))
        h:set_text(i..":"..h.text)
        offset = offset + 32
    end
end

function dissect_block(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "BLOCK")
    payload_tree:add_le(pf_block_version, tvbuf(offset, 4))
    offset = offset + 4
    payload_tree:add(pf_block_prev_hash, tvbuf(offset, 32))
    offset = offset + 32
    payload_tree:add(pf_block_merkle_root, tvbuf(offset, 32))
    offset = offset + 32
    payload_tree:add(pf_block_timestamp, tvbuf(offset, 8))
    offset = offset + 8
    payload_tree:add_le(pf_block_index, tvbuf(offset, 4))
    local block_idx = tvbuf(offset, 4):le_uint()
    offset = offset + 4
    payload_tree:add(pf_block_nextconsensus, tvbuf(offset, 20))
    offset = offset + 20
    pktinfo.cols.info:append(" ("..block_idx..")")
end

function dissect_ping(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "PING")
    payload_tree:add_le(pf_ping_lastblockindex, tvbuf(offset, 4))
    local last_block_index = tvbuf(offset, 4):le_uint()
    offset = offset + 4
    local usecs = tvbuf(offset, 4):le_uint()
    local nstime = NSTime.new(usecs, 0)
    payload_tree:add(pf_ping_timestamp, tvbuf(offset, 4), nstime)
    offset = offset + 4
    payload_tree:add(pf_ping_nonce, tvbuf(offset, 4))
    offset = offset + 4
    pktinfo.cols.info:append(" ("..last_block_index..")")
end

local NEO_MSG_HDR_LEN = 3

function get_length(tvbuf, pktinfo, offset)
    -- must return number representing full length of the PDU, if we can't then return 0 indicating we need more data
    
    -- offset is offset to the start of the message (aka msg.config)
    dprint("offset:"..offset)

    -- bytes remaining to create a message off
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        dprint("Captured packet was shorter than original, can't reassemble")
        return 0
    end

    if msglen < NEO_MSG_HDR_LEN then
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- we can at least attempt to read the variable length byte
    local value, len_byte_count = read_var_int(tvbuf, offset+2, msglen-NEO_MSG_HDR_LEN)
    if value == nil then
        dprint("get_length(): Not enough data to determine length")
        return -DESEGMENT_ONE_MORE_SEGMENT
    else
        dprint("get_length(): "..value.." "..len_byte_count)
        return value, len_byte_count
    end
end

local last_frame = -1

-- return values
-- positive num = length of NEO message dissected
-- 0 = error
-- negative num = number of bytes missing for a message
function dissectNEO(tvbuf, pktinfo, root, offset)
    local length_val, new_offset = get_length(tvbuf, pktinfo, offset)

    if length_val < 0 then
        return length_val
    end

    dprint("new offset:"..new_offset)

    pktinfo.cols.protocol:set("NEO3")

    -- collect data but don't set tree yet until we're sure we have a valid msg type
    -- local msg_config_buf = tvbuf(offset, 1)
    -- offset = offset + 1
    
    local message_config = message_config_table[tvbuf(offset,1):uint()]
    if message_config == nil then
        return 0
    end

    
    local message_type = message_type_table[tvbuf(offset+1,1):uint()]
    if message_type == nil then
        return 0
    end

    if pktinfo.number ~= last_frame then
        pktinfo.cols.info:set(message_type)
        last_frame = pktinfo.number
    else
        pktinfo.cols.info:append(", "..message_type)
    end

    local tree = root:add(neo_protocol, tvbuf(offset, length_val+2+new_offset))
    tree:add(pf_message_config, tvbuf(offset,1))
    offset = offset + 1
    tree:add(pf_message_type, tvbuf(offset,1))
    offset = offset + 1 -- inc for type offset

    offset = offset + new_offset -- set offset to data[0] of payload 
    if message_type == "VERSION" then
        dprint("data offset going into version: "..offset)
        dissect_version(tvbuf, pktinfo, tree, offset)
    elseif message_type == "GETBLOCKS" then
        dissect_getblocks(tvbuf, pktinfo, tree, offset)
    elseif message_type == "GETBLOCKBYINDEX" then
        dissect_getblockbyindex(tvbuf, pktinfo, tree, offset)
    elseif message_type == "INV" then
        dissect_inventory(tvbuf, pktinfo, tree, offset)
    elseif message_type == "BLOCK" then 
        dissect_block(tvbuf, pktinfo, tree, offset)
    elseif message_type == "GETHEADERS" then
        -- same payload as GETBLOCKS
        dissect_getblocks(tvbuf, pktinfo, tree, offset)
    elseif message_type == "PING" then
        dissect_ping(tvbuf, pktinfo, tree, offset)
    elseif message_type == "PONG" then
        dissect_ping(tvbuf, pktinfo, tree, offset)
    end

    return length_val + 2 + new_offset -- lenght_val = payload size, 2 = msg.config & msg.type, new_offset = size of var len field
end

function neo_protocol.dissector(tvbuf, pktinfo, root)
    local offset = 0
    local pktlen = tvbuf:len()
    local bytes_consumed = 0
    dprint("pktlen: "..pktlen)
    while bytes_consumed < pktlen do
        dprint("frame number: "..pktinfo.number)
        local result = dissectNEO(tvbuf, pktinfo, root, bytes_consumed)
        dprint("Result after dissectNEO: "..result)
        if result > 0 then
            bytes_consumed = bytes_consumed + result
        elseif result == 0 then
            return 0
        else
            pktinfo.desegment_offset = bytes_consumed
            result = -result
            pktinfo.desegment_len = result
            return pktlen
        end
    end

    return bytes_consumed
end


tcp_table = DissectorTable.get("tcp.port"):add(20333, neo_protocol)
