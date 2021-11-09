local neo_protocol = Proto("neo3", "NEO3 Blockchain")

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
    [0x2E] = "EXTENSIBLE",
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

local attribute_type = {
    [0x1] = "HIGH_PRIORITY",
    [0x11] = "ORACLE_RESPONSE"
}

local pf_message_config = ProtoField.uint8("neo3.message.config","Config", base.HEX, message_config_table)
local pf_message_type   = ProtoField.uint8("neo3.message.type","Type", base.HEX, message_type_table)
local pf_payload        = ProtoField.new("Payload", "neo3.message.payload", ftypes.STRING)
local pf_payload_size   = ProtoField.new("Size", "neo3.payload.size", ftypes.UINT32)

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
local pf_block_nonce = ProtoField.uint64("neo3.payload.block.nonce", "Nonce", base.DEC)
local pf_block_index = ProtoField.uint32("neo3.payload.block.index", "Index", base.DEC)
local pf_block_primary_index = ProtoField.uint8("neo3.payload.block.primary_index", "Primary index", base.DEC)
local pf_block_nextconsensus = ProtoField.new("Next consensus", "neo3.payload.block.nextconsensus", ftypes.BYTES)

local pf_tx = ProtoField.string("neo3.transaction", "Transaction")
local pf_txs = ProtoField.string("neo3.transactions", "Transactions")
local pf_tx_version = ProtoField.uint8("neo3.payload.transaction.version", "Version", base.DEC)
local pf_tx_nonce = ProtoField.uint32("neo3.payload.transaction.nonce", "Nonce", base.DEC)
local pf_tx_system_fee = ProtoField.int64("neo3.payload.transaction.systemfee", "System fee", base.DEC)
local pf_tx_network_fee = ProtoField.int64("neo3.payload.transaction.networkfee", "Network fee", base.DEC)
local pf_tx_valid_until = ProtoField.uint32("neo3.payload.transaction.validuntilblock", "Valid until block", base.DEC)
local pf_tx_signers = ProtoField.uint8("neo3.payload.transaction.signers", "Signers", base.DEC)
local pf_tx_attributes = ProtoField.uint8("neo3.payload.transaction.attributes", "Attributes", base.DEC)
local pf_tx_attribute = ProtoField.uint8("neo3.payload.transaction.attribute", "Attribute", base.HEX, attribute_type)
local pf_tx_script = ProtoField.new("Script", "neo3.payload.transaction.script", ftypes.BYTES)
local pf_tx_witnesses = ProtoField.string("neo3.witnesses", "Witnesses")
local MAX_TX_ATTRIBUTES = 16
local MAX_SUB_ITEMS = 16

local pf_signer = ProtoField.string("neo3.signer", "Signer")
local pf_signers = ProtoField.string("neo3.signers", "Signers")
local pf_signer_account = ProtoField.new("Account", "neo3.signer.account", ftypes.BYTES)
local pf_signer_scope = ProtoField.string("neo3.signer.scope","Witness scope")

local pf_signer_allowed_contracts = ProtoField.string("neo3.signer.allowedcontracts", "Allowed contracts")
local pf_signer_allowed_contract = ProtoField.new("contract", "neo3.signer.allowedcontract", ftypes.BYTES)
local pf_signer_allowed_groups = ProtoField.string("neo3.signer.allowedgroups", "Allowed groups")
local pf_signer_allowed_group = ProtoField.new("group", "neo3.signer.allowedgroup", ftypes.BYTES)

local pf_headers_version = ProtoField.uint32("neo3.payload.headers.version", "Version", base.DEC)
local pf_headers_prev_hash = ProtoField.new("PrevHash", "neo3.payload.headers.prevhash", ftypes.BYTES)
local pf_headers_merkle_root = ProtoField.new("MerkleRoot", "neo3.payload.headers.merkleroot", ftypes.BYTES)
local pf_headers_timestamp = ProtoField.uint64("neo3.payload.headers.timestamp", "Timestamp", base.DEC)
local pf_headers_nonce = ProtoField.uint64("neo3.payload.headers.nonce", "Nonce", base.DEC)
local pf_headers_index = ProtoField.uint32("neo3.payload.headers.index", "Index", base.DEC)
local pf_headers_primary_index = ProtoField.uint8("neo3.payload.block.primary_index", "Primary index", base.DEC)
local pf_headers_nextconsensus = ProtoField.new("Next consensus", "neo3.payload.headers.nextconsensus", ftypes.BYTES)
local pf_headers_label = ProtoField.uint8("neo3.payload.headers", "Headers", base.DEC)
local pf_header_list_item = ProtoField.string("neo3.payload.headers.list_item", "Header")
local MAX_HEADERS_COUNT = 2000

local pf_witness_list_item = ProtoField.string("neo3.witness", "Witness")
local pf_witness_invocation_script = ProtoField.new("invocation script", "neo3.invocationscript", ftypes.BYTES)
local pf_witness_verification_script = ProtoField.new("verification script", "neo3.verificationscript", ftypes.BYTES)
local MAX_INVOCATION_SCRIPT = 1024
local MAX_VERIFICATION_SCRIPT = 1024

local pf_filterload_filter = ProtoField.new("Filter", "neo3.filterload.filter", ftypes.BYTES)
local pf_filterload_k = ProtoField.uint8("neo3.filterload.k", "K", base.DEC)
local pf_filterload_tweak = ProtoField.uint32("neo3.filterload.tweak", "Tweak", base.DEC)

local pf_filteradd_data = ProtoField.new("Data", "neo3.filteradd.data", ftypes.BYTES)

local function read_var_int(tvbuf, start_idx, max)
    -- max is max bytes to read
    -- return (payload length, variable length byte count) - add this to offset to read the actual value
    local fb = tvbuf(start_idx, 1):uint()
    local value = nil
    local offset = 1
    if fb == 0 then
        value = fb
    elseif fb == 0xfd then
        -- test for enough data remaining to take out a uint16
        if tvbuf:reported_length_remaining()-start_idx < 3 then
            return nil, nil
        end
        
        value = tvbuf(start_idx+offset, 2):le_uint()
        offset = offset + 2
    elseif fb == 0xfe then
        -- test for enough data remaining to take out a uint32
        if tvbuf:reported_length_remaining()-start_idx < 5 then
            return nil, nil
        end
        value = tvbuf(start_idx+offset, 4):le_uint()
        offset = offset + 4
    elseif fb == 0xff then
        -- test for enough data remaining to take out a uint64
        if tvbuf:reported_length_remaining()-start_idx < 9 then
            return nil, nil
        end
        value = tvbuf(start_idx+offset, 8):le_uint64()
        offset = offset + 8
    else
        value = fb
    end

    if value > max then
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
    pf_block_nonce,
    pf_block_index,
    pf_block_primary_index,
    pf_block_nextconsensus,
    pf_headers_version,
    pf_headers_prev_hash,
    pf_headers_merkle_root,
    pf_headers_timestamp,
    pf_headers_nonce,
    pf_headers_index,
    pf_headers_primary_index,
    pf_headers_nextconsensus,
    pf_headers_label,
    pf_header_list_item,
    pf_tx,
    pf_txs,
    pf_tx_version,
    pf_tx_nonce,
    pf_tx_system_fee,
    pf_tx_network_fee,
    pf_tx_valid_until,
    pf_tx_signers,
    pf_tx_attributes,
    pf_tx_attribute,
    pf_tx_script,
    pf_tx_witnesses,
    pf_signer,
    pf_signers,
    pf_signer_account,
    pf_signer_scope,
    pf_signer_allowed_contracts,
    pf_signer_allowed_contract,
    pf_signer_allowed_groups,
    pf_signer_allowed_group,
    pf_getblockbyindex_index_start,
    pf_getblockbyindex_count,
    pf_ping_lastblockindex,
    pf_ping_nonce,
    pf_ping_timestamp,
    pf_witness_list_item,
    pf_witness_invocation_script,
    pf_witness_verification_script,
    pf_filterload_filter,
    pf_filterload_k,
    pf_filterload_tweak,
    pf_filteradd_data
}

function dissect_version(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "VERSION")
    local magic = tvbuf(offset,4):le_uint()
    payload_tree:add_le(pf_version_magic, tvbuf(offset, 4))
    offset = offset + 4

    if magic == 877933390 then
        pktinfo.cols.info:append(" (TestNet)")
    elseif magic == 860833102 then
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

    local size, len_byte_count = read_var_int(tvbuf, offset, 1024)
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
    payload_tree:add_le(pf_getheaders_count, tvbuf(offset, 2), count)
end

function dissect_getblockbyindex(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "GETBLOCKBYINDEX")
    payload_tree:add_le(pf_getblockbyindex_index_start, tvbuf(offset, 4))
    local start_idx = tvbuf(offset, 4):le_int()
    offset = offset + 4
    local count = tvbuf(offset, 2):le_int()
    if count == -1 then
        count = MAX_GETHEADERS
    end
    payload_tree:add_le(pf_getblockbyindex_count, tvbuf(offset, 2), count)
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
    -- if we know reading a header works, then we can read the index at a fixed offset

    local new_offset = dissect_header(tvbuf, pktinfo, payload_tree, offset, "Header")
    if new_offset == nil then
        return nil
    else
        local block_idx = tvbuf(offset + 84, 4):le_uint()
        pktinfo.cols.info:append(" ("..block_idx..")")
        offset = new_offset
    end

    local cnt, len_byte_count = read_var_int(tvbuf, offset, 0xFFFF)
    if cnt == nil then -- can't have 0 signers as a valid tx
        pktinfo.cols.info:append(" (ERR)")
        return nil
    end

    offset = offset + len_byte_count

    local txs_tree = payload_tree:add(pf_txs)
    txs_tree:append_text(cnt)
    for i=0,cnt-1 do
        local tx_tree = txs_tree:add(pf_tx)
        tx_tree:set_text(i)
        new_offset = dissect_transaction(tvbuf, pktinfo, tx_tree, offset)
        if new_offset == nil then
            pktinfo.cols.info:append(" (ERR)")
            break
        else
            offset = new_offset
        end
    end
end

function parse_scope(value)
    local ret = ""
    if value == 0 then
        return "NONE"
    elseif value == 0x80 then
        return "GLOBAL" -- global can't have other flags
    end

    if bit32.band(value, 0x01) == 0x01 then
       ret = "CALLED_BY_ENTRY, "
    end
    if bit32.band(value, 0x10) == 0x10 then
        ret = ret.."ALLOWED_CONTRACTS, "
    end
    if bit32.band(value, 0x20) == 0x20 then
        ret = ret.."ALLOWED_GROUPS"
    end
    return ret:sub(1,-3)
end

function dissect_signer(tvbuf, pktinfo, tree, offset)
    local signer_tree = tree:add(pf_signer)
    signer_tree:add_le(pf_signer_account, tvbuf(offset, 20))
    offset = offset + 20
    local scope = tvbuf(offset, 1):uint()
    signer_tree:add(pf_signer_scope, parse_scope(scope))
    offset = offset + 1

    -- test for for custom contracts
    if bit32.band(scope, 0x10) == 0x10 then
        local contracts = signer_tree:add(pf_signer_allowed_contracts)

        local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_SUB_ITEMS)
        if cnt == nil then
            pktinfo.cols.info:append(" (ERR)")
            return nil
        end
        offset = offset + len_byte_count

        for i=0,cnt-1 do
            c = contracts:add_le(pf_signer_allowed_contract, tvbuf(offset, 20))
            c:set_text("0x"..tvbuf(offset, 20))
            offset = offset + 20
        end
    end

    -- test for for custom groups
    if bit32.band(scope, 0x20) == 0x20 then
        local groups = signer_tree:add(pf_signer_allowed_groups)

        local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_SUB_ITEMS)
        if cnt == nil then
            pktinfo.cols.info:append(" (ERR)")
            return nil
        end
        offset = offset + len_byte_count

        for i=0,cnt-1 do
            g = groups:add_le(pf_signer_allowed_group, tvbuf(offset, 33))
            g:set_text(""..tvbuf(offset, 33))
            offset = offset + 33
        end
    end
    return offset
end

function dissect_transaction(tvbuf, pktinfo, tree, offset)
    tree:add(pf_tx_version, tvbuf(offset, 1))
    offset = offset + 1
    tree:add_le(pf_tx_nonce, tvbuf(offset, 4))
    offset = offset + 4
    tree:add_le(pf_tx_system_fee, tvbuf(offset, 8))
    offset = offset + 8
    tree:add_le(pf_tx_network_fee, tvbuf(offset, 8))
    offset = offset + 8
    tree:add_le(pf_tx_valid_until, tvbuf(offset, 4))
    offset = offset + 4

    -- read list of signers
    local signer_cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_TX_ATTRIBUTES)
    if signer_cnt == nil or signer_cnt == 0 then -- can't have 0 signers as a valid tx
        pktinfo.cols.info:append(" (Signers ERR)")
        return nil
    end
    offset = offset + len_byte_count

    local signers_tree = tree:add(pf_signers)
    signers_tree:append_text(signer_cnt)
    for i=0,signer_cnt-1 do
        local new_offset = dissect_signer(tvbuf, pktinfo, signers_tree, offset)
        if new_offset == nil then
            break
        else
            offset = new_offset
        end
    end

    -- read attributes
    local attr_cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_TX_ATTRIBUTES-signer_cnt)
    if attr_cnt == nil then
        pktinfo.cols.info:append(" (Attributes ERR)"..attr_cnt.." "..len_byte_count)
        return nil
    end
    local attributes_tree = tree:add(pf_tx_attributes, tvbuf(offset, len_byte_count)) -- can never be longer than 1 byte (max value is 16d)
    offset = offset + len_byte_count

    for i=0,attr_cnt-1 do
        attributes_tree:add(pf_tx_attribute, tvbuf(offset, 1))
        offset = offset + 1
    end

    -- read script
    local script_len, len_byte_count = read_var_int(tvbuf, offset, 0xFFFF)
    if script_len == nil then
        pktinfo.cols.info:append(" (Script ERR)")
        return nil
    end
    offset = offset + len_byte_count
    tree:add(pf_tx_script, tvbuf(offset, script_len))
    offset = offset + script_len

    -- read witnesses
    local witness_cnt, len_byte_count = read_var_int(tvbuf, offset, 1)
    if witness_cnt == nil or witness_cnt > 1 then
        return nil -- format error
    end
    offset = offset + len_byte_count

    local witness_tree = tree:add(pf_tx_witnesses)
    for i=0,witness_cnt-1 do
        local new_offset = dissect_witness(tvbuf, pktinfo, witness_tree, offset)
        if new_offset == nil then
            return nil
        else
            offset = new_offset
        end
    end
    return offset
end

function dissect_witness(tvbuf, pktinfo, tree, offset)
    local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_INVOCATION_SCRIPT)

    if cnt == nil then
        pktinfo.cols.info:append(" (ERR)")
        return nil
    end
    if cnt == 0 then
        tree:add(pf_witness_invocation_script, tvbuf(offset, 0))
        offset = offset + len_byte_count
    else
        offset = offset + len_byte_count
        tree:add(pf_witness_invocation_script, tvbuf(offset, cnt))
        offset = offset + cnt
    end

    cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_VERIFICATION_SCRIPT)
      --pktinfo.cols.info:append(" ("..cnt..")"..len_byte_count)

    if cnt == 0 then
        tree:add(pf_witness_verification_script, tvbuf(offset, 0))
        offset = offset + len_byte_count
    else
        offset = offset + len_byte_count
        tree:add(pf_witness_verification_script, tvbuf(offset, cnt))
        offset = offset + cnt
    end
    return offset
end

-- dissect single header
function dissect_header(tvbuf, pktinfo, tree, offset, header_label)
        local header_item = tree:add(pf_header_list_item)
        header_item:add_le(pf_headers_version, tvbuf(offset, 4))
        offset = offset + 4
        header_item:add_le(pf_headers_prev_hash, tvbuf(offset, 32))
        offset = offset + 32
        header_item:add(pf_headers_merkle_root, tvbuf(offset, 32))
        offset = offset + 32
        header_item:add_le(pf_headers_timestamp, tvbuf(offset, 8))
        offset = offset + 8
        header_item:add(pf_headers_nonce, tvbuf(offset, 8))
        offset = offset + 8
        header_item:add_le(pf_headers_index, tvbuf(offset, 4))
        local h_idx = tvbuf(offset, 4):le_uint()
        header_label = header_label or h_idx
        header_item:set_text(header_label)
        offset = offset + 4
        header_item:add_le(pf_block_primary_index, tvbuf(offset, 1))
        offset = offset + 1
        header_item:add(pf_block_nextconsensus, tvbuf(offset, 20))
        offset = offset + 20

        local witness_cnt, len_byte_count = read_var_int(tvbuf, offset, 1)
        if witness_cnt == nil or witness_cnt > 1 then
            return nil -- format error
        end
        offset = offset + len_byte_count

        local witness_tree = header_item:add(pf_witness_list_item)
        local new_offset = dissect_witness(tvbuf, pktinfo, witness_tree, offset)
        if new_offset == nil then
            return nil
        else
            offset = new_offset
        end
        return offset
end

-- dissect HEADERS payload
function dissect_headers(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "HEADERS")

    local cnt, len_byte_count = read_var_int(tvbuf, offset, MAX_HEADERS_COUNT)
    if cnt == nil then
        pktinfo.cols.info:append(" (ERR)")
        return nil
    end
    pktinfo.cols.info:append(" ("..cnt..")")

    local headers_tree = payload_tree:add(pf_headers_label, tvbuf(offset, len_byte_count))
    offset = offset + len_byte_count

    for i=0,cnt-1 do
        local new_offset = dissect_header(tvbuf, pktinfo, headers_tree, offset, nil)
        if new_offset == nil then
            break
        else
            offset = new_offset
        end
    end
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

function dissect_filterload(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "FILTERLOAD")
    local size, len_byte_count = read_var_int(tvbuf, offset, 36000)
    if size == nil then
        pktinfo.cols.info:append(" (Filter ERR)")
        return nil
    end
    offset = offset + len_byte_count

    payload_tree:add(pf_filterload_filter, tvbuf(offset, size))
    offset = offset + size

    payload_tree:add(pf_filterload_k, tvbuf(offset, 1))
    if tvbuf(offset, 1):uint() > 50 then
        pktinfo.cols.info:append(" (K value ERR)")
        return nil
    end
    offset = offset + 1

    payload_tree:add_le(pf_filterload_tweak, tvbuf(offset, 4))
    offset = offset + 4
    return offset
end

function dissect_filteradd(tvbuf, pktinfo, tree, offset)
    payload_tree = tree:add(pf_payload, tvbuf(offset), "FILTERADD")
    local size, len_byte_count = read_var_int(tvbuf, offset, 36000)
    if size == nil then
        pktinfo.cols.info:append(" (Data ERR)")
        return nil
    end
    offset = offset + len_byte_count

    payload_tree:add(pf_filteradd_data, tvbuf(offset, size))
    offset = offset + size
    return offset
end

local NEO_MSG_HDR_LEN = 3

function get_length(tvbuf, pktinfo, offset)
    -- must return number representing full length of the PDU, if we can't then return 0 indicating we need more data

    -- offset is offset to the start of the message (aka msg.config)

    -- bytes remaining to create a message off
    local msglen = tvbuf:len() - offset

    -- check if capture was only capturing partial packet size
    if msglen ~= tvbuf:reported_length_remaining(offset) then
        -- captured packets are being sliced/cut-off, so don't try to desegment/reassemble
        return 0
    end

    if msglen < NEO_MSG_HDR_LEN then
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- we can at least attempt to read the variable length byte
    local value, len_byte_count = read_var_int(tvbuf, offset+2, msglen-NEO_MSG_HDR_LEN)
    if value == nil then
        return -DESEGMENT_ONE_MORE_SEGMENT
    else
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

    pktinfo.cols.protocol:set("NEO3")
    
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

    if message_config ~= "COMPRESSED" then
        if message_type == "VERSION" then
            dissect_version(tvbuf, pktinfo, tree, offset)
        elseif message_type == "GETBLOCKS" then
            dissect_getblocks(tvbuf, pktinfo, tree, offset)
        elseif message_type == "GETBLOCKBYINDEX" then
            dissect_getblockbyindex(tvbuf, pktinfo, tree, offset)
        elseif message_type == "INV" then
            dissect_inventory(tvbuf, pktinfo, tree, offset)
        elseif message_type == "GETDATA" then
            dissect_inventory(tvbuf, pktinfo, tree, offset)
        elseif message_type == "NOTFOUND" then
            dissect_inventory(tvbuf, pktinfo, tree, offset)
        elseif message_type == "BLOCK" then
            dissect_block(tvbuf, pktinfo, tree, offset)
        elseif message_type == "TRANSACTION" then
            payload_tree = tree:add(pf_payload, tvbuf(offset), "TRANSACTION")
            dissect_transaction(tvbuf, pktinfo, payload_tree, offset)
        elseif message_type == "GETHEADERS" then
            dissect_getblockbyindex(tvbuf, pktinfo, tree, offset)
        elseif message_type == "PING" then
            dissect_ping(tvbuf, pktinfo, tree, offset)
        elseif message_type == "PONG" then
            dissect_ping(tvbuf, pktinfo, tree, offset)
        elseif message_type == "HEADERS" then
            dissect_headers(tvbuf, pktinfo, tree, offset)
        elseif message_type == "FILTERLOAD" then
            dissect_filterload(tvbuf, pktinfo, tree, offset)
        elseif message_type == "FILTERADD" then
            dissect_filteradd(tvbuf, pktinfo, tree, offset)
        end
    end

    return length_val + 2 + new_offset -- lenght_val = payload size, 2 = msg.config & msg.type, new_offset = size of var len field
end

function neo_protocol.dissector(tvbuf, pktinfo, root)
    local pktlen = tvbuf:len()
    local bytes_consumed = 0

    while bytes_consumed < pktlen do
        local result = dissectNEO(tvbuf, pktinfo, root, bytes_consumed)
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


tcp_table = DissectorTable.get("tcp.port"):add(10333, neo_protocol)
