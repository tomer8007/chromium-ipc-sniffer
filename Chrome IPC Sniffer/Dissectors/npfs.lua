npfs_protocol = Proto("NPFS",  "NamedPipe Capture Protocol")

local get_chrome_name = require("helpers\\common").get_chrome_type_name

-- Header fields
local code                  = ProtoField.int16 ("npfs.code"             , "Code"     , base.DEC)
local source_pid            = ProtoField.int32 ("npfs.sourcepid"       , "Source PID"         , base.DEC)
local source_pid_type       = ProtoField.int32 ("npfs.sourcetype"       , "Source Process Type"         , base.DEC)
local dest_pid              = ProtoField.int32 ("npfs.destpid"          , "Destination PID"         , base.DEC)
local dest_pid_type         = ProtoField.int32 ("npfs.desttype"         , "Destination Process Type"         , base.DEC)

local thread_id             = ProtoField.int32 ("npfs.threadid"         , "Thread TID"        , base.DEC)
local pipe_name_length      = ProtoField.int8 ("npfs.pipenamelength"    , "Pipe Name Length"        , base.DEC)
local pipe_name             = ProtoField.string ("npfs.pipename"        , "Pipe Name"        , base.ASCII)
local timestamp             = ProtoField.int64 ("npfs.timestamp"        , "Timestamp"            , base.DEC)

local raw_data              = ProtoField.new("Raw Data", "npfs.data", ftypes.BYTES)

local data_length           = ProtoField.int32 ("npfs.datalen"           , "Captured Raw Data Length"             , base.DEC)

-- Psauedo Fields for unioned filtering
local s_pid                 = ProtoField.int32 ("npfs.pid"              , "Source PID"         , base.DEC)
local d_pid                 = ProtoField.int32 ("npfs.pid"              , "Dest PID"         , base.DEC)
local s_type                = ProtoField.new ("Source Process Type", "npfs.process_type" , ftypes.STRING)
local d_type                = ProtoField.new ( "Dest Process Type" , "npfs.process_type" , ftypes.STRING)

--
-- Expert Info
--
local expert_info_pipeerror = ProtoExpert.new("npfs.pipeerror", "Could not find destination PID", expert.group.COMMENTS_GROUP, expert.severity.WARN)


npfs_protocol.fields = {
  code, source_pid, source_pid_type, dest_pid, dest_pid_type, thread_id, pipe_name_length, pipe_name, timestamp, data_length,   -- Header
  raw_data,                                                                                                                     -- Extra Fields
  s_pid, d_pid, s_type, d_type,                                                                                                 -- Hidden Fields
}

npfs_protocol.experts = {expert_info_pipeerror}

local _sourcepid = Field.new("npfs.sourcepid")
local _dstpid = Field.new("npfs.destpid")
local _pipename = Field.new("npfs.pipename")
local _data_len = Field.new("npfs.datalen")
local _sourcetype = Field.new("npfs.sourcetype")
local _desttype = Field.new("npfs.desttype")


function npfs_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.src = Address.ip('127.0.0.1')
    pinfo.dst = Address.ip('127.0.0.1')
    pinfo.cols.protocol = npfs_protocol.name

    local        subtree =    tree:add(npfs_protocol, buffer(), "Named Pipe Capture Metadata")

    -- Header
    local offset = 0
    code_value = buffer(offset,2):le_uint()
    subtree:add_le(code,                buffer(offset,2)):append_text(" (" .. get_code_name(code_value) .. ")");            offset = offset + 2
    subtree:add_le(source_pid,          buffer(offset,4));                                                                  offset = offset + 4
    subtree:add_le(dest_pid,            buffer(offset,4));                                                                  offset = offset + 4
    subtree:add_le(source_pid_type,     buffer(offset,4)):append_text(" (" .. get_chrome_name(_sourcetype()()) .. ")");;    offset = offset + 4 
    subtree:add_le(dest_pid_type,       buffer(offset,4)):append_text(" (" .. get_chrome_name(_desttype()()) .. ")");;      offset = offset + 4    
    subtree:add_le(thread_id,           buffer(offset,4));                                                                  offset = offset + 4
    local pipe_name_length_value =      buffer(offset,1):le_uint()
    subtree:add_le(pipe_name_length,    buffer(offset,1));                                                                  offset = offset + 1
    subtree:add_le(pipe_name,           buffer(offset, pipe_name_length_value));                                            offset = offset + pipe_name_length_value
    if string.match(_pipename()(), "Unknown") then
        subtree:add_proto_expert_info(expert_info_pipeerror, "Could not find pipe name, most likely because it was closed")
    elseif _dstpid()() == 0 then
        subtree:add_proto_expert_info(expert_info_pipeerror, "Could not find destination PID, most likely because its pipe handle was closed")
    end
    subtree:add_le(timestamp,           buffer(offset,8)):append_text(" (" .. "100-ns intervals since 1/1/1601, GMT" .. ")");                      offset = offset + 8
    subtree:add_le(data_length,    buffer(offset,4));                                                                       offset = offset + 4

    subtree:set_len(offset)

    subtree:append_text(", Src PID: " .. _sourcepid()() .. " (" .. get_chrome_name(_sourcetype()()) .. ")" ..", Dst PID: " .. _dstpid()() .." (" .. get_chrome_name(_desttype()()) .. ")" .. ", Pipe: " .. _pipename()())

    -- Add hidden fields
    subtree:add_le(s_pid, _sourcepid()()):set_hidden()
    subtree:add_le(d_pid, _dstpid()()):set_hidden()
    subtree:add_le(s_type, get_chrome_name(_sourcetype()() )):set_hidden()
    subtree:add_le(d_type, get_chrome_name(_desttype()() )):set_hidden()

    pinfo.cols.info = get_chrome_name(_sourcetype()()) .. " ➜ " .. get_chrome_name(_desttype()()) .. ":"

    mojo_data_len = buffer(offset, 4):le_uint()

    -- Check the payload and decide if it should be interpreted as Mojo or not
    if mojo_data_len == _data_len()() and mojo_data_len > 4 then
        Dissector.get("mojo"):call(buffer(offset, length-offset):tvb(),  pinfo, tree)

        if mojo_data_len > length - offset then
            pinfo.cols.info = tostring(pinfo.cols.info) .. " [truncated]"
        end

    elseif _pipename()():find("chrome%.sync%.") ~= nil then
        Dissector.get("audiosync"):call(buffer(offset, _data_len()()):tvb(),  pinfo, tree)
    else
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Raw Pipe Data"
        Dissector.get("data"):call(buffer(offset, _data_len()()):tvb(),  pinfo, tree)
    end

end

function get_code_name(opcode)
    local opcode_name = "Unknown"

    if opcode ==  9 then opcode_name = "IRP_MJ_WRITE" end
    if opcode == 8 then opcode_name = "IRP_MJ_READ" end
    
    return opcode_name
end

local tcp_port = DissectorTable.get("ethertype")
tcp_port:add(0x807, npfs_protocol)
