sync_protocol = Proto("AudioSync",  "Audio Sync Protocol")

local get_chrome_name = require("helpers\\common").get_chrome_type_name

-- Header fields

-- https://source.chromium.org/chromium/chromium/src/+/master:services/audio/sync_reader.cc;l=163
local control_signal        = ProtoField.uint32 ("audiosync.control_signal"             , "Control Signal"     , base.HEX)

-- https://source.chromium.org/chromium/chromium/src/+/master:services/audio/sync_reader.cc;l=257
local buffer_index          = ProtoField.uint32 ("audiosync.buffer_index"       , "Renderer Buffer Index"         , base.DEC)

-- From other layers
local source_pid_type      = ProtoField.int32 ("npfs.sourcetype"       , "Source Process Type"         , base.DEC)
local dest_pid_type        = ProtoField.int32 ("npfs.desttype"       , "Destination Process Type"         , base.DEC)


sync_protocol.fields = {
   source_pid_type, dest_pid_type,      -- (From NPFS)
   control_signal, buffer_index,        -- Header
}

local _controlcode = Field.new("audiosync.control_signal")
local _bufferindex = Field.new("audiosync.buffer_index")


-- Fields from other layers
local _sourcetype = Field.new("npfs.sourcetype")
local _desttype = Field.new("npfs.desttype")


function sync_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = sync_protocol.name

    local        subtree =    tree:add(sync_protocol, buffer(), "Audio Synchronization Protocol")

    pinfo.cols.info = tostring(pinfo.cols.info) .. " Audio Sync"

    -- Header
    local offset = 0

    if get_chrome_name(_sourcetype()()) == "Renderer" then
        subtree:add_le(buffer_index,        buffer(offset,4));                                                                      offset = offset + 4

        pinfo.cols.info = tostring(pinfo.cols.info) .. ": Buffer #" .. _bufferindex()()
    else
        subtree:add_le(control_signal,        buffer(offset,4)):append_text(" (" .. get_code_name(_controlcode()()) .. ")");        offset = offset + 4

        pinfo.cols.info = tostring(pinfo.cols.info) .. " (" .. get_code_name(_controlcode()()) .. ")"
    end

end

function get_code_name(opcode)
    local opcode_name = "Unknown"

    if opcode ==  0 then opcode_name = "Request More Data" end
    if opcode == 0xffffffff then opcode_name = "Stop" end
    
    return opcode_name
end