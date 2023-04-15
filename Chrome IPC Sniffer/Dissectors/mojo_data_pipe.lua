mojodata_protocol = Proto("MOJODATA",  "Mojo Data Pipe Control")

-- Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/data_pipe_control_message.cc;l=14
-- https://source.chromium.org/chromium/chromium/src/+/main:mojo/core/data_pipe_control_message.h;l=27
local command           = ProtoField.int32 ("mojodata.command"              , "Control Command"     , base.DEC)
local num_bytes         = ProtoField.int32 ("mojodata.num_bytes"       , "Number Of Bytes Passed"         , base.DEC)

mojodata_protocol.fields = {
  command, num_bytes                                                                                             -- Hidden Fields
}

local _command = Field.new("mojodata.command")
local _numbytes = Field.new("mojodata.num_bytes")

function mojodata_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = mojodata_protocol.name

    local        subtree =    tree:add(mojodata_protocol, buffer(), "Mojo Data Pipe Control Message")

    -- Header
    local offset = 0
    command_value = buffer(offset,4):le_uint()
    subtree:add_le(command,            buffer(offset,4)):append_text(" (" .. get_code_name(command_value) .. ")");            offset = offset + 4
    subtree:add_le(num_bytes,          buffer(offset,4));                                                                     offset = offset + 4

    subtree:append_text(", Command: " .. get_code_name(command_value) ..", Bytes Count: " .. _numbytes()())

    if command_value == 0 then
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Wrote " .. _numbytes()() .. " bytes to data pipe"
    elseif command_value == 1 then
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Read " .. _numbytes()() .. " bytes from data pipe"
    end
    
end

function get_code_name(opcode)
    local opcode_name = "Unknown"

    if opcode == 0 then opcode_name = "DATA_WAS_WRITTEN" end
    if opcode == 1 then opcode_name = "DATA_WAS_READ" end
    
    return opcode_name
end
