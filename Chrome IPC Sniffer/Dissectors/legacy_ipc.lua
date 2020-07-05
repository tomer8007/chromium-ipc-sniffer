legacyipc_protocol = Proto("LEGACYIPC",  "Legacy IPC Protocol")

local common = require("helpers\\common")
local get_chrome_name = common.get_chrome_type_name

local legacy_ipc_interface_json, err = io.open(common.script_path() .. "helpers\\legacy_ipc_interfaces.json", "rb"):read("*all")
local legacy_ipc_interfaces_info = common.json_to_table(legacy_ipc_interface_json)

-- Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message.h;l=248
local payload_size      = ProtoField.uint32 ("legacyipc.payload_size"               , "Payload Size"     , base.DEC)
local routing           = ProtoField.uint32 ("legacyipc.routing"       , "Destination View ID"         , base.HEX)
local message_type      = ProtoField.uint32 ("legacyipc.type"       , "Message Type"         , base.HEX)
local reference_number  = ProtoField.uint32 ("legacyipc.refnum"         , "Reference Number"         , base.HEX) -- 10 bits of PID + 14 bit count
local pid               = ProtoField.uint8("legacyipc.pid", "Process ID", base.DEC)
local count             = ProtoField.uint32("legacyipc.count", "Count", base.DEC)
local flags             = ProtoField.uint32 ("legacyipc.flags"          , "Flags"         , base.HEX)
local padding           = ProtoField.new("Padding", "legacyipc.padding", ftypes.BYTES)

-- Flags
-- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message.h;l=49
local flag_priority_mask = ProtoField.bool("legacyipc.haspriority", "PRIORITY_MASK", 8, {"This message has a priority in the low 2 bits", "This message has no priority info"}, 0x3)
local flag_sync = ProtoField.bool("legacyipc.issync", "SYNC_BIT", 8, {"This is a syncronous message", "This is an asyncronous message"}, 0x4)
local flag_replay = ProtoField.bool("legacyipc.isreplay", "REPLAY_BIT", 8, {"This is a replay", "This is NOT a replay"}, 0x8)
local flag_replay_error = ProtoField.bool("legacyipc.isreplayerror", "REPLAY_ERROR_BIT", 8, {"This is a replay error", "This is NOT a replay error"}, 0x10)
local flag_unlock = ProtoField.bool("legacyipc.isunlock", "UNBLOCK_BIT", 8, {"This is an unlock", "This is NOT an unlock"}, 0x20)
local flag_pumping_msgs = ProtoField.bool("legacyipc.ispumping", "PUMPING_MSGS_BIT", 8, {"This is pumping messages", "This is NOT pumping messages"}, 0x40)
local flag_has_sent_time = ProtoField.bool("legacyipc.hastime", "HAS_SENT_TIME_BIT", 8, {"This message has a sent time", "This message does not have a sent time"}, 0x80)

-- Message type
-- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message_macros.h;l=304
local message_id_class = ProtoField.uint16("legacyipc.messageclass", "Message ID Class", base.DEC)
local message_id_line = ProtoField.uint16("legacyipc.line", "Message ID Line Number", base.DEC)

local link_field                    = ProtoField.new("Definition Link", "legacyipc.definitionlink", ftypes.STRING)

local payload            = ProtoField.new("Payload", "legacyipc.payload", ftypes.BYTES)


legacyipc_protocol.fields = {
   payload_size, routing, message_type, message_id_class, message_id_line, reference_number, pid, count, flags, payload, padding,           -- Header
   flag_priority_mask, flag_sync, flag_replay, flag_replay_error, flag_unlock, flag_pumping_msgs, flag_has_sent_time,                       -- Flags
   link_field
}

local _payloadsize = Field.new("legacyipc.payload_size")
local _routing = Field.new("legacyipc.routing")
local _messagetype = Field.new("legacyipc.type")
local _flags = Field.new("legacyipc.flags")
local _haspriority = Field.new("legacyipc.haspriority")
local _refnum = Field.new("legacyipc.refnum")

local _messageclass = Field.new("legacyipc.messageclass")


function legacyipc_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = legacyipc_protocol.name

    local        subtree =    tree:add(legacyipc_protocol, buffer(), "Legacy IPC Protocol")

    -- Header
    local offset = 0
    
    subtree:add_le(payload_size,        buffer(offset,4));                                                                          offset = offset + 4
    routingTree =       subtree:add_le(routing,             buffer(offset,4));                                                      offset = offset + 4
    typeTree =          subtree:add_le(message_type,        buffer(offset,4));                                          

    typeTree:add_le(message_id_line, buffer(offset, 2));                                                                            offset = offset + 2
    typeTree:add_le(message_id_class, buffer(offset, 2)):append_text(" (" .. get_message_class_name(_messageclass()()) .. ")");     offset = offset + 2
    
    controlFlagsTree =  subtree:add_le(buffer(offset,4), "Control Flags");  
    
    flagsTree =         controlFlagsTree:add_le(flags, buffer(offset, 1));                                              
    priorityTree =  flagsTree:add_le(flag_priority_mask, buffer(offset, 1))
                    flagsTree:add_le(flag_sync, buffer(offset, 1))
                    flagsTree:add_le(flag_replay, buffer(offset, 1))
                    flagsTree:add_le(flag_replay_error, buffer(offset, 1))
                    flagsTree:add_le(flag_unlock, buffer(offset, 1))
                    flagsTree:add_le(flag_pumping_msgs, buffer(offset, 1))
                    flagsTree:add_le(flag_has_sent_time, buffer(offset, 1))                                                         offset = offset + 1

    if _haspriority()() then
        local priority_value = bit32.band(_flags()(), 0x2)
        priorityTree:append_text(string.format(" (%s)", get_priority_name(priority_value)))
    end

    refNumTree = controlFlagsTree:add_le(reference_number, buffer(offset, 3));                                  
    refNumTree:add_le(pid, buffer(offset, 1), bit32.arshift(_refnum()(), 14));  
    refNumTree:add_le(count, buffer(offset, 3), bit32.band(_refnum()(), 0x3fff));                                                   offset = offset + 3 

    subtree:add(payload,                buffer(offset, _payloadsize()()));                                                          offset = offset + _payloadsize()()

    local special_routing = get_special_routing(_routing()())
    local special_type = get_special_type(_messagetype()())

    if special_routing ~= "" then
        routingTree:append_text(string.format(" (%s)", special_routing))
    end
    if special_type ~= "" then
        typeTree:append_text(string.format(" (%s)", special_type))
    end

    subtree:append_text(string.format(", Routing: 0x%x, Type: 0x%x", _routing()(), _messagetype()()))

    -- Try to resolve the message name
    local message_name = nil
    local defintion_link = nil
    local message_info = legacy_ipc_interfaces_info[string.format("%X", _messagetype()())]
    if message_info ~= nil then
        message_name = message_info["name"]
        defintion_link = message_info["link"]

        typeTree:append_text(" [" .. message_name .. "]")
        subtree:add(link_field, defintion_link):set_text("[" .. defintion_link .. "]")
    end

    if offset % 8 ~= 0 then
        local missingSize = 8 - offset % 8
        subtree:add(padding, buffer(offset, missingSize));                                                                          offset = offset + missingSize
    end

    if get_special_type(_messagetype()()) == "IPC_REPLY_ID" then
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Legacy IPC: Replay Message"
    elseif message_name ~= nil then
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Legacy IPC: Message " .. message_name
    else
        pinfo.cols.info = tostring(pinfo.cols.info) .. " Legacy IPC: Message " .. string.format("0x%x", _messagetype()())
    end

end

function  get_special_routing(routing)
    -- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message.h;l=301
    local opcode_name = ""

    if routing == 0x7fffffff then opcode_name = "MSG_ROUTING_CONTROL" end
    if routing == 0xfffffffe then opcode_name = "MSG_ROUTING_NONE" end
    
    return opcode_name
end

function  get_special_type(type)
    -- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message.h;l=309
    local opcode_name = ""

    if type == 0xFFFFFFF0 then opcode_name = "IPC_REPLY_ID" end
    if type == 0xFFFFFFF1 then opcode_name = "IPC_LOGGING_ID" end
    
    return opcode_name
end

function get_priority_name(priority)
    -- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message.h;l=40
    local opcode_name = "unknown"

    if priority == 1 then opcode_name = "PRIORITY_LOW" end
    if priority == 2 then opcode_name = "PRIORITY_NORMAL" end
    if priority == 3 then opcode_name = "PRIORITY_HIGH" end
    
    return opcode_name
end

function get_message_class_name(class)
    -- https://source.chromium.org/chromium/chromium/src/+/master:ipc/ipc_message_start.h;l=14
    local opcode_name = "Unknown"

    if class == 0 then opcode_name = "AutomationMsgStart" end
    if class == 1 then opcode_name = "FrameMsgStart" end
    if class == 2 then opcode_name = "PageMsgStart" end
    if class == 3 then opcode_name = "ViewMsgStart" end
    if class == 4 then opcode_name = "WidgetMsgStart" end
    if class == 5 then opcode_name = "TestMsgStart" end
    if class == 6 then opcode_name = "WorkerMsgStart" end
    if class == 7 then opcode_name = "NaClMsgStart" end
    if class == 8 then opcode_name = "GpuChannelMsgStart" end
    if class == 9 then opcode_name = "MediaMsgStart" end
    if class == 10 then opcode_name = "PpapiMsgStart" end
    if class == 11 then opcode_name = "ChromeMsgStart" end
    if class == 12 then opcode_name = "DragMsgStart" end
    if class == 13 then opcode_name = "PrintMsgStart" end
    if class == 14 then opcode_name = "ExtensionMsgStart" end
    if class == 15 then opcode_name = "TextInputClientMsgStart" end
    if class == 16 then opcode_name = "PrerenderMsgStart" end
    if class == 17 then opcode_name = "ChromotingMsgStart" end
    if class == 18 then opcode_name = "AndroidWebViewMsgStart" end
    if class == 19 then opcode_name = "NaClHostMsgStart" end
    if class == 20 then opcode_name = "EncryptedMediaMsgStart" end
    if class == 21 then opcode_name = "CastMsgStart" end
    if class == 22 then opcode_name = "GinJavaBridgeMsgStart" end
    if class == 23 then opcode_name = "ChromeUtilityPrintingMsgStart" end
    if class == 24 then opcode_name = "OzoneGpuMsgStart" end
    if class == 25 then opcode_name = "WebTestMsgStart" end
    if class == 26 then opcode_name = "ExtensionsGuestViewMsgStart" end
    if class == 27 then opcode_name = "GuestViewMsgStart" end
    if class == 28 then opcode_name = "MediaPlayerDelegateMsgStart" end
    if class == 29 then opcode_name = "ExtensionWorkerMsgStart" end
    if class == 30 then opcode_name = "SubresourceFilterMsgStart" end
    if class == 31 then opcode_name = "UnfreezableFrameMsgStart" end
    
    return opcode_name
end



