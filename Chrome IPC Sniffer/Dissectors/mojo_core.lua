mojocore_protocol = Proto("mojo",  "Mojo Core")

local common = require("helpers\\common")

-- Channel Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/channel.h;l=95
local num_bytes                             = ProtoField.uint32 ("mojo.numbytes"  , "Message Length"     , base.DEC)
local num_header_bytes                      = ProtoField.uint16 ("mojo.numheaderbytes"       , "Generic Message Header Length"         , base.DEC)
local message_type                          = ProtoField.uint16 ("mojo.type"       , "Message Type"         , base.DEC)
local num_handles                           = ProtoField.uint16 ("mojo.numhandles"      , "Handles Count"        , base.DEC)
local padding                               = ProtoField.new("Padding", "mojo.padding", ftypes.BYTES)
local platform_handle                       = ProtoField.uint32 ("mojo.platformhandle"       , "Platform Handle"         , base.DEC)

-- Normal Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=48
local normal_header_type                    = ProtoField.uint32 ("mojo.messagetype"      , "Normal Message Type"        , base.DEC)
local normal_header_padding                 = ProtoField.new("Padding", "mojo.normalpadding", ftypes.BYTES)

-- Event Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=24
-- NodeController::OnEventMessage -> ports::Event::Deserialize
local event_type                            = ProtoField.uint32 ("mojo.event.type"      , "Event Type"        , base.DEC)
local event_padding                         = ProtoField.new("Padding", "mojo.event.padding", ftypes.BYTES)
local event_port_name                       = ProtoField.new("Destination Port Name", "mojo.event.port", ftypes.BYTES)

-- User Message Event Data fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=30
local usermessage_seq_num                   = ProtoField.int64 ("mojo.um.seqnum"      , "Sequence Number"        , base.DEC)
local usermessage_num_ports                 = ProtoField.uint32 ("mojo.um.numports"      , "Ports Count"        , base.DEC)
local usermessage_padding                   = ProtoField.new("Padding", "mojo.um.padding", ftypes.BYTES)

-- Observe Proxy Event Data fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=36
local observe_proxy_node_name               = ProtoField.new("Proxy Node Name", "mojo.proxy.node", ftypes.BYTES)
local observe_proxy_port_name               = ProtoField.new("Proxy Port Name", "mojo.proxy.port", ftypes.BYTES)
local observe_proxy_target_node_name        = ProtoField.new("Proxy Target Node Name", "mojo.proxy.targetnode", ftypes.BYTES)
local observe_proxy_target_port_name        = ProtoField.new("Proxy Target Port Name", "mojo.proxy.targetport", ftypes.BYTES)

-- Observe Clousure Event Data fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=47
local observe_closure_last_sequence_number  = ProtoField.int64 ("mojo.closure.seqnum"      , "Last Sequence Number"        , base.DEC)

-- Observe Proxy Ack Event Data fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=43
local observe_proxy_ack_last_sequence_number = ProtoField.int64 ("mojo.proxyack.seqnum"      , "Last Sequence Number"        , base.DEC)

-- Merge Port Event Data fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=51
local merge_port_new_port_name              = ProtoField.new("New Port Name", "mojo.mergeport.port", ftypes.BYTES)
local merge_port_new_port_descriptor        = ProtoField.new("New Port Descriptor", "mojo.mergeport.portdescriptor", ftypes.BYTES)

-- Relay Event Message fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=123
local destination_node                      = ProtoField.new("Destination Node", "mojo.relay.dst", ftypes.BYTES)
local relay_message_payload                 = ProtoField.new("Relayed Event Message Payload", "mojo.relay.payload", ftypes.BYTES)

-- Message From Replay fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=128
local source_node                           = ProtoField.new("Source Node", "mojo.relayed.source", ftypes.BYTES)
local relayed_message_payload               = ProtoField.new("Relayed Event Message Payload", "mojo.relayed.payload", ftypes.BYTES)

-- Request Introduction fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=111
local intruduction_node                     = ProtoField.new("Node Name", "mojo.introduction.node", ftypes.BYTES)

-- Add Broker Client fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=73
local add_broker_client_name                = ProtoField.new("Client Node Name", "mojo.addclient.client", ftypes.BYTES)

-- Accept Broker Client fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=95
local accept_broker_client_broker           = ProtoField.new("Broker Node Name", "mojo.acceptclient.broker", ftypes.BYTES)

-- Accept Invitation fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=61
local accept_invitation_token               = ProtoField.new("Token", "mojo.acceptinvitation.token", ftypes.BYTES)
local accept_invitation_name                = ProtoField.new("Invitee Node Name", "mojo.acceptinvitation.invitee_name", ftypes.BYTES)

-- Accept Invitee fields
local inviter_name                          = ProtoField.new("Inviter Node Name", "mojo.invitee.inivtername", ftypes.BYTES)
local token                                 = ProtoField.new("Token Node Name", "mojo.invitee.token", ftypes.BYTES)

-- Request Port Merge fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=101
local request_port_merge_connector          = ProtoField.new("Connector Port Name", "mojo.portmerge.connector", ftypes.BYTES)
local request_port_merge_token              = ProtoField.new("Token String", "mojo.portmerge.token", ftypes.BYTES)

-- Broker Message fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/broker_messages.h

-- INIT
local broker_pipe_name_length                = ProtoField.uint32 ("mojo.pipenamelen"      , "Pipe Name Length"        , base.DEC)
-- BUFFER_REQUEST
local broker_bufffer_size                    = ProtoField.uint32 ("mojo.broker_buffersize"      , "Buffer Size"        , base.DEC)
-- BUFFER_RESPONSE
local broker_guid                            = ProtoField.new("GUID", "mojo.broker_guid", ftypes.GUID)

--
-- User Message fields
--

-- User Message Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/user_message_impl.cc;l=47
local usermessage_num_dispatchers            = ProtoField.uint32 ("mojo.um.numdispatchers"      , "Dispatchers Count"        , base.DEC)
local usermessage_header_size                = ProtoField.uint32 ("mojo.um.headersize"      , "Header Size"        , base.DEC)

local usermessage_dispatchers_headers        = ProtoField.new ("Dispatchers Headers", "mojo.um.dispatchersheaders"     , ftypes.BYTES)
local usermessage_dispatchers_descriptors    = ProtoField.new ("Dispatchers Descriptors", "mojo.um.dispatchersdescriptors"      , ftypes.BYTES)

-- Port Descriptor fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.h;l=69
local peer_node_name                        = ProtoField.new("Peer Node Name", "mojo.port.peernode", ftypes.BYTES)
local peer_port_name                        = ProtoField.new("Peer Port Name", "mojo.port.peerport", ftypes.BYTES)
local referring_node_name                   = ProtoField.new("Referring Node Name", "mojo.port.refnodename", ftypes.BYTES)
local referring_port_name                   = ProtoField.new("Referring Port Name", "mojo.port.refportname", ftypes.BYTES)
local next_sequence_num_to_send             = ProtoField.int64 ("mojo.port.nextseqnum1"      , "Next Sequence Number To Send"        , base.DEC)
local next_sequence_num_to_recv             = ProtoField.int64 ("mojo.port.nextseqnum2"      , "Next Sequence Number To Receive"        , base.DEC)
local last_sequence_num_to_recv             = ProtoField.int64 ("mojo.port.lastseqnum"      , "Last Sequence Number To Receive"        , base.DEC)
local peer_closed                           = ProtoField.uint8 ("mojo.port.perrclosed"      , "Peer Closed"        , base.DEC)
local port_padding                          = ProtoField.new("Padding", "mojo.port.padding", ftypes.BYTES)
local port_name                             = ProtoField.new("Port Name", "mojo.port.portname", ftypes.BYTES)

-- Dispatcher Header fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/user_message_impl.cc;l=57
local dispatcher_type                       = ProtoField.int32 ("mojo.dispatcher.type"      , "Dispatcher Type"        , base.DEC)
local dispatcher_num_bytes                  = ProtoField.uint32 ("mojo.dispatcher.numbytes"      , "Serialized Dispatcher Size"        , base.DEC)
local dispatcher_num_ports                  = ProtoField.uint32 ("mojo.dispatcher.numports"      , "Ports Count"        , base.DEC)
local dispatcher_num_handles                = ProtoField.uint32 ("mojo.dispatcher.numhandles"      , "Platform Handles Count"        , base.DEC)

-- Message Pipe Dispatcher fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/message_pipe_dispatcher.cc;l=28
local pipe_id                               = ProtoField.uint64 ("mojo.pipe.id"      , "Pipe ID"        , base.HEX)
local pipe_endpoint                         = ProtoField.uint8 ("mojo.pipe.endpoint"      , "Endpoint"        , base.DEC)
local pipe_padding                          = ProtoField.new("Padding", "mojo.pipe.padding", ftypes.BYTES)

-- Data Pipe Consumer Dispatcher fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/data_pipe_consumer_dispatcher.cc;l=34
local datapipe_struct_size                  = ProtoField.uint32 ("mojo.datapipe.options_size"      , "Options Struct Size"        , base.DEC)
local datapipe_create_flags                 = ProtoField.uint32 ("mojo.datapipe.createflags"      , "Create Flags"        , base.HEX)
local datapipe_element_size                 = ProtoField.uint32 ("mojo.datapipe.elementsize"      , "Element Size"        , base.DEC)
local datapipe_capacity                     = ProtoField.uint32 ("mojo.datapipe.capacity"      , "Capacity (in bytes)"        , base.DEC)
local datapipe_pipe_id                      = ProtoField.uint64 ("mojo.datapipe.id"      , "Pipe ID"        , base.HEX)
local datapipe_read_offset                  = ProtoField.uint32 ("mojo.datapipe.readoffset"      , "Read Offset"        , base.DEC)
local datapipe_bytes_available              = ProtoField.uint32 ("mojo.datapipe.bytesavailable"      , "Bytes Available"        , base.DEC)
local datapipe_flags                        = ProtoField.uint8 ("mojo.datapipe.flags"      , "Flags"        , base.HEX)
local datapipe_buffer_guid                  = ProtoField.new("Buffer GUID", "mojo.datapipe.guid", ftypes.GUID)
local datapipe_padding                      = ProtoField.new("Padding", "mojo.datapipe.padding", ftypes.BYTES)

-- Shared Buffer Dispatcher Fields
-- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/shared_buffer_dispatcher.cc;l=31
local sharedbuffer_num_bytes                = ProtoField.uint64 ("mojo.sharedbuffer.numbytes"      , "Bytes Count"        , base.DEC)
local sharedbuffer_acess_mode               = ProtoField.uint32 ("mojo.sharedbuffer.accessmode"      , "Access Mode"        , base.HEX)
local sharedbuffer_guid                     = ProtoField.new("GUID", "mojo.sharedbuffer.guid", ftypes.GUID)
local sharedbuffer_padding                  = ProtoField.new("Padding", "mojo.sharedbuffer.padding", ftypes.BYTES)


local dispatcher_descriptor                 = ProtoField.new("Dispatcher Data", "mojo.dispatcher_descriptor", ftypes.BYTES)

local data                                  = ProtoField.new("Data", "mojo.payload", ftypes.BYTES)

-- From other layers
local source_pid_type                       = ProtoField.int32 ("npfs.sourcetype"       , "Source Process Type"         , base.DEC)
local dest_pid_type                         = ProtoField.int32 ("npfs.desttype"       , "Destination Process Type"         , base.DEC)


mojocore_protocol.fields = {
  source_pid_type, dest_pid_type,                                                     -- (From NPFS)
  num_bytes, num_header_bytes, message_type, num_handles, padding, platform_handle,   -- Channel Header
  normal_header_type, normal_header_padding,                                          -- Normal Header
  broker_pipe_name_length, broker_bufffer_size, broker_guid,                              -- Broker Messages fields
  event_type, event_padding, event_port_name,                                         -- Event Header
  usermessage_seq_num, usermessage_num_ports, usermessage_padding,                    -- User Message Event Data
  observe_proxy_node_name, observe_proxy_port_name, observe_proxy_target_node_name, observe_proxy_target_port_name, -- Observe Proxy Event Data
  observe_closure_last_sequence_number,                                                                             -- Observe Closure Event Data
  observe_proxy_ack_last_sequence_number,                                                                           -- Observe Proxy Ack Event Data
  merge_port_new_port_name, merge_port_new_port_descriptor,                                                         -- Merge Port Event Data
  usermessage_num_dispatchers, usermessage_header_size, usermessage_dispatchers_headers, usermessage_dispatchers_descriptors, -- User Message Header
  peer_node_name, peer_port_name, referring_node_name, referring_port_name, next_sequence_num_to_send, -- Port Descriptor
  next_sequence_num_to_recv, last_sequence_num_to_recv, peer_closed, port_padding, port_name,             -- Port Descriptor (Contd.)
  dispatcher_type, dispatcher_num_bytes, dispatcher_num_ports, dispatcher_num_handles,                   -- Dispatcher Header
  pipe_id, pipe_endpoint, pipe_padding,                                                                  -- Message Pipe Descriptor 
  datapipe_pipe_id, datapipe_read_offset, datapipe_bytes_available,                                     -- Data Pipe Consumer Descriptor
  datapipe_flags, datapipe_buffer_guid, datapipe_padding, datapipe_struct_size, datapipe_create_flags,  -- Data Pipe Consumer Descriptor (Contd.)
  datapipe_element_size, datapipe_capacity,                                                             -- Data Pipe Consumer Descriptor (Contd.)
  sharedbuffer_num_bytes, sharedbuffer_acess_mode, sharedbuffer_guid, sharedbuffer_padding,             -- Shared Buffer Descriptor 
  dispatcher_descriptor,                                                                                -- Unknown Dispatcher Descriptor
  intruduction_node,                                                                                    -- Request Intoduction
  inviter_name, token,                                                                                  -- Accept Invitee
  accept_invitation_token, accept_invitation_name,                                                      -- Accept Invitation
  add_broker_client_name,                                                                               -- Add Broker Client
  accept_broker_client_broker,                                                                          -- Accept Broker Client
  destination_node, relay_message_payload,                                                              -- Replay Message
  source_node, relayed_message_payload,                                                                 -- Relayed Message
  request_port_merge_connector, request_port_merge_token,                                               -- Request Port Merge
  data,                                                                                                  -- Unparsed Data
}

-- Channel Header fields
local _numbytes = Field.new("mojo.numbytes")
local _numheaderbytes = Field.new("mojo.numheaderbytes")
local _numhandles = Field.new("mojo.numhandles")
local _type = Field.new("mojo.type")

-- Normal Header fields
local _messagetype = Field.new("mojo.messagetype")

-- Event Header fields
local _eventtype = Field.new("mojo.event.type")
local _eventport = Field.new("mojo.event.port")

-- Observe Proxy fields
local _proxyport = Field.new("mojo.proxy.port")
local _targetport = Field.new("mojo.proxy.targetport")

-- User Message Event fields
local _um_num_dispatchers = Field.new("mojo.um.numdispatchers")
local _um_num_ports = Field.new("mojo.um.numports")

-- User Message Header fields
local _um_headersize = Field.new("mojo.um.headersize")

-- Dispatcher Header fields
local _dispatcher_type = Field.new("mojo.dispatcher.type")
local _dispatcher_numbytes = Field.new("mojo.dispatcher.numbytes")

-- Fields from other layers
local _sourcetype = Field.new("npfs.sourcetype")
local _desttype = Field.new("npfs.desttype")

function mojocore_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = mojocore_protocol.name

    local subtree =       tree:add(mojocore_protocol, buffer(), "Mojo Core Channel Message")
    local headerSubtree = subtree:add("Generic Message Header")

    -- Generic Header
    local offset = 0
    headerSubtree:add_le(num_bytes,         buffer(offset,4));                                                                offset = offset + 4
    headerSubtree:add_le(num_header_bytes,  buffer(offset,2));                                                                offset = offset + 2
    headerSubtree:add_le(message_type,      buffer(offset,2)):append_text(" (" .. get_message_type(_type()()) .. ")");        offset = offset + 2
    headerSubtree:add_le(num_handles,       buffer(offset,2));                                                                offset = offset + 2
    headerSubtree:add_le(padding,           buffer(offset,6));                                                                offset = offset + 6
    
    local extraHeaderSize = _numheaderbytes()() - 16
    if _numhandles()() > 0 then
      local handlesSubtree = headerSubtree:add(buffer(offset, _numhandles()() * 4), "Platform Handles")
      for i=1, _numhandles()() do
        handle_node_text = "Windows Handle " .. i .. ": " .. buffer(offset, 4):le_uint()
        handlesSubtree:add_le(platform_handle,   buffer(offset, 4)):set_text(handle_node_text);                                offset = offset + 4
      end

      if extraHeaderSize > _numhandles()() * 4 then
            local paddingSize = extraHeaderSize - _numhandles()() * 4
            handlesSubtree:add_le(padding, buffer(offset, paddingSize));                                                        offset = offset + paddingSize
            handlesSubtree:set_len(_numhandles()() * 4 + paddingSize)
      end
    end

    headerSubtree:set_len(_numheaderbytes()())

    headerSubtree:append_text(", Type: " .. get_message_type(_type()()) .. ", Handles Count: " .. _numhandles()())

    if _type()() == 1 then
        -- Normal Header

        local normalSubtree = subtree:add(buffer(offset, 8), "Normal Message Header")
        local normal_message_offset = offset

        headerTypeTree = normalSubtree:add_le(normal_header_type,  buffer(offset,4))                                            offset = offset + 4
        normalSubtree:add_le(padding,             buffer(offset,4));                                                            offset = offset + 4

        local message_type_string = get_normal_message_type(_messagetype()())

        if _messagetype()() == 5 then
            -- Event

            -- Event::Deserialize
            -- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.cc;l=104

            local eventSubtree = subtree:add(buffer(offset), "Event")
            local eventStartOffset = offset

            eventSubtree:add_le(event_type,         buffer(offset,4)) :append_text(" (" .. get_event_type(_eventtype()()) .. ")");  offset = offset + 4
            eventSubtree:add_le(event_padding,     buffer(offset,4));                                                               offset = offset + 4
            eventSubtree:add_le(event_port_name,   buffer(offset,16));                                                              offset = offset + 16

            port_name_string = to_128bit_hex_string(buffer(offset-16 , 16))
            eventSubtree:append_text(", Type: " .. get_event_type(_eventtype()()) .. ", Port Name: " .. port_name_string)
            subtree:append_text(", Event Type: " .. get_event_type(_eventtype()()))
            subtree:append_text(" to port " .. string.lower(tostring(_eventport()())))

            local eventDataSubstree = eventSubtree:add(buffer(offset), "Event Data")
            local eventDataStartOffset = offset 

            if _eventtype()() == 0 then
                -- User Message

                eventDataSubstree:append_text(" (User Message)")
                eventDataSubstree:add_le(usermessage_seq_num,     buffer(offset,8));                                                          offset = offset + 8
                eventDataSubstree:add_le(usermessage_num_ports,   buffer(offset,4));                                                          offset = offset + 4
                eventDataSubstree:add_le(usermessage_padding,     buffer(offset,4));                                                          offset = offset + 4
                
                for i=1, _um_num_ports()() do
                    local portSubtree = eventDataSubstree:add(buffer(offset), "Port " .. i .. " Descriptor")
                    offset = read_port_descriptor(buffer(offset), portSubtree) + offset
                end
                for i=1, _um_num_ports()() do
                    port_name_tree_text = "Port " .. i .. " Name: " .. to_128bit_hex_string(buffer(offset, 16))
                    eventDataSubstree:add_le(port_name,   buffer(offset, 16)):set_text(port_name_tree_text);                                  offset = offset + 16
                end

                local usermessageSubtree = eventDataSubstree:add(buffer(offset), "Serialized Mojo Dispatchers (User Message Header)")
                usermessageSubtree:add_le(usermessage_num_dispatchers,     buffer(offset,4));                                                 offset = offset + 4
                usermessageSubtree:add_le(usermessage_header_size,         buffer(offset,4));                                                 offset = offset + 4

                -- UserMessageImpl::ExtractSerializedHandles
                dispatchers_types = {}
                dispatchers_sizes = {}
                for i=1, _um_num_dispatchers()() do
                    local dispatcherSubtree = usermessageSubtree:add(buffer(offset), "Dispatcher " .. i .. " Header")
                    dispatchers_types[i], dispatchers_sizes[i], size = read_dispatcher_header(buffer(offset), dispatcherSubtree)
                    offset = offset + size
                end
                for i=1, _um_num_dispatchers()() do
                    -- Dispatcher::Deserialize
                    if dispatchers_types[i] ~= -1 then
                        local dispatcherSubtree = usermessageSubtree:add(buffer(offset), "Serialized Dispatcher " .. i)
                        read_dispatcher_descriptor(buffer(offset), dispatcherSubtree, dispatchers_types[i], dispatchers_sizes[i])
                        offset = offset + dispatchers_sizes[i]
                    end
                end
                  
                usermessageSubtree:set_len(_um_headersize()())

                subtree:set_len(offset)

                -- Now call the next layer
                local next_value = buffer(offset, 4):le_uint()
                if next_value == 1 or next_value == 0 then
                    -- looks like a mojo data pipe control message
                    Dissector.get("mojodata"):call(buffer(offset):tvb(), pinfo, tree)
                else
                    -- this is most likely a mojo message pipe with binded message
                    Dissector.get("mojouser"):call(buffer(offset):tvb(), pinfo, tree)
                end
      
            elseif _eventtype()() == 2 then
                -- Observe Proxy

                eventDataSubstree:append_text(" (Observe Proxy)")

                eventDataSubstree:add_le(observe_proxy_node_name,     buffer(offset,16));                                                        offset = offset + 16
                eventDataSubstree:add_le(observe_proxy_port_name,   buffer(offset,16));                                                          offset = offset + 16
                eventDataSubstree:add_le(observe_proxy_target_node_name,     buffer(offset,16));                                                 offset = offset + 16
                eventDataSubstree:add_le(observe_proxy_target_port_name,     buffer(offset,16));                                                 offset = offset + 16

                local source_port = string.lower(string.sub(tostring(_proxyport()()), 0, 16)) .. ".."
                local target_port = string.lower(string.sub(tostring(_targetport()()), 0, 16)) .. ".."
                pinfo.cols.info = tostring(pinfo.cols.info) .. " Observe Proxying Port: " .. source_port .. " -> " .. target_port
            
            elseif _eventtype()() == 4 then
                -- Observe Closure

                eventDataSubstree:append_text(" (Observe Closure)")
                pinfo.cols.info = tostring(pinfo.cols.info) .. " Observe Port Closure: " .. string.lower(string.sub(tostring(_eventport()()), 0, 16)) .. "..."

                eventDataSubstree:add_le(observe_closure_last_sequence_number,     buffer(offset,8));                                           offset = offset + 8
            elseif _eventtype()() == 3 then
                -- Observe Proxy Ack

                eventDataSubstree:append_text(" (Observe Proxy Acknowledgement)")
                pinfo.cols.info = tostring(pinfo.cols.info) .. " Observe Proxy Acknowledgement"

                eventDataSubstree:add_le(observe_proxy_ack_last_sequence_number,     buffer(offset,8));                                         offset = offset + 8
            
            elseif _eventtype()() == 5 then
                -- Merge Port

                eventDataSubstree:append_text(" (Merge Port Request)")
                pinfo.cols.info = tostring(pinfo.cols.info) .. " Merge Port Request"

                eventDataSubstree:add_le(merge_port_new_port_name,                   buffer(offset,16));                                        offset = offset + 16
                local portSubtree = eventDataSubstree:add(buffer(offset), "New Port Descriptor ")
                offset = read_port_descriptor(buffer(offset), portSubtree) + offset

            elseif offset == _numbytes()() then
                eventDataSubstree:append_text(" (Empty)")
            end

            eventDataSubstree:set_len(offset - eventDataStartOffset)
            eventSubtree:set_len(offset - eventStartOffset)

            if _eventtype()() == 6 then
                pinfo.cols.info = tostring(pinfo.cols.info) .. " User Message Read Acknowledgment Request"
            elseif _eventtype()() == 1 then
                pinfo.cols.info = tostring(pinfo.cols.info) .. " Port Accepted"
            elseif _eventtype()() == 7 then
              pinfo.cols.info = tostring(pinfo.cols.info) .. " User Message Read Acknowledgment"
            end

            -- pinfo.cols.info = tostring(pinfo.cols.info) .. ", Port " .. port_name_string
        elseif _messagetype()() == 0 and offset + 32 == length then
            -- ACCEPT_INVITEE
            local acceptInviteeSubtree = subtree:add(buffer(offset), "Accept Invitee")

            acceptInviteeSubtree:add(inviter_name, buffer(offset, 16));                                                     offset = offset + 16
            acceptInviteeSubtree:add(token, buffer(offset, 16));                                                            offset = offset + 16
        elseif _messagetype()() == 0 then
            -- probably BrokerMessageHeader's INIT
            message_type_string = get_broker_message_type(_messagetype()())

            local initSubtree = subtree:add(buffer(offset), "Broker Message (INIT)")
            initSubtree:add(broker_pipe_name_length, buffer(offset, 4));                                                    offset = offset + 4
        elseif _messagetype()() == 1 and offset + 32 == length then
            -- ACCEPT_INVITATION
            local acceptInvitationSubtree = subtree:add(buffer(offset), "Accept Invitation")

            acceptInvitationSubtree:add(accept_invitation_token, buffer(offset, 16));                                       offset = offset + 16
            acceptInvitationSubtree:add(accept_invitation_name, buffer(offset, 16));                                        offset = offset + 16
        elseif _messagetype()() == 1 then
            -- looks like BrokerMessageHeader's BUFFER_REQUEST

            message_type_string = get_broker_message_type(_messagetype()())

            local bufferRequestSubtree = subtree:add(buffer(offset), "Broker Message (BUFFER_REQUEST)")
            bufferRequestSubtree:add(broker_bufffer_size, buffer(offset, 4));                                               offset = offset + 4
        elseif _messagetype()() == 2 and _numhandles()() ~= 1 then
            -- ADD_BROKER_CLIENT
            -- NOTE: this can also be BUFFER_RESPONSE in rare cases
            local addClientSubtree = subtree:add(buffer(offset), "Add Broker Client")

            addClientSubtree:add(add_broker_client_name, buffer(offset, 16));                                               offset = offset + 16
        elseif _messagetype()() == 2 then
            -- looks like BrokerMessageHeader's BUFFER_RESPONSE

            message_type_string = get_broker_message_type(_messagetype()())

            local bufferResponseSubtree = subtree:add(buffer(offset), "Broker Message (BUFFER_RESPONSE)")
            bufferResponseSubtree:add(broker_guid, buffer(offset, 16));                                                     offset = offset + 16
        elseif _messagetype()() == 4 then
            -- ACCEPT_BROKER_CLIENT
            local acceptClientSubtree = subtree:add(buffer(offset), "Accept Broker Client")

            acceptClientSubtree:add(accept_broker_client_broker, buffer(offset, 16));                                       offset = offset + 16
        elseif _messagetype()() == 6 then
            -- REQUEST_PORT_MERGE
            local portMergeSubtree = subtree:add(buffer(offset), "Request Port Merge")

            portMergeSubtree:add(request_port_merge_connector, buffer(offset, 16));                                         offset = offset + 16
            portMergeSubtree:add(request_port_merge_token, buffer(offset))                                                  offset = length
        elseif _messagetype()() == 7 then
            -- REQUEST_INTRODUCTION
            local introductionSubtree = subtree:add(buffer(offset), "Request Introduction")

            introductionSubtree:add(intruduction_node, buffer(offset, 16));                                                 offset = offset + 16
        elseif _messagetype()() == 8 then
            -- INTRODUCE
            local introductionSubtree = subtree:add(buffer(offset), "Introduce")

            introductionSubtree:add(intruduction_node, buffer(offset, 16));                                                 offset = offset + 16
        elseif _messagetype()() == 9 then
            -- RELAY_EVENT_MESSAGE
            -- TOOD: we can parse the wrapped EVENT_MESSAGE here too
            local relayMessageSubtree = subtree:add(buffer(offset), "Relay Event Message")

            relayMessageSubtree:add(destination_node, buffer(offset, 16));                                                  offset = offset + 16
            relayMessageSubtree:add(relay_message_payload, buffer(offset));     
        elseif _messagetype()() == 11 then
            -- EVENT_MESSAGE_FROM_RELAY
            -- TOOD: we can parse the wrapped EVENT_MESSAGE here too
            local relayedMessageSubtree = subtree:add(buffer(offset), "Message From Relay")

            relayedMessageSubtree:add(source_node, buffer(offset, 16));                                                     offset = offset + 16
            relayedMessageSubtree:add(relayed_message_payload, buffer(offset));     
        else
            local payloadSubtree = subtree:add(buffer(offset), "Payload")
            payloadSubtree:add_le(data, buffer(offset))
        end

        headerTypeTree:append_text(" (" .. message_type_string .. ")");

        normalSubtree:append_text(", Type: " .. message_type_string)
        subtree:append_text(", Type: " .. message_type_string)
        subtree:append_text(", Handles Count: " .. _numhandles()())

        if _messagetype()() ~= 5 then
            pinfo.cols.info = tostring(pinfo.cols.info) .. " Message " .. message_type_string
        end

        if _numhandles()() > 0 then
            pinfo.cols.info = tostring(pinfo.cols.info) .. " [+" .. _numhandles()() .. " Native Handles]"
        end
    end

    -- tree:append_text(", Src PID: " .. _sourcepid()() .. ", Dst PID: " .. _dstpid()())

end


function read_dispatcher_descriptor(buffer, subtree, dispatcher_type, descriptor_size)
  local offset = 0

  subtree:append_text(" (" .. get_dispatcher_type(dispatcher_type) .. ")")

  if dispatcher_type == 1 then
      -- MESSAGE_PIPE
      pipe_id_value = buffer(offset, 8)

      subtree:add(pipe_id,              buffer(offset,8));                                          offset = offset + 8
      subtree:add_le(pipe_endpoint,     buffer(offset,1));                                          offset = offset + 1
      subtree:add(pipe_padding,      buffer(offset,7));                                             offset = offset + 7

      subtree:append_text(", Pipe ID: " .. to_64bit_hex_string(pipe_id_value))
  elseif dispatcher_type == 3 then
      -- DATA_PIPE_CONSUMER
      pipe_id_value = buffer(offset+16, 8)

      local optionsSubtree = subtree:add(buffer(offset, 16), "Create Data Pipe Options");
      optionsSubtree:add_le(datapipe_struct_size, buffer(offset, 4));                               offset = offset + 4
      optionsSubtree:add(datapipe_flags, buffer(offset, 4));                                        offset = offset + 4
      optionsSubtree:add_le(datapipe_element_size, buffer(offset, 4));                              offset = offset + 4
      optionsSubtree:add_le(datapipe_capacity, buffer(offset, 4));                                  offset = offset + 4
      
      subtree:add(datapipe_pipe_id, buffer(offset, 8));                                             offset = offset + 8
      subtree:add_le(datapipe_read_offset, buffer(offset, 4));                                      offset = offset + 4
      subtree:add_le(datapipe_bytes_available, buffer(offset, 4));                                  offset = offset + 4
      subtree:add(datapipe_flags, buffer(offset, 1));                                               offset = offset + 1
      subtree:add(datapipe_buffer_guid, buffer(offset, 16));                                        offset = offset + 16
      subtree:add(datapipe_padding, buffer(offset, 7));                                             offset = offset + 7

      subtree:append_text(", Pipe ID: " .. to_64bit_hex_string(pipe_id_value))
  elseif dispatcher_type == 4 then
      -- SHARED_BUFFER

      subtree:add_le(sharedbuffer_num_bytes, buffer(offset, 8));                                    offset = offset + 8
      subtree:add(sharedbuffer_acess_mode, buffer(offset, 4));                                      offset = offset + 4
      subtree:add(sharedbuffer_guid, buffer(offset, 16));                                           offset = offset + 16
      subtree:add(sharedbuffer_padding, buffer(offset, 4));                                         offset = offset + 4

  else
      subtree:add(dispatcher_descriptor, buffer(offset, descriptor_size));                          offset = offset + descriptor_size
  end

  subtree:set_len(descriptor_size)

  return offset
end

function get_message_type(type)
    -- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/channel.h;l=63
    local opcode_name = "Unknown"

    if type ==  0 then 
        opcode_name = "NORMAL_LEGACY"
    end
    if type ==  1 then 
        opcode_name = "NORMAL"
    end
    
    return opcode_name
end

function get_normal_message_type(type)
  --
  -- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/node_channel.cc;l=27
  -- NodeChannel::OnChannelMessage
  --

  local opcode_name = "Unknown"

  if type == 0 then opcode_name = "ACCEPT_INVITEE" end
  if type == 1 then opcode_name = "ACCEPT_INVITATION" end
  if type == 2 then opcode_name = "ADD_BROKER_CLIENT" end
  if type == 3 then opcode_name = "BROKER_CLIENT_ADDED" end
  if type == 4 then opcode_name = "ACCEPT_BROKER_CLIENT" end
  if type == 5 then opcode_name = "EVENT_MESSAGE" end
  if type == 6 then opcode_name = "REQUEST_PORT_MERGE" end
  if type == 7 then opcode_name = "REQUEST_INTRODUCTION" end
  if type == 8 then opcode_name = "INTRODUCE" end
  if type == 9 then opcode_name = "RELAY_EVENT_MESSAGE" end
  if type == 10 then opcode_name = "BROADCAST_EVENT" end
  if type == 11 then opcode_name = "EVENT_MESSAGE_FROM_RELAY" end
  if type == 12 then opcode_name = "ACCEPT_PEER" end
  
  return opcode_name
end

function get_broker_message_type(type)
  local opcode_name = "Unknown"

  if type == 0 then opcode_name = "INIT" end
  if type == 1 then opcode_name = "BUFFER_REQUEST" end
  if type == 2 then opcode_name = "BUFFER_RESPONSE" end
  return opcode_name
end
function get_event_type(type)
  --
  -- https://source.chromium.org/chromium/chromium/src/+/master:mojo/core/ports/event.h;l=30
  --

  local opcode_name = "Unknown"

  if type == 0 then opcode_name = "kUserMessage" end
  if type == 1 then opcode_name = "kPortAccepted" end
  if type == 2 then opcode_name = "kObserveProxy" end
  if type == 3 then opcode_name = "kObserveProxyAck" end
  if type == 4 then opcode_name = "kObserveClosure" end
  if type == 5 then opcode_name = "kMergePort" end
  if type == 6 then opcode_name = "kUserMessageReadAckRequest" end
  if type == 7 then opcode_name = "kUserMessageReadAck" end
  
  return opcode_name
end

function get_dispatcher_type(type)
  local type_name = "Unknown"

  if type == 0 then type_name = "UNKNOWN" end
  if type == 1 then type_name = "MESSAGE_PIPE" end
  if type == 2 then type_name = "DATA_PIPE_PRODUCER" end
  if type == 3 then type_name = "DATA_PIPE_CONSUMER" end
  if type == 4 then type_name = "SHARED_BUFFER" end
  if type == 5 then type_name = "WATCHER" end
  if type == 6 then type_name = "INVITATION" end
  if type == -1 then type_name = "PLATFORM_HANDLE" end

  return type_name
end

function read_port_descriptor(buffer, subtree)
    local offset = 0
    subtree:add_le(peer_node_name,     buffer(offset,16));                                             offset = offset + 16
    subtree:add_le(peer_port_name,     buffer(offset,16));                                             offset = offset + 16
    subtree:add_le(referring_node_name,     buffer(offset,16));                                        offset = offset + 16
    subtree:add_le(referring_port_name,     buffer(offset,16));                                        offset = offset + 16
    subtree:add_le(next_sequence_num_to_send,     buffer(offset,8));                                   offset = offset + 8
    subtree:add_le(next_sequence_num_to_recv,     buffer(offset,8));                                   offset = offset + 8
    subtree:add_le(last_sequence_num_to_recv,     buffer(offset,8));                                   offset = offset + 8
    subtree:add_le(peer_closed,     buffer(offset,1));                                                 offset = offset + 1
    subtree:add_le(port_padding,     buffer(offset,7));                                                offset = offset + 7

    subtree:set_len(offset)

    return offset
end

function read_dispatcher_header(buffer, subtree)
  local offset = 0
  dispatcher_type_value = buffer(offset, 4):le_int()
  descriptor_size = buffer(offset + 4, 4):le_uint()

  subtree:add_le(dispatcher_type,         buffer(offset,4)):append_text(" (" .. get_dispatcher_type(dispatcher_type_value) .. ")");     offset = offset + 4
  subtree:add_le(dispatcher_num_bytes,    buffer(offset,4));                                                                            offset = offset + 4
  subtree:add_le(dispatcher_num_ports,    buffer(offset,4));                                                                            offset = offset + 4
  subtree:add_le(dispatcher_num_handles,  buffer(offset,4));                                                                            offset = offset + 4

  subtree:set_len(offset)
  subtree:append_text(", Type: " .. get_dispatcher_type(dispatcher_type_value))

  return dispatcher_type_value, descriptor_size, offset
end

function to_128bit_hex_string(buffer)
  str = string.format('%x%x%x%x', buffer(0, 4):uint(), buffer(4, 4):uint(),
                                               buffer(8, 4):uint(), buffer(12, 4):uint())

  return str
end

function to_64bit_hex_string(buffer)
  str = string.format('%x%x', buffer(0, 4):uint(), buffer(4, 4):uint())

  return str
end