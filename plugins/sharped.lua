--------------------------------------------------------------------------------
--
-- SHARP
--
--------------------------------------------------------------------------------
--[[
    This dissector is developed to facilitate the analysis of the network 
    communications between MediaTek MT2503/MTK3333 empowered devices and backend 
    servers. The custom protocol built on TCP packets was provided and 
    implemented by the third party, and it was not well designed. 
    Every piece of data sent from a device is ended with character sharp #. 
    However, at the time being, network packets from servers do not follow this   
    rule, and each one represents a piece of complete information. (we recommand 
    that both sides should do the same, so that long data could be sent from a 
    server using several packets.)
    Note: Some parts of the script file have been removed, as disclosure of the 
    information may violate the confident agreement with the bussiness client. 
    Note: This script should be placed in Wireshark\App\Wireshark\plugins
]]------------------------------------------------------------

local default_settings = 
{
    port       = 8000, 
    delimiter  = "#" 
}

-- creates a Proto object
local sharp_proto = Proto("SHARP", "Sharp-Separated Segment")

function sharp_proto.dissector(buffer, pinfo, tree) 
    -- ignore communucations behind API gateway  
    if isPrivate(pinfo.net_src) and isPrivate(pinfo.net_dst) then 
        return 0 
    end 
    pinfo.cols.protocol = "SHARP" 
    -- get the length of the packet buffer 
    local packet_len  = buffer:len() 
    local subtree
    if packet_len == buffer:reported_len() then 
        subtree = tree:add(sharp_proto,buffer(),"SHARP")
    else 
        subtree = tree:add(sharp_proto,buffer(),"SHARP(broken)") 
    end 
    local tcp_load       = buffer():string()
    local bytes_consumed = 0; 
    -- server send 
    if isPrivate(pinfo.net_src) then
        readData(buffer(), pinfo, subtree)
        return packet_len 
    end 
    -- client send 
    local jj, kk
    kk = 1 
    while bytes_consumed < packet_len do 
        _, jj = tcp_load:find( default_settings.delimiter, kk )
        if jj then 
            readData(buffer(kk-1,jj-kk+1), pinfo, subtree) 
            bytes_consumed         = bytes_consumed + jj - kk + 1 
        else 
            pinfo.desegment_offset = bytes_consumed 
            pinfo.desegment_len    = DESEGMENT_ONE_MORE_SEGMENT
            return packet_len
        end 
        kk = jj+1; 
    end 
    return packet_len 
end

local proto_fields = {
-- for more, see ProtoField: 
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html 
    length    = ProtoField.uint32("sharp.length", "Section Length", base.DEC), 
    type      = ProtoField.string("sharp.type", "Type", base.ASCII),       
    timestamp = ProtoField.uint32("sharp.timestamp", "Timestamp", base.DEC) 
}
sharp_proto.fields = proto_fields  

function readData(buffer, pinfo, tree) 
    local packet_len = buffer:len()
    local subtree    = tree:add(proto_fields.length, buffer, packet_len, nil, "bytes")
    local str        = buffer:string() 
    if str:sub(1,1) == "{" or str:sub(1,1) == "[" then 
        subtree:add(proto_fields.type, buffer, "json", nil, "(JSON)", "JavaScript Object Notation ")
    elseif str:sub(1,1) == "<" then 
        subtree:add(proto_fields.type, buffer, "xml", nil, "(XML)", "Extensible Markup Language ")
    else 
        subtree:add(proto_fields.type, buffer, "unknown")
    end 
    local t,tbuffer = getField(buffer,"T","[^\"]*")
    if t then 
        subtree:add(proto_fields.timestamp,tbuffer,t,nil,os.date("(%Y-%m-%d %X)", t))
    end 
end 

-- Private Internets, RFC1918
function isPrivate(address)
-- 24-bit block  
    if (Address.ip("10.0.0.0")<=address) and (address<=Address.ip("10.255.255.255")) then 
        return true 
    end 
-- 20-bit block  
    if (Address.ip("172.16.0.0")<=address) and (address<=Address.ip("172.31.255.255")) then 
        return true 
    end
-- 16-bit block 
    if (Address.ip("192.168.0.0")<=address) and (address<=Address.ip("192.168.255.255")) then 
        return true 
    end
    return false 
end 

function getField(buffer,key,value_pattern)
    local str = buffer:string()
    local pattern = "("..key.."=\"("..value_pattern..")\")"
    local whole, value = str:match(pattern)
    local target_buffer
    if whole then 
        local ii,jj   = str:find(pattern)
        target_buffer = buffer(ii-1,jj-ii+1) 
    end
    return value, target_buffer
end

function getField2(buffer,key,value_pattern)
    local str = buffer:string()
    local pattern = "[^%a]("..key.."=\"("..value_pattern..")\")"
    local whole, value = str:match(pattern)
    local target_buffer 
    if whole then 
        local ii,jj = str:find(pattern)
        ii = ii + 1
        target_buffer = buffer(ii-1,jj-ii+1)
    end
    return value, target_buffer
end

-- load the tcp.port table
tpc_table = DissectorTable.get("tcp.port")
-- register the protocol with port number 
tpc_table:add(default_settings.port,sharp_proto)
 
