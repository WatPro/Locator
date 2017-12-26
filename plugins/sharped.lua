-------------------------------------------------------------------------------
--
-- SHARP
--
-------------------------------------------------------------------------------
--[[

]]----------------------------------------

local default_settings = 
{
    port       = 7076, 
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
    local subtree = tree:add(sharp_proto,buffer(),"SHARP")
    -- get the length of the packet buffer 
    local packet_len     = buffer:len() 
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
    type = ProtoField.string("sharp.type", "Type", base.ASCII)
}
sharp_proto.fields = proto_fields  

function readData(buffer, pinfo, tree) 
    local packet_len = buffer:len()
    local subtree    = tree:add(buffer,"Section Size: " .. packet_len)
    local str        = buffer:string() 
    if str:sub(1,1) == "{" or str:sub(1,1) == "[" then 
        subtree:add(proto_fields.type, "json", "Type:", "JavaScript Object Notation (JSON) ")
    elseif str:sub(1,1) == "<" then 
        subtree:add(proto_fields.type, "xml", "Type:", "Extensible Markup Language (XML) ")
    else 
        subtree:add(proto_fields.type, "unknown", "Type:", "Unknown ")
    end 
    getField(buffer,subtree,"T","Timestamp","[^\"]*")
end 

function isPrivate(address)
-- Private Internets, 24-bit block, RFC1918 
    if (Address.ip("10.0.0.0")<=address) and (address<=Address.ip("10.255.255.255")) then 
        return true 
    end 
    return false 
end 

function getField(buffer,tree,key,key_name,value_pattern)
    local str = buffer:string()
    local pattern = "("..key.."=\"("..value_pattern..")\")"
    local whole, value = str:match(pattern)
    if whole then 
        local ii,jj = str:find(pattern)
-- alternatively, pattern = "[^%a]("..key.."=\"("..value_pattern..")\")" 
-- then ii = ii + 1
        tree:add(buffer(ii-1,jj-ii+1),key_name..": "..value)
    end
    return value
end



-- load the tcp.port table
tpc_table = DissectorTable.get("tcp.port")
-- register the protocol with port number 
tpc_table:add(default_settings.port,sharp_proto)
