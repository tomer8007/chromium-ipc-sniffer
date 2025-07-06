local common = {}
-- local d = require('debug')

local json = require('json')

function common.get_chrome_type_name(opcode)
  local opcode_name = "Unknown"

  if opcode ==  0 then opcode_name = "Unknown" end
  if opcode == 1 then opcode_name = "Broker" end
  if opcode == 2 then opcode_name = "Renderer" end
  if opcode == 3 then opcode_name = "Extension" end
  if opcode == 4 then opcode_name = "Notification" end
  if opcode == 5 then opcode_name = "Plugin" end
  if opcode == 6 then opcode_name = "Worker" end
  if opcode == 7 then opcode_name = "NCAL" end
  if opcode == 8 then opcode_name = "GPU Process" end
  if opcode == 9 then opcode_name = "Watcher" end
  if opcode == 10 then opcode_name = "Service Worker" end
  if opcode == 11 then opcode_name = "Network Service" end
  if opcode == 12 then opcode_name = "Audio Service" end
  if opcode == 13 then opcode_name = "CDM Service" end

  return opcode_name
end

function common.readAll(file)
  local f = assert(io.open(file, "rb"))
  local content = f:read("*all")
  f:close()
  return content
end

function common.script_path()
  local str = debug.getinfo(2, "S").source:sub(2)
  return str:match("(.*[/\\])")
end

function common.json_to_table(json_str)
  -- L="return ".. json:gsub('("[^"]-"):','[%1]=') 
  -- return loadstring(L)()
  return json.decode(json_str)
end

function common.split (inputstr, sep)
  if sep == nil then
	sep = "%s"
  end

  local t={}
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
          table.insert(t, str)
  end
  return t
end

function common.trim(s)
   return s:gsub("^%s+", ""):gsub("%s+$", "")
end

function common.startswith(str,start)
   return str:sub(1, #start) == start
end

function common.endswith(str,ending)
   return ending == "" or str:sub(-#ending) == ending
end

function common.last_indexof(str, pattern)
	return str:match(".*()" .. pattern)
end

function common.find_last(haystack, needle)
    local i=haystack:match(".*"..needle.."()")
    if i==nil then return nil else return i-1 end
end

function common.merge_tables(first_table, second_table)
	for k,v in pairs(second_table) do first_table[k] = v end
	return first_table
end

function common.numLong(s)
    ret = 0
    for i=1,string.len(s),1 do
        ret = (ret * 256) + string.byte(s,i)
    end
    return ret
end


return common