-- Banc de test MAME : simule l'hote BricoNeo et execute des extensions
-- Brico68k sur le driver "aes". Sortie : une ligne JSON par extension
-- dans le fichier OUT (variable d'environnement BRICO_OUT).
-- Les commandes a lancer viennent de BRICO_JOBS : "addr,p1,p2,p3,name;..."

-- MAME re-runs the autoboot script after a soft reset (MVS watchdog, used
-- by TestWatchdog): the first instance keeps running, a second one would
-- truncate the output file. Run once per process.
if BRICO_RUNNER_LOADED then return end
BRICO_RUNNER_LOADED = true

local OUT = os.getenv("BRICO_OUT")
local JOBS = os.getenv("BRICO_JOBS") or ""
local MAX_FRAMES_PER_JOB = tonumber(os.getenv("BRICO_MAXFRAMES") or "1200")

local cpu = manager.machine.devices[":maincpu"]
local space = cpu.spaces["program"]
local region = manager.machine.memory.regions[":mainbios"]

local CMD_IN = 0x90  -- offsets dans la ROM (verifies par lecture du magic)

local function parse_jobs(s)
  local jobs = {}
  for item in string.gmatch(s, "[^;]+") do
    local a, p1, p2, p3, name = string.match(item, "([^,]+),([^,]+),([^,]+),([^,]+),([^,]+)")
    table.insert(jobs, {addr=tonumber(a), p1=tonumber(p1), p2=tonumber(p2), p3=tonumber(p3), name=name})
  end
  return jobs
end

local jobs = parse_jobs(JOBS)
-- BRICO_EXTRA_LUA : script de diagnostic supplementaire (dofile)
if os.getenv("BRICO_EXTRA_LUA") then dofile(os.getenv("BRICO_EXTRA_LUA")) end
local f = io.open(OUT, "w")

-- la region est lue/ecrite en ordre natif (little-endian) alors que le
-- 68000 la voit en big-endian : on echange les octets de chaque mot.
local function sw(v) return v end -- verifie empiriquement : write_u16 est deja dans le bon ordre pour le 68000

-- BIOS socket address faults (68000 -> BricoNeo), BRICO_SOCKET="bit,value;..."
-- (A1-A16 stuck at value). The CPU at socket offset x gets the word of
-- salias(x): the region is rewritten once, and everything the BricoNeo does
-- by address (command block, port, EOT) uses the address the socket sees.
local SOCK = {}
for b, v in string.gmatch(os.getenv("BRICO_SOCKET") or "", "(%d+),(%d)") do
  table.insert(SOCK, {bit = tonumber(b), v = tonumber(v)})
end
local function salias(o)
  for _, s in ipairs(SOCK) do
    local m = 1 << s.bit
    if s.v == 1 then o = o | m else o = o & ~m end
  end
  return o & 0x1fffe
end
-- CPU offsets whose socket address is o (none when a stuck line forbids o)
local function preimages(o)
  local out = {}
  local n = #SOCK
  for c = 0, (1 << n) - 1 do
    local x = o
    for i, s in ipairs(SOCK) do
      local m = 1 << s.bit
      if (c >> (i - 1)) & 1 == 1 then x = x | m else x = x & ~m end
    end
    if salias(x) == o then out[x] = true end
  end
  local list = {}
  for x in pairs(out) do table.insert(list, x) end
  return list
end
if #SOCK > 0 then
  local orig = {}
  for x = 0, 0x1fffe, 2 do orig[x] = region:read_u16(x) end
  for x = 0, 0x1fffe, 2 do region:write_u16(x, orig[salias(x)]) end
end

local function w16(off, v)
  if #SOCK == 0 then region:write_u16(off, sw(v)); return end
  for _, x in ipairs(preimages(off)) do region:write_u16(x, sw(v)) end
end
local function w32(off, v)
  w16(off, (v >> 16) & 0xffff)
  w16(off + 2, v & 0xffff)
end

local function json_escape(s)
  s = s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n"):gsub("\r", "\\r"):gsub("\t", "\\t")
  s = s:gsub("[%c]", function(c) return string.format("\\u%04x", c:byte()) end)
  return s
end

-- verification de l'endianness d'acces a la region
local m0 = region:read_u16(0x80)
f:write(string.format('{"probe_magic":"%04x"}\n', m0))
f:flush()

local expecting = false
local values = {}
local eot = false
local resets = 0

local function port_tap(offset, data, mask)
  local o = salias(offset & 0x1fffe)
  if o == 0x1ff02 then
    expecting = true
  elseif o == 0x1ff00 then
    eot = true
  end
  return data
end
BRICO_TAP_PORT = {}
if #SOCK == 0 then
  BRICO_TAP_PORT[1] = space:install_read_tap(0xc1ff00, 0xc1ff03, "brico_port", port_tap)
else
  for _, t in ipairs({0x1ff00, 0x1ff02}) do
    for _, x in ipairs(preimages(t)) do
      table.insert(BRICO_TAP_PORT, space:install_read_tap(0xc00000 + x, 0xc00001 + x, "brico_port" .. x, port_tap))
    end
  end
end

BRICO_TAP_DATA = space:install_read_tap(0xc20000, 0xc3ffff, "brico_data", function(offset, data, mask)
  if expecting then
    expecting = false
    table.insert(values, salias((offset - 0xc20000) & 0x1fffe) // 2)
  end
  return data
end)

-- Forcage optionnel de l'octet STATUS_B ($380000, octet haut du mot) :
-- BRICO_STATUSB="clear,set" (masques 8 bits). Permet de tester les
-- chemins MVS (bit 7) et les etats carte memoire (bits 4-6) sous "aes".
local sb = os.getenv("BRICO_STATUSB")
if sb then
  local clr, set = string.match(sb, "([^,]+),([^,]+)")
  clr = tonumber(clr); set = tonumber(set)
  BRICO_TAP_SB = space:install_read_tap(0x380000, 0x380001, "brico_statusb", function(offset, data, mask)
    if (mask & 0xff00) ~= 0 then
      data = (data & ~(clr << 8)) | (set << 8)
    end
    return data
  end)
end

-- Pannes simulees :
-- BRICO_STUCK="start,end,ormask,andmask" : donnees lues = (d & and) | or
-- BRICO_ALIAS="start,end,addrmask" : stockage fantome indexe par
--   (adresse & addrmask) -> simule une ligne d'adresse collee a 0, ou
--   (sur la palette) une ligne de selection de banque collee.
local st = os.getenv("BRICO_STUCK")
if st then
  local a, b, o, n = string.match(st, "([^,]+),([^,]+),([^,]+),([^,]+)")
  a = tonumber(a); b = tonumber(b); o = tonumber(o); n = tonumber(n)
  BRICO_TAP_STUCK = space:install_read_tap(a, b, "brico_stuck", function(offset, data, mask)
    return (data & n) | o
  end)
end
local al = os.getenv("BRICO_ALIAS")
if al then
  local a, b, m = string.match(al, "([^,]+),([^,]+),([^,]+)")
  a = tonumber(a); b = tonumber(b); m = tonumber(m)
  BRICO_SHADOW = {}
  BRICO_TAP_ALIAS_W = space:install_write_tap(a, b, "brico_alias_w", function(offset, data, mask)
    local k = offset & m
    local old = BRICO_SHADOW[k] or 0
    BRICO_SHADOW[k] = (old & ~mask) | (data & mask)
    return data
  end)
  BRICO_TAP_ALIAS_R = space:install_read_tap(a, b, "brico_alias_r", function(offset, data, mask)
    return BRICO_SHADOW[offset & m] or 0
  end)
end

-- Trace de lectures : BRICO_LOGREAD="start,end,max" -> {"read":addr,"data":v}
local lr = os.getenv("BRICO_LOGREAD")
if lr then
  local a, b, n = string.match(lr, "([^,]+),([^,]+),([^,]+)")
  a = tonumber(a); b = tonumber(b); n = tonumber(n)
  local logged = 0
  BRICO_TAP_LOG = space:install_read_tap(a, b, "brico_logread", function(offset, data, mask)
    if logged < n then
      logged = logged + 1
      f:write(string.format('{"read":"%06x","data":"%04x","mask":"%04x","pc":"%x"}\n', offset, data, mask, cpu.state["CURPC"].value))
    end
    return data
  end)
end

-- 1 ms clear, as Brico16Bits (CommandExtension.cpp: sleep_ms(1) then clear):
-- the first read of the command block 1 ms (machine time) or more after the
-- launch sees it cleared. The frame-based clear below stays as a fallback.
BRICO_T_LAUNCH = nil
BRICO_CLEARED = true
local function clear_cmd()
  BRICO_CLEARED = true
  w32(CMD_IN, 0); w32(CMD_IN + 4, 0); w32(CMD_IN + 8, 0); w32(CMD_IN + 12, 0)
end
local function clear_tap(offset, data, mask)
  if not BRICO_CLEARED and BRICO_T_LAUNCH and manager.machine.time:as_double() - BRICO_T_LAUNCH >= 0.001 then
    clear_cmd()
    return 0
  end
  return data
end
BRICO_TAP_1MS = {}
if #SOCK == 0 then
  BRICO_TAP_1MS[1] = space:install_read_tap(0xc00090, 0xc0009f, "brico_clear_1ms", clear_tap)
else
  for o = 0x90, 0x9e, 2 do
    for _, x in ipairs(preimages(o)) do
      table.insert(BRICO_TAP_1MS, space:install_read_tap(0xc00000 + x, 0xc00001 + x, "brico_clear" .. x, clear_tap))
    end
  end
end

-- Captures d'ecran : BRICO_SNAP="i,j" (numeros de commande, 1 = premiere)
local SNAP = {}
for n in string.gmatch(os.getenv("BRICO_SNAP") or "", "%d+") do SNAP[tonumber(n)] = true end
local SNAP_FRAMES = tonumber(os.getenv("BRICO_SNAP_FRAMES") or "30")
local snap_wait = 0

local state = "boot"
local frames = 0
local job_i = 0
local job_frames = 0

local function finish_job(status)
  local j = jobs[job_i]
  local chars = {}
  for _, v in ipairs(values) do
    if v == 10 or (v >= 32 and v < 127) then table.insert(chars, string.char(v)) end
  end
  local hex = {}
  for _, v in ipairs(values) do table.insert(hex, string.format("%04x", v)) end
  local stk = {}
  for a = 0x10f2f0, 0x10f2fe, 2 do table.insert(stk, string.format("%04x", space:read_u16(a))) end
  f:write(string.format('{"name":"%s","status":"%s","frames":%d,"count":%d,"text":"%s","hex":"%s","stack":"%s"}\n',
    j.name, status, job_frames, #values, json_escape(table.concat(chars)), table.concat(hex, " "), table.concat(stk, " ")))
  f:flush()
end


BRICO_SUB = emu.add_machine_frame_notifier(function()
  frames = frames + 1
  if state == "boot" then
    if os.getenv("BRICO_TRACE") and frames == 30 then
      local parts = {}
      for k, v in pairs(cpu.state) do table.insert(parts, string.format('"%s":"%x"', k, v.value)) end
      f:write("{" .. table.concat(parts, ",") .. "}\n")
      f:flush()
    end
    if os.getenv("BRICO_TRACE") and (frames % 20) == 1 then
      f:write(string.format('{"boot_pc":"%x","frame":%d}\n', cpu.state["CURPC"].value, frames))
      f:flush()
    end
    if frames >= 60 then
      -- NB (cartouche AES via liste logicielle) : dans ce MAME, les lectures CPU
      -- de $000100-$000103 renvoient parfois $FFFF, de facon NON deterministe
      -- (meme config : $FFFF puis la bonne valeur). Cause non trouvee.
      -- BRICO_MEMDUMP="start,end,file" : copie binaire (68000, big-endian) vue par le CPU
      local md = os.getenv("BRICO_MEMDUMP")
      if md then
        local a, b, fn = string.match(md, "([^,]+),([^,]+),(.+)")
        local fd = io.open(fn, "wb")
        for ad = tonumber(a), tonumber(b), 2 do
          local v = space:read_u16(ad)
          fd:write(string.char(v >> 8, v & 0xff))
        end
        fd:close()
      end
      state = "next"
    end
    return
  end
  if state == "next" then
    -- s'assurer que la commande est a 0 avant de lancer la suivante
    w32(CMD_IN, 0)
    job_i = job_i + 1
    if job_i > #jobs then
      state = "done"
      f:write('{"done":true}\n')
      f:close()
      manager.machine:exit()
      return
    end
    local j = jobs[job_i]
    values = {}
    eot = false
    expecting = false
    job_frames = 0
    state = "settle"
    return
  end
  if state == "settle" then
    -- laisser la boucle .loop_wait_for_no_command voir le 0
    job_frames = job_frames + 1
    if job_frames >= 3 then
      local j = jobs[job_i]
      w32(CMD_IN + 4, j.p1)
      w32(CMD_IN + 8, j.p2)
      w32(CMD_IN + 12, j.p3)
      w32(CMD_IN, j.addr)
      BRICO_T_LAUNCH = manager.machine.time:as_double()
      BRICO_CLEARED = false
      if os.getenv("BRICO_TRACE") then
        f:write(string.format('{"set_cmd":"%08x","seen":"%08x","p1seen":"%08x","pc":"%x"}\n', j.addr, space:read_u32(0xc00090), space:read_u32(0xc00094), cpu.state["CURPC"].value))
        f:flush()
      end
      job_frames = 0
      state = "run"
    end
    return
  end
  if state == "run" then
    job_frames = job_frames + 1
    if job_frames == 1 and not BRICO_CLEARED then
      -- fallback: the extension did not read the command after 1 ms
      clear_cmd()
    end
    if job_frames == 2 and os.getenv("BRICO_TRACE") then
      f:write(string.format('{"trace_pc":"%x","cmd_seen":"%08x","p1_seen":"%08x"}\n', cpu.state["CURPC"].value, space:read_u32(0xc00090), space:read_u32(0xc00094)))
      f:flush()
    end
    local done = nil
    if eot then done = "eot" elseif job_frames >= MAX_FRAMES_PER_JOB then done = "timeout" end
    if done then
      finish_job(done)
      if SNAP[job_i] then state = "snap"; snap_wait = 0 else state = "next" end
    end
    return
  end
  if state == "snap" then
    snap_wait = snap_wait + 1
    if snap_wait >= SNAP_FRAMES then
      local j = jobs[job_i]
      manager.machine.screens[":screen"]:snapshot(string.format("job%02d_%s.png", job_i, j.name))
      state = "next"
    end
  end
end)
