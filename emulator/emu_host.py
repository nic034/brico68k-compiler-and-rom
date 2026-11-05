# ---------------------------------------------------------------------------
# Core loader + Brico16Bits-like host (shared by the window and --run)
# ---------------------------------------------------------------------------
import ctypes
import re
import struct

FRAME_CYCLES = 202752
CPU_HZ = 12000000
H_IDLE, H_SENT, H_WAIT, H_DONE, H_TIMEOUT = range(5)
TYPE_VOID, TYPE_WORD, TYPE_STRING, TYPE_DUMP = range(4)
TYPE_NAMES = {TYPE_VOID: "void", TYPE_WORD: "word", TYPE_STRING: "text", TYPE_DUMP: "dump"}


class Core:
    def __init__(self, lib_path):
        self.lib = lib = ctypes.CDLL(str(lib_path))
        lib.neo_version.restype = ctypes.c_int
        lib.neo_load_bios.argtypes = [ctypes.c_char_p, ctypes.c_int]
        lib.neo_run.argtypes = [ctypes.c_uint32]
        lib.neo_host_send.argtypes = [ctypes.c_uint32] * 4
        lib.neo_host_values.argtypes = [ctypes.POINTER(ctypes.c_uint16), ctypes.c_int]
        lib.neo_host_cycles.restype = ctypes.c_uint32
        lib.neo_get_lines.argtypes = [ctypes.POINTER(ctypes.c_uint16)]
        lib.neo_frames.restype = ctypes.c_uint32
        lib.neo_pc.restype = ctypes.c_uint32
        lib.neo_cycles.restype = ctypes.c_uint64
        lib.neo_set_options.argtypes = [ctypes.c_int, ctypes.c_int]
        lib.neo_peek16.argtypes = [ctypes.c_uint32]
        lib.neo_peek16.restype = ctypes.c_uint16
        lib.neo_z80_commands.restype = ctypes.c_uint32
        lib.neo_fault_add.argtypes = [ctypes.c_int] * 4
        lib.neo_fault_add.restype = ctypes.c_int
        self._vals = (ctypes.c_uint16 * 2048)()
        self._lines = (ctypes.c_uint16 * 224)()

    def load(self, rom):
        if self.lib.neo_load_bios(rom, len(rom)) != 0:
            raise ValueError("ROM larger than 128 KB")

    def power_on(self):
        self.lib.neo_power_on()

    def lines(self):
        self.lib.neo_get_lines(self._lines)
        return list(self._lines)


def parse_extensions(rom):
    """[(name, address, type, description)] from the BricoNeo table at $A0."""
    exts, off = [], 0xA0
    for _ in range(200):
        addr, typ = struct.unpack_from(">IH", rom, off)
        if addr == 0xFFFFFFFF:
            return exts
        off += 6
        end = rom.index(b"\0", off); name = rom[off:end].decode("latin-1"); off = end + 1 + ((end + 1) & 1)
        end = rom.index(b"\0", off); desc = rom[off:end].decode("latin-1"); off = end + 1 + ((end + 1) & 1)
        exts.append((name, addr, typ, desc))
    raise ValueError("extension table without end marker")


def parse_uint(text):
    """Same rules as Brico16Bits Command::ParseUint: $hex, 0xhex or decimal."""
    t = text.strip()
    try:
        if t.startswith("$"):
            return int(t[1:], 16) & 0xFFFFFFFF
        if t.lower().startswith("0x"):
            return int(t, 16) & 0xFFFFFFFF
        return int(t) & 0xFFFFFFFF
    except ValueError:
        m = re.match(r"\d+", t)            # sscanf("%d") stops at the first non-digit
        return int(m.group()) if m else 0


def format_result(typ, values):
    """Text as Brico16Bits DisplayResult shows it."""
    if typ == TYPE_VOID:
        return ""
    if typ == TYPE_WORD:
        return f"0x{values[0]:04x}\n" if values else "[Empty]\n"
    if typ == TYPE_STRING:
        return "".join(chr(v & 0xFF) for v in values if v & 0xFF) + "\n"
    if typ == TYPE_DUMP:
        if len(values) < 2:
            return "[Empty]\n"
        base = values[0] | (values[1] << 16)
        out = [f"Memory content starting at address 0x{base:06x}:"]
        data = values[2:]
        for i in range(0, len(data), 8):
            row = data[i:i + 8]
            words = "".join(f"{w:04x} " for w in row) + "     " * (8 - len(row))
            chars = "".join((chr(c) if 32 <= c < 128 else ".") for w in row for c in (w >> 8, w & 0xFF))
            out.append(f"{base + 2 * i:06x}: {words} | {chars}")
        return "\n".join(out) + "\n"
    return f"Wrong return type sent by host ({typ})\n"


class Host:
    """Brico16Bits host on top of the core: commands by name, 1 ms clear, 3 s timeout."""

    def __init__(self, core, rom):
        self.core = core
        self.rom = rom
        self.exts = parse_extensions(rom)
        self.by_name = {n.lower(): (n, a, t, d) for n, a, t, d in self.exts}
        self.pending = None

    def find(self, name):
        return self.by_name.get(name.lower())

    def start(self, line):
        """Starts a command line ("TestDAC 1", "Dump $100000 8"). Returns an error text or None."""
        parts = line.split()
        if not parts:
            return "Empty command"
        ext = self.find(parts[0])
        if ext is None:
            return f"Unknown command: {parts[0]} (type Help)"
        params = [parse_uint(p) for p in parts[1:4]] + [0, 0, 0]
        if self.core.lib.neo_host_send(ext[1], params[0], params[1], params[2]) != 0:
            return "Busy: the previous command is still running"
        self.pending = ext
        return None

    def poll(self):
        """None while running, else (status, text, seconds)."""
        st = self.core.lib.neo_host_state()
        if st in (H_SENT, H_WAIT) or self.pending is None:
            return None
        n = self.core.lib.neo_host_values(self.core._vals, 2048)
        values = list(self.core._vals[:n])
        secs = self.core.lib.neo_host_cycles() / CPU_HZ
        self.core.lib.neo_host_ack()
        name, _, typ, _ = self.pending
        self.pending = None
        if st == H_TIMEOUT:
            return "timeout", "[Timeout]\n", 3.0
        text = format_result(typ, values)
        if self.core.lib.neo_host_overflow():
            text += "[Output truncated: more than 2048 words, the Brico16Bits buffer size]\n"
        return "eot", text, secs

    def run_blocking(self, line, max_frames=400):
        err = self.start(line)
        if err:
            return "error", err + "\n", 0.0
        for _ in range(max_frames):
            self.core.lib.neo_run_frame()
            r = self.poll()
            if r:
                return r
        return "timeout", "[Timeout]\n", 3.0


# ---------------------------------------------------------------------------
# Simulated faults
# ---------------------------------------------------------------------------
FAULT_REGIONS = {"wram": 0, "pal": 1, "vramlo": 2, "vramhi": 3, "line": 4}
REGION_NAMES = {0: "WRAM", 1: "Palette RAM", 2: "VRAM lower (slow)", 3: "VRAM upper (fast)",
                4: "LSPC line counter"}
FAULT_KINDS = {"data": 0, "addr": 1, "lane": 2}
DATA_BITS = {0: 15, 1: 15, 2: 15, 3: 15, 4: 8}
ADDR_RANGE = {0: (1, 15), 1: (1, 13), 2: (0, 14), 3: (0, 10)}

FAULT_HELP = ("Fault syntax: REGION:data:BIT:0|1 (data bit stuck), REGION:addr:LINE:0|1 (address line stuck),\n"
              "wram:lane:lower|upper (WRAM chip dead). REGION = wram, pal, vramlo, vramhi, line.\n"
              "Bits: data 0-15 (line counter 0-8); address WRAM A1-A15, pal A1-A12 + 13 = bank select,\n"
              "vramlo 0-14, vramhi 0-10. Example: --fault wram:data:5:1 --fault pal:addr:13:0")


def parse_fault(spec):
    """'wram:data:5:1' -> (region, kind, bit, value). Raises ValueError with a readable reason."""
    parts = spec.strip().lower().split(":")
    if len(parts) < 3 or parts[0] not in FAULT_REGIONS or parts[1] not in FAULT_KINDS:
        raise ValueError(f"bad fault '{spec}'. " + FAULT_HELP.splitlines()[0])
    region, kind = FAULT_REGIONS[parts[0]], FAULT_KINDS[parts[1]]
    if kind == 2:
        if region != 0 or parts[2] not in ("lower", "upper"):
            raise ValueError("byte lane faults: wram:lane:lower or wram:lane:upper")
        return region, kind, 0, 1 if parts[2] == "upper" else 0
    if len(parts) != 4 or parts[3] not in ("0", "1") or not parts[2].isdigit():
        raise ValueError(f"bad fault '{spec}': expected REGION:{parts[1]}:BIT:0|1")
    bit, value = int(parts[2]), int(parts[3])
    if kind == 0 and bit > DATA_BITS[region]:
        raise ValueError(f"{REGION_NAMES[region]}: data bits 0-{DATA_BITS[region]}")
    if kind == 1:
        if region not in ADDR_RANGE:
            raise ValueError("the line counter has no address lines")
        lo, hi = ADDR_RANGE[region]
        if not lo <= bit <= hi:
            raise ValueError(f"{REGION_NAMES[region]}: address lines {lo}-{hi}")
    return region, kind, bit, value


def describe_fault(f):
    region, kind, bit, value = f
    name = REGION_NAMES[region]
    if kind == 2:
        return f"{name}: {'upper (D8-D15)' if value else 'lower (D0-D7)'} chip dead"
    if kind == 0:
        return f"{name}: data bit D{bit} stuck at {value}"
    if region == 1 and bit == 13:
        return f"{name}: bank select stuck at bank {value}"
    return f"{name}: address line A{bit} stuck at {value}"


def fault_spec(f):
    region, kind, bit, value = f
    r = {v: k for k, v in FAULT_REGIONS.items()}[region]
    if kind == 2:
        return f"{r}:lane:{'upper' if value else 'lower'}"
    return f"{r}:{'data' if kind == 0 else 'addr'}:{bit}:{value}"


def apply_faults(core, faults):
    core.lib.neo_fault_clear()
    for f in faults:
        if core.lib.neo_fault_add(*f) != 0:
            raise ValueError(f"fault refused by the core: {describe_fault(f)}")


# ---------------------------------------------------------------------------
# Real console logs (PuTTY / Tera Term session log of the BricoNeo console)
# ---------------------------------------------------------------------------
_ESC = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
# Brico16Bits built-in commands (Commands/*.cpp, COMMAND_NAME), lower case
CONSOLE_BUILTINS = {"loadbank", "storebank", "bootsel", "clearbuffer", "dbg", "delay", "free", "freq", "listroms",
                    "ls", "readword", "readwords", "reset", "sendrompart", "setromw", "trace", "?"}


def clean_terminal(raw):
    """Terminal output -> plain lines, as the screen showed them: colour codes removed, CR, backspace
    and erase-line applied (the console redraws its prompt with CR + ESC[2K and erases with BS SP BS)."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    lines, line, col = [], [], 0
    pos = 0
    for m in list(_ESC.finditer(raw)) + [None]:
        chunk = raw[pos:m.start()] if m else raw[pos:]
        for ch in chunk:
            if ch == "\n":
                lines.append("".join(line).rstrip()); line, col = [], 0
            elif ch == "\r":
                col = 0
            elif ch == "\b":
                col = max(0, col - 1)
            elif ch < " " and ch != "\t":
                continue                                  # bell and other controls
            else:
                if col < len(line):
                    line[col] = ch
                else:
                    line.append(ch)
                col += 1
        if m is None:
            break
        seq = m.group()
        if seq in ("\x1b[2K", "\x1b[K", "\x1b[0K"):
            if seq == "\x1b[2K":
                line, col = [], 0
            else:
                del line[col:]
        elif seq in ("\x1b[2J", "\x1b[H"):
            if seq == "\x1b[2J":
                lines.append(""); line, col = [], 0
        pos = m.end()
    if line:
        lines.append("".join(line).rstrip())
    return lines


def parse_console_log(raw, ext_names):
    """Session log -> [{'line': typed command, 'name': extension or built-in, 'output': text}].
    A command line is '> ' followed by an extension name, a console built-in or ';'. Other lines
    (extension output, even when it starts with '> ') belong to the command above them."""
    exts = {n.lower(): n for n in ext_names}
    entries, cur = [], None
    for line in clean_terminal(raw):
        if line.startswith(">"):
            rest = line[1:].strip()
            word = rest.split()[0].lstrip("*@") if rest else ""
            if not rest:
                cur = None                                 # idle prompt
                continue
            if rest.startswith(";") or word.lower() in exts or word.lower() in CONSOLE_BUILTINS:
                name = ";" if rest.startswith(";") else exts.get(word.lower(), word)
                cur = {"line": rest, "name": name, "output": []}
                entries.append(cur)
                continue
        if cur is not None:
            cur["output"].append(line)
    for e in entries:
        while e["output"] and not e["output"][-1].strip():
            e["output"].pop()
        e["output"] = "\n".join(e["output"]) + ("\n" if e["output"] else "")
    return entries
