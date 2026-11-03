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
