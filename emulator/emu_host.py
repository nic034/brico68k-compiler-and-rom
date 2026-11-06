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
        lib.neo_cart_load.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        lib.neo_cart_load.restype = ctypes.c_int
        lib.neo_cart_writes.restype = ctypes.c_uint32
        lib.neo_cart_latch_writes.restype = ctypes.c_uint32
        lib.neo_cart_bank.restype = ctypes.c_int
        self.cart = None
        self._vals = (ctypes.c_uint16 * 2048)()
        self._lines = (ctypes.c_uint16 * 224)()

    def load(self, rom):
        if self.lib.neo_load_bios(rom, len(rom)) != 0:
            raise ValueError("ROM larger than 128 KB")

    def load_cart(self, cart):
        """cart: None, 'none', 'test', 'diag' or a CartImage (see load_cartridge). Like a real
        cartridge it stays in across power cycles; insert it with the console off."""
        if isinstance(cart, str) or cart is None:
            cart = make_cart(cart or "none")
        data = cart.data or None
        if self.lib.neo_cart_load(cart.mode, data, len(cart.data)) != 0:
            raise ValueError(f"cartridge refused by the core ({len(cart.data)} bytes)")
        self.cart = cart

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


EXC_NAMES = {2: "bus error", 3: "address error", 4: "illegal instruction", 5: "divide by zero", 6: "CHK",
             7: "TRAPV", 8: "privilege violation", 10: "line A opcode", 11: "line F opcode",
             24: "unexpected interrupt"}


def format_exception(typ, values):
    """Brico16Bits (local branch workspace/nicolas-exceptions): a 68000 exception ends the output with
    the 68k command EXCPT + 6 words; the output before it is shown as usual, then the report
    (CommandExtension + Command68kException). None when the output does not end with a report."""
    if len(values) < 11 or any((values[-11 + i] != ord(ch)) for i, ch in enumerate("EXCPT")):
        return None
    v = values[-6:]
    txt = format_result(typ, values[:-11]) if len(values) > 11 else ""
    txt += (f"\n*** 68000 exception: {EXC_NAMES.get(v[0], 'reserved vector')} (vector {v[0]}) "
            f"at PC ${(v[2] << 16) | v[3]:06x}, SR ${v[1]:04x}")
    if v[0] in (2, 3):
        txt += f", access ${(v[4] << 16) | v[5]:06x}"
    return txt + " ***\n(PC/SR are read from the exception frame in work RAM)\n" \
        "[Extension aborted by a 68000 exception]\n"


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
        exc = format_exception(typ, values)
        if exc:
            return "exception", exc, secs
        text = format_result(typ, values)
        if self.core.lib.neo_host_overflow():
            text += ("[More than 2047 words: the BricoNeo ring buffer wrapped, only the last words are left "
                     "(Brico16Bits InputBuffer, 2048 words)]\n")
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
# Test cartridge P ROM (same bytes as tools/make_test_cart.py, checked by compare_mame.py)
# ---------------------------------------------------------------------------
# Security code: 61 words (neogeodev wiki "Security code", word 25 = $6606 as in the system ROM)
SECURITY_CODE = [
    0x7600, 0x4A6D, 0x0A14, 0x6600, 0x003C, 0x206D, 0x0A04, 0x3E2D, 0x0A08, 0x13C0,
    0x0030, 0x0001, 0x3210, 0x0C01, 0x00FF, 0x671A, 0x3028, 0x0002, 0xB02D, 0x0ACE,
    0x6610, 0x3028, 0x0004, 0xB02D, 0x0ACF, 0x6606, 0xB22D, 0x0AD0, 0x6708, 0x5088,
    0x51CF, 0xFFD4, 0x3607, 0x4E75, 0x206D, 0x0A04, 0x3E2D, 0x0A08, 0x3210, 0xE049,
    0x0C01, 0x00FF, 0x671A, 0x3010, 0xB02D, 0x0ACE, 0x6612, 0x3028, 0x0002, 0xE048,
    0xB02D, 0x0ACF, 0x6606, 0xB22D, 0x0AD0, 0x6708, 0x5888, 0x51CF, 0xFFD8, 0x3607,
    0x4E75]
TEST_CART_SEC = 0x186


def test_cart_prom():
    """3 MB P ROM in 68000 order: pseudo-random words (fixed seed) + a game header
    ("NEO-GEO", NGH $0999, P ROM size $300000, security code pointer $182 -> $186)."""
    import random
    rnd = random.Random(0xB1C068)
    p = bytearray(rnd.getrandbits(8) for _ in range(3 * 0x100000))
    p[0x100:0x108] = b"NEO-GEO\x00"
    p[0x108:0x10A] = (0x0999).to_bytes(2, "big")
    p[0x10A:0x10E] = (0x300000).to_bytes(4, "big")
    p[0x182:0x186] = TEST_CART_SEC.to_bytes(4, "big")
    for i, w in enumerate(SECURITY_CODE):
        p[TEST_CART_SEC + 2 * i:TEST_CART_SEC + 2 * i + 2] = w.to_bytes(2, "big")
    return bytes(p)


# ---------------------------------------------------------------------------
# Cartridges: none, built-in test cartridge, a game ROM set (folder or MAME zip), the
# diagnostic PROG board. Only P1/P2 are on the 68000 bus (the core gets them); S, C, V
# and M1 are loaded and checked (size, CRC32) but not used: the core renders no fix
# layer or sprites and has no YM2610.
# ---------------------------------------------------------------------------
CART_MODES = {"none": 0, "test": 1, "game": 1, "diag": 2}
CHIP_AREAS = {"maincpu": "P", "fixed": "S", "audiocpu": "M1", "ymsnd:adpcma": "V", "ymsnd:adpcmb": "V",
              "ymsnd": "V", "sprites": "C"}
MAX_FILE = 64 << 20          # largest Neo Geo chip is 16 MB; refuse anything silly
MAX_SET = 512 << 20


class CartImage:
    def __init__(self, kind, data=b"", name="", chips=None, notes=None):
        self.kind, self.mode, self.data, self.name = kind, CART_MODES[kind], data, name
        self.chips = chips or []        # dicts: chip, file, size, crc, expected, status
        self.notes = notes or []

    def describe(self):
        if self.kind == "none":
            return "No cartridge"
        if self.kind == "diag":
            return "Diagnostic PROG board (SRAM 1 MiB)"
        banks = max(0, len(self.data) // 0x100000 - 1)
        return f"{self.name or 'Game cartridge'} (P1 + {banks} P2 bank{'s' if banks != 1 else ''})"

    def report(self):
        lines = [self.describe()]
        for c in self.chips:
            exp = f" list {c['expected']}" if c.get("expected") and c["expected"] != c.get("crc") else ""
            size = f"{c['size']:#x}" if c.get("size") is not None else "-"
            lines.append(f"  {c['chip']:<3} {c['file'] or '-':<22} {size:>9}  CRC32 {c.get('crc') or '-':<8}{exp}  {c['status']}")
        lines += [f"  {n}" for n in self.notes]
        return "\n".join(lines)


def make_cart(kind):
    if kind == "none":
        return CartImage("none")
    if kind == "test":
        return CartImage("test", test_cart_prom(), "Built-in test cartridge (NGH 0999)",
                         notes=["Generated P ROM: header + security code at $186, pseudo-random words "
                                "(same bytes as the MAME bench cartridge 'brtest')."])
    if kind == "diag":
        import random
        rnd = random.Random(0x5EA)       # SRAM power-on content: anything
        return CartImage("diag", bytes(rnd.getrandbits(8) for _ in range(0x100000)),
                         "Diagnostic PROG board", notes=[
                             "jwestfall69 neogeo-diag-aes-prog: one 1 MiB 16-bit SRAM read in P1 and P2, "
                             "written through P2 (byte lanes by /PORTWEU, /PORTWEL)."])
    raise ValueError(f"unknown cartridge '{kind}': none, test, diag or a ROM set path")


def _crc(data):
    import zlib
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def _word_swap(data):
    b = bytearray(data)
    b[0::2], b[1::2] = data[1::2], data[0::2]
    return bytes(b)


def read_rom_set(path):
    """{file name (lower case): bytes} from a folder (top level) or a .zip (MAME romset)."""
    from pathlib import Path
    import zipfile
    p, files, total = Path(path), {}, 0
    if p.is_dir():
        items = [(f.name, f.stat().st_size, f.read_bytes) for f in sorted(p.iterdir()) if f.is_file()]
    elif zipfile.is_zipfile(p):
        z = zipfile.ZipFile(p)
        items = [(Path(i.filename).name, i.file_size, (lambda i=i: z.read(i)))
                 for i in z.infolist() if not i.is_dir()]
    else:
        raise ValueError(f"{p.name}: not a folder nor a zip file")
    for name, size, read in items:
        if not name or name.startswith(".") or name.lower().endswith((".xml", ".txt", ".md", ".dat")):
            continue
        if size > MAX_FILE or total + size > MAX_SET:
            raise ValueError(f"{name}: too large for a Neo Geo ROM set")
        total += size
        files[name.lower()] = read()
    if not files:
        raise ValueError(f"{p.name}: no ROM file")
    return files


def parse_softlist(xml_path):
    """MAME software list (hash/neogeo.xml) -> {name: {"description", "areas": {area: (size,
    [ (name|None, offset, size, crc|None, loadflag|None) ])}}}. The file is the user's: parsed
    with expat, entities not expanded beyond the standard ones."""
    import xml.etree.ElementTree as ET
    out = {}
    for sw in ET.parse(str(xml_path)).getroot().iter("software"):
        areas = {}
        for part in sw.iter("part"):
            for da in part.iter("dataarea"):
                roms = []
                for r in da.iter("rom"):
                    roms.append((r.get("name"), int(r.get("offset", "0"), 0), int(r.get("size", "0"), 0),
                                 (r.get("crc") or "").lower() or None, r.get("loadflag")))
                areas[da.get("name")] = (int(da.get("size", "0"), 0), roms)
        out[sw.get("name")] = {"description": (sw.findtext("description") or "").strip(), "areas": areas,
                               "cloneof": sw.get("cloneof")}
    return out


def _build_area(size, roms, files, by_crc):
    """MAME ROM loading for one data area: load16_word_swap, load16_byte, continue, ignore."""
    region = bytearray(size)                 # MAME regions start zero-filled
    cur, pos, flag = None, 0, None
    for name, off, sz, crc, lf in roms:
        if name:
            cur = by_crc.get(crc) if crc else None
            if cur is None:
                cur = files.get(name.lower())
            if cur is None:
                return None
            pos, flag = 0, lf
        elif lf == "ignore":
            pos += sz
            continue
        elif lf != "continue" or cur is None:
            continue                         # fill/unknown: left zero
        chunk = cur[pos:pos + sz]
        pos += sz
        mode = flag if lf == "continue" else lf
        if mode == "load16_word_swap":
            chunk = _word_swap(chunk)
        if mode == "load16_byte":
            end = min(off + 2 * len(chunk), size)
            region[off:end:2] = chunk[:(end - off + 1) // 2]
        else:
            region[off:off + len(chunk)] = chunk[:max(0, size - off)]
    return bytes(region)


def _p_window(maincpu):
    """MAME maincpu region -> P1 MB + whole 1 MB P2 banks (a smaller chip is mirrored, as it
    ignores the upper address lines)."""
    if not maincpu:
        raise ValueError("no P ROM")
    p1 = maincpu[:0x100000]
    while len(p1) < 0x100000:
        p1 = (p1 + p1)[:0x100000]
    p2 = maincpu[0x100000:]
    if len(p2) % 0x100000:
        last = p2[len(p2) // 0x100000 * 0x100000:]
        while len(last) < 0x100000:
            last = (last + last)[:0x100000]
        p2 = p2[:len(p2) // 0x100000 * 0x100000] + last
    data = p1 + p2
    if len(data) > 0x1000000:
        raise ValueError("P ROM larger than 16 MB")
    return data


def _chip_of(name):
    m = re.search(r"(?:^|[-_.])(?:e|s)?(p|s|m|v|c)(\d)(?:[._-]|$)", name.lower())
    return {"p": "P", "s": "S", "m": "M1", "v": "V", "c": "C"}[m.group(1)] if m else "?"


def load_cartridge(path, softlist=None):
    """A game ROM set (folder or MAME zip) -> CartImage. With the official MAME list
    (hash/neogeo.xml) the set is identified by its CRCs, loaded with the list's layout and
    every chip checked; without it, P1/P2 are found by name and the byte order by the
    NEO-GEO header (CRCs listed, not checked)."""
    from pathlib import Path
    files = read_rom_set(path)
    crcs = {n: _crc(d) for n, d in files.items()}
    by_crc = {crcs[n]: d for n, d in files.items()}
    notes, chips = [], []
    if softlist:
        lst = parse_softlist(softlist) if not isinstance(softlist, dict) else softlist
        best, score = None, 0
        for sname, sw in lst.items():
            want = {c for _, (_, roms) in sw["areas"].items() for (_, _, _, c, _) in roms if c}
            s = len(want & set(by_crc))
            if s > score or (s == score and s and sname == Path(path).stem.lower()):
                best, score = sname, s
        if best is None:
            notes.append(f"No software of {Path(str(softlist)).name if not isinstance(softlist, dict) else 'the list'} "
                         "matches these files' CRC32: unknown or bad dump. Layout guessed from the header.")
        else:
            sw = lst[best]
            seen = set()
            for area, (size, roms) in sw["areas"].items():
                for name, off, sz, crc, lf in roms:
                    if not name:
                        continue
                    got = by_crc.get(crc) if crc else None
                    fname = next((n for n in files if crcs[n] == crc), None) if got is not None else None
                    if got is None and name.lower() in files:
                        fname = name.lower()
                    if fname:
                        seen.add(fname)
                    st = ("OK" if fname and crcs[fname] == crc else
                          "MISSING" if not fname else "BAD CRC (dump differs from the official list)")
                    if not crc:
                        st = "no CRC in the list (no good dump known)" if fname else "MISSING"
                    chips.append({"chip": CHIP_AREAS.get(area, area), "file": fname or name,
                                  "size": len(files[fname]) if fname else None,
                                  "crc": crcs.get(fname), "expected": crc, "status": st})
            for n in files:
                if n not in seen:
                    chips.append({"chip": _chip_of(n), "file": n, "size": len(files[n]), "crc": crcs[n],
                                  "expected": None, "status": "not in the list for this game"})
            if "maincpu" not in sw["areas"]:
                raise ValueError(f"{best}: the list has no maincpu (P ROM) area")
            size, roms = sw["areas"]["maincpu"]
            maincpu = _build_area(size, roms, files, by_crc)
            if maincpu is None:
                raise ValueError(f"{best}: P ROM file missing, cannot insert the cartridge")
            bad = [c for c in chips if c["status"] != "OK"]
            notes.append(f"Identified as '{best}' ({sw['description']}) by {score} CRC32 from the official list"
                         + (f"; {len(bad)} chip(s) not OK" if bad else "; every chip OK"))
            if any(c["status"] == "MISSING" for c in chips):
                notes.append("MISSING: not in this set. A MAME split clone set keeps the chips it shares in "
                             "its parent's zip: merge them, or check the parent too.")
            return CartImage("game", _p_window(maincpu), f"{best} - {sw['description']}", chips, notes)
    # no list (or no match): P1 / P2 by name, byte order and layout by the header
    ps = sorted((n for n in files if _chip_of(n) == "P"),
                key=lambda n: int(re.search(r"p(\d)", n).group(1)) if re.search(r"p(\d)", n) else 9)
    if not ps:
        raise ValueError("no P ROM file (name with p1 / p2) in the set")
    p1 = files[ps[0]]
    swap = None
    for sw_ in (True, False):
        d = _word_swap(p1) if sw_ else p1
        if d[0x100:0x107] == b"NEO-GEO":
            swap, layout = sw_, "flat"
        elif len(d) > 0x100107 and d[0x100100:0x100107] == b"NEO-GEO":
            swap, layout = sw_, "halves"
        if swap is not None:
            break
    if swap is None:
        raise ValueError(f"{ps[0]}: no NEO-GEO header in either byte order (encrypted or not a P1)")
    conv = (lambda d: _word_swap(d)) if swap else (lambda d: d)
    p = conv(p1)
    if layout == "halves":              # MAME ROM_CONTINUE: second MB at $000000, first at $100000
        p = p[0x100000:0x200000] + p[:0x100000] + p[0x200000:]
    maincpu = p                         # P1 (then P2 bank 0.. when the P1 file is over 1 MB)
    for n in ps[1:]:
        if len(maincpu) < 0x100000:
            maincpu = (maincpu * (0x100000 // len(maincpu) + 1))[:0x100000]
        maincpu += conv(files[n])
    for n in files:
        chips.append({"chip": _chip_of(n), "file": n, "size": len(files[n]), "crc": crcs[n],
                      "expected": None, "status": "not checked (no official list)"})
    notes.append(f"P ROM {'byte-swapped files (MAME order)' if swap else 'files in 68000 order'}, "
                 f"layout from the NEO-GEO header{' (P1 halves swapped, ROM_CONTINUE)' if layout == 'halves' else ''}. "
                 "Give the MAME list hash/neogeo.xml to check every chip's CRC32.")
    return CartImage("game", _p_window(maincpu), Path(path).stem, chips, notes)


# Simulated faults
# ---------------------------------------------------------------------------
FAULT_REGIONS = {"wram": 0, "pal": 1, "vramlo": 2, "vramhi": 3, "line": 4, "bios": 5, "cart": 6}
REGION_NAMES = {0: "WRAM", 1: "Palette RAM", 2: "VRAM lower (slow)", 3: "VRAM upper (fast)",
                4: "LSPC line counter", 5: "BIOS socket (68000 -> BricoNeo)", 6: "Cartridge slot P bus"}
FAULT_KINDS = {"data": 0, "addr": 1, "lane": 2, "float": 3, "strobe": 2}
# 0-3 strobes; 4-5 /PORTOE (P2 output enable); 6-9 the OE dead behind a 245 / NEO-G0 / NEO-BUF (bus hold)
STROBES = ["portwel", "portweu", "romoel", "romoeu", "portoel", "portoeu",
           "romoel245", "romoeu245", "portoel245", "portoeu245"]
# the BIOS socket has no data faults: a bad D line stops the boot, nothing to test
DATA_BITS = {0: 15, 1: 15, 2: 15, 3: 15, 4: 8, 5: -1, 6: 15}
ADDR_RANGE = {0: (1, 15), 1: (1, 13), 2: (0, 14), 3: (0, 10), 5: (1, 16), 6: (1, 19)}

FAULT_HELP = ("Fault syntax: REGION:data:BIT:0|1 (data bit stuck), REGION:addr:LINE:0|1 (address line stuck),\n"
              "wram:lane:lower|upper (WRAM chip dead), bios:float:LINE (BIOS socket line unstable).\n"
              "REGION = wram, pal, vramlo, vramhi, line, bios, cart. Bits: data 0-15 (line counter 0-8);\n"
              "address WRAM A1-A15, pal A1-A12 + 13 = bank select, vramlo 0-14, vramhi 0-10,\n"
              "bios A1-A16 (socket, 68000 -> BricoNeo; address faults only), cart A1-A19 (slot).\n"
              "Cartridge slot: cart:data:BIT:0|1, cart:addr:LINE:0|1, cart:float:BIT (D line unstable),\n"
              "cart:strobe:portwel|portweu|romoel|romoeu|portoel|portoeu (strobe dead; the OE ones: the 68000 reads\n"
              "its prefetched word), ...245 suffix (romoel245 ...): OE dead behind a 245, bus hold. Needs --cart test or diag.\n"
              "Example: --fault wram:data:5:1 --fault pal:addr:13:0 --fault bios:addr:15:1")


def parse_fault(spec):
    """'wram:data:5:1' -> (region, kind, bit, value). Raises ValueError with a readable reason."""
    parts = spec.strip().lower().split(":")
    if len(parts) < 3 or parts[0] not in FAULT_REGIONS or parts[1] not in FAULT_KINDS:
        raise ValueError(f"bad fault '{spec}'. " + FAULT_HELP.splitlines()[0])
    region, kind = FAULT_REGIONS[parts[0]], FAULT_KINDS[parts[1]]
    if kind == 2 and region == 6:
        if parts[1] != "strobe" or len(parts) != 3 or parts[2] not in STROBES:
            raise ValueError("cartridge strobe: cart:strobe:" + "|".join(STROBES))
        return region, kind, 0, STROBES.index(parts[2])
    if kind == 3 and region == 6:
        if len(parts) != 3 or not parts[2].isdigit() or not 0 <= int(parts[2]) <= 15:
            raise ValueError("unstable data line: cart:float:BIT, BIT 0-15")
        return region, kind, int(parts[2]), 0
    if kind == 2:
        if region != 0 or parts[1] != "lane" or parts[2] not in ("lower", "upper"):
            raise ValueError("byte lane faults: wram:lane:lower or wram:lane:upper")
        return region, kind, 0, 1 if parts[2] == "upper" else 0
    if kind == 3:
        if region != 5 or len(parts) != 3 or not parts[2].isdigit() or not 1 <= int(parts[2]) <= 16:
            raise ValueError("unstable line: bios:float:LINE, LINE 1-16")
        return region, kind, int(parts[2]), 0
    if len(parts) != 4 or parts[3] not in ("0", "1") or not parts[2].isdigit():
        raise ValueError(f"bad fault '{spec}': expected REGION:{parts[1]}:BIT:0|1")
    bit, value = int(parts[2]), int(parts[3])
    if kind == 0 and bit > DATA_BITS[region]:
        if DATA_BITS[region] < 0:
            raise ValueError(f"{REGION_NAMES[region]}: address faults only (a bad data line stops the boot)")
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
    if kind == 2 and region == 6:
        return f"{name}: /{STROBES[value].upper()} dead"
    if kind == 3 and region == 6:
        return f"{name}: data line D{bit} unstable"
    if kind == 2:
        return f"{name}: {'upper (D8-D15)' if value else 'lower (D0-D7)'} chip dead"
    if kind == 0:
        return f"{name}: data bit D{bit} stuck at {value}"
    if kind == 3:
        return f"{name}: address line A{bit} unstable"
    if region == 1 and bit == 13:
        return f"{name}: bank select stuck at bank {value}"
    return f"{name}: address line A{bit} stuck at {value}"


def fault_spec(f):
    region, kind, bit, value = f
    r = {v: k for k, v in FAULT_REGIONS.items()}[region]
    if kind == 2 and region == 6:
        return f"{r}:strobe:{STROBES[value]}"
    if kind == 2:
        return f"{r}:lane:{'upper' if value else 'lower'}"
    if kind == 3:
        return f"{r}:float:{bit}"
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
