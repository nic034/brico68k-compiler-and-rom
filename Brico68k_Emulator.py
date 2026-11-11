#!/usr/bin/env python3
"""Brico68k Emulator - test the Brico68k ROM without a BricoNeo / Brico16Bits.

One file, no MAME: a Neo Geo AES model built around the Musashi 68000 core
(C, embedded below as a Windows x64 DLL and a Linux x64 shared library) plus
a Brico16Bits-like host. Type the same commands as on the Brico16Bits console
(Help, Echo 1234, TestWRAM, TestDAC 1, Dump $100000 16...).

Emulated (modelled on MAME snk/neogeo.cpp): 68000 @ 12 MHz with exact cycle
counts, BIOS ROM, WRAM, palette RAM (2 banks), system latch, LSPC registers
and VRAM, line counter / frame timing, auto-animation counter, inputs (AES,
nothing pressed, no memory card), open bus, watchdog (NEO-B1, as on
real AES and MVS boards; on by default, MAME's aes driver has none).
Host: command + P1-P3 written into the ROM, cleared after 1 ms, 3 s timeout,
2048-word buffer, as Brico16Bits CommandExtension.cpp.
Z80 (superzazu/z80 core, 4 MHz) wired as on the board (sound latch, NMI,
reply latch, 2 KB RAM), running a built-in test M1 that only answers the
standard handshake ($03 reset -> $00, $01 -> $01), or no program at all (like
an AES without cartridge).
Cartridge (window: Cartridge tab, one at a time; text mode: --cart): none, the
built-in test cartridge, a game ROM set (folder or MAME zip: P1/P2 on the 68000
bus with the P2 bank latch; S, C, V, M1 loaded and their size and CRC32 shown,
checked against the official MAME list hash/neogeo.xml with --cart-list), or
the jwestfall69 diagnostic PROG board (SRAM in both P windows).
Simulated faults (window: Faults tab, text mode: --fault): data bit stuck,
address line stuck, WRAM chip dead, on WRAM, palette RAM (also seen on the
screen), VRAM, the LSPC line counter and the cartridge slot (data, address,
strobes) - to see how each test reacts.
The screen shows the backdrop colour of each line, and over it the fix layer and
the sprites drawn from VRAM with the cartridge's S and C tiles (generated tiles
for the built-in test cartridge): a simple drawing for the ROM's test screens,
not a game renderer (vertical shrink approximated: no L0 ROM; no auto-animation).
NOT emulated: YM2610 and sound, Z80 ROM banking (V is not used), protected
cartridges (SMA, PVC, CMC, encrypted P), memory card, and the
LSPC VRAM access delays of real boards (neither does MAME): code that accesses
VRAM too fast passes here and can fail on a real console. Interrupts: VBLANK
(IRQ1), LSPC timer (IRQ2) and IRQ3 at power-on, timed as in MAME. Checked word
for word against MAME: 46/46 commands, with and without the test cartridge.

Run: double-click, or  python Brico68k_Emulator.py [ROM]
Text mode: python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234" [--rom ROM]
           python Brico68k_Emulator.py --script bench/real_aes_session.txt
           python Brico68k_Emulator.py --compare putty.log     (real console log vs emulator)
           python Brico68k_Emulator.py --diagnose putty.log    (which modelled fault explains it)
           python Brico68k_Emulator.py --check [--rom ROM]
           python Brico68k_Emulator.py --cart kof98.zip --cart-list neogeo.xml --run CartTest
Python 3.8+, standard library only: nothing to install with pip. The window
needs Tkinter, which comes with Python on Windows (python.org installer) and is
the python3-tk package on Linux distributions that split it out.
"""
import base64
import ctypes
import hashlib
import json
import lzma
import os
import platform
import re
import struct
import sys
import time
from pathlib import Path

APP_NAME = "Brico68k Emulator"
APP_VERSION = "1.16"
TOOL_DIR = Path(__file__).resolve().parent
WORK_DIR = TOOL_DIR / "brico68k_emulator"
CONFIG_PATH = WORK_DIR / "config.json"
IS_WIN = os.name == "nt"
ROM_CANDIDATES = ["rom/ROM.BIO", "output/ROM.BIO", "ROM.BIO",
                  "rom/Brico68k.bin", "output/Brico68k.bin", "Brico68k.bin"]   # older builds

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
        lib.neo_get_vram.argtypes = [ctypes.POINTER(ctypes.c_uint16)]
        lib.neo_get_palette.argtypes = [ctypes.POINTER(ctypes.c_uint16)]
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
        self._vram = (ctypes.c_uint16 * 0x8800)()
        self._pal = (ctypes.c_uint16 * 0x1000)()

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

    def layer_state(self):
        """Reads VRAM and the palette as the display sees them; returns a checksum of what the
        tile layers depend on (redraw only when it changes)."""
        import zlib
        self.lib.neo_get_vram(self._vram)
        self.lib.neo_get_palette(self._pal)
        return zlib.crc32(bytes(self._pal), zlib.crc32(bytes(self._vram))) ^ id(self.cart)

    def layers(self):
        """Fix layer and sprites from the last layer_state(): 224 rows of 320 colour words or None
        (backdrop). See render_layers for what is and is not drawn."""
        return render_layers(self._vram, self._pal, self.cart.tiles if self.cart else None)

    def screen(self):
        """The whole picture: 224 rows of 320 colour words, tile layers over the backdrop lines."""
        self.layer_state()
        lines = self.lines()
        return [[lines[y] if c is None else c for c in row] for y, row in enumerate(self.layers())]


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
    # vectors like a game's (wiki "68k vector table"): SP $10F300, reset $C00402, the exceptions to
    # the system ROM entry points, VBLANK and timer to the cartridge. With the vector table switch
    # held on the cartridge the console then starts as with a real game (reset = system ROM $402).
    vec = [0x0010F300, 0x00C00402, 0x00C00408, 0x00C0040E, 0x00C00414] + [0x00C00426] * 27
    vec[8], vec[9], vec[15], vec[24], vec[25], vec[26] = 0x00C0041A, 0x00C00420, 0x00C0042C, 0x00C00432, 0x200, 0x204
    for i, v in enumerate(vec):
        p[4 * i:4 * i + 4] = v.to_bytes(4, "big")
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
    def __init__(self, kind, data=b"", name="", chips=None, notes=None, tiles=None):
        self.kind, self.mode, self.data, self.name = kind, CART_MODES[kind], data, name
        self.tiles = tiles              # RomTiles / SyntheticTiles for the screen, None = no tile
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
                                "(same bytes as the MAME bench cartridge 'brtest').",
                                "Tiles for the screen: generated here (S: a 5 x 7 font at the ASCII codes, "
                                "C: numbered tiles with an F), not the MAME bench cartridge's."],
                         tiles=SyntheticTiles())
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
            tiles = RomTiles(_build_area(*sw["areas"]["fixed"], files, by_crc) if "fixed" in sw["areas"] else None,
                             _build_area(*sw["areas"]["sprites"], files, by_crc) if "sprites" in sw["areas"] else None)
            notes.append(tiles.note())
            return CartImage("game", _p_window(maincpu), f"{best} - {sw['description']}", chips, notes, tiles)
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
    # tiles by name: S1, and the C pairs interleaved byte by byte (odd chip first), as MAME loads them
    num = lambda n: int(re.search(r"[sc](\d)", n).group(1)) if re.search(r"[sc](\d)", n) else 9
    ss = sorted((n for n in files if _chip_of(n) == "S"), key=num)
    cs = sorted((n for n in files if _chip_of(n) == "C"), key=num)
    spr = bytearray()
    for i in range(0, len(cs) - 1, 2):
        a, b = files[cs[i]], files[cs[i + 1]]
        m = min(len(a), len(b))
        pair = bytearray(2 * m)
        pair[0::2], pair[1::2] = a[:m], b[:m]
        spr += pair
    tiles = RomTiles(files[ss[0]] if ss else None, bytes(spr) if spr else None)
    notes.append(tiles.note())
    return CartImage("game", _p_window(maincpu), Path(path).stem, chips, notes, tiles)


# Simulated faults
# ---------------------------------------------------------------------------
FAULT_REGIONS = {"wram": 0, "pal": 1, "vramlo": 2, "vramhi": 3, "line": 4, "bios": 5, "cart": 6, "vec": 7}
REGION_NAMES = {0: "WRAM", 1: "Palette RAM", 2: "VRAM lower (slow)", 3: "VRAM upper (fast)",
                4: "LSPC line counter", 5: "BIOS socket (68000 -> BricoNeo)", 6: "Cartridge slot P bus",
                7: "Vector table switch"}
FAULT_KINDS = {"data": 0, "addr": 1, "lane": 2, "float": 3, "strobe": 2, "stuck": 0}
# 0-3 strobes; 4-5 /PORTOE (P2 output enable); 6-9 the OE dead behind a 245 / NEO-G0 / NEO-BUF (bus hold)
STROBES = ["portwel", "portweu", "romoel", "romoeu", "portoel", "portoeu",
           "romoel245", "romoeu245", "portoel245", "portoeu245"]
# the BIOS socket has no data faults: a bad D line stops the boot, nothing to test
DATA_BITS = {0: 15, 1: 15, 2: 15, 3: 15, 4: 8, 5: -1, 6: 15, 7: 0}
ADDR_RANGE = {0: (1, 15), 1: (1, 13), 2: (0, 14), 3: (0, 10), 5: (1, 16), 6: (1, 19)}

FAULT_HELP = ("Fault syntax: REGION:data:BIT:0|1 (data bit stuck), REGION:addr:LINE:0|1 (address line stuck),\n"
              "wram:lane:lower|upper (WRAM chip dead), bios:float:LINE (BIOS socket line unstable).\n"
              "REGION = wram, pal, vramlo, vramhi, line, bios, cart. Bits: data 0-15 (line counter 0-8);\n"
              "address WRAM A1-A15, pal A1-A12 + 13 = bank select, vramlo 0-14, vramhi 0-10,\n"
              "bios A1-A16 (socket, 68000 -> BricoNeo; address faults only), cart A1-A19 (slot).\n"
              "Cartridge slot: cart:data:BIT:0|1, cart:addr:LINE:0|1, cart:float:BIT (D line unstable),\n"
              "cart:strobe:portwel|portweu|romoel|romoeu|portoel|portoeu (strobe dead; the OE ones: the 68000 reads\n"
              "its prefetched word), ...245 suffix (romoel245 ...): OE dead behind a 245, bus hold. Needs --cart test or diag.\n"
              "Vector table switch (system latch Q1) held: vec:stuck:bios (system ROM) or vec:stuck:cart.\n"
              "Example: --fault wram:data:5:1 --fault pal:addr:13:0 --fault bios:addr:15:1")


def parse_fault(spec):
    """'wram:data:5:1' -> (region, kind, bit, value). Raises ValueError with a readable reason."""
    parts = spec.strip().lower().split(":")
    if len(parts) < 3 or parts[0] not in FAULT_REGIONS or parts[1] not in FAULT_KINDS:
        raise ValueError(f"bad fault '{spec}'. " + FAULT_HELP.splitlines()[0])
    region, kind = FAULT_REGIONS[parts[0]], FAULT_KINDS[parts[1]]
    if region == 7 or parts[1] == "stuck":
        if region != 7 or parts[1] != "stuck" or len(parts) != 3 or parts[2] not in ("bios", "cart"):
            raise ValueError("vector table switch: vec:stuck:bios or vec:stuck:cart")
        return region, 0, 0, 1 if parts[2] == "cart" else 0
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
    if region == 7:
        return f"{name}: held on the {'cartridge' if value else 'system ROM'} (latch Q1)"
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
    if region == 7:
        return f"vec:stuck:{'cart' if value else 'bios'}"
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
# Tile layers: the screen from VRAM. The core keeps VRAM and the palette but draws nothing;
# this draws the fix layer and the sprites from them, for the test screens of the ROM (TestGfx).
# Layer rules as MAME snk/neogeo_spr.cpp. NOT a game-accurate renderer:
# - vertical shrink is approximated (source line = window line * 256 / (shrink + 1)): the real
#   table is the L0 ROM, which is SNK's and not included;
# - no auto-animation, no 96 sprites per line limit, windows over 32 tiles not handled;
# - tiles: the cartridge's S and C ROMs when the set has them (not decrypted: CMC / PCM sets show
#   noise), generated tiles for the built-in test cartridge, none without a cartridge or with the
#   PROG board (no CHA board: nothing drives the tile data).
# ---------------------------------------------------------------------------
_FONT = {" ": "0000000", "-": "000V000", "0": "EHJLPHE", "1": "4C4444E", "2": "EH1248V", "3": "U11E11U", "4": "26AIV22",
         "5": "VGU11HE", "6": "68GUHHE", "7": "V124888", "8": "EHHEHHE", "9": "EHHF12C", "A": "EHHVHHH", "B": "UHHUHHU",
         "C": "EHGGGHE", "D": "UHHHHHU", "E": "VGGUGGV", "F": "VGGUGGG", "G": "EHGNHHF", "H": "HHHVHHH", "I": "E44444E",
         "J": "72222IC", "K": "HIKOKIH", "L": "GGGGGGV", "M": "HRLLHHH", "N": "HPLJHHH", "O": "EHHHHHE", "P": "UHHUGGG",
         "Q": "EHHHLID", "R": "UHHUKIH", "S": "FGGE11U", "T": "V444444", "U": "HHHHHHE", "V": "HHHHHA4", "W": "HHHLLRH",
         "X": "HHA4AHH", "Y": "HHA4444", "Z": "V1248GV"}       # 5 x 7, one base-32 digit per row
_ZOOM_X = ["0000000010000000", "0000100010000000", "0000100010001000", "0010100010001000", "0010100010001010",
           "0010101010001010", "0010101010101010", "1010101010101010", "1010101011101010", "1011101011101010",
           "1011101011101011", "1011101111101011", "1011101111101111", "1111101111101111", "1111101111111111",
           "1111111111111111"]                                   # MAME zoom_x_tables: the columns kept


class SyntheticTiles:
    """Tiles of the built-in test cartridge. Fix: a 5 x 7 font at the ASCII codes of the digits,
    capitals, space and '-', a hollow box for every other tile except $00, $20 and $FF (blank:
    VRAM is zero at power-on in the core, a real one holds anything).
    Sprites: a frame in colour 1 + n % 15, an F (shows the flips) and the low 8 bits of the
    tile number along the bottom, both in colour 13."""
    synthetic = True

    def __init__(self, fix_tiles=0x1000, sprite_tiles=0x2000):
        self._f, self._s = {}, {}
        self.nf, self.ns = fix_tiles, sprite_tiles      # chip sizes: tile numbers wrap, as on a ROM

    def note(self):
        return "Tiles: generated"

    def fix(self, n):
        n %= self.nf
        if n not in self._f:
            t = None
            ch = chr(n & 0xFF) if n < 0x100 else ""
            if ch in _FONT and ch != " ":
                t = [[0] * 8] + [[0] + [1 if int(row, 32) >> (4 - x) & 1 else 0 for x in range(5)] + [0, 0]
                                 for row in _FONT[ch]]
            elif n not in (0x00, 0x20, 0xFF):
                t = [[1 if (x in (1, 6) and 1 <= y <= 6) or (y in (1, 6) and 1 <= x <= 6) else 0 for x in range(8)]
                     for y in range(8)]
            self._f[n] = t
        return self._f[n]

    def sprite(self, n):
        n %= self.ns
        if n not in self._s:
            t = [[0] * 16 for _ in range(16)]
            c = 1 + n % 15
            for i in range(16):
                t[0][i] = t[15][i] = t[i][0] = t[i][15] = c
            for y in range(3, 13):
                t[y][4] = 13
            for x in range(4, 11):
                t[3][x] = 13
            for x in range(4, 9):
                t[7][x] = 13
            for b in range(8):
                if n >> b & 1:
                    t[13][13 - b] = 13
            self._s[n] = t
        return self._s[n]


class RomTiles:
    """Tiles of a game ROM set: S ROM (32 bytes a tile) and the C ROMs as MAME loads them
    (C1/C2 interleaved byte by byte, 128 bytes a tile). A blank tile is None."""
    synthetic = False

    def __init__(self, s_rom, c_rom):
        self.s, self.c = s_rom or b"", c_rom or b""
        self._f, self._s = {}, {}

    def note(self):
        return (f"Tiles for the screen: S ROM {len(self.s) // 32} tiles, C ROMs {len(self.c) // 128} tiles"
                + ("" if self.s and self.c else " (a missing chip gives no tile)")
                + ". Not decrypted: an encrypted set shows noise.")

    def fix(self, n):
        if n not in self._f:
            t = None
            if self.s:
                o = (n * 32) % (len(self.s) - len(self.s) % 32 or 32)
                g = self.s[o:o + 32]
                if len(g) == 32 and any(g):
                    t = [[(g[(0x10, 0x18, 0x00, 0x08)[x >> 1] + y] >> (4 if x & 1 else 0)) & 15 for x in range(8)]
                         for y in range(8)]
            self._f[n] = t
        return self._f[n]

    def sprite(self, n):
        if n not in self._s:
            t = None
            if len(self.c) >= 128:
                o = (n * 128) % (len(self.c) - len(self.c) % 128)
                g = self.c[o:o + 128]
                if any(g):
                    t = []
                    for y in range(16):
                        row = []
                        for half in (0x40, 0x00):       # left 8 pixels, then right 8
                            b0, b1, b2, b3 = (g[half | i | y << 2] for i in (0, 2, 1, 3))
                            row += [(b3 >> x & 1) << 3 | (b2 >> x & 1) << 2 | (b1 >> x & 1) << 1 | (b0 >> x & 1)
                                    for x in range(8)]
                        t.append(row)
            self._s[n] = t
        return self._s[n]


def test_cart_tile_roms(fix_tiles=0x1000, sprite_tiles=0x2000):
    """The built-in test cartridge's tiles as ROM files: (S1, C1, C2), in the chips' own formats
    (what RomTiles decodes). tools/make_test_cart.py writes them, so the MAME bench cartridge
    shows the same tiles as this emulator."""
    src = SyntheticTiles()
    s1 = bytearray(fix_tiles * 32)
    for n in range(fix_tiles):
        t = src.fix(n)
        if t:
            for y in range(8):
                for x in range(8):
                    s1[n * 32 + (0x10, 0x18, 0x00, 0x08)[x >> 1] + y] |= t[y][x] << (4 if x & 1 else 0)
    c = bytearray(sprite_tiles * 128)                 # C1 / C2 interleaved byte by byte, as MAME loads them
    for n in range(sprite_tiles):
        t = src.sprite(n)
        for y in range(16):
            for half, x0 in ((0x40, 0), (0x00, 8)):
                for x in range(8):
                    v = t[y][x0 + x]
                    for plane, i in enumerate((0, 2, 1, 3)):
                        if v >> plane & 1:
                            c[n * 128 + (half | i | y << 2)] |= 1 << x
    return bytes(s1), bytes(c[0::2]), bytes(c[1::2])


def render_layers(vram, pal, tiles):
    """Fix layer and sprites from VRAM ($0000-$87FF) and the 4096 colours of the palette bank.
    Returns 224 rows of 320 entries: a colour word, or None where the backdrop shows.
    tiles = None (no cartridge): every row is None."""
    W, H = 320, 224
    out = [[None] * W for _ in range(H)]
    if tiles is None:
        return out
    x = y = rows = zy = 0
    for s in range(381):                                # low numbers first: higher ones on top
        y3, z2 = vram[0x8200 + s], vram[0x8000 + s]
        zx = z2 >> 8 & 15
        if y3 & 0x40:                                   # sticky: glued to the right of the previous one
            x = (x + (vram[0x8000 + s - 1] >> 8 & 15) + 1) & 0x1FF if s else 0
        else:
            x = vram[0x8400 + s] >> 7
            y = (0x200 - (y3 >> 7)) & 0x1FF
            rows, zy = y3 & 0x3F, z2 & 0xFF
        if not rows:
            continue
        x0 = x - 0x200 if x >= 0x1F0 else x
        if x0 >= W:
            continue
        keep = _ZOOM_X[zx]
        base = s * 64
        for wl in range(min(rows, 32) * 16):
            sy = ((y + wl) & 0x1FF) - 16
            if not 0 <= sy < H:
                continue
            src = wl if zy == 0xFF else wl * 256 // (zy + 1)
            if src >= (512 if zy == 0xFF else 256):
                continue
            ti, line = (src >> 4) & 31, src & 15
            lo, at = vram[base + ti * 2], vram[base + ti * 2 + 1]
            t = tiles.sprite(lo | (at >> 4 & 15) << 16)
            if t is None:
                continue
            row = t[line ^ 15 if at & 2 else line]
            po = (at >> 8) * 16
            dst = out[sy]
            xo = x0
            for sx in range(16):
                if keep[sx] == "1":
                    c = row[15 - sx if at & 1 else sx]
                    if c and 0 <= xo < W:
                        dst[xo] = pal[po + c]
                    xo += 1
    for col in range(40):                               # fix layer: above everything
        for r in range(2, 30):
            w = vram[0x7000 + col * 32 + r]
            t = tiles.fix(w & 0xFFF)
            if t is None:
                continue
            po = (w >> 12) * 16
            for ty in range(8):
                dst, row = out[(r - 2) * 8 + ty], t[ty]
                for tx in range(8):
                    if row[tx]:
                        dst[col * 8 + tx] = pal[po + row[tx]]
    return out


def write_png(path, rows, scale=1):
    """rows: lists of (r, g, b). A plain 8-bit RGB PNG (no dependency)."""
    import zlib
    h, w = len(rows) * scale, len(rows[0]) * scale
    raw = bytearray()
    for row in rows:
        line = b"\x00" + b"".join(bytes(p) * scale for p in row)
        raw += line * scale
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


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

# ---------------------------------------------------------------------------
# Embedded core
# ---------------------------------------------------------------------------
def core_platform():
    m = platform.machine().lower()
    if IS_WIN and m in ("amd64", "x86_64", "arm64"):
        return "windows-x86_64"
    if sys.platform.startswith("linux") and m in ("x86_64", "amd64"):
        return "linux-x86_64"
    return None


def core_path():
    """Extracts the embedded core for this system (if needed). Returns its path, or raises."""
    plat = core_platform()
    cores = globals().get("EMBEDDED_CORES", {})
    if plat not in cores:
        raise RuntimeError(f"No embedded emulator core for this system ({platform.system()} {platform.machine()}): "
                           "Windows x64 and Linux x64 are supported.")
    name, sha, data = cores[plat]
    stem, ext = os.path.splitext(name)
    dest = WORK_DIR / f"{stem}-{sha[:12]}{ext}"
    if not (dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha):
        raw = lzma.decompress(base64.b64decode(data))
        if hashlib.sha256(raw).hexdigest() != sha:
            raise RuntimeError("Embedded emulator core is corrupted (checksum): download the tool again.")
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, dest)
        for old in list(WORK_DIR.glob(f"{stem}-*{ext}")) + [WORK_DIR / name]:
            if old != dest:
                try:
                    old.unlink()                # an older core; may be in use by another window
                except OSError:
                    pass
    return dest


# MAME snk/neogeo_v.cpp create_rgb_lookups: 3900/2200/1000/470/220 ohm, dark = 8.2k pull-down
_G = [1 / 3900, 1 / 2200, 1 / 1000, 1 / 470, 1 / 220]
_SUM = sum(_G)
_LEVELS = [[round(255 * sum(g for i, g in enumerate(_G) if v >> i & 1) / (_SUM + (1 / 8200 if dark else 0)))
            for v in range(32)] for dark in (0, 1)]


def neo_rgb3(c):
    """Neo Geo colour word -> (r, g, b), 0-255 (MAME DAC model)."""
    d = c >> 15
    r = ((c >> 14) & 1) | ((c >> 7) & 0x1E)
    g = ((c >> 13) & 1) | ((c >> 3) & 0x1E)
    b = ((c >> 12) & 1) | ((c << 1) & 0x1E)
    L = _LEVELS[d]
    return L[r], L[g], L[b]


def neo_rgb(c):
    """Neo Geo colour word -> '#rrggbb' (MAME DAC model)."""
    return "#%02x%02x%02x" % neo_rgb3(c)


# ---------------------------------------------------------------------------
# Start-up check
# ---------------------------------------------------------------------------
def check_rom(path):
    """Problems with a ROM file: [(what, detail)]."""
    if not path:
        return [("Brico68k ROM", "not selected")]
    p = Path(path)
    if not p.is_file():
        return [("Brico68k ROM file", str(p))]
    data = p.read_bytes()
    if len(data) > 0x20000:
        return [("ROM of 128 KB or less", f"{p.name} is {len(data)} bytes")]
    if len(data) < 0xA0 + 6 or data[0x80:0x88] != b"BricoNeo":
        return [("BricoNeo header (magic 'BricoNeo' at $80)", f"{p.name}: not a Brico68k ROM")]
    if struct.unpack_from(">H", data, 4)[0] != 0x00C0:
        return [("68000 byte order (reset vector $00C0xxxx)", f"{p.name}: byte-swapped dump?")]
    try:
        parse_extensions(data)
    except Exception as e:
        return [("readable extension table at $A0", f"{p.name}: {e}")]
    return []


def startup_check(rom_path):
    missing = []
    if sys.version_info < (3, 8):
        missing.append(("Python 3.8 or newer", sys.version.split()[0]))
    try:
        core_path()
    except Exception as e:
        missing.append(("emulator core", str(e)))
    missing += check_rom(rom_path)
    return missing


def default_rom():
    for c in ROM_CANDIDATES:
        if (TOOL_DIR / c).is_file():
            return str(TOOL_DIR / c)
    return ""


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(cfg):
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


HELP_BUILTIN = ("Built-in: Help (this list), Reset (console reset), Power (power cycle: clears RAM), Clear,\n"
                "Delay ms and ; comment (as on the BricoNeo console). Run script... plays a whole file.\n"
                "Simulated hardware faults: Faults tab (text mode: --fault, see --fault help).\n"
                "Parameters: decimal, $hex or 0xhex, as on Brico16Bits (e.g. Dump $100000 16).\n")


def help_text(host):
    lines = [f"{len(host.exts)} extensions in this ROM:"]
    for n, a, t, d in host.exts:
        lines.append(f"  {n:<13} [{TYPE_NAMES.get(t, t)}] {d}")
    return "\n".join(lines) + "\n" + HELP_BUILTIN


# ---------------------------------------------------------------------------
# Text mode
# ---------------------------------------------------------------------------
def parse_script(text):
    """BricoNeo console script -> steps: ('cmd', line) / ('wait', seconds) / ('note', comment).
    Same conventions as the Brico16Bits console: ';' starts a comment, 'Delay ms' waits."""
    steps = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(";"):
            steps.append(("note", line[1:].strip()))
        elif line.split()[0].lower() == "delay":
            parts = line.split()
            ms = parse_uint(parts[1]) if len(parts) > 1 else 0
            steps.append(("wait", ms / 1000.0))
        else:
            steps.append(("cmd", line))
    return steps


# ---------------------------------------------------------------------------
# Real console log vs emulator
# ---------------------------------------------------------------------------
VARIES = {"TestInp": "depends on the controllers, switches and memory card plugged in",
          "CartTest": "depends on the cartridge: insert the same game set in the emulator (Cartridge tab) to compare",
          "TestStatusA": "depends on coins, service button and memory card",
          "TestSystype": "depends on the board and its jumpers"}
VERDICT_ONLY = {"TestTiming": "the measured cycle counts can differ slightly on a real board"}


def _norm(text):
    return [l.rstrip() for l in (text or "").splitlines() if l.strip()]


def replay_log(core, rom, entries):
    """Runs the commands of a real log, in order, on a powered-on core.
    Returns the emulator output for each entry (None: comment, Delay or console built-in)."""
    return [exp for _, exp in replay_iter(core, rom, entries)]


def replay_iter(core, rom, entries):
    host = Host(core, rom)
    for e in entries:
        out = []
        words = e["line"].split()
        w = words[0].lower() if words else ""
        if e["name"] == ";" or not words:
            out.append(None)
        elif w == "delay":
            ms = parse_uint(words[1]) if len(words) > 1 else 0
            for _ in range(round(ms * 60 / 1000)):
                core.lib.neo_run_frame()
            out.append(None)
        elif w == "reset":                             # Brico16Bits Reset: the watchdog resets the console
            core.lib.neo_reset()
            for _ in range(60):
                core.lib.neo_run_frame()
            out.append(None)
        elif w[:1] in "*@" or host.find(w) is None:    # loop / binary modes and other built-ins
            out.append(None)
        else:
            out.append(host.run_blocking(e["line"])[1])
        yield e, out[0]


def compare_rows(entries, expected):
    rows = []
    for e, exp in zip(entries, expected):
        if exp is None:
            continue
        name, real = e["name"], e["output"]
        rs, rv = classify(name, "timeout" if "[Timeout]" in real else "eot", real)
        es, _ = classify(name, "timeout" if "[Timeout]" in exp else "eot", exp)
        if _norm(real) == _norm(exp):
            match = "same"
        elif name in VARIES:
            match = "varies"
        elif name in VERDICT_ONLY and rs == es:
            match = "same verdict"
        else:
            match = "DIFFERENT"
        rows.append({"line": e["line"], "name": name, "real": real, "expected": exp, "real_status": rs,
                     "real_verdict": rv, "exp_status": es, "match": match,
                     "note": VARIES.get(name) or VERDICT_ONLY.get(name, "")})
    return rows


def compare_diff(row):
    import difflib
    d = difflib.unified_diff(_norm(row["expected"]), _norm(row["real"]), "expected (emulator)", "real console",
                             lineterm="", n=1)
    return "\n".join(list(d)[2:])


def compare_summary(rows):
    n = {k: sum(1 for r in rows if r["match"] == k) for k in ("same", "same verdict", "varies", "DIFFERENT")}
    fails = sum(1 for r in rows if r["real_status"] == "FAIL")
    return (f"{len(rows)} commands compared: {n['same']} same, {n['same verdict']} same verdict, "
            f"{n['varies']} vary with the hardware plugged in, {n['DIFFERENT']} different; "
            f"{fails} FAIL on the real console")


def compare_report(rows, log_name, setup):
    out = [f"Real console log: {log_name}", f"Emulator: {setup}", ""]
    out.append(f"  {'Command':<26}{'Real':<9}{'Emulator':<10}Match")
    for r in rows:
        out.append(f"  {r['line'][:25]:<26}{STATUS_STYLE[r['real_status']][0]:<9}"
                   f"{STATUS_STYLE[r['exp_status']][0]:<10}{r['match']}")
    out += ["", compare_summary(rows)]
    for r in rows:
        if r["match"] in ("DIFFERENT", "varies", "same verdict"):
            out += ["", f"=== {r['line']} ({r['match']}{': ' + r['note'] if r['note'] else ''})", compare_diff(r)]
    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Fault dictionary: which modelled fault explains a real console log
# ---------------------------------------------------------------------------
def all_single_faults():
    """Every single fault the core models: data bits and address lines stuck at 0/1, WRAM chip dead."""
    out = []
    for region in FAULT_REGIONS.values():
        if region == 6:                      # cartridge slot: needs a cartridge, not in console logs yet
            continue
        out += [(region, 0, bit, v) for bit in range(DATA_BITS[region] + 1) for v in (0, 1)]
        if region in ADDR_RANGE:
            lo, hi = ADDR_RANGE[region]
            out += [(region, 1, bit, v) for bit in range(lo, hi + 1) for v in (0, 1)]
    return out + [(0, 2, 0, 0), (0, 2, 0, 1)]


_DX = {}


def _dx_init(rom, raw, z80, wd, limit=None):
    if "core" not in _DX:
        _DX["core"] = Core(core_path())
    _DX.update(rom=rom, z80=z80, wd=wd, limit=limit,
               entries=parse_console_log(raw, [n for n, *_ in parse_extensions(rom)]))


def _dx_score(fault, limit=None):
    """(fault, commands compared, commands still different) for one candidate (None = healthy).
    Stops early (None as the list) once more than `limit` commands differ: worse than no fault at all."""
    core, rom = _DX["core"], _DX["rom"]
    limit = _DX.get("limit") if limit is None else limit
    core.load(rom); core.power_on(); core.lib.neo_set_options(_DX["z80"], _DX["wd"])
    apply_faults(core, [fault] if fault else [])
    for _ in range(60):
        core.lib.neo_run_frame()
    n, diff = 0, []
    for e, exp in replay_iter(core, rom, _DX["entries"]):
        if exp is None:
            continue
        n += 1
        if compare_rows([e], [exp])[0]["match"] == "DIFFERENT":
            diff.append(e["line"])
            if limit is not None and len(diff) > limit:
                return fault, None, None
    return fault, n, diff


def diagnose(rom, raw, z80=None, wd=1, progress=None):
    """Replays the log under every single modelled fault and ranks them by commands left unexplained.
    z80=None tries both Z80 settings on a healthy console and keeps the closer one."""
    if z80 is None:
        scores = {}
        for mode in (1, 0):
            _dx_init(rom, raw, mode, wd)
            scores[mode] = len(_dx_score(None, limit=None)[2])
        z80 = 1 if scores[1] <= scores[0] else 0
    _dx_init(rom, raw, z80, wd)
    base = _dx_score(None)
    limit = len(base[2])
    faults = all_single_faults()
    results = []
    workers = max(1, min(8, (os.cpu_count() or 2) - 1))
    try:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=workers, initializer=_dx_init, initargs=(rom, raw, z80, wd, limit)) as ex:
            for i, r in enumerate(ex.map(_dx_score, faults, chunksize=4)):
                results.append(r)
                if progress:
                    progress(i + 1, len(faults))
    except Exception:                                   # no multiprocessing here: one process does it all
        results = []
        _DX["limit"] = limit
        for i, f in enumerate(faults):
            results.append(_dx_score(f))
            if progress:
                progress(i + 1, len(faults))
    results = sorted((r for r in results if r[2] is not None), key=lambda r: (len(r[2]), r[0]))
    return {"z80": z80, "watchdog": wd, "tried": len(faults), "compared": base[1], "healthy_diff": base[2],
            "candidates": [{"fault": describe_fault(f), "spec": fault_spec(f), "explained": n - len(d),
                            "total": n, "still_different": d} for f, n, d in results]}


def diagnose_report(d, log_name, top=8):
    out = [f"Diagnosis of {log_name}: {d['tried']} single faults tried "
           f"(Z80 {'test M1' if d['z80'] else 'no program'}, watchdog {'on' if d['watchdog'] else 'off'})."]
    n = d["compared"]
    if not d["healthy_diff"]:
        out.append(f"The log matches a healthy console ({n}/{n} commands): nothing to explain.")
        return "\n".join(out) + "\n"
    out.append(f"Healthy console: {n - len(d['healthy_diff'])}/{n} commands match; different: "
               + ", ".join(d["healthy_diff"]))
    better = [c for c in d["candidates"] if len(c["still_different"]) < len(d["healthy_diff"])]
    exact = [c for c in better if not c["still_different"]]
    best = exact + [c for c in better if c["still_different"]][:3] if exact else better[:top]
    if not best:
        out.append("No single modelled fault explains the log better than a healthy console.")
    else:
        out.append("Best candidates (equal scores = the log cannot tell them apart):")
        for i, c in enumerate(best, 1):
            rest = "explains every command" if not c["still_different"] else \
                "still different: " + ", ".join(c["still_different"])
            out.append(f"  {i}. {c['fault']}  [{c['spec']}]  {c['explained']}/{c['total']}, {rest}")
        if exact and all(c["spec"].startswith("bios:") for c in exact):
            out.append("The console never answers: a BIOS socket address line (68000 -> BricoNeo) is suspect, "
                       "and the log cannot say which one. Look at the screen after power-on: the firmware runs "
                       "TestBus at boot and, on a fault, shows 16 bands, A1 at the top (red = stuck at 0, "
                       "blue = stuck at 1, orange = unstable). No bands: a line the code itself needs (A1-A14, "
                       "D0-D15): reseat the BricoNeo, then BricoNeo Trace and a continuity meter.")
    out.append("Limits: one stuck-at fault at a time, in the modelled chips only (WRAM, palette RAM, VRAM, "
               "line counter, BIOS socket address lines). Intermittent faults, shorts between lines, timing "
               "faults and other chips are not in the dictionary.")
    return "\n".join(out) + "\n"


def main_cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--rom", default=None)
    ap.add_argument("--run", nargs="*", default=None, help="commands to run, e.g. \"TestWRAM\" \"Echo 1234\"")
    ap.add_argument("--script", metavar="FILE", help="run a BricoNeo console script (';' comments, 'Delay ms')")
    ap.add_argument("--compare", metavar="LOG",
                    help="compare a session log of the real BricoNeo console with the emulator")
    ap.add_argument("--diagnose", metavar="LOG",
                    help="find which modelled fault explains a real console log (fault dictionary)")
    ap.add_argument("--json", action="store_true", help="--compare / --diagnose: machine-readable output")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--z80", choices=["testm1", "none"], default=None,
                    help="testm1 (default): Z80 runs the built-in test M1; none: Z80 without program "
                         "(--diagnose picks the closer one when not given)")
    ap.add_argument("--no-watchdog", action="store_true",
                    help="no watchdog, like MAME's aes driver (real AES and MVS boards have one, in NEO-B1)")
    ap.add_argument("--watchdog", action="store_true", help=argparse.SUPPRESS)   # default since 1.7, kept for old scripts
    ap.add_argument("--fault", action="append", default=[], metavar="SPEC",
                    help="simulated hardware fault, repeatable, e.g. wram:data:5:1 (see --fault help)")
    ap.add_argument("--cart", default="none", metavar="CART",
                    help="cartridge: none (default), test (built-in test cartridge), diag (diagnostic PROG "
                         "board) or a game ROM set (folder or MAME .zip)")
    ap.add_argument("--cart-list", metavar="XML", help="official MAME list (hash/neogeo.xml): identifies the "
                    "ROM set by CRC32, loads it with the list's layout and checks every chip")
    ap.add_argument("--png", metavar="FILE", help="after --run / --script: save the screen (backdrop, fix layer "
                    "and sprites drawn from VRAM, x2) as a PNG")
    ap.add_argument("rom_pos", nargs="?")
    a = ap.parse_args(argv)
    if "help" in [f.lower() for f in a.fault]:
        print(FAULT_HELP)
        return 0
    try:
        faults = [parse_fault(f) for f in a.fault]
    except ValueError as e:
        print(f"ERROR: {e}")
        return 2
    rom_path = a.rom or a.rom_pos or default_rom()
    missing = startup_check(rom_path)
    for w, d in missing:
        print(f"MISSING: {w} -> {d}")
    if a.check:
        print("OK: nothing missing" if not missing else f"{len(missing)} missing item(s)")
        return 1 if missing else 0
    if missing:
        return 1
    rom = Path(rom_path).read_bytes()
    if a.diagnose:
        try:
            raw = Path(a.diagnose).read_bytes()
        except OSError as e:
            print(f"ERROR: cannot read the log: {e}")
            return 2
        if not parse_console_log(raw, [n for n, *_ in parse_extensions(rom)]):
            print("ERROR: no BricoNeo command found in this log ('> Command' lines)")
            return 2
        core_path()                                   # extract the core once, before the worker processes

        def prog(i, n):
            if i % 16 == 0 or i == n:
                print(f"PROGRESS {i} {n}", file=sys.stderr, flush=True)
        d = diagnose(rom, raw, None if a.z80 is None else (1 if a.z80 == "testm1" else 0),
                     0 if a.no_watchdog else 1, prog)
        print(json.dumps(d) if a.json else diagnose_report(d, Path(a.diagnose).name), end="\n" if a.json else "")
        return 0
    try:
        cart = make_cart(a.cart) if a.cart in ("none", "test", "diag") else load_cartridge(a.cart, a.cart_list)
    except (OSError, ValueError) as e:
        print(f"ERROR: cartridge: {e}")
        return 2
    core = Core(core_path())
    core.load(rom)
    core.load_cart(cart)
    if cart.kind != "none":
        print("CART: " + cart.report().replace("\n", "\nCART: "))
    core.power_on()
    core.lib.neo_set_options(0 if a.z80 == "none" else 1, 0 if a.no_watchdog else 1)
    apply_faults(core, faults)
    for f in faults:
        print(f"FAULT: {describe_fault(f)}")
    for _ in range(60):
        core.lib.neo_run_frame()
    host = Host(core, rom)
    if a.compare:
        try:
            raw = Path(a.compare).read_bytes()
        except OSError as e:
            print(f"ERROR: cannot read the log: {e}")
            return 2
        entries = parse_console_log(raw, [n for n, *_ in host.exts])
        if not entries:
            print("ERROR: no BricoNeo command found in this log ('> Command' lines)")
            return 2
        rows = compare_rows(entries, replay_log(core, rom, entries))
        setup = (f"Z80 {'no program' if a.z80 == 'none' else 'test M1'}, watchdog "
                 f"{'off' if a.no_watchdog else 'on'}, " + (", ".join(describe_fault(f) for f in faults) or "no fault"))
        if a.json:
            print(json.dumps({"setup": setup, "summary": compare_summary(rows),
                              "rows": [dict(r, diff=compare_diff(r)) for r in rows]}))
        else:
            print(compare_report(rows, Path(a.compare).name, setup), end="")
        return 0
    if a.script:
        try:
            steps = parse_script(Path(a.script).read_text(encoding="utf-8", errors="replace"))
        except OSError as e:
            print(f"ERROR: cannot read the script: {e}")
            return 2
    else:
        steps = [("cmd", line) for line in (a.run or ["Help"])]
    for kind, arg in steps:
        if kind == "note":
            print(f"; {arg}")
            continue
        if kind == "wait":
            print(f"> Delay {arg * 1000:.0f}")
            for _ in range(round(arg * 60)):
                core.lib.neo_run_frame()
            continue
        print(f"> {arg}")
        if arg.strip().lower() == "help":
            print(help_text(host), end="")
            continue
        st, text, secs = host.run_blocking(arg)
        print(text, end="")
        print(f"[{st}, {secs * 1000:.0f} ms emulated]")
    if a.png:
        for _ in range(4):                            # a few frames: the backdrop lines of the last command
            core.lib.neo_run_frame()
        cache = {}
        try:
            write_png(a.png, [[cache.get(c) or cache.setdefault(c, neo_rgb3(c)) for c in row]
                              for row in core.screen()], 2)
        except OSError as e:
            print(f"ERROR: cannot write the picture: {e}")
            return 2
        print(f"SCREEN: {a.png}" + ("" if cart.tiles else " (no tiles: backdrop only)"))
    return 0


# ---------------------------------------------------------------------------
# Diagnostic catalogue: how the tests are grouped, run and judged
# ---------------------------------------------------------------------------
CATEGORIES = [
    ("Overview", ["TestChip", "TestBus"]),
    ("Memory", ["TestWRAM", "TestBRAM", "TestPRAM"]),
    ("Video", ["TestVRAM", "TestLSPC", "TestTiming", "TestGfx", "TestDAC"]),
    ("Sound", ["TestZ80", "TestAudio", "PlayEyeSnd"]),
    ("Inputs and system", ["TestInp", "TestStatusA", "TestSystype", "TestVectors", "TestWatchdog"]),
    ("Cartridge", ["CartTest", "CartDiag"]),
    ("Tools", ["Version", "Echo", "Read", "Write", "WriteB", "Dump", "Color"]),
]
TOOLS = set(CATEGORIES[-1][1])
CHK_PROGRESS, CHK_PROG_MAGIC = 0x10FFF0, 0x10FFF2   # TestChip progress word and its magic ($C4EC)
# what the emulator cannot judge by itself
LOOK = {"TestDAC": "Look at the screen: 16 bands, one colour bit each (a black band = dead bit).",
        "TestGfx": "Look at the screen: labels, fix tiles, flips, 8 x 4 tiles, H and V shrink (drawn from VRAM; "
                   "V shrink approximated, no L0 ROM). No tiles without a game or the test cartridge.",
        "PlayEyeSnd": "Sound is not emulated: the eyecatcher music cannot be heard here."}
STATUS_STYLE = {   # status -> (label, foreground, background)
    "PASS": ("PASS", "#1a7f37", "#dafbe1"), "FAIL": ("FAIL", "#cf222e", "#ffebe9"),
    "WARN": ("CHECK", "#9a6700", "#fff8c5"), "NA": ("N/A", "#59636e", "#eef1f4"),
    "INFO": ("INFO", "#0969da", "#ddf4ff"), "LOOK": ("LOOK", "#8250df", "#fbefff"),
    "RUN": ("RUNNING", "#0969da", "#ddf4ff"), "ARMED": ("ARMED", "#9a6700", "#fff8c5"),
    "": ("", "#59636e", "#ffffff"),
}


def classify(name, status, text):
    """(status, one-line verdict) from a test output, as a technician would read it."""
    if status == "timeout":
        return "FAIL", "Timeout: no end-of-transmission within 3 s (the 68000 is stuck or busy)."
    if status == "error":
        return "FAIL", text.strip().splitlines()[0] if text.strip() else "Error"
    lines = [l.strip() for l in text.splitlines()]
    verdicts = [l for l in lines if l.startswith("=>")]
    errors = [l for l in lines if l.startswith("ERROR")]
    exc = [l for l in lines if "EXCEPTION" in l.upper() and "***" in l]
    if exc:
        return "FAIL", (exc[-1].strip("* ") + ". Most extensions use WRAM for the stack: "
                        "if TestWRAM fails, fix that first.")
    if errors:
        return "FAIL", errors[-1]
    if name == "TestWatchdog" and any("ARMED" in l for l in lines):
        return "ARMED", "Armed: the watchdog is being starved; run TestWatchdog again to read the result."
    if verdicts:
        v = verdicts[-1]
        s = v.lower()
        if "n/a" in s:
            return "NA", v
        if "inconclusive" in s or "check" in s or "cannot run" in s:
            return "WARN", v
        if "success" in s:
            return "PASS", v
        if "fail" in s or "error" in s:
            return "FAIL", v
        return "INFO", v
    if name == "TestAudio" and "ACK $01 received" in text:
        return "PASS", "Z80 ACK received (the beeps themselves are not emulated)."
    if name in LOOK:
        return "LOOK", LOOK[name]
    if name in TOOLS:
        return "INFO", "Done."
    return "INFO", "Report only, no automatic verdict: read the output."


def run_all_plan(names, watchdog):
    """Steps for Run all: ('cmd', line) / ('wait', seconds) / ('skip', name, status, why)."""
    plan = []
    order = [n for _, group in CATEGORIES[:-1] for n in group]
    order += [n for n in names if n not in order and n not in TOOLS]      # extensions added later
    for n in order:
        if n not in names or n == "TestDAC":
            continue
        if n == "PlayEyeSnd":
            plan.append(("skip", n, "NA", "Sound is not emulated: nothing to judge."))
        elif n == "TestWatchdog":
            if watchdog:
                plan += [("cmd", n), ("wait", 2.0), ("cmd", n)]
            else:
                plan.append(("skip", n, "NA", "Watchdog switched off in Settings (as in MAME's aes driver): "
                                              "enable it in Settings to run this test."))
        elif n == "TestAudio":
            plan += [("cmd", n), ("wait", 4.0)]            # the 68000 beeps for ~3.5 s
        else:
            plan.append(("cmd", n))
    if "TestDAC" in names:
        plan.append(("cmd", "TestDAC"))                     # last: the pattern stays on screen
    return plan


# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------
def main_gui(rom_arg=None):
    import tkinter as tk
    from tkinter import filedialog, ttk

    cfg = load_config()
    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.minsize(1000, 660)
    geo = cfg.get("geometry") or "1280x820"
    mg = re.match(r"(\d+)x(\d+)([+-]-?\d+)?([+-]-?\d+)?$", geo)
    if mg:
        w, h = min(int(mg.group(1)), root.winfo_screenwidth()), min(int(mg.group(2)), root.winfo_screenheight())
        geo = f"{max(w, 1000)}x{max(h, 660)}"
        if mg.group(3) and mg.group(4):
            x, y = int(mg.group(3).replace("+", "")), int(mg.group(4).replace("+", ""))
            if 0 <= x < root.winfo_screenwidth() - 100 and 0 <= y < root.winfo_screenheight() - 100:
                geo += f"+{x}+{y}"
    root.geometry(geo if mg else "1280x820")

    # --- theme (light) -----------------------------------------------------------
    C = dict(bg="#f3f5f7", panel="#ffffff", field="#ffffff", border="#d0d7de", text="#1f2328",
             muted="#59636e", accent="#0969da", ok="#1a7f37", warn="#9a6700", err="#cf222e",
             btn="#eef1f4", btn_hover="#e1e6eb", head="#f6f8fa")
    ui = "Segoe UI" if IS_WIN else "DejaVu Sans"
    F = (ui, 10); FB = (ui, 10, "bold"); FS = (ui, 9); FT = (ui, 15, "bold"); FV = (ui, 13, "bold")
    mono = ("Consolas", 10) if IS_WIN else ("DejaVu Sans Mono", 10)
    root.configure(bg=C["bg"])
    sty = ttk.Style(root)
    sty.theme_use("clam")
    sty.configure(".", background=C["bg"], foreground=C["text"], fieldbackground=C["field"],
                  bordercolor=C["border"], lightcolor=C["border"], darkcolor=C["border"], font=F)
    for name, bg in (("TFrame", C["bg"]), ("Card.TFrame", C["panel"]), ("Head.TFrame", C["panel"])):
        sty.configure(name, background=bg)
    sty.configure("Card.TFrame", borderwidth=1, relief="solid")
    sty.configure("TLabel", background=C["bg"], foreground=C["text"])
    for name, fg, font in (("Card.TLabel", C["text"], F), ("CardMuted.TLabel", C["muted"], FS),
                           ("CardBold.TLabel", C["text"], FB), ("Title.TLabel", C["text"], FT),
                           ("HeadMuted.TLabel", C["muted"], F)):
        sty.configure(name, background=C["panel"], foreground=fg, font=font)
    sty.configure("TButton", background=C["btn"], foreground=C["text"], padding=(10, 4), relief="flat")
    sty.map("TButton", background=[("disabled", C["btn"]), ("active", C["btn_hover"])],
            foreground=[("disabled", "#8c959f")])
    sty.configure("Accent.TButton", background=C["accent"], foreground="#ffffff")
    sty.map("Accent.TButton", background=[("disabled", C["btn"]), ("active", "#0550ae")],
            foreground=[("disabled", "#8c959f")])
    sty.configure("TCheckbutton", background=C["panel"]); sty.map("TCheckbutton", background=[("active", C["panel"])])
    sty.configure("TRadiobutton", background=C["panel"]); sty.map("TRadiobutton", background=[("active", C["panel"])])
    sty.configure("TCombobox", fieldbackground=C["field"], background=C["btn"], arrowcolor=C["text"])
    sty.map("TCombobox", fieldbackground=[("readonly", C["field"])])
    sty.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                  rowheight=24, borderwidth=0, font=F)
    sty.map("Treeview", background=[("selected", "#ddf4ff")], foreground=[("selected", C["text"])])
    sty.configure("Treeview.Heading", background=C["head"], foreground=C["muted"], relief="flat", font=FS)
    sty.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(0, 0, 0, 0))
    sty.configure("TNotebook.Tab", background=C["btn"], foreground=C["muted"], padding=(16, 6), font=F)
    sty.map("TNotebook.Tab", background=[("selected", C["panel"])], foreground=[("selected", C["text"])])
    sty.configure("Busy.Horizontal.TProgressbar", troughcolor=C["head"], background=C["accent"])

    st = {"core": None, "host": None, "rom": None, "running": False, "t_last": 0.0, "fps_t": time.time(),
          "fps_n": 0, "fps": 0.0, "history": list(cfg.get("history", []))[-50:], "hist_i": 0,
          "busy_t0": None, "busy_name": "", "busy_line": "", "screens": [], "colours": [None] * 224,
          "results": {}, "plan": [], "plan_total": 0, "wait_until": None, "faults": [], "log": [],
          "cart": None}
    st["hist_i"] = len(st["history"])
    for spec in cfg.get("faults", []):
        try:
            st["faults"].append(parse_fault(spec))
        except ValueError:
            pass

    # --- header ----------------------------------------------------------------------
    head = ttk.Frame(root, style="Head.TFrame", padding=(16, 10)); head.pack(fill="x")
    b_pause = ttk.Button(head, text="Pause", width=6, command=lambda: toggle_pause()); b_pause.pack(side="right")
    b_reset = ttk.Button(head, text="Reset", width=6, command=lambda: do_reset()); b_reset.pack(side="right", padx=6)
    b_power = ttk.Button(head, text="Power on", width=9, style="Accent.TButton", command=lambda: power_on())
    b_power.pack(side="right")
    ttk.Label(head, text=APP_NAME, style="Title.TLabel").pack(side="left")
    ttk.Label(head, text=f" {APP_VERSION}", style="HeadMuted.TLabel").pack(side="left", pady=(5, 0))
    rom_chip = ttk.Frame(head, style="Head.TFrame"); rom_chip.pack(side="left", padx=(20, 0))
    rom_name = tk.StringVar(); rom_info = tk.StringVar()
    b_open = ttk.Button(rom_chip, text="Change ROM...", command=lambda: pick_rom()); b_open.pack(side="right")
    ttk.Label(rom_chip, textvariable=rom_name, style="CardBold.TLabel").pack(side="left")
    ttk.Label(rom_chip, textvariable=rom_info, style="HeadMuted.TLabel").pack(side="left", padx=(8, 8))
    tk.Frame(root, height=1, bg=C["border"]).pack(fill="x")

    missing_var = tk.StringVar()
    missing_box = tk.Label(root, textvariable=missing_var, justify="left", anchor="w", bg="#ffebe9", fg="#82071e",
                           padx=16, pady=8, font=F)

    # --- status bar --------------------------------------------------------------------
    sbar = tk.Frame(root, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
    sbar.pack(fill="x", side="bottom")
    lamps = {}
    for key, label in (("cpu", "68000"), ("host", "Host"), ("z80", "Z80"), ("cart", "No cartridge"), ("fault", "No fault")):
        f = tk.Frame(sbar, bg=C["panel"]); f.pack(side="left", padx=(12, 4), pady=4)
        d = tk.Label(f, text="●", fg="#8c959f", bg=C["panel"], font=F); d.pack(side="left")
        t = tk.Label(f, text=label, fg=C["text"], bg=C["panel"], font=FS); t.pack(side="left")
        lamps[key] = (d, t)
    status = tk.StringVar()
    tk.Label(sbar, textvariable=status, fg=C["muted"], bg=C["panel"], font=FS).pack(side="right", padx=12)
    busy_var = tk.StringVar()
    busy_bar = ttk.Progressbar(sbar, style="Busy.Horizontal.TProgressbar", length=120, maximum=3.0)
    busy_bar.pack(side="right", padx=(0, 6))
    tk.Label(sbar, textvariable=busy_var, fg=C["accent"], bg=C["panel"], font=FS).pack(side="right", padx=6)

    # --- body: sidebar | notebook -----------------------------------------------------------
    body = ttk.Panedwindow(root, orient="horizontal"); body.pack(fill="both", expand=True, padx=12, pady=10)
    side = ttk.Frame(body, style="Card.TFrame", padding=10); body.add(side, weight=0)
    main = ttk.Frame(body); body.add(main, weight=1)

    srow = ttk.Frame(side, style="Card.TFrame", borderwidth=0); srow.pack(fill="x")
    b_runall = ttk.Button(srow, text="Run all tests", style="Accent.TButton", command=lambda: run_all())
    b_runall.pack(side="right")
    ttk.Label(srow, text="Diagnostics", style="CardBold.TLabel").pack(side="left")
    summary = tk.StringVar(value="Not run yet.")
    ttk.Label(side, textvariable=summary, style="CardMuted.TLabel").pack(anchor="w", pady=(6, 4))
    thumb = tk.Canvas(side, width=256, height=179, bg="#000000", highlightthickness=1,
                      highlightbackground="#8c959f", cursor="hand2")
    thumb.pack(side="bottom", anchor="w", pady=(4, 0))
    ttk.Label(side, text="Screen (click to enlarge)", style="CardBold.TLabel").pack(side="bottom", anchor="w")
    srun = ttk.Frame(side, style="Card.TFrame", borderwidth=0); srun.pack(side="bottom", fill="x", pady=(6, 8))
    b_run = ttk.Button(srun, text="Run selected", command=lambda: run_selected()); b_run.pack(side="left")
    b_stop = ttk.Button(srun, text="Stop", command=lambda: stop_plan()); b_stop.pack(side="left", padx=6)
    tf = ttk.Frame(side, style="Card.TFrame", borderwidth=0); tf.pack(fill="both", expand=True)
    tree = ttk.Treeview(tf, columns=("st",), show="tree headings", selectmode="browse")
    tree.heading("#0", text="Test", anchor="w"); tree.heading("st", text="Result", anchor="w")
    tree.column("#0", width=170, stretch=True); tree.column("st", width=80, stretch=False)
    tsb = ttk.Scrollbar(tf, command=tree.yview); tree.configure(yscrollcommand=tsb.set)
    tsb.pack(side="right", fill="y"); tree.pack(fill="both", expand=True)
    for k, (lbl, fg, bg) in STATUS_STYLE.items():
        tree.tag_configure("s_" + k, foreground=fg, background=bg if k else C["panel"])
    tree.tag_configure("group", font=FB, foreground=C["muted"])

    nb = ttk.Notebook(main); nb.pack(fill="both", expand=True)

    # Report tab
    rep = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(rep, text="Report")
    verdict = tk.Label(rep, text="Select a test, or run them all.", anchor="w", justify="left", font=FV,
                       bg=C["head"], fg=C["muted"], padx=12, pady=10, wraplength=700)
    verdict.pack(fill="x")
    rep_title = tk.StringVar(); rep_desc = tk.StringVar()
    rhead = ttk.Frame(rep, style="Card.TFrame", borderwidth=0); rhead.pack(fill="x", pady=(10, 0))
    b_again = ttk.Button(rhead, text="Run again", command=lambda: run_selected()); b_again.pack(side="right")
    b_copyrep = ttk.Button(rhead, text="Copy", command=lambda: copy_text(rtext)); b_copyrep.pack(side="right", padx=6)
    ttk.Label(rhead, textvariable=rep_title, style="CardBold.TLabel").pack(side="left")
    rdesc = ttk.Label(rep, textvariable=rep_desc, style="CardMuted.TLabel", wraplength=700, justify="left")
    rdesc.pack(anchor="w", fill="x", pady=(2, 8))
    rtext = tk.Text(rep, wrap="word", font=mono, bg="#fbfcfd", fg=C["text"], bd=0, padx=10, pady=8,
                    highlightthickness=1, highlightbackground=C["border"], state="disabled")
    rtext.pack(fill="both", expand=True)

    # Console tab
    conf = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(conf, text="Console")
    chead = ttk.Frame(conf, style="Card.TFrame", borderwidth=0); chead.pack(fill="x")
    b_save = ttk.Button(chead, text="Save log", command=lambda: save_log()); b_save.pack(side="right")
    b_copy = ttk.Button(chead, text="Copy", command=lambda: copy_text(con)); b_copy.pack(side="right", padx=6)
    b_clear = ttk.Button(chead, text="Clear", command=lambda: clear()); b_clear.pack(side="right")
    b_script = ttk.Button(chead, text="Run script...", command=lambda: run_script()); b_script.pack(side="right", padx=(0, 6))
    ttk.Label(chead, text="Brico16Bits console: every command and its raw output", style="CardMuted.TLabel").pack(side="left")
    ebar = ttk.Frame(conf, style="Card.TFrame", borderwidth=0); ebar.pack(fill="x", side="bottom", pady=(8, 0))
    b_send = ttk.Button(ebar, text="Send", width=8, style="Accent.TButton", command=lambda: send()); b_send.pack(side="right")
    cmd_var = tk.StringVar()
    e_cmd = ttk.Entry(ebar, textvariable=cmd_var, font=mono); e_cmd.pack(side="left", fill="x", expand=True, padx=(0, 8), ipady=3)
    cbox = ttk.Frame(conf, style="Card.TFrame", borderwidth=0); cbox.pack(fill="both", expand=True, pady=(8, 0))
    con = tk.Text(cbox, wrap="word", font=mono, bg="#fbfcfd", fg=C["text"], bd=0, padx=10, pady=8,
                  highlightthickness=1, highlightbackground=C["border"], state="disabled")
    csb = ttk.Scrollbar(cbox, command=con.yview); con.configure(yscrollcommand=csb.set)
    csb.pack(side="right", fill="y"); con.pack(fill="both", expand=True)
    for t in (con, rtext):
        t.tag_configure("cmd", foreground=C["accent"], font=(mono[0], mono[1], "bold"))
        t.tag_configure("info", foreground=C["muted"]); t.tag_configure("err", foreground=C["err"])
        t.tag_configure("ok", foreground=C["ok"]); t.tag_configure("warn", foreground=C["warn"])

    # Compare tab: a session log of the real console, replayed here
    cmpf = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(cmpf, text="Compare")
    cmph = ttk.Frame(cmpf, style="Card.TFrame", borderwidth=0); cmph.pack(fill="x")
    b_cmp_open = ttk.Button(cmph, text="Open real console log...", style="Accent.TButton", command=lambda: compare_open())
    b_cmp_open.pack(side="left")
    b_cmp_diag = ttk.Button(cmph, text="Find the fault", command=lambda: compare_diagnose())
    b_cmp_diag.pack(side="left", padx=6)
    b_cmp_apply = ttk.Button(cmph, text="Apply to Faults", command=lambda: compare_apply())
    b_cmp_apply.pack(side="left")
    cmp_info = tk.StringVar(value="Session log of the BricoNeo console (PuTTY: Session > Logging > All session "
                                  "output). Every command is replayed here with the current Settings and faults.")
    cmp_lbl = ttk.Label(cmpf, textvariable=cmp_info, style="CardMuted.TLabel", wraplength=700, justify="left")
    cmp_lbl.pack(fill="x", pady=(6, 6))
    cmpf.bind("<Configure>", lambda e: cmp_lbl.configure(wraplength=max(300, e.width - 30)))
    cmp_pane = ttk.Panedwindow(cmpf, orient="vertical"); cmp_pane.pack(fill="both", expand=True)
    cmp_tf = ttk.Frame(cmp_pane, style="Card.TFrame", borderwidth=0); cmp_pane.add(cmp_tf, weight=1)
    cmp_tree = ttk.Treeview(cmp_tf, columns=("cmd", "real", "emu", "match"), show="headings", selectmode="browse",
                            height=6)
    for col, txt, w, s in (("cmd", "Command", 220, True), ("real", "Real console", 110, False),
                           ("emu", "Emulator", 100, False), ("match", "Match", 130, False)):
        cmp_tree.heading(col, text=txt, anchor="w"); cmp_tree.column(col, width=w, stretch=s)
    cmp_sb = ttk.Scrollbar(cmp_tf, command=cmp_tree.yview); cmp_tree.configure(yscrollcommand=cmp_sb.set)
    cmp_sb.pack(side="right", fill="y"); cmp_tree.pack(fill="both", expand=True)
    for k, (lbl, fg, bg) in STATUS_STYLE.items():
        cmp_tree.tag_configure("s_" + k, foreground=fg)
    cmp_tree.tag_configure("diff", background="#ffebe9"); cmp_tree.tag_configure("vary", background="#fff8c5")
    cmp_text = tk.Text(cmp_pane, wrap="word", font=mono, bg="#fbfcfd", fg=C["text"], bd=0, padx=10, pady=8, height=8,
                       highlightthickness=1, highlightbackground=C["border"], state="disabled")
    cmp_pane.add(cmp_text, weight=1)
    cmp_text.tag_configure("add", foreground=C["err"]); cmp_text.tag_configure("del", foreground=C["ok"])
    cmp_text.tag_configure("head", foreground=C["accent"], font=(mono[0], mono[1], "bold"))
    cmp_text.tag_configure("info", foreground=C["muted"])

    # Screen tab
    scrf = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(scrf, text="Screen")
    ttk.Label(scrf, text="Backdrop colour of each line (palette $401FFE). Sprites and fix layer are not drawn: "
              "TestDAC and Color are fully visible.", style="CardMuted.TLabel").pack(anchor="w")
    big_holder = tk.Frame(scrf, bg=C["panel"]); big_holder.pack(fill="both", expand=True, pady=(8, 0))
    big = tk.Canvas(big_holder, width=640, height=448, bg="#000000", highlightthickness=1, highlightbackground="#8c959f")
    big.pack()

    # Faults tab
    flt = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(flt, text="Faults")
    # Settings tab
    cartf = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(cartf, text="Cartridge")
    sett = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(sett, text="Settings")

    for cv, s in ((thumb, 0.8), (big, 2.0)):
        st["screens"].append([cv, s, [cv.create_rectangle(0, 0, 0, 0, outline="", fill="#000000") for _ in range(224)]])
    # tile layers (fix + sprites): one image over the line rectangles of each screen, transparent
    # where the backdrop shows. base = 320 x 224, items = [canvas image item, scaled image]
    st["layers"] = {"key": None, "t": 0.0, "base": None, "shown": False,
                    "items": [[cv.create_image(0, 0, anchor="nw", state="hidden"), None] for cv, _, _ in st["screens"]]}

    # --- Faults tab content ----------------------------------------------------------------
    ttk.Label(flt, text="Simulated hardware faults", style="CardBold.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
    ttk.Label(flt, text="Break the console the way real boards fail, then run the tests. Applied at once, "
              "kept across power cycles.", style="CardMuted.TLabel", wraplength=560, justify="left").grid(row=1, column=0, columnspan=4, sticky="w", pady=(0, 6))
    flb = tk.Listbox(flt, height=6, bg=C["field"], fg=C["text"], font=F, bd=1, relief="solid", highlightthickness=0,
                     selectbackground="#ddf4ff", selectforeground=C["text"], activestyle="none")
    flb.grid(row=2, column=0, columnspan=4, sticky="we")
    fb = ttk.Frame(flt, style="Card.TFrame", borderwidth=0); fb.grid(row=3, column=0, columnspan=4, sticky="e", pady=(6, 0))
    ttk.Button(fb, text="Remove selected", command=lambda: fault_remove()).pack(side="left", padx=(0, 6))
    ttk.Button(fb, text="Clear all", command=lambda: fault_clear()).pack(side="left")
    ttk.Separator(flt).grid(row=4, column=0, columnspan=4, sticky="we", pady=12)
    ttk.Label(flt, text="Add a fault", style="CardBold.TLabel").grid(row=5, column=0, columnspan=4, sticky="w")
    REGIONS = [("WRAM", "wram"), ("Palette RAM", "pal"), ("VRAM lower (slow)", "vramlo"),
               ("VRAM upper (fast)", "vramhi"), ("LSPC line counter", "line"),
               ("BIOS socket (68000 -> BricoNeo)", "bios"), ("Cartridge slot (P bus)", "cart"),
               ("Vector table switch", "vec")]
    reg_var = tk.StringVar(value=REGIONS[0][0]); kind_var = tk.StringVar(value="Data bit stuck")
    bit_var = tk.StringVar(value="0"); lvl_var = tk.StringVar(value="1"); range_var = tk.StringVar(); ferr = tk.StringVar()
    ttk.Label(flt, text="Component", style="Card.TLabel").grid(row=6, column=0, sticky="w", pady=3)
    ttk.Combobox(flt, textvariable=reg_var, values=[r for r, _ in REGIONS], state="readonly", width=22).grid(row=6, column=1, sticky="w")
    ttk.Label(flt, text="Fault", style="Card.TLabel").grid(row=7, column=0, sticky="w", pady=3)
    cb_kind = ttk.Combobox(flt, textvariable=kind_var, state="readonly", width=22); cb_kind.grid(row=7, column=1, sticky="w")
    bit_lbl = ttk.Label(flt, text="Bit D", style="Card.TLabel"); bit_lbl.grid(row=6, column=2, sticky="w", padx=(20, 6))
    sp_bit = ttk.Spinbox(flt, textvariable=bit_var, from_=0, to=15, width=6); sp_bit.grid(row=6, column=3, sticky="w")
    lvl_lbl = ttk.Label(flt, text="Stuck at", style="Card.TLabel"); lvl_lbl.grid(row=7, column=2, sticky="w", padx=(20, 6))
    cb_lvl = ttk.Combobox(flt, textvariable=lvl_var, values=["0", "1"], state="readonly", width=14); cb_lvl.grid(row=7, column=3, sticky="w")
    ttk.Label(flt, textvariable=range_var, style="CardMuted.TLabel").grid(row=8, column=0, columnspan=4, sticky="w")
    ttk.Label(flt, textvariable=ferr, style="Card.TLabel", foreground=C["err"]).grid(row=9, column=0, columnspan=3, sticky="w")
    ttk.Button(flt, text="Add fault", style="Accent.TButton", command=lambda: fault_add_form()).grid(row=9, column=3, sticky="e", pady=6)
    ttk.Separator(flt).grid(row=10, column=0, columnspan=4, sticky="we", pady=12)
    ttk.Label(flt, text="Typical AES faults", style="CardBold.TLabel").grid(row=11, column=0, columnspan=4, sticky="w")
    PRESETS = [("WRAM: upper chip dead (D8-D15)", "wram:lane:upper"), ("WRAM: data D3 stuck at 1", "wram:data:3:1"),
               ("WRAM: address line A9 stuck at 0", "wram:addr:9:0"), ("Palette RAM: dark bit D15 stuck at 0", "pal:data:15:0"),
               ("Palette RAM: R4 (D11) stuck at 0", "pal:data:11:0"), ("Palette RAM: bank select stuck at bank 0", "pal:addr:13:0"),
               ("VRAM lower: address line A3 stuck at 0", "vramlo:addr:3:0"), ("VRAM upper: data D7 stuck at 1", "vramhi:data:7:1"),
               ("LSPC line counter: bit 3 stuck at 1", "line:data:3:1"),
               ("BIOS socket: A15 stuck at 1", "bios:addr:15:1"), ("BIOS socket: A16 stuck at 0", "bios:addr:16:0"),
               ("BIOS socket: A5 unstable (bad contact)", "bios:float:5")]
    pre_var = tk.StringVar(value=PRESETS[0][0])
    ttk.Combobox(flt, textvariable=pre_var, values=[n for n, _ in PRESETS], state="readonly", width=44).grid(
        row=12, column=0, columnspan=3, sticky="we", pady=4)
    ttk.Button(flt, text="Add preset", command=lambda: fault_add(dict(PRESETS)[pre_var.get()])).grid(row=12, column=3, sticky="e")
    flt.columnconfigure(1, weight=1)

    # --- Settings tab content --------------------------------------------------------------
    ttk.Label(sett, text="ROM", style="CardBold.TLabel").grid(row=0, column=0, sticky="w")
    rom_var = tk.StringVar(value=rom_arg or cfg.get("rom") or default_rom())
    e_rom = ttk.Entry(sett, textvariable=rom_var); e_rom.grid(row=1, column=0, columnspan=2, sticky="we", pady=(4, 0))
    ttk.Button(sett, text="Browse...", command=lambda: pick_rom()).grid(row=1, column=2, sticky="w", padx=(6, 0), pady=(4, 0))
    ttk.Separator(sett).grid(row=2, column=0, columnspan=3, sticky="we", pady=12)
    ttk.Label(sett, text="Z80 program", style="CardBold.TLabel").grid(row=3, column=0, sticky="w")
    Z80_CHOICES = ["Test M1 (handshake only)", "No program (AES without cartridge)"]
    old = cfg.get("z80", "")
    z80_var = tk.StringVar(value=Z80_CHOICES[1] if ("without" in old or old.startswith("No")) else Z80_CHOICES[0])
    for i, ch in enumerate(Z80_CHOICES):
        ttk.Radiobutton(sett, text=ch, value=ch, variable=z80_var).grid(row=4 + i, column=0, columnspan=3, sticky="w")
    ttk.Label(sett, text="Watchdog", style="CardBold.TLabel").grid(row=6, column=0, sticky="w", pady=(10, 0))
    # real AES and MVS boards both have the NEO-B1 watchdog: on by default since 1.7 (older settings said off by default)
    wd_var = tk.BooleanVar(value=cfg.get("watchdog", True) if cfg.get("cfg_version", 1) >= 2 else True)
    ttk.Checkbutton(sett, text="Watchdog (NEO-B1, about 135 ms: real AES and MVS boards have one; MAME's aes driver has none)", variable=wd_var).grid(row=7, column=0, columnspan=3, sticky="w")
    ttk.Label(sett, text="Speed", style="CardBold.TLabel").grid(row=8, column=0, sticky="w", pady=(10, 0))
    speed_var = tk.StringVar(value="fast" if cfg.get("fast") else "real")
    ttk.Radiobutton(sett, text="Real time (60 frames/s, like the console)", value="real", variable=speed_var).grid(row=9, column=0, columnspan=3, sticky="w")
    ttk.Radiobutton(sett, text="Fast (as fast as this PC can)", value="fast", variable=speed_var).grid(row=10, column=0, columnspan=3, sticky="w")
    ttk.Separator(sett).grid(row=11, column=0, columnspan=3, sticky="we", pady=12)
    CART_CHOICES = [("none", "No cartridge"),
                    ("test", "Built-in test cartridge (generated P ROM: header + security code, 2 P2 banks)"),
                    ("game", "Game cartridge: the ROM set below (P1, P2 on the 68000 bus; S, C, V, M1 loaded and checked)"),
                    ("diag", "Diagnostic PROG board (jwestfall69 neogeo-diag-aes-prog: SRAM on the P bus)")]
    ttk.Label(cartf, text="Inserted (one or the other; changing it powers the console off and on)",
              style="CardBold.TLabel").grid(row=0, column=0, columnspan=4, sticky="w")
    cart_var = tk.StringVar(value=cfg.get("cart", "none") if cfg.get("cart") in dict(CART_CHOICES) else "none")
    for i, (val, label) in enumerate(CART_CHOICES):
        ttk.Radiobutton(cartf, text=label, value=val, variable=cart_var).grid(row=1 + i, column=0, columnspan=4, sticky="w")
    cart_set_var = tk.StringVar(value=cfg.get("cart_set", ""))
    cart_list_var = tk.StringVar(value=cfg.get("cart_list", ""))
    ttk.Separator(cartf).grid(row=5, column=0, columnspan=4, sticky="we", pady=10)
    ttk.Label(cartf, text="Game ROM set", style="Card.TLabel").grid(row=6, column=0, sticky="w")
    ttk.Entry(cartf, textvariable=cart_set_var).grid(row=6, column=1, sticky="we")
    ttk.Button(cartf, text="Zip...", command=lambda: pick_cart(False)).grid(row=6, column=2, padx=(6, 0))
    ttk.Button(cartf, text="Folder...", command=lambda: pick_cart(True)).grid(row=6, column=3, padx=(6, 0))
    ttk.Label(cartf, text="Official MAME list", style="Card.TLabel").grid(row=7, column=0, sticky="w", pady=(4, 0), padx=(0, 8))
    ttk.Entry(cartf, textvariable=cart_list_var).grid(row=7, column=1, sticky="we", pady=(4, 0))
    ttk.Button(cartf, text="neogeo.xml...", command=lambda: pick_cart_list()).grid(row=7, column=2, columnspan=2, sticky="we", padx=(6, 0), pady=(4, 0))
    ttk.Label(cartf, style="CardMuted.TLabel", justify="left", wraplength=760, text=(
        "The list (MAME hash/neogeo.xml, optional) identifies the set by CRC32, loads it with the list's layout, "
        "and checks every chip.")).grid(row=8, column=0, columnspan=4, sticky="we", pady=(4, 8))
    cart_info = tk.StringVar(value="")               # same text as the box, for scripts and tests
    cart_txt = tk.Text(cartf, height=12, wrap="none", relief="flat", bg=C["panel"], fg=C["text"], borderwidth=1,
                       highlightthickness=1, highlightbackground=C["border"],
                       font=("Consolas", 9) if platform.system() == "Windows" else ("DejaVu Sans Mono", 9))
    cart_sb = ttk.Scrollbar(cartf, orient="vertical", command=cart_txt.yview); cart_txt.configure(yscrollcommand=cart_sb.set)
    cart_txt.grid(row=9, column=0, columnspan=4, sticky="nsew"); cart_sb.grid(row=9, column=4, sticky="ns")
    cart_txt.configure(state="disabled")
    cartf.columnconfigure(1, weight=1); cartf.rowconfigure(9, weight=1)
    ttk.Label(sett, text="What is emulated", style="CardBold.TLabel").grid(row=12, column=0, sticky="w")
    ttk.Label(sett, style="CardMuted.TLabel", justify="left", wraplength=760, text=(
        "68000 (Musashi, exact cycle counts), Z80 (4 MHz) running a test M1, WRAM, palette RAM (2 banks), "
        "system latch, LSPC registers and VRAM, line counter and frame timing, AES inputs with nothing plugged in, "
        "open bus, VBLANK and timer interrupts, Brico16Bits host (1 ms clear, 3 s timeout).\nNot emulated: YM2610 "
        "and sound, memory card, protected cartridges (SMA, PVC, CMC). Fix layer and sprites: drawn from VRAM "
        "with the cartridge's S and C tiles (V shrink approximated). Cartridge: P1/P2 "
        "(P2 banks) or the PROG board SRAM on the 68000 bus; V, M1 are only loaded and checked.\n"
        "Keys: F5 reset, F8 pause, Ctrl+L clear the console, Up/Down command history.")).grid(
        row=13, column=0, columnspan=3, sticky="we")
    sett.columnconfigure(0, weight=1)

    # --- helpers ---------------------------------------------------------------------------
    def write(widget, text, tag=None, auto=True):
        widget.configure(state="normal")
        if tag is None and auto:
            for line in text.splitlines(True):
                s = line.lower(); t = None
                if s.startswith("=>"):
                    t = "ok" if "success" in s else ("err" if "fail" in s or "error" in s else "warn")
                elif "[timeout]" in s or s.startswith("error"):
                    t = "err"
                widget.insert("end", line, t)
        else:
            widget.insert("end", text, tag)
        widget.see("end")
        widget.configure(state="disabled")

    def out(text, tag=None):
        st["log"].append(text)
        write(con, text, tag)

    def lamp(key, colour, text):
        lamps[key][0].configure(fg=colour); lamps[key][1].configure(text=text)

    def copy_text(w):
        root.clipboard_clear(); root.clipboard_append(w.get("1.0", "end-1c")); status.set("Copied to the clipboard.")

    def clear():
        con.configure(state="normal"); con.delete("1.0", "end"); con.configure(state="disabled"); st["log"] = []

    def save_log(path=None):
        p = path or filedialog.asksaveasfilename(title="Save console", defaultextension=".txt",
                                                 filetypes=[("Text", "*.txt"), ("All files", "*")],
                                                 initialfile="brico68k_console.txt")
        if p:
            Path(p).write_text(con.get("1.0", "end-1c"), encoding="utf-8")
            status.set(f"Console saved: {Path(p).name}")

    def pick_rom():
        p = filedialog.askopenfilename(title="Brico68k ROM", filetypes=[("ROM", "*.bin"), ("All files", "*")],
                                       initialdir=str(Path(rom_var.get()).parent) if rom_var.get() else str(TOOL_DIR))
        if p:
            rom_var.set(p); power_on()

    def pick_cart(folder):
        if folder:
            p = filedialog.askdirectory(title="Game ROM set folder")
        else:
            p = filedialog.askopenfilename(title="Game ROM set (MAME zip)", filetypes=[("Zip", "*.zip"), ("All files", "*")])
        if p:
            cart_set_var.set(p); cart_var.set("game")

    def pick_cart_list():
        p = filedialog.askopenfilename(title="Official MAME list (hash/neogeo.xml)",
                                       filetypes=[("MAME software list", "*.xml"), ("All files", "*")])
        if p:
            cart_list_var.set(p)
            if cart_var.get() == "game":
                cart_changed()

    def build_cart():
        """CartImage for the current choice; raises ValueError / OSError with a readable reason."""
        k = cart_var.get()
        if k != "game":
            return make_cart(k)
        if not cart_set_var.get().strip():
            raise ValueError("choose the game ROM set (zip or folder) first")
        return load_cartridge(cart_set_var.get().strip(), cart_list_var.get().strip() or None)

    def show_cart(cart):
        cart_info.set(cart.report() if cart.kind != "none" else "No cartridge inserted.")
        cart_txt.configure(state="normal"); cart_txt.delete("1.0", "end")
        cart_txt.insert("end", cart_info.get()); cart_txt.configure(state="disabled")
        lamp("cart", C["ok"] if cart.kind != "none" else "#8c959f",
             {"none": "No cartridge", "test": "Test cartridge", "diag": "PROG board"}.get(cart.kind, "Game cartridge"))

    def cart_changed(*_):
        persist()
        if st["core"]:
            out("--- Cartridge changed: power off, insert, power on ---\n", "info")
            power_on()

    def refresh_missing(*_):
        items = startup_check(rom_var.get().strip())
        if items:
            missing_var.set(f"Missing ({len(items)}) - fix this before powering on:\n" +
                            "\n".join(f"   • {w}: {d}" for w, d in items))
            missing_box.pack(fill="x", after=head)
            rom_name.set(Path(rom_var.get()).name or "No ROM"); rom_info.set("not usable")
        else:
            missing_box.pack_forget()
            data = Path(rom_var.get()).read_bytes()
            major, minor = struct.unpack_from(">HH", data, 0x88)
            rom_name.set(Path(rom_var.get()).name)
            rom_info.set(f"BricoNeo {major}.{minor} · {len(parse_extensions(data))} ext.")
        b_power.configure(state="disabled" if items else "normal")
        return not items

    def apply_options(*_):
        if st["core"]:
            st["core"].lib.neo_set_options(0 if z80_var.get().startswith("No") else 1, 1 if wd_var.get() else 0)
        on = not z80_var.get().startswith("No")
        lamp("z80", C["ok"] if on else C["warn"], "Z80 test M1" if on else "Z80 no program")
        persist()

    # --- test list -----------------------------------------------------------------------------
    def fill_tree():
        tree.delete(*tree.get_children())
        host = st["host"]
        if not host:
            return
        names = [n for n, *_ in host.exts]
        known = set()
        for cat, group in CATEGORIES:
            present = [n for n in group if n in names]
            if cat != "Tools":
                known.update(present)
            if cat == "Tools":
                other = [n for n in names if n not in known and n not in group]
                if other:
                    tree.insert("", "end", iid="cat_Other", text="Other", open=True, tags=("group",))
                    for n in other:
                        tree.insert("cat_Other", "end", iid=n, text=n, values=("",))
            if present:
                tree.insert("", "end", iid="cat_" + cat, text=cat, open=(cat != "Tools"), tags=("group",))
                for n in present:
                    tree.insert("cat_" + cat, "end", iid=n, text=n, values=("",))
        for n, r in st["results"].items():
            set_row(n, r["status"])

    def set_row(name, s):
        if tree.exists(name):
            tree.item(name, values=(STATUS_STYLE[s][0],), tags=("s_" + s,))

    def update_summary():
        counts = {}
        for r in st["results"].values():
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        if not counts:
            summary.set("Not run yet."); return
        parts = [f"{counts[k]} {STATUS_STYLE[k][0].lower()}" for k in ("PASS", "FAIL", "WARN", "LOOK", "INFO", "NA", "ARMED") if counts.get(k)]
        summary.set(" · ".join(parts))

    def show_report(name):
        host = st["host"]
        ext = host.find(name) if host else None
        rep_title.set(name)
        rep_desc.set(ext[3] if ext else "")
        r = st["results"].get(name)
        rtext.configure(state="normal"); rtext.delete("1.0", "end"); rtext.configure(state="disabled")
        if st["busy_t0"] is not None and st["busy_name"] == name:
            lbl, fg, bg = STATUS_STYLE["RUN"]
            verdict.configure(text=f"{lbl}   {st['busy_line']} ...", fg=fg, bg=bg)
            write(rtext, f"> {st['busy_line']}\n(running: the result appears here when the 68000 sends its end of transmission)\n", "info")
        elif r:
            lbl, fg, bg = STATUS_STYLE[r["status"]]
            verdict.configure(text=f"{lbl}   {r['verdict']}", fg=fg, bg=bg)
            write(rtext, f"> {r['line']}   ({r['secs'] * 1000:.0f} ms emulated, {r['when']})\n", "cmd")
            write(rtext, r["text"] or "(no output)\n")
        elif ext and name in TOOLS:
            verdict.configure(text="Tool command: use the Console tab (parameters needed).", fg=C["muted"], bg=C["head"])
        else:
            verdict.configure(text="Not run yet: press Run selected.", fg=C["muted"], bg=C["head"])

    def on_select(_e=None):
        sel = tree.selection()
        if sel and not sel[0].startswith("cat_"):
            show_report(sel[0])

    def run_selected():
        sel = tree.selection()
        if not sel or sel[0].startswith("cat_"):
            return
        name = sel[0]
        if name in TOOLS:
            cmd_var.set(name + " "); nb.select(conf); e_cmd.focus_set(); e_cmd.icursor("end"); return
        st["plan"] = [("cmd", name)]; st["plan_total"] = 1
        nb.select(rep)
        next_step()

    def run_all():
        if not st["host"] or st["plan"]:
            return
        names = [n for n, *_ in st["host"].exts]
        st["results"].clear(); fill_tree(); update_summary()
        st["plan"] = run_all_plan(names, wd_var.get()); st["plan_total"] = len(st["plan"]); st["plan_label"] = "Run all"
        out("--- Run all tests ---\n", "info")
        nb.select(rep)
        next_step()

    def run_script(path=None):
        if not st["host"] or st["plan"]:
            return
        p = path or filedialog.askopenfilename(title="BricoNeo console script",
                                               filetypes=[("Text", "*.txt"), ("All files", "*")],
                                               initialdir=str(TOOL_DIR / "bench") if (TOOL_DIR / "bench").is_dir() else str(TOOL_DIR))
        if not p:
            return
        try:
            steps = parse_script(Path(p).read_text(encoding="utf-8", errors="replace"))
        except OSError as ex:
            out(f"Cannot read the script: {ex}\n", "err"); return
        st["plan"] = [s for s in steps if s[0] != "note"]; st["plan_total"] = len(st["plan"]); st["plan_label"] = "Script"
        out(f"--- Script {Path(p).name}: {st['plan_total']} steps ---\n", "info")
        nb.select(conf)
        next_step()

    def stop_plan():
        if st["plan"]:
            st["plan"] = []; st["wait_until"] = None
            out(f"--- {st.get('plan_label', 'Run all')} stopped ---\n", "info")

    def next_step():
        """Starts the next step of the plan (when the host is idle)."""
        while st["plan"] and st["host"] and not st["host"].pending and st["wait_until"] is None:
            step = st["plan"].pop(0)
            if step[0] == "skip":
                _, n, s, why = step
                record(n, n, "skip", "", 0.0, (s, why)); continue
            if step[0] == "wait":
                out(f"> Delay {step[1] * 1000:.0f}\n", "cmd")
                st["wait_until"] = st["core"].lib.neo_cycles() + int(step[1] * 12e6); return
            send(step[1], from_plan=True)
            return

    def record(name, line, stt, text, secs, forced=None):
        s, v = forced or classify(name, stt, text)
        if name in ("TestZ80", "TestAudio", "TestChip") and s in ("FAIL", "WARN") and z80_var.get().startswith("No") \
                and (name != "TestChip" or "Z80" in v):
            v += "  Expected here: Settings > Z80 program is 'No program' (AES without cartridge)."
        st["results"][name] = {"status": s, "verdict": v, "text": text, "secs": secs, "line": line,
                               "when": time.strftime("%H:%M:%S")}
        set_row(name, s); update_summary()
        sel = tree.selection()
        if (sel and sel[0] == name) or st["plan_total"]:
            tree.selection_set(name); tree.see(name); show_report(name)

    # --- machine -------------------------------------------------------------------------------
    def power_on():
        if not refresh_missing():
            return
        try:
            rom = Path(rom_var.get()).read_bytes()
            core = st["core"] or Core(core_path())
            try:
                cart = build_cart()
            except (OSError, ValueError) as ex:
                raise ValueError(f"cartridge: {ex} (Cartridge tab)") from None
            core.load(rom); core.load_cart(cart); core.power_on()
            st["cart"] = cart; show_cart(cart)
            st["core"], st["rom"] = core, rom
            apply_options(); apply_faults(core, st["faults"])
            st["host"] = Host(core, rom)
            for _ in range(60):             # 1 s of boot, as --run does: the ROM is ready for commands
                core.lib.neo_run_frame()
        except Exception as ex:
            out(f"Cannot start: {ex}\n", "err"); return
        st["busy_t0"] = None; st["plan"] = []; st["plan_total"] = 0; st["wait_until"] = None
        st["results"].clear(); fill_tree(); update_summary()
        major, minor = struct.unpack_from(">HH", rom, 0x88)
        out(f"--- Power on · {Path(rom_var.get()).name} · BricoNeo {major}.{minor} · "
            f"{len(st['host'].exts)} extensions · type Help ---\n", "info")
        if st["cart"].kind != "none":
            out(f"--- Cartridge: {st['cart'].report()} ---\n", "info")
        for f in st["faults"]:
            out(f"--- Fault active: {describe_fault(f)} ---\n", "warn")
        st["running"] = True; st["t_last"] = time.time(); b_pause.configure(text="Pause")
        persist()

    def do_reset():
        if st["core"]:
            st["core"].lib.neo_reset(); st["host"].pending = None; st["busy_t0"] = None
            for _ in range(60):
                st["core"].lib.neo_run_frame()
            st["plan"] = []; st["plan_total"] = 0; st["wait_until"] = None
            out("--- Reset (RAM kept) ---\n", "info")

    def toggle_pause():
        if not st["core"]:
            return
        st["running"] = not st["running"]; st["t_last"] = time.time()
        b_pause.configure(text="Pause" if st["running"] else "Run")

    def send(line=None, from_plan=False):
        line = (line if line is not None else cmd_var.get()).strip()
        if not line:
            return
        if not from_plan:
            cmd_var.set("")
            if not st["history"] or st["history"][-1] != line:
                st["history"].append(line)
            st["hist_i"] = len(st["history"])
        out(f"> {line}\n", "cmd")
        if line.startswith(";"):
            return
        word = line.split()[0].lower()
        if word == "clear":
            clear(); return
        if word == "power":
            power_on(); return
        host = st["host"]
        if host is None:
            out("Power on first.\n", "err"); return
        if word == "help":
            out(help_text(host)); return
        if word == "delay":
            parts = line.split()
            ms = parse_uint(parts[1]) if len(parts) > 1 else 0
            st["wait_until"] = st["core"].lib.neo_cycles() + ms * 12000
            if not st["running"]:
                toggle_pause()
            return
        if word == "reset":
            do_reset(); return
        err = host.start(line)
        if err:
            out(err + "\n", "err"); return
        st["busy_t0"] = st["core"].lib.neo_cycles(); st["busy_name"] = host.pending[0]; st["busy_line"] = line
        set_row(host.pending[0], "RUN")
        sel = tree.selection()
        if from_plan or (sel and sel[0] == host.pending[0]):
            if tree.exists(host.pending[0]):
                tree.selection_set(host.pending[0]); tree.see(host.pending[0])
            show_report(host.pending[0])
        if not st["running"]:
            toggle_pause()

    def history(step):
        h = st["history"]
        if not h:
            return "break"
        st["hist_i"] = max(0, min(len(h), st["hist_i"] + step))
        cmd_var.set(h[st["hist_i"]] if st["hist_i"] < len(h) else ""); e_cmd.icursor("end")
        return "break"

    # --- faults --------------------------------------------------------------------------------
    def push_faults():
        if st["core"]:
            apply_faults(st["core"], st["faults"])
        n = len(st["faults"])
        lamp("fault", C["err"] if n else "#8c959f", f"{n} fault{'s' if n > 1 else ''} active" if n else "No fault")
        flb.delete(0, "end")
        for f in st["faults"]:
            flb.insert("end", describe_fault(f))
        if not st["faults"]:
            flb.insert("end", "(none: the console is healthy)")
        nb.tab(flt, text=f"Faults ({n})" if n else "Faults")
        persist()

    def fault_add(spec):
        try:
            f = parse_fault(spec)
        except ValueError as ex:
            ferr.set(str(ex)); return
        if f in st["faults"]:
            ferr.set("Already active."); return
        st["faults"].append(f); ferr.set("")
        push_faults(); out(f"--- Fault added: {describe_fault(f)} ---\n", "warn")

    def fault_remove():
        sel = flb.curselection()
        if sel and st["faults"]:
            f = st["faults"].pop(sel[0]); push_faults(); out(f"--- Fault removed: {describe_fault(f)} ---\n", "info")

    def fault_clear():
        if st["faults"]:
            st["faults"].clear(); push_faults(); out("--- All faults removed ---\n", "info")

    def kinds_for(code):
        if code == "cart":
            return ["Data bit stuck", "Data line unstable", "Address line stuck", "Strobe dead"]
        if code == "bios":
            return ["Address line stuck", "Address line unstable"]
        if code == "vec":
            return ["Switch held"]
        k = ["Data bit stuck"]
        if code != "line":
            k.append("Address line stuck")
        if code == "wram":
            k.append("Chip dead (byte lane)")
        return k

    def update_form(*_):
        code = dict(REGIONS)[reg_var.get()]
        ks = kinds_for(code); cb_kind.configure(values=ks)
        if kind_var.get() not in ks:
            kind_var.set(ks[0])
        k = kind_var.get()
        if k.startswith("Switch"):
            bit_lbl.configure(text="Latch Q1"); sp_bit.grid_remove(); lvl_lbl.configure(text="Held on")
            cb_lvl.configure(values=["system ROM", "cartridge"])
            if lvl_var.get() not in ("system ROM", "cartridge"):
                lvl_var.set("system ROM")
            range_var.set("$000000-$00007F always read from that side (REG_SWPBIOS / REG_SWPROM ignored). "
                          "Held on the cartridge: the console starts on the cartridge's vectors."); return
        if k.startswith("Strobe"):
            bit_lbl.configure(text="Signal"); sp_bit.grid_remove(); lvl_lbl.configure(text="Strobe")
            cb_lvl.configure(values=[s.upper() for s in STROBES])
            if lvl_var.get().lower() not in STROBES:
                lvl_var.set("ROMOEU")
            range_var.set("Never asserted: byte not written (PORTWE), or not driven (OE: the 68000 reads its prefetch; 245: last write). Needs a cartridge."); return
        if k.startswith("Chip"):
            bit_lbl.configure(text="Chip"); sp_bit.grid_remove(); lvl_lbl.configure(text="Lane")
            cb_lvl.configure(values=["lower (D0-D7)", "upper (D8-D15)"])
            if not lvl_var.get().startswith(("lower", "upper")):
                lvl_var.set("upper (D8-D15)")
            range_var.set("Writes to that chip are lost, it reads $FF."); return
        sp_bit.grid(); lvl_lbl.configure(text="Stuck at"); cb_lvl.configure(values=["0", "1"])
        if k.endswith("unstable"):
            lvl_lbl.configure(text="Level"); cb_lvl.configure(values=["random"]); lvl_var.set("random")
        elif lvl_var.get() not in ("0", "1"):     # was: "random" then always "1" (shown even for unstable)
            lvl_var.set("1")
        if k.startswith("Data"):
            lo, hi = 0, DATA_BITS[FAULT_REGIONS[code]]; bit_lbl.configure(text="Bit D")
            if code == "cart":
                range_var.set("Slot data lines D0-D15 (P1, P2, PROG board). Needs a cartridge.")
                sp_bit.configure(from_=lo, to=hi)
                if not bit_var.get().isdigit() or not lo <= int(bit_var.get()) <= hi:
                    bit_var.set(str(lo))
                return
            range_var.set(f"Data bits D0-D{hi}" + (" (palette: also changes the colours on screen)" if code == "pal" else ""))
        else:
            lo, hi = ADDR_RANGE[FAULT_REGIONS[code]]; bit_lbl.configure(text="Line A")
            range_var.set(f"Address lines A{lo}-A{hi}" + (" (13 = bank select)" if code == "pal" else "")
                          + (" between the 68000 and the BricoNeo; A1-A14 stop the boot" if code == "bios" else ""))
        sp_bit.configure(from_=lo, to=hi)
        try:
            if not lo <= int(bit_var.get()) <= hi:
                bit_var.set(str(lo))
        except ValueError:
            bit_var.set(str(lo))

    def fault_add_form():
        code = dict(REGIONS)[reg_var.get()]; k = kind_var.get()
        if k.startswith("Switch"):
            fault_add(f"vec:stuck:{'cart' if lvl_var.get() == 'cartridge' else 'bios'}")
        elif k.startswith("Chip"):
            fault_add(f"wram:lane:{lvl_var.get().split()[0]}")
        elif k.startswith("Strobe"):
            fault_add(f"cart:strobe:{lvl_var.get().lower()}")
        else:
            if k.endswith("unstable"):
                fault_add(f"{code}:float:{bit_var.get().strip()}")
            else:
                fault_add(f"{code}:{'data' if k.startswith('Data') else 'addr'}:{bit_var.get().strip()}:{lvl_var.get()}")

    # --- screen --------------------------------------------------------------------------------
    def layout_big(_e=None):
        w = max(320, big_holder.winfo_width() - 4); h = max(224, big_holder.winfo_height() - 4)
        s = max(1.0, int(min(w / 320, h / 224) * 4) / 4)
        scr = st["screens"][1]
        if s == scr[1] and _e is not None and int(big.cget("width")) == int(320 * s):
            return
        scr[1] = s; place(scr)

    def place(scr):
        cv, s, rects = scr
        W, H = int(320 * s), int(224 * s)
        cv.configure(width=W, height=H)
        for y, r in enumerate(rects):
            cv.coords(r, 0, int(y * s), W, int((y + 1) * s))
        scale_layers()

    def draw():
        lines = st["core"].lines(); cols = st["colours"]
        for y, c in enumerate(lines):
            if cols[y] != c:
                cols[y] = c; fill = neo_rgb(c)
                for cv, _, rects in st["screens"]:
                    cv.itemconfigure(rects[y], fill=fill)
        draw_layers()

    def scale_layers():
        """Fits the tile layer image to each screen (scales are multiples of 1/20: zoom then subsample)."""
        L = st.get("layers")
        if not L:
            return
        for (cv, s, _), it in zip(st["screens"], L["items"]):
            old = it[1]                      # kept until the item shows the new one: Tk refuses to
            if not (L["shown"] and L["base"]):          # configure an item whose image is gone
                cv.itemconfigure(it[0], image="", state="hidden"); it[1] = None
                continue
            k = max(1, round(s * 20))
            g = __import__("math").gcd(k, 20)
            img = L["base"].zoom(k // g) if k // g > 1 else L["base"]
            new = img.subsample(20 // g) if 20 // g > 1 else img
            cv.itemconfigure(it[0], image=new, state="normal"); cv.tag_raise(it[0])
            it[1] = new
            del old

    def draw_layers(force=False):
        """Redraws the fix layer and the sprites when VRAM, the palette or the cartridge changed.
        Not while a command runs (a memory test fills VRAM with patterns), at most 5 times a second."""
        L, core, host = st["layers"], st["core"], st["host"]
        now = time.time()
        if core is None or (not force and ((host and host.pending) or now - L["t"] < 0.2)):
            return
        L["t"] = now
        key = core.layer_state()
        if key == L["key"]:
            return
        L["key"] = key
        rows = core.layers()
        base = tk.PhotoImage(width=320, height=224)          # transparent
        cache, shown = {}, False
        for y, row in enumerate(rows):
            x = 0
            while x < 320:
                if row[x] is None:
                    x += 1
                    continue
                x0 = x; run = []
                while x < 320 and row[x] is not None:
                    c = row[x]; run.append(cache.get(c) or cache.setdefault(c, neo_rgb(c))); x += 1
                base.put("{" + " ".join(run) + "}", to=(x0, y)); shown = True
        old = L["base"]                      # the screens may still show the old picture
        L["base"], L["shown"] = base, shown
        scale_layers()
        del old

    # --- Compare tab: work in a separate process (the core in this window keeps its state) --------
    st["job"] = None; st["cmp"] = None; st["diag"] = None

    def cmp_show(text_parts):
        cmp_text.configure(state="normal"); cmp_text.delete("1.0", "end")
        for txt, tag in text_parts:
            cmp_text.insert("end", txt, tag)
        cmp_text.configure(state="disabled")

    def job_args():
        args = [sys.executable, str(Path(__file__).resolve()), "--rom", rom_var.get(), "--json"]
        if not wd_var.get():
            args.append("--no-watchdog")
        return args

    def start_job(kind, args):
        import subprocess, threading
        if st["job"]:
            return
        job = {"kind": kind, "progress": None, "out": None, "err": "", "done": False}
        st["job"] = job

        def work():
            try:
                pr = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                      creationflags=0x08000000 if IS_WIN else 0)
                err = []
                for line in pr.stderr:
                    if line.startswith("PROGRESS"):
                        _, i, n = line.split(); job["progress"] = (int(i), int(n))
                    else:
                        err.append(line)
                job["out"] = pr.stdout.read(); pr.wait(); job["err"] = "".join(err)
            except Exception as ex:
                job["err"] = str(ex)
            job["done"] = True
        threading.Thread(target=work, daemon=True).start()

    def poll_job():
        job = st["job"]
        if not job:
            return
        if not job["done"]:
            p = job["progress"]
            cmp_info.set(("Replaying the log under every modelled fault... " + (f"{p[0]}/{p[1]}" if p else ""))
                         if job["kind"] == "diag" else "Replaying the log in the emulator...")
            return
        st["job"] = None
        try:
            data = json.loads(job["out"].strip().splitlines()[-1])
        except (ValueError, IndexError, AttributeError):
            msg = (job["out"] or "").strip() or job["err"].strip() or "no output"
            cmp_info.set("Failed: " + msg.splitlines()[-1]); return
        if job["kind"] == "cmp":
            show_compare(data)
        else:
            show_diagnosis(data)

    def compare_open(path=None):
        p = path or filedialog.askopenfilename(title="Session log of the real BricoNeo console",
                                               filetypes=[("Logs", "*.log *.txt"), ("All files", "*")])
        if not p:
            return
        st["cmp_log"] = p; st["diag"] = None
        args = job_args() + ["--compare", p, "--z80", "none" if z80_var.get().startswith("No") else "testm1"]
        for f in st["faults"]:
            args += ["--fault", fault_spec(f)]
        nb.select(cmpf)
        start_job("cmp", args)

    def show_compare(data):
        st["cmp"] = data
        cmp_tree.delete(*cmp_tree.get_children())
        for i, r in enumerate(data["rows"]):
            tags = ["s_" + r["real_status"]]
            if r["match"] == "DIFFERENT":
                tags.append("diff")
            elif r["match"] == "varies":
                tags.append("vary")
            cmp_tree.insert("", "end", iid=str(i), values=(r["line"], STATUS_STYLE[r["real_status"]][0],
                                                           STATUS_STYLE[r["exp_status"]][0], r["match"]), tags=tags)
        cmp_info.set(f"{Path(st['cmp_log']).name}: {data['summary']}.  Emulator: {data['setup']}")
        diffs = [r for r in data["rows"] if r["match"] == "DIFFERENT"]
        if diffs:
            cmp_tree.selection_set(str(data["rows"].index(diffs[0])))
        else:
            cmp_show([("Every command gives the same output as the emulator", "head"),
                      (" (apart from the ones marked 'varies', which depend on what is plugged in).\n", "info")])

    def cmp_select(_e=None):
        sel = cmp_tree.selection()
        if not sel or not st["cmp"]:
            return
        r = st["cmp"]["rows"][int(sel[0])]
        parts = [(f"{r['line']}: real console {STATUS_STYLE[r['real_status']][0]}, emulator "
                  f"{STATUS_STYLE[r['exp_status']][0]}, {r['match']}\n", "head"),
                 (r["real_verdict"] + "\n", "info")]
        if r["note"]:
            parts.append(("Note: " + r["note"] + "\n", "info"))
        if r["match"] == "same":
            parts.append(("\n" + r["real"], None))
        else:
            parts.append(("\n- expected (emulator)   + real console\n", "info"))
            for line in r["diff"].splitlines():
                parts.append((line + "\n", "add" if line.startswith("+") else "del" if line.startswith("-") else None))
        cmp_show(parts)

    def compare_diagnose():
        if not st.get("cmp_log"):
            compare_open()
            if not st.get("cmp_log"):
                return
        nb.select(cmpf)
        start_job("diag", job_args() + ["--diagnose", st["cmp_log"]])

    def show_diagnosis(d):
        st["diag"] = d
        cmp_info.set(f"{Path(st['cmp_log']).name}: {d['tried']} single faults tried.")
        rep_text = diagnose_report(d, Path(st["cmp_log"]).name)
        parts = []
        for line in rep_text.splitlines():
            parts.append((line + "\n", "head" if line.startswith(("Diagnosis", "Best", "Healthy", "The log", "No single"))
                          else "info" if line.startswith("Limits") else None))
        cmp_show(parts)

    def compare_apply():
        d = st["diag"]
        if not d or not d["candidates"] or len(d["candidates"][0]["still_different"]) >= len(d["healthy_diff"]):
            cmp_info.set("Run 'Find the fault' first: nothing to apply."); return
        spec = d["candidates"][0]["spec"]
        if parse_fault(spec) not in st["faults"]:
            fault_add(spec)
        if d["z80"] == 0:
            z80_var.set(Z80_CHOICES[1])
        cmp_info.set(f"Applied: {d['candidates'][0]['fault']}. The emulator now behaves like the real console; "
                     "run the tests or open the log again to check.")

    # --- main loop ------------------------------------------------------------------------------
    def tick():
        poll_job()
        core = st["core"]; now = time.time()
        if core and st["running"]:
            fast = speed_var.get() == "fast"
            if fast:
                n = 30; st["t_last"] = now
            else:
                n = max(0, min(int((now - st["t_last"]) * 59.185), 6)); st["t_last"] += n / 59.185
                if now - st["t_last"] > 0.5:
                    st["t_last"] = now
            host = st["host"]
            for _ in range(n):
                core.lib.neo_run_frame()
                r = host.poll() if host and host.pending else None
                if r:
                    stt, text, secs = r
                    out(text, "err" if stt == "timeout" else None)
                    out(f"   ({secs * 1000:.0f} ms)\n", "info")
                    record(st["busy_name"], st["busy_line"], stt, text, secs)
                    st["busy_t0"] = None
                if st["wait_until"] is not None and core.lib.neo_cycles() >= st["wait_until"]:
                    st["wait_until"] = None
                if st["plan"] and not (host and host.pending) and st["wait_until"] is None:
                    next_step()
                    if not fast:
                        break
            if n:
                draw(); st["fps_n"] += n
            if not st["plan"] and st["plan_total"] and not (host and host.pending) and st["wait_until"] is None:
                if st["plan_total"] > 1:
                    lbl = st.get("plan_label", "Run all")
                    out(f"--- {lbl} done" + (f": {summary.get()}" if lbl == "Run all" else "") + " ---\n", "info")
                st["plan_total"] = 0
        if st["busy_t0"] is not None and core:
            el = (core.lib.neo_cycles() - st["busy_t0"]) / 12e6
            pct = None
            if core.lib.neo_peek16(CHK_PROG_MAGIC) == 0xC4EC:   # the test publishes its progress in WRAM
                pct = min(100, core.lib.neo_peek16(CHK_PROGRESS))
            if pct is not None:
                busy_var.set(f"{st['busy_name']} · {pct} %"); busy_bar.configure(maximum=100); busy_bar["value"] = pct
            else:
                busy_var.set(f"{st['busy_name']} · {min(el, 3.0):.1f} s / 3 s")
                busy_bar.configure(maximum=3.0); busy_bar["value"] = min(el, 3.0)
            st["last_pct"] = pct
            lamp("host", C["warn"], "Host busy")
        elif st["wait_until"] is not None:
            busy_var.set("Waiting (beeps / watchdog)..."); busy_bar["value"] = 0; lamp("host", C["warn"], "Host waiting")
        else:
            busy_var.set(""); busy_bar["value"] = 0
            lamp("host", C["ok"] if core else "#8c959f", "Host ready" if core else "Host")
        if core:
            lamp("cpu", C["ok"] if st["running"] else C["warn"], "68000 running" if st["running"] else "68000 paused")
        else:
            lamp("cpu", "#8c959f", "68000 off")
        if st["plan_total"]:
            done = st["plan_total"] - len(st["plan"])
            b_runall.configure(text=f"Running {done}/{st['plan_total']}", state="disabled")
        else:
            b_runall.configure(text="Run all tests", state="normal" if core else "disabled")
        if now - st["fps_t"] >= 1.0:
            st["fps"] = st["fps_n"] / (now - st["fps_t"]); st["fps_t"] = now; st["fps_n"] = 0
            if core:
                status.set(f"{st['fps']:.0f} frames/s · PC ${core.lib.neo_pc():06X} · {core.lib.neo_cycles() / 12e6:.1f} s")
        st["after"] = root.after(5, tick)

    def persist():
        save_config({"cfg_version": 2, "rom": rom_var.get(), "z80": z80_var.get(), "watchdog": wd_var.get(),
                     "faults": [fault_spec(f) for f in st["faults"]], "fast": speed_var.get() == "fast",
                     "history": st["history"][-50:], "geometry": root.winfo_geometry(),
                     "cart": cart_var.get(), "cart_set": cart_set_var.get(), "cart_list": cart_list_var.get()})

    def on_close():
        persist()
        try:
            root.after_cancel(st["after"])
        except (KeyError, tk.TclError):
            pass
        root.destroy()

    # --- bindings --------------------------------------------------------------------------------
    e_cmd.bind("<Return>", lambda _e: send())
    e_cmd.bind("<Up>", lambda _e: history(-1)); e_cmd.bind("<Down>", lambda _e: history(1))
    tree.bind("<<TreeviewSelect>>", on_select)
    cmp_tree.bind("<<TreeviewSelect>>", cmp_select)
    tree.bind("<Double-1>", lambda _e: run_selected()); tree.bind("<Return>", lambda _e: run_selected())
    thumb.bind("<Button-1>", lambda _e: nb.select(scrf))
    big_holder.bind("<Configure>", layout_big)

    def layout_thumb(e):
        if e.widget is not root:
            return
        s = 0.8 if e.height >= 780 else 0.55
        scr = st["screens"][0]
        if scr[1] != s:
            scr[1] = s; place(scr)
    root.bind("<Configure>", layout_thumb, add="+")
    rep.bind("<Configure>", lambda e: (verdict.configure(wraplength=max(300, e.width - 40)),
                                       rdesc.configure(wraplength=max(300, e.width - 30))))
    reg_var.trace_add("write", update_form); kind_var.trace_add("write", update_form)
    z80_var.trace_add("write", apply_options); wd_var.trace_add("write", apply_options)
    cart_var.trace_add("write", cart_changed)
    speed_var.trace_add("write", lambda *_: persist())
    rom_var.trace_add("write", refresh_missing)
    root.bind("<Control-l>", lambda _e: clear()); root.bind("<F5>", lambda _e: do_reset())
    root.bind("<F8>", lambda _e: toggle_pause())
    root.protocol("WM_DELETE_WINDOW", on_close)

    out(f"{APP_NAME} {APP_VERSION} · Musashi 68000 + Z80 + Neo Geo AES model · Brico16Bits-like host\n", "info")
    for scr in st["screens"]:
        place(scr)
    update_form(); push_faults(); apply_options()
    if refresh_missing():
        power_on()
    root.update_idletasks()
    try:
        body.sashpos(0, 300)
    except tk.TclError:
        pass
    st["after"] = root.after(5, tick)
    root._b68k = {"send": send, "state": st, "status": status, "console": con, "missing": missing_var,
                  "tree": tree, "run_all": run_all, "run_script": run_script, "run_selected": run_selected, "stop": stop_plan,
                  "cmd": cmd_var, "reset": do_reset, "pause": toggle_pause, "z80": z80_var, "wd": wd_var,
                  "speed": speed_var, "save_log": save_log, "history": history, "busy": busy_var,
                  "lamps": lamps, "rom": rom_var, "notebook": nb, "compare_open": compare_open, "compare_diagnose": compare_diagnose,
                  "compare_apply": compare_apply, "compare_tree": cmp_tree, "compare_text": cmp_text,
                  "compare_info": cmp_info, "tabs": {"report": rep, "console": conf, "compare": cmpf,
                  "screen": scrf, "faults": flt, "cartridge": cartf, "settings": sett}, "verdict": verdict, "report_text": rtext,
                  "summary": summary, "fault_add": fault_add, "fault_remove": fault_remove,
                  "fault_clear": fault_clear, "fault_list": flb, "fault_form": (reg_var, kind_var, bit_var, lvl_var,
                  fault_add_form, ferr), "big": big, "thumb": thumb,
                  "cart": cart_var, "cart_set": cart_set_var, "cart_list": cart_list_var, "cart_info": cart_info,
                  "busy_bar": busy_bar, "key_widgets": [b_power, b_reset, b_pause, b_open, b_runall, b_run, b_stop, tree, thumb]}
    return root


# ===========================================================================
# Embedded emulator core: Musashi 4.60 68000 core (Karl Stenerud, MIT licence),
# superzazu/z80 Z80 core (Nicolas Allemand, MIT licence)
# + neocore.c (Neo Geo AES model + host), built with zig 0.17.1 -O2:
# Windows x86_64-windows-gnu DLL, Linux x86_64-linux-gnu.2.17 shared library.
# Format: platform -> (file name, sha256, lzma data in base64).
# ===========================================================================
EMBEDDED_CORES = {
    'windows-x86_64': ('neocore.dll', 'c4d535890608e6718712e6154e25bf3ab9b9f553ee4bf2a374b6ddbca035d3f5',
        '/Td6WFoAAATm1rRGAgAhARwAAAAQz1jM48CH7/5dACaWi3hACIINKFClpqlYtwoVCGYBVWHU0ztwwoLfksgh9NXn3m1fiWncFMVi'
        '5JxqH+5WxIuezUBYBtG1RVEmD/+C1WpLeEfcWJoZxmxybmeo94Q7Flg9Lr8ulOAG50ovKYBaHTAE5SJlEzVoNDZ2Gr4qfadE/uDe'
        'Sw5Y6wPFCjq58Cl9N889Om8IT7g686Cefh/zEknJevgiIy9QVXxykrephinOTffhJ8V5QcWHr6D0Xc8fuHmhKz4m3XTDFA1UsfDd'
        'U/UtdjRSaMG4E0jr3M3W33W8PfolUDyBwqdPQ/vftDFYBvY/kg/lzTwCixHiVTAQn1o/7XVudjlYHt3VZt06Pl7sayNwpZz9Xv5V'
        'ZFEyCcWWRNRtCVwiYEAd8RIiUc2aiHtiA9w/iptspQGZBUxIHB92AG78GuGNH1rE3adWwmhHbozOMadVBg5jGpN06tssqZbBlHTv'
        'trfnqhPT2XAI4BIITPnOzxfNIi7fQyXspuYM7/qbhLBmjHBNb5Cj3UOy0H3Cw0+QJQk3mvqhTlPOcQnImITI1aAy6ejYXyWYQFPE'
        'uY48riBUmfbtoCXr3H2G7FRrl+7ZJp2I5juYXP0Uhn1lD3CTBBNNf0u4JF7fCp3zWDE3HWEjHk623FM4xEohToUzAcuw5dSUdHyp'
        'tONRd9uELq82hfdPwJepbv/xeUEv0OMa8jQmoKxCmLqC+BXLLDkA8GgzOHMWP6UF9yKaL3vHEr262qQYtPk9geqpYLUGARMwN2OX'
        'R5AAyrT6s+tAaJcY9vyo3EB3SKgFWCesr1J2j1Ge2Fr+9Cfp9VYhe7YhMRUgE6CWv9O681b61dl+pAE15KgoKee22CC1HqEO7+b8'
        'PaHSFZKKwjdMTom60WHi86xBbf2GcRwMMUyvgyBOl/fftYBchupBzL0dsR9KJa1JYC7YjipxkNSwCAmkaayhJ2uRY0Szjn859niZ'
        '7m65V36HyFCxeQaJvviuoc1Y7o6zDG53dPZMOeugQv8Asr8DA6r5tz0snERy7ds56tRWsAnkR6o5A1dFBn6fXaIj/QB2gdfly236'
        'tpsT1BoehCGfBjal52GZHaVbYWn8ubPq8K+bJkcrWiCx1jKtROL6ZD0dQw03J9yzJ8pdi/yXzKoniIdGVMrzp/BtxWTIwSjd5NaF'
        'z/Lf+m84QY8abURB9angD/g/uDfaIcRnTtR8sVHWlP2ojHQqp7A3nwkwMJkAm5AwFr239QQGchgFxu2tc1o5Lrs19iS0nlKRag4R'
        'mW3YWCCsTUwGV3W1xpJwXyzY4AY22dUBvuE+uOw7aD32Mwe27Y73ssbyLreC5xSJR+cNRgOFsRgcAQ1lqifkdBKkt3I6FfU7KWeO'
        'XlWCyq/+JK/sXst04+psCvQpIy3PHxPSpXj/EnBRFz39IYUUL2xMFaRGSrJ4hTjBHrqhw3E7UDTpqNHYTfvKhIyOthvfQHuP9vSv'
        'PLwXdXI2cUet0iNkAewLH2ptnGiIOB8jblvUlHut/wk8UuvKLRye03+0y5Mf3n1ABLIhFm14DG5yA4ukri0DQVh/vPSJFamrsvfU'
        'GJJA8iT21uBvADufvnalAk+4PJEFc6Iwujwywahdvlyiue+z8wz27320Opr883DlLez2pjs5yxAj0bNu3jgfThu057DoaRKqf12X'
        'ddWTPpg391tke9F9498pOKuNSgukvL5kqB2nPEnEASlmmtz79tbAWsPubf3SVtsTiX8A+6KQ6VJXgA01VrhXu4iqopl3LJkRVHN+'
        'VCyvHJMAqRP8/kM68H5rDJADtHGAMepK9LAhi2uhEvJw6qGUt3JLKJTWnQXebJ890Fc1dzBLx94P/bWRNIPbXp/qgo/6wHsn7FwK'
        'WjAZbr+EG47Dkd/vAWOZ2wQZZbUmGoFd6G3INgIbTQJ5EL+4kBSD6XINoA7vKCBDuJy91BHUppZjMyXGqfroCW48Wsptz50VUF0b'
        'kqakQwJQ/3BLBkoIIbcwRlGnAJDT3/hw0lMMpIrXzsCIhVNe+DC6zfRy2ykooBpBvARjG1DUBNM8/c74PY1cT0XhJEIchWxIc9mU'
        '7k6BhBVTTuv7LrIKZaheJcNtHYzXQ2hqnzjfR5BuwUJhTAOjJWKEcG1BbbyiB5qWHJcE6qmbY1zDS/PA53UoJtpOqKPaGMtsSHfF'
        'Xzk/cL9xy7H2W0StStraETOMfaI01H1SaQ2wJgXV6a63WC3xfNC7vbJAmSspw2qwM2M+MEm9guyvgJ2goo+mnk6tEBljvb7WFAew'
        '6cpKeiyF1cmH5NCwZom5mvDbrg7dza2WkXxJqzrxbc4z1oYZgNvW2KOyVF1PDP72IoTCdvWI81LZtr37ELymCsVFA01khhELvdOX'
        'ZhNQPu5cODAiYBidhgxHQiRGmjDVI4xANKRjASRodg8bdc15NbuC2Fu7RFAChNm1MdMqUQ660GcoB8DYs0uyLVyWr6CoZibYJJ5F'
        'G0ODtllpS/f1mLxIRTA9YGUuVAN0aslr6gv/7PAk13NVZzPkhz/IJYnYa/sSWJm+onDAldcOO+x9w4ZvnWwC9hM8aDnSOYBN6Z82'
        'RBf4SWrmINVmeXtFLwxMN9x6TflcRAJTRyg3OKQG1hoeuyfl6+rC2zREw8q43/IsF3ApMmLJRrGeiojx1LniyxVMAw4dgD33AY0p'
        'pO0pf3skU34lRotfOd8lx9VCcY6eo07iTWXDhwl8o9PlkxMDV/mEES6eRPrgrrtKVz/ACNOMBzdb4L/7LIMoysHpPUOdAEAJpx1/'
        'LUMufkFi52FK/tYiYo2wxqWSbywxoinYFsZPBVY4N9QJfoBVPX3tYFtinEOJynDy+I/wlqO9OVxWXjf9oJM191E1t7ipb1xVXGG7'
        'jDquz59Y4CafEfdgijFTzzJsXSnf+roV1TXS7KkiKIQCk7Lv4Oxen3IVbgtloIb55dp7L02ueuatuDpVVV3uUxTyLAI5RwZLkv1e'
        'v+nA6qJP0/DFBRO3Qq+IYp6XqbrvhQGGfBN7HjeYRgnTHY/Mnb/5fBDd5mrJ11rQa4u3va8dpAoVjvHc1Do3SRYoGg3CJx3plite'
        'blWAduO/O+Y2+aAzWSsiGZoyXxvvDPWSLjkCdgZiyS6ozCN+KkFjR09yMI97V2bVbpAAb58O6b1gVnrfrQ0Yb9x9vPNcn4gAiDRP'
        'N6f2rZYu8f6VJTVrLoRwzSpU/Chikl6+QWOzzfZUzTnuLfql602QhosYTTW0drIJipigCNJEYqfwmz4Lh2GA8+wl17yU1DFljVhq'
        'Chi+6H4Re/lRIvcYLDM/hz/glfMf7GCQ9nkzEw2EQf2KRpA5h+H2Z1omb//WcgxMhxeqfwDHiQm2AvM6uMiNjl904GseG4+jnPKn'
        'QVJiqNRyug4JCk7NtulrErVwnV5fv3HF012tovuk2KJm2D0qRGk4nF4GhD9FGxk866CRLGnuJz0H14VAalAPk/Dp9Rm3gUeiOiD3'
        'iZNC0GpCsIOZ4Y0qWOXv3Xm2VNCvlGrGN2p2LClOrVR07/kcc3s6kphdhzkVcfZ/q4dBVc9tw9kbljy03Eqp9+Y9WvZuaniw933m'
        '1tnaOZ2fMDmNTvmsu8AIS7xuvGM+EFcnVRWiyr0HYzMX7gkk16nd1iGgMO3hUe5Pp2tX7OjOGcvLu7QU9lmUbLTOX4axqCvhYC0A'
        'EOH0HF1JYjsFnMHaw7B5XSrrZ9mwdoj008sYniaBxnV0talWUHnrZZTPJmQVca4xVI5k7DMMMGDXtUZw+80WE2uK2MVaDSl5HsPm'
        'x3+URwdeOd2QweTZkIUIkrum0hm4o2Gp3PvdV8NEIL/5kmlmupjjlwrEMFjWJg91aaxyTQ1SXhiFN5gIt+9xCJxs7zgeoZeJITPW'
        '0lLDdH9Vh6/l6Xb61g12105TNtGDtG5abn5hLwDKIeQ865vpLaA6WpRIJuyn+tygogFcmCrKuINJr6FKo7Kunnw6LHcA1dKfo+AX'
        '9jJLlASwMjglSkIs/SYx6zUZJFNE0HZ1M8MJHtcuHfkhoqPw0SiDJT0dML1Jcy2M01kWpIGSp/XU3M/+e8RziZpDBegtiK5fOglp'
        '0dTo5g9Jv3ZTcYvziOpyAm4TTWN2Zo4KN1t2Hk6V6K9KgIPvhyAVabwNxyIB2rADpHljl25HQFAj4n2RDkMnkWT+BBZiwFfIkdy1'
        '3f2rQz3cv83Y5DIFONQEDkidKaUx0ATuvOXJ24BtcGS2kgM1HTREXqVOBJ4DOxaqTPKmGQPYMTwOOTvs+aqPd5hAJPeM4wgnqIoI'
        'UpSvam89lKIrF7RkHMW8nlTGz4pO+LNkJKiK87ln86RqcaG3ScNTF2iX7kMdsLkNOq6Q72raIVYSPydOzGCIG+WsygszGnBUI88J'
        'hc+bzqPruGGMV2ayLxYo5mARdz20RtfiHcYsvKk/oYcTdm7DWl5BKkWrzXmXBned0ZUIqNN8r0sDQiVkYPCss/O47czUeR44Q5t/'
        '+cOZ/z2OOO7bjckuqhisd131dYJLjmhRcPtZN1WvKwdjUno7KRMMfBt/1+llr8TxBJkza+jsxOrSSKF1pC76ItVEAjeDZTgEI0OI'
        '1EgzGaXc1z5vntka6S/JvuZ5+ndcrFZMUKZl0sUjcKkerAOuQeXnv+Mk53n9pThr/41IiY/LGXznVvEUIIZCyDSFE1PqBrKKJxz7'
        'yM6vYHcQHPZrvvM6HTewz6zcZqz0dGms74dUExZvE9F5xxiO8wCP5CB84wwTNpd0SXNZmcgjoC5J8RMKHZpXZY74WmUZ3H6aKCN8'
        'bMutPV8TIuerViwmn6SdP4clrd7vOs60iK+fS85YXxbGOdoq0BC6WqfXZPopgYJ6H3Nfv310qjY98+EvHc9qCJQ73L5qwjKyINqJ'
        '/CWX9P/UaQU3mThGoxZxwuU7sp3YHUXX5laVfbkaCUxUNHxFcofWPDAgFt9PGGEVxXcMtXSzmjzf4xO7o7i7GBMsNPfTNB01OV40'
        'sryijfVvO5GC9TzjfBkQ2xQdYjQWLIKYH/1bRb8m8uAOFewg6vqlDSYDmkXg891E/IM8eNhcemyQ7yIwrRYivjajcFC7mFyuSHU5'
        'otdUsKHxn7CQvkWsN2lBGVmsD+MFf2C1SHhof9GBd2m0IWscc3FRFc8B+p/crArAzLIKSF8BOsFBt3zk8FVKC7Om8eTqif3gagrg'
        'mFTHjm5/w1bRZI9/WQsYomh1/R2wxyB5Qyv4rFX6RhW40gvSb72YFHH7kSPq3MzvVVVqE8Z7O6zwjkGeCiN2t5y45WhAPvrEytIB'
        'pA2u105ecPWvl7kh1ZPBPHiaiSTMdCqOght1D99aIsJfKgHrpre4ctiBfajhauVDoaSdLE5NOgdG725bfpFfb8Kr2bR4TaL2Hxu1'
        'Zna+WmeVPzl/+ev2NDM9joz6KvogppQZpUuUIu9LYTaBZPEaVUShXevVETwsfSTsEzY7yu0yr67bui3I7vnCtIxmnq0QdzjPnAGG'
        'BUnT24OydRUJo623eNlNFnYHNIi6gPW5I3dMEQxgGZjE8p73cQt07noHrMxkghx7qIv4Sb9IhLQJ1w5ytoHEu7tOM26fK3/XUPyA'
        'iyYquY0iIGKFCXImLi2ta5kyEfVGLbBj3yaNm0JnW+nl3NjfIBjlA2o1k7O7AHId6O3VrK9E8H33xzT3p0GRufKcLcrPL6LdGHNN'
        'A67rzja/ImOtnaNt3qZ9oZWrw5mxJPKZjjHZQ1Y81MarDEnHRAoPoDWEJBNvFdXwmNKMMMPF/bdLaBEgBH7eMIlkYW8baoSp3Wpv'
        'pAHj7olBi1O8QA5kfpVGyw66eRMA4DbY5SOkmdYqJ8R6KkwLIG5wF7c9GFBrn/wjpGwE4fMIozWel/6ynN7zVYPJ2a8XcaV/NJLv'
        'AQNPLe+N4Mg4yQQVvxCYLdR42UtIj+N9ihmxhTxC8jtbFoNLTuSzARAKEcENBZyii6plavEaoQCa5HwHWhmIw6kTkRHz1zV5LIsa'
        'gZZwO3ul6Du9yMv7vz2tdz4vGj8hBLzdmYPSz+XJbzdSBSQSge3ncZONMgahQeeAZZmh2cUVh+TmqVu/q8yx3t0rQjzAd5m9Rw5v'
        '4F+4LLcWkJSnumnF8Zb6vKfltgbs7k00K1N/1EK6n46PBBg9PpEo3p6d6xXPOsE2LHFSMg33hAV7OXLr2vQjG4gjwEkgrPF+J6N3'
        'eLjyBXoych2jrWr1cgmUrAo4f9v4zsbQKCF3TVG56PnREwM60h9N6rsDvoY3Uqp1Aw715blSoDgNdPt5F7KEeNNEOEZEJ77infL0'
        'GhQP236vycW0xByvyocAhEZ+vmGGojHRZZ69ZoOpiMvz5YS5/t5wkF+ChTgSpesUzYPrzB+BK7yrFGJQcj12wRNTyv470zX+WViU'
        'eJmFhInJjPABaBqPKtQMK+E/Zdbzs+Y9fOtOPAnWMOUEEcqPaUXwjSqN1hXukVJ3p63yvZnzsC4jdDb291VX+yicTygeBaEK6AMT'
        'ZXC1bz7xOEZJdpHdmPzdWWph1ponzhrRI+295as3JzvGNrYvTaTgAUAbKh8DEZz3KIbbnXxQroJfT71BPLTZ1F7G382B5DTEmIfm'
        'RBvzzUiYj05f+MjBoFIlkOMwTgoaaH+kRQ+nB4xubC9xM8uUNZDT3PJx/YtDWGMPj7LslhZ26MNqAa3C7syF4P+iwR3yuWwsyfRG'
        'VWSp6M/QUKQS81+4FxkRiCd4IOWP6hdjHHUX/EGpNHLjjQ9hgsUxAqx8dU07B7g3W/6lVEL40uyVEexoCHiLaZmkjY8mdi1GtB1b'
        'VLQ9CXsDjEIubqDzSfqXXqNb4JskjILjBQfbk8uzAzZqij5GMV/sL6QQnKS8HS+9/Afq1vNhlJk4bPt/O8J2/TJwVF8FRj0KrhIU'
        'RTQDVA4nL6jX20OKSsiWHPDOlKin16b2WqhOdrWYZCw92NypgBCbIXWAyYcJJBlPJGkODzJHvuOoo4CZiPQ6Zx4aK5KLpmD/F9zh'
        'h3vuBZm5wRTCppY6oXH0z1dofujMUZTxfb6SdYO3gKkIGmw4SBVkIcu1JRaKO7TVZj3syK/GbYNMYMWUf9eQzz+xIjRVLtd0c/4d'
        'stcaowwEJAF3ri8jr50dWtUexbcRj7BBy8uZPbMwyNqCyj+/+9ADBSrVFwQJ/JzR7W4KPegE0MbpGITtyGhyWIEUR0U2btNpBiv5'
        'XG93P4gvZWXMbBx68HDKxCHGpJqkobYJjo0U1tbgwP/oFeVeMYQNKYmYKJV+4/4D1sMC9petuLhKLGORw1j+w8miHsZRS9/+jY1i'
        'cr/O0a0j3Cpb9lV0YozsYPOsK+uIYZtCMLRxa9G42DGFw2yalHNqKsHKT20LDHwMLu/AgVbzFLxbiXzI9ri5e/LFDD1lX6uqWciU'
        '1261QXEu4nkZpyNhA53dYqYGDzzSjniX9GF+5Kmqf2bpT5KfQnV5R+phHfzH5UuxXXN3acXYPnw/+0k/3XgrCg1FwQoacSe0s2+S'
        'RWgf5RWpMB1/LvD9twfrSrWvAKEgeJpJyOTamzziCbLXFAv1UAH3QmAtxe8/pdgpIf26x/hVi+UcWolOsUuZX5LDvvOuU0EqEhqO'
        'A0AYf8f1P5ua48yBnW5w5ME5/uRrewiDZrOWUg6cpbwPr1hlimgMMZZfEHQ79zaeNsN5OqfEWEmUfBA8XOQ8ZDSWKgSn7C9oWPW7'
        'vWDeGOYdEgj/McY1fvsh8nHDGpU5CtC7VKrfRYshDRS56qv5NkYIvFpYXydVP/Fx5yrCd0axYoVmBPaGfqptOTlGjBz/fPzNlyc7'
        '/6GhjJFouT/iSDqq7zyossAaSLRlmyBvzWlp8lIapxTNizpsLCJjQn444iPrdQ8JKUh0mAqDuegJBBO9qS5MTahrY47MMpKz+y4x'
        'fxXEQrIHfRxvVG/8Jbpxcyfmu7hNIzYNYgqEzI/qBfrGhMp8+RBvNeewsHU4Sbjrotj14wm83NtoMRWjurKYQPpgnSkPY329OAfi'
        '5xYUFT3SkQZXoZmVo66be6ypoZS0M0+cCraSbo7Xx7aPNRiMCjBQw4HcwWuBcrJ/HaL7qdfP4KHVx1HHit23YCtAAjlTMn+vyQfZ'
        '279gcJZlZOvBpv++nCpkiqW2eUhGB5dDsvztJNRQM2jvgnr99vHrWMmER+GgDcuhgo7DwuaYg0AlpyXzt+BoZrYFDLsEwzOpggIv'
        '5KOZRg5U97rNFirfraWnSoPMcb449YSYsOOJKaN4Dus0xPjVJcnJGNd2m1rbvGy4OfxUbmnRXagHeEWzTvmGFQ3n42yAR7rKF3gu'
        'RsxAjtT+Idzekjscwspzcf6u+sFrkKXLTjm6ClsKRr9reYZmZVvU2zk6FCaX38H8DjQ9Ecy5B0en4zJCbNnyIIW7fYA5b1D7C37Z'
        'telqdhZC081zqqHRs8hLrnkVo+c2mYjluG03fdRLA7RfFg0bZ3ijziPWelFqkdLnvvr7PCOjL5EE+BPpU2ZYAldsxehpUum5sQVT'
        'hQgr3LKpLevFxP894AcPfC2RdvokzKVY0mdfJyq7dMXUoYdUayJGbXke5ZnonfkYKkk06Rcl6jAyZiIEpWu2UOVfOsZsmM0LNmVX'
        '0UmLu1g8a+C4023KzcKXUcmxlkGDwV9RVd6MERrIn7Vl/0bkm/zHpS1eGoz1EVlAx7NESselnDz+s2DnkMcFlB6WDrpOyASvrONC'
        'ERObKtl14g+K1nap8ShsP3L0jZT7o5NCBose2aYBTaM5Nb8W0X/u8XpDi1VEY4jZuO/yA0pNiMti7Poasqut5iqxKgAeZ+JB0mEZ'
        '88uQcO92BF1VJOmw+Ydk911qkB8Xx11fANLGxWiaMbNH3Bj0ICYeTTiv4mvaSpI09QbCMTJE3Bd03uG6M6CzGIpDA8D7NXcQS6SL'
        '5zgVULSOfqNQYhVU3q8zmQENC1A9A3CUw5P4tnwQ42XZn/1D/oWK8dOunD5rjZ5whIVSqn3KicqcCZkTMqr6YbwMz28CQNb/ODo7'
        'dRTlpZ57Djmvpj0Sl879nYzGSCnx5VDykPFIAf1zSEaG4cZ0dymH6oDF7Bf/HoDnkO6B1+xEbgkwqY6X/z4/w8E41L4lodM/03Kg'
        'NN+XZs4SkboXXLQiKWYLCPF84gkWXMOVhH06X/MGAKAdZ5pWhQGkfKA1cFBdXVrVScEAvJPbSMaapYVXMxlhb/gZphjvcpV2m1Ar'
        'VgKdAaGq2cgqgVlRH0c3Ve71jWVokHn3iUSf6kB9aNrqK23Ms0Jc4Ka2SPGCkLR0fBRgQqRtava9eLfXXkA8SJ22LHHhngcZr1Db'
        'tvhDm1jv2uMSYniWor5arD4pqrQyKBFB8/wujDVQlGW7ROID+K7V0gUdlnLRxybEFloyc4x7CouxOzA0D4YZJ59MkiV4g4weyKjD'
        'wjmTFfJYg5kTRDU4C7SYRFwLgWz0fQt5526NC7slxzN/PWjqWF8ri67TlEkxYMru9oU3+ziYdz8ao6iEqzGUuxLjtUJVz+ej0C7W'
        'L1bDaEtxpisqRLONE+zKMGuJ5G9WJ2bVbw7BomWZthP5eqPCprJjdJwwO/lihrhzZBJ3mjCuMhe8VLHcjmJoEEZAu4lLHpAVvKoI'
        '+D5kHQIETp1QEY/kiPTJUMgDDlE5HJTmJrO86wnF/Z3u7xi300z3cUUJ1Sep2bthN4ahhNy1/7RdRQC3FdatCczXckhJ5gsorQV1'
        'L2q2isfc3YGURZt5Z8UxbGGzRtUvGDd5Gq/LD59T5RbwZXN0bAnivbzuOK2ICncTJKLkNMIXqDHVUi3Mpof1qIgT7WesZ7UnFZdx'
        'ZTCRvD9qPbUksBpCU0Pnn8WttcM7mcYVnwbgUizIYQZwQPzeTBOz5XZBTXL5sVIRlNDfklcDTd3Fc9vpySrrgxx9sdp4dqojjVc5'
        'izvBWuhGRLcg0KYmDLGB3HglnhWB/iApgswt4Mfs2SwPBOMNdxjOMEC8dckU15UWrrD5JLzPZZrmcTqftxBq7KCleIj9trqKK41M'
        'tWYnywDPS8Qpeuq1fAWuVneJECn/LWNyjvLr5sqlw1YWXPv0uSvE6SR+mq4/k8ZxQbA+9uADZJOOl/VzCdtptju5wtBIjQMDlSb5'
        'RvLpbAn9IiYjw22P8O8O6H9SFirDXu5d/+Dzm1SfIOl6x691zmSv+F8WI+u9nRckTOLAxXpSLPcb20LisSfpklG5XIf0K8kG//yM'
        'HAAFEm4uFvDJmIICUMTHREOgU68wsnp1tdi4SOoyNkGMmgNBWWmMfIvBv8VoVLwyEAQlyE3ULL2ZWRBW51sLFYUrajg+vidOc1oG'
        'Bhmj/TVxr6r1EWbpfc9WQQfDoAeHMIQw6Zg9+XMhD6bo9kzU76TwZnYw0D1+GMWlNd9EAN5LH4/kYXQsEL5/B5MD/ymKerzVxUSh'
        'QnLqOutwRKgehJy5b2x9zjjoc0elxBWh3iZUe7Nq3uReujsiRvqohXX/BkffGS0BFjCmeeDEu6tVg1WOHqPqwdmXvZowR2TayGTE'
        '8AmXZ5c1kYakym51KwPrIsCGyzmGm5aNWb6dy7yjPOenLKQD344vdGn0u64JTNaDqECVI3ySqEL6YxViMXQOckbJY6lnhYKzwlhg'
        'HboJF17+k5Eee9SCPhnqWnpkWaMuLy6NPZlc0o+qFnQwRRCKaFSCrce9a6P+L37TUG/e2UInS9hXor5W28qtuV7WwKsI76XCWbrX'
        '0Cg3jJg0h9VHqGf0wEvbSq/MSbSJ0qGPHYVMRm5dPV36xsCmSq8fS43aEXrhGJeWzVTUtuP2ekUYQe/WBretIxDiTgYQv70yEnLI'
        'QQQn6/XZF23UX91dYHvN0iIPau+1TDhJ78HEq462aBbpT7RCjYQTF+rRsMZVGe3ti8fwcGVMzm8hvQN7eiLG7qlUkqAXUkO7wdRj'
        'OcNYeQlM3AlGXugkfa9ftwJEgHVlqfV0jfFLbPf7yF9Vla6FnXBtNwFDp2M7c8aO85a9tMFtgWTNaodt4r81Vway0UQqO6aE+kon'
        'YVQINyXn2PtGKTYrS/ZiEMW0ofkpwva5nJgIPidJ4ZU4ROleWgu34Mrps0nixISLGXPorkX+GSgnKWUcXKj7f5NfdvfKVfzKQ1jO'
        '8OCU2AzaEO4igaeoTlqhee49zHm73ocrtK83vT+mrJRnJ3nYT+3Fd1MvjKj6SwTiRDy3qhGMluBXGc37kWKuz+LUlkM6yfDW5+zb'
        'oG0emv+jgFU7baI0YI4vlMrU8kePL0iji8ZTZ2KYLc15Nd4ed+3fHAwi6QKQKbuzTu4yJzwzuThNC93qt0rFXjxS7DRxSFVLg5X/'
        '/nuo/J/Bo3yXEQZCIdbWEq7h11nD9zf2Acc9k5OTZLJAFogEqmzRFvizfGAMohuh2e33RntTWjDtHmcAJzcanxlPQvXw7h/5NE3P'
        '2DWW0h4L+p5RVw/Ca3XTSFVhps3UkIKBh2M17D9bD3vMzgQNLzwTaYTXYmvyZWN8C8dZvDblsaodRN7IQkZq2K5hQwreTY0fpUZ7'
        'ApddxhCwewgzSN1kFzUe+FWDlDrukg9Z35jy7OePrIkxHYA2I8wZrtuYbEh4dK48CwS9pQZUYYqbztvKSIL2VcEOLb+KZTEGK4+I'
        'CU1CtGmdjmDmC7DP7/qvY6cbanUGxus5+Okia6dBkK/7d7Y9H8Bcxo3t97dOS5Rgwv7F2U6yJXKVI3ftjrewjYgmLfL+accUiXZG'
        'IJ13ShEKhfgzr2v8fRi5W4wsImYVR0CwDbUHflBQi11ySHvZffeT9Ah+Y6r2+HxSWKjc2vbysOeu0SNLCCh/+yI1d7kig4QI4YfR'
        '8mp3gQJACnhz1Nu1FVKV5RKvyOrbJT/hqXqEU3Hz57GBYf6bi2E3PiqUIKkOM98X7MyPXrrHU2u90rTxDRi4Mtbad9/y+fCfCaZA'
        'KET9pxE+4g9GKssnRxlBgMX2hKDXQ0J0+fWE98ZHf70U4nwHyuM0t4MXDPYz5ciOd1tepQkvgIXx4YZNCTByjvazATs+U/JV7eLc'
        'yelsbvUU/HTOs6J0Be8DmKB+UhfIhkkU9ztmWn1MmaQQwdsGSuKh+gQvYZXX96mraaq/1n+1uBc31U9dgEjHrqzOWRKBYQvaSTzk'
        'UuU3EB0jp/8v9VTAoxhHJsdQ1IGNKSgdtrdgrSVaNQJXXyLe8cbHUmcAg2ultFUCM6A9eXsCDsfOQh1xHokcJ2QegLeDg8Hwflvl'
        'NaLvvaHC5sFbWjIaMuXnoK8pU359zJ/Ua6W42Er4tPtXoe0E1L5IpIvl05OKB2qwZMyQmngR+C3L2Vj3AHok1SwFonYCwFe0RK/J'
        'rbfS2lOMyKmWMrz5TZa9qLjVYiDrFkoDHDTLtTH/JQ1E+7n6Zw9o0rr/zuh3LmwaAZFIWUDuYkfShEezaNRnYOfcF+1FBeazupGr'
        'vzkRju8bgbHzGKe3H4o7wyjuKqIlLqX+qcXdaSeDnmQILAQblu2tkw5DZy4RLz+IFZ565xoEBaL19ns2OSs53usH4w1ehG4lrB+L'
        '9Fc1XGVbQnp1Glm1CIgMb9SaF3tuVWZhsJ/Ly+iRh/LCVJfQ2Zx9rYzArw7SHjHrPOVQqS3NJ7BfuPI7+AsKzQ57Yj3mFk5iWLPj'
        'BbIvq5bug4JkNu75k6+G0K7CXbERObhLRICgSapdhKQllYRLysZdG0C/WRGA4cddjl8I2kKm5YSIDVRJqRKELZfrqZW0+N74RUDk'
        'anPxnnH0efpTepOcBz/FYiyn4RPGhO2Yt/fg1Ij09S3WuFZMg+fZ5h4HkPwAYnB1HXiUIbQAR5/NO3CBWJM+UYz/rd98zVKAXqqf'
        'YIjarEydjV+SvHBhYNXkva5cJkxB/BV0uhzFagFE4K8vMFHOKW002zD4UawZSM/z8MuX9o1jlxBPkYJjDmsZBVzM3rpexrvIypjY'
        'Ld1zpgMpSYiS99FInViikIMCe/QPWk+3TVKPFHssmdCwcgy2z6mbZ3eerePosVHIDWp9MUUwcev4MeDciE4QGfOD5OLQvJxCx6lV'
        'u04WzEuNfgp9Knj7QeocfgBu9c/UL/cuU/bdv3mhHrSNXVszns/lNl7xzEalfTqIyEoE8TXBQaMH9UkmcoG/QNlf1ca883ZGIS18'
        'Hoox3xTc0y6BA0yt7jUZ9mVNYiBQI5k1RJUnl+n3+vG2CgX7TgjQ9RnYrbawr2bqNWOBZeD+BRbZQMWydVmXl/c9agfhhvqYLooJ'
        'VOqws8I+j3PukLBUvjljLjx4tRlHfFUwSKtE1yjKx37ftZo0MoYTOa/2K3G6mOT6edlRBQtreKwbNCeJge+Flckg+vNvx594/W1S'
        'Fwl3Iru73B4xBX77SOKEDKaLCruHUPKwjOyRV1cAB19ayRXJBYeG+n98+q2JKRAtbDRqZNrSFb1eV2GhLf62kl/iZRe8wNO6HHM3'
        'sHX0LMqdbR5O23Ea4KtvuJzu0RQKXoTW6SY2vSguMkIr0fyanp+jjUGPnIlRGoe1p4nAXfVtOLR4cfQQ47zVknkH50LUL8528lnF'
        'T9xI4IJ276zWsgT67IIEQ4GpZSrwS8k2l116adFdMLExrI9McF/5vATf3rXDHzEjyBJhRWtzC1+OaKaCnCYUhFiJ2CHyxq6lvrWH'
        'IJq6aQwTSKgWOqysP81zqVSYuIhkawlE994cwd9Lb9mblwW8wMurt0/TB8wqwurwg1SwlR2MLZf/AIIUtbhAfw/mHcFXDr8MMkhx'
        'rZmEoQet7qndBIVPckRUeShNoC4eImcGMrp+CtXwl1xFBZNLozUcjtPoYKREiPzQr3hOrAqg7bcSoLIKPyVTm8CFhZbNjNwyB9qO'
        'WEwhQjjMBzd8GD2zHiRhPJkecQga+cS1cgaBVLYzxsFRwhJTzVo+Tj114G/yCvTj9QlFB+k2evwq513CXdCw2cwFiu5+j1Q1U6eU'
        'A5im43r4vSOOxvlgvixLf/hdtzUI+OlXHsurZlIbqvRiOVdEAS4ow9fpVvXXZyUX+hHc3LI2h+Jo1f10Wtvf1CftnuDq3MN+OxvO'
        'SxIp3wHLXYib7TsQYPMzBD0yEpJDUCNVX4EIobg/NIDDdcIb1LYN509aZJm6046x4GgYmiD9Ap+XWaubFhWznIssYC4/W9UQ4D0w'
        'tHpEh6s5QBpVKsCod/j2wNS6saGrQyB2oRlMrq/YjQ7muaGUmyJlADoRR0hGAaZUHqiMc8xcnhePvZRCp+clIbVtQUh9APDsYzAC'
        'L9EXvZ9eys73dG31wRtEkWDsEL3GSUDlE2BVSREDz40sH4h7pSVtdjLnoeLHYHlxT7TENXx1Sq35FjLpKi4QxP1s3IQZJEN6U0RM'
        'UfKmJKb9XRaeO59VitSWBFjiUtUqCnfthuGxvuBLvHubyZkg7KvgQY3mQKw7e6ymrfF3/nXJOGLt0xqFUIN5BPgK66DgR7SkIwjz'
        'KjI2d9d7OdUxLq4YVllyC5/Mz3s/qZ3yX2jp+7mYJrhpJUPsPdDyRldMOHgj6ykEBACrfipxIYI1WN0zf8txscwrrAA/S5kbH0mE'
        'B+pGm7hbxotCFvRc8dr/1TLMmjSNXJca3Tqmis2xvyRed9uVwUrdW+3HHXrJ80ghIFs3/7QkEC3mIvc3YtGf9lpwBtF0SM3lShFe'
        '5zUejblN4T+Ok7jcvJzUOGaZ03IjGLW+BIuT6MmbhpSEUiBsfppoHUcAhTIasjj7S6hZlfmNobPPgWTQ94d6N7TEVznhiD7Sqm+q'
        '6a0vGu3FB/hPYcFduO8ilGVY+gYIOGj3Sy4Z1bkAQ7ccR+s9aVxFNM/tQU4auWBbLSGy2K9qC+Iwx978dh5FhB3aetrkbRFmg1KZ'
        'e3SoJbteQkhxnrt4v6H/v1eKButLX4CTXStdsc7L08S+Lwx6IzR2a9J4l2BAMb9OBkcAYmrFb44DqNaFzjH2YocqoXH53esr967k'
        'n4MgtxizkaJ3WqmVvarv6jHWJwq/MZizuUcGs0n6yWkwgsXGw4KD4ojV6X3ljZwz1iOgMAzAPvIPFXY2T/Owx25MSZm8mjlZb6k1'
        '5h92yQz++xJuE9E4rQmrhcG3tEL1wbGTLRHkJ0EUzXPHuc5Jo6cS8+3JKpeA8HoMNYFugRP6dTAwJ2RVYO1W/mv4UrIb7WIQ/nll'
        'pQTOk8/4Qr/5qidbm3ylzzARu+ZeHvchZcpJnJUWBBsLPlqic1KLpmtPxRpcfmNV+BYDp4bMU8u/dQOIUQTzlhCmPuZbHhcS5Jse'
        '22KKcvkkcUJUsgXQdRLYMLikeYfjcVUq7ueyrr8Qk4hO4ke2ecxur26+PMNbEMckjfBxX+aDzKfPn3LP/6sKNZ4a5DRbPzhDfjmL'
        'fLaOoYLpxjyhHMZttCH1u9NeNktM5JpxMZPeIsnLMhisCcpUmamxhvnojx6dary28L5S8L30FJSQjZqhN1OV74LJKoQ1iwL8OIds'
        'GSgO7KEWnLVDech3zLnK7bCNnY2I93gNtR/ygLGM+1cCrX0R36bOKgQZtcjpQ3/TxxyBLMeCZS1cwiZt4GN6sHncxv/RFl+h/d6c'
        'J4m1fpmdzlVtiuIHhACzjTHAxHhIY9CUrkakLjtqvDLYsElsvYhDjwQn4ZcmX1m1J+17nz5ZhLm5q4C/spwklGqfhqWZGXqJSI50'
        'wR8Um6wa1h1gbLdyLfM2yC/FcK4iaMtAO9kp/epvMgQfr72RdS/4Z6iPZ0JEaxWQw514yjV2km8ik7tk3OEImBHJTduGQJgJ/ktB'
        'biJCXpDp81dR08GS5sxV6uDg/8KPhqXrHTZ3Kf4LUPgtngx90EVSdyazqxksQDNWbHcKcwOZhtJbYTTEGZYUA9pHWjyepuDo/o1x'
        '4hpBQYnqvnDNRC4wJb6PW7FDIYu3LaBtiqV5omSIN4zzyT2MqWtsOIbaACF76/1TVy2uwQW0zRWJpdn5YGSrLXzHw146ohJ+8JmD'
        'C0/9xIV1X81ffV9taOYijRbFNmupPvfJWbQgRCTQAAQP2nQA0lbw7ILejYX4KR/VD3Eu1lOBcWDRD6DkC6Yo4Ugemx+UycUX0hJ9'
        'A0c9qJ7DnF2oWwbWTUhKe04QbIhOjgmgLEjQXzEQmsh76k2v5WrBNiNofXAZFemxq9dFZfr3ThSNCcFNlkhaFyW291FLRiau/XLm'
        'FoYb4qPU7lZsxU36l9jKAVWIYEVwFd8rCde0qHLCCVXZuxbltxzYWmWaqqGnMs3XIkosqqaNQSp/FZRq+UBQ0I/2HhCZQr4EOoAk'
        'hLX+0IyBDjV9xAEDj3zC8C4oT2W2jWdjNSMToygvN6b+87jLxwFXlYdkrftcTaHkTWAPfQUvbi67F/DwKcfiCkPk9dKHCkbf5vQN'
        'wg9KxKf6T4IFpJhS/bxOKVtwQiiqX8VK+7snil7Z4FmyS5yGXSKMhrF8AqGIkL2AEllRfJNcArG2wn7gGTzZWdSPjnKZPGWaI24A'
        'xt4BEd700hr9ogkgn4/6E28IOxTxGDFfB+aJ71uES1VnKe5V/knb3Zhci3a8QF1pK8sUtY1ZiIG35YrLQbBpLbwL7HqUYZpTQfrq'
        'yk8pBdqNpS/golJyY3Ct3XdkPgnKOLV59xhwmct3HwXHYTYZ8kGmU5Dt3kDNMnWojLCn9tFsNld2Rj5BTwQyEoVbMY5iBsJSP9+Q'
        'CV2pcI59wgkoeHph/tgVerTXBJsbLCH5mJIsD8KRmQ2VJs4VRGl+Okv4KNEEIzJd4Oj8dBVsOBb6FPq2/5ko1/hivbdTKmT+4mt5'
        'ptvPNyPvjYfQ7KxHacPA/5cHZotBDPBz24HWsRW1jGDNQS4XSQdJry2iO3R1KXmW77dveOYv5icmI9f5qfSQb3pUlei3Kdz47Sqm'
        'urTGAjM2MqrNOWcbvM8q3zzkAj8c3JSpRdOL2bX7DWqQgNf7m/HJQoBvwZkMPwYT2Ayf+71pCW3XIHh0gamxx4nevCi+ZKLKMJ4W'
        'aeakmhUjUGIu+TeBXnkKN6rWVisitCxuSCB8WVadCJ53OZs6gkU9JkNJZC+s6lBMGZEtH2ebnjzzAzLY77mBZ7g9A4FvWJ9KJvk0'
        '46lBgldXXJ9vjtplaQjQdyrEY4rm1wNKyf/pnXXY5tSEsMny1W9hbxO5fFR+Zu0Lm6PqrwvcHLjD86KYkxIMPHez0ofc8tx8KP0m'
        '7t9wwW14gqgn41jZfExinOS/ALj3AdofU7dvYPq3EQ4WDlGp8vKndyTIg16DpGThwws1vPl3AL6MXyJNnl0ZOtzSDLdL1PcNAbYg'
        's/TpQkUTYOQdanIJ4W+StQM2KJT5zubcRoEB0UZUlXey5mP0PgUnLLtpeG48QYdTXxZMCcWs5b8FBPUiOKzMMyl6cUiKyo8+Azlk'
        'Apw8wqrbDT2SIIixNv2Q/OzsAMTPRF49OQuZZHLRuuLn6N8DW+0WQscxXXQmZG1tbpJ0LoDASiJyxAeKU0apuiMSxI8pQYRxF9QG'
        'rrH6ccRdlBiNR4/QTqQOzUNdv7EY+8+D/lk/GopIS9AUc931X8XbZwbYnu6I3NsocYhErZqorGh6cdwFjM+7UpEdsw2VuzKALzDV'
        'G8h4hZbgZMA0kl3fUbuQI/HmPfJ04p3q17ORZesNb1Q1YoIlS21ZRPjJEAyVupGRW3Xq1YESNc3D9N2LE4o61umNSCq/QmvR0f5z'
        '2YSJC4SR2hBRPFJfpnHX0BFK3mP6aaYE2CPKG5ihGKpyYK1v9+3DhQLL42yV8wLU4gqTUpG/Qram/cTQHji75ElHByWuEejFejyJ'
        'Aqz45f9x4NfVor0J2tIJrta9OJk9V3DARzgC2yIbGF8H+lcFFUACubzVgBQ0EQn7Ypjz3uuKvAam495fTzsjGSGMa9zjstGZooH4'
        'BcSEEyqbBcEuRHx9G0MR4DmFK/8Skn+R/NutROfRQhBrquEJrp5OXNFivyVCsz3DJNszFBJdxTpzf/lUXtRisOMW1Kq12NCz/xWr'
        'fDluR9pru1DoYL247D2YZSZ3ngrOX4kNOgNds5fc+x57O2o9rqYeEiGygdFWQV5CAq5KIheRxhS9DPMC075U4GSvLZtfqGfCfl4Q'
        'DeWjzZjj8DK6fjLKN+dHA1yO08ZKltycnKXZC8Rt3mwoyxpzR/5+W/VejBrorqYm/HdPSvkyACygj0LJ/vvY3NqnVLIExFaNIhXg'
        '27vq3fQyj9jQbuhTjZZnlCLCVPEfQzkMliRmL4w4o9DuOQzOMnblC0/zAQnjUxuks8bQq+sp2WqTGGk3Udek/fJi1L9+rlkaxYz2'
        'o3eYGx0AV2OftGD2mdCoPSvNopvsdt5iENrlBfJqjox7Wmek4JlhFQ8ldo72WJLMUhgzHrX46k71/ejBcdjmSLxN94577NzeyixL'
        'zodFzglJd5xtizNBlXrIIlBpi8Vxjlntgzs1i+UDuSD1OUQ5Uu6sfWN3EAuJn9Q5Mst8Nkg7se6gluujOEUT0XcX7KjXZ4h1va9j'
        '2oSSA9/oQ+2No8vtHhf6H5OXXzicFXO4jHv7aIuoUeE0whoWyQF9kM4eBKLixrWhgTGOgyINqBmT0bMs6FqbGNH3ywKCEM9A0Th2'
        'AOFN7F+jhRNRZUSJ3mAz86w+ZFrKlSQdzSLEnRtdI5D9dylI5uZP5gwJLm7TF2ZRZpM+DvcDsxvhTrGmaWmYEONm6uNg9pGD6enK'
        '5yyLtoSvxIX7LuOZxdtWdMsOXQMayLZeFumNIhY7Ka4djRo4KC0W4tnlJsMzGfjQuhxVUl0RSZcWf2T+7AymVA5JbyAogbnd7+Kx'
        '7UhAU7+mudajtImQvi95qaA4jurEjPaWg+l/rngZJuXzP1o+DXh4qiBz9apa5ASCmEQcyiEnLO4N7AOz7a2rDz757GfS4Z0Uymvo'
        'ti8KRlMt9SEKUkfIHNFdQF0FLMjpoIgrILWRzcnMLvSEFpla+CTDpbPb/c+SExCq8SyVKmdDSprbbkXiSquJJe+anvMaU5gEMSKl'
        'qqMvTPuHGy9A0O+ZrmYBIplFRne71Y5yuy+Ay7vsWeaG806u6sbdr2DmTts72a6Giz2Tl0fF3V0LkMc56iF6Lh0+KPig3/flumAu'
        'saVJecys2c5BP6KCDAJ2vbH0W5aMf7GG0oX9luhM5pi3pXQVicJPObNpaVkkyxtomHIOEbpqRpux7quRr3JxHjSjHDt20a5uBmz2'
        '/Ru6ej1XfrGOAIqIPa3RxgoNkAOY4ObxxrQie6XMYsBBXDO5BmlLRb24/0afjLCAmNhRRoGuWserG/JSpiBopUeu7uJ7+7M49lER'
        'wV3D/EWmUZFjGkHJDqR233BJ0suoNj/nfZlyDMuQFWayWXkMOaLatYxKrEeG05oPL7quwfYgccJ7xLFDhhWMEv6vZ5e11fLYDBKm'
        'W0SV56wwPjcVO1J6I9BPuJM0Q87/hrtj1n/puGNySKWUmkmg0QeYtMQYvHYG5LD2jhaVSOA9/NXy3sBJFJhxHB1pbl3rqfiuQ3/d'
        'p/IQ1xq8apMMrAx2XcUGBBP8gEX8k7gPg3i/tK2WK8pTnkyxZTw0ig6j9h2Nhe4gk5ZvglsAsXQhTJ5hZNJWDpVmWtXKpYIKgoE2'
        'nFEdk5XiXHRZMLuT9g9gVWWeosSqMIbcJMWJD9KHwcal1tOAGjEOPt9gkzh0W8lXnbLpTVuO2k2Whc1mz/EO3vMubfWjnfFh8lR1'
        '7a41r38en48Q/oPbWb6LNolHPKTGmSv5s6R+pezla4wQ3s+9Iy/kQh0EObzEAQnypSPFZE12uVTTLUcM9GqvMuqlo0Eb05v/Acnb'
        'cLv1/mK8eGvHvOQCfnUKTnEzUcB/SHx4jam88mSUKfEWU0xPiLyChxrwVkHD1Dvf5GFWBcZoM+vaojJV1bNZIPCMhvYuaM7onL2N'
        'XsmpgDNBeAeAfLw0YL1miP9nBWAAc+3Sbyg3XSS8DiyiECGt9cLKja+aiEP9aT1tWTrRdVMLkRAJ2iO7d2Y2cFDOkwW2hPdj0u8C'
        'o445w9Zyo3mJF5Wh6pQx7PSS6y15fRO/br5Et0uGuaZmyFbyTTGSnvJ18/ACFk13r7WPDPjzqoOfvabDACPRlxvKQ/TsPTsCZYGV'
        'UqUe1YcAKPqOnzaCDrQoS6Hwj1ls0PK7H+6AA2SVXSCG9YRkmPY4U+LV47TBXkS/WR2S+JcdYCY/fGbyCeyilCJ0MbIJ61+tDQn3'
        'sGzzBzCba4Iem8968jOjkF3098MTRMFXEBb5SnEslibgb1c/CBM/6X1DZFAoYj89GPCZ6MCztgNyWcGF0x1IZTgOHNvCeum4q3IB'
        'jPnI+kDe4XbCTq4sJzL/IkdSOfwp5uV1PhzlXd9mIQSR2WIX+lwNIoVMPgeuv4LKfi32+aQI8JijCo8CRvFf3+VpM4JrUREiNdUs'
        'yD2d/F8sYgyoRfmllSii908sjKzvLhKXPzJ1HGhQK9dT3qEQYhs1UB45g0Z9UFCtaWe8P6ZdZHzIya0XjWlFd6xToNkaNeBWrzZ8'
        'pvp3tc40eB2/wU3MzMPxzaL4DyJaHFeVN/G0kg/a4BTZh3AYp9SzCW/n94GvOBdnavWbQerapKSAGbTbWJoLzXrWdz9264bt5lu9'
        'PhEqPx3sF0ndkx2e9G7j8khpdkwWGJuz0jANsST2Fh6KdB0+jTlSB/HlrQPSlhfRfOl5cSIlAnwxgK36dOSXTjCVolqJcE1+uQuM'
        '0oJDga93woc2t/y7BNTO3DjUuibOoDLQeHIcMIX5phvKzAax/raYNjFucbByo0AMFVZFz7eJO9L63cTofraGKmWtgSksyQV8yNjr'
        '5yJcn2KdlIfh399V2wEek+T6RblHxT7aP5fqhycpSoriHBquNbwBeN0hK8Z+etd2bayFNevV1G+mI+60HAlCdLO1StSqEdUPNyAY'
        'tScWoIFyRN2U9CT6zOXYEGranDCRmGUEy84esNgGzCKWm8iC4WWPcndrRgjneE0WuG62WwZk4L07R/E8jzDfwoMxNCq3OCzauaak'
        'yK1PnhHAsBgQ3LQQNfwo8oXr+K8CkEL9rQH3tpy1nTfuU1Zmv/hr4MJ3P8D7XmSL+VmtRA7m3c8oTe5aMT+Rw1JeaPqc3EpsxxoW'
        'WjwTzTBJ3tSsyoxYY9GHgeRly5H9bdi3G6QGkKUsYCQgr5jbnbUrR2vrq8CA8r40YNfxW7A5TROENYR/nEl0SEESEdwQpXCxS5z6'
        'Kzw/T+1XRS1+XRP+EAFKMtz8HN1jZjbEweoxsbJZfo16WeEAF8VAzsJIW5gJp3nbY2ibzsMWWOlOFBY8PkM7+DCu8mI1mVQnuIJg'
        '9EV/VT4YZap0eUq/L3sz8bDUEzcJIaeu5FFfUpY1bdgCljoc7m4VXBWj1MAc4PkpzO+ltA39cCCxbCNSuH5r/RlMqe07x2RQkhxZ'
        'JXePQzoWCuh1gIXdzcQyXGJuEIBqVXfx7u5wedWaetQKNCtDsJ915Pmtxdrh8aJEzKSs1O3bAzjTspJzFeXmBZop5Bji5O0OTLZb'
        'l4FPwZtk0SCU65GZGbce1Pltj+CFBWmqJvsAu7gQUnQrYYzvMDl8ZN6TTZJWKwEdkRY+f2DtHO/8XJVCTAq9EH115Jm816223lVE'
        '+rlp2G2VVCdd8ZD7kf1pTJgy6pcS6Ry9w/vTTk5rL3xKBYQbj7KDjJ+Q2p48cDCaiUSIjHQmoBOK3FRiNBdBiAyCZSQQLvIBqZi9'
        'vJGCI+oreIGNnMnKv9J4pUoFInjUhqHxs69dpbqDbdK7d6GuupjOdjQfletmwVNi3ieDj6yrp4Nc7QAL27AWkfbtBW8Ywq+YSwby'
        'zpC70HtdlbaXTqOcaIrJb4dI/LcQH6/rz/+xk7goMr/w2i62uhD+amx5NjD5tbRqDKRKNa0r599GQvbgi2G0GInrkmLd98fGTwEv'
        'f+aLTj5IlDVmV/6Qi5MuPz6QryS2Ivn7j7Yrxu17Fjt/fYEs+VplgYLl6A78SLwzxyhM9IYplQvd3qTmx0RblS+FcB7W1akFHMzy'
        'w/lN7FHrgJmRHww2/7Dy3eW/E3m3eqiJjYczHJfwXa98DZnSMMCbNDbsBAh0OqDFe/8Q9Al7TvOr5YmEN+Cw3p/YTiKDXuzn6REk'
        'gdykg9TJNs6vodP6PnWyBBVF27msVQrz1HKtK7reLKhibUBVx1KttW6VDyNcprtZhXwpC1CNKfd+syRi/cm/hUNyoHY01WdoTc2D'
        '3gzMsPnJe8bMzlj35k5WohE9H8fJ1uBjn6evMdwLb9y1O0GK1XM+xj31ALhkhJpUkzyl5dX7pUVtDpaCpWz04HsdUe8dn9DgXIZ1'
        'XiPf4HCKbqjRpS7wAPE8vBBTq6Rcb5BBVyl8A916D2cspJAvig4a+oiJkN5EPjkuBzWhDgta4neFA8/D0ohwtvN38OsWnWlaUXIx'
        'wJUjb3G7QiBFz8cHCwW6B0cNuakC6fttHXCMqlZbwhMgFqnRT3AjXNd6M3C1r2KeXEgNYNwoPqdGnh8IFP7ykKBP4fByyklmu3fZ'
        '37RfPqZJj6L4NIosietB/xHzVhUZDKpW06i5VEuAYLgaBhXwwiFjhPKge/gDAUT+QO+5FGhk/FiHaLQXIez8QSmNmH7ErRjkYDEk'
        '2WmR0woS4kM2Bn7t4u9NVK0B4C+R7mdc2bBkGX/SWeiFdr5df0SE1rCRI/aylYAZw0TACS/v9DfXEsOPSoDiBtO6r3rs2sDlwdJi'
        'F+mvxE6YxW7knKzfwVcLe0ozAgdZaR48gvmnt5jAnigVHwdylk9wT5Ztr9t+0zB1PJ+4KjaDpdpm3GVfFhX/VuNOu4wjGEmp2Zvn'
        't/EV0Sqq0dbKW/6RFXX4UBYbLSe5G/fUrIJfzni23mY3064OWEf8FRW3JVHQPFQY3E6kciQgvwjc9gxfuu6mDjKUU2LyazR6PNW/'
        '/Y66e2uADgtTapbkVEmc1rj8xjbXvGVgtKqL362bfvBbp6cXt2PLNy3h6sxMPsAB1ezrIttRUzH65o8ToWSHqPoJJ0WAqQlEobEq'
        'X/tzZCzWgAPXz7sM30ghKop6OtvJD+usBt++o58CRyfUTgu4+EVp6bLu8rOZO1aFroKq5O/baK5n2cFTG8hUy6PNI69IioDNXYKf'
        'NOi9dboUVUviessShz2jszx3bH8kP4jcgeRjmNR3oSBHR17tuNd9j1rrSlQxAMvuVN8qhy/o3xF0JE39yeguANwSKB4xUXTIiDAE'
        'UMX8+cObi2C2UNRY00CxSfvQH6/MzjWs5jDpXVBgrh0ulZ7akeMOV2NuVsIgHgcZWFJgc+HWgRG+c+Ey/JbohEy9C/0Gayr0IYLm'
        'cqbQJrZhS46/p6gJZ2gTbLjE+mc7dgLym4gup3OckWhu7HlzWx5yxkI82dtHT6hPUs/J1r2BQBN7HqGvWDx2SS3ArS52UiP9LQ3O'
        'xstLXO5qAh/QN00S0ZgmAJe7QLlun2+jrWRPMCz6IaTC6E9U/B7I93EdObPBD6jViAAX0yBkwa0AlcOnFUKkUif1BDDrAWT4D2OM'
        'NosxNeBhTy/vtpeo6a39L7eJUlgHN/jPGClQnqzHMT8cVAnSeYLIlvFoYC3vnanSNyhVhshzVGfGArWsnIptZdC1FUEc6Ce66moY'
        'w46+nLjlmmZWwaSIxBTjW3T1OrXEfo8y4SYBvX9MBxU7momwcwFMgXyPS6J0GGtGw7MsffZkb7Gbr9UUwn+eISH68CdBzKs154Ql'
        'Bn/so+0r54TeQFjCEgaEYUzdnBGeoCYEzHpJKw7s1bVt2e9de0hEtaKlSHwbK4SXpz1mxYSaIghL0EoGAtD0lFeQencg3hoTekzz'
        'Q30rYbr3KATubpiGNXNbQHIwUUBCPhe1IMfQSnIa6DCbXTMYSUcGCtcHzvMiQatZAex5HdEoc766g1aXgONUQ9HF37oljM9RMrmP'
        '9LqPvHIGmYlAkm164v0EtUwIe9B6oXQSv2AntyRrPE656XFojuRTVwmmFSI+OFAueQv1DaAwRADK1qdMm/d/cD53Fwu9kR+bKqcr'
        'tebIFm+AE18RHQYwBa+vh2HeGQy7FGaphqpK+3UKP0Fy/PSCL04sv8LgUw0q6hQkO7Biuh63ILocshNh6IDrL+93J4LWWQz1N+C+'
        'ylfU4LkSTmRZPhjDgcrOsQk7VnGLdlf8zVOuY4qTgx8UIs9m7v8aelDFeKnj9gjCQBmFkgGbKIkXtuX+iHiIlG6dYsEfDbOeR+fL'
        'P9Ha9izFctRDSPTkBqPMjFVjTud6VcpBgfjhyvFudlPJuzDtmQtpcym2khQAMMzeGekmsQbMi2fFHleAVNz4aZtWDoh/B3pScmqW'
        'rQpvoLJCqvb9yq9nh908Tx86a5kUeuUelUEtNqKJfVqj0oK0kvs7eZKNpC4U87whCaGRC+cEBCIHI3a7VSMVgyZzfPlLhrMNCIvC'
        'vmC3JpYE3t6Bczm+mqwADdP2L9fTXMN+2unw+seU4pSgFGG88kd+pK6Cob/gz93/5zRKD9jN7pnkETYIKYyWJgqKwmRh6vxRPr3a'
        'l6WLSWLav6IUeXP0VnYaEZ5b1rkKLIAqvLxXxnLMGe17w5IYwQdSaEBJrgOJrjGzVM8lt+8goZo0wN5CdoCRvWD5FJ31sxL96r4D'
        'YFgoTq2zUTaCztm/zxr9/TG3FjBp4bysIRuAzKZj5Y6YCQeoqSEV4cUXG+hmdp8Qgs7MCcqVBgQqHsvRJGIrizV6lfMQ1NYqY3vw'
        'goYtwPxmjjbEn3dKqmAQGawL85CXulfpU6HnSHxD0i9c3zUweJ8fdnn2d3wOUvhTPXe3h1qgZgMvd8PXXwEZrkYMbxLBBtWETB3z'
        'nCipZelqhScON2I4Hwm9ZYuMMvT3uQ4JwPCPueMf3K8VsVdullqooq81Pmebww4Zzh3aurbOd/PF52Hsmiuo+7wf/R6UjtMqww/V'
        'wTTEZOthDosNECWDCqrXZk4xFkCQmNWjk3bzTM49JLzChnJhFW9MkYswqI1H7CQrPOpci/ES4ikslCY/CvFx36vyvWPu4ur4kwPV'
        'OewVcDZ0At+GgbdMgrKwYjOSQjcVdhiEx2GvK8dOs9QPqcxsDrOuV/wuSucbQtQmifkTLID8YmJBXc1e5qveNbIuApFQuI5LlfxU'
        'XoNFQNNm0bkUKA1cCIWh7hJ7OO2WSxq4X55gVvs9nOb71VPXwqGpprG2YqEoTZaT0tdqEn7J2v9nV6htm+u9GUTBjo9OW29rdSlB'
        '9v+yOeY4i/NLdslYfHoTJB6QMFgzh63y6uT+q6ZPqRgwwSqtMyMI+bIH33bOZyqz6vxUquNOtHRTWqy0QcULLEXq7CKHaOkvB7Vx'
        'Eb6ymNcANNOermvVptLg21pcPtbCrLiduAxs+flSZNRrnYJ5qP/GVsyJkj9ccc8nmBOjbFjbO2fFVuUyl1iir+qSIC0oPgCYOTGx'
        'nS5rN41J74IfyRhkkqo9nSAEaLKoa21mJ3Tp15AcAFtnzf1wwgf367ViOai3Bv8ilOEU+luqga5pHYDKtIR8z7Xq9puVtAZSht8y'
        '7CXROBKz1O0PM729LFY88wYGMn6kYc50Uy4oOCV1FT1az5ppYLy5qwNsUltRtzOe+hg9IdpdUdPvdQmL9JESr/X43pZ6pnGXLr3f'
        'dbhzNUPFXCKrLMnz1I9Y/mdu/Uf2fzUS4qXcOp4HPCZY0++HJqOF+0M2Yt3PBiXNPKg2iAapcso228ZZXaZBWnBXmQwN10lcAwFz'
        'KQZ6Q6SlDuW8nyla26uQHyyFkzd7j7RFzbBJNcwsakzZNzdh56fnBb6MICADWsSbuKpEkNeJt/VbdaBvgh9f6iV4I3tV0H8AXBe+'
        'ADJOPoWJ3g8ShWlEDITjeti3ETHEYs1IX3s8jMGt5QYdhsPDJEjqgKIlMotMw9lniFwVFAEqj1Wt8kgqRuLDzImZ4p631JCF6gzc'
        '1mecwLpFYil/2KwO0fGDtG8nXPFv781OR7+zcOwRwsWzJuW16h08n2bFM9cUOFipHlfA4RWrU/nrD+PtIK7AhmSpFv1A4NQyw+Z4'
        'pYuZDxTGUWC6wCF048H61aQxPsyP66IOn/1tb765V6Uspjm0kiMtfwEzduyzA2EpiHBgksQTLPbjpnFc+k5i6LGCkUMKBTe4v0wb'
        'PGD9Iwdt7T897VXjpi1GtwyDjp0flRb7J6iwc4tY3XzzWUS+PHYkUOWEeeVRQyBYnQtS/0OvDyER/zZ1pgx3qc/jMN2/icrm+5K0'
        'PRkoyLy3zL5AtrryOagRSqt/lu5O86QZE1kTsvDgtERU5gJ78H/GYOAEMGfkF0MDhHgVESuHc/1zj+325MtmfBATv5IBV91TSkKv'
        'B9/THAVUqzKiY8dFceMiS6DFNqpSIDD4ZANywRNcsa1uUA7XMOTDgv2hB2d/xnrSshmodWE/B+OSRkuFnqfrEQnn5zhNTPNEZgsB'
        'z2rt5Q/YopJCNoWsxQfvC4zqG0hemPWbRFAKP8oic5OWBsxfj3CMyxm8v7Al9y9FpN2uTDlKRO2cniI2tRSg4grCpbfRO3XtS5gN'
        'vJkCE0XEc2UDrRpXU31Q7CMIrgrwl2rk4X84ffbhv0P0/ECqJR1+rDyh+Ia7ptxPuqM7fHBjxbn6sAH6vgDiSusO7kN8wNYAu+Qx'
        'KJW5pTeX3lPOyjFHCozz+wIV9f6pv6EJXhNyHrzup0tXfGksypJJWqfk3c+M7iHKDDdP+zdMNW09MwvaJX/6sVYhevtOD3fmobmE'
        'xfrypwzIlEv1t6nphPXapC/b6ARyH7Ir9jV55RuvMg8v0TTe/tZ8zoi5xZJrEm+xsFsFb9NkH83Ca4bKCL/yFyO2ET8POh5GwXZv'
        'LvJNjDgT3Su3FEN19orTfEip/U+6AjLAef/yyQVu7pcF9sJ0AWryHaPSgusXrDaZWgoq9TF/EFUvMQQ+WR6o5FRfflfWwMfGuInV'
        'NuQ4eRWI8/JyuKru8vjS4yTq3UUkNw3a4yld5X7sC4zcPLGezclO4/8RSE0mGrZ/Xea0DPSL2aaCZdftlO+gp3WJ6/P1EXDhA3e4'
        '/WKEpc5Qp5zcqcBjtiWs2+rU4k6BxlU8nQ7QonmXcO+67JN87f/j3DwZGDIzL8366mwvX1oTkiXuXSoRVvc+D1M/Ix1iDYA+QEv1'
        'vLR4XIdq5cA+s2BWZktm2aasjTBMt0sVJTpRyQo/zztNjo9Ccw9LTb7BaZF56NTHJgw0vfdUqm7Anzt0I2hn4VEX0WVS0MeMDHR6'
        'vdw7rt6ZLtkraISideV1jIUfjEHME5tdR+eyl0B+ZFbZFWIyHE5fpN2JqDTgGsrQdX4PWAwy7dXrVM6qRmrJMZQxtWScAeDccHd5'
        'Pw5RBW/ZW3EO4Ubk9R2CxH0eB/OndzNnS3sOx7BBjVJphaeJq25m5j8ebEQupyKQ0oWGCGZsbgWBKScnCjR1sOJnh+k70VO5pSDp'
        'LPVa9UUx+kvYtg3XLgwPY4Gkj0q8hRccbfa+Sv2isWPivi9AkbKdacJgwFN2l1k6NVo/7k18MlBSdCwL8H6oj/g/OeixEXaknaDj'
        'SxbQPjj6Iy4va29Idkt7WapbrGwpNo6Tuw8wir5j3C5Imi7Q5i8gPSCDJMr1ctIIScIPwQhdNNUFgdllPA6xNrTmncGAhB7CGsoS'
        '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'
        'Bc2a0++Io0Vj4qVFjY+Twldsor9K8Ho/SN7Oej5CzhG60P2kh/rcuOuf5LW/NV84s7S0HjNh8hFDdwyGaO04l1mbwUr4iCUm6MHQ'
        '934wVV9CFPBDmvGjCaNMg4O2UqhCvgkjzkuXgYEDf6cDruEeMmH8ENSgUkozxiZ3yqDLzDNJFrJb5/LzuSipl+86g6dtRde9L5er'
        'sDnr67sBVuxByaCBlcDA7OzLigSAtV+0ia+lmfYx8jp2NvFJe5TCdNfh/l4rW3a8JLu3OVeYpRWRN4gME9fBlwrihCtIupeJqAV9'
        '82iq7NUl+wH86mPOF7SkLR2ElAHNllfGuxwv7pAAp/jDeoRdTX4hGCo3N4Q+JDY3GzbJFEKWnNzyb2iwI8lwpuoQii/pdivlyqRC'
        'YH4AWEyVps41gHpNmHExzmDcwg19t2jBxntJRPGiUIg+jqYBjOvznInwxuTy4/7UcFnWlpdUpes12xFzS5QBavZV0a/yaDnlh9PW'
        '2DLTPrPUlWyngM5kJ6GwlrcXc/mUt5CfQSz/kg3ueAy6E0eei8Tsy50/YAHc7uYVt7quKjj9wGchidOJ+oZbL1MYzSRxcjb7V0oj'
        'ZmtCGLVuTvaV7TmpRfuJLLb0XdTYfmf0WuOtbaTmL2ue76L6CBTaaZ1mzpmiX1s3u7iz81zkdeum9uNOHdFcCT7aM94UuTXaXZjO'
        'gD547nJkSy5qju5S/rbzXL1YSkhlBiFk3rMhJjoGC90t+52VUcdhHzkvc7GBe/rxy+Hd0oNhOrq9uQIVOlMcnbP7adoIM6k5ZurU'
        '3OhY0lJxTKRiD3k9W1Rp9AxWWRCCbOQzlF9XXbBO7mkQVUkvtrSJ7PcaE05Nb+tuU2bc9gxJ+QiJJV17Y9kqlEhfOaIyETjqvlQd'
        'BNKgb0iXREX2qizYBPltUANEcy7ACtpIuQNLE7MpECs2ottER/uobPCQZMYMcWvD3mkNSI2kjsRz9n7J0xSXjFdI9CHR9h/ST3EW'
        '4korFJZJ09GnmotouEFdKvPu8MFw8bm9JoPBaT5RyKlZKXmilkQTjTypJAmFuHqOBbpoVfvyHRPNUgCEgmzvqcNzbm5GuOm+1Apc'
        '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'
        'Z06pSeWPISYWQ0UaEhzPD50Xbc2tdNpAzDmDqagE/Nc9L8IIVGV8Lk/lX2iZcjOMr6GNq0ZuC7vWNo5nkQKaUsjj8hGMOSu1p5D6'
        'f7jMOTbOkx/u+NwP3A+mfWhO9A5359F4vEll5GrZzRzlS/b279EIsWg8riphVmcpffOsu9CcG9c5gb+bl/gIk3PwWfunotZcTzko'
        'yXzdM4qmD1/COEPrG4lIuaK8jPHLnWFMummsbRVO068/PDB9ot4vn9pCKbtpn85qI+XIhEja7ejgp8CbvQ2sI5/29EOcn46xM6lX'
        'AflE6Pii+pSloMv5UpXyVov5ew0Z9TbcjyoQXU8v2r2DKGoB75KMyio4OjqTk7as0VyMfr+mq+eO66wT4mEyWW/dzo/1BxVIf2nF'
        'oLHBtSTozTmQ1QyvZc5qlUs7BYzH8jCcVFfsvXoHzQFYAi6b0WrkQqanQWMKIKwZHp0+w4eENM7kPcD3mxGMQLYnYbAX4hhn7Y3E'
        '6SYrdc+QArb/vVbAJkWbwWWODToh4UxRp8pr6vAkwkLQkn/+frScWZ5KJdblWFkx964adgj2O5mqyxiFQXtNCFh/AWwfIm/XD0B5'
        'GSJo2voXvwV08fYSxtHamurV5xyPBzZv5q/rKNXznklcTQFFPCDILWE21bMKE3CeZa1rp4huehQronG4l8ORAnYSCgFN4QwCAk4r'
        'Re8ezaVxBKueqUp7RvSXov1RM5cawk+905JtAaZDkugGolFxoUDmGt1QefOkusVT3Cy6hBmudADjeJQvdKP/+eTF3gaVmbB0HrtE'
        'wHfRwJa9jZbVGdji4ACyBEQJTs5m0XWIr+Hsqw9cNr4eulRm65V3U0AhiAzICrXZ7w5l0JExeNajZ7drvKPUEutiO+/fnqvAENDA'
        'Mem2ZcwgzU8lhuJu+54qt/2UnzJ3nWJM6oXgc8FfHMPsuTXc3ofdxdzYvExx0wkMPMomp0DE3tdOFIQP1CX2WbKaCw1MQo5U8x/T'
        't4TeLUqaad3pdlNGn8p2hJZWQ8UWiCjr61MMartv1fVWxGCJxdre9e6brS7sSslVqO3JIY0u/Q1h10EXNSbsryThS0eYagP6+T3m'
        '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'
        'AAAAAARZWg=='),
    'linux-x86_64': ('libneocore.so', '45634bce3e1646573136c5beeb25058f4e20251766075869d1df9e06def9edd8',
        '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'
        '4DjZ+zP5scRn+wIAAAAABFla'),
}

if __name__ == "__main__":
    args = sys.argv[1:]
    if any(x.startswith("-") for x in args):          # any option = text mode; the window only takes a ROM path
        sys.exit(main_cli(args))
    try:
        main_gui(args[0] if args else None).mainloop()
    except ImportError:
        # Tkinter is part of Python but some Linux distributions ship it apart; pip cannot install it.
        if IS_WIN:
            hint = "Reinstall Python from python.org and keep the 'tcl/tk and IDLE' option ticked."
        elif sys.platform == "darwin":
            hint = "Install Python from python.org (it includes Tk), or: brew install python-tk"
        else:
            hint = ("Install the Tk package of your distribution, e.g. sudo apt install python3-tk "
                    "(Debian/Ubuntu), sudo dnf install python3-tkinter (Fedora), sudo pacman -S tk (Arch).")
        print("The window needs Tkinter, which this Python does not have.\n" + hint +
              "\nText mode works without it: python Brico68k_Emulator.py --run \"Help\"")
        sys.exit(1)
