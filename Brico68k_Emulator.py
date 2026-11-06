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
NOT emulated: YM2610 and sound, Z80 ROM banking, sprites and fix layer (the
screen shows the backdrop colour of each line; S, C, V are not used), protected
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
           python Brico68k_Emulator.py --crc-plan kof98 --cart-list neogeo.xml > kof98_crc.txt
               (P1/P2 CRC32 plan for CartCRC on a real console; NGH number accepted, e.g. 0242)
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
APP_VERSION = "1.12"
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


CRC_CHUNK = 0x40000          # CartCRC: at most 256 KiB per command (< 1.5 s, BricoNeo timeout 3 s)


def crc_plan(software):
    """CartCRC commands for each P file of a software list entry (parse_softlist value), in the
    file's byte order: [(file, expected CRC32, size, [command, ...], remark)]. The first command
    of a file starts its CRC (P3 = 0); the next ones continue it from the CRC the ROM keeps in
    WRAM: P3 = $FFFFFFFF where the previous one stopped, $FFFFFFFE after a jump (a file
    whose halves are swapped, ROM_CONTINUE). So the plan is fixed text, pasted at once.
    remark != "": CartCRC cannot check this file (the commands are left out)."""
    if "maincpu" not in software["areas"]:
        return []
    files, cur = [], None
    for name, off, sz, crc, lf in software["areas"]["maincpu"][1]:
        if name:
            cur = {"file": name, "crc": crc, "segs": [], "flag": lf}
            files.append(cur)
        elif lf == "continue" and cur is not None:
            cur["segs"].append((off, sz))
            continue
        else:
            if cur is not None and lf in ("ignore", "fill"):
                cur["skip"] = lf                # file bytes not all loaded: its CRC is not computable
            continue
        cur["segs"].append((off, sz))
    out = []
    for f in files:
        size = sum(s for _, s in f["segs"])
        remark = ""
        if f.get("skip"):
            remark = f"'{f['skip']}' entries in the list: part of the file is not in the P ROM space"
        elif f["flag"] != "load16_word_swap":
            remark = f"loaded '{f['flag'] or 'plain'}' in the list: CartCRC reads the word-swapped MAME order only"
        elif any(o % 4 or s % 4 for o, s in f["segs"]):
            remark = "offset or size not a multiple of 4 bytes"
        elif any(o + s > 0x900000 for o, s in f["segs"]):
            remark = "beyond P2 bank 7: CartCRC selects banks 0-7 only"
        cmds, nxt = [], None
        if not remark:
            for off, sz in f["segs"]:
                o, end = off, off + sz
                while o < end:
                    boundary = (o // 0x100000 + 1) * 0x100000      # never across a window or bank
                    n = min(CRC_CHUNK, end - o, boundary - o)
                    if o < 0x100000:
                        p1 = o
                    else:
                        bank, w = divmod(o - 0x100000, 0x100000)
                        p1 = (0x200000 + w) | (bank << 24)
                    p3 = "0" if not cmds else ("$FFFFFFFF" if p1 == nxt else "$FFFFFFFE")
                    cmds.append(f"CartCRC ${p1:X} ${n:X} {p3}")
                    nxt, o = p1 + n, o + n
        out.append((f["file"], f["crc"], size, cmds, remark))
    return out


def crc_family(lst, key):
    """Software list entries for a key: a set name (its parent and the parent's clones) or an
    NGH number as CartTest prints it (e.g. 0242: every set whose P files are named 242-...)."""
    key = key.strip().lower()
    if key in lst:
        parent = lst[key].get("cloneof") or key
        names = [n for n, sw in lst.items() if n == parent or sw.get("cloneof") == parent]
        return sorted(names, key=lambda n: (n != parent, n))
    if key.isdigit():
        pre = f"{int(key, 10):03d}-"
        return sorted(n for n, sw in lst.items() if any(
            (r[0] or "").lower().startswith(pre) for r in sw["areas"].get("maincpu", (0, []))[1]))
    raise ValueError(f"'{key}' is neither a set of the list nor an NGH number")


def format_crc_plan(lst, key, list_name="neogeo.xml"):
    """A BricoNeo console script (pasted at once: ';' lines are comments for the console too)."""
    names = crc_family(lst, key)
    if not names:
        raise ValueError(f"no set of {list_name} matches '{key}'")
    groups = {}                                     # same commands -> one block, every set's CRCs
    for n in names:
        plan = crc_plan(lst[n])
        sig = tuple((tuple(c), r) for (_, _, _, c, r) in plan)
        groups.setdefault(sig, []).append((n, plan))
    lines = [f"; CartCRC plan from the official MAME list {list_name}: '{key}' ({len(names)} set(s))",
             "; Paste the lines into the BricoNeo console (needs WRAM: run TestWRAM first).",
             "; The last 'CRC32 $' printed for each P file must be one of the values listed for it;",
             "; none: that P file reads wrong (bad chip, bad contact, or a set not in the list).",
             "; Protected carts (SMA, PVC, encrypted P) cannot match: the list has the file CRCs."]
    for g, (sig, members) in enumerate(groups.items(), 1):
        if len(groups) > 1:
            lines.append(f"; ===== layout {g} of {len(groups)}: {', '.join(m for m, _ in members)}")
        nfiles = len(members[0][1])
        for i in range(nfiles):
            file, _, size, cmds, remark = members[0][1][i]
            lines.append(f"; --- P file {i + 1} of {nfiles} ({size // 1024} KiB)")
            for m, plan in members:
                f2, crc2 = plan[i][0], plan[i][1]
                lines.append(f";   {m:<10} {f2:<14} CRC32 ${(crc2 or 'no good dump known').upper()}"
                             f"   {lst[m]['description']}")
            if remark:
                lines.append(f";   not checkable: {remark}")
            lines += cmds
    return "\n".join(lines) + "\n"


def crc_check(host, lst, key):
    """Runs the CartCRC plan of 'key' on the console behind host and compares each P file's CRC
    with the official list: report text (what the user does by hand on a real console)."""
    names = crc_family(lst, key)
    if not names:
        raise ValueError(f"no set of the list matches '{key}'")
    groups = {}
    for n in names:
        plan = crc_plan(lst[n])
        groups.setdefault(tuple((tuple(c), r) for (_, _, _, c, r) in plan), []).append((n, plan))
    out, full, unchecked = [], set(), False
    for sig, members in groups.items():
        ok_sets = {m for m, _ in members}
        for i, (cmds, remark) in enumerate(sig):
            if remark or not cmds:
                out.append(f"P file {i + 1}: not checkable ({remark or 'no command'})")
                ok_sets = set()
                continue
            crc = None
            for c in cmds:
                st, txt, _ = host.run_blocking(c)
                m = re.search(r"CRC32 \$([0-9A-F]{8})", txt)
                if st != "eot" or not m:
                    out.append(f"P file {i + 1}: not checked, '{c}' gave {st}: {txt.strip()[:120]}")
                    crc = None
                    break
                crc = m.group(1).lower()
            if crc is None:
                ok_sets, unchecked = set(), True
                continue
            hit = [m for m, plan in members if crc and plan[i][1] == crc]
            ok_sets &= set(hit)
            out.append(f"P file {i + 1}: CRC32 ${(crc or '--------').upper()} -> " +
                       (", ".join(f"{m} ({members[[x for x, _ in members].index(m)][1][i][0]})" for m in hit)
                        if hit else "no set of the list: this P file reads wrong, or the set is unknown"))
        full |= ok_sets
    out.append("=> every P file matches: " + ", ".join(sorted(full)) if full else
               "=> not checked: fix the error above first" if unchecked else
               "=> no set of the list matches all the P files")
    return "\n".join(out)


def run_crc_plan(host, script):
    """Runs a CartCRC plan on the emulator: [(command, status, CRC32 printed or None)]."""
    res = []
    for line in script.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        st, txt, _ = host.run_blocking(line)
        m = re.search(r"CRC32 \$([0-9A-F]{8})", txt)
        res.append((line, st, m.group(1) if m else None))
    return res


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
            notes.append(format_crc_plan(lst, best, "neogeo.xml" if isinstance(softlist, dict)
                                         else Path(str(softlist)).name).rstrip("\n"))
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
STROBES = ["portwel", "portweu", "romoel", "romoeu"]
# the BIOS socket has no data faults: a bad D line stops the boot, nothing to test
DATA_BITS = {0: 15, 1: 15, 2: 15, 3: 15, 4: 8, 5: -1, 6: 15}
ADDR_RANGE = {0: (1, 15), 1: (1, 13), 2: (0, 14), 3: (0, 10), 5: (1, 16), 6: (1, 19)}

FAULT_HELP = ("Fault syntax: REGION:data:BIT:0|1 (data bit stuck), REGION:addr:LINE:0|1 (address line stuck),\n"
              "wram:lane:lower|upper (WRAM chip dead), bios:float:LINE (BIOS socket line unstable).\n"
              "REGION = wram, pal, vramlo, vramhi, line, bios, cart. Bits: data 0-15 (line counter 0-8);\n"
              "address WRAM A1-A15, pal A1-A12 + 13 = bank select, vramlo 0-14, vramhi 0-10,\n"
              "bios A1-A16 (socket, 68000 -> BricoNeo; address faults only), cart A1-A19 (slot).\n"
              "Cartridge slot: cart:data:BIT:0|1, cart:addr:LINE:0|1, cart:float:BIT (D line unstable),\n"
              "cart:strobe:portwel|portweu|romoel|romoeu (strobe dead). Needs --cart test or diag.\n"
              "Example: --fault wram:data:5:1 --fault pal:addr:13:0 --fault bios:addr:15:1")


def parse_fault(spec):
    """'wram:data:5:1' -> (region, kind, bit, value). Raises ValueError with a readable reason."""
    parts = spec.strip().lower().split(":")
    if len(parts) < 3 or parts[0] not in FAULT_REGIONS or parts[1] not in FAULT_KINDS:
        raise ValueError(f"bad fault '{spec}'. " + FAULT_HELP.splitlines()[0])
    region, kind = FAULT_REGIONS[parts[0]], FAULT_KINDS[parts[1]]
    if kind == 2 and region == 6:
        if parts[1] != "strobe" or len(parts) != 3 or parts[2] not in STROBES:
            raise ValueError("cartridge strobe: cart:strobe:portwel|portweu|romoel|romoeu")
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


def neo_rgb(c):
    """Neo Geo colour word -> '#rrggbb' (MAME DAC model)."""
    d = c >> 15
    r = ((c >> 14) & 1) | ((c >> 7) & 0x1E)
    g = ((c >> 13) & 1) | ((c >> 3) & 0x1E)
    b = ((c >> 12) & 1) | ((c << 1) & 0x1E)
    L = _LEVELS[d]
    return f"#{L[r]:02x}{L[g]:02x}{L[b]:02x}"


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
    ap.add_argument("--crc-plan", metavar="GAME", help="CartCRC plan from --cart-list for a set name (its "
                    "clones too) or an NGH number: a script to paste into the BricoNeo console; with --cart, "
                    "also run on the emulator and checked")
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
    crc_lst = crc_script = None
    if a.crc_plan:
        if not a.cart_list:
            print("ERROR: --crc-plan needs the official MAME list: --cart-list hash/neogeo.xml")
            return 2
        try:
            crc_lst = parse_softlist(a.cart_list)
            crc_script = format_crc_plan(crc_lst, a.crc_plan, Path(a.cart_list).name)
        except (OSError, ValueError, SyntaxError) as e:        # ET.ParseError is a SyntaxError
            print(f"ERROR: CRC plan: {e}")
            return 2
        if a.cart == "none":
            print(crc_script, end="")                            # for a real console: no ROM needed
            return 0
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
    if crc_script:
        print(crc_script, end="")
        print("; --- run on the emulator, cartridge above:")
        print(crc_check(host, crc_lst, a.crc_plan))
        return 0
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
    return 0


# ---------------------------------------------------------------------------
# Diagnostic catalogue: how the tests are grouped, run and judged
# ---------------------------------------------------------------------------
CATEGORIES = [
    ("Overview", ["ChipCheck", "TestBus"]),
    ("Memory", ["TestWRAM", "TestBRAM", "TestPRAM"]),
    ("Video", ["TestVRAM", "TestLSPC", "TestTiming", "TestDAC"]),
    ("Sound", ["TestZ80", "TestAudio", "PlayEyeSnd"]),
    ("Inputs and system", ["TestInp", "TestStatusA", "TestSystype", "TestWatchdog"]),
    ("Cartridge", ["CartTest"]),
    ("Tools", ["Version", "Echo", "Read", "Write", "WriteB", "Dump", "Color", "CartCRC"]),
]
TOOLS = set(CATEGORIES[-1][1])
CHK_PROGRESS, CHK_PROG_MAGIC = 0x10FFF0, 0x10FFF2   # ChipCheck progress word and its magic ($C4EC)
# what the emulator cannot judge by itself
LOOK = {"TestDAC": "Look at the screen: 16 bands, one colour bit each (a black band = dead bit).",
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
               ("BIOS socket (68000 -> BricoNeo)", "bios"), ("Cartridge slot (P bus)", "cart")]
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
        "checks every chip and gives the CartCRC plan for each P file.")).grid(row=8, column=0, columnspan=4, sticky="we", pady=(4, 8))
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
        "and sound, sprites, fix layer, memory card, protected cartridges (SMA, PVC, CMC). Cartridge: P1/P2 "
        "(P2 banks) or the PROG board SRAM on the 68000 bus; S, C, V, M1 are only loaded and checked.\n"
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
        if name in ("TestZ80", "TestAudio", "ChipCheck") and s in ("FAIL", "WARN") and z80_var.get().startswith("No") \
                and (name != "ChipCheck" or "Z80" in v):
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
        if k.startswith("Strobe"):
            bit_lbl.configure(text="Signal"); sp_bit.grid_remove(); lvl_lbl.configure(text="Strobe")
            cb_lvl.configure(values=[s.upper() for s in STROBES])
            if lvl_var.get().lower() not in STROBES:
                lvl_var.set("ROMOEU")
            range_var.set("Never asserted: its byte is not written (PORTWE) or floats high (ROMOE). Needs a cartridge."); return
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
        if k.startswith("Chip"):
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

    def draw():
        lines = st["core"].lines(); cols = st["colours"]
        for y, c in enumerate(lines):
            if cols[y] != c:
                cols[y] = c; fill = neo_rgb(c)
                for cv, _, rects in st["screens"]:
                    cv.itemconfigure(rects[y], fill=fill)

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
# + neocore.c (Neo Geo AES model + host), built with zig 0.17.0 -O2:
# Windows x86_64-windows-gnu DLL, Linux x86_64-linux-gnu.2.17 shared library.
# Format: platform -> (file name, sha256, lzma data in base64).
# ===========================================================================
EMBEDDED_CORES = {
    'windows-x86_64': ('neocore.dll', '0700601c7f7a037ba6ce889e99ed40037848229694db96dee670e710b65aff8c',
        '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'),
    'linux-x86_64': ('libneocore.so', '447a4738f3a741686a7cd23e80bd4a828aca453c41f58574da36a1c6a1110e09',
        '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'),
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
