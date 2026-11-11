#!/usr/bin/env python3
"""make_test_cart.py - synthetic Neo Geo cartridge for the MAME bench.

MAME only loads Neo Geo cartridges through a software list, so this writes:
  <out>/hash/neogeo.xml           one software entry, "brtest"
  <out>/roms/neogeo/brtest/*      the ROM files (MAME naming and byte order)
Content (all generated, nothing copyrighted):
  P ROM 3 MB: P1 1 MB + P2 2 MB (2 banks), pseudo-random words, fixed seed,
              game header and security code (CartTest).
  S1 128 KB : fix tiles, tile $20 blank, other tiles striped.
  M1 64 KB  : the emulator's built-in test M1 (emulator/neo_py.py TEST_M1_PARTS): $03 = silence
               + reset (reply $00), $01 = reply $01, $5C/$5D/$5E = SSG beeps, $02 = a jingle.
  V1, C1/C2 : blank.
Usage: python3 tools/make_test_cart.py OUTDIR      then mame_bench.py with
       BRICO_CART=OUTDIR (adds -hashpath / -cart brtest).
"""
import hashlib
import random
import sys
import zlib
from pathlib import Path

NAME = "brtest"



# Security code: 61 words (neogeodev wiki "Security code"; word 25 is $6606 as in
# the system ROM, the wiki listing says $0606). Same as the emulator (emu_host.py).
SECURITY_CODE = [
    0x7600, 0x4A6D, 0x0A14, 0x6600, 0x003C, 0x206D, 0x0A04, 0x3E2D, 0x0A08, 0x13C0,
    0x0030, 0x0001, 0x3210, 0x0C01, 0x00FF, 0x671A, 0x3028, 0x0002, 0xB02D, 0x0ACE,
    0x6610, 0x3028, 0x0004, 0xB02D, 0x0ACF, 0x6606, 0xB22D, 0x0AD0, 0x6708, 0x5088,
    0x51CF, 0xFFD4, 0x3607, 0x4E75, 0x206D, 0x0A04, 0x3E2D, 0x0A08, 0x3210, 0xE049,
    0x0C01, 0x00FF, 0x671A, 0x3010, 0xB02D, 0x0ACE, 0x6612, 0x3028, 0x0002, 0xE048,
    0xB02D, 0x0ACF, 0x6606, 0xB22D, 0x0AD0, 0x6708, 0x5888, 0x51CF, 0xFFD8, 0x3607,
    0x4E75]
SEC_AT = 0x186


def p_rom():
    """3 MB of P ROM in 68000 (big-endian) order: pseudo-random words (fixed seed) and a
    game header: "NEO-GEO", NGH $0999, P ROM size $300000, security code pointer
    $182 -> $186 (wiki "68k program header"). CartTest reads it."""
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
    p[0x182:0x186] = SEC_AT.to_bytes(4, "big")
    for i, w in enumerate(SECURITY_CODE):
        p[SEC_AT + 2 * i:SEC_AT + 2 * i + 2] = w.to_bytes(2, "big")
    return bytes(p)


def word_swap(data):
    return bytes(b for i in range(0, len(data), 2) for b in (data[i + 1], data[i]))


def tile_roms():
    """S1, C1, C2: the tiles of the emulator's built-in test cartridge (a 5 x 7 font at the ASCII
    codes, numbered sprite tiles with an F), so TestGfx shows the same picture in MAME."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "emulator"))
    from emu_host import test_cart_tile_roms
    return test_cart_tile_roms(0x20000 // 32, 0x100000 // 128)


def m_rom():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "emulator"))
    from neo_py import TEST_M1_PARTS          # the Z80 program of the emulator (listing there)
    m = bytearray(b"\xff" * 0x10000)
    for a, b in TEST_M1_PARTS:
        m[a:a + len(b)] = b
    return bytes(m)


def rom_xml(name, data, offset, extra=""):
    crc = f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"
    sha = hashlib.sha1(data).hexdigest()
    return (f'\t\t\t\t<rom {extra}name="{name}" offset="0x{offset:06x}" size="0x{len(data):06x}" '
            f'crc="{crc}" sha1="{sha}" />\n')


def build(out):
    out = Path(out)
    rd = out / "roms" / "neogeo" / NAME
    rd.mkdir(parents=True, exist_ok=True)
    (out / "hash").mkdir(parents=True, exist_ok=True)
    p = p_rom()
    s1, c1, c2 = tile_roms()
    files = {
        "brt-p1.p1": word_swap(p[:0x100000]),
        "brt-p2.p2": word_swap(p[0x100000:]),
        "brt-s1.s1": s1,
        "brt-m1.m1": m_rom(),
        "brt-v1.v1": bytes(0x80000),
        "brt-c1.c1": c1,
        "brt-c2.c2": c2,
    }
    for n, d in files.items():
        (rd / n).write_bytes(d)
    sw = 'loadflag="load16_word_swap" '
    xml = ('<?xml version="1.0"?>\n<!DOCTYPE softwarelist SYSTEM "softwarelist.dtd">\n'
           '<softwarelist name="neogeo" description="Brico68k bench test cartridge">\n'
           f'\t<software name="{NAME}">\n\t\t<description>Brico68k bench test cartridge</description>\n'
           '\t\t<year>2026</year>\n\t\t<publisher>Brico68k bench</publisher>\n'
           '\t\t<part name="cart" interface="neo_cart">\n'
           # without it MAME 0.264 maps $000100-$000103 to a protection handler (reads $FFFF)
           '\t\t\t<feature name="slot" value="rom" />\n'
           '\t\t\t<dataarea name="maincpu" width="16" endianness="big" size="0x300000">\n'
           + rom_xml("brt-p1.p1", files["brt-p1.p1"], 0, sw) + rom_xml("brt-p2.p2", files["brt-p2.p2"], 0x100000, sw) +
           '\t\t\t</dataarea>\n\t\t\t<dataarea name="fixed" size="0x040000">\n'
           + rom_xml("brt-s1.s1", files["brt-s1.s1"], 0) +
           '\t\t\t</dataarea>\n\t\t\t<dataarea name="audiocpu" size="0x020000">\n'
           + rom_xml("brt-m1.m1", files["brt-m1.m1"], 0) +
           '\t\t\t</dataarea>\n\t\t\t<dataarea name="ymsnd:adpcma" size="0x080000">\n'
           + rom_xml("brt-v1.v1", files["brt-v1.v1"], 0) +
           '\t\t\t</dataarea>\n\t\t\t<dataarea name="sprites" size="0x100000">\n'
           + rom_xml("brt-c1.c1", files["brt-c1.c1"], 0, 'loadflag="load16_byte" ')
           + rom_xml("brt-c2.c2", files["brt-c2.c2"], 1, 'loadflag="load16_byte" ') +
           '\t\t\t</dataarea>\n\t\t</part>\n\t</software>\n</softwarelist>\n')
    (out / "hash" / "neogeo.xml").write_text(xml)
    return p


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    build(sys.argv[1])
    print(f"test cartridge '{NAME}' written to {sys.argv[1]}")
