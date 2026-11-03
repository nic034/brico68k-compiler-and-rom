#!/usr/bin/env python3
"""make_test_cart.py - synthetic Neo Geo cartridge for the MAME bench.

MAME only loads Neo Geo cartridges through a software list, so this writes:
  <out>/hash/neogeo.xml           one software entry, "brtest"
  <out>/roms/neogeo/brtest/*      the ROM files (MAME naming and byte order)
Content (all generated, nothing copyrighted):
  P ROM 3 MB: P1 1 MB + P2 2 MB (2 banks), pseudo-random words, fixed seed.
  S1 128 KB : fix tiles, tile $20 blank, other tiles striped.
  M1 64 KB  : tiny Z80 service: $03 = reset (reply $00), $01 = reply $01.
               No YM2610 code: lets TestZ80 / the TestAudio handshake run on AES.
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

# Z80 service (same bytes as bricobanc engines/z80_reference_service.asm):
#   di / ld sp,$ffff / xor a / out ($0c),a / out ($08),a (NMI on) / ei / jp idle
#   NMI ($66): in a,($00) / cp 3 / jp z,0 / cp 1 / jp nz,done / ld a,1 / out ($0c),a / retn
Z80_BOOT = bytes.fromhex("f331ffffafd30cd308fbc30a00")
Z80_NMI = bytes.fromhex("db00fe03ca0000fe01c276003e01d30ced45")


def p_rom():
    """3 MB of P ROM in 68000 (big-endian) order."""
    rnd = random.Random(0xB1C068)
    return bytes(rnd.getrandbits(8) for _ in range(3 * 0x100000))


def word_swap(data):
    return bytes(b for i in range(0, len(data), 2) for b in (data[i + 1], data[i]))


def s_rom():
    s = bytearray(0x20000)
    for tile in range(len(s) // 32):
        if tile == 0x20:
            continue  # blank (space)
        for i in range(32):
            s[tile * 32 + i] = 0xF0 if (i // 4) % 2 else 0x0F
    return bytes(s)


def m_rom():
    m = bytearray(b"\xff" * 0x10000)
    m[:len(Z80_BOOT)] = Z80_BOOT
    m[0x66:0x66 + len(Z80_NMI)] = Z80_NMI
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
    files = {
        "brt-p1.p1": word_swap(p[:0x100000]),
        "brt-p2.p2": word_swap(p[0x100000:]),
        "brt-s1.s1": s_rom(),
        "brt-m1.m1": m_rom(),
        "brt-v1.v1": bytes(0x80000),
        "brt-c1.c1": bytes(0x80000),
        "brt-c2.c2": bytes(0x80000),
    }
    for n, d in files.items():
        (rd / n).write_bytes(d)
    sw = 'loadflag="load16_word_swap" '
    xml = ('<?xml version="1.0"?>\n<!DOCTYPE softwarelist SYSTEM "softwarelist.dtd">\n'
           '<softwarelist name="neogeo" description="Brico68k bench test cartridge">\n'
           f'\t<software name="{NAME}">\n\t\t<description>Brico68k bench test cartridge</description>\n'
           '\t\t<year>2026</year>\n\t\t<publisher>Brico68k bench</publisher>\n'
           '\t\t<part name="cart" interface="neo_cart">\n'
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
