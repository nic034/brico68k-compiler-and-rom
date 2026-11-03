#!/usr/bin/env python3
"""cart_checksum.py - same checksum as the TestCart extension, from a dump.

TestCart (P1=0) reads $000000-$0FFFFF as 68000 words (big-endian) and gives
  s1 = sum of the words, s2 = sum of the successive s1, both mod 2^32.
A ROM smaller than 1 MB is mirrored by the cartridge, so it is repeated here
to fill 1 MB, as the 68000 sees it (full address decoding assumed).

Byte order: MAME P ROM files (.p1/.p2, loaded "load16_word_swap") and most
EPROM programmer reads of a 16-bit ROM store the LOW byte first: that is the
default here. Use --big-endian for a file already in 68000 order.
Some 2 MB "p1" files hold the two halves swapped (MAME ROM_CONTINUE): the
checksum of every 1 MB slice is printed, so pick the one that matches.

Usage:  python cart_checksum.py 201-p1.p1 [--big-endian]
        TestCart P1=1 (P2 window) bank n = slice n+1 of the full P ROM.
"""
import argparse
import sys
from pathlib import Path

WINDOW = 0x100000  # 1 MB seen by the 68000 at $000000 or $200000


def words(data, big_endian):
    if len(data) % 2:
        data += b"\xff"
    if not big_endian:
        data = bytes(b for i in range(0, len(data), 2) for b in (data[i + 1], data[i]))
    return data


def checksum(window):
    """window: 1 MB in 68000 (big-endian) byte order. Returns (s1, s2)."""
    s1 = s2 = 0
    mv = memoryview(window)
    for i in range(0, len(window), 2):
        s1 = (s1 + (mv[i] << 8 | mv[i + 1])) & 0xFFFFFFFF
        s2 = (s2 + s1) & 0xFFFFFFFF
    return s1, s2


def mirrored(data):
    """Repeat a ROM smaller than 1 MB to fill the 1 MB window."""
    if not data:
        raise ValueError("empty file")
    reps = -(-WINDOW // len(data))
    return (data * reps)[:WINDOW]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dump")
    ap.add_argument("--big-endian", action="store_true", help="file already in 68000 byte order")
    a = ap.parse_args(argv)
    data = words(Path(a.dump).read_bytes(), a.big_endian)
    print(f"{a.dump}: {len(data)} bytes, {'big' if a.big_endian else 'little'}-endian words")
    slices = [data[i:i + WINDOW] for i in range(0, len(data), WINDOW)] or [b""]
    for n, sl in enumerate(slices):
        s1, s2 = checksum(mirrored(sl))
        note = " (mirrored to 1 MB)" if len(sl) < WINDOW else ""
        print(f"  slice {n} (+{n * WINDOW:#08x}): s1=${s1:08X} s2=${s2:08X}{note}")
    print("TestCart P1=0 must match slice 0 (or slice 1 for a 2 MB p1 stored swapped).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
