"""Compares the emulator core with the MAME bench, word for word.
Needs MAME, BRICO_SOUND_ROM (your 000-lo.lo) and a built core (emulator/build_core.py).
Usage: BRICO_SOUND_ROM=000-lo.lo python3 emulator/compare_mame_faults.py rom/ROM.BIO
"""
import sys, os
HERE = __import__('pathlib').Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'tools'))
from emu_host import *
import mame_bench
R = sys.argv[1]
rom = open(R, 'rb').read()
CASES = [
  ("wram:data:5:1",   {"BRICO_STUCK": "0x100000,0x10ffff,0x0020,0xFFFF"}, ["TestWRAM", "ChipCheck"]),
  ("wram:data:12:0",  {"BRICO_STUCK": "0x100000,0x10ffff,0,0xEFFF"},     ["TestWRAM", "ChipCheck"]),
  ("wram:lane:upper", {"BRICO_STUCK": "0x100000,0x10ffff,0xFF00,0xFFFF"}, ["TestWRAM", "ChipCheck"]),
  ("wram:addr:7:0",   {"BRICO_ALIAS": "0x100000,0x10ffff,0xFFFF7F"},    ["TestWRAM", "ChipCheck"]),
  ("wram:addr:12:0",  {"BRICO_ALIAS": "0x100000,0x10ffff,0xFFEFFF"},    ["TestWRAM", "ChipCheck"]),
  ("pal:data:3:0",    {"BRICO_STUCK": "0x400000,0x401fff,0,0xFFF7"},    ["TestPRAM", "ChipCheck"]),
  ("pal:data:15:1",   {"BRICO_STUCK": "0x400000,0x401fff,0x8000,0xFFFF"},["TestPRAM", "ChipCheck"]),
  # the bench's shadow store is shared by both palette banks: MAME also reports a (false) bank-select fault
  ("pal:addr:6:0",    {"BRICO_ALIAS": "0x400000,0x401fff,0xFFFFBF"},    ["TestPRAM", "ChipCheck"]),
  ("line:data:3:1",   {"BRICO_STUCK": "0x3c0006,0x3c0007,0x0400,0xFFFF"},["TestTiming", "ChipCheck"]),
  ("line:data:0:0",   {"BRICO_STUCK": "0x3c0006,0x3c0007,0,0xFF7F"},    ["TestTiming", "ChipCheck"]),
]
# cartridge slot (needs BRICO_CART = the tools/make_test_cart.py folder; the emulator inserts the
# same test cartridge). MAME's fault covers $000080-$2FFFFF (WRAM too: CartTest does not use it).
# (A slot address fault is not comparable on a game cartridge: the bench's BRICO_ALIAS is a
# shadow RAM, so the ROM would read 0 and become writable.)
CART_CASES = [
  ("cart:data:3:0",   {"BRICO_STUCK": "0x000080,0x2fffff,0,0xFFF7"},    ["CartTest"]),
  ("cart:data:12:1",  {"BRICO_STUCK": "0x000080,0x2fffff,0x1000,0xFFFF"},["CartTest"]),
] if os.environ.get("BRICO_CART") else []
# Diagnostic PROG board, no cartridge in MAME: BRICO_ALIAS's shadow RAM over $000080-$2FFFFF with
# A21 masked off is one RAM seen at $0xxxxx and $2xxxxx, written by byte lanes: the board's SRAM
# (WRAM keeps its own shadow). The emulator inserts the board with a zeroed SRAM, as the shadow.
DIAG_CASES = [
  ("diag",              {"BRICO_ALIAS": "0x000080,0x2fffff,0xDFFFFF"},  ["CartDiag", "TestWRAM", "CartDiag"]),
  ("diag+cart:addr:5:0", {"BRICO_ALIAS": "0x000080,0x2fffff,0xDFFFDF"}, ["CartDiag"]),
  ("diag+cart:addr:19:0", {"BRICO_ALIAS": "0x000080,0x2fffff,0xD7FFFF"}, ["CartDiag"]),
] if not os.environ.get("BRICO_CART") else []
VRAM = [("vramlo:data:2:1", "vramhi:data:2:1", {"BRICO_STUCK": "0x3c0002,0x3c0003,0x0004,0xFFFF"},
         ["TestVRAM", "TestLSPC", "ChipCheck"])]
def emu_run(faults, jobs):
    c = Core(os.environ.get('CORE', str(HERE / 'build' / 'libneocore_zig.so'))); c.load(rom)
    if faults and faults[0] == "diag":
        c.load_cart(CartImage("diag", bytes(0x100000))); faults = faults[1:]
    else:
        c.load_cart('test' if os.environ.get('BRICO_CART') else 'none')
    # with the test cartridge the Z80 runs its M1 (MAME does); without, no program (MAME aes, no cart)
    c.power_on(); c.lib.neo_set_options(1 if os.environ.get('BRICO_CART') else 0, 0)
    apply_faults(c, [parse_fault(f) for f in faults])
    for _ in range(60): c.lib.neo_run_frame()
    h = Host(c, rom); out = []
    for j in jobs:
        h.start(j)
        for _ in range(400):
            c.lib.neo_run_frame(); st = c.lib.neo_host_state()
            if st in (H_DONE, H_TIMEOUT): break
        n = c.lib.neo_host_values(c._vals, 2048); v = list(c._vals[:n]) if st == H_DONE else []
        c.lib.neo_host_ack(); h.pending = None
        out.append(('eot' if st == H_DONE else 'timeout', v))
    return out
def mame_run(env, jobs):
    old = dict(os.environ); os.environ.update(env)
    try:
        res, _ = mame_bench.run(R, jobs)
    finally:
        os.environ.clear(); os.environ.update(old)
    return [(r['status'], [int(x, 16) for x in r['hex'].split()] if r['hex'] else []) for r in res if 'name' in r]
def measured_only(a, b):
    """ChipCheck measures the 68000 clock against the host's 1 ms clear, which the MAME bench can only
    approximate (first command read after 1 ms of machine time): the last digit may differ."""
    import re
    f = lambda v: re.sub(r"~\d+\.\d (MHz|Hz)", r"~x \1", ''.join(chr(x) for x in v if x == 10 or 32 <= x < 127))
    return f(a) == f(b)
ok = tot = 0
for spec, env, jobs in CASES + CART_CASES + DIAG_CASES + [((a, b), e, j) for a, b, e, j in VRAM]:
    faults = list(spec) if isinstance(spec, tuple) else spec.split("+")
    e = emu_run(faults, jobs); m = mame_run(env, jobs)
    for j, (es, ev), (ms, mv) in zip(jobs, e, m):
        tot += 1; same = es == ms and (ev == mv or measured_only(ev, mv)); ok += same
        txt = ''.join(chr(x) for x in ev if x == 10 or 32 <= x < 127)
        verdict = [l for l in txt.splitlines() if l.startswith('=>')]
        print(f"{'SAME' if same else 'DIFF'}  {'+'.join(faults):34} {j:11} -> {verdict[-1] if verdict else txt[-60:]!r}")
        if not same and os.environ.get("SHOW_DIFF"):
            import difflib
            mt = ''.join(chr(x) for x in mv if x == 10 or 32 <= x < 127)
            for l in list(difflib.unified_diff(mt.splitlines(), txt.splitlines(), 'mame', 'emu', lineterm='', n=0))[2:14]:
                print('     ', l)
print(f"{ok}/{tot} identical to MAME with the same injected fault")
