"""Compares the emulator core with the MAME bench, word for word.
Needs MAME, BRICO_SOUND_ROM (your 000-lo.lo) and a built core (emulator/build_core.py).
Usage: BRICO_SOUND_ROM=000-lo.lo python3 emulator/compare_mame_faults.py rom/Brico68k.bin
"""
import sys, os
HERE = __import__('pathlib').Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'tools'))
from emu_host import *
import mame_bench
R = sys.argv[1]
rom = open(R, 'rb').read()
CASES = [
  ("wram:data:5:1",   {"BRICO_STUCK": "0x100000,0x10ffff,0x0020,0xFFFF"}, ["TestWRAM"]),
  ("wram:data:12:0",  {"BRICO_STUCK": "0x100000,0x10ffff,0,0xEFFF"},     ["TestWRAM"]),
  ("wram:lane:upper", {"BRICO_STUCK": "0x100000,0x10ffff,0xFF00,0xFFFF"}, ["TestWRAM"]),
  ("wram:addr:7:0",   {"BRICO_ALIAS": "0x100000,0x10ffff,0xFFFF7F"},    ["TestWRAM"]),
  ("wram:addr:12:0",  {"BRICO_ALIAS": "0x100000,0x10ffff,0xFFEFFF"},    ["TestWRAM"]),
  ("pal:data:3:0",    {"BRICO_STUCK": "0x400000,0x401fff,0,0xFFF7"},    ["TestPRAM"]),
  ("pal:data:15:1",   {"BRICO_STUCK": "0x400000,0x401fff,0x8000,0xFFFF"},["TestPRAM"]),
  ("pal:addr:6:0",    {"BRICO_ALIAS": "0x400000,0x401fff,0xFFFFBF"},    ["TestPRAM"]),
  ("line:data:3:1",   {"BRICO_STUCK": "0x3c0006,0x3c0007,0x0400,0xFFFF"},["TestTiming"]),
  ("line:data:0:0",   {"BRICO_STUCK": "0x3c0006,0x3c0007,0,0xFF7F"},    ["TestTiming"]),
]
VRAM = [("vramlo:data:2:1", "vramhi:data:2:1", {"BRICO_STUCK": "0x3c0002,0x3c0003,0x0004,0xFFFF"},
         ["TestVRAML", "TestVRAMU", "MarchVRAML", "MarchVRAMU", "TestLSPC"])]
def emu_run(faults, jobs):
    c = Core(os.environ.get('CORE', str(HERE / 'build' / 'libneocore_zig.so'))); c.load(rom); c.power_on(); c.lib.neo_set_options(0, 0)
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
ok = tot = 0
for spec, env, jobs in CASES + [((a, b), e, j) for a, b, e, j in VRAM]:
    faults = list(spec) if isinstance(spec, tuple) else [spec]
    e = emu_run(faults, jobs); m = mame_run(env, jobs)
    for j, (es, ev), (ms, mv) in zip(jobs, e, m):
        tot += 1; same = es == ms and ev == mv; ok += same
        txt = ''.join(chr(x) for x in ev if x == 10 or 32 <= x < 127)
        verdict = [l for l in txt.splitlines() if l.startswith('=>')]
        print(f"{'SAME' if same else 'DIFF'}  {'+'.join(faults):34} {j:11} -> {verdict[-1] if verdict else txt[-60:]!r}")
print(f"{ok}/{tot} identical to MAME with the same injected fault")
