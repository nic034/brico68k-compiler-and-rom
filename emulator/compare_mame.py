"""Compares the emulator core with the MAME bench, word for word.
Needs MAME, BRICO_SOUND_ROM (your 000-lo.lo) and a built core (emulator/build_core.py).
Usage: BRICO_SOUND_ROM=000-lo.lo python3 emulator/compare_mame.py rom/Brico68k.bin
"""
import sys, os, json
HERE = __import__('pathlib').Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'tools'))
from emu_host import *
import mame_bench
R = sys.argv[1]
JOBS = ["Echo:0x1234","Read:0x320001","Read:0x380000","Read:0x300000","Write:0x5A:0x100001","WriteB:0xA5:0x100000","Dump:0x100000:8",
        "TestInp","TestWRAM","TestBRAM","TestPRAM","TestVRAM","TestLSPC","Color:0x7FFF",
        "TestStatusA","TestSystype","TestZ80","TestTiming","ChipCheck","TestDAC","Echo:0x77","TestDAC:0x10","TestBus","Echo:0x66","@0xC00001","Echo:0x55","PlayEyeSnd","TestAudio","Echo:0x88",
        "TestWatchdog","Echo:0x99","TestWatchdog","Dump:0xC00000:16","Read:0x400000"]
res, _ = mame_bench.run(R, JOBS)
mame = [r for r in res if 'name' in r]
rom = open(R, 'rb').read()
c = Core(os.environ.get('CORE', str(HERE / 'build' / 'libneocore_zig.so'))); c.load(rom); c.power_on(); c.lib.neo_set_options(int(os.environ.get("Z80","0")), 0)
for _ in range(60): c.lib.neo_run_frame()
h = Host(c, rom)
def measured_only(a, b):
    """ChipCheck measures the 68000 clock against the host's 1 ms clear, which the MAME bench can only
    approximate (first command read after 1 ms of machine time): the last digit may differ."""
    import re
    f = lambda v: re.sub(r"~\d+\.\d (MHz|Hz)", r"~x \1", ''.join(chr(x) for x in v if x == 10 or 32 <= x < 127))
    return f(a) == f(b)
same = 0
for job, m in zip(JOBS, mame):
    if job.startswith('@'):              # raw address: here an odd one, for the 68000 exception report
        c.lib.neo_host_send(int(job[1:], 16), 0, 0, 0); h.pending = ('raw', 0, 2, '')
    else:
        err = h.start(job.replace(':', ' '))
    vals = None
    for f in range(400):
        c.lib.neo_run_frame()
        st = c.lib.neo_host_state()
        if st == H_DONE:
            n = c.lib.neo_host_values(c._vals, 2048); vals = list(c._vals[:n]); c.lib.neo_host_ack(); h.pending = None
            st = 'eot'; break
        if st == H_TIMEOUT:            # the MAME bench waits its whole 400 frames before the next job
            for _ in range(400 - f - 1): c.lib.neo_run_frame()
            c.lib.neo_host_ack(); h.pending = None; vals = []; st = 'timeout'; break
    else:
        st = 'stuck'
    mv = [int(x, 16) for x in m['hex'].split()] if m['hex'] else []
    if st == 'timeout': vals = []
    ok = (st == m['status']) and (vals == mv or measured_only(vals or [], mv))
    same += ok
    if not ok:
        print(f"DIFF {job}: emu={st} {len(vals or [])} words / mame={m['status']} {len(mv)} words")
        et = ''.join(chr(v) for v in (vals or []) if v == 10 or 32 <= v < 127); mt = m['text']
        import difflib
        for l in list(difflib.unified_diff(mt.splitlines(), et.splitlines(), 'mame', 'emu', lineterm='', n=0))[:12]: print('   ', l)
    # skip the time the host waits after a "lost" command identically
print(f"{same}/{len(JOBS)} identical to MAME")
