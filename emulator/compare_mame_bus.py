"""TestBus (BIOS socket address lines) in the emulator core and in MAME, same fault injected:
compares the 16 screen bands (A1 at the top) and the command status.
Needs MAME, BRICO_SOUND_ROM (your 000-lo.lo) and a built core (emulator/build_core.py).
Usage: BRICO_SOUND_ROM=000-lo.lo python3 emulator/compare_mame_bus.py rom/Brico68k.bin
"""
import sys, os, glob, tempfile
HERE = __import__('pathlib').Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent / 'tools'))
from emu_host import *
import mame_bench
from PIL import Image

R = sys.argv[1]
rom = open(R, 'rb').read()
# emulator spec, MAME BRICO_SOCKET; single and double stuck lines (unstable lines: emulator only)
CASES = [("", ""), ("bios:addr:15:1", "15,1"), ("bios:addr:15:0", "15,0"), ("bios:addr:16:0", "16,0"),
         ("bios:addr:16:1", "16,1"), ("bios:addr:15:1+bios:addr:16:1", "15,1;16,1"),
         ("bios:addr:15:0+bios:addr:16:1", "15,0;16,1")]
COL = {0x20F0: 'G', 0x0060: 'g', 0x4F00: 'R', 0x108F: 'B', 0x4F80: 'O', 0x6FF0: 'Y', 0x0888: '.'}


def emu_bands(spec):
    c = Core(os.environ.get('CORE', str(HERE / 'build' / 'libneocore_zig.so'))); c.load(rom)
    c.lib.neo_set_options(0, 1)
    apply_faults(c, [parse_fault(f) for f in spec.split('+') if f]); c.power_on()
    for _ in range(60):
        c.lib.neo_run_frame()
    st, _, _ = Host(c, rom).run_blocking('TestBus', 200)
    for _ in range(20):
        c.lib.neo_run_frame()
    L = c.lines()
    return st, ''.join(COL.get(L[14 * j + 7], '?') for j in range(16))


def pix(c):
    r, g, b = c
    if g > 200 and r < 60 and b < 60: return 'G'
    if g > 60 and r < 40 and b < 40: return 'g'
    if r > 200 and g < 60: return 'R'
    if b > 200 and r < 60: return 'B'
    if r > 200 and 100 < g < 170: return 'O'
    if r > 200 and g > 200 and b < 60: return 'Y'
    return '?'


def mame_bands(sock):
    with tempfile.TemporaryDirectory() as d:
        old = dict(os.environ)
        os.environ.update(BRICO_SOCKET=sock, BRICO_SNAP="1", BRICO_SNAP_DIR=d, BRICO_SNAP_FRAMES="20")
        try:
            res, _ = mame_bench.run(R, ['TestBus'], maxframes=200)
        finally:
            os.environ.clear(); os.environ.update(old)
        st = [r['status'] for r in res if 'name' in r][0]
        im = Image.open(glob.glob(d + '/**/*.png', recursive=True)[0]).convert('RGB')
        return st, ''.join(pix(im.getpixel((im.size[0] // 2, 14 * j + 7))) for j in range(16))


ok = 0
for spec, sock in CASES:
    e, m = emu_bands(spec), mame_bands(sock)
    same = e == m and (e[0] == 'eot') == (m[0] == 'eot'); ok += same
    print(f"{'SAME' if same else 'DIFF'}  {spec or 'healthy':32} emu {e[0]:7} {e[1]}   mame {m[0]:7} {m[1]}")
print(f"{ok}/{len(CASES)} identical to MAME (bands A1..A16: G/g OK, R reads 0, B reads 1, O unstable, Y CRC error)")
