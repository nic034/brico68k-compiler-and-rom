"""TestGfx in MAME against the emulator's drawing, pixel by pixel (320 x 224, three screens).
Usage: python3 emulator/compare_mame_gfx.py rom/ROM.BIO WORKDIR      (needs MAME and Pillow)
The cartridge is tools/make_test_cart.py's: the same generated tiles as the emulator's test cartridge.
L0 ROM: a table generated here with the emulator's approximation (source line = window line *
256 / (shrink + 1)); the real one is SNK's. So the V shrink zone is equal by construction: this
checks everything else against MAME's own sprite and fix code (positions, flips, H shrink,
palettes, priorities, fix map). With BRICO_SOUND_ROM = your 000-lo.lo, MAME uses the real table
and the V shrink zone shows how far the approximation is."""
import sys, os
from pathlib import Path
R = Path(__file__).resolve().parent.parent; S = Path(sys.argv[2]); S.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(R / "emulator")); sys.path.insert(0, str(R / "tools"))
import make_test_cart
make_test_cart.build(S / "cartdir")
lo = bytearray(0x20000)
for zy in range(256):
    for line in range(256):
        lo[zy * 256 + line] = min(255, line * 256 // (zy + 1))
lo[0x10000:] = lo[:0x10000]
(S / "gen-lo.lo").write_bytes(lo)
os.environ.setdefault("BRICO_SOUND_ROM", str(S / "gen-lo.lo"))
os.environ.update(BRICO_CART=str(S / "cartdir"),
                  BRICO_SNAP="1,2,3", BRICO_SNAP_DIR=str(S / "snap"))
import mame_bench
from PIL import Image
JOBS = ["TestGfx:0x100", "TestGfx:0x1F00:1", "TestGfx:0x0FFE"]
rom = sys.argv[1]
res, p = mame_bench.run(rom, JOBS)
print([r.get("status") for r in res if "name" in r])
snaps = sorted((S / "snap").rglob("*.png"), key=lambda f: f.stat().st_mtime)
print([f.name for f in snaps])
import importlib.util
spec = importlib.util.spec_from_file_location("e", str(R / "Brico68k_Emulator.py")); E = importlib.util.module_from_spec(spec); spec.loader.exec_module(E)
data = open(rom, "rb").read()
c = E.Core(E.core_path()); c.load(data); c.load_cart(E.make_cart("test")); c.power_on(); c.lib.neo_set_options(1, 0)
for _ in range(60): c.lib.neo_run_frame()
h = E.Host(c, data)
total = 0
for job, f in zip(JOBS, snaps[-3:]):
    h.run_blocking(job.replace(":", " "))
    for _ in range(4): c.lib.neo_run_frame()
    mine = [[E.neo_rgb3(w) for w in row] for row in c.screen()]
    im = Image.open(f).convert("RGB")
    W, H = im.size
    px = im.load()
    bad = [(x, y) for y in range(min(H, 224)) for x in range(min(W, 320)) if px[x, y] != mine[y][x]]
    total += len(bad)
    print(f"{job}: MAME snapshot {W}x{H}, {len(bad)} of {W*H} pixels differ", bad[:6],
          [(px[x, y], mine[y][x]) for x, y in bad[:3]])
    E.write_png(str(S / ("emu_" + f.name)), mine, 1)
print("identical to MAME" if not total else f"{total} pixel(s) differ: pictures in {S}")
sys.exit(1 if total else 0)
