"""ROM regression check on the Brico68k Emulator core: does a source change keep every output?

  python3 emulator/regress_rom.py run ROM OUT.json [JOBS]    record every scenario
  python3 emulator/regress_rom.py compare OLD.json NEW.json   list what differs

"run" records, for every scenario (no cartridge / test cartridge / PROG board, watchdog on
or off, each single fault the core models, each cartridge slot fault) and every command:
status, the raw output words, emulated time, Z80 commands, cartridge writes, and the 224
backdrop lines after the screen commands (TestDAC). About 1 minute on 2 cores.
CORE=python runs the built-in Python core (the default when no C core is next to
Brico68k_Emulator.py). With CORE=python or CORE=emulator/build/libneocore_test.so
(emulator/build_test_core.py) it also runs
10 input sets (joypads, DIP, STATUS_A/B, SYSTYPE, MVS with a backup RAM): the stock core is
an AES with nothing pressed, so it never reaches the MVS / button / memory card branches.
After TestGfx it records a checksum of the VRAM and palette words and of the picture drawn from
them; the vector table switch held on either side is one of the faults (vec:stuck:bios / cart).

"compare" must print 0 differences for a change that is meant to keep the outputs. Apart:
- unstable cartridge lines (cart:float): random per access, status only;
- chaotic by construction, counted but not differences: BIOS socket A1-A14 stuck or any
  socket line unstable (the 68000 reads its own code wrong), and with a WRAM fault every
  command from TestAudio on (its stack is in the bad WRAM). What happens there depends on
  where each byte of the code is;
- Dump / Read of the ROM itself, and the TestWatchdog loop count (a few loops: it depends on
  the cycles spent before the starve loop), shown as MEASURED.
"""
import sys, os, json, re, zlib, ctypes, difflib, importlib.util
from collections import defaultdict
from multiprocessing import Pool
from pathlib import Path

EMU = str(Path(__file__).resolve().parent.parent / "Brico68k_Emulator.py")
spec = importlib.util.spec_from_file_location("bemu", EMU)
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

HEALTHY = ["Echo $1234", "Read $320001", "Read $380000", "Read $300000", "Read $C00080",
           "Write $5A $100001", "Write $1234 $100000", "WriteB $A5 $100000", "Read $100000",
           "Dump $100000 8", "Dump $100001 4", "Dump $C00000 3000",
           "TestInp", "TestWRAM", "TestBRAM", "TestPRAM", "TestVRAM", "TestLSPC", "Color $7FFF",
           "TestStatusA", "TestSystype", "TestZ80", "TestTiming", "TestChip",
           "TestDAC", "Echo $77", "TestDAC 1", "Echo $78", "TestDAC $10", "TestDAC $17", "TestDAC $1F",
           "TestDAC $30", "TestDAC $35", "TestDAC 5", "Echo $79",
           "Echo $66", "Echo $67", "@0xC00001", "Echo $55", "@0xC00000", "Echo $56",
           "TestFM", "TestSsg", "TestAudio", "Echo $88",
           "TestWatchdog", "Echo $99", "TestWatchdog", "Echo $9A", "TestWatchdog", "TestWatchdog",
           "Dump $C00000 16", "Read $400000", "Dump $100 8", "TestWRAM",
           "TestVectors", "TestGfx", "Echo $31", "TestGfx $12345", "TestDAC $15", "TestVectors",
           "TestGfx $12345 1", "TestGfx 0 1", "TestDAC $12",
           "Version", "TestBus", "Echo $5C", "CartTest", "CartTest 1", "Echo $5D"]   # back in -16: appended, older recordings still line up
SCREEN = {"testdac"}
DECODE = ["TestDecode", "Echo $5B"]       # last in every scenario that has it: older recordings still line up


def run_cmd(c, h, line):
    rec = {"cmd": line}
    z0, w0, l0 = c.lib.neo_z80_commands(), c.lib.neo_cart_writes(), c.lib.neo_cart_latch_writes()
    if line.startswith("@"):
        c.lib.neo_host_send(int(line[1:], 16), 0, 0, 0)
    else:
        err = h.start(line)
        if err:
            rec["status"] = "error:" + err
            return rec
    st = "stuck"
    vals = []
    for f in range(400):
        c.lib.neo_run_frame()
        s = c.lib.neo_host_state()
        if s == E.H_DONE:
            n = c.lib.neo_host_values(c._vals, 2048)
            vals = list(c._vals[:n])
            st = "eot"
            break
        if s == E.H_TIMEOUT:
            st = "timeout"
            break
    rec["secs"] = round(c.lib.neo_host_cycles() / E.CPU_HZ, 4)
    c.lib.neo_host_ack()
    h.pending = None
    rec["status"] = st
    rec["words"] = vals
    rec["text"] = "".join(chr(v) if v == 10 or 32 <= v < 127 else f"<{v:04X}>" for v in vals)
    rec["overflow"] = int(c.lib.neo_host_overflow())
    if line.split()[0].lower() == "testgfx" and st == "eot":
        c.layer_state()                                # what the screen is made of: VRAM and palette words
        buf, pal = c._vram, list(c._pal[:32]) + [c._pal[4095]]
        rec["gfx"] = zlib.crc32(bytes(str((list(buf[0x0000:0x0900]), list(buf[0x7000:0x7500]),
                                           list(buf[0x8000:0x8600]), pal)), "ascii"))
        rows = c.layers()                              # and the picture drawn from them
        rec["pixels"] = zlib.crc32(bytes(str(rows), "ascii"))
    if line.split()[0].lower() in SCREEN and st == "eot":
        for _ in range(4):
            c.lib.neo_run_frame()
        rec["lines"] = c.lines()
    rec["z80"] = c.lib.neo_z80_commands() - z0
    rec["cartw"] = c.lib.neo_cart_writes() - w0
    rec["latchw"] = c.lib.neo_cart_latch_writes() - l0
    # let a still running test (TestAudio beeps, watchdog starve) finish as the console would
    for _ in range(30):
        c.lib.neo_run_frame()
    return rec


CORE = os.environ.get("CORE")       # test-only core with settable inputs (core/libneocore_test.so), or "python"


def scenario(args):
    name, rom_path, cart, wd, faults, cmds = args[:6]
    rom = open(rom_path, "rb").read()
    c = E.Core(None if CORE == "python" else (CORE or E.core_path()))
    if len(args) > 6:
        c.lib.neo_test_inputs(*args[6])
    c.load(rom)
    c.load_cart(E.make_cart(cart))
    c.lib.neo_fault_clear()        # the core keeps its faults across power cycles; workers are reused
    c.power_on()
    c.lib.neo_set_options(1, wd)
    E.apply_faults(c, [E.parse_fault(f) for f in faults])
    for _ in range(60):
        c.lib.neo_run_frame()
    h = E.Host(c, rom)
    out = []
    for line in cmds:
        out.append(run_cmd(c, h, line))
    return name, out


def scenarios(rom):
    sc = []
    for cart in ("none", "test", "diag"):
        sc.append((f"healthy/{cart}", rom, cart, 1, [], HEALTHY + (["CartDiag", "TestWRAM", "CartDiag"] if cart == "diag" else [])
                   + DECODE))
    sc.append(("healthy/none/nowd", rom, "none", 0, [], ["TestWatchdog", "Echo 1", "TestWatchdog", "TestChip"]))
    sc.append(("healthy/test/z80none", rom, "test", 1, [], ["TestZ80", "TestChip", "TestAudio", "Echo 2"]))
    tests = {"wram": ["TestWRAM", "TestChip", "TestAudio", "Echo 3", "TestWatchdog", "TestWatchdog"] + DECODE,
             "pal": ["TestPRAM", "TestChip", "TestDAC", "Echo 3"] + DECODE,
             "lspc": ["TestLSPC", "TestChip", "Echo 3"] + DECODE,
             "vramlo": ["TestVRAM", "TestChip", "TestLSPC"], "vramhi": ["TestVRAM", "TestChip", "TestLSPC"],
             "line": ["TestTiming", "TestChip", "TestDAC", "Echo 4", "TestBus", "Echo 5"],
             "bios": ["TestBus", "Echo 6", "Version", "Dump $C07FF0 16"],
             "vec": ["TestVectors", "Echo $41", "TestVectors", "TestChip"]}
    for f in E.all_single_faults():
        spec_ = E.fault_spec(f)
        reg = spec_.split(":")[0]
        sc.append((f"fault/{spec_}", rom, "none", 1, [spec_], tests[reg]))
    for b in range(1, 17):
        sc.append((f"fault/bios:float:{b}", rom, "none", 1, [f"bios:float:{b}"], tests["bios"]))
    cart_faults = ([f"cart:data:{b}:{v}" for b in range(16) for v in (0, 1)] +
                   [f"cart:addr:{b}:{v}" for b in range(1, 20) for v in (0, 1)] +
                   [f"cart:float:{b}" for b in range(16)] +
                   [f"cart:strobe:{s}" for s in ("portwel", "portweu", "romoel", "romoeu", "portoel", "portoeu")] +
                   [f"cart:strobe:{s}245" for s in ("romoel", "romoeu", "portoel", "portoeu")])
    for cart in ("test", "diag"):                       # vector table switch held, with a cartridge
        for side in ("bios", "cart"):
            sc.append((f"fault/{cart}/vec:stuck:{side}", rom, cart, 1, [f"vec:stuck:{side}"],
                       ["TestVectors", "Echo $41", "TestVectors"]))
    for cf in cart_faults:
        sc.append((f"fault/diag/{cf}", rom, "diag", 1, [cf], ["CartDiag", "Echo $42"]))
        sc.append((f"fault/test/{cf}", rom, "test", 1, [cf], ["CartTest", "CartTest 1"]))
    if CORE:
        cmds = ["TestInp", "TestStatusA", "TestSystype", "TestBRAM", "TestChip", "TestWRAM"]
        # p1, dip, p2, status_a, status_b, systype word, MVS backup RAM
        for i, inp in enumerate([
                (0xFF, 0x00, 0xFF, 0x00, 0x7F, 0xFF00, 0), (0x00, 0xFF, 0x00, 0xFF, 0x0F, 0x0000, 0),
                (0xA5, 0x5A, 0x3C, 0xE7, 0xFF, 0xFFFF, 1), (0x5A, 0xA5, 0xC3, 0x18, 0x80, 0x0040, 1),
                (0xFE, 0x01, 0x7F, 0x07, 0xEA, 0x0080, 1), (0x01, 0x80, 0x80, 0x20, 0x95, 0x00C0, 1),
                (0x6E, 0x33, 0x99, 0x40, 0xC6, 0x007F, 1), (0x81, 0xCC, 0x66, 0x9F, 0x23, 0x1234, 0),
                (0x33, 0x0F, 0xF0, 0x5A, 0x41, 0x00BF, 0), (0xCC, 0xF0, 0x0F, 0xA5, 0xB9, 0x0000, 1)]):
            sc.append((f"inputs/{i}", rom, "none", 1, [], cmds, inp))
    return sc



def compare(a, b):

    MEASURED = re.compile(r"(after ~)\d+( ms \()\d+( loops)")    # TestWatchdog: depends on the print time
    diffs = 0
    chaos = defaultdict(int)
    times = defaultdict(lambda: [0.0, 0.0, 0])
    for sc in a:
        if "cart:float" in sc:          # random by design (unstable line): status only
            if [r["status"] for r in a[sc]] != [r["status"] for r in b.get(sc, [])]:
                print("DIFF status", sc); diffs += 1
            continue
        if sc not in b:
            print("MISSING scenario", sc); diffs += 1; continue
        wild = False
        for ra, rb in zip(a[sc], b[sc]):
            name = ra["cmd"].split()[0]
            # Chaotic by construction, compared apart: the 68000 runs garbage, so what it does
            # depends on where each byte of the code is. BIOS socket A1-A14 stuck or any socket
            # line unstable (the code itself is read wrong; unstable = random per access), and
            # with a bad WRAM everything from TestAudio on (its stack is in the bad WRAM).
            chaotic = (sc.startswith("fault/bios:float") or
                       (sc.startswith("fault/bios:addr:") and int(sc.split(":")[2]) <= 14))
            if sc.startswith("fault/wram") and name == "TestAudio":
                wild = True
            if chaotic or wild:
                if any(ra.get(k) != rb.get(k) for k in ("status", "words", "lines")):
                    chaos[sc] += 1
                continue
            if ra["cmd"].startswith(("Dump $C0", "Read $C0")):     # reads the ROM itself: layout changes
                continue
            keys = ("status", "words", "lines", "gfx", "pixels", "z80", "cartw", "latchw", "overflow")
            bad = [k for k in keys if ra.get(k) != rb.get(k)]
            if bad == ["words"] and MEASURED.sub("", ra.get("text", "")) == MEASURED.sub("", rb.get("text", "")):
                g = lambda r: " | ".join(l.strip() for l in r.get("text", "").splitlines() if "after ~" in l)
                print(f"MEASURED {sc} {ra['cmd']}: {g(ra)}  ->  {g(rb)}")
                bad = []
            if bad:
                diffs += 1
                print(f"DIFF {sc} :: {ra['cmd']} :: {bad}")
                if "words" in bad:
                    for l in list(difflib.unified_diff(ra.get("text", "").splitlines(), rb.get("text", "").splitlines(),
                                                       "old", "new", lineterm="", n=0))[:14]:
                        print("    " + l)
                for k in bad:
                    if k != "words":
                        print(f"    {k}: {str(ra.get(k))[:120]} -> {str(rb.get(k))[:120]}")
            if ra.get("status") == "eot" and rb.get("status") == "eot":
                t = times[name]; t[0] += ra["secs"]; t[1] += rb["secs"]; t[2] += 1
    print(f"\n{diffs} difference(s); chaotic scenarios that differ (not regressions): {len(chaos)}")
    print("\nEmulated time per command (sum over all runs, old -> new):")
    for n, (ta, tb, k) in sorted(times.items(), key=lambda x: -x[1][0]):
        if ta > 0:
            print(f"  {n:13s} {k:4d} runs  {ta*1000/k:8.1f} ms -> {tb*1000/k:8.1f} ms  ({(tb-ta)/ta*100:+.1f} %)")

    return diffs


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "run":
        rom, out = sys.argv[2], sys.argv[3]
        jobs = int(sys.argv[4]) if len(sys.argv) > 4 else os.cpu_count()
        E.core_path()
        sc = scenarios(rom)
        with Pool(jobs) as p:
            res = dict(p.map(scenario, sc, chunksize=4))
        json.dump(res, open(out, "w"))
        print(f"{len(res)} scenarios, {sum(len(v) for v in res.values())} commands -> {out}")
    elif len(sys.argv) == 4 and sys.argv[1] == "compare":
        sys.exit(1 if compare(json.load(open(sys.argv[2])), json.load(open(sys.argv[3]))) else 0)
    else:
        print(__doc__)
        sys.exit(2)
