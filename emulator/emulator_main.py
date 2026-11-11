#!/usr/bin/env python3
"""Brico68k Emulator - test the Brico68k ROM without a BricoNeo / Brico16Bits.

One file, pure Python, no MAME, no DLL: a Neo Geo AES model built around a
Python port of the Musashi 68000 core (same decode, cycle counts, bus access
order and exceptions as the C Musashi, checked instruction by instruction)
plus a Brico16Bits-like host. Optional: a C build of the same core
(neocore.dll / libneocore.so next to this file, or BRICO68K_CORE=path) is used
when present, for speed; the results are the same word for word. Type the same commands as on the Brico16Bits console
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
The screen shows the backdrop colour of each line, and over it the fix layer and
the sprites drawn from VRAM with the cartridge's S and C tiles (generated tiles
for the built-in test cartridge): a simple drawing for the ROM's test screens,
not a game renderer (vertical shrink approximated: no L0 ROM; no auto-animation).
NOT emulated: YM2610 and sound, Z80 ROM banking (V is not used), protected
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
Python 3.8+, standard library only: nothing to install with pip. The window
needs Tkinter, which comes with Python on Windows (python.org installer) and is
the python3-tk package on Linux distributions that split it out.
"""
import json
import os
import platform
import re
import struct
import sys
import time
from pathlib import Path

APP_NAME = "Brico68k Emulator"
APP_VERSION = "1.18"
TOOL_DIR = Path(__file__).resolve().parent
WORK_DIR = TOOL_DIR / "brico68k_emulator"
CONFIG_PATH = WORK_DIR / "config.json"
IS_WIN = os.name == "nt"
ROM_CANDIDATES = ["rom/ROM.BIO", "output/ROM.BIO", "ROM.BIO",
                  "rom/Brico68k.bin", "output/Brico68k.bin", "Brico68k.bin"]   # older builds

# @@HOST@@

# ---------------------------------------------------------------------------
# Embedded core
# ---------------------------------------------------------------------------
C_CORE_NAMES = ("neocore.dll",) if IS_WIN else ("libneocore.so", "libneocore.dylib")


def core_path():
    """The emulator core: None = the built-in Python core (the default, nothing to install);
    else the path of a C core library (neocore.c, built by emulator/build_core.py) that is
    faster: put neocore.dll (Windows) or libneocore.so (Linux) next to this script, or give
    its path in the BRICO68K_CORE environment variable (BRICO68K_CORE=python forces the
    Python core). Both give the same results word for word."""
    env = os.environ.get("BRICO68K_CORE", "").strip()
    if env.lower() == "python":
        return None
    if env:
        if not Path(env).is_file():
            raise RuntimeError(f"BRICO68K_CORE: no file {env}")
        return Path(env)
    for name in C_CORE_NAMES:
        if (TOOL_DIR / name).is_file():
            return TOOL_DIR / name
    return None


def core_label():
    try:
        p = core_path()
    except RuntimeError as e:
        return str(e)
    return f"C ({p.name})" if p else "Python"


# MAME snk/neogeo_v.cpp create_rgb_lookups: 3900/2200/1000/470/220 ohm, dark = 8.2k pull-down
_G = [1 / 3900, 1 / 2200, 1 / 1000, 1 / 470, 1 / 220]
_SUM = sum(_G)
_LEVELS = [[round(255 * sum(g for i, g in enumerate(_G) if v >> i & 1) / (_SUM + (1 / 8200 if dark else 0)))
            for v in range(32)] for dark in (0, 1)]


def neo_rgb3(c):
    """Neo Geo colour word -> (r, g, b), 0-255 (MAME DAC model)."""
    d = c >> 15
    r = ((c >> 14) & 1) | ((c >> 7) & 0x1E)
    g = ((c >> 13) & 1) | ((c >> 3) & 0x1E)
    b = ((c >> 12) & 1) | ((c << 1) & 0x1E)
    L = _LEVELS[d]
    return L[r], L[g], L[b]


def neo_rgb(c):
    """Neo Geo colour word -> '#rrggbb' (MAME DAC model)."""
    return "#%02x%02x%02x" % neo_rgb3(c)


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
    ap.add_argument("--png", metavar="FILE", help="after --run / --script: save the screen (backdrop, fix layer "
                    "and sprites drawn from VRAM, x2) as a PNG")
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
        core_path()                                   # a bad BRICO68K_CORE fails here, not in the workers

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
    if a.png:
        for _ in range(4):                            # a few frames: the backdrop lines of the last command
            core.lib.neo_run_frame()
        cache = {}
        try:
            write_png(a.png, [[cache.get(c) or cache.setdefault(c, neo_rgb3(c)) for c in row]
                              for row in core.screen()], 2)
        except OSError as e:
            print(f"ERROR: cannot write the picture: {e}")
            return 2
        print(f"SCREEN: {a.png}" + ("" if cart.tiles else " (no tiles: backdrop only)"))
    return 0


# ---------------------------------------------------------------------------
# Diagnostic catalogue: how the tests are grouped, run and judged
# ---------------------------------------------------------------------------
CATEGORIES = [
    ("Overview", ["TestChip", "TestBus"]),
    ("Memory", ["TestWRAM", "TestBRAM", "TestPRAM"]),
    ("Video", ["TestVRAM", "TestLSPC", "TestTiming", "TestGfx", "TestDAC"]),
    ("Sound", ["TestZ80", "TestAudio", "PlayEyeSnd"]),
    ("Inputs and system", ["TestInp", "TestStatusA", "TestSystype", "TestVectors", "TestWatchdog"]),
    ("Cartridge", ["CartTest", "CartDiag"]),
    ("Tools", ["Version", "Echo", "Read", "Write", "WriteB", "Dump", "Color"]),
]
TOOLS = set(CATEGORIES[-1][1])
CHK_PROGRESS, CHK_PROG_MAGIC = 0x10FFF0, 0x10FFF2   # TestChip progress word and its magic ($C4EC)
LAMP_OFF = ("#e6e9ed", "#59636e")     # status bar pill when off: background, text
# what the emulator cannot judge by itself
LOOK = {"TestDAC": "Look at the screen: 16 bands, one colour bit each (a black band = dead bit).",
        "TestGfx": "Look at the screen: labels, fix tiles, flips, 8 x 4 tiles, H and V shrink (drawn from VRAM; "
                   "V shrink approximated, no L0 ROM). No tiles without a game or the test cartridge.",
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
    for key, label in (("cpu", "68000 off"), ("host", "Host"), ("z80", "Z80"), ("cart", "No cartridge"), ("fault", "No fault")):
        # a pill: solid colour + white text when on, pale grey when off (a coloured dot alone was too small)
        f = tk.Frame(sbar, bg=LAMP_OFF[0], padx=8, pady=2); f.pack(side="left", padx=(8, 0), pady=5)
        d = tk.Label(f, text="○", fg=LAMP_OFF[1], bg=LAMP_OFF[0], font=(F[0], F[1] + 3)); d.pack(side="left")
        t = tk.Label(f, text=label, fg=LAMP_OFF[1], bg=LAMP_OFF[0], font=(FS[0], FS[1], "bold")); t.pack(side="left", padx=(4, 0))
        lamps[key] = (d, t, f)
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
    cprev_box = tk.Frame(cbox, bg=C["panel"])     # screen preview, top right of the console
    cprev = tk.Canvas(cprev_box, width=192, height=134, bg="#000000", highlightthickness=1,
                      highlightbackground="#8c959f", cursor="hand2")
    cprev.pack(side="top")
    cprev_txt = tk.StringVar(value="Screen (click to enlarge)")
    tk.Label(cprev_box, textvariable=cprev_txt, bg=C["panel"], fg=C["muted"], font=FS, justify="right").pack(side="top", anchor="e")
    csb.pack(side="right", fill="y"); cprev_box.pack(side="right", anchor="n", padx=(8, 8))
    con.pack(fill="both", expand=True)
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
    ttk.Label(scrf, text="Backdrop colour of each line (palette $401FFE), fix layer and sprites (tiles from the "
              "cartridge's S and C ROMs).", style="CardMuted.TLabel").pack(anchor="w")
    scr_hint = tk.StringVar()
    ttk.Label(scrf, textvariable=scr_hint, style="CardMuted.TLabel", foreground=C["warn"]).pack(anchor="w")
    big_holder = tk.Frame(scrf, bg=C["panel"]); big_holder.pack(fill="both", expand=True, pady=(8, 0))
    big = tk.Canvas(big_holder, width=640, height=448, bg="#000000", highlightthickness=1, highlightbackground="#8c959f")
    big.pack()

    # Faults tab
    flt = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(flt, text="Faults")
    # Settings tab
    cartf = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(cartf, text="Cartridge")
    sett = ttk.Frame(nb, style="Card.TFrame", padding=14); nb.add(sett, text="Settings")

    for cv, s in ((thumb, 0.8), (big, 2.0), (cprev, 0.6)):
        st["screens"].append([cv, s, [cv.create_rectangle(0, 0, 0, 0, outline="", fill="#000000") for _ in range(224)]])
    # tile layers (fix + sprites): one image over the line rectangles of each screen, transparent
    # where the backdrop shows. base = 320 x 224, items = [canvas image item, scaled image]
    st["layers"] = {"key": None, "t": 0.0, "base": None, "shown": False,
                    "items": [[cv.create_image(0, 0, anchor="nw", state="hidden"), None] for cv, _, _ in st["screens"]]}

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
               ("BIOS socket (68000 -> BricoNeo)", "bios"), ("Cartridge slot (P bus)", "cart"),
               ("Vector table switch", "vec")]
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
        "and checks every chip.")).grid(row=8, column=0, columnspan=4, sticky="we", pady=(4, 8))
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
        "68000 (Musashi port, exact cycle counts), Z80 (4 MHz) running a test M1, WRAM, palette RAM (2 banks), "
        "system latch, LSPC registers and VRAM, line counter and frame timing, AES inputs with nothing plugged in, "
        "open bus, VBLANK and timer interrupts, Brico16Bits host (1 ms clear, 3 s timeout).\nNot emulated: YM2610 "
        "and sound, memory card, protected cartridges (SMA, PVC, CMC). Fix layer and sprites: drawn from VRAM "
        "with the cartridge's S and C tiles (V shrink approximated). Cartridge: P1/P2 "
        "(P2 banks) or the PROG board SRAM on the 68000 bus; V, M1 are only loaded and checked.\n"
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
        d, t, f = lamps[key]
        if colour == "#8c959f":              # off / nothing
            bg, fg, dot = LAMP_OFF[0], LAMP_OFF[1], "○"
        else:
            bg, fg, dot = colour, "#ffffff", "●"
        f.configure(bg=bg); d.configure(bg=bg, fg=fg, text=dot); t.configure(bg=bg, fg=fg, text=text)

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
        if name in ("TestZ80", "TestAudio", "TestChip") and s in ("FAIL", "WARN") and z80_var.get().startswith("No") \
                and (name != "TestChip" or "Z80" in v):
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
        status.set("Power on: building the core and booting the ROM (1 to 3 s)...")
        root.configure(cursor="watch"); root.update_idletasks()
        try:
            _power_on()
        finally:
            root.configure(cursor=""); status.set("")

    def _power_on():
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
            root.configure(cursor="watch"); root.update_idletasks()
            st["core"].lib.neo_reset(); st["host"].pending = None; st["busy_t0"] = None
            for _ in range(60):
                st["core"].lib.neo_run_frame()
            root.configure(cursor="")
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
        if code == "vec":
            return ["Switch held"]
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
        if k.startswith("Switch"):
            bit_lbl.configure(text="Latch Q1"); sp_bit.grid_remove(); lvl_lbl.configure(text="Held on")
            cb_lvl.configure(values=["system ROM", "cartridge"])
            if lvl_var.get() not in ("system ROM", "cartridge"):
                lvl_var.set("system ROM")
            range_var.set("$000000-$00007F always read from that side (REG_SWPBIOS / REG_SWPROM ignored). "
                          "Held on the cartridge: the console starts on the cartridge's vectors."); return
        if k.startswith("Strobe"):
            bit_lbl.configure(text="Signal"); sp_bit.grid_remove(); lvl_lbl.configure(text="Strobe")
            cb_lvl.configure(values=[s.upper() for s in STROBES])
            if lvl_var.get().lower() not in STROBES:
                lvl_var.set("ROMOEU")
            range_var.set("Never asserted: byte not written (PORTWE), or not driven (OE: the 68000 reads its prefetch; 245: last write). Needs a cartridge."); return
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
        if k.startswith("Switch"):
            fault_add(f"vec:stuck:{'cart' if lvl_var.get() == 'cartridge' else 'bios'}")
        elif k.startswith("Chip"):
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
        scale_layers()

    def draw():
        lines = st["core"].lines(); cols = st["colours"]
        for y, c in enumerate(lines):
            if cols[y] != c:
                cols[y] = c; fill = neo_rgb(c)
                for cv, _, rects in st["screens"]:
                    cv.itemconfigure(rects[y], fill=fill)
        draw_layers()

    def scale_layers():
        """Fits the tile layer image to each screen (scales are multiples of 1/20: zoom then subsample)."""
        L = st.get("layers")
        if not L:
            return
        for (cv, s, _), it in zip(st["screens"], L["items"]):
            old = it[1]                      # kept until the item shows the new one: Tk refuses to
            if not (L["shown"] and L["base"]):          # configure an item whose image is gone
                cv.itemconfigure(it[0], image="", state="hidden"); it[1] = None
                continue
            k = max(1, round(s * 20))
            g = __import__("math").gcd(k, 20)
            img = L["base"].zoom(k // g) if k // g > 1 else L["base"]
            new = img.subsample(20 // g) if 20 // g > 1 else img
            cv.itemconfigure(it[0], image=new, state="normal"); cv.tag_raise(it[0])
            it[1] = new
            del old

    def draw_layers(force=False):
        """Redraws the fix layer and the sprites when VRAM, the palette or the cartridge changed.
        Not while a command runs (a memory test fills VRAM with patterns), at most 5 times a second."""
        L, core, host = st["layers"], st["core"], st["host"]
        now = time.time()
        if core is None or (not force and ((host and host.pending) or now - L["t"] < 0.2)):
            return
        L["t"] = now
        no_tiles = not (st.get("cart") and st["cart"].tiles)
        scr_hint.set("No cartridge tiles: the fix layer and the sprites stay empty, as on a real AES without a game "
                     "(TestGfx shows a black screen). Cartridge tab > test cartridge to see them." if no_tiles else "")
        cprev_txt.set("No cartridge tiles:\nno fix layer, no sprites" if no_tiles else "Screen (click to enlarge)")
        key = core.layer_state()
        if key == L["key"]:
            return
        L["key"] = key
        rows = core.layers()
        base = tk.PhotoImage(width=320, height=224)          # transparent
        cache, shown = {}, False
        for y, row in enumerate(rows):
            x = 0
            while x < 320:
                if row[x] is None:
                    x += 1
                    continue
                x0 = x; run = []
                while x < 320 and row[x] is not None:
                    c = row[x]; run.append(cache.get(c) or cache.setdefault(c, neo_rgb(c))); x += 1
                base.put("{" + " ".join(run) + "}", to=(x0, y)); shown = True
        old = L["base"]                      # the screens may still show the old picture
        L["base"], L["shown"] = base, shown
        scale_layers()
        del old

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
            ran = 0
            for _ in range(n):
                if time.time() - now > 0.06:    # keep the window responsive (the Python core is ~real time)
                    break
                core.lib.neo_run_frame()
                ran += 1
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
            if ran:
                draw(); st["fps_n"] += ran
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
    cprev.bind("<Button-1>", lambda _e: nb.select(scrf))
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

    out(f"{APP_NAME} {APP_VERSION} · Musashi 68000 + Z80 + Neo Geo AES model · Brico16Bits-like host"
        f" · core: {core_label()}\n", "info")
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
                  fault_add_form, ferr), "big": big, "thumb": thumb, "console_preview": cprev, "screen_hint": scr_hint,
                  "cart": cart_var, "cart_set": cart_set_var, "cart_list": cart_list_var, "cart_info": cart_info,
                  "busy_bar": busy_bar, "key_widgets": [b_power, b_reset, b_pause, b_open, b_runall, b_run, b_stop, tree, thumb]}
    return root



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
