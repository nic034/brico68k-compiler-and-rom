#!/usr/bin/env python3
"""Proves the extension checker (emu_host.check_command, used by --test) sees each Brico16Bits rule
being broken: builds the ROM from source/ with the extra extension test/ExtCheckBad.s ("CheckBad",
one broken rule per P1 value), runs every case on the Python core and checks the findings.
Also checks that the real ROM's extensions give no finding but the known ones.
Needs the vasm / vlink of Brico68k_Compiler (brico68k_compiler/toolchain/bin).
Usage: python3 emulator/test/test_ext_check.py
"""
import shutil, subprocess, sys, tempfile
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE.parent))
import emu_host as H

BIN = REPO / "brico68k_compiler" / "toolchain" / "bin"
FLAGS = ["-chklabels", "-nocase", "-Fvobj", "-m68000", "-Dvasm=1", "-DBuildNEO=1", "-spaces", "-quiet"]
# P1 -> (level, text the finding must contain); None: no finding at all
CASES = {
    0: None,
    1: ("FAIL", "interrupts enabled"),
    2: ("FAIL", "no end of transmission"),
    3: ("WARN", "2 EOT reads"),
    4: ("WARN", "P1-P3 read after the 1 ms clear"),
    5: ("FAIL", "watchdog reset before the EOT"),
    6: ("FAIL", "not read for 3."),
    7: ("FAIL", "ring buffer wrapped"),
    8: ("WARN", "output after the EOT"),
    9: ("WARN", "close to the 3 s"),
    10: ("FAIL", "outside the BIOS ROM"),
    11: ("WARN", "word extension sent 3 words"),
}


def build(tmp):
    src = tmp / "source"
    shutil.copytree(REPO / "source", src)
    shutil.copy(HERE / "ExtCheckBad.s", src / "ExtCheckBad.s")
    main = (src / "Brico68k.s").read_text()
    anchor = "\tDECLARE_EXTENSION EXT_ECHO,"
    assert anchor in main
    main = main.replace(anchor, '\tDECLARE_EXTENSION EXT_CHECK_BAD, BRICO_EXT_OUTPUT_TYPE_WORD, "CheckBad", '
                                '"Test fixture: breaks one rule per P1."\n' + anchor, 1)
    (src / "Brico68k.s").write_text(main)
    ld = (src / "Brico68k.ld").read_text()        # the fixture does not fit the 32 KiB NeoDiag layout
    assert "len=0x7f7a" in ld
    (src / "Brico68k.ld").write_text(ld.replace("len=0x7f7a", "len=0xff80"))
    objs = []
    for s in sorted(src.glob("*.s")):
        o = tmp / (s.stem + ".o")
        subprocess.run([str(BIN / "vasmm68k_mot"), *FLAGS, f"-I{src / 'inc'}", "-o", str(o), str(s)],
                       cwd=src, check=True)
        objs.append(str(o))
    out = tmp / "rom.bin"
    subprocess.run([str(BIN / "vlink"), "-brawbin1", "-T", str(src / "Brico68k.ld"), "-o", str(out), *objs],
                   cwd=src, check=True)
    return out.read_bytes().ljust(0x20000, b"\xff")


def boot(rom):
    c = H.Core(None)
    c.load(rom)
    c.load_cart(H.make_cart("none"))
    c.power_on()
    c.lib.neo_set_options(1, 1)
    for _ in range(60):
        c.lib.neo_run_frame()
    return H.Host(c, rom)


fails = 0
with tempfile.TemporaryDirectory() as t:
    rom = build(Path(t))
for p1, want in CASES.items():
    host = boot(rom)                      # fresh console: a broken case must not spoil the next one
    st, text, secs, found = H.check_command(host, f"CheckBad {p1}")
    ok = (not found) if want is None else any(lv == want[0] and want[1] in msg for lv, msg in found)
    fails += not ok
    print(f"{'ok  ' if ok else 'FAIL'} case {p1:2d} ({st}, {secs * 1000:.0f} ms): "
          + ("; ".join(f"{lv} {msg}" for lv, msg in found) or "no finding"), flush=True)

# the real ROM: only the known finding (TestVRAM takes 1.77 s of the 3 s)
known = {"TestVRAM"}
real = (REPO / "rom" / "ROM.BIO").read_bytes()
host = boot(real)
for name, *_ in host.exts:
    line = {"Read": "Read $100000", "Write": "Write 5 $100000", "WriteB": "WriteB 5 $100000",
            "Dump": "Dump $100000 16", "Color": "Color 1"}.get(name, name)
    st, text, secs, found = H.check_command(host, line, name == "TestWatchdog")
    if name == "TestWatchdog":
        host.core.lib.neo_run(2 * H.CPU_HZ)            # let the armed watchdog reset the console
    bad = bool(found) != (name in known)
    fails += bad
    if found or bad:
        print(f"{'FAIL' if bad else 'ok  '} ROM.BIO {name}: " + "; ".join(f"{lv} {msg}" for lv, msg in found))
print(f"{fails} failure(s)")
sys.exit(1 if fails else 0)
