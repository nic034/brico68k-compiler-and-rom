#!/usr/bin/env python3
"""TestDecode against every fault that touches the address decoding, on the Python core.

Healthy console: the four lines say OK and the last line says "Test success" ("Test failure" otherwise). Then, for every modelled decoding fault, the verdict the ROM
must give and no other: wram:sel / pal:sel / lspc:sel:LINE:0 name exactly that line (and only that
region), LINE:1 (the chip never answers at its normal addresses) is the word itself being bad,
wram:leak fails the independence line only. Stuck data bits and a dead WRAM chip are "the word
itself is bad", a stuck address line inside the chip is not a decoding fault (still OK).
Usage: python3 emulator/test/test_decode.py [ROM]      (default rom/ROM.BIO)
"""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import emu_host as H

ROM = Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parent.parent / "rom" / "ROM.BIO").read_bytes()
TITLES = ("Work RAM", "Palette RAM", "LSPC regs", "WRAM / palette")
BAD = "the word itself is bad (RAM test)"
# One hint line per failing decoding group (what the Board-Folk AES 3.5 schematic shows), none for a bad RAM
HINTS = {"Work RAM": "  WRAM: U1/U2 see A1-A15; NEO-C1 U4 sees A17-A23, not A16 (AES)",
         "Palette RAM": "  Palette: NEO-C1 U4 PAL -> NEO-G0 U5; PA0-PA11 from NEO-B1 U13 (AES)",
         "LSPC regs": "  LSPC regs: NEO-C1 U4 LSPOE/LSPWE -> LSPC2 U21, which sees only A1-A3",
         "WRAM / palette": "  Two RAMs on at once: NEO-C1 U4 WRx/WWx (WRAM), PAL -> NEO-G0 (palette)"}


def run(faults):
    c = H.Core(None)
    c.load(ROM)
    c.power_on()
    c.lib.neo_set_options(1, 1)
    H.apply_faults(c, [H.parse_fault(f) for f in faults])
    for _ in range(60):
        c.lib.neo_run_frame()
    st, text, _ = H.Host(c, ROM).run_blocking("TestDecode")
    assert st == "eot", f"{faults}: {st}"
    verdicts = {}
    for line in text.splitlines():
        for t in TITLES:
            if line.startswith("> " + t):
                verdicts[t] = line.split("  ")[-1].strip() if line.rstrip().endswith("OK") else line.split("FAIL: ", 1)[1].strip()
    assert set(verdicts) == set(TITLES), f"{faults}: {text!r}"
    verdicts["=>"] = text.strip().splitlines()[-1].strip()
    verdicts["hints"] = sorted(l.rstrip() for l in text.splitlines()
                               if l.startswith("  ") and not l.startswith("  Next"))
    return verdicts


def expect(faults, **want):
    got = run(faults)
    exp = {t: "OK" for t in TITLES}
    exp.update({k.replace("_", " "): v for k, v in want.items()})
    exp["=>"] = "=> Test success" if all(v == "OK" for v in exp.values()) else "=> Test failure"
    exp["hints"] = sorted(HINTS[t] for t in TITLES if exp[t] != "OK" and exp[t] != BAD)
    ok = got == exp
    print(("ok   " if ok else "FAIL ") + (",".join(faults) or "healthy"))
    if not ok:
        for t in (*TITLES, "=>", "hints"):
            if got[t] != exp[t]:
                print(f"       {t}: expected {exp[t]!r}, got {got[t]!r}")
    return ok


fails = 0
fails += not expect([])
for region, title, (lo, hi) in (("wram", "Work RAM", H.SEL_RANGE[0]), ("pal", "Palette RAM", H.SEL_RANGE[1]),
                                ("lspc", "LSPC regs", H.SEL_RANGE[8])):
    for line in range(lo, hi + 1):
        fails += not expect([f"{region}:sel:{line}:0"], **{title: f"not a mirror on A{line}"})
        # the chip is dead at its normal addresses: the independence line fails too when it is WRAM or
        # palette (a dead word is a lost word), the LSPC has no word in that test
        extra = {"WRAM / palette": "a word lost or changed by the other"} if region != "lspc" else {}
        fails += not expect([f"{region}:sel:{line}:1"], **{title: BAD}, **extra)
fails += not expect(["wram:leak"], **{"WRAM / palette": "a word lost or changed by the other"})
# faults of the RAM itself are not decoding faults: the word itself is bad, or nothing to see
lost = {"WRAM / palette": "a word lost or changed by the other"}
fails += not expect(["wram:data:3:1"], **{"Work RAM": BAD}, **lost)
fails += not expect(["wram:lane:upper"], **{"Work RAM": BAD}, **lost)
fails += not expect(["pal:data:9:0"], **{"Palette RAM": BAD}, **lost)
fails += not expect(["wram:addr:5:0"])                # folds the chip onto itself, the mirrors still agree
fails += not expect(["pal:addr:13:1"])                # bank select stuck: bank 1 answers everywhere
print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
