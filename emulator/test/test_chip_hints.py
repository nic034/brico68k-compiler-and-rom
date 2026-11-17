#!/usr/bin/env python3
"""Chip references of the RAM tests (WRAM, palette, VRAM), on the Python core.

Each fault must name the chip that the Board-Folk NeoGeoAES-3.5 schematic gives for that data bus half
(U1/U2 WRAM, U7/U6 palette, U17/U18 slow VRAM, U19/U20 fast VRAM) and the matching hint line.
What the schematic does NOT prove: D0-D7 -> PC0-PC7 passes through NEO-G0, and E0 / F0 being VRAM data
bit 0 is by pin name; these are checked against the schematic's names only.
Usage: python3 emulator/test/test_chip_hints.py [ROM]      (default rom/ROM.BIO)
"""
import sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import emu_host as H

ROM = Path(sys.argv[1] if len(sys.argv) > 1 else HERE.parent.parent / "rom" / "ROM.BIO").read_bytes()
D_BUS = "shared D bus (68000, LSPC2, NEO-G0, ROM U36, slot)"
PAL = "NEO-G0 U5 (D <-> PC buffer, WE), or 74LS273 U9/U10 on PC"
CASES = [  # (faults, command, lines that must be in the output, lines that must not be)
    (["wram:data:3:1"], "TestWRAM", ["Chip     : lower chip (D0-D7) = AES U1", D_BUS], ["U2"]),
    (["wram:lane:upper"], "TestWRAM", ["Chip     : upper chip (D8-D15) = AES U2", D_BUS], ["AES U1"]),
    (["wram:addr:5:0"], "TestWRAM", ["BOTH chips (D0-D15) = AES U1+U2", "68000 pin Ak (direct to U1+U2 on AES)"], []),
    (["pal:data:3:1"], "TestPRAM", ["lower chip (D0-D7) = AES U7 (PC0-7)", PAL], ["U6"]),
    (["pal:data:9:0"], "TestPRAM", ["upper chip (D8-D15) = AES U6 (PC8-15)", PAL], ["U7"]),
    (["pal:addr:5:0"], "TestPRAM", ["AES U6+U7 (PC0-15)", "NEO-B1 U13 (PA0-PA11, AES)"], []),
    (["vramlo:data:3:1"], "TestVRAM", ["slow VRAM lower chip (D0-D7) = AES U17 (E0-7)"], ["U18"]),
    (["vramlo:data:9:0"], "TestVRAM", ["slow VRAM upper chip (D8-D15) = AES U18 (E8-15)"], ["U17"]),
    (["vramhi:data:3:1"], "TestVRAM", ["fast VRAM (CXK5814) lower chip (D0-D7) = AES U19 (F0-7)"], ["U20"]),
    (["vramhi:data:9:0"], "TestVRAM", ["fast VRAM (CXK5814) upper chip (D8-D15) = AES U20 (F8-15)"], ["U19"]),
    (["vramlo:addr:3:0"], "TestVRAM", ["BOTH chips (D0-D15) = AES U17+U18 (E0-15)", "come only from the LSPC2 U21"], []),
    (["vramhi:addr:3:0"], "TestVRAM", ["BOTH chips (D0-D15) = AES U19+U20 (F0-15)", "come only from the LSPC2 U21"], []),
    ([], "TestWRAM", ["=> Test Success"], ["AES"]),               # healthy: no reference
    ([], "TestPRAM", ["=> Test Success"], ["AES"]),
    ([], "TestVRAM", ["=> Test success"], ["AES"]),
]


def run(faults, cmd):
    c = H.Core(None)
    c.load(ROM)
    c.power_on()
    c.lib.neo_set_options(1, 1)
    H.apply_faults(c, [H.parse_fault(f) for f in faults])
    for _ in range(60):
        c.lib.neo_run_frame()
    st, text, _ = H.Host(c, ROM).run_blocking(cmd)
    assert st == "eot", f"{faults} {cmd}: {st}"
    return text


fails = 0
for faults, cmd, must, mustnot in CASES:
    text = run(faults, cmd)
    bad = [m for m in must if m not in text] + [f"unexpected {m!r}" for m in mustnot if m in text]
    print(("ok   " if not bad else "FAIL ") + cmd + " " + (",".join(faults) or "healthy"))
    for b in bad:
        print("       " + b)
    fails += bool(bad)
print(f"\n{fails} failure(s)")
sys.exit(1 if fails else 0)
