#!/usr/bin/env python3
"""Lockstep test of the Python AES model (neo_py.py) against the C core (neocore.c).

Both cores run the same ROM and the same command sequences (with the console reset button,
the Z80 options, cartridges, faults and odd run lengths); after every slice the cycle count,
PC, frame count, Z80 commands, cartridge bank and writes, host state and output words, the
backdrop lines and the YM2610 SSG registers the Z80 wrote are compared, and VRAM / palette at the end of each sequence.
Usage: python3 emulator/test/test_neo_py.py [C core] [ROM]
  C core: default emulator/build/libneocore_test.so (build_test_core.py), which also has the
  test input hook.
"""
import random, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import emu_host as H

CLIB = sys.argv[1] if len(sys.argv) > 1 else str(HERE.parent / "build" / "libneocore_test.so")
ROM = Path(sys.argv[2] if len(sys.argv) > 2 else HERE.parent.parent / "rom" / "ROM.BIO").read_bytes()

SEQS = [
    ("none", 1, 1, [], None, ["Echo $1234", "Echo $4321", "TestWRAM", "TestChip", "TestZ80", "TestAudio", "TestDAC 1",
                              "RESET", "TestVectors", "TestGfx", "TestWatchdog", "Echo 5"]),
    ("test", 1, 1, [], None, ["Dump $100 8", "TestGfx $100", "TestZ80", "RESET", "TestDAC", "TestGfx $12345 1"]),
    ("diag", 1, 0, [], None, ["CartDiag", "TestWatchdog", "Echo 7", "TestLSPC"]),
    ("none", 0, 1, [], None, ["TestZ80", "TestAudio", "TestChip", "TestFM", "TestSsg", "Echo 3"]),
    ("none", 1, 1, [(0, 0, 3, 1), (2, 1, 5, 0)], None, ["TestWRAM", "TestVRAM", "TestGfx", "TestChip"]),
    ("test", 1, 1, [(6, 3, 4, 0), (5, 1, 15, 1)], None, ["CartDiag", "TestChip", "Echo 9"]),
    ("none", 1, 1, [], (0xA5, 0x5A, 0x3C, 0xE7, 0xFF, 0xFFFF, 1), ["TestInp", "TestBRAM", "TestStatusA", "TestSystype"]),
    # address decoding faults (kind 4: a line the decoder should ignore; kind 5: WRAM writes reach the palette)
    ("none", 1, 1, [(0, 4, 17, 0)], None, ["TestDecode", "TestWRAM", "Echo 5"]),
    ("none", 1, 1, [(1, 4, 15, 1), (8, 4, 6, 0)], None, ["TestDecode", "TestPRAM", "TestLSPC", "TestDAC 1"]),
    ("none", 1, 1, [(0, 5, 0, 1)], None, ["TestDecode", "TestPRAM", "TestChip"]),
    ("none", 1, 1, [(8, 4, 9, 1)], None, ["TestDecode", "TestChip", "Echo 6"]),
]


def state(c):
    L = c.lib
    n = L.neo_host_values(c._vals, 2048)
    # the C library is one global state per process: its Z80 command counter is not reset by a
    # power-on (neither is the Python one), so compare what each sequence added
    return (L.neo_cycles(), L.neo_pc(), L.neo_frames(), L.neo_z80_commands() - c.z0, L.neo_cart_bank(), L.neo_cart_writes(),
            L.neo_cart_latch_writes(), L.neo_host_state(), list(c._vals[:n]), L.neo_host_overflow(), tuple(c.lines()),
            L.neo_watchdog_resets(), c.ssg())


fails = 0
rnd = random.Random(5)
for si, (cart, z80, wd, faults, inputs, cmds) in enumerate(SEQS):
    cores = []
    for lib in (CLIB, None):
        c = H.Core(lib)
        if inputs:
            c.lib.neo_test_inputs(*inputs)
        c.load(ROM)
        c.load_cart(cart)
        c.lib.neo_fault_clear()
        for f in faults:
            assert c.lib.neo_fault_add(*f) == 0
        c.power_on()
        c.lib.neo_set_options(z80, wd)
        c.z0 = c.lib.neo_z80_commands()
        cores.append(c)
    steps = 0
    for cmd in ["WAIT"] + cmds:
        for c in cores:
            if cmd == "RESET":
                c.lib.neo_reset()
            elif cmd != "WAIT":
                H.Host(c, ROM).start(cmd)
        for k in range(40):
            n = rnd.choice([H.FRAME_CYCLES, 768, 1, 37, 5000, 100000])
            for c in cores:
                c.lib.neo_run(n)
            a, b = state(cores[0]), state(cores[1])
            steps += 1
            if a != b:
                fails += 1
                print(f"seq {si} {cmd} slice {k}: C {[x if not isinstance(x, (list, tuple)) else len(x) for x in a]}")
                print(f"{' ' * len(f'seq {si} {cmd} slice {k}:')} Py {[x if not isinstance(x, (list, tuple)) else len(x) for x in b]}")
                break
        else:
            continue
        break
    va, vb = [], []
    for c, v in zip(cores, (va, vb)):
        c.layer_state()
        v += [list(c._vram), list(c._pal), c.lib.neo_peek16(0x3C0006)]
    if va != vb:
        fails += 1
        print(f"seq {si}: VRAM / palette differ")
    print(f"seq {si}: {steps} slices, {'OK' if not fails else 'FAIL'}", flush=True)
print(f"{fails} failure(s)")
sys.exit(1 if fails else 0)
