#!/usr/bin/env python3
"""Differential test of the pure-Python 68000 (emulator/m68k_py.py) against the C Musashi
of the emulator core, instruction by instruction.

Both CPUs run on the same flat 16 MB memory that logs every bus access. Each case: pulse
reset, random registers / SR (supervisor or user, trace bit, interrupt mask, flags), a random
opcode (or one picked per handler so the rare ones are covered) followed by random extension
words, sometimes an interrupt request, then execute(N) for a random small N (one or a few
instructions, exceptions included). Compared: cycles returned, D0-A7, PC, SR, USP, ISP, PPC,
IR, and the full list of bus accesses (kind, address, value, in order).

Needs gcc and the Musashi sources configured by build_core.py / build_test_core.py
(emulator/build/src): the harness library (musashi_harness.c + Musashi) is built on the fly.
Usage: python3 emulator/test/test_m68k_py.py [cases] [seed]
"""
import ctypes, random, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import m68k_py, m68k_tables

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "build" / "src"
if not (SRC / "m68kops.c").exists():                    # build_test_core.py only makes src_test
    SRC = HERE.parent / "build" / "src_test"
if not (SRC / "m68kops.c").exists():
    sys.exit("Musashi sources not found: run emulator/build_test_core.py (or build_core.py) first")
LIBPATH = HERE.parent / "build" / "libmusashi_test.so"
import subprocess
subprocess.run(["gcc", "-O2", "-fPIC", "-shared", "-w", f"-I{SRC}", "-o", str(LIBPATH), str(HERE / "musashi_harness.c")]
               + [str(SRC / f) for f in ("m68kcpu.c", "m68kops.c", "m68kdasm.c", "softfloat/softfloat.c")] + ["-lm"],
               check=True)
lib = ctypes.CDLL(str(LIBPATH))
CASES = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
SEED = int(sys.argv[2]) if len(sys.argv) > 2 else 1
lib.h_get_reg.restype = ctypes.c_uint32
lib.h_set_reg.argtypes = [ctypes.c_int, ctypes.c_uint32]
lib.h_poke.argtypes = [ctypes.c_uint32, ctypes.c_char_p, ctypes.c_int]
lib.h_init()

rnd = random.Random(SEED)
mem = bytearray(rnd.getrandbits(8) for _ in range(0x1000000))
lib.h_poke(0, bytes(mem), len(mem))
log = []


def b16(a):
    v = (mem[a] << 8) | mem[a + 1]
    log.append((1, a, v))
    return v


def b8(a):
    log.append((0, a, mem[a]))
    return mem[a]


def w16(a, v):
    a &= 0xFFFFFE
    mem[a] = v >> 8
    mem[a + 1] = v & 0xFF
    log.append((3, a, v))


def w8(a, v):
    mem[a] = v
    log.append((2, a, v))


t0 = time.time()
cpu = m68k_py.M68K(b16, b8, w16, w8)
print(f"Python core built in {time.time() - t0:.2f} s")

raw = __import__("lzma").decompress(__import__("base64").b64decode("".join(m68k_tables.M68K_TABLES)))
idx = memoryview(raw[:0x20000]).cast("H")
by_name = {}
for op in range(0x10000):
    by_name.setdefault(m68k_tables.M68K_NAMES[idx[op]], []).append(op)
names = sorted(by_name)
REGS = list(range(16)) + [16, 17, 19, 20, 29, 30]
RN = [f"D{i}" for i in range(8)] + [f"A{i}" for i in range(8)] + ["PC", "SR", "USP", "ISP", "PPC", "IR"]
buf = (ctypes.c_uint32 * (4096 * 3))()


def rval():
    k = rnd.random()
    if k < 0.15:
        return rnd.choice([0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF])
    if k < 0.35:
        return rnd.getrandbits(8)
    if k < 0.5:
        return rnd.getrandbits(16)
    return rnd.getrandbits(32)


fails = 0
accesses = 0
cycles = 0
covered = set()
for case in range(CASES):
    pc = rnd.randrange(0x400, 0xFF0000, 2)
    op = rnd.getrandbits(16) if rnd.random() < 0.3 else rnd.choice(by_name[rnd.choice(names)])
    covered.add(m68k_tables.M68K_NAMES[idx[op]])
    code = op.to_bytes(2, "big") + bytes(rnd.getrandbits(8) for _ in range(10))
    if rnd.random() < 0.3:      # small displacements / sane extension words
        code = code[:2] + bytes([rnd.choice([0, 0xFF]), rnd.getrandbits(8)]) + code[4:]
    mem[pc:pc + len(code)] = code
    lib.h_poke(pc, code, len(code))
    sr = rnd.getrandbits(16) & 0xA71F
    if rnd.random() < 0.9:
        sr &= 0x7FFF                    # trace mostly off
    even = lambda: 0xFFFFFFFE if rnd.random() < 0.9 else 0xFFFFFFFF
    st = {17: sr, 19: rval() & even(), 20: rval() & even()}
    regs = [rval() for _ in range(16)]
    for i in range(8, 16):
        if rnd.random() < 0.9:
            regs[i] &= ~1
    irq = rnd.choice([0] * 6 + [1, 2, 3, 4, 5, 6, 7])
    n = rnd.choice([1, 1, 1, 2, 4, 8, 20, 60, 200])
    # identical setup on both sides
    log.clear()
    lib.h_set_irq(0)                # no interrupt while the registers are set (Musashi set_reg(SR) checks them)
    cpu.set_irq(0)
    if rnd.random() < 0.6:          # else keep the state of the previous case (STOP, halt, run mode...)
        lib.h_reset()
        cpu.pulse_reset()
    for c in (lib.h_set_reg, cpu.set_reg):
        c(17, sr)
        c(19, st[19])
        c(20, st[20])
        for i in range(15):
            c(i, regs[i])
        c(16, pc)
    lib.h_set_irq(irq)
    cpu.set_irq(irq)
    log.clear()
    rc = lib.h_exec(40 + n)
    rp = cpu.execute(40 + n)
    if rnd.random() < 0.2:          # a second slice, as neo_run does
        log.clear()
        rc = (rc, lib.h_exec(n))
        rp = (rp, cpu.execute(n))
    nl = lib.h_log(buf)
    clog = [(buf[3 * i], buf[3 * i + 1], buf[3 * i + 2]) for i in range(nl)]
    cr = [lib.h_get_reg(r) for r in REGS]
    pr = [cpu.get_reg(r) for r in REGS]
    accesses += len(clog)
    cycles += rc if isinstance(rc, int) else sum(rc)
    if rc != rp or cr != pr or clog != log[:4096]:
        fails += 1
        if fails <= 15:
            print(f"case {case}: op {op:04x} {m68k_tables.M68K_NAMES[idx[op]]} pc {pc:06x} sr {sr:04x} irq {irq} n {n}")
            print("  code", code.hex())
            if rc != rp:
                print(f"  cycles C {rc} Py {rp}")
            for i, (a, b) in enumerate(zip(cr, pr)):
                if a != b:
                    print(f"  {RN[i]}: C {a:08x} Py {b:08x}")
            if clog != log[:4096]:
                for i in range(max(len(clog), len(log))):
                    a = clog[i] if i < len(clog) else None
                    b = log[i] if i < len(log) else None
                    if a != b:
                        print(f"  access #{i}: C {a} Py {b}")
                        break
        # resync memory after a divergence
        lib.h_poke(0, bytes(mem), len(mem))
print(f"{CASES} cases, {accesses} bus accesses and {cycles} cycles compared, {fails} mismatches, {len(covered)}/{len(names)} handlers covered, {time.time() - t0:.0f} s")
sys.exit(1 if fails else 0)
