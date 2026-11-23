"""Bug hunt and unexpected-input bench for the Brico68k ROM, on the emulator.

    python emulator/test/bench_fuzz.py [ROM] [--seed N] [--rounds N] [--core PATH|python] [--check N]

Every command of the ROM gets random and extreme parameters (0, 1, $FFFF, $FFFFFFFF, odd
addresses, counts over the BricoNeo buffer...), in random order, on a healthy console and
under random combinations of modelled faults. After each command the bench checks what must
hold whatever the input:
  - the command ends: an EOT or an exception report (EXCPT), never the 3 s timeout
    (except the cases a real BricoNeo would also time out: TestWatchdog armed, faults on the
    BIOS socket, user writes into the stack / vectors / I/O);
  - at most 2047 output words (the BricoNeo ring buffer is 2048);
  - the result fits the declared type (word: 1 word, string: printable + NUL, dump: count);
  - "Echo <random>" right after returns that value: the 68000 is back in the dispatcher.
--check N also runs N random command lines on the Python core under the Brico16Bits rule
check (IRQs masked during output, P1-P3 read first, one EOT, polling after the EOT...).
Exit code 1 when something breaks; each failure is printed with the seed and the sequence
needed to replay it. Emulation only: says nothing about a real AES.
"""
import argparse
import importlib.util
import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("bemu", ROOT / "Brico68k_Emulator.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

EXTREME = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF,
           0x80000000, 0xFFFFFFFF, 0xFFFFFFFE, 2045, 2046, 2047, 2048, 4096]
# addresses: real regions, mirrors, odd, unmapped, wrap-around
ADDRS = [0x100000, 0x100001, 0x10FFFE, 0x10FFFF, 0x1FFFFE, 0x200000, 0x2FFFFE, 0x300000, 0x300001,
         0x320000, 0x340000, 0x380000, 0x3A0001, 0x3C0000, 0x3C0002, 0x3C000C, 0x400000, 0x401FFE,
         0x7FFFFE, 0x800000, 0xBFFFFE, 0xC00000, 0xC00001, 0xC1FF00, 0xC7FFFE, 0xD00000, 0xD0FFFE,
         0xE00000, 0xFFFFFE, 0xFFFFFF, 0x000000, 0x0000FF, 0x00FFFE]
# commands the bench does not run with random parameters: they write where the user tells them
WRITERS = {"write", "writeb"}
# writes that legitimately kill the console (the user hit its stack, vectors, watchdog or system latches)
SAFE_WRITE_AREAS = [(0x100000, 0x10F000)]           # WRAM below the stack / variables


def rnd_param(r):
    k = r.random()
    if k < 0.4:
        return r.choice(EXTREME)
    if k < 0.7:
        return r.choice(ADDRS)
    if k < 0.85:
        return r.getrandbits(16)
    return r.getrandbits(32)


def fmt(v):
    return f"${v:X}"


def boot(rom, core_path, faults=(), z80=1, wd=1, cart="test"):
    c = E.Core(core_path)
    c.load(rom)
    if cart:
        c.load_cart(E.make_cart(cart))
    c.power_on()
    c.lib.neo_set_options(z80, wd)
    E.apply_faults(c, list(faults))
    for _ in range(60):
        c.lib.neo_run_frame()
    return c


def type_ok(typ, values, line):
    """'' or why the output does not fit the declared result type (EOT case)."""
    if typ == 1 and len(values) != 1:
        return f"WORD result with {len(values)} words"
    if typ == 2:
        if not values:
            return "STRING result with no word"
        b = b"".join(v.to_bytes(2, "big") for v in values)
        if 0 not in b:
            return "STRING result with no NUL"
        txt = b[:b.index(0)]
        bad = [x for x in txt if not (32 <= x < 127 or x in (10, 13, 9))]
        if bad:
            return f"STRING result with non-printable bytes {bad[:4]}"
    if typ == 3 and len(values) > 2047:
        return f"DUMP of {len(values)} words"
    return ""


class Bench:
    def __init__(self, rom, core_path, seed):
        self.rom = rom
        self.core_path = core_path
        self.r = random.Random(seed)
        self.seed = seed
        self.exts = E.parse_extensions(rom)
        self.stack_users = {n.lower() for n, _, _, d in self.exts if "WRAM (stack)" in d or "Uses WRAM" in d
                            or "need WRAM" in d}
        self.fail = []
        self.stats = {"commands": 0, "eot": 0, "exception": 0, "timeout_expected": 0, "echo": 0}

    def line_for(self, name):
        n = self.r.randint(0, 3)
        return " ".join([name] + [fmt(rnd_param(self.r)) for _ in range(n)])

    def expected_hang(self, line, faults):
        w = line.split()
        n = w[0].lower()
        if any(f[0] == 5 for f in faults):              # BIOS socket fault: host link itself is broken
            return True
        if n in self.stack_users and any(f[0] == 0 for f in faults):
            return True                                 # WRAM fault under a command that uses the stack:
                                                        # a corrupted return address, anything can follow
        if n == "testwatchdog":
            return True
        if n in WRITERS:
            addr = E.parse_uint(w[2]) if len(w) > 2 else 0
            return not any(lo <= addr < hi for lo, hi in SAFE_WRITE_AREAS)
        return False

    def run_seq(self, label, seq, faults=()):
        c = boot(self.rom, self.core_path, faults)
        h = E.Host(c, self.rom)
        types = {n.lower(): t for n, _, t, _ in self.exts}
        done = []
        for line in seq:
            done.append(line)
            st, text, secs = h.run_blocking(line)
            vals = h.last_values
            self.stats["commands"] += 1
            name = line.split()[0].lower()
            if st == "timeout" or st == "exception" or (faults and any(f[0] == 0 for f in faults)
                                                        and name in self.stack_users):
                if self.expected_hang(line, faults) or (st == "exception" and faults):
                    self.stats["timeout_expected"] += 1
                    return                                # console state no longer defined: next sequence
                if st == "exception":
                    self.stats["exception"] += 1
                    self.fail.append((label, faults, done[:], f"exception: {text.strip()[:200]}"))
                else:
                    self.fail.append((label, faults, done[:], "timeout (no EOT in 3 s)"))
                return
            self.stats["eot"] += 1
            if name == "testwatchdog" or any(f[0] == 5 for f in faults):
                return              # console resets ~0.13 s later / host link itself broken: output undefined
            if c.lib.neo_host_overflow():
                self.fail.append((label, faults, done[:], f"over 2047 words ({len(vals)})"))
            why = type_ok(types.get(name, 0), vals, line)
            if why:
                self.fail.append((label, faults, done[:], why))
            if faults:
                continue
            v = self.r.getrandbits(16)
            st2, _, _ = h.run_blocking(f"Echo {fmt(v)}")
            self.stats["echo"] += 1
            if st2 != "eot" or h.last_values != [v]:
                if self.expected_hang(line, faults):
                    return
                self.fail.append((label, faults, done[:], f"Echo after it: {st2} {h.last_values[:3]} (expected {v:04X})"))
                return

    def random_seq(self, k):
        names = [n for n, *_ in self.exts if n.lower() not in WRITERS]
        seq = [self.line_for(self.r.choice(names)) for _ in range(k)]
        if self.r.random() < 0.3:                           # a harmless write in WRAM below the stack
            a = self.r.randrange(0x100000, 0x10F000) & ~1
            seq.insert(self.r.randrange(len(seq) + 1), f"Write {fmt(self.r.getrandbits(16))} {fmt(a)}")
        return seq

    def random_faults(self):
        pool = E.all_single_faults()
        return tuple(self.r.sample(pool, self.r.randint(1, 3)))


def report(b, t0):
    s = b.stats
    print(f"--- {s['commands']} commands, {s['eot']} EOT, {s['echo']} Echo checks, "
          f"{s['timeout_expected']} expected hangs/exceptions, {len(b.fail)} failure(s), {time.time() - t0:.0f} s")
    seen = set()
    for label, faults, seq, why in b.fail:
        key = (seq[-1].split()[0].lower(), why.split(":")[0], faults)
        if key in seen:
            continue
        seen.add(key)
        print(f"FAIL [{label}] {why}")
        if faults:
            print("     faults: " + " ".join(E.fault_spec(f) for f in faults))
        print("     sequence: " + " | ".join(seq[-6:]))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rom", nargs="?", default=str(ROOT / "rom" / "ROM.BIO"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--rounds", type=int, default=200)
    ap.add_argument("--core", default=str(ROOT / "emulator" / "build" / "libneocore_test.so"))
    ap.add_argument("--check", type=int, default=0)
    a = ap.parse_args()
    core = None if a.core == "python" or not Path(a.core).is_file() else Path(a.core)
    rom = Path(a.rom).read_bytes()
    b = Bench(rom, core, a.seed)
    t0 = time.time()
    names = [n for n, *_ in b.exts if n.lower() not in WRITERS]
    # 1. each command alone with every extreme value as P1 (P2/P3 random), healthy console
    for n in names:
        for v in EXTREME + ADDRS:
            b.run_seq("extreme", [f"{n} {fmt(v)} {fmt(rnd_param(b.r))} {fmt(rnd_param(b.r))}"])
    # 2. random sequences, healthy
    for i in range(a.rounds):
        b.run_seq(f"seq {i}", b.random_seq(b.r.randint(2, 8)))
    # 3. random sequences under 1-3 random faults: must end (EOT or EXCPT), stay under 2047 words
    for i in range(a.rounds // 2):
        b.run_seq(f"faults {i}", b.random_seq(b.r.randint(1, 5)), b.random_faults())
    # 4. Brico16Bits rule check on the Python core with random parameters
    for i in range(a.check):
        c = boot(rom, None)
        h = E.Host(c, rom)
        line = b.line_for(b.r.choice(names))
        if b.expected_hang(line, ()):
            continue
        chk = E.ExtCheck(c)
        chk.begin()
        st, text, secs = h.run_blocking(line)
        chk.after()
        typ = {n.lower(): t for n, _, t, _ in b.exts}[line.split()[0].lower()]
        for lvl, msg in chk.end(typ, st, secs, h.last_values, resets_ok=False):
            if lvl == "FAIL":
                b.fail.append((f"rules {i}", (), [line], f"rule: {msg}"))
    report(b, t0)
    sys.exit(1 if b.fail else 0)


if __name__ == "__main__":
    main()
