# ---------------------------------------------------------------------------
# Pure-Python 68000, a line-for-line port of Musashi 4.60 (Karl Stenerud, MIT licence) as
# the C core builds it (68000, address error + trace + RESET emulation on, prefetch off,
# no function code / PMMU emulation): same decode table, same cycle counts, same order of
# bus accesses, same flags, same exceptions (address error frame, trace, interrupts with
# auto-vectors and the auto-clear of the interrupt level, STOP, halt on a double fault).
# Checked instruction by instruction against the C Musashi (emulator/test_m68k_py.py).
#
# make_m68k(bus16, bus8, wbus16, wbus8) -> object with execute(cycles), pulse_reset(),
# set_irq(level), get_reg(n), set_reg(n, v), cycles_run(), pc().
# The bus functions get 24-bit addresses: bus16(a) a even, bus8(a), wbus16(a, v), wbus8(a, v).
# 32-bit accesses are two 16-bit ones, high word first (as neocore.c's Musashi callbacks).
# The code below is generated once at start-up: one small function per Musashi handler,
# specialised per opcode (register numbers baked in).
#
# Musashi: Copyright (c) 1998-2001 Karl Stenerud. MIT licence:
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software
# and associated documentation files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or
# substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
# BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# ---------------------------------------------------------------------------
import base64 as _b64
import lzma as _lzma

try:                          # one-file build: the tables are inlined above
    M68K_NAMES, M68K_TABLES
except NameError:
    from m68k_tables import M68K_NAMES, M68K_TABLES

# Musashi m68ki_exception_cycle_table[0] (68000)
_CYC_EXC = ([40, 4, 50, 50, 34, 38, 40, 34, 34, 34, 34, 34, 4, 4, 4, 44] + [4] * 8 + [44] * 8 + [34] * 16
            + [4] * 208)
_SIZES = {"8": (8, "0xFF", 0, "0xFFFFFF00"), "16": (16, "0xFFFF", 8, "0xFFFF0000"),
          "32": (32, "0xFFFFFFFF", 24, "0")}
_CONDS = {
    "t": "True", "f": "False",
    "hi": "(not (fC & 0x100) and fZ)", "ls": "((fC & 0x100) or not fZ)",
    "cc": "(not (fC & 0x100))", "cs": "(fC & 0x100)",
    "ne": "fZ", "eq": "(not fZ)",
    "vc": "(not (fV & 0x80))", "vs": "(fV & 0x80)",
    "pl": "(not (fN & 0x80))", "mi": "(fN & 0x80)",
    "ge": "(not ((fN ^ fV) & 0x80))", "lt": "((fN ^ fV) & 0x80)",
    "gt": "(not ((fN ^ fV) & 0x80) and fZ)", "le": "(((fN ^ fV) & 0x80) or not fZ)",
}
_STATE = ("fN", "fZ", "fV", "fC", "fX", "fS", "T1", "T0", "IMASK", "pc", "rem", "tracing", "stopped",
          "run_mode", "instr_mode", "INT_LEVEL", "nmi_pending", "aerr_addr", "aerr_mode", "aerr_fc",
          "reset_cycles", "initial", "ppc", "ir")


def _ea(mode, sz, r):
    """Lines computing `ea` (Musashi EA_xx_MODE_SZ), r = 'ay' or 'ax' (register index variable)."""
    n = sz // 8
    if mode == "ai":
        return [f"ea = R[{r}]"]
    if mode == "pi":
        return [f"ea = R[{r}]", f"R[{r}] = (ea + {n}) & 0xFFFFFFFF"]
    if mode == "pi7":
        return ["ea = R[15]", "R[15] = (ea + 2) & 0xFFFFFFFF"]
    if mode == "pd":
        return [f"ea = R[{r}] = (R[{r}] - {n}) & 0xFFFFFFFF"]
    if mode == "pd7":
        return ["ea = R[15] = (R[15] - 2) & 0xFFFFFFFF"]
    if mode == "di":
        return ["d = imm16()", f"ea = (R[{r}] + d - ((d & 0x8000) << 1)) & 0xFFFFFFFF"]
    if mode == "ix":
        return [f"ea = ix(R[{r}])"]
    if mode == "aw":
        return ["d = imm16()", "ea = (d - ((d & 0x8000) << 1)) & 0xFFFFFFFF"]
    if mode == "al":
        return ["ea = imm32()"]
    if mode == "pcdi":
        return ["ea = pc", "d = imm16()", "ea = (ea + d - ((d & 0x8000) << 1)) & 0xFFFFFFFF"]
    if mode == "pcix":
        return ["ea = ix(pc)"]
    raise ValueError(mode)


def _rd(mode, sz):
    """Read at `ea` for an operand in `mode` (PC-relative = program space)."""
    if sz == 8:
        return "rd8(ea)"
    return f"rdp{sz}(ea)" if mode in ("pcdi", "pcix") else f"rd{sz}(ea)"


def _oper(mode, sz, var, r="ay", d="dy"):
    """Lines putting the operand (Musashi OPER_xx_MODE_SZ, or the register) into `var`."""
    mask = _SIZES[str(sz)][1]
    if mode == "d":
        return [f"{var} = R[{d}]" + ("" if sz == 32 else f" & {mask}")]
    if mode == "a":
        return [f"{var} = R[{r}]" + ("" if sz == 32 else f" & {mask}")]
    if mode == "i":
        return [f"{var} = " + {8: "imm16() & 0xFF", 16: "imm16()", 32: "imm32()"}[sz]]
    return _ea(mode, sz, r) + [f"{var} = {_rd(mode, sz)}"]


def _wr(sz, ea, val):
    return f"wr{sz}({ea}, {val})"


def _store_d(sz, reg, val):
    """Musashi *r_dst = MASK_OUT_BELOW_n(*r_dst) | val."""
    if sz == 32:
        return f"R[{reg}] = {val}"
    return f"R[{reg}] = (R[{reg}] & {_SIZES[str(sz)][3]}) | {val}"


def _flags_logic(sz, res):
    sh = _SIZES[str(sz)][2]
    return [f"fN = {res} >> {sh}" if sh else f"fN = {res}", f"fZ = {res}", "fC = 0", "fV = 0"]


def _carry(sz, r):
    """Musashi CFLAG_8/16 and, for 32 bits, CFLAG_ADD_32/SUB_32: bit 8 = carry / borrow out.
    r is the unmasked Python result (s + d, d - s), so its bit 8/16/32 is the carry."""
    return {8: r, 16: f"{r} >> 8", 32: f"{r} >> 24"}[sz]


def _gen(name):
    """Python source of the handler factory for one Musashi handler."""
    t = name.split("_")
    fam = t[0]
    L = []                                   # body lines (inside h())
    add = L.extend

    def size():
        return int(t[1])

    # ---------------------------------------------------------------- arithmetic / logic
    if fam in ("add", "sub", "cmp", "and", "or", "eor") and len(t) >= 3:
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]
        if fam == "eor":                                   # eor_SZ_MODE (Dx -> <ea>)
            mode = t[2]
            if mode == "d":
                add(["R[dy] ^= R[dx]" + ("" if sz == 32 else f" & {mask}"),
                     "res = R[dy]" + ("" if sz == 32 else f" & {mask}")] + _flags_logic(sz, "res"))
            else:
                add(_ea(mode, sz, "ay") + [f"res = (R[dx] ^ rd{sz}(ea)) & {mask}", _wr(sz, "ea", "res")]
                    + _flags_logic(sz, "res"))
        elif fam == "cmp":                                 # cmp_SZ_MODE
            mode = t[2]
            add(_oper(mode, sz, "s") + [f"dd = R[dx] & {mask}", "r = dd - s",
                f"fN = r >> {sh}" if sh else "fN = r", f"fZ = r & {mask}",
                f"fV = ((s ^ dd) & (r ^ dd)) >> {sh}" if sh else "fV = (s ^ dd) & (r ^ dd)",
                f"fC = {_carry(sz, 'r')}"])
        else:
            direction, mode = t[2], t[3]
            if direction == "er":
                add(_oper(mode, sz, "s"))
                if fam in ("add", "sub"):
                    op = "+" if fam == "add" else "-"
                    vf = "((s ^ r) & (dd ^ r))" if fam == "add" else "((s ^ dd) & (r ^ dd))"
                    add([f"dd = R[dx] & {mask}", f"r = dd {op} s",
                         f"fN = r >> {sh}" if sh else "fN = r",
                         f"fV = {vf} >> {sh}" if sh else f"fV = {vf}",
                         f"fX = fC = {_carry(sz, 'r')}", f"fZ = r & {mask}", _store_d(sz, "dx", "fZ")])
                elif fam == "and":
                    add([f"R[dx] &= s | {hi}" if sz != 32 else "R[dx] &= s",
                         f"fZ = R[dx] & {mask}", f"fN = fZ >> {sh}" if sh else "fN = fZ", "fC = 0", "fV = 0"])
                else:  # or
                    add(["R[dx] |= s", f"res = R[dx] & {mask}"] + _flags_logic(sz, "res"))
            else:                                          # re: Dx op <ea> -> <ea>
                add(_ea(mode, sz, "ay"))
                if fam in ("add", "sub"):
                    op = "+" if fam == "add" else "-"
                    vf = "((s ^ r) & (dd ^ r))" if fam == "add" else "((s ^ dd) & (r ^ dd))"
                    add([f"s = R[dx] & {mask}" if sz != 32 else "s = R[dx]", f"dd = rd{sz}(ea)", f"r = dd {op} s",
                         f"fN = r >> {sh}" if sh else "fN = r",
                         f"fV = {vf} >> {sh}" if sh else f"fV = {vf}",
                         f"fX = fC = {_carry(sz, 'r')}", f"fZ = r & {mask}", _wr(sz, "ea", "fZ")])
                elif fam == "and":
                    add([f"res = R[dx] & rd{sz}(ea)"] + _flags_logic(sz, "res") + [_wr(sz, "ea", "res")])
                else:  # or: write then flags
                    add([f"res = (R[dx] | rd{sz}(ea)) & {mask}", _wr(sz, "ea", "res")] + _flags_logic(sz, "res"))

    elif fam in ("adda", "suba", "cmpa"):
        sz = size(); mode = t[2]
        op = "+" if fam == "adda" else "-"
        add(_oper(mode, sz, "s"))
        if sz == 16:
            add(["s = (s - ((s & 0x8000) << 1)) & 0xFFFFFFFF"])
        if fam == "cmpa":
            add(["dd = R[ax]", "r = dd - s", "fN = r >> 24", "fZ = r & 0xFFFFFFFF",
                 "fV = ((s ^ dd) & (r ^ dd)) >> 24", "fC = r >> 24"])
        else:
            add([f"R[ax] = (R[ax] {op} s) & 0xFFFFFFFF"])

    elif fam in ("addi", "subi", "andi", "ori", "eori", "cmpi") and t[2] not in ("toc", "tos"):
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; mode = t[2]
        add(_oper("i", sz, "s"))
        if fam == "cmpi":
            add(_oper(mode, sz, "dd") + ["r = dd - s", f"fN = r >> {sh}" if sh else "fN = r", f"fZ = r & {mask}",
                 f"fV = ((s ^ dd) & (r ^ dd)) >> {sh}" if sh else "fV = (s ^ dd) & (r ^ dd)",
                 f"fC = {_carry(sz, 'r')}"])
        elif fam in ("addi", "subi"):
            op = "+" if fam == "addi" else "-"
            vf = "((s ^ r) & (dd ^ r))" if fam == "addi" else "((s ^ dd) & (r ^ dd))"
            if mode == "d":
                add([f"dd = R[dy] & {mask}" if sz != 32 else "dd = R[dy]"])
            else:
                add(_ea(mode, sz, "ay") + [f"dd = rd{sz}(ea)"])
            add([f"r = dd {op} s", f"fN = r >> {sh}" if sh else "fN = r",
                 f"fV = {vf} >> {sh}" if sh else f"fV = {vf}",
                 f"fX = fC = {_carry(sz, 'r')}", f"fZ = r & {mask}",
                 _store_d(sz, "dy", "fZ") if mode == "d" else _wr(sz, "ea", "fZ")])
        else:
            op = {"andi": "&", "ori": "|", "eori": "^"}[fam]
            if mode == "d":
                if fam == "andi":
                    add([f"R[dy] &= s | {hi}" if sz != 32 else "R[dy] &= s",
                         f"fZ = R[dy] & {mask}", f"fN = fZ >> {sh}" if sh else "fN = fZ", "fC = 0", "fV = 0"])
                else:
                    add([f"R[dy] {op}= s", f"res = R[dy] & {mask}"] + _flags_logic(sz, "res"))
            else:
                add(_ea(mode, sz, "ay") + [f"res = s {op} rd{sz}(ea)"])
                if fam == "andi":
                    add(_flags_logic(sz, "res") + [_wr(sz, "ea", "res")])
                else:
                    add([_wr(sz, "ea", "res")] + _flags_logic(sz, "res"))

    elif fam in ("andi", "ori", "eori"):                   # to CCR / SR
        op = {"andi": "&", "ori": "|", "eori": "^"}[fam]
        if t[2] == "toc":
            add([f"set_ccr(get_ccr() {op} (imm16() & 0xFF))"])
        else:
            add(["if fS:", "    s = imm16()", f"    set_sr(get_sr() {op} s)", "else:", "    exception_privilege()"])

    elif fam in ("addq", "subq"):
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; mode = t[2]
        op = "+" if fam == "addq" else "-"
        if mode == "a":
            add([f"R[ay] = (R[ay] {op} q) & 0xFFFFFFFF"])
        else:
            vf = "((s ^ r) & (dd ^ r))" if fam == "addq" else "((s ^ dd) & (r ^ dd))"
            add(["s = q"])
            if mode == "d":
                add([f"dd = R[dy] & {mask}" if sz != 32 else "dd = R[dy]"])
            else:
                add(_ea(mode, sz, "ay") + [f"dd = rd{sz}(ea)"])
            add([f"r = dd {op} s", f"fN = r >> {sh}" if sh else "fN = r",
                 f"fV = {vf} >> {sh}" if sh else f"fV = {vf}",
                 f"fX = fC = {_carry(sz, 'r')}", f"fZ = r & {mask}",
                 _store_d(sz, "dy", "fZ") if mode == "d" else _wr(sz, "ea", "fZ")])

    elif fam in ("addx", "subx"):
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]
        op = "+" if fam == "addx" else "-"
        vf = "((s ^ r) & (dd ^ r))" if fam == "addx" else "((s ^ dd) & (r ^ dd))"
        if t[2] == "rr":
            add([f"s = R[dy] & {mask}" if sz != 32 else "s = R[dy]", f"dd = R[dx] & {mask}" if sz != 32 else "dd = R[dx]"])
        else:
            v = t[3] if len(t) > 3 else ""
            add(_oper("pd7" if v in ("ay7", "axy7") else "pd", sz, "s"))
            add(_ea("pd7" if v in ("ax7", "axy7") else "pd", sz, "ax") + [f"dd = rd{sz}(ea)"])
        add([f"r = dd {op} s {op} ((fX >> 8) & 1)", f"fN = r >> {sh}" if sh else "fN = r",
             f"fV = {vf} >> {sh}" if sh else f"fV = {vf}", f"fX = fC = {_carry(sz, 'r')}",
             f"r &= {mask}", "fZ |= r", _store_d(sz, "dx", "r") if t[2] == "rr" else _wr(sz, "ea", "r")])

    elif fam in ("abcd", "sbcd"):
        if t[2] == "rr":
            add(["s = R[dy]", "dd = R[dx]"])
        else:
            v = t[3] if len(t) > 3 else ""
            add(_oper("pd7" if v in ("ay7", "axy7") else "pd", 8, "s"))
            add(_ea("pd7" if v in ("ax7", "axy7") else "pd", 8, "ax") + ["dd = rd8(ea)"])
        if fam == "abcd":
            add(["r = (s & 0x0F) + (dd & 0x0F) + ((fX >> 8) & 1)", "fV = ~r", "if r > 9:", "    r += 6",
                 "r += (s & 0xF0) + (dd & 0xF0)", "fX = fC = (r > 0x99) << 8", "if fC:", "    r -= 0xA0"])
        else:  # C unsigned arithmetic: keep r modulo 2^32
            add(["r = ((dd & 0x0F) - (s & 0x0F) - ((fX >> 8) & 1)) & 0xFFFFFFFF", "fV = ~r", "if r > 9:",
                 "    r = (r - 6) & 0xFFFFFFFF", "r = (r + (dd & 0xF0) - (s & 0xF0)) & 0xFFFFFFFF",
                 "fX = fC = (r > 0x99) << 8", "if fC:", "    r = (r + 0xA0) & 0xFFFFFFFF"])
        if fam == "abcd":
            add(["fV &= r", "fN = r", "r &= 0xFF"])
        else:
            add(["r &= 0xFF", "fV &= r", "fN = r"])
        add(["fZ |= r", _store_d(8, "dx", "r") if t[2] == "rr" else "wr8(ea, r)"])

    elif fam == "nbcd":
        mode = t[2]
        if mode == "d":
            add(["dd = R[dy]"])
        else:
            add(_ea(mode, 8, "ay") + ["dd = rd8(ea)"])
        add(["r = (0x9A - dd - ((fX >> 8) & 1)) & 0xFF", "if r != 0x9A:", "    fV = ~r",
             "    if (r & 0x0F) == 0x0A:", "        r = (r & 0xF0) + 0x10", "    r &= 0xFF", "    fV &= r",
             "    " + (_store_d(8, "dy", "r") if mode == "d" else "wr8(ea, r)"),
             "    fZ |= r", "    fC = fX = 0x100", "else:", "    fV = 0", "    fC = fX = 0", "fN = r"])

    elif fam == "cmpm":
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]
        v = t[2] if len(t) > 2 else ""
        add(_oper("pi7" if v in ("ay7", "axy7") else "pi", sz, "s"))
        add(_oper("pi7" if v in ("ax7", "axy7") else "pi", sz, "dd", r="ax"))
        add(["r = dd - s", f"fN = r >> {sh}" if sh else "fN = r", f"fZ = r & {mask}",
             f"fV = ((s ^ dd) & (r ^ dd)) >> {sh}" if sh else "fV = (s ^ dd) & (r ^ dd)", f"fC = {_carry(sz, 'r')}"])

    # ---------------------------------------------------------------- single operand
    elif fam in ("neg", "negx"):
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; mode = t[2]
        if mode == "d":
            add(["src = R[dy]"])
        else:
            add(_ea(mode, sz, "ay") + [f"src = rd{sz}(ea)"])
        x = " - ((fX >> 8) & 1)" if fam == "negx" else ""
        add([f"r = 0 - (src & {mask}){x}", f"fN = r >> {sh}" if sh else "fN = r"])
        if sz == 32:   # CFLAG_SUB_32(src, 0, res) = (src | res) >> 23
            add(["fX = fC = (src | (r & 0xFFFFFFFF)) >> 23"])
        else:
            add([f"fX = fC = {_carry(sz, 'r')}"])
        add([f"fV = (src & r) >> {sh}" if sh else "fV = src & r", f"r &= {mask}"])
        add(["fZ |= r" if fam == "negx" else "fZ = r",
             _store_d(sz, "dy", "r") if mode == "d" else _wr(sz, "ea", "r")])

    elif fam == "not":
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; mode = t[2]
        if mode == "d":
            add([f"res = ~R[dy] & {mask}", _store_d(sz, "dy", "res")] + _flags_logic(sz, "res"))
        else:
            add(_ea(mode, sz, "ay") + [f"res = ~rd{sz}(ea) & {mask}", _wr(sz, "ea", "res")] + _flags_logic(sz, "res"))

    elif fam == "clr":
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; mode = t[2]
        if mode == "d":
            add([f"R[dy] &= {hi}"])
        else:
            add(_ea(mode, sz, "ay") + [_wr(sz, "ea", "0")])
        add(["fN = 0", "fV = 0", "fC = 0", "fZ = 0"])

    elif fam == "tst":
        sz = size(); mode = t[2]
        add(_oper(mode, sz, "res") + _flags_logic(sz, "res"))

    elif fam == "tas":
        mode = t[2]
        if mode == "d":
            add(["fZ = R[dy] & 0xFF", "fN = fZ", "fV = 0", "fC = 0", "R[dy] |= 0x80"])
        else:
            add(_ea(mode, 8, "ay") + ["dd = rd8(ea)", "fZ = dd", "fN = dd", "fV = 0", "fC = 0", "wr8(ea, dd | 0x80)"])

    elif fam[0] == "s" and fam[1:] in _CONDS and t[1] == "8":   # Scc
        cond = _CONDS[fam[1:]]; mode = t[2]
        if mode == "d":
            if fam == "st":
                add(["R[dy] |= 0xFF"])
            elif fam == "sf":
                add(["R[dy] &= 0xFFFFFF00"])
            else:
                add([f"if {cond}:", "    R[dy] |= 0xFF", "    rem -= 2", "else:", "    R[dy] &= 0xFFFFFF00"])
        else:
            val = {"st": "0xFF", "sf": "0"}.get(fam, f"(0xFF if {cond} else 0)")
            add(_ea(mode, 8, "ay") + [f"wr8(ea, {val})"])

    # ---------------------------------------------------------------- bits
    elif fam in ("btst", "bchg", "bclr", "bset"):
        sz = size(); kind, mode = t[2], t[3]
        if sz == 32:   # data register, bit modulo 32
            add(["m = 1 << (R[dx] & 31)" if kind == "r" else "m = 1 << (imm16() & 31)"])
            if fam == "btst":
                add(["fZ = R[dy] & m"])
            else:
                add(["fZ = R[dy] & m", {"bchg": "R[dy] ^= m", "bclr": "R[dy] &= ~m", "bset": "R[dy] |= m"}[fam]])
        elif fam == "btst":
            if kind == "r":
                add(_oper(mode, 8, "v") + ["fZ = v & (1 << (R[dx] & 7))"])
            else:
                add(["b = imm16() & 7"] + _oper(mode, 8, "v") + ["fZ = v & (1 << b)"])
        else:
            if kind == "s":
                add(["m = 1 << (imm16() & 7)"] + _ea(mode, 8, "ay") + ["v = rd8(ea)"])
            else:
                add(_ea(mode, 8, "ay") + ["v = rd8(ea)", "m = 1 << (R[dx] & 7)"])
            add(["fZ = v & m", "wr8(ea, " + {"bchg": "v ^ m", "bclr": "v & ~m", "bset": "v | m"}[fam] + ")"])

    # ---------------------------------------------------------------- shifts / rotates
    elif fam in ("asl", "asr", "lsl", "lsr", "rol", "ror", "roxl", "roxr") and t[2] not in ("r", "s"):
        mode = t[2]                                         # memory, word, shift by 1
        add(_ea(mode, 16, "ay") + ["src = rd16(ea)"])
        if fam == "asl":
            add(["res = (src << 1) & 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res", "fX = fC = src >> 7",
                 "src &= 0xC000", "fV = 0 if (src == 0 or src == 0xC000) else 0x80"])
        elif fam == "asr":
            add(["res = src >> 1", "if src & 0x8000:", "    res |= 0x8000", "wr16(ea, res)", "fN = res >> 8",
                 "fZ = res", "fV = 0", "fC = fX = src << 8"])
        elif fam == "lsl":
            add(["res = (src << 1) & 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res", "fX = fC = src >> 7", "fV = 0"])
        elif fam == "lsr":
            add(["res = src >> 1", "wr16(ea, res)", "fN = 0", "fZ = res", "fC = fX = src << 8", "fV = 0"])
        elif fam == "rol":
            add(["res = ((src << 1) | (src >> 15)) & 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res",
                 "fC = src >> 7", "fV = 0"])
        elif fam == "ror":
            add(["res = ((src >> 1) | (src << 15)) & 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res",
                 "fC = src << 8", "fV = 0"])
        elif fam == "roxl":
            add(["v = src | (((fX >> 8) & 1) << 16)", "res = (v << 1) | (v >> 16)", "fC = fX = res >> 8",
                 "res &= 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res", "fV = 0"])
        else:
            add(["v = src | (((fX >> 8) & 1) << 16)", "res = (v >> 1) | (v << 16)", "fC = fX = res >> 8",
                 "res &= 0xFFFF", "wr16(ea, res)", "fN = res >> 8", "fZ = res", "fV = 0"])

    elif fam in ("asl", "asr", "lsl", "lsr", "rol", "ror", "roxl", "roxr"):
        add(_shift_reg(fam, int(t[1]), t[2]))

    # ---------------------------------------------------------------- moves
    elif fam == "move" and t[2] in ("frs", "toc", "tos", "fru", "tou"):
        kind = t[2]; mode = t[3] if len(t) > 3 else None
        if kind == "frs":   # 68000: not privileged
            if mode == "d":
                add(["R[dy] = (R[dy] & 0xFFFF0000) | get_sr()"])
            else:
                add(_ea(mode, 16, "ay") + ["wr16(ea, get_sr())"])
        elif kind == "toc":
            add(_oper(mode, 16, "v") + ["set_ccr(v)"])
        elif kind == "tos":
            add(["if fS:"] + ["    " + x for x in _oper(mode, 16, "v")] + ["    set_sr(v)", "else:",
                 "    exception_privilege()"])
        elif kind == "fru":
            add(["if fS:", "    R[ay] = SPB[0]", "else:", "    exception_privilege()"])
        else:
            add(["if fS:", "    SPB[0] = R[ay]", "else:", "    exception_privilege()"])

    elif fam == "move":
        sz = size(); sb, mask, sh, hi = _SIZES[t[1]]; dmode, smode = t[2], t[3]
        add(_oper(smode, sz, "res"))
        if dmode == "d":
            add([_store_d(sz, "dx", "res")])
        else:
            add(_ea(dmode, sz, "ax"))
            if sz == 32 and dmode == "pd":          # MOVE.L -(An): low word first (Musashi)
                add(["wr16((ea + 2) & 0xFFFFFFFF, res & 0xFFFF)", "wr16(ea, res >> 16)"])
            else:
                add([_wr(sz, "ea", "res")])
        add(_flags_logic(sz, "res"))

    elif fam == "movea":
        sz = size(); mode = t[2]
        add(_oper(mode, sz, "v"))
        add(["R[ax] = (v - ((v & 0x8000) << 1)) & 0xFFFFFFFF" if sz == 16 else "R[ax] = v"])

    elif fam == "moveq":
        add(["res = R[dx] = q8", "fN = res >> 24", "fZ = res", "fV = 0", "fC = 0"])

    elif fam == "movem":
        sz = size(); direction, mode = t[2], t[3]
        n = sz // 8
        add(["lst = imm16()"])
        if mode in ("pi", "pd"):
            add(["ea = R[ay]"])
        else:
            add(_ea(mode, sz, "ay"))
        add(["count = 0", "i = 0", "while lst:", "    if lst & 1:"])
        if direction == "er":
            rd = (f"rdp{sz}(ea)" if mode in ("pcdi", "pcix") else f"rd{sz}(ea)")
            if sz == 16:
                add([f"        v = {rd}", "        R[i] = (v - ((v & 0x8000) << 1)) & 0xFFFFFFFF"])
            else:
                add([f"        R[i] = {rd}"])
            add([f"        ea = (ea + {n}) & 0xFFFFFFFF", "        count += 1"])
        elif mode == "pd":
            add([f"        ea = (ea - {n}) & 0xFFFFFFFF"])
            if sz == 16:
                add(["        wr16(ea, R[15 - i] & 0xFFFF)"])
            else:
                add(["        wr16((ea + 2) & 0xFFFFFFFF, R[15 - i] & 0xFFFF)", "        wr16(ea, R[15 - i] >> 16)"])
            add(["        count += 1"])
        else:
            add([f"        wr{sz}(ea, R[i]" + (" & 0xFFFF)" if sz == 16 else ")"),
                 f"        ea = (ea + {n}) & 0xFFFFFFFF", "        count += 1"])
        add(["    lst >>= 1", "    i += 1"])
        if mode in ("pi", "pd"):
            add(["R[ay] = ea"])
        add([f"rem -= count << {2 if sz == 16 else 3}"])

    elif fam == "movep":
        sz = size(); direction = t[2]
        add(_ea("di", sz, "ay"))
        if direction == "er":
            if sz == 16:
                add(["v = rd8(ea) << 8", "v += rd8((ea + 2) & 0xFFFFFFFF)", "R[dx] = (R[dx] & 0xFFFF0000) | v"])
            else:
                add(["v = rd8(ea) << 24", "v += rd8((ea + 2) & 0xFFFFFFFF) << 16", "v += rd8((ea + 4) & 0xFFFFFFFF) << 8",
                     "v += rd8((ea + 6) & 0xFFFFFFFF)", "R[dx] = v"])
        else:
            add(["s = R[dx]"])
            shifts = (8, 0) if sz == 16 else (24, 16, 8, 0)
            for k, shf in enumerate(shifts):
                add([f"wr8((ea + {2 * k}) & 0xFFFFFFFF, (s >> {shf}) & 0xFF)" if k else f"wr8(ea, (s >> {shf}) & 0xFF)"])

    elif fam == "move16":
        add(["w2 = imm16()", "rx_ = 8 + (ir & 7)", "ry_ = 8 + ((w2 >> 12) & 7)",
             "wr32(R[ry_], rd32(R[rx_]))", "wr32((R[ry_] + 4) & 0xFFFFFFFF, rd32((R[rx_] + 4) & 0xFFFFFFFF))",
             "wr32((R[ry_] + 8) & 0xFFFFFFFF, rd32((R[rx_] + 8) & 0xFFFFFFFF))",
             "wr32((R[ry_] + 12) & 0xFFFFFFFF, rd32((R[rx_] + 12) & 0xFFFFFFFF))",
             "R[rx_] = (R[rx_] + 16) & 0xFFFFFFFF", "R[ry_] = (R[ry_] + 16) & 0xFFFFFFFF"])

    # ---------------------------------------------------------------- multiply / divide / chk
    elif fam in ("mulu", "muls"):
        mode = t[2]
        add(_oper(mode, 16, "x"))
        if fam == "mulu":
            add(["rem -= bin(x).count('1') << 1", "res = x * (R[dx] & 0xFFFF)"])
        else:
            add(["x = (x - ((x & 0x8000) << 1)) & 0xFFFFFFFF",
                 "rem -= bin((x ^ (x << 1)) & ((1 << x.bit_length()) - 1)).count('1') << 1",
                 "dd = R[dx] & 0xFFFF", "res = (x * (dd - ((dd & 0x8000) << 1))) & 0xFFFFFFFF"])
        add(["R[dx] = res", "fZ = res", "fN = res >> 24", "fV = 0", "fC = 0"])

    elif fam == "divu":
        add(_oper(t[2], 16, "s") + ["if s:", "    dd = R[dx]", "    qu = dd // s", "    if qu < 0x10000:",
             "        fZ = qu", "        fN = qu >> 8", "        fV = 0", "        fC = 0",
             "        R[dx] = (qu | ((dd % s) << 16)) & 0xFFFFFFFF", "    else:", "        fV = 0x80",
             "else:", "    exception_trap(5)"])

    elif fam == "divs":
        add(_oper(t[2], 16, "s") + ["s -= (s & 0x8000) << 1", "if s:",
             "    if R[dx] == 0x80000000 and s == -1:", "        fZ = 0", "        fN = 0", "        fV = 0",
             "        fC = 0", "        R[dx] = 0", "    else:",
             "        dd = R[dx] - ((R[dx] & 0x80000000) << 1)",
             "        qu = abs(dd) // abs(s)", "        if (dd < 0) != (s < 0):", "            qu = -qu",
             "        rm = dd - qu * s",
             "        if -0x8000 <= qu <= 0x7FFF:", "            fZ = qu & 0xFFFFFFFF", "            fN = qu >> 8",
             "            fV = 0", "            fC = 0", "            R[dx] = ((qu & 0xFFFF) | (rm << 16)) & 0xFFFFFFFF",
             "        else:", "            fV = 0x80", "else:", "    exception_trap(5)"])

    elif fam == "chk":
        add(["src = R[dx] & 0xFFFF", "src -= (src & 0x8000) << 1"] + _oper(t[2], 16, "b")
            + ["b -= (b & 0x8000) << 1", "fZ = src & 0xFFFF", "fV = 0", "fC = 0", "if not (0 <= src <= b):",
               "    fN = 0x80 if src < 0 else 0", "    exception_trap(6)"])

    # ---------------------------------------------------------------- flow
    elif fam in ("bra", "bsr") or (fam[0] == "b" and fam[1:] in _CONDS and len(t) == 2):
        long_ = t[1] == "16"
        if fam == "bsr":
            if long_:
                add(["off = imm16()", "push32(pc)", "pc = (pc - 2 + off - ((off & 0x8000) << 1)) & 0xFFFFFFFF"])
            else:
                add(["push32(pc)", "pc = (pc + q8) & 0xFFFFFFFF"])
        elif fam == "bra":
            if long_:
                add(["off = imm16()", "pc = (pc - 2 + off - ((off & 0x8000) << 1)) & 0xFFFFFFFF"])
            else:
                add(["pc = (pc + q8) & 0xFFFFFFFF"])
            add(["if pc == ppc:", "    rem = cmod(rem, CYC[ir])"])
        else:
            cond = _CONDS[fam[1:]]
            if long_:
                add([f"if {cond}:", "    off = imm16()", "    pc = (pc - 2 + off - ((off & 0x8000) << 1)) & 0xFFFFFFFF",
                     "else:", "    pc = (pc + 2) & 0xFFFFFFFF", "    rem -= 2"])
            else:
                add([f"if {cond}:", "    pc = (pc + q8) & 0xFFFFFFFF", "else:", "    rem += 2"])

    elif fam.startswith("db"):
        cond = fam[2:]
        dbf = ["v = (R[dy] - 1) & 0xFFFF", "R[dy] = (R[dy] & 0xFFFF0000) | v", "if v != 0xFFFF:",
               "    off = imm16()", "    pc = (pc - 2 + off - ((off & 0x8000) << 1)) & 0xFFFFFFFF", "    rem += 2",
               "else:", "    pc = (pc + 2) & 0xFFFFFFFF", "    rem -= 2"]
        if cond == "f":
            add(dbf)
        elif cond == "t":
            add(["pc = (pc + 2) & 0xFFFFFFFF"])
        else:
            add([f"if not {_CONDS[cond]}:"] + ["    " + x for x in dbf] + ["else:", "    pc = (pc + 2) & 0xFFFFFFFF"])

    elif fam in ("jmp", "jsr", "lea", "pea"):
        add(_ea(t[2], 32, "ay"))
        add({"jmp": ["pc = ea", "if pc == ppc:", "    rem = cmod(rem, CYC[ir])"],
             "jsr": ["push32(pc)", "pc = ea"], "lea": ["R[ax] = ea"], "pea": ["push32(ea)"]}[fam])

    elif fam == "link":
        if len(t) > 2:   # a7
            add(["R[15] = (R[15] - 4) & 0xFFFFFFFF", "wr32(R[15], R[15])"])
        else:
            add(["push32(R[ay])", "R[ay] = R[15]"])
        add(["d = imm16()", "R[15] = (R[15] + d - ((d & 0x8000) << 1)) & 0xFFFFFFFF"])
    elif fam == "unlk":
        if len(t) > 2:
            add(["R[15] = rd32(R[15])"])
        else:
            add(["R[15] = R[ay]", "R[ay] = pull32()"])
    elif fam == "rts":
        add(["pc = pull32()"])
    elif fam == "rtr":
        add(["set_ccr(pull16())", "pc = pull32()"])
    elif fam == "rte":
        add(["if fS:", "    nsr = pull16()", "    npc = pull32()", "    pc = npc", "    set_sr(nsr)",
             "    instr_mode = 0", "    run_mode = 0", "else:", "    exception_privilege()"])
    elif fam == "trap":
        add(["exception_trapN(32 + (ir & 15))"])
    elif fam == "trapv":
        add(["if fV & 0x80:", "    exception_trap(7)"])
    elif fam in ("illegal",) or name == "x_illegal":
        add(["exception_illegal()"])
    elif fam == "1010":
        add(["exception_line(10)"])
    elif fam == "1111" or name == "x_1111":
        add(["exception_line(11)"])
    elif fam == "nop":
        add(["pass"])
    elif fam == "stop":
        add(["if fS:", "    nsr = imm16()", "    stopped |= 1", "    set_sr(nsr)", "    c = CYC[ir]",
             "    if rem >= c:", "        rem = c", "    else:", "        rem = cmod(rem, c)", "else:",
             "    exception_privilege()"])
    elif fam == "reset":
        add(["if fS:", "    reset_cb()", "    rem -= 132", "else:", "    exception_privilege()"])
    elif fam == "ext":
        if t[1] == "16":
            add(["v = R[dy]", "v = (v & 0xFFFF0000) | (v & 0xFF) | (0xFF00 if v & 0x80 else 0)", "R[dy] = v",
                 "fN = v >> 8", "fZ = v & 0xFFFF", "fV = 0", "fC = 0"])
        else:
            add(["v = R[dy]", "v = (v & 0xFFFF) | (0xFFFF0000 if v & 0x8000 else 0)", "R[dy] = v",
                 "fN = v >> 24", "fZ = v", "fV = 0", "fC = 0"])
    elif fam == "swap":
        add(["v = R[dy]", "v = ((v << 16) & 0xFFFFFFFF) | (v >> 16)", "R[dy] = v", "fZ = v", "fN = v >> 24",
             "fC = 0", "fV = 0"])
    elif fam == "exg":
        a, b = {"dd": ("dx", "dy"), "aa": ("ax", "ay"), "da": ("dx", "ay")}[t[2]]
        add([f"R[{a}], R[{b}] = R[{b}], R[{a}]"])
    else:
        raise ValueError(f"no Python handler for {name}")
    return L


def _shift_reg(fam, sz, kind):
    """Register shifts and rotates (Musashi asl_8_s ... roxr_32_r), ported line by line."""
    sb, mask, sh, hi = _SIZES[str(sz)]
    tbl = f"SH{sz}"
    L = []
    if kind == "s":
        L.append("shift = q")
    else:
        L.append("shift = R[dx] & 0x3F")
    src = f"src = R[dy] & {mask}" if sz != 32 else "src = R[dy]"
    N = (lambda v: f"fN = {v} >> {sh}" if sh else f"fN = {v}")
    st = (lambda v: _store_d(sz, "dy", v))
    if fam in ("asl", "lsl"):
        L += [src, f"res = (src << shift) & {mask}"]
        if kind == "s":
            L += ["rem -= shift << 1", st("res"), N("res"), "fZ = res"]
            L += [{8: "fX = fC = src << shift", 16: "fX = fC = src >> (8 - shift)",
                   32: "fX = fC = src >> (24 - shift)"}[sz]]
            if fam == "asl":
                L += [f"t = {tbl}[shift + 1]", "src &= t"]
                L += ["fV = 0 if (src == 0 or (src == t and shift < 8)) else 0x80" if sz == 8 else
                      "fV = 0 if (src == 0 or src == t) else 0x80"]
            else:
                L += ["fV = 0"]
            return L
        lim = sz if (fam == "asl" or sz == 32) else sz + 1     # asl: < sz ; lsl 8/16: <= sz ; lsl 32: < 32
        L += ["if shift:", "    rem -= shift << 1", f"    if shift < {lim}:", "        " + st("res"),
              "        fX = fC = " + {8: "src << shift", 16: "(src << shift) >> 8", 32: "(src >> (32 - shift)) << 8"}[sz],
              "        " + N("res"), "        fZ = res"]
        if fam == "asl":
            L += [f"        t = {tbl}[shift + 1]", "        src &= t",
                  "        fV = 0 if (src == 0 or src == t) else 0x80", "    else:",
                  "        R[dy] &= " + (hi if sz != 32 else "0"),
                  f"        fX = fC = (src & 1) << 8 if shift == {sz} else 0",
                  "        fN = 0", "        fZ = 0", "        fV = 0 if src == 0 else 0x80"]
        else:
            L += ["        fV = 0", "    else:", "        R[dy] &= " + (hi if sz != 32 else "0")]
            if sz == 32:
                L += ["        fX = fC = (src & 1) << 8 if shift == 32 else 0"]
            else:
                L += ["        fX = fC = 0"]
            L += ["        fN = 0", "        fZ = 0", "        fV = 0"]
        L += ["else:", "    fC = 0", "    " + N("src"), "    fZ = src", "    fV = 0"]
        return L
    if fam in ("asr", "lsr"):
        L += [src, "res = src >> shift"]
        if kind == "s":
            L += ["rem -= shift << 1"]
            if fam == "asr":
                L += [f"if src & {hex(1 << (sz - 1))}:", f"    res |= {tbl}[shift]", st("res"), N("res"), "fZ = res",
                      "fV = 0", "fX = fC = src << (9 - shift)"]
            else:
                L += [st("res"), "fN = 0", "fZ = res", "fX = fC = src << (9 - shift)", "fV = 0"]
            return L
        msb = hex(1 << (sz - 1))
        if fam == "asr":
            L += ["if shift:", "    rem -= shift << 1", f"    if shift < {sz}:", f"        if src & {msb}:",
                  f"            res |= {tbl}[shift]", "        " + st("res"),
                  "        fX = fC = " + ("src << (9 - shift)" if sz == 8 else "(src >> (shift - 1)) << 8"),
                  "        " + N("res"), "        fZ = res", "        fV = 0",
                  f"    elif src & {msb}:", "        R[dy] |= " + mask, "        fC = fX = 0x100", "        fN = 0x80",
                  "        fZ = 0xFFFFFFFF", "        fV = 0",
                  "    else:", "        R[dy] &= " + (hi if sz != 32 else "0"), "        fC = fX = 0", "        fN = 0",
                  "        fZ = 0", "        fV = 0"]
        else:
            lim = f"shift <= {sz}" if sz != 32 else "shift < 32"
            L += ["if shift:", "    rem -= shift << 1", f"    if {lim}:", "        " + st("res"),
                  "        fX = fC = " + ("src << (9 - shift)" if sz == 8 else "(src >> (shift - 1)) << 8"),
                  "        fN = 0", "        fZ = res", "        fV = 0",
                  "    else:", "        R[dy] &= " + (hi if sz != 32 else "0")]
            L += ["        fX = fC = ((src >> 31) << 8) if shift == 32 else 0" if sz == 32 else "        fX = fC = 0"]
            L += ["        fN = 0", "        fZ = 0", "        fV = 0"]
        L += ["else:", "    fC = 0", "    " + N("src"), "    fZ = src", "    fV = 0"]
        return L
    if fam in ("rol", "ror"):
        L += [src]
        if kind == "s":
            L += ["orig = shift", f"shift = orig & {sz - 1}"]
        else:
            L += ["orig = shift", f"shift = orig & {sz - 1}"]
        if fam == "rol":
            L += [f"res = ((src << shift) | (src >> ({sz} - shift))) & {mask}"]
        else:
            L += [f"res = ((src >> shift) | (src << ({sz} - shift))) & {mask}"]
        if kind == "s":
            L += ["rem -= orig << 1", st("res"), N("res"), "fZ = res"]
            if fam == "rol":
                L += [{8: "fC = src << orig", 16: "fC = src >> (8 - shift)", 32: "fC = src >> (24 - shift)"}[sz]]
            else:
                L += [{8: "fC = src << (9 - orig)", 16: "fC = src << (9 - shift)", 32: "fC = src << (9 - shift)"}[sz]]
            L += ["fV = 0"]
            return L
        if fam == "rol" and sz != 32:
            L += ["if orig:", "    rem -= orig << 1", "    if shift:", "        " + st("res"),
                  "        fC = " + ("src << shift" if sz == 8 else "(src << shift) >> 8"),
                  "        " + N("res"), "        fZ = res", "        fV = 0", "    else:", "        fC = (src & 1) << 8",
                  "        " + N("src"), "        fZ = src", "        fV = 0"]
        else:
            if fam == "rol":     # 32
                cexp = "(src >> ((32 - shift) & 31)) << 8"
            else:
                cexp = {8: "src << (8 - ((shift - 1) & 7))", 16: "(src >> ((shift - 1) & 15)) << 8",
                        32: "(src >> ((shift - 1) & 31)) << 8"}[sz]
            L += ["if orig:", "    rem -= orig << 1", "    " + st("res"), "    fC = " + cexp, "    " + N("res"),
                  "    fZ = res", "    fV = 0"]
        L += ["else:", "    fC = 0", "    " + N("src"), "    fZ = src", "    fV = 0"]
        return L
    # roxl / roxr: rotate through X, (sz + 1)-bit value
    w = sz + 1
    rot = (f"res = (v << shift) | (v >> ({w} - shift))" if fam == "roxl" else
           f"res = (v >> shift) | (v << ({w} - shift))")
    cx = {8: "fC = fX = res", 16: "fC = fX = res >> 8", 32: "fC = fX = res >> 24"}[sz]
    body = [src, f"v = src | (((fX >> 8) & 1) << {sz})", rot]
    if sz == 32:   # uint64 arithmetic: keep 64 bits
        body.append("res &= 0xFFFFFFFFFFFFFFFF")
    if kind == "s":
        L += body + ["rem -= shift << 1", cx, f"res &= {mask}", st("res"), N("res"), "fZ = res", "fV = 0"]
        return L
    L += ["if shift:", "    orig = shift", f"    shift = orig % {w}"] + ["    " + x for x in body]
    L += ["    rem -= orig << 1", "    " + cx, f"    res &= {mask}", "    " + st("res"), "    " + N("res"),
          "    fZ = res", "    fV = 0", "else:", "    fC = fX", "    " + N("R[dy]"),
          f"    fZ = R[dy] & {mask}", "    fV = 0"]
    return L


_RUNTIME = r'''
def _build(bus16, bus8, wbus16, wbus8, reset_cb, CYC, H_NAMES, H_INDEX, FAST, FW):
    # FAST[0] true: a 16-bit read at $C00000-$CFFFFF (the BIOS socket, mirrored every 128 KB) is
    # FW[a & 0x1FFFE], without calling bus16. The bus owner keeps FW equal to its BIOS words and
    # clears FAST[0] whenever such a read must be seen (host port armed, faults, watch hook).
    # Used for the opcode and extension word fetches only: same values, same order, no side effect.
    R = [0] * 16                 # D0-D7, A0-A7 (A7 = active stack pointer)
    SPB = [0] * 8                # Musashi REG_SP_BASE: [0] USP, [4] ISP
    SH8 = [0, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE] + [0xFF] * 57
    SH16 = [(0xFFFF << (16 - i)) & 0xFFFF for i in range(17)] + [0xFFFF] * 48
    SH32 = [(0xFFFFFFFF << (32 - i)) & 0xFFFFFFFF for i in range(33)] + [0xFFFFFFFF] * 32
    CYC_EXC = %(cyc_exc)r
    fN = fZ = fV = fC = fX = 0
    fS = 0
    T1 = T0 = 0
    IMASK = 0x700
    INT_LEVEL = 0
    nmi_pending = False
    pc = ppc = ir = 0
    rem = initial = 0
    reset_cycles = 0
    tracing = 0
    stopped = 0
    run_mode = 0
    instr_mode = 0
    aerr_addr = aerr_mode = aerr_fc = 0
    in_exec = False

    class AErr(Exception):
        pass

    def cmod(a, b):              # C '%%' (truncates toward zero)
        return a %% b if a >= 0 else -((-a) %% b)

    def aerr(a, mode, fc):
        nonlocal aerr_addr, aerr_mode, aerr_fc
        aerr_addr = a & 0xFFFFFFFF
        aerr_mode = mode
        aerr_fc = fc
        raise AErr()

    # ---- bus (Musashi m68ki_read/write_xx_fc, ADDRESS_68K = 24 bits)
    def rd8(a):
        return bus8(a & 0xFFFFFF)

    def rd16(a):
        if a & 1:
            aerr(a, 0x10, fS | 1)
        return bus16(a & 0xFFFFFF)

    def rd32(a):
        if a & 1:
            aerr(a, 0x10, fS | 1)
        a &= 0xFFFFFF
        return (bus16(a) << 16) | bus16((a + 2) & 0xFFFFFF)

    def rdp16(a):
        if a & 1:
            aerr(a, 0x10, fS | 2)
        return bus16(a & 0xFFFFFF)

    def rdp32(a):
        if a & 1:
            aerr(a, 0x10, fS | 2)
        a &= 0xFFFFFF
        return (bus16(a) << 16) | bus16((a + 2) & 0xFFFFFF)

    def wr8(a, v):
        wbus8(a & 0xFFFFFF, v & 0xFF)

    def wr16(a, v):
        if a & 1:
            aerr(a, 0, fS | 1)
        wbus16(a & 0xFFFFFF, v & 0xFFFF)

    def wr32(a, v):
        if a & 1:
            aerr(a, 0, fS | 1)
        a &= 0xFFFFFF
        wbus16(a, (v >> 16) & 0xFFFF)
        wbus16((a + 2) & 0xFFFFFF, v & 0xFFFF)

    def imm16():
        nonlocal pc
        a = pc
        if a & 1:
            aerr(a, 0x10, fS | 2)
        pc = (a + 2) & 0xFFFFFFFF
        a &= 0xFFFFFF
        if FAST[0] and 0xC00000 <= a < 0xD00000:
            return FW[a & 0x1FFFE]
        return bus16(a)

    def imm32():
        nonlocal pc
        a = pc
        if a & 1:
            aerr(a, 0x10, fS | 2)
        pc = (a + 4) & 0xFFFFFFFF
        a &= 0xFFFFFF
        if FAST[0] and 0xC00000 <= a < 0xCFFFFE:
            return (FW[a & 0x1FFFE] << 16) | FW[(a + 2) & 0x1FFFE]
        return (bus16(a) << 16) | bus16((a + 2) & 0xFFFFFF)

    def ix(base):                # 68000 brief extension word
        ext = imm16()
        x = R[ext >> 12]
        if not ext & 0x800:
            x = (x & 0xFFFF) - ((x & 0x8000) << 1)
        return (base + x + (ext & 0xFF) - ((ext & 0x80) << 1)) & 0xFFFFFFFF

    def push16(v):
        R[15] = (R[15] - 2) & 0xFFFFFFFF
        wr16(R[15], v)

    def push32(v):
        R[15] = (R[15] - 4) & 0xFFFFFFFF
        wr32(R[15], v)

    def pull16():
        R[15] = (R[15] + 2) & 0xFFFFFFFF
        return rd16((R[15] - 2) & 0xFFFFFFFF)

    def pull32():
        R[15] = (R[15] + 4) & 0xFFFFFFFF
        return rd32((R[15] - 4) & 0xFFFFFFFF)

    # ---- status register
    def get_ccr():
        return ((fX >> 4) & 0x10) | ((fN >> 4) & 8) | ((not fZ) << 2) | ((fV >> 6) & 2) | ((fC >> 8) & 1)

    def get_sr():
        return T1 | T0 | (fS << 11) | IMASK | get_ccr()

    def set_ccr(v):
        nonlocal fX, fN, fZ, fV, fC
        fX = (v & 0x10) << 4
        fN = (v & 8) << 4
        fZ = 0 if v & 4 else 1
        fV = (v & 2) << 6
        fC = (v & 1) << 8

    def set_s_flag(v):
        nonlocal fS
        SPB[fS] = R[15]
        fS = v
        R[15] = SPB[fS]

    def set_sr_noint(v):
        nonlocal T1, T0, IMASK
        v &= 0xA71F
        T1 = v & 0x8000
        T0 = v & 0x4000
        IMASK = v & 0x0700
        set_ccr(v)
        set_s_flag((v >> 11) & 4)

    def set_sr(v):
        set_sr_noint(v)
        check_interrupts()

    def check_interrupts():
        nonlocal nmi_pending
        if nmi_pending:
            nmi_pending = False
            exception_interrupt(7)
        elif INT_LEVEL > IMASK:
            exception_interrupt(INT_LEVEL >> 8)

    # ---- exceptions
    def init_exception():
        nonlocal T1, T0, tracing
        sr = get_sr()
        T1 = T0 = 0
        tracing = 0
        set_s_flag(4)
        return sr

    def jump_vector(v):
        nonlocal pc
        pc = rd32(v << 2)

    def exception_trap(v):
        nonlocal rem
        sr = init_exception()
        push32(pc)
        push16(sr)
        jump_vector(v)
        rem -= CYC_EXC[v] - CYC[ir]

    exception_trapN = exception_trap

    def exception_privilege():
        nonlocal rem, instr_mode
        sr = init_exception()
        instr_mode = 8
        push32(ppc)
        push16(sr)
        jump_vector(8)
        rem -= CYC_EXC[8] - CYC[ir]

    def exception_illegal():
        nonlocal rem, instr_mode
        sr = init_exception()
        instr_mode = 8
        push32(ppc)
        push16(sr)
        jump_vector(4)
        rem -= CYC_EXC[4] - CYC[ir]

    def exception_line(v):       # 1010 / 1111
        nonlocal rem
        sr = init_exception()
        push32(ppc)
        push16(sr)
        jump_vector(v)
        rem -= CYC_EXC[v] - CYC[ir]

    def exception_trace():
        nonlocal rem, instr_mode, stopped
        sr = init_exception()
        instr_mode = 8
        push32(pc)
        push16(sr)
        jump_vector(9)
        stopped &= ~1
        rem -= CYC_EXC[9]

    def exception_interrupt(level):
        nonlocal instr_mode, stopped, IMASK, pc, rem, INT_LEVEL
        instr_mode = 8
        stopped &= ~1
        if stopped:
            return
        vector = 24 + level
        sr = init_exception()
        IMASK = level << 8
        npc = rd32(vector << 2)
        if npc == 0:
            npc = rd32(15 << 2)
        push32(pc)
        push16(sr)
        pc = npc
        rem -= CYC_EXC[vector]
        INT_LEVEL = 0

    def exception_address_error():
        nonlocal run_mode, stopped, rem
        sr = init_exception()
        if run_mode == 1:        # fault while writing the frame of a bus/address error: halt
            bus8(0xFFFF01)
            stopped = 2
            return
        run_mode = 1
        push32(pc)
        push16(sr)
        push16(ir)
        push32(aerr_addr)
        push16(aerr_mode | instr_mode | aerr_fc)
        jump_vector(3)
        run_mode = 2
        rem -= CYC_EXC[3]

    def address_error_trap():    # what Musashi's setjmp block does, nested faults included
        while True:
            try:
                exception_address_error()
                return
            except AErr:
                pass

%(handlers)s
    # ---- decode table: one specialised function per opcode
    loc = dict(locals())         # (not inside the comprehension: before Python 3.12 it has its own locals())
    factories = {n: f for n, f in loc.items() if n.startswith("F_")}
    H = [None] * 0x10000
    for op in range(0x10000):
        H[op] = factories["F_" + H_NAMES[H_INDEX[op]]](op)

    def execute(num):
        nonlocal reset_cycles, rem, initial, tracing, ppc, pc, ir, in_exec, stopped
        if reset_cycles:
            rc = reset_cycles
            reset_cycles = 0
            num -= rc
            if num <= 0:
                return rc
        rem = num
        initial = num
        try:
            check_interrupts()
        except AErr:
            address_error_trap()
            if stopped:
                rem = 0
                return initial
        if stopped:
            rem = 0
            return initial
        H_ = H
        C_ = CYC
        while True:
            try:
                while True:
                    tracing = T1
                    a = ppc = pc
                    if a & 1:
                        aerr(a, 0x10, fS | 2)
                    pc = (a + 2) & 0xFFFFFFFF
                    a &= 0xFFFFFF
                    if FAST[0] and 0xC00000 <= a < 0xD00000:
                        ir = i_ = FW[a & 0x1FFFE]
                    else:
                        ir = i_ = bus16(a)
                    H_[i_]()
                    rem -= C_[i_]
                    if tracing:
                        exception_trace()
                    if rem <= 0:
                        break
                ppc = pc
                return initial - rem
            except AErr:
                address_error_trap()
                if stopped:
                    rem = 0
                    return initial
                if rem <= 0:
                    return initial - rem

    def pulse_reset():
        nonlocal stopped, rem, run_mode, instr_mode, T1, T0, tracing, IMASK, INT_LEVEL, pc, reset_cycles
        stopped = 0
        rem = 0
        run_mode = 2
        instr_mode = 0
        T1 = T0 = 0
        tracing = 0
        IMASK = 0x700
        INT_LEVEL = 0
        set_s_flag(4)
        pc = 0
        R[15] = imm32()
        pc = imm32()
        run_mode = 0
        reset_cycles = CYC_EXC[0]

    def set_irq(level):
        nonlocal INT_LEVEL, nmi_pending
        old = INT_LEVEL
        INT_LEVEL = level << 8
        if old != 0x700 and INT_LEVEL == 0x700:
            nmi_pending = True

    def cycles_run():
        return initial - rem

    def get_pc():
        return pc

    def get_reg(n):
        if n < 16:
            return R[n]
        return {16: pc, 17: get_sr(), 18: R[15], 19: R[15] if not fS else SPB[0],
                20: R[15] if fS else SPB[4], 29: ppc, 30: ir}.get(n, 0)

    def set_reg(n, v):
        nonlocal pc
        v &= 0xFFFFFFFF
        if n < 16:
            R[n] = v
        elif n == 16:
            pc = v
        elif n == 17:
            set_sr(v)
        elif n == 18:
            R[15] = v
        elif n == 19:
            if fS:
                SPB[0] = v
            else:
                R[15] = v
        elif n == 20:
            if fS:
                R[15] = v
            else:
                SPB[4] = v

    def state():
        return dict(R=list(R), pc=pc, sr=get_sr(), usp=SPB[0] if fS else R[15], isp=R[15] if fS else SPB[4],
                    stopped=stopped, run_mode=run_mode, instr_mode=instr_mode, int_level=INT_LEVEL, ppc=ppc)

    return execute, pulse_reset, set_irq, cycles_run, get_pc, get_reg, set_reg, state
'''


def _factory_src(name):
    import re
    body = _gen(name)
    text = "\n".join(body)
    assigned = [v for v in _STATE if re.search(r"(?<![\w\[.])%s\s*(?:[-+&|^]|<<|>>)?=(?!=)" % v, text)]
    pre = ["    def F_%s(op):" % name, "        dx = (op >> 9) & 7", "        dy = op & 7", "        ax = dx + 8",
           "        ay = dy + 8", "        q = (((op >> 9) - 1) & 7) + 1",
           "        q8 = ((op & 0xFF) - ((op & 0x80) << 1)) & 0xFFFFFFFF", "        def h():"]
    if assigned:
        pre.append("            nonlocal " + ", ".join(assigned))
    return "\n".join(pre + ["            " + l for l in body] + ["        return h"])


class M68K:
    """The Python 68000. Methods as Musashi's m68k_* API."""

    def __init__(self, bus16, bus8, wbus16, wbus8, reset_cb=lambda: None, names=None, tables=None, fast=None):
        """fast: (FAST, FW) from the bus owner (see _build); None = every fetch through bus16."""
        if fast is None:
            fast = ([0], [])
        if names is None:
            names, tables = M68K_NAMES, M68K_TABLES
        raw = _lzma.decompress(_b64.b64decode("".join(tables)))
        index = memoryview(raw[:0x20000]).cast("H")
        cyc = list(raw[0x20000:])
        src = _RUNTIME % {"cyc_exc": _CYC_EXC, "handlers": "\n".join(_factory_src(n) for n in names)}
        g = {}
        exec(compile(src, "<m68k_py>", "exec"), g)
        (self.execute, self.pulse_reset, self.set_irq, self.cycles_run, self.pc, self.get_reg, self.set_reg,
         self.state) = g["_build"](bus16, bus8, wbus16, wbus8, reset_cb, cyc, names, list(index), fast[0], fast[1])
