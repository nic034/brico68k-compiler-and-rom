#!/usr/bin/env python3
"""Builds a TEST-ONLY emulator core for emulator/regress_rom.py: build/libneocore_test.so.

The shipped core is an AES with nothing pressed and no memory card, so the ROM's MVS, button,
DIP and memory card branches never run in it. This copy of neocore.c adds one function,
neo_test_inputs(p1, dip, p2, status_a, status_b, systype, mvs), that sets those ports, and a
64 KB backup RAM at $D00000 when mvs = 1. Everything else is the shipped core: with the default
values it gives the same results word for word.
Never packaged into Brico68k_Emulator.py. Linux, gcc. Reuses the Musashi / z80 clones of
build_core.py (same pinned commits) or clones them.
Usage: python3 emulator/build_test_core.py
"""
import shutil, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import build_core as bc                       # MUSASHI/Z80 URLs and commits, fetch()

B = HERE / "build"


def patch(c):
    rep = [
        ("static unsigned read16(unsigned a, int lsb_only)\n{",
         "static unsigned t_p1 = 0xFF, t_dip = 0x00, t_p2 = 0xFF, t_sa = 0x00, t_sb = 0x7F, t_sys = 0xFF00, t_mvs = 0;\n"
         "static uint8_t t_bram[0x10000];\n"
         "EXPORT void neo_test_inputs(int p1, int dip, int p2, int sa, int sb, int sys, int mvs)\n"
         "{ t_p1 = p1; t_dip = dip; t_p2 = p2; t_sa = sa; t_sb = sb; t_sys = sys; t_mvs = mvs; }\n"
         "static unsigned read16(unsigned a, int lsb_only)\n{"),
        ("if (a < 0x320000) return 0xFF00;                        /* P1: nothing pressed */",
         "if (a < 0x320000) return (a == 0x300080) ? t_sys : ((t_p1 << 8) | t_dip);"),
        ("if (a < 0x340000) { z80_sync(); return (unsigned)z80_reply << 8; }",
         "if (a < 0x340000) { z80_sync(); return ((unsigned)z80_reply << 8) | t_sa; }"),
        ("if (a < 0x360000) return 0xFF00;                        /* P2 */",
         "if (a < 0x360000) return t_p2 << 8;"),
        ("if (a < 0x3A0000) return 0x7FFF;                        /* STATUS_B: AES, no memory card */",
         "if (a < 0x3A0000) return (t_sb << 8) | 0xFF;"),
        ("return open_bus();                                      /* AES: no backup RAM */",
         "if (t_mvs && a < 0xD10000) return (t_bram[a & 0xFFFE] << 8) | t_bram[(a & 0xFFFE) + 1];\n\treturn open_bus();"),
        ("\t/* ROM, cartridge, memory card, unmapped: ignored */",
         "\tif (t_mvs && a >= 0xD00000 && a < 0xD10000) {\n"
         "\t\tif (mask & 0xFF00) t_bram[a & 0xFFFE] = (uint8_t)(d >> 8);\n"
         "\t\tif (mask & 0x00FF) t_bram[(a & 0xFFFE) + 1] = (uint8_t)d;\n"
         "\t\treturn;\n\t}\n\t/* ROM, cartridge, memory card, unmapped: ignored */"),
    ]
    for old, new in rep:
        if c.count(old) != 1:
            sys.exit(f"neocore.c changed, patch point not found: {old[:60]}")
        c = c.replace(old, new)
    return c


def main():
    B.mkdir(exist_ok=True)
    bc.fetch(bc.MUSASHI, bc.MUSASHI_COMMIT, B / "musashi")
    bc.fetch(bc.Z80, bc.Z80_COMMIT, B / "z80")
    src = B / "src_test"
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(B / "musashi", src, ignore=shutil.ignore_patterns(".git", "test", "example"))
    conf = (src / "m68kconf.h").read_text()
    for name in ("M68K_EMULATE_ADDRESS_ERROR", "M68K_EMULATE_TRACE", "M68K_EMULATE_RESET"):
        i = conf.index(f"#define {name} ")
        j = conf.index("\n", i)
        conf = conf[:i] + f"#define {name:<28}M68K_OPT_ON" + conf[j:]
    conf = conf.replace("#define M68K_RESET_CALLBACK()       your_reset_handler_function()",
                        "void neo_reset_instr(void);\n#define M68K_RESET_CALLBACK()       neo_reset_instr()")
    (src / "m68kconf.h").write_text(conf)
    (src / "neocore.c").write_text(patch((HERE / "neocore.c").read_text()))
    shutil.copy(B / "z80" / "z80.c", src)
    shutil.copy(B / "z80" / "z80.h", src)
    bc.run(["gcc", "-O2", "-o", str(src / "m68kmake"), str(src / "m68kmake.c")])
    bc.run([str(src / "m68kmake"), ".", "m68k_in.c"], cwd=src)
    files = ["neocore.c", "z80.c", "m68kcpu.c", "m68kops.c", "m68kdasm.c", "softfloat/softfloat.c"]
    bc.run(["gcc", "-O2", "-fPIC", "-shared", "-o", str(B / "libneocore_test.so")] + files + ["-lm"], cwd=src)
    print(f"-> {B / 'libneocore_test.so'} (test only)")


if __name__ == "__main__":
    main()
