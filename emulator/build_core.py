#!/usr/bin/env python3
"""Rebuilds the emulator core and Brico68k_Emulator.py.

1. clones Musashi (Karl Stenerud, MIT) at a pinned commit,
2. enables address-error, trace and RESET-instruction emulation in m68kconf.h,
3. generates m68kops.c/h with m68kmake,
4. builds neocore.dll (x86_64-windows-gnu) and libneocore.so (x86_64-linux-gnu.2.17)
   with zig (pip install ziglang),
5. writes ../Brico68k_Emulator.py (main + host + embedded cores).
Usage: python3 emulator/build_core.py
"""
import shutil, subprocess, sys
from pathlib import Path

MUSASHI = "https://github.com/kstenerud/Musashi.git"
MUSASHI_COMMIT = "313ebf1"
HERE = Path(__file__).resolve().parent
B = HERE / "build"
ZIG = [sys.executable, "-m", "ziglang", "cc"]


def run(cmd, **kw):
    print("+", " ".join(map(str, cmd)))
    subprocess.run(cmd, check=True, **kw)


def main():
    shutil.rmtree(B, ignore_errors=True)
    run(["git", "clone", "-q", MUSASHI, str(B / "musashi")])
    run(["git", "-C", str(B / "musashi"), "checkout", "-q", MUSASHI_COMMIT])
    src = B / "src"
    shutil.copytree(B / "musashi", src, ignore=shutil.ignore_patterns(".git", "test", "example"))
    conf = (src / "m68kconf.h").read_text()
    for name in ("M68K_EMULATE_ADDRESS_ERROR", "M68K_EMULATE_TRACE", "M68K_EMULATE_RESET"):
        i = conf.index(f"#define {name} ")
        j = conf.index("\n", i)
        conf = conf[:i] + f"#define {name:<28}M68K_OPT_ON" + conf[j:]
    conf = conf.replace("#define M68K_RESET_CALLBACK()       your_reset_handler_function()",
                        "void neo_reset_instr(void);\n#define M68K_RESET_CALLBACK()       neo_reset_instr()")
    (src / "m68kconf.h").write_text(conf)
    shutil.copy(HERE / "neocore.c", src)
    host = ZIG + ["-O2"]
    run(host + ["-o", str(src / "m68kmake"), str(src / "m68kmake.c")])
    run([str(src / "m68kmake"), ".", "m68k_in.c"], cwd=src)
    files = ["neocore.c", "m68kcpu.c", "m68kops.c", "m68kdasm.c", "softfloat/softfloat.c"]
    run(ZIG + ["-target", "x86_64-windows-gnu", "-O2", "-s", "-shared", "-o", str(B / "neocore.dll")] + files, cwd=src)
    run(ZIG + ["-target", "x86_64-linux-gnu.2.17", "-O2", "-s", "-fPIC", "-shared", "-o",
               str(B / "libneocore_zig.so")] + files + ["-lm"], cwd=src)
    run([sys.executable, str(HERE / "package_emulator.py"), str(HERE.parent / "Brico68k_Emulator.py")])


if __name__ == "__main__":
    main()
