"""Runs bench/real_aes_session.txt in the emulator and writes the output a healthy console should give.
Usage: python bench/make_expected.py [--no-z80] [--no-watchdog] > expected.txt"""
import importlib.util, sys
from pathlib import Path
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("emu", here.parent / "Brico68k_Emulator.py")
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
rom = (here.parent / "rom" / "Brico68k.bin").read_bytes()
core = m.Core(m.core_path()); core.load(rom); core.power_on()
core.lib.neo_set_options(0 if "--no-z80" in sys.argv else 1, 0 if "--no-watchdog" in sys.argv else 1)
for _ in range(60):
    core.lib.neo_run_frame()
host = m.Host(core, rom)
for line in (here / "real_aes_session.txt").read_text().splitlines():
    line = line.strip()
    if not line or line.startswith(";"):
        continue
    print(f"==== {line}")
    if line.lower().startswith("delay"):
        for _ in range(int(int(line.split()[1]) * 60 / 1000)):
            core.lib.neo_run_frame()
        continue
    status, text, secs = host.run_blocking(line)
    print(text, end="")
