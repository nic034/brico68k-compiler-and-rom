"""Test helper: writes what a PuTTY session log of the BricoNeo console would contain for a script,
with the emulator standing in for the console. Used to check --compare without a real board.
It reproduces the Brico16Bits console output: banner with screen clear, coloured '> ' prompt,
typed characters echoed one by one (with one typing error fixed by backspace), CR LF line ends,
comments recoloured after Enter, [Timeout] on a timeout.
Usage: python3 make_fake_console_log.py Brico68k_Emulator.py SCRIPT OUT [--fault SPEC]... [--z80 none]"""
import importlib.util, sys
from pathlib import Path

emu, script, out = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("emu", emu); m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
args = sys.argv[4:]
faults = [m.parse_fault(args[i + 1]) for i, x in enumerate(args) if x == "--fault"]
rom = Path(m.default_rom()).read_bytes()
core = m.Core(m.core_path()); core.load(rom); core.power_on()
core.lib.neo_set_options(0 if "none" in args else 1, 1)
m.apply_faults(core, faults)
for _ in range(60):
    core.lib.neo_run_frame()
host = m.Host(core, rom)
COL = lambda n: f"\x1b[38;5;{n}m"
PROMPT = COL(13) + "> " + COL(15)
o = ["\x1b[2J\x1b[H\n\nWelcome to BricoNeo - Compiled 2026-10-22 - Bouz/@AurelienBricole\n",
     "Found BricoNeo ROM version 1.35. Special mode flags: 0x0003\n\nType " + COL(11) + "?" + COL(15) + " for help\n"]
o.append(PROMPT)
for raw in Path(script).read_text().splitlines():
    line = raw.strip()
    if not line:
        o.append("\n" + PROMPT)                      # empty line: Return on an empty command
        continue
    typed = line
    if line == "TestPRAM":                           # a typing error fixed with backspace
        o.append("TestPRA" + "X" + "\b \b" + "M")
    else:
        o.append(typed)
    if line.startswith(";"):
        o.append("\b" * len(line) + COL(8) + line + COL(15))
    o.append("\n")
    w = line.split()[0].lower()
    if line.startswith(";"):
        pass
    elif w == "delay":
        for _ in range(round(int(line.split()[1]) * 60 / 1000)):
            core.lib.neo_run_frame()
    else:
        st, text, secs = host.run_blocking(line)
        o.append((COL(9) + "[Timeout]" + COL(15) + "\n") if st == "timeout" else text)
    o.append(PROMPT)
data = "".join(o).replace("\n", "\r\n")             # Pico stdio sends CR LF
Path(out).write_bytes(data.encode())
print(f"{out}: {len(data)} bytes")
