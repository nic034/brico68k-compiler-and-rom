"""Builds Brico68k_Emulator.py: one Python file, standard library only, no DLL.
emulator_main.py + the Python core (m68k_tables.py, m68k_py.py, neo_py.py) + emu_host.py.
A C build of the same core (build_core.py) is optional and is never embedded: the tool uses it
when it finds it next to the script (see core_path)."""
import sys
from pathlib import Path
here = Path(__file__).parent
main = (here / "emulator_main.py").read_text()
parts = []
for name, title in (("m68k_tables.py", "Musashi 68000 decode / cycle tables (Musashi 4.60, Karl Stenerud, MIT licence)"),
                    ("m68k_py.py", "Python 68000"), ("neo_py.py", "Python Neo Geo AES model"),
                    ("emu_host.py", "Core loader + host")):
    parts.append(f"# {'=' * 75}\n# {name}: {title}\n# {'=' * 75}\n" + (here / name).read_text())
if main.count("# @@HOST@@\n") != 1:
    sys.exit("emulator_main.py: '# @@HOST@@' marker missing")
out = main.replace("# @@HOST@@\n", "\n".join(parts))
dest = Path(sys.argv[1] if len(sys.argv) > 1 else here.parent / "Brico68k_Emulator.py")
dest.write_text(out)
print(dest, len(out), "bytes")
