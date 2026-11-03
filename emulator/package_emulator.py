"""Builds Brico68k_Emulator.py: main + host + embedded cores (lzma, base64)."""
import base64, hashlib, lzma, sys
from pathlib import Path
here = Path(__file__).parent
main = (here / "emulator_main.py").read_text()
host = (here / "emu_host.py").read_text()
cores = {"windows-x86_64": ("neocore.dll", here / "build/neocore.dll"),
         "linux-x86_64": ("libneocore.so", here / "build/libneocore_zig.so")}
lines = ["# ===========================================================================",
         "# Embedded emulator core: Musashi 4.60 68000 core (Karl Stenerud, MIT licence),",
         "# superzazu/z80 Z80 core (Nicolas Allemand, MIT licence)",
         "# + neocore.c (Neo Geo AES model + host), built with zig 0.17.0 -O2:",
         "# Windows x86_64-windows-gnu DLL, Linux x86_64-linux-gnu.2.17 shared library.",
         "# Format: platform -> (file name, sha256, lzma data in base64).",
         "# ===========================================================================",
         "EMBEDDED_CORES = {"]
for plat, (name, path) in cores.items():
    raw = path.read_bytes()
    b = base64.b64encode(lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)).decode()
    chunks = "\n".join(f"        '{b[i:i + 100]}'" for i in range(0, len(b), 100))
    lines.append(f"    '{plat}': ('{name}', '{hashlib.sha256(raw).hexdigest()}',\n{chunks}),")
lines.append("}\n")
out = main.replace("# @@HOST@@\n", host).replace("# @@CORES@@\n", "\n".join(lines))
dest = Path(sys.argv[1] if len(sys.argv) > 1 else here / "Brico68k_Emulator.py")
dest.write_text(out)
print(dest, len(out), "bytes")
