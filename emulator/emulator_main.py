#!/usr/bin/env python3
"""Brico68k Emulator - test the Brico68k ROM without a BricoNeo / Brico16Bits.

One file, no MAME: a Neo Geo AES model built around the Musashi 68000 core
(C, embedded below as a Windows x64 DLL and a Linux x64 shared library) plus
a Brico16Bits-like host. Type the same commands as on the Brico16Bits console
(Help, Echo 1234, TestWRAM, TestDAC 1, Dump $100000 16...).

Emulated (modelled on MAME snk/neogeo.cpp): 68000 @ 12 MHz with exact cycle
counts, BIOS ROM, WRAM, palette RAM (2 banks), system latch, LSPC registers
and VRAM, line counter / frame timing, auto-animation counter, inputs (AES,
nothing pressed, no memory card, no cartridge), open bus, watchdog (option).
Host: command + P1-P3 written into the ROM, cleared after 1 ms, 3 s timeout,
2048-word buffer, as Brico16Bits CommandExtension.cpp.
NOT emulated: Z80 and YM2610 (replaced by a responder that answers like the
standard sound driver handshake, or stays silent), sound, sprites and fix
layer (the screen shows the backdrop colour of each line), interrupts,
cartridge, memory card. Checked word for word against MAME: 32/32 commands.

Run: double-click, or  python Brico68k_Emulator.py [ROM]
Text mode: python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234" [--rom ROM]
           python Brico68k_Emulator.py --check [--rom ROM]
Python 3.8+, standard library only (tkinter for the window).
"""
import base64
import ctypes
import hashlib
import json
import lzma
import os
import platform
import re
import struct
import sys
import time
from pathlib import Path

APP_NAME = "Brico68k Emulator"
APP_VERSION = "1.0"
TOOL_DIR = Path(__file__).resolve().parent
WORK_DIR = TOOL_DIR / "brico68k_emulator"
CONFIG_PATH = WORK_DIR / "config.json"
IS_WIN = os.name == "nt"
ROM_CANDIDATES = ["rom/Brico68k.bin", "output/Brico68k.bin", "Brico68k.bin"]

# @@HOST@@

# ---------------------------------------------------------------------------
# Embedded core
# ---------------------------------------------------------------------------
def core_platform():
    m = platform.machine().lower()
    if IS_WIN and m in ("amd64", "x86_64", "arm64"):
        return "windows-x86_64"
    if sys.platform.startswith("linux") and m in ("x86_64", "amd64"):
        return "linux-x86_64"
    return None


def core_path():
    """Extracts the embedded core for this system (if needed). Returns its path, or raises."""
    plat = core_platform()
    cores = globals().get("EMBEDDED_CORES", {})
    if plat not in cores:
        raise RuntimeError(f"No embedded emulator core for this system ({platform.system()} {platform.machine()}): "
                           "Windows x64 and Linux x64 are supported.")
    name, sha, data = cores[plat]
    dest = WORK_DIR / name
    if not (dest.is_file() and hashlib.sha256(dest.read_bytes()).hexdigest() == sha):
        raw = lzma.decompress(base64.b64decode(data))
        if hashlib.sha256(raw).hexdigest() != sha:
            raise RuntimeError("Embedded emulator core is corrupted (checksum): download the tool again.")
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, dest)
    return dest


# MAME snk/neogeo_v.cpp create_rgb_lookups: 3900/2200/1000/470/220 ohm, dark = 8.2k pull-down
_G = [1 / 3900, 1 / 2200, 1 / 1000, 1 / 470, 1 / 220]
_SUM = sum(_G)
_LEVELS = [[round(255 * sum(g for i, g in enumerate(_G) if v >> i & 1) / (_SUM + (1 / 8200 if dark else 0)))
            for v in range(32)] for dark in (0, 1)]


def neo_rgb(c):
    """Neo Geo colour word -> '#rrggbb' (MAME DAC model)."""
    d = c >> 15
    r = ((c >> 14) & 1) | ((c >> 7) & 0x1E)
    g = ((c >> 13) & 1) | ((c >> 3) & 0x1E)
    b = ((c >> 12) & 1) | ((c << 1) & 0x1E)
    L = _LEVELS[d]
    return f"#{L[r]:02x}{L[g]:02x}{L[b]:02x}"


# ---------------------------------------------------------------------------
# Start-up check
# ---------------------------------------------------------------------------
def check_rom(path):
    """Problems with a ROM file: [(what, detail)]."""
    if not path:
        return [("Brico68k ROM", "not selected")]
    p = Path(path)
    if not p.is_file():
        return [("Brico68k ROM file", str(p))]
    data = p.read_bytes()
    if len(data) > 0x20000:
        return [("ROM of 128 KB or less", f"{p.name} is {len(data)} bytes")]
    if len(data) < 0xA0 + 6 or data[0x80:0x88] != b"BricoNeo":
        return [("BricoNeo header (magic 'BricoNeo' at $80)", f"{p.name}: not a Brico68k ROM")]
    if struct.unpack_from(">H", data, 4)[0] != 0x00C0:
        return [("68000 byte order (reset vector $00C0xxxx)", f"{p.name}: byte-swapped dump?")]
    try:
        parse_extensions(data)
    except Exception as e:
        return [("readable extension table at $A0", f"{p.name}: {e}")]
    return []


def startup_check(rom_path):
    missing = []
    if sys.version_info < (3, 8):
        missing.append(("Python 3.8 or newer", sys.version.split()[0]))
    try:
        core_path()
    except Exception as e:
        missing.append(("emulator core", str(e)))
    missing += check_rom(rom_path)
    return missing


def default_rom():
    for c in ROM_CANDIDATES:
        if (TOOL_DIR / c).is_file():
            return str(TOOL_DIR / c)
    return ""


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(cfg):
    try:
        WORK_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    except Exception:
        pass


HELP_BUILTIN = ("Built-in: Help (this list), Reset (console reset), Power (power cycle: clears RAM), Clear.\n"
                "Parameters: decimal, $hex or 0xhex, as on Brico16Bits (e.g. Dump $100000 16).\n")


def help_text(host):
    lines = [f"{len(host.exts)} extensions in this ROM:"]
    for n, a, t, d in host.exts:
        lines.append(f"  {n:<13} [{TYPE_NAMES.get(t, t)}] {d}")
    return "\n".join(lines) + "\n" + HELP_BUILTIN


# ---------------------------------------------------------------------------
# Text mode
# ---------------------------------------------------------------------------
def main_cli(argv):
    import argparse
    ap = argparse.ArgumentParser(description=APP_NAME)
    ap.add_argument("--rom", default=None)
    ap.add_argument("--run", nargs="*", default=None, help="commands to run, e.g. \"TestWRAM\" \"Echo 1234\"")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--z80", choices=["standard", "none"], default="standard")
    ap.add_argument("--watchdog", action="store_true", help="emulate the watchdog (MVS-like, 135 ms)")
    ap.add_argument("rom_pos", nargs="?")
    a = ap.parse_args(argv)
    rom_path = a.rom or a.rom_pos or default_rom()
    missing = startup_check(rom_path)
    for w, d in missing:
        print(f"MISSING: {w} -> {d}")
    if a.check:
        print("OK: nothing missing" if not missing else f"{len(missing)} missing item(s)")
        return 1 if missing else 0
    if missing:
        return 1
    rom = Path(rom_path).read_bytes()
    core = Core(core_path())
    core.load(rom)
    core.power_on()
    core.lib.neo_set_options(1 if a.z80 == "standard" else 0, 1 if a.watchdog else 0)
    for _ in range(60):
        core.lib.neo_run_frame()
    host = Host(core, rom)
    for line in a.run or ["Help"]:
        print(f"> {line}")
        if line.strip().lower() == "help":
            print(help_text(host), end="")
            continue
        st, text, secs = host.run_blocking(line)
        print(text, end="")
        print(f"[{st}, {secs * 1000:.0f} ms emulated]")
    return 0


# ---------------------------------------------------------------------------
# Window
# ---------------------------------------------------------------------------
def main_gui(rom_arg=None):
    import tkinter as tk
    from tkinter import filedialog, ttk

    cfg = load_config()
    root = tk.Tk()
    root.title(f"{APP_NAME} {APP_VERSION}")
    root.minsize(980, 640)
    root.geometry("1200x800")
    mono = ("Consolas", 10) if IS_WIN else ("Monospace", 10)
    st = {"core": None, "host": None, "rom": None, "running": False, "fast": False, "t_last": 0.0,
          "frames_done": 0, "fps_t": time.time(), "fps_n": 0, "history": [], "hist_i": 0, "busy_since": None,
          "rects": [], "colours": [None] * 224}

    # --- top: ROM + controls ----------------------------------------------
    top = ttk.Frame(root); top.pack(fill="x", padx=8, pady=(8, 4))
    rom_var = tk.StringVar(value=rom_arg or cfg.get("rom") or default_rom())
    ttk.Label(top, text="ROM:").pack(side="left")
    ttk.Entry(top, textvariable=rom_var).pack(side="left", fill="x", expand=True, padx=6)
    ttk.Button(top, text="Browse...", command=lambda: pick_rom()).pack(side="left")
    b_power = ttk.Button(top, text="Power on", command=lambda: power_on()); b_power.pack(side="left", padx=(12, 4))
    b_reset = ttk.Button(top, text="Reset", command=lambda: do_reset()); b_reset.pack(side="left", padx=4)
    b_pause = ttk.Button(top, text="Pause", command=lambda: toggle_pause()); b_pause.pack(side="left", padx=4)

    opts = ttk.Frame(root); opts.pack(fill="x", padx=8)
    z80_var = tk.StringVar(value=cfg.get("z80", "Standard sound driver (simulated)"))
    Z80_CHOICES = ["Standard sound driver (simulated)", "No answer (dead Z80 / no M1)"]
    ttk.Label(opts, text="Z80:").pack(side="left")
    ttk.Combobox(opts, textvariable=z80_var, values=Z80_CHOICES, state="readonly", width=34).pack(side="left", padx=6)
    wd_var = tk.BooleanVar(value=cfg.get("watchdog", False))
    ttk.Checkbutton(opts, text="Watchdog (135 ms, as MAME MVS; MAME has none on AES)", variable=wd_var,
                    command=lambda: apply_options()).pack(side="left", padx=12)
    fast_var = tk.BooleanVar(value=cfg.get("fast", False))
    ttk.Checkbutton(opts, text="Fast (not real time)", variable=fast_var).pack(side="left", padx=12)
    z80_var.trace_add("write", lambda *_: apply_options())

    missing_var = tk.StringVar(value="")
    missing_box = tk.Label(root, textvariable=missing_var, justify="left", anchor="w", wraplength=1100,
                           bg="#fdecea", fg="#7a1c14", bd=1, relief="solid", padx=10, pady=6)

    # --- bottom (packed first so the panes never push them out) -------------
    status = tk.StringVar(value="Power on to start.")
    ttk.Label(root, textvariable=status, anchor="w", relief="sunken").pack(fill="x", side="bottom")
    entry_row = ttk.Frame(root); entry_row.pack(fill="x", side="bottom", padx=8, pady=(0, 6))
    ttk.Label(entry_row, text="Command:").pack(side="left")
    cmd_var = tk.StringVar()
    e_cmd = ttk.Entry(entry_row, textvariable=cmd_var, font=mono); e_cmd.pack(side="left", fill="x", expand=True, padx=6)
    b_send = ttk.Button(entry_row, text="Send", command=lambda: send()); b_send.pack(side="left")

    # --- middle: screen + extensions | console ------------------------------
    mid = ttk.Panedwindow(root, orient="horizontal"); mid.pack(fill="both", expand=True, padx=8, pady=6)
    left = ttk.Frame(mid); mid.add(left, weight=0)
    ttk.Label(left, text="Neo Geo screen (backdrop colour per line)").pack(anchor="w")
    W, H = 320 * 2, 224 * 2
    canvas = tk.Canvas(left, width=W, height=H, bg="black", highlightthickness=1, highlightbackground="#888")
    canvas.pack()
    for y in range(224):
        st["rects"].append(canvas.create_rectangle(0, 2 * y, W, 2 * y + 2, outline="", fill="#000000"))
    ttk.Label(left, text="Sprites and fix layer are not rendered: enough for TestDAC / Color.",
              foreground="#666").pack(anchor="w")
    ttk.Label(left, text="Extensions in this ROM (double-click to use):").pack(anchor="w", pady=(8, 0))
    tree = ttk.Treeview(left, columns=("type", "desc"), show="tree headings", height=6)
    tree.heading("#0", text="Command"); tree.heading("type", text="Result"); tree.heading("desc", text="Description")
    tree.column("#0", width=110, stretch=False); tree.column("type", width=50, stretch=False); tree.column("desc", width=470)
    tree.pack(fill="both", expand=True)

    right = ttk.Frame(mid); mid.add(right, weight=1)
    ttk.Label(right, text="Brico16Bits console (emulated host)").pack(anchor="w")
    con = tk.Text(right, wrap="word", font=mono, state="disabled", bg="#101418", fg="#e6edf3", insertbackground="white")
    sy = ttk.Scrollbar(right, command=con.yview); con.configure(yscrollcommand=sy.set)
    sy.pack(side="right", fill="y"); con.pack(fill="both", expand=True)
    con.tag_configure("cmd", foreground="#7ee787"); con.tag_configure("info", foreground="#8b949e")
    con.tag_configure("err", foreground="#ff7b72")

    def out(text, tag=None):
        con.configure(state="normal")
        con.insert("end", text, tag)
        con.see("end")
        con.configure(state="disabled")

    def pick_rom():
        p = filedialog.askopenfilename(title="Brico68k ROM", filetypes=[("ROM", "*.bin"), ("All files", "*")],
                                       initialdir=str(Path(rom_var.get()).parent) if rom_var.get() else str(TOOL_DIR))
        if p:
            rom_var.set(p)

    def refresh_missing(*_):
        items = startup_check(rom_var.get().strip())
        if items:
            missing_var.set(f"Missing ({len(items)}) - fix before powering on:\n" +
                            "\n".join(f"  • {w}: {d}" for w, d in items))
            missing_box.pack(fill="x", padx=8, pady=(4, 0), after=opts)
        else:
            missing_box.pack_forget()
        b_power.configure(state="disabled" if items else "normal")
        return not items

    def apply_options():
        if st["core"]:
            st["core"].lib.neo_set_options(0 if z80_var.get().startswith("No") else 1, 1 if wd_var.get() else 0)

    def power_on():
        if not refresh_missing():
            return
        try:
            rom = Path(rom_var.get()).read_bytes()
            core = st["core"] or Core(core_path())
            core.load(rom)
            core.power_on()
            st["core"], st["rom"] = core, rom
            apply_options()
            host = Host(core, rom)
            st["host"] = host
        except Exception as ex:
            out(f"Cannot start: {ex}\n", "err")
            return
        tree.delete(*tree.get_children())
        for n, a, t, d in host.exts:
            tree.insert("", "end", text=n, values=(TYPE_NAMES.get(t, t), d))
        major, minor = struct.unpack_from(">HH", rom, 0x88)
        out(f"--- Power on: {Path(rom_var.get()).name}, BricoNeo {major}.{minor}, {len(host.exts)} extensions. "
            "Type Help. ---\n", "info")
        st["running"] = True; st["t_last"] = time.time(); b_pause.configure(text="Pause")
        persist()

    def do_reset():
        if st["core"]:
            st["core"].lib.neo_reset()
            st["host"].pending = None
            out("--- Reset (RAM kept) ---\n", "info")

    def toggle_pause():
        st["running"] = not st["running"]
        st["t_last"] = time.time()
        b_pause.configure(text="Pause" if st["running"] else "Run")

    def send(line=None):
        line = (line if line is not None else cmd_var.get()).strip()
        if not line:
            return
        cmd_var.set("")
        st["history"].append(line); st["hist_i"] = len(st["history"])
        out(f"> {line}\n", "cmd")
        word = line.split()[0].lower()
        if word == "clear":
            con.configure(state="normal"); con.delete("1.0", "end"); con.configure(state="disabled"); return
        if word == "power":
            power_on(); return
        host = st["host"]
        if host is None:
            out("Power on first.\n", "err"); return
        if word == "help":
            out(help_text(host)); return
        if word == "reset":
            do_reset(); return
        err = host.start(line)
        if err:
            out(err + "\n", "err"); return
        st["busy_since"] = time.time()
        if not st["running"]:
            toggle_pause()

    def history(step):
        h = st["history"]
        if not h:
            return
        st["hist_i"] = max(0, min(len(h), st["hist_i"] + step))
        cmd_var.set(h[st["hist_i"]] if st["hist_i"] < len(h) else "")
        e_cmd.icursor("end")

    def draw():
        lines = st["core"].lines()
        cols = st["colours"]
        for y, c in enumerate(lines):
            if cols[y] != c:
                cols[y] = c
                canvas.itemconfigure(st["rects"][y], fill=neo_rgb(c))

    def tick():
        core = st["core"]
        if core and st["running"]:
            now = time.time()
            if fast_var.get():
                n = 30
            else:
                n = int((now - st["t_last"]) * 59.185)
                n = max(0, min(n, 6))          # catch up a little, never spiral
            if n:
                st["t_last"] += n / 59.185 if not fast_var.get() else (now - st["t_last"])
                for _ in range(n):
                    core.lib.neo_run_frame()
                    r = st["host"].poll() if st["host"] and st["host"].pending else None
                    if r:
                        stt, text, secs = r
                        out(text, "err" if stt == "timeout" else None)
                        st["busy_since"] = None
                draw()
                st["fps_n"] += n
            if now - st["fps_t"] >= 1.0:
                busy = f" | running {st['host'].pending[0]}..." if st["host"] and st["host"].pending else ""
                status.set(f"{'Fast' if fast_var.get() else 'Real time'}: {st['fps_n'] / (now - st['fps_t']):.0f} frames/s"
                           f" | PC ${core.lib.neo_pc():06X} | emulated {core.lib.neo_cycles() / 12e6:.1f} s"
                           f" | watchdog resets {core.lib.neo_watchdog_resets()}{busy}")
                st["fps_t"] = now; st["fps_n"] = 0
        root.after(5, tick)

    def persist():
        save_config({"rom": rom_var.get(), "z80": z80_var.get(), "watchdog": wd_var.get(), "fast": fast_var.get()})

    def on_close():
        persist(); root.destroy()

    e_cmd.bind("<Return>", lambda _e: send())
    e_cmd.bind("<Up>", lambda _e: history(-1))
    e_cmd.bind("<Down>", lambda _e: history(1))
    tree.bind("<Double-1>", lambda _e: (cmd_var.set(tree.item(tree.focus(), "text") + " "), e_cmd.focus_set(),
                                       e_cmd.icursor("end")))
    rom_var.trace_add("write", refresh_missing)
    root.protocol("WM_DELETE_WINDOW", on_close)
    out(f"{APP_NAME} {APP_VERSION} - Musashi 68000 + Neo Geo AES model, Brico16Bits-like host. No MAME needed.\n"
        "Not emulated: Z80/YM2610 (simulated answer), sound, sprites, fix layer.\n", "info")
    if refresh_missing():
        power_on()
    e_cmd.focus_set()
    root.after(5, tick)
    root._b68k = {"send": send, "state": st, "status": status, "console": con, "missing": missing_var}
    return root


# @@CORES@@

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--run" in args or "--check" in args:
        sys.exit(main_cli(args))
    try:
        main_gui(args[0] if args and not args[0].startswith("-") else None).mainloop()
    except ImportError:
        print("tkinter missing: use --run, or install Tk support for Python.")
        sys.exit(1)
