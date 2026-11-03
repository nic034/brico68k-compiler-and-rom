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
Z80 (superzazu/z80 core, 4 MHz) wired as on the board (sound latch, NMI,
reply latch, 2 KB RAM), running a built-in test M1 that only answers the
standard handshake ($03 reset -> $00, $01 -> $01), or no program at all (like
an AES without cartridge).
NOT emulated: YM2610 and sound, Z80 ROM banking, sprites and fix layer (the
screen shows the backdrop colour of each line), interrupts, cartridge, memory
card. Checked word for word against MAME: 32/32 commands with both Z80 setups.

Run: double-click, or  python Brico68k_Emulator.py [ROM]
Text mode: python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234" [--rom ROM]
           python Brico68k_Emulator.py --check [--rom ROM]
Python 3.8+, standard library only: nothing to install with pip. The window
needs Tkinter, which comes with Python on Windows (python.org installer) and is
the python3-tk package on Linux distributions that split it out.
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
APP_VERSION = "1.3"
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
    ap.add_argument("--z80", choices=["testm1", "none"], default="testm1",
                    help="testm1: Z80 runs the built-in test M1; none: Z80 without program")
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
    core.lib.neo_set_options(1 if a.z80 == "testm1" else 0, 1 if a.watchdog else 0)
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
    root.minsize(1000, 660)
    root.geometry(cfg.get("geometry") or "1280x820")

    # --- theme ---------------------------------------------------------------
    # light theme (white panels, GitHub-like greys and blue accent)
    C = dict(bg="#f3f5f7", panel="#ffffff", field="#ffffff", border="#d0d7de", text="#1f2328",
             muted="#59636e", accent="#0969da", ok="#1a7f37", warn="#9a6700", err="#cf222e",
             btn="#eef1f4", btn_hover="#e1e6eb", sel="#0969da", alert_bg="#ffebe9", alert_fg="#82071e")
    ui_font = ("Segoe UI", 10) if IS_WIN else ("DejaVu Sans", 10)
    ui_bold = (ui_font[0], 10, "bold")
    title_font = (ui_font[0], 15, "bold")
    mono = ("Consolas", 10) if IS_WIN else ("DejaVu Sans Mono", 10)
    root.configure(bg=C["bg"])
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=C["bg"], foreground=C["text"], fieldbackground=C["field"],
                    bordercolor=C["border"], lightcolor=C["border"], darkcolor=C["border"], font=ui_font)
    style.configure("Panel.TFrame", background=C["panel"])
    style.configure("Card.TFrame", background=C["panel"], borderwidth=1, relief="solid")
    style.configure("TLabel", background=C["bg"], foreground=C["text"])
    style.configure("Panel.TLabel", background=C["panel"], foreground=C["text"])
    style.configure("Muted.TLabel", background=C["panel"], foreground=C["muted"])
    style.configure("Head.TLabel", background=C["panel"], foreground=C["text"], font=ui_bold)
    style.configure("Title.TLabel", background=C["bg"], foreground=C["text"], font=title_font)
    style.configure("Sub.TLabel", background=C["bg"], foreground=C["muted"])
    style.configure("TButton", background=C["btn"], foreground=C["text"], padding=(10, 4), relief="flat")
    style.map("TButton", background=[("disabled", C["btn"]), ("active", C["btn_hover"])],
              foreground=[("disabled", C["muted"])])
    style.configure("Accent.TButton", background=C["sel"], foreground="#ffffff")
    style.configure("Small.TButton", padding=(6, 0))
    style.map("Accent.TButton", background=[("disabled", C["btn"]), ("active", "#0550ae")],
              foreground=[("disabled", C["muted"])])
    style.configure("TCheckbutton", background=C["bg"], foreground=C["text"])
    style.map("TCheckbutton", background=[("active", C["bg"])])
    style.configure("TRadiobutton", background=C["bg"], foreground=C["text"])
    style.map("TRadiobutton", background=[("active", C["bg"])])
    style.configure("TCombobox", fieldbackground=C["field"], background=C["btn"], foreground=C["text"],
                    arrowcolor=C["text"])
    style.map("TCombobox", fieldbackground=[("readonly", C["field"])], foreground=[("readonly", C["text"])])
    root.option_add("*TCombobox*Listbox.background", C["field"])
    root.option_add("*TCombobox*Listbox.foreground", C["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", C["sel"])
    style.configure("TEntry", fieldbackground=C["field"], foreground=C["text"], insertcolor=C["text"])
    style.configure("Treeview", background=C["field"], fieldbackground=C["field"], foreground=C["text"],
                    rowheight=22, borderwidth=0)
    style.map("Treeview", background=[("selected", "#ddf4ff")], foreground=[("selected", C["text"])])
    style.configure("Treeview.Heading", background=C["btn"], foreground=C["text"], relief="flat", font=ui_bold)
    style.configure("Vertical.TScrollbar", background=C["btn"], troughcolor=C["field"], arrowcolor=C["text"])
    style.configure("Busy.Horizontal.TProgressbar", troughcolor=C["field"], background=C["accent"])
    style.configure("TPanedwindow", background=C["bg"])

    st = {"core": None, "host": None, "rom": None, "running": False, "t_last": 0.0,
          "fps_t": time.time(), "fps_n": 0, "fps": 0.0, "history": list(cfg.get("history", []))[-50:],
          "hist_i": None, "busy_t0": None, "busy_name": "", "rects": [], "colours": [None] * 224,
          "scale": 2, "log": []}
    st["hist_i"] = len(st["history"])

    # --- header ---------------------------------------------------------------
    header = ttk.Frame(root); header.pack(fill="x", padx=14, pady=(10, 4))
    ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
    ttk.Label(header, text=f"  {APP_VERSION} · Neo Geo AES test bench, no MAME needed",
              style="Sub.TLabel").pack(side="left", pady=(4, 0))
    rom_info = tk.StringVar(value="")
    ttk.Label(header, textvariable=rom_info, style="Sub.TLabel").pack(side="right", pady=(4, 0))

    bar = ttk.Frame(root); bar.pack(fill="x", padx=14, pady=(4, 2))
    rom_var = tk.StringVar(value=rom_arg or cfg.get("rom") or default_rom())
    # buttons packed first from the right: they are never pushed out of a narrow window
    b_pause = ttk.Button(bar, text="Pause", width=8, command=lambda: toggle_pause()); b_pause.pack(side="right", padx=(3, 0))
    b_reset = ttk.Button(bar, text="Reset", width=8, command=lambda: do_reset()); b_reset.pack(side="right", padx=3)
    b_power = ttk.Button(bar, text="Power on", width=10, style="Accent.TButton", command=lambda: power_on())
    b_power.pack(side="right", padx=3)
    b_open = ttk.Button(bar, text="Open ROM...", command=lambda: pick_rom()); b_open.pack(side="right", padx=(6, 12))
    ttk.Label(bar, text="ROM").pack(side="left")
    e_rom = ttk.Entry(bar, textvariable=rom_var, width=20); e_rom.pack(side="left", fill="x", expand=True, padx=(6, 0))

    opts = ttk.Frame(root); opts.pack(fill="x", padx=14, pady=(2, 6))
    Z80_CHOICES = ["Test M1 (handshake only)", "No program (AES without cartridge)"]
    old = cfg.get("z80", "")
    z80_var = tk.StringVar(value=Z80_CHOICES[1] if ("without" in old or old.startswith("No")) else Z80_CHOICES[0])
    ttk.Label(opts, text="Z80").pack(side="left")
    ttk.Combobox(opts, textvariable=z80_var, values=Z80_CHOICES, state="readonly", width=34).pack(side="left", padx=(6, 18))
    wd_var = tk.BooleanVar(value=cfg.get("watchdog", False))
    ttk.Checkbutton(opts, text="Watchdog 135 ms (MAME MVS behaviour)", variable=wd_var,
                    command=lambda: apply_options()).pack(side="left", padx=(0, 18))
    speed_var = tk.StringVar(value="fast" if cfg.get("fast") else "real")
    ttk.Label(opts, text="Speed").pack(side="left")
    ttk.Radiobutton(opts, text="Real time", value="real", variable=speed_var).pack(side="left", padx=(6, 2))
    ttk.Radiobutton(opts, text="Fast", value="fast", variable=speed_var).pack(side="left", padx=2)
    z80_var.trace_add("write", lambda *_: apply_options())

    missing_var = tk.StringVar(value="")
    missing_box = tk.Label(root, textvariable=missing_var, justify="left", anchor="w", bg=C["alert_bg"],
                           fg=C["alert_fg"], bd=1, relief="solid", padx=12, pady=8, font=ui_font, wraplength=1200)

    # --- bottom: status bar, command bar (packed first: never pushed out) --------
    statusbar = tk.Frame(root, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
    statusbar.pack(fill="x", side="bottom")
    lamps = {}
    for key, label in (("cpu", "68000"), ("host", "Host"), ("z80", "Z80")):
        f = tk.Frame(statusbar, bg=C["panel"]); f.pack(side="left", padx=(10, 6), pady=3)
        dot = tk.Label(f, text="●", fg=C["muted"], bg=C["panel"], font=ui_font); dot.pack(side="left")
        txt = tk.Label(f, text=label, fg=C["text"], bg=C["panel"], font=ui_font); txt.pack(side="left")
        lamps[key] = (dot, txt, label)
    status = tk.StringVar(value="")
    tk.Label(statusbar, textvariable=status, fg=C["muted"], bg=C["panel"], font=ui_font, anchor="e").pack(
        side="right", padx=10)

    cmdbar = ttk.Frame(root); cmdbar.pack(fill="x", side="bottom", padx=14, pady=(4, 8))
    cmd_var = tk.StringVar()
    busy_var = tk.StringVar(value="")
    b_send = ttk.Button(cmdbar, text="Send", width=8, style="Accent.TButton", command=lambda: send())
    b_send.pack(side="right")
    busy_bar = ttk.Progressbar(cmdbar, style="Busy.Horizontal.TProgressbar", length=110, maximum=3.0)
    busy_bar.pack(side="right", padx=(0, 8))
    busy_lbl = ttk.Label(cmdbar, textvariable=busy_var, style="Sub.TLabel", width=24, anchor="e")
    busy_lbl.pack(side="right", padx=(6, 4))
    ttk.Label(cmdbar, text="Command", font=ui_bold).pack(side="left")
    e_cmd = ttk.Entry(cmdbar, textvariable=cmd_var, font=mono); e_cmd.pack(side="left", fill="x", expand=True, padx=8, ipady=3)

    # --- body ------------------------------------------------------------------
    body = ttk.Panedwindow(root, orient="horizontal"); body.pack(fill="both", expand=True, padx=14, pady=4)

    left = ttk.Frame(body, style="Card.TFrame", padding=10); body.add(left, weight=1)
    ttk.Label(left, text="Screen", style="Head.TLabel").pack(anchor="w")
    screen_holder = tk.Frame(left, bg=C["panel"]); screen_holder.pack(fill="x", pady=(4, 2))
    canvas = tk.Canvas(screen_holder, width=640, height=448, bg="#000000", highlightthickness=1,
                       highlightbackground="#8c959f")
    canvas.pack(anchor="n")
    for y in range(224):
        st["rects"].append(canvas.create_rectangle(0, 0, 0, 0, outline="", fill="#000000"))
    cap = ttk.Label(left, text="Backdrop colour of each line (palette $401FFE). Sprites and fix layer are not "
                    "drawn: TestDAC and Color are fully visible.", style="Muted.TLabel", wraplength=620)
    cap.pack(anchor="w")

    rpane = ttk.Panedwindow(body, orient="vertical"); body.add(rpane, weight=1)
    right = ttk.Frame(rpane, style="Card.TFrame", padding=10); rpane.add(right, weight=3)
    extp = ttk.Frame(rpane, style="Card.TFrame", padding=10); rpane.add(extp, weight=1)
    rhead = ttk.Frame(right, style="Panel.TFrame"); rhead.pack(fill="x")
    b_save = ttk.Button(rhead, text="Save log", width=9, style="Small.TButton", command=lambda: save_log()); b_save.pack(side="right")
    b_copy = ttk.Button(rhead, text="Copy", width=6, style="Small.TButton", command=lambda: copy_log()); b_copy.pack(side="right", padx=4)
    b_clear = ttk.Button(rhead, text="Clear", width=6, style="Small.TButton", command=lambda: clear()); b_clear.pack(side="right")
    ttk.Label(rhead, text="Console", style="Head.TLabel").pack(side="left")
    cframe = ttk.Frame(right, style="Panel.TFrame"); cframe.pack(fill="both", expand=True, pady=(6, 0))
    con = tk.Text(cframe, wrap="word", font=mono, state="disabled", bg="#fbfcfd", fg=C["text"], bd=0,
                  insertbackground=C["text"], padx=8, pady=6, selectbackground="#b6d7ff", highlightthickness=1,
                  highlightbackground=C["border"], highlightcolor=C["border"])
    csb = ttk.Scrollbar(cframe, command=con.yview); con.configure(yscrollcommand=csb.set)
    csb.pack(side="right", fill="y"); con.pack(fill="both", expand=True)
    con.tag_configure("cmd", foreground=C["accent"], font=(mono[0], mono[1], "bold"))
    con.tag_configure("info", foreground=C["muted"])
    con.tag_configure("err", foreground=C["err"])
    con.tag_configure("ok", foreground=C["ok"])
    con.tag_configure("warn", foreground=C["warn"])

    ttk.Label(extp, text="Extensions", style="Head.TLabel").pack(anchor="w", pady=(0, 2))
    frow = ttk.Frame(extp, style="Panel.TFrame"); frow.pack(fill="x")
    filter_var = tk.StringVar()
    e_filter = ttk.Entry(frow, textvariable=filter_var); e_filter.pack(side="left", fill="x", expand=True)
    b_ins = ttk.Button(frow, text="Insert", width=7, command=lambda: insert_selected()); b_ins.pack(side="right", padx=(6, 0))
    b_run = ttk.Button(frow, text="Run", width=7, command=lambda: run_selected()); b_run.pack(side="right", padx=(6, 0))
    ttk.Label(frow, text="Filter", style="Panel.TLabel").pack(side="left", padx=(0, 6), before=e_filter)
    tree_frame = ttk.Frame(extp, style="Panel.TFrame"); tree_frame.pack(fill="both", expand=True, pady=(4, 2))
    tree = ttk.Treeview(tree_frame, columns=("type",), show="tree headings", height=5, selectmode="browse")
    tree.heading("#0", text="Command", anchor="w"); tree.heading("type", text="Result", anchor="w")
    tree.column("#0", width=150, stretch=True); tree.column("type", width=70, stretch=False)
    tsb = ttk.Scrollbar(tree_frame, command=tree.yview); tree.configure(yscrollcommand=tsb.set)
    tsb.pack(side="right", fill="y"); tree.pack(fill="both", expand=True)
    desc_var = tk.StringVar(value="Select an extension to see its description.")
    desc_lbl = ttk.Label(extp, textvariable=desc_var, style="Muted.TLabel", wraplength=560, justify="left")
    desc_lbl.pack(anchor="w", fill="x")


    # --- helpers -----------------------------------------------------------------
    def out(text, tag=None):
        st["log"].append(text)
        con.configure(state="normal")
        if tag is None:                      # colour the verdict lines of the tests
            for line in text.splitlines(True):
                t = None
                s = line.lower()
                if s.startswith("=>"):
                    t = "ok" if "success" in s else ("err" if "fail" in s or "error" in s else "warn")
                elif "[timeout]" in s:
                    t = "err"
                con.insert("end", line, t)
        else:
            con.insert("end", text, tag)
        con.see("end")
        con.configure(state="disabled")

    def lamp(key, colour, text=None):
        dot, txt, label = lamps[key]
        dot.configure(fg=colour)
        txt.configure(text=text or label)

    def pick_rom():
        p = filedialog.askopenfilename(title="Brico68k ROM", filetypes=[("ROM", "*.bin"), ("All files", "*")],
                                       initialdir=str(Path(rom_var.get()).parent) if rom_var.get() else str(TOOL_DIR))
        if p:
            rom_var.set(p)
            power_on()

    def refresh_missing(*_):
        items = startup_check(rom_var.get().strip())
        if items:
            missing_var.set(f"Missing ({len(items)}) - fix this before powering on:\n" +
                            "\n".join(f"     • {w}: {d}" for w, d in items))
            missing_box.pack(fill="x", padx=14, pady=(0, 4), after=opts)
            rom_info.set("")
        else:
            missing_box.pack_forget()
            data = Path(rom_var.get()).read_bytes()
            major, minor = struct.unpack_from(">HH", data, 0x88)
            rom_info.set(f"BricoNeo {major}.{minor} · {len(parse_extensions(data))} extensions · "
                         f"{len(data) // 1024} KB")
        b_power.configure(state="disabled" if items else "normal")
        return not items

    def apply_options():
        if st["core"]:
            st["core"].lib.neo_set_options(0 if z80_var.get().startswith("No") else 1, 1 if wd_var.get() else 0)
        lamp("z80", C["ok"] if not z80_var.get().startswith("No") else C["warn"],
             "Z80 test M1" if not z80_var.get().startswith("No") else "Z80 no program")

    def fill_tree(*_):
        host = st["host"]
        tree.delete(*tree.get_children())
        if not host:
            return
        f = filter_var.get().strip().lower()
        for n, a, t, d in host.exts:
            if not f or f in n.lower() or f in d.lower():
                tree.insert("", "end", iid=n, text=n, values=(TYPE_NAMES.get(t, t),))

    def selected():
        sel = tree.selection()
        return sel[0] if sel else None

    def on_select(_e=None):
        n = selected()
        if n and st["host"]:
            name, addr, t, d = st["host"].find(n)
            desc_var.set(f"{name}  ·  ${addr:06X}  ·  result: {TYPE_NAMES.get(t, t)}\n{d}")

    def insert_selected():
        n = selected()
        if n:
            cmd_var.set(n + " ")
            e_cmd.focus_set(); e_cmd.icursor("end")

    def run_selected():
        n = selected()
        if n:
            send(n)

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
            st["host"] = Host(core, rom)
        except Exception as ex:
            out(f"Cannot start: {ex}\n", "err")
            return
        st["busy_t0"] = None
        fill_tree()
        major, minor = struct.unpack_from(">HH", rom, 0x88)
        out(f"--- Power on · {Path(rom_var.get()).name} · BricoNeo {major}.{minor} · "
            f"{len(st['host'].exts)} extensions · type Help ---\n", "info")
        st["running"] = True; st["t_last"] = time.time()
        b_pause.configure(text="Pause")
        persist()

    def do_reset():
        if st["core"]:
            st["core"].lib.neo_reset()
            st["host"].pending = None
            st["busy_t0"] = None
            out("--- Reset (RAM kept) ---\n", "info")

    def toggle_pause():
        if not st["core"]:
            return
        st["running"] = not st["running"]
        st["t_last"] = time.time()
        b_pause.configure(text="Pause" if st["running"] else "Run")

    def clear():
        con.configure(state="normal"); con.delete("1.0", "end"); con.configure(state="disabled")
        st["log"] = []

    def copy_log():
        root.clipboard_clear(); root.clipboard_append(con.get("1.0", "end-1c"))
        status.set("Console copied to the clipboard.")

    def save_log(path=None):
        p = path or filedialog.asksaveasfilename(title="Save console", defaultextension=".txt",
                                                 filetypes=[("Text", "*.txt"), ("All files", "*")],
                                                 initialfile="brico68k_console.txt")
        if p:
            Path(p).write_text(con.get("1.0", "end-1c"), encoding="utf-8")
            status.set(f"Console saved: {Path(p).name}")

    def send(line=None):
        line = (line if line is not None else cmd_var.get()).strip()
        if not line:
            return
        cmd_var.set("")
        if not st["history"] or st["history"][-1] != line:
            st["history"].append(line)
        st["hist_i"] = len(st["history"])
        out(f"> {line}\n", "cmd")
        word = line.split()[0].lower()
        if word == "clear":
            clear(); return
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
        st["busy_t0"] = st["core"].lib.neo_cycles()
        st["busy_name"] = host.pending[0]
        if not st["running"]:
            toggle_pause()

    def history(step):
        h = st["history"]
        if not h:
            return "break"
        st["hist_i"] = max(0, min(len(h), st["hist_i"] + step))
        cmd_var.set(h[st["hist_i"]] if st["hist_i"] < len(h) else "")
        e_cmd.icursor("end")
        return "break"

    def layout_screen(_e=None):
        # width of the left pane, but leave ~280 px of height to the extension list
        w = max(320, left.winfo_width() - 24)
        h = max(224, left.winfo_height() - 110)       # title + caption
        s = max(1.0, min(w / 320, h / 224))
        s = int(s * 4) / 4                   # quarter steps: each line keeps an integer-ish height
        if s == st["scale"] and _e is not None and canvas.winfo_width() > 10:
            return
        st["scale"] = s
        W, H = int(320 * s), int(224 * s)
        canvas.configure(width=W, height=H)
        for y, r in enumerate(st["rects"]):
            canvas.coords(r, 0, int(y * s), W, int((y + 1) * s))

    def draw():
        lines = st["core"].lines()
        cols = st["colours"]
        for y, c in enumerate(lines):
            if cols[y] != c:
                cols[y] = c
                canvas.itemconfigure(st["rects"][y], fill=neo_rgb(c))

    def tick():
        core = st["core"]
        now = time.time()
        if core and st["running"]:
            fast = speed_var.get() == "fast"
            if fast:
                n = 30
                st["t_last"] = now
            else:
                n = max(0, min(int((now - st["t_last"]) * 59.185), 6))
                st["t_last"] += n / 59.185
                if now - st["t_last"] > 0.5:
                    st["t_last"] = now        # never try to catch up after a stall
            host = st["host"]
            for _ in range(n):
                core.lib.neo_run_frame()
                r = host.poll() if host and host.pending else None
                if r:
                    stt, text, secs = r
                    out(text, "err" if stt == "timeout" else None)
                    if stt != "timeout":
                        out(f"   ({secs * 1000:.0f} ms)\n", "info")
                    st["busy_t0"] = None
            if n:
                draw()
                st["fps_n"] += n
        # busy indicator (emulated time against the 3 s host timeout)
        if st["busy_t0"] is not None and core:
            el = (core.lib.neo_cycles() - st["busy_t0"]) / 12e6
            busy_var.set(f"{st['busy_name']} · {min(el, 3.0):.1f} s / 3 s")
            busy_bar["value"] = min(el, 3.0)
            lamp("host", C["warn"], "Host busy")
        else:
            busy_var.set(""); busy_bar["value"] = 0
            lamp("host", C["ok"] if core else C["muted"], "Host ready" if core else "Host")
        if core:
            lamp("cpu", C["ok"] if st["running"] else C["warn"], "68000 running" if st["running"] else "68000 paused")
        else:
            lamp("cpu", C["muted"], "68000 off")
        if now - st["fps_t"] >= 1.0:
            st["fps"] = st["fps_n"] / (now - st["fps_t"])
            st["fps_t"] = now; st["fps_n"] = 0
            if core:
                status.set(f"{st['fps']:.0f} frames/s · PC ${core.lib.neo_pc():06X} · emulated "
                           f"{core.lib.neo_cycles() / 12e6:.1f} s · Z80 commands {core.lib.neo_z80_commands()} · "
                           f"watchdog resets {core.lib.neo_watchdog_resets()}")
        root.after(5, tick)

    def persist():
        save_config({"rom": rom_var.get(), "z80": z80_var.get(), "watchdog": wd_var.get(),
                     "fast": speed_var.get() == "fast", "history": st["history"][-50:],
                     "geometry": root.winfo_geometry()})

    def on_close():
        persist(); root.destroy()

    # --- bindings ------------------------------------------------------------------
    e_cmd.bind("<Return>", lambda _e: send())
    e_cmd.bind("<Up>", lambda _e: history(-1))
    e_cmd.bind("<Down>", lambda _e: history(1))
    tree.bind("<<TreeviewSelect>>", on_select)
    tree.bind("<Double-1>", lambda _e: insert_selected())
    tree.bind("<Return>", lambda _e: run_selected())
    filter_var.trace_add("write", fill_tree)
    rom_var.trace_add("write", refresh_missing)
    left.bind("<Configure>", lambda e: (layout_screen(e), cap.configure(wraplength=max(200, e.width - 24))))
    extp.bind("<Configure>", lambda e: desc_lbl.configure(wraplength=max(200, e.width - 24)))

    def keep_ext_visible(_e=None):
        # the extension pane never gets smaller than its filter row + 4 list rows + description
        h = rpane.winfo_height()
        try:
            if h > 300 and h - rpane.sashpos(0) < 250:
                rpane.sashpos(0, h - 250)
        except tk.TclError:
            pass
    rpane.bind("<Configure>", keep_ext_visible)

    def keep_console_wide(_e=None):
        # console column >= 440 px, screen column >= 360 px, whatever the window width
        w = body.winfo_width()
        try:
            pos = body.sashpos(0)
            if w > 820 and w - pos < 440:
                body.sashpos(0, w - 440)
            elif pos < 360:
                body.sashpos(0, 360)
        except tk.TclError:
            pass
    body.bind("<Configure>", keep_console_wide, add="+")
    root.bind("<Control-l>", lambda _e: clear())
    root.bind("<F5>", lambda _e: do_reset())
    root.bind("<F8>", lambda _e: toggle_pause())
    root.protocol("WM_DELETE_WINDOW", on_close)

    out(f"{APP_NAME} {APP_VERSION} · Musashi 68000 + Z80 + Neo Geo AES model · Brico16Bits-like host\n"
        "Z80 runs a built-in test M1 (handshake only). Not emulated: YM2610/sound, sprites, fix layer.\n"
        "Keys: Enter send · Up/Down history · F5 reset · F8 pause · Ctrl+L clear\n", "info")
    apply_options()
    root.update_idletasks()
    try:
        body.sashpos(0, max(420, int(root.winfo_width() * 0.52)))
        rpane.sashpos(0, max(150, min(int(rpane.winfo_height() * 0.62), rpane.winfo_height() - 250)))
    except tk.TclError:
        pass
    layout_screen()
    if refresh_missing():
        power_on()
    e_cmd.focus_set()
    root.after(5, tick)
    root._b68k = {"send": send, "state": st, "status": status, "console": con, "missing": missing_var,
                  "tree": tree, "filter": filter_var, "run_selected": run_selected, "insert": insert_selected,
                  "cmd": cmd_var, "reset": do_reset, "pause": toggle_pause, "z80": z80_var, "wd": wd_var,
                  "speed": speed_var, "save_log": save_log, "history": history, "busy": busy_var,
                  "lamps": lamps, "desc": desc_var, "rom": rom_var, "canvas": canvas,
                  "key_widgets": [b_open, b_power, b_reset, b_pause, b_send, b_run, b_ins, b_clear, b_copy, b_save,
                                  e_cmd, e_filter, tree, con, canvas]}
    return root


# @@CORES@@

if __name__ == "__main__":
    args = sys.argv[1:]
    if "--run" in args or "--check" in args:
        sys.exit(main_cli(args))
    try:
        main_gui(args[0] if args and not args[0].startswith("-") else None).mainloop()
    except ImportError:
        # Tkinter is part of Python but some Linux distributions ship it apart; pip cannot install it.
        if IS_WIN:
            hint = "Reinstall Python from python.org and keep the 'tcl/tk and IDLE' option ticked."
        elif sys.platform == "darwin":
            hint = "Install Python from python.org (it includes Tk), or: brew install python-tk"
        else:
            hint = ("Install the Tk package of your distribution, e.g. sudo apt install python3-tk "
                    "(Debian/Ubuntu), sudo dnf install python3-tkinter (Fedora), sudo pacman -S tk (Arch).")
        print("The window needs Tkinter, which this Python does not have.\n" + hint +
              "\nText mode works without it: python Brico68k_Emulator.py --run \"Help\"")
        sys.exit(1)
