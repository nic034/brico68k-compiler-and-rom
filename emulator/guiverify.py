"""Drives the Brico68k Emulator window like a user and checks every function.
Usage: python3.12 guiverify.py Brico68k_Emulator.py OUTDIR"""
import importlib.util, subprocess, sys, time
from pathlib import Path

spec = importlib.util.spec_from_file_location("emu", sys.argv[1]); m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
root = m.main_gui()
b = root._b68k
st = b["state"]
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))


def pump(seconds):
    t = time.time() + seconds
    while time.time() < t:
        root.update()
        time.sleep(0.003)


def wait_idle(timeout=15):
    t = time.time() + timeout
    while time.time() < t:
        pump(0.05)
        if st["host"] and not st["host"].pending:
            return True
    return False


def console():
    return b["console"].get("1.0", "end-1c")


def shot(name):
    root.update()
    subprocess.run(["import", "-window", "root", "-crop",
                    f"{root.winfo_width()}x{root.winfo_height()}+{root.winfo_rootx()}+{root.winfo_rooty()}",
                    str(OUT / name)], check=False)


def all_inside(w, depth=0):
    """Every mapped widget fully inside the window (nothing pushed out)."""
    bad = []
    W, H = root.winfo_width(), root.winfo_height()
    for c in w.winfo_children():
        if not c.winfo_ismapped():
            continue
        x = c.winfo_rootx() - root.winfo_rootx(); y = c.winfo_rooty() - root.winfo_rooty()
        if c.winfo_width() > 1 and (x < 0 or y < 0 or x + c.winfo_width() > W + 1 or y + c.winfo_height() > H + 1):
            bad.append(f"{c.winfo_class()} {x},{y} {c.winfo_width()}x{c.winfo_height()}")
        bad += all_inside(c, depth + 1)
    return bad


pump(1.5)
check("auto power on", st["core"] is not None and st["running"])
check("23 extensions in the list", len(b["tree"].get_children()) == 23, str(len(b["tree"].get_children())))
check("lamps", "running" in b["lamps"]["cpu"][1].cget("text") and "ready" in b["lamps"]["host"][1].cget("text"))
shot("01_start.png")

# every extension, typed in the command bar, against --run text mode
cmds = ["Echo $BEEF", "Read 0x320001", "Write $5A $100001", "WriteB $A5 $100000", "Dump $100000 8", "TestInp",
        "TestWRAM", "TestBRAM", "TestPRAM", "TestVRAML", "TestVRAMU", "MarchVRAML", "MarchVRAMU", "TestLSPC",
        "Color $7FFF", "TestStatusA", "TestSystype", "TestZ80", "TestTiming", "PlayEyeSnd", "TestDAC 1"]
b["speed"].set("fast")
for c in cmds:
    b["cmd"].set(c)
    b["send"]()
    ok = wait_idle()
    if not ok:
        check(f"cmd {c} finished", False)
pump(0.3)
gui_text = console()
cli = subprocess.run([sys.executable, sys.argv[1], "--run", *cmds], capture_output=True, text=True).stdout
for c in cmds:
    seg_cli = cli.split(f"> {c}\n", 1)[1].split("[eot", 1)[0] if f"> {c}\n" in cli else None
    seg_gui = gui_text.split(f"> {c}\n", 1)[1].split("   (", 1)[0] if f"> {c}\n" in gui_text else None
    check(f"GUI = text mode: {c}", seg_cli is not None and seg_gui is not None and seg_cli.strip() == seg_gui.strip(),
          "" if seg_cli == seg_gui else f"cli={seg_cli!r:.80} gui={seg_gui!r:.80}")
b["speed"].set("real")
pump(1.0)
cols = set(st["colours"])
check("TestDAC 1: 16 colours on screen", len(cols) == 16, str(len(cols)))
shot("02_dac.png")

# TestAudio then a command sent during the beeps -> [Timeout] (same as Brico16Bits)
b["speed"].set("fast")
b["send"]("TestAudio"); wait_idle()
b["send"]("Echo 1"); wait_idle()
check("command during TestAudio beeps times out", console().rstrip().endswith("[Timeout]"), console()[-60:])
b["send"]("Echo 2"); wait_idle()
check("next command works again", "0x0002" in console()[-40:])

# built-ins, errors
b["send"]("Help"); pump(0.2)
check("Help lists the extensions", "23 extensions in this ROM" in console())
b["send"]("Nope"); pump(0.2)
check("unknown command message", "Unknown command: Nope" in console())

# history
b["cmd"].set(""); b["history"](-1)
check("history Up", b["cmd"].get() == "Nope", b["cmd"].get())
b["history"](-1)
check("history Up twice", b["cmd"].get() == "Help", b["cmd"].get())
b["history"](1); b["history"](1)
check("history back to empty", b["cmd"].get() == "", b["cmd"].get())

# filter + select + run + insert
b["filter"].set("march")
kids = b["tree"].get_children()
check("filter 'march'", list(kids) == ["MarchVRAML", "MarchVRAMU"], str(kids))
b["tree"].selection_set("MarchVRAMU"); pump(0.1)
check("description shown", "MarchVRAMU" in b["desc"].get() and "March-C" in b["desc"].get())
b["insert"]()
check("Insert puts the name in the command bar", b["cmd"].get() == "MarchVRAMU ")
b["cmd"].set("")
b["run_selected"](); wait_idle()
check("Run executes the selected extension", "March" in console()[-300:] and "success" in console()[-120:])
b["filter"].set("")
check("filter cleared", len(b["tree"].get_children()) == 23)

# Z80 option
b["z80"].set("No program (AES without cartridge)"); pump(0.1)
b["send"]("TestZ80"); wait_idle()
check("Z80 no program -> INCONCLUSIVE", "INCONCLUSIVE" in console()[-400:])
b["z80"].set("Test M1 (handshake only)"); pump(0.1)
b["send"]("TestZ80"); wait_idle()
check("Z80 test M1 -> success", "Test success" in console()[-300:])

# watchdog option
b["wd"].set(True); root.nametowidget  # checkbutton variable only: apply like the click does
st["core"].lib.neo_set_options(1, 1)
b["send"]("TestWatchdog"); wait_idle(); pump(0.4)
b["send"]("TestWatchdog"); wait_idle()
check("watchdog on: reset measured", "after ~13" in console()[-400:], console()[-200:])
b["wd"].set(False); st["core"].lib.neo_set_options(1, 0)

# pause / reset / busy indicator
b["speed"].set("real")
b["pause"](); pump(0.3)
check("pause", not st["running"] and "paused" in b["lamps"]["cpu"][1].cget("text"))
b["send"]("MarchVRAML"); pump(0.15)
check("sending while paused resumes", st["running"])
pump(0.35)
check("busy indicator shows the running test", "MarchVRAML" in b["busy"].get(), repr(b["busy"].get()))
shot("03_busy.png")
wait_idle()
check("busy indicator cleared", b["busy"].get() == "")
b["reset"](); pump(0.3)
b["send"]("Echo 3"); wait_idle()
check("works after Reset", "0x0003" in console()[-40:])

# simulated faults, through the dialog
b["speed"].set("fast")
b["faults_dialog"](); pump(0.3)
fu = st["fault_ui"]
fu["add"]("wram:lane:upper"); pump(0.1)
check("fault lamp red with 1 fault", "1 fault" in b["lamps"]["fault"][1].cget("text"), b["lamps"]["fault"][1].cget("text"))
b["send"]("TestWRAM"); wait_idle()
check("WRAM chip dead -> TestWRAM failure", "Test Failure" in console()[-600:])
fu["reg"].set("Palette RAM"); pump(0.05); fu["kind"].set("Data bit stuck"); pump(0.05)
fu["bit"].set("11"); fu["lvl"].set("0"); fu["add_form"](); pump(0.1)
check("form adds 'Palette RAM: data bit D11 stuck at 0'", any("D11 stuck at 0" in fu["list"].get(i) for i in range(fu["list"].size())))
b["send"]("TestDAC"); wait_idle(); pump(0.5)
band_r4 = st["core"].lines()[7]
check("palette D11 stuck at 0 -> R4 band black on screen", band_r4 == 0, hex(band_r4))
shot("06_faults.png")
fu["bit"].set("99"); fu["add_form"](); pump(0.05)
check("out-of-range bit refused with a message", "data bits" in fu["err"].get(), fu["err"].get())
fu["reg"].set("WRAM"); pump(0.05); fu["kind"].set("Address line stuck"); pump(0.05)
check("WRAM address line range shown", fu["bit"].get() == "1")
fu["list"].selection_set(0); fu["remove"](); pump(0.1)
check("remove selected", len(st["faults"]) == 1)
fu["clear"](); pump(0.1)
check("clear all", not st["faults"] and "No fault" in b["lamps"]["fault"][1].cget("text"))
b["send"]("TestWRAM"); wait_idle()
check("healthy again -> TestWRAM success", "success" in console()[-200:].lower())
fu["add"]("vramlo:addr:3:0"); pump(0.1)
import json
cfgp = Path(sys.argv[1]).resolve().parent / "brico68k_emulator" / "config.json"
check("faults saved in the settings", "vramlo:addr:3:0" in json.loads(cfgp.read_text()).get("faults", []))
fu["clear"](); fu["win"].destroy(); pump(0.1)
b["speed"].set("real")

# save log
lp = OUT / "log.txt"
b["save_log"](str(lp))
check("Save log writes the console", lp.is_file() and "MarchVRAML" in lp.read_text(encoding="utf-8"))

# window sizes: nothing pushed out, screen keeps its ratio
for geo in ("1000x660", "1280x820", "1600x1000"):
    root.geometry(geo); pump(0.6)
    bad = all_inside(root)
    cw, ch = int(b["canvas"].cget("width")), int(b["canvas"].cget("height"))
    check(f"{geo}: every widget inside the window", not bad, "; ".join(bad[:3]))
    check(f"{geo}: screen ratio 320:224", abs(cw * 224 - ch * 320) <= 320, f"{cw}x{ch}")
    hidden = [w.winfo_class() + ":" + (w.cget("text") if "text" in w.keys() else "") for w in b["key_widgets"] if not w.winfo_viewable()]
    check(f"{geo}: every button / field visible", not hidden, ", ".join(hidden))
    squeezed = [(w.cget("text") if "text" in w.keys() else w.winfo_class()) for w in b["key_widgets"]
                if w.winfo_class() in ("TButton",) and w.winfo_width() < w.winfo_reqwidth() - 2]
    check(f"{geo}: no button squeezed", not squeezed, ", ".join(squeezed))
    need = {"1000x660": 1.0, "1280x820": 1.5, "1600x1000": 2.0}[geo]
    check(f"{geo}: screen scale >= {need}", cw >= 320 * need, f"{cw}x{ch}")
    shot(f"04_{geo}.png")

# missing ROM box
bad_rom = OUT / "bad.bin"; bad_rom.write_bytes(b"\0" * 4096)
b["rom"].set(str(bad_rom)); pump(0.3)
check("bad ROM: red box + Power disabled", "Missing" in b["missing"].get())
shot("05_missing.png")

root.destroy()
fails = [r for r in results if not r[1]]
for n, ok, d in results:
    print(("PASS " if ok else "FAIL ") + n + (f"  [{d}]" if d and not ok else ""))
print(f"{len(results) - len(fails)}/{len(results)} checks passed")
