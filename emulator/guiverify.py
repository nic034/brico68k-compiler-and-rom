"""Drives the Brico68k Emulator window like a user and checks every function.
Usage: python3.12 guiverify.py Brico68k_Emulator.py OUTDIR   (needs a display, e.g. xvfb-run)"""
import importlib.util, json, subprocess, sys, time
from pathlib import Path

spec = importlib.util.spec_from_file_location("emu", sys.argv[1]); m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
OUT = Path(sys.argv[2]); OUT.mkdir(parents=True, exist_ok=True)
cfgp = Path(sys.argv[1]).resolve().parent / "brico68k_emulator" / "config.json"
if cfgp.exists():
    cfgp.unlink()                                   # start from default settings
root = m.main_gui()
b = root._b68k
st = b["state"]
tree = b["tree"]; nb = b["notebook"]; tabs = b["tabs"]
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))


def pump(seconds):
    t = time.time() + seconds
    while time.time() < t:
        root.update()
        time.sleep(0.003)


def wait_idle(timeout=20):
    t = time.time() + timeout
    while time.time() < t:
        pump(0.05)
        if st["host"] and not st["host"].pending and not st["plan"] and st["wait_until"] is None:
            return True
    return False


def console():
    return b["console"].get("1.0", "end-1c")


def report():
    return b["report_text"].get("1.0", "end-1c")


def badge(name):
    return tree.item(name, "values")[0] if tree.exists(name) else None


def shot(name):
    root.update()
    subprocess.run(["import", "-window", "root", "-crop",
                    f"{root.winfo_width()}x{root.winfo_height()}+{root.winfo_rootx()}+{root.winfo_rooty()}",
                    str(OUT / name)], check=False)


def all_inside(w):
    """Every mapped widget fully inside the window (nothing pushed out)."""
    bad = []
    W, H = root.winfo_width(), root.winfo_height()
    for c in w.winfo_children():
        if not c.winfo_ismapped():
            continue
        x = c.winfo_rootx() - root.winfo_rootx(); y = c.winfo_rooty() - root.winfo_rooty()
        if c.winfo_width() > 1 and (x < 0 or y < 0 or x + c.winfo_width() > W + 1 or y + c.winfo_height() > H + 1):
            bad.append(f"{c.winfo_class()} {x},{y} {c.winfo_width()}x{c.winfo_height()}")
        bad += all_inside(c)
    return bad


def buttons(w):
    out = []
    for c in w.winfo_children():
        if c.winfo_class() == "TButton" and c.winfo_ismapped():
            out.append(c)
        out += buttons(c)
    return out


def layout_checks(tag):
    bad = all_inside(root)
    check(f"{tag}: every widget inside the window", not bad, "; ".join(bad[:3]))
    sq = [c.cget("text") for c in buttons(root) if c.winfo_width() < c.winfo_reqwidth() - 2]
    check(f"{tag}: no button squeezed", not sq, ", ".join(sq))


pump(1.5)
ext_rows = [i for g in tree.get_children() for i in tree.get_children(g)]
groups = [tree.item(g, "text") for g in tree.get_children()]
check("auto power on", st["core"] is not None and st["running"])
check("23 extensions in the sidebar", len(ext_rows) == 23, str(len(ext_rows)))
check("grouped by category", groups == ["Memory", "Video", "Sound", "Inputs and system", "Tools"], str(groups))
check("Tools group collapsed", not tree.item("cat_Tools", "open"))
check("lamps", "running" in b["lamps"]["cpu"][1].cget("text") and "ready" in b["lamps"]["host"][1].cget("text"))
check("all badges empty before a run", all(badge(n) == "" for n in ext_rows))
shot("01_start.png")

# --- Run all, healthy console, default settings (Z80 test M1, no watchdog), fast -----------------------------
b["speed"].set("fast")
b["run_all"](); pump(0.2)
check("Run all button shows progress", "Running" in str([w.cget("text") for w in b["key_widgets"][4:5]]))
check("Run all finished", wait_idle(60))
pump(0.3)
expect = {"TestWRAM": "PASS", "TestBRAM": "N/A", "TestPRAM": "PASS", "TestVRAML": "PASS", "TestVRAMU": "PASS",
          "MarchVRAML": "PASS", "MarchVRAMU": "PASS", "TestLSPC": "PASS", "TestTiming": "PASS", "TestDAC": "LOOK",
          "TestZ80": "PASS", "TestAudio": "PASS", "PlayEyeSnd": "N/A", "TestInp": "INFO", "TestStatusA": "INFO",
          "TestSystype": "INFO", "TestWatchdog": "N/A"}
for n, e in expect.items():
    check(f"Run all badge {n} = {e}", badge(n) == e, str(badge(n)))
check("tools not run by Run all", all(badge(n) == "" for n in m.TOOLS))
check("summary line", b["summary"].get().startswith("10 pass") and "1 look" in b["summary"].get(), b["summary"].get())
check("console 'Run all done' with summary", "Run all done: 10 pass" in console())
check("TestDAC last: 16 colours on screen", len(set(st["colours"])) == 16, str(len(set(st["colours"]))))
check("report shows the last test", "TestDAC" in report() and "LOOK" in b["verdict"].cget("text"))
shot("02_runall.png")

# report of one test, by selecting it
tree.selection_set("MarchVRAMU"); pump(0.2)
check("report verdict for selected test", b["verdict"].cget("text").startswith("PASS") and "success" in b["verdict"].cget("text"))
check("report raw output", "> MarchVRAMU" in report() and "ms emulated" in report())
tree.selection_set("TestWatchdog"); pump(0.1)
check("watchdog N/A explained", "enable it in Settings" in b["verdict"].cget("text"))

# GUI result = text mode (--run), for every test and every tool
cmds = ["Echo $BEEF", "Read 0x320001", "Write $5A $100001", "WriteB $A5 $100000", "Dump $100000 8", "TestInp",
        "TestWRAM", "TestBRAM", "TestPRAM", "TestVRAML", "TestVRAMU", "MarchVRAML", "MarchVRAMU", "TestLSPC",
        "Color $7FFF", "TestStatusA", "TestSystype", "TestZ80", "TestTiming", "PlayEyeSnd", "TestDAC 1"]
b["send"]("Power"); pump(0.2)            # fresh RAM, like --run (Run all left test patterns in WRAM)
b["send"]("Clear"); pump(0.1)
for c in cmds:
    b["cmd"].set(c); b["send"](); wait_idle()
pump(0.3)
gui_text = console()
cli = subprocess.run([sys.executable, sys.argv[1], "--run", *cmds], capture_output=True, text=True).stdout
for c in cmds:
    seg_cli = cli.split(f"> {c}\n", 1)[1].split("[eot", 1)[0] if f"> {c}\n" in cli else None
    seg_gui = gui_text.split(f"> {c}\n", 1)[1].split("   (", 1)[0] if f"> {c}\n" in gui_text else None
    check(f"GUI = text mode: {c}", seg_cli is not None and seg_gui is not None and seg_cli.strip() == seg_gui.strip(),
          "" if seg_cli == seg_gui else f"cli={seg_cli!r:.80} gui={seg_gui!r:.80}")
check("typed command updates its badge", badge("Echo") == "INFO" and badge("TestWRAM") == "PASS")

# Run selected, from the sidebar
tree.selection_set("TestLSPC"); pump(0.05)
b["run_selected"](); pump(0.1)
check("Run selected opens the Report tab", nb.select() == str(tabs["report"]))
wait_idle()
check("Run selected result", badge("TestLSPC") == "PASS" and "> TestLSPC" in report())
tree.selection_set("Dump"); pump(0.05); b["run_selected"](); pump(0.1)
check("tool: Run selected goes to the console with the name typed", nb.select() == str(tabs["console"])
      and b["cmd"].get() == "Dump ")
b["cmd"].set("")

# command during TestAudio beeps -> [Timeout] (same as Brico16Bits) -> FAIL badge
b["send"]("TestAudio"); wait_idle()
b["send"]("TestWRAM"); wait_idle()
check("command during the beeps times out", "[Timeout]" in console()[-200:])
check("timeout gives a FAIL badge", badge("TestWRAM") == "FAIL")
tree.selection_set("TestWRAM"); pump(0.1)
check("timeout verdict explained", "Timeout" in b["verdict"].cget("text"))
b["send"]("TestWRAM"); wait_idle()
check("next run is PASS again", badge("TestWRAM") == "PASS")

# built-ins, errors, history
b["send"]("Help"); pump(0.2)
check("Help lists the extensions", "23 extensions in this ROM" in console())
b["send"]("Nope"); pump(0.2)
check("unknown command message", "Unknown command: Nope" in console())
b["cmd"].set(""); b["history"](-1)
check("history Up", b["cmd"].get() == "Nope", b["cmd"].get())
b["history"](-1)
check("history Up twice", b["cmd"].get() == "Help", b["cmd"].get())
b["history"](1); b["history"](1)
check("history back to empty", b["cmd"].get() == "", b["cmd"].get())

# Settings: Z80 without program -> Run all explains the expected Z80 failures
b["z80"].set("No program (AES without cartridge)"); pump(0.1)
check("Z80 lamp follows the setting", "no program" in b["lamps"]["z80"][1].cget("text"))
b["run_all"](); wait_idle(60); pump(0.2)
check("no program: TestZ80 CHECK", badge("TestZ80") == "CHECK", str(badge("TestZ80")))
check("no program: TestAudio FAIL", badge("TestAudio") == "FAIL", str(badge("TestAudio")))
tree.selection_set("TestAudio"); pump(0.1)
check("no program: failure marked as expected", "Expected here" in b["verdict"].cget("text"))
b["z80"].set("Test M1 (handshake only)"); pump(0.1)

# Settings: watchdog -> Run all runs TestWatchdog twice and reads the result
b["wd"].set(True); pump(0.1)
b["run_all"](); wait_idle(60); pump(0.2)
check("watchdog on: TestWatchdog PASS after two passes", badge("TestWatchdog") == "PASS", str(badge("TestWatchdog")))
check("watchdog on: 11 pass", b["summary"].get().startswith("11 pass"), b["summary"].get())
b["wd"].set(False); pump(0.1)

# Stop during Run all
b["run_all"](); pump(0.15)
b["stop"](); wait_idle()
check("Stop ends Run all early", "Run all stopped" in console() and badge("TestDAC") == "", str(badge("TestDAC")))

# pause / reset / busy indicator
b["speed"].set("real")
b["pause"](); pump(0.3)
check("pause", not st["running"] and "paused" in b["lamps"]["cpu"][1].cget("text"))
b["send"]("MarchVRAML"); pump(0.15)
check("sending while paused resumes", st["running"])
pump(0.35)
check("busy indicator shows the running test", "MarchVRAML" in b["busy"].get(), repr(b["busy"].get()))
check("running badge", badge("MarchVRAML") == "RUNNING", str(badge("MarchVRAML")))
tree.selection_set("MarchVRAML"); pump(0.1)
check("report says RUNNING, not the old result", b["verdict"].cget("text").startswith("RUNNING"), b["verdict"].cget("text"))
shot("03_busy.png")
wait_idle()
check("busy indicator cleared", b["busy"].get() == "")
b["reset"](); pump(0.3)
b["send"]("Echo 3"); wait_idle()
check("works after Reset", "0x0003" in console()[-40:])

# simulated faults, from the Faults tab
b["speed"].set("fast")
nb.select(tabs["faults"]); pump(0.3)
b["fault_add"]("wram:lane:upper"); pump(0.1)
check("fault lamp red with 1 fault", "1 fault" in b["lamps"]["fault"][1].cget("text"), b["lamps"]["fault"][1].cget("text"))
check("Faults tab title shows the count", nb.tab(tabs["faults"], "text") == "Faults (1)")
shot("06_faults.png")
b["run_all"](); wait_idle(60); pump(0.2)
check("WRAM chip dead -> TestWRAM FAIL in Run all", badge("TestWRAM") == "FAIL", str(badge("TestWRAM")))
check("other tests still pass", badge("TestPRAM") == "PASS" and badge("MarchVRAMU") == "PASS")
check("68000 exception in TestAudio (stack in dead WRAM) -> FAIL", badge("TestAudio") == "FAIL", str(badge("TestAudio")))
tree.selection_set("TestAudio"); pump(0.1)
check("exception verdict points to TestWRAM", "EXCEPTION" in b["verdict"].cget("text") and "TestWRAM" in b["verdict"].cget("text"))
reg, kind, bit, lvl, add_form, ferr = b["fault_form"]
reg.set("Palette RAM"); pump(0.05); kind.set("Data bit stuck"); pump(0.05)
bit.set("11"); lvl.set("0"); add_form(); pump(0.1)
fl = b["fault_list"]
check("form adds 'Palette RAM: data bit D11 stuck at 0'", any("D11 stuck at 0" in fl.get(i) for i in range(fl.size())))
b["send"]("TestDAC"); wait_idle(); pump(0.5)
check("palette D11 stuck at 0 -> R4 band black on screen", st["core"].lines()[7] == 0, hex(st["core"].lines()[7]))
bit.set("99"); add_form(); pump(0.05)
check("out-of-range bit refused with a message", "data bits" in ferr.get(), ferr.get())
reg.set("WRAM"); pump(0.05); kind.set("Address line stuck"); pump(0.05)
check("WRAM address line range shown", bit.get() == "1")
fl.selection_set(0); b["fault_remove"](); pump(0.1)
check("remove selected", len(st["faults"]) == 1)
b["fault_clear"](); pump(0.1)
check("clear all", not st["faults"] and "No fault" in b["lamps"]["fault"][1].cget("text"))
b["send"]("TestWRAM"); wait_idle()
check("healthy again -> TestWRAM PASS", badge("TestWRAM") == "PASS")
b["fault_add"]("vramlo:addr:3:0"); pump(0.1)
check("faults saved in the settings", "vramlo:addr:3:0" in json.loads(cfgp.read_text()).get("faults", []))
b["fault_clear"](); pump(0.1)

# screen: thumbnail click opens the Screen tab, big screen scaled
b["thumb"].event_generate("<Button-1>", x=10, y=10); pump(0.3)
check("thumbnail opens the Screen tab", nb.select() == str(tabs["screen"]))
shot("07_screen.png")

# save log
lp = OUT / "log.txt"
b["save_log"](str(lp))
check("Save log writes the console", lp.is_file() and "MarchVRAML" in lp.read_text(encoding="utf-8"))

# window sizes, every tab
b["speed"].set("real")
for geo in ("1000x660", "1280x820", "1600x1000"):
    root.geometry(geo); pump(0.6)
    for tname in ("report", "console", "screen", "faults", "settings"):
        nb.select(tabs[tname]); pump(0.25)
        layout_checks(f"{geo} {tname}")
        if tname == "screen":
            cw, ch = int(b["big"].cget("width")), int(b["big"].cget("height"))
            check(f"{geo}: screen ratio 320:224", abs(cw * 224 - ch * 320) <= 320, f"{cw}x{ch}")
            need = {"1000x660": 1.0, "1280x820": 1.5, "1600x1000": 2.0}[geo]
            check(f"{geo}: screen scale >= {need}", cw >= 320 * need, f"{cw}x{ch}")
        shot(f"04_{geo}_{tname}.png")
    hidden = [w.winfo_class() + ":" + (w.cget("text") if "text" in w.keys() else "") for w in b["key_widgets"]
              if not w.winfo_viewable()]
    check(f"{geo}: header and sidebar widgets visible", not hidden, ", ".join(hidden))
    check(f"{geo}: sidebar tree at least 8 rows high", tree.winfo_height() >= 8 * 24, str(tree.winfo_height()))
nb.select(tabs["report"])

# missing ROM box
bad_rom = OUT / "bad.bin"; bad_rom.write_bytes(b"\0" * 4096)
good = b["rom"].get()
b["rom"].set(str(bad_rom)); pump(0.3)
check("bad ROM: red box + Power disabled", "Missing" in b["missing"].get()
      and str(b["key_widgets"][0].cget("state")) == "disabled")
shot("05_missing.png")
b["rom"].set(good); pump(0.2)
check("good ROM again: box gone", not b["missing"].get() or str(b["key_widgets"][0].cget("state")) == "normal")

root.destroy()
fails = [r for r in results if not r[1]]
for n, ok, d in results:
    print(("PASS " if ok else "FAIL ") + n + (f"  [{d}]" if d and not ok else ""))
print(f"{len(results) - len(fails)}/{len(results)} checks passed")
