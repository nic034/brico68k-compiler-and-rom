#!/usr/bin/env python3
"""mame_bench.py - Brico68k test bench in a REAL MAME (drivers "aes" / "neogeo").

A BricoNeo host is simulated in Lua (tools/mame_ext_runner.lua): it writes the
command and P1-P3 into the ROM, clears them right after the launch (like
Brico16Bits CommandExtension.cpp), decodes the output port (reads in
SYSTEM_ROM_MIRROR) and stops on EOT. MAME emulates the whole hardware: this is
the reference for the VRAM / LSPC / timing / audio tests.

Usage:
  python3 tools/mame_bench.py rom/Brico68k.bin                         # all
  python3 tools/mame_bench.py ROM Echo:0x1234 Read:0x320001 TestWRAM    # chosen
  python3 tools/mame_bench.py ROM @0xC00081                             # raw address

Environment variables:
  BRICO_SOUND_ROM   path of YOUR 000-lo.lo dump (needed by MAME, not provided)
  BRICO_MAME        mame binary (default /usr/games/mame)
  BRICO_DRIVER      "aes" (default) or "neogeo" (MVS: the ROM replaces sp-s2.sp1,
                    BRICO_MVS_DIR must hold YOUR sm1.sm1 and sfix.sfix dumps)
  BRICO_CART        folder made by tools/make_test_cart.py: inserts the synthetic
                    test cartridge "brtest" (known 3 MB P ROM, tiny Z80 M1)
  BRICO_STATUSB     "clear,set": forces STATUS_B bits (e.g. 0x00,0x80 = MVS)
  BRICO_STUCK       "start,end,or,and": simulated data fault on reads
  BRICO_ALIAS       "start,end,mask": stuck address / bank line
  BRICO_WAV         .wav path: records the audio output (TestAudio, PlayEyeSnd)
  BRICO_SNAP        "i,j,...": PNG screenshot after command number i (1 = first)
                    into BRICO_SNAP_DIR (BRICO_SNAP_FRAMES=30)
  BRICO_LOGREAD     "start,end,max": log CPU reads in that range
  BRICO_MEMDUMP     "start,end,file": binary copy of memory as the CPU sees it
  BENCH_SHORT=1     only print the verdict and the error details
More than 180 frames (3 s) is flagged: the real host gives up there.
MAME has no watchdog in the "aes" driver (MVS only)."""
import json, os, shutil, struct, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOUND = Path(os.environ.get("BRICO_SOUND_ROM", "000-lo.lo"))
MAME = os.environ.get("BRICO_MAME", "/usr/games/mame")
LUA = HERE / "mame_ext_runner.lua"


def parse_table(data):
    exts, off = [], 0xA0
    while True:
        addr, typ = struct.unpack_from(">IH", data, off)
        if addr == 0xFFFFFFFF:
            break
        off += 6
        end = data.index(b"\0", off); name = data[off:end].decode(); off = end + 1
        off += off & 1
        end = data.index(b"\0", off); off = end + 1
        off += off & 1
        exts.append((name, addr, typ))
    return exts


def run(rom, wanted=None, maxframes=400):
    data = Path(rom).read_bytes()
    exts = parse_table(data)
    jobs = []
    by_name = {n: a for n, a, t in exts}
    if wanted is None:
        wanted = [n for n, a, t in exts]
    for w in wanted:
        parts = w.split(":")
        name = parts[0]
        params = tuple(int(p, 0) for p in parts[1:]) + (0,) * (3 - len(parts[1:]))
        addr = int(name[1:], 0) if name.startswith("@") else by_name[name]
        jobs.append(f"{addr},{params[0]},{params[1]},{params[2]},{name.replace(',', '_')}")
    with tempfile.TemporaryDirectory(prefix="brico_bench_") as tmp:
        tmp = Path(tmp)
        driver = os.environ.get("BRICO_DRIVER", "aes")
        rs = tmp / "roms" / driver; rs.mkdir(parents=True)
        padded = data + b"\0" * (0x20000 - len(data))
        # MAME charge neo-epo.bin avec ROM_LOAD16_WORD_SWAP : le fichier doit
        # etre octets-inverses par mot (format des dumps BIOS Neo Geo), sinon
        # le 68000 lit des vecteurs inverses et plante des le reset.
        swapped = bytearray(padded); swapped[0::2], swapped[1::2] = padded[1::2], padded[0::2]
        (rs / ("sp-s2.sp1" if driver == "neogeo" else "neo-epo.bin")).write_bytes(bytes(swapped))
        if driver == "neogeo":
            mvs = Path(os.environ["BRICO_MVS_DIR"])
            for f in ("sm1.sm1", "sfix.sfix"):
                shutil.copyfile(mvs / f, rs / f)
        shutil.copyfile(SOUND, rs / "000-lo.lo")
        cart_args = []
        cart = os.environ.get("BRICO_CART")
        if cart:
            cart = Path(cart)
            dst = tmp / "roms" / "neogeo" / "brtest"
            shutil.copytree(cart / "roms" / "neogeo" / "brtest", dst)
            cart_args = ["-hashpath", str(cart / "hash"), "-cart1" if driver == "neogeo" else "-cart", "brtest"]
        snap_dir = os.environ.get("BRICO_SNAP_DIR")
        if snap_dir:
            Path(snap_dir).mkdir(parents=True, exist_ok=True)
            cart_args += ["-snapshot_directory", str(Path(snap_dir).resolve())]
        out = tmp / "out.jsonl"
        env = dict(os.environ, BRICO_OUT=str(out), BRICO_JOBS=";".join(jobs), BRICO_MAXFRAMES=str(maxframes),
                   HOME=str(tmp))
        wav = os.environ.get("BRICO_WAV")
        cmd = [MAME, driver, "-rompath", str(tmp / "roms"), "-skip_gameinfo", "-nothrottle",
               "-video", "none", "-sound", "none", *(["-wavwrite", wav] if wav else []), "-autoboot_script", str(LUA), "-seconds_to_run", "600",
               "-nvram_directory", str(tmp / "nv"), "-cfg_directory", str(tmp / "cfg"), *cart_args]
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=900)
        if os.environ.get("BENCH_DEBUG"):
            print(p.stdout[-4000:], p.stderr[-4000:])
        if not out.exists():
            raise SystemExit("no Lua output")
        rows = []
        for l in out.read_text(errors="replace").splitlines():
            if l.strip():
                try:
                    rows.append(json.loads(l))
                except ValueError:
                    rows.append({"raw": l[:200]})
        return rows, p


if __name__ == "__main__":
    rom = sys.argv[1]
    wanted = sys.argv[2:] or None
    res, p = run(rom, wanted)
    for r in res:
        if "name" in r:
            t = r["text"]
            verdict = "FAIL" if ("ailure" in t or "FAIL" in t) else "ok"
            if r["status"] == "eot" and r["frames"] > 180:
                verdict += " / OVER 3 s (real host times out)"
            print(f"=== {r['name']} [{r['status']}, {r['frames']} frames, {r['count']} values] -> {verdict}")
            if os.environ.get("BENCH_SHORT"):
                lines = [l for l in t.splitlines() if l.strip()]
                keep = [l for l in lines if any(k in l for k in ("Failure", "Address", "Expected", "Read  ", "Bad bits", "bank :", "=> "))]
                print("\n".join(keep) if keep else "\n".join(lines[-2:]))
            else:
                print(t if t.strip() else r["hex"][:400])
            if os.environ.get("BENCH_STACK"):
                print("   stack $10F2F0:", r.get("stack"))
        else:
            print(r)
