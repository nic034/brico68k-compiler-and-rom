# Brico68k Compiler and ROM

A one-file tool that builds the **Brico68k** Neo Geo diagnostic ROM, and a ready-to-use build
of an extended Brico68k (BricoNeo 1.35 + review fixes + new tests).

The ROM runs on the **BricoNeo** board, driven by the unmodified **Brico16Bits** host firmware.
It is a BIOS-socket diagnostic for Neo Geo AES and MVS consoles.

| Path | What it is |
|---|---|
| `Brico68k_Compiler.py` | Brico68k Compiler 1.2 (Python 3.8+, standard library only, Tk window) |
| `rom/Brico68k.bin` | Ready-to-use ROM, 128 KB padded with `$FF` (SHA-256 in `rom/Brico68k.bin.sha256`) |
| `source/` | Firmware source used to build that ROM (vasm Motorola syntax) |
| `tools/` | Cartridge checksum tool and the MAME test bench |

## Quick start

1. Install Python 3.8 or newer (python.org; on Windows tick "Add to PATH").
2. Double-click `Brico68k_Compiler.py`, or run `python Brico68k_Compiler.py`.
3. Click **Build**. The result is `output/Brico68k.bin`.
4. Plug the BricoNeo in over USB, then click **Detect** and **Copy Brico68k.bin**.
   `BANK0` is saved and loaded at start-up; the drive root loads into RAM only.

The vasm assembler and the vlink linker are taken care of automatically:

- **Windows x64 and Linux x64**: vasm 1.9d and vlink 0.17a are embedded in the script, so
  nothing is downloaded.
- **Other systems** (macOS...): the tool downloads their sources and builds them with gcc or
  clang. Without a C compiler, it installs the zig compiler through pip.

Everything the tool creates stays in `brico68k_compiler/` next to the script.

At start-up the window lists anything that is missing in a red box: source files, includes,
the embedded tools, or a writable output folder. It refuses to build until the list is empty.

Text mode:

```
python Brico68k_Compiler.py --check                      # only list missing files
python Brico68k_Compiler.py --cli                        # build ./source into ./output
python Brico68k_Compiler.py --cli --source github        # latest Aurelien34/Brico68k release
python Brico68k_Compiler.py --cli --source github:main   # upstream development branch
```

The GitHub sources are Aurelien's original code, **without** the fixes and tests of this
repository.

## ROM contents: 24 extensions

Commands are typed on the Brico16Bits console. "No WRAM" means the test never relies on
work RAM (no stack), so it still runs on a board with dead WRAM.

| Command | No WRAM | What it does |
|---|:-:|---|
| Echo, Read, Write, WriteB, Dump | yes | Link check and raw memory access. Odd addresses are handled. |
| TestInp | yes | Controllers, memory card detect, AES/MVS mode |
| TestWRAM / TestBRAM / TestPRAM | yes | Data bus walking 1/0, patterns, address lines; PRAM checks both banks + bank select. TestBRAM is MVS only and destructive. |
| TestVRAML / TestVRAMU / MarchVRAML / MarchVRAMU | yes | Slow and fast VRAM, including March-C |
| TestLSPC | yes | LSPC2-A2 registers, VRAM auto-increment |
| Color | yes | Whole screen in one colour (upstream) |
| TestStatusA / TestSystype | yes | Coin, service and RTC bits / TEST and JAMMA sense, AES/MVS aware |
| TestAudio | no | Z80 handshake, then left / right / centre beeps (upstream, reworked). Wait ~4 s before the next command. |
| PlayEyeSnd | yes | Eyecatcher music, sound command `$02` (upstream) |
| **TestZ80** | yes | Z80 handshake 03/01/03: needs 16 stable fresh replies, flags a latch echo |
| **TestDAC** | yes | RGB DAC pattern: 16 bands, one colour bit each. `P1=1` adds the dark bit; `P1=$10+n` fills the screen with band n for a scope or multimeter. |
| **TestTiming** | yes | LSPC line counter (+1 steps, range, lines per frame, stuck bits named), CPU cycles per frame, auto-animation counter |
| **TestCart** | yes | P1 ROM checksum, stuck data bits, mirror size. `P1=1` checks the P2 window, banks 0-7. |
| **TestWatchdog** | no | First run starves the watchdog; the second run reports the reset and its delay |

Bold entries are new in this repository.

To check a cartridge, compare TestCart with its dump:
`python tools/cart_checksum.py 201-p1.p1` prints the same `s1` / `s2` values.

### Changes compared with upstream Brico68k 1.35

- **Exceptions**: every 68000 exception vector used to point to address 0. They now print
  the exception and return to the command loop. Vector 9 stays the upstream TRACE debugger.
- **Command read**: the command word is re-read until stable, which fixes a torn 32-bit read.
- **Palette bank registers**: `$3A000F` selects bank 0 and `$3A001F` bank 1. This was checked
  in MAME (`snk/neogeo.cpp`, `write_a3`); upstream 1.35 still has them swapped.
- **TestAudio**: the Brico16Bits host waits for one EOT with a fixed 3 s timeout. The 1.35
  version sent an EOT after its first line, so its later messages were lost. It now sends
  one EOT before the beeps and no longer leaks stack on the error path.
- **Write**: odd addresses no longer crash with a 68000 address error.
- **RAM tests**: more precise reports (address, expected, read, bad bits, byte lane), plus
  general optimizations.

## References

| Component | Version used |
|---|---|
| Brico16Bits host firmware | [Aurelien34/Brico16Bits](https://github.com/Aurelien34/Brico16Bits) at `5859d6b` (2026-10-22, "Fixed remote keyboard detection"). Compatible **without modification**. |
| Brico68k upstream | [Aurelien34/Brico68k](https://github.com/Aurelien34/Brico68k) `main` at `52c1c92` (2026-11-02, BricoNeo 1.35 + PlayEyeSnd). The `v1.34` tag (`434a447`) actually announces 1.33 with 13 extensions. |
| This ROM | announces BricoNeo **1.35**, 24 extensions, SHA-256 `3439ee2968d3401683b522e352cae56ab05bee6f10eace674a2818ea6e9518a7` |
| vasm / vlink | vasm 1.9d (Volker Barthelmann, Frank Wille), vlink 0.17a (Frank Wille), built from source with zig 0.17.0 |
| Emulation | MAME 0.264, drivers `aes` and `neogeo` (MVS) |

The ROM keeps the BricoNeo header and the BricoExt layout (magic at `$80`, flags at `$8C`,
`jmp` at `$8E`, extension table at `$A0`). The reset vector upper word is `$00C0`, so
Brico16Bits recognises the byte order.

## Testing

`tools/mame_bench.py` runs the ROM in a real MAME, with a simulated Brico16Bits host written
in Lua. It needs your own BIOS dumps: `000-lo.lo`, plus `sm1.sm1` and `sfix.sfix` for MVS.

```
python3 tools/make_test_cart.py /tmp/testcart          # synthetic cartridge, nothing copyrighted
BRICO_SOUND_ROM=000-lo.lo python3 tools/mame_bench.py rom/Brico68k.bin
BRICO_SOUND_ROM=000-lo.lo BRICO_CART=/tmp/testcart python3 tools/mame_bench.py rom/Brico68k.bin TestCart TestZ80
BRICO_SOUND_ROM=000-lo.lo BRICO_DRIVER=neogeo BRICO_MVS_DIR=dumps/ python3 tools/mame_bench.py rom/Brico68k.bin TestWatchdog Echo:1 TestWatchdog
```

Verified in MAME, on `aes`, `aes` with the test cartridge, and `neogeo`: all 24 extensions,
each well under the 3 s host limit.

- TestDAC: 16 exact colours on screenshots.
- TestTiming: 202,739 cycles per frame against 202,752 expected. Injected stuck counter bits,
  at 0 and at 1, are named exactly.
- TestWatchdog: reset after ~133 ms on MVS (MAME: 135 ms).
- TestZ80: passes with a real SM1 and with the test M1.
- TestCart: the P2 window matches `cart_checksum.py` exactly.

### Known limits (read before trusting a result)

- **Nothing here has been validated on real hardware yet.** MAME is the reference used.
- **TestCart P1 in MAME**: with a cartridge loaded through a software list, CPU reads of
  `$000100`-`$000103` often return `$FFFF`. The cause was not found, and it does not happen on
  every run. The P1 checksum is exact when those two words read correctly, and every other
  P1 byte matches the dump. Check TestCart P1 against a known good cartridge.
- **TestWatchdog**: MAME emulates the watchdog on MVS only. On AES in MAME the test reports
  "no reset", which is expected there. Commands sent during the 1.5 s starve window are lost.
- **TestTiming** on PAL boards: the expected 312 lines is not verified (MAME is NTSC only).
  The CPU cycle check assumes no bus wait states, so it reports CHECK, not FAIL, when it is
  off by more than 0.5 %.
- **TestAudio** keeps the 68000 busy for ~3.5 s while beeping; a command sent meanwhile times
  out.
- **TestDAC levels** (100 / 47 / 22 / 10 / 6 %) come from MAME's resistor model
  (220 / 470 / 1k / 2k2 / 3k9 ohm). Real boards will differ slightly.

## Licences

- Brico68k firmware source: MIT, © Aurelien34. See `source/LICENSE`; the changes in this
  repository are under the same licence.
- vasm and vlink: their authors' terms. They are free for non-commercial use; ask the authors
  before any commercial redistribution of the embedded binaries.
- MAME, BIOS and cartridge dumps are **not** included. Use your own.
