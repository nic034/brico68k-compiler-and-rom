# Brico68k Compiler and ROM

A one-file tool that builds the **Brico68k** Neo Geo diagnostic ROM, and a ready-to-use build
of an extended Brico68k (BricoNeo 1.35 + review fixes + new tests).

The ROM runs on the **BricoNeo** board, driven by the unmodified **Brico16Bits** host firmware.
It is a BIOS-socket diagnostic for Neo Geo AES and MVS consoles.

| Path | What it is |
|---|---|
| `Brico68k_Compiler.py` | Brico68k Compiler 1.2 (Python 3.8+, standard library only, Tk window) |
| `Brico68k_Emulator.py` | Brico68k Emulator 1.9: tests the ROM on an emulated AES, no MAME and no BricoNeo needed |
| `rom/Brico68k.bin` | Ready-to-use ROM, 128 KB padded with `$FF` (SHA-256 in `rom/Brico68k.bin.sha256`) |
| `source/` | Firmware source used to build that ROM (vasm Motorola syntax) |
| `tools/` | MAME test bench and its synthetic test cartridge |
| `emulator/` | Emulator core source (Neo Geo model + host) and its build script |
| `bench/` | Session to paste into the real BricoNeo console, and the expected healthy output |
| `CHANGELOG.md` | What changed, release by release, with checksums and checks |

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

## Brico68k Emulator

Tests the ROM without a BricoNeo, a Brico16Bits or MAME. Double-click `Brico68k_Emulator.py`, or
run `python Brico68k_Emulator.py [ROM]`. It opens `rom/Brico68k.bin` by default. Then type the
same commands as on the Brico16Bits console: `Help`, `Echo 1234`, `TestWRAM`, `TestDAC 1`,
`Dump $100000 16`.

The file embeds a small emulator core for Windows x64 and Linux x64. The core is the Musashi
68000 (exact cycle counts), a real Z80 (superzazu/z80) and a Neo Geo AES model written from
MAME's driver:

- **Emulated**: BIOS ROM, WRAM, both palette banks, the system latch, LSPC registers and VRAM,
  the line counter and frame timing, the auto-animation counter, AES inputs with nothing
  plugged in, and open bus.
- **Host**: modelled on Brico16Bits. The command and P1-P3 are cleared after 1 ms, the timeout
  is 3 s, and the buffer holds 2048 words.
- **Z80**: 4 MHz, wired as on the board: sound latch on port `$00` (NMI when a command is
  pending and the NMI is enabled with `out ($08)` / `out ($18)`), reply latch on port `$0C`,
  2 KB RAM. It runs a built-in test M1 that only answers the standard handshake
  (`$03` reset gives `$00`, `$01` gives `$01`). It can also run without any program, like an
  AES with no cartridge.
- **Watchdog**: on by default. Real AES and MVS boards both have it, in NEO-B1 (kicked by any
  write to `REG_DIPSW` `$300001`, about 135 ms, it resets the whole system, Z80 included).
  MAME's `aes` driver has none: switch it off in Settings, or `--no-watchdog`, to compare with it.
- **Palette RAM byte writes** set both bytes of the word, as on the board (UDS/LDS are ignored
  for palette writes and the 68000 puts the byte on both halves of the bus; neogeodev wiki,
  "Palettes"). MAME writes one byte only. The ROM tests use word accesses; only `WriteB` to the
  palette shows the difference.
- **Options**: the watchdog and the Z80 program.
- **Not emulated**: the YM2610 (ports `$04`-`$07` read 0) and sound, Z80 ROM banking, sprites,
  the fix layer, a cartridge and a memory card. The screen shows the backdrop colour of each
  line, which is enough for TestDAC and Color.
- **Interrupts** (1.9): VBLANK (level 1, line `$F0` + 58 mclk), LSPC timer (level 2, 6 MHz
  pixel clock, `REG_LSPCMODE` bits 4-7, `REG_TIMERHIGH/LOW`, reloads as in MAME) and level 3
  pending from power-on, acknowledged through `REG_IRQACK`. Taken from MAME `neogeo.cpp`.
- **ChipCheck progress**: while ChipCheck runs, the status bar shows its percentage (the test
  writes it in WRAM, `$10FFF0`). The real BricoNeo console cannot show it: Brico16Bits displays
  an extension's output only once it has ended.
- **Not modelled either, in MAME or here**: the LSPC VRAM access delays of real boards (a read
  is valid 16 CPU cycles after the address write; 12 cycles between two writes). Code that
  accesses VRAM too fast passes in both and can fail on a real console.
- **Scripts**: the console accepts `; comment` and `Delay ms` like the BricoNeo console, and
  **Run script...** (or `--script FILE` in text mode) plays a whole file, such as
  `bench/real_aes_session.txt`.

Checked against MAME, 33 test commands each time (`emulator/compare_mame.py`), with
word-for-word identical output (ChipCheck's two measured clock values may differ in the last
digit, see Testing):

- `aes` without a cartridge, against the Z80 without a program: 33 out of 33;
- `aes` with the bench test cartridge, whose real MAME Z80 runs the same M1, against the
  built-in test M1: 32 out of 33. This covers TestZ80, TestAudio and PlayEyeSnd. The one
  difference is TestTiming, by one pass of its measuring loop (202,724 against 202,739
  cycles over 4 frames): scheduling phase, not behaviour.

Nothing to install with pip: the emulator uses only the Python standard library, and its core is
embedded. The window needs Tkinter. It comes with Python on Windows (python.org installer); on
Linux it may be a separate package (`sudo apt install python3-tk`), and the tool says so if it is
missing.

The window (light theme) is a diagnostic dashboard:

- **Sidebar**: the tests grouped by Memory, Video, Sound, Inputs and system, and Tools, each with a
  result badge, plus a live thumbnail of the screen (click it to enlarge).
- **Run all tests** chains every test in a sensible order: memory, video, Z80 and audio (with a
  4 s wait for the beeps), inputs, TestWatchdog in two passes (only when the watchdog option is
  on), then TestDAC last so its pattern stays on screen. The tools (Echo, Read, Write, Dump...)
  need parameters and are not part of it. **Stop** ends the sequence.
- **Report** tab: the verdict of the selected test in a coloured banner, its description, its
  raw output and its emulated duration, with Run again and Copy.
- **Console** tab: the Brico16Bits-like terminal. Commands typed there also update the badges.
- **Screen** tab: the screen, scaled to the window and keeping the 320:224 ratio.
- **Faults** and **Settings** tabs: see below; Settings also holds the ROM path, the Z80 program,
  the watchdog and the speed.
- A status bar with lamps (68000, host, Z80, faults), a busy indicator that counts the emulated
  time against the 3 s host limit, and the frame rate.

Badges are read from the text the ROM prints, the way a technician would read it:

| Badge | Meaning |
|---|---|
| PASS | the last `=>` line says success; TestAudio got its Z80 ACK |
| FAIL | failure line, `ERROR` line, 68000 exception, or timeout |
| CHECK | inconclusive, out of tolerance, or the test could not run |
| N/A | not applicable here: TestBRAM on AES, PlayEyeSnd (no sound), TestWatchdog with the watchdog off |
| LOOK | TestDAC: only your eyes can judge the 16 bands |
| INFO | report only (TestInp, TestStatusA, TestSystype, tools): read the output |
| ARMED | first TestWatchdog pass; run it again for the result |

A badge is a reading aid, not a second opinion: the raw output in the Report tab is what the ROM
said. With the Z80 option set to no program, the Z80 failures are marked as expected.
Keys: Enter sends, Up/Down browses the history, F5 resets, F8 pauses, Ctrl+L clears the console.

### Simulated faults

The **Faults** tab, and `--fault` in text mode, inject faults. You can break the console
in the ways real boards fail, then see how each test reports it:

- **data bit stuck** at 0 or 1: WRAM D0-D15, palette RAM D0-D15, VRAM lower or upper D0-D15,
  LSPC line counter bits 0-8. A palette fault also changes the colours on screen, so TestDAC
  shows the dead band.
- **address line stuck** at 0 or 1: WRAM A1-A15, palette A1-A12 plus the bank select (13), VRAM
  lower 0-14 and upper 0-10.
- **WRAM chip dead**, lower (D0-D7) or upper (D8-D15) byte lane: writes are lost and reads give
  `$FF`.

The tab also has presets for typical AES faults. Faults stay active across power cycles, like
a real hardware fault; a red lamp and the tab title show how many are active. Example:

```
python Brico68k_Emulator.py --fault wram:lane:upper --fault pal:data:11:0 --run TestWRAM TestPRAM
python Brico68k_Emulator.py --fault help
```

Checked against the MAME bench with the same fault injected (`emulator/compare_mame_faults.py`):
25 out of 26 outputs are identical, ChipCheck included. That covers WRAM data bits, a dead chip and address lines,
palette data and address lines, the line counter, and VRAM data. MAME's probes cannot model the
palette bank select, VRAM address lines or the on-screen effect, so those were checked by hand:
TestPRAM reports bank independence, TestVRAML or TestVRAMU fails on the right half, and the R4
band turns black. The one difference: the bench's palette address fault shares one store
between both banks, so MAME's ChipCheck also reports a bank-select fault that a real board
would not have.

Text mode: `python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234"` and `--check`.
Rebuild the core: `python3 emulator/build_core.py` (needs git and `pip install ziglang`; clones
already at the pinned commits in `emulator/build/` are reused, so a rebuild works offline). The
build is reproducible: the same sources give the same core checksums.
It fetches Musashi and the Z80 core at pinned commits.
The build is reproducible: it gives the same binaries.

## ROM contents: 24 extensions

Commands are typed on the Brico16Bits console. "No WRAM" means the test never relies on
work RAM (no stack), so it still runs on a board with dead WRAM.

| Command | No WRAM | What it does |
|---|:-:|---|
| **ChipCheck** | partly | Quick state of the board, one line per part, < 1 s (see below) |
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
| **TestWatchdog** | no | First run starves the watchdog; the second run reports the reset and its delay |

Bold entries are new in this repository.

### ChipCheck: quick state of the board

One line per part, what to suspect when it fails, and the test to run next. About 0.35 s
(0.6 s when the Z80 does not answer). The long tests stay the reference for a failing line.

| Line | How it is checked | A failure points to |
|---|---|---|
| Work RAM | Walking 1/0 on both bytes, then each address line A1-A15 (stuck at 0 and at 1) | The bits (D3, D8-D15...) or lines (A9) named; upper/lower chip or NEO-C1 WRU/WRL/WWU/WWL |
| Palette RAM | Same on both banks (A1-A12), plus bank select | Palette RAM chip or latch, NEO-B1 bus switch; bank: system latch |
| VRAM slow / fast | Same through the LSPC2 (A0-A14 / A0-A10), with the LSPC access delays | The VRAM chip, LSPC2-A2 B/E or C/F bus |
| LSPC2 registers | `REG_VRAMMOD` write and read-back | LSPC2-A2, NEO-C1 LSPOE/LSPWE |
| NEO-C1 ports | P1, P2, STATUS_B, SOUND/STATUS_A each read from two places followed by different opcodes: a port nobody drives returns the open bus (the next opcode) | NEO-C1 input buffers |
| VBLANK / timer IRQ | The 68000 takes level 1 and level 2 interrupts (needs WRAM for the stack: skipped if WRAM fails) | LSPC2-A2 interrupt outputs IP0/IP1, its timer |
| Z80 | Standard sound driver handshake, as TestZ80 | No cartridge (inconclusive), else Z80, M1, Z80 RAM, latches |
| NEO-D0: 68KCLK 12 MHz | CPU cycles counted until Brico16Bits clears the command, 1 ms after the launch (its own crystal): about +-5 % | 68000 clock |
| NEO-D0: 24 MHz > LSPC2 | CPU cycles per video frame, 202,752 expected (same crystal: checks the dividers), and the frame rate from the 1 ms reference | LSPC2 line counter or the 24 MHz path |
| NEO-D0: 6 MHz pixel | CPU cycles per LSPC timer tick, 2.00 expected | Pixel clock |
| NEO-D0: Z80 control | Shown by the Z80 answer | - |

Not visible from the 68000, so not in the table: the YM2610 interface, the 12 MHz to the
cartridge (NEO-ZMC2), the memory card bank select (needs a multi-bank card), the joypad
outputs, the LSPC2 -> NEO-B1 pixel pipeline (sprites, fix: TestDAC covers palette RAM to the
DAC only), the watchdog (TestWatchdog; the wiki notes it can be disabled by jumper J2) and the
sound itself (TestAudio). A part that stops the console from booting cannot be checked at all:
then nothing answers.

Limits: the floating-port check can only miss a dead port, not flag a healthy one (a bus pulled
to a fixed value would hide it). The two clock lines measured against the BricoNeo are
approximate. Failures of several parts at once (e.g. WRAM chip or NEO-C1 select) are listed
together: the test cannot tell them apart.

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
- **VRAM tests**: two `nop` between the VRAM address write and the read, so the read comes more
  than 16 CPU cycles after the address (neogeodev wiki, "VRAM"). It came 12 cycles after the end
  of the write before. MAME does not model this delay, so only a real board can show the
  difference. MarchVRAML now takes 1.75 s of the 3 s host limit.
- **RAM tests**: more precise reports (address, expected, read, bad bits, byte lane), plus
  general optimizations.

## References

| Component | Version used |
|---|---|
| Brico16Bits host firmware | [Aurelien34/Brico16Bits](https://github.com/Aurelien34/Brico16Bits) at `5859d6b` (2026-10-22, "Fixed remote keyboard detection"). Compatible **without modification**. |
| Brico68k upstream | [Aurelien34/Brico68k](https://github.com/Aurelien34/Brico68k) `main` at `52c1c92` (2026-11-02, BricoNeo 1.35 + PlayEyeSnd). The `v1.34` tag (`434a447`) actually announces 1.33 with 13 extensions. |
| This ROM | announces BricoNeo **1.35**, 24 extensions, SHA-256 `cadca47e7e621b019d66391bd41ea24a05a41de0785712f059e924ad2cacab07` |
| vasm / vlink | vasm 1.9d (Volker Barthelmann, Frank Wille), vlink 0.17a (Frank Wille), built from source with zig 0.17.0 |
| Emulation | MAME 0.264, drivers `aes` and `neogeo` (MVS) |

The ROM keeps the BricoNeo header and the BricoExt layout (magic at `$80`, flags at `$8C`,
`jmp` at `$8E`, extension table at `$A0`). The reset vector upper word is `$00C0`, so
Brico16Bits recognises the byte order.

## Testing on a real console (BricoNeo running Brico16Bits)

1. Console off. Put the BricoNeo in the SP1 (BIOS) socket, pin 1 the right way. Insert a game
   cartridge: on an AES the Z80 program comes from the cartridge, so TestZ80 and TestAudio need one.
2. Connect the USB cable. Open the first serial port with PuTTY or Tera Term and **turn session
   logging on** (PuTTY: Session > Logging > All session output).
3. Drop `rom/Brico68k.bin` at the root of the `BricoNeo` USB drive. The root loads it in RAM only
   and resets the console: your bank 0 is untouched, and the next power cycle brings it back.
   (Put it in a bank folder to keep it.)
4. Type `?`: the Extensions section must list the 24 commands.
5. Paste the whole of `bench/real_aes_session.txt` into the terminal. The `;` lines are comments
   and `Delay` waits, both built into the BricoNeo console.
6. In the emulator, **Compare** tab > **Open real console log...** (or
   `python Brico68k_Emulator.py --compare putty.log`). Every command of the log is replayed in the
   emulator and the outputs are compared, command by command: `same`, `varies` (TestInp,
   TestStatusA and TestSystype depend on what is plugged in), `same verdict` (TestTiming: cycle
   counts may differ slightly) or `DIFFERENT`, with the diff. Look at the screen for TestDAC.
   `bench/expected_healthy_aes.txt` (and `..._no_cartridge.txt`) give the same reference as text.
7. If something differs: **Find the fault** (or `--diagnose putty.log`). The log is replayed under
   each of the 256 single faults the emulator models (data bit or address line stuck at 0 or 1 in
   WRAM, palette RAM, VRAM and the line counter, WRAM chip dead), and the faults are ranked by how
   many commands they explain. **Apply to Faults** puts the best one in the emulator. It takes
   about 1.5 min on 2 cores, much less with more cores (the work is spread over processes).
   Limits: one stuck-at fault at a time, modelled chips only. Intermittent faults, shorts between
   lines, timing faults and the other chips are not in the dictionary, so "no candidate" does not
   mean "no fault".

## Testing

`tools/mame_bench.py` runs the ROM in a real MAME, with a simulated Brico16Bits host written
in Lua. It needs your own BIOS dumps: `000-lo.lo`, plus `sm1.sm1` and `sfix.sfix` for MVS.

```
python3 tools/make_test_cart.py /tmp/testcart          # synthetic cartridge (tiny Z80 M1), nothing copyrighted
BRICO_SOUND_ROM=000-lo.lo python3 tools/mame_bench.py rom/Brico68k.bin
BRICO_SOUND_ROM=000-lo.lo BRICO_CART=/tmp/testcart python3 tools/mame_bench.py rom/Brico68k.bin TestZ80 TestAudio
BRICO_SOUND_ROM=000-lo.lo BRICO_DRIVER=neogeo BRICO_MVS_DIR=dumps/ python3 tools/mame_bench.py rom/Brico68k.bin TestWatchdog Echo:1 TestWatchdog
```

Verified in MAME, on `aes`, `aes` with the test cartridge, and `neogeo`: all extensions,
each well under the 3 s host limit.

- ChipCheck: identical to MAME (`aes`, with and without the test cartridge), and under every
  bench fault but one: the bench's palette address fault shares one store between both banks,
  so MAME also reports a bank-select fault that a real board would not have. The two measured
  clock values may differ in the last digit: the bench clears the command at the first read
  after 1 ms of machine time (`tools/mame_ext_runner.lua`), the real host at exactly 1 ms.
- With the test cartridge, TestTiming can differ from the emulator by one pass of its measuring
  loop (202,724 against 202,739 cycles over 4 frames): scheduling phase, not behaviour.

- TestDAC: 16 exact colours on screenshots.
- TestTiming: 202,739 cycles per frame against 202,752 expected. Injected stuck counter bits,
  at 0 and at 1, are named exactly.
- TestWatchdog: reset after ~133 ms on MVS (MAME: 135 ms).
- TestZ80: passes with a real SM1 and with the test M1.

### Known limits (read before trusting a result)

- **Nothing here has been validated on real hardware yet.** MAME is the reference used.
- **TestWatchdog**: MAME emulates the watchdog on MVS only, although the AES has the same
  NEO-B1 watchdog (Brico16Bits' own `Reset` command relies on it). On AES in MAME the test
  reports "no reset"; on a real AES it must pass. Commands sent during the 1.5 s starve window
  are lost. The reset is modelled as instant, as in MAME; on the board /RESET then stays low a
  while (about 200 ms by Charles MacDonald's measures, unverified per the wiki).
- **TestTiming** on PAL boards: the expected 312 lines is not verified (MAME is NTSC only).
  The CPU cycle check assumes no bus wait states, so it reports CHECK, not FAIL, when it is
  off by more than 0.5 %.
- **TestAudio** keeps the 68000 busy for ~3.5 s while beeping; a command sent meanwhile times
  out.
- **TestDAC levels** (100 / 47 / 22 / 10 / 6 %) come from MAME's resistor model
  (220 / 470 / 1k / 2k2 / 3k9 ohm). Real boards will differ slightly.

## Licences

- Brico68k Emulator core: Musashi 68000, MIT, © Karl Stenerud (`emulator/MUSASHI_LICENSE.txt`);
  Z80 core superzazu/z80, MIT, © Nicolas Allemand (`emulator/Z80_LICENSE.txt`);
  `emulator/neocore.c` is written from MAME's Neo Geo driver behaviour (no MAME code is copied).
- Brico68k firmware source: MIT, © Aurelien34. See `source/LICENSE`; the changes in this
  repository are under the same licence.
- vasm and vlink: their authors' terms. They are free for non-commercial use; ask the authors
  before any commercial redistribution of the embedded binaries.
- MAME, BIOS and cartridge dumps are **not** included. Use your own.
