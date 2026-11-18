# Brico68k Compiler and ROM

A one-file tool that builds the **Brico68k** Neo Geo diagnostic ROM, and a ready-to-use build
of an extended Brico68k (BricoNeo 1.35 + review fixes + new tests).

The ROM runs on the **BricoNeo** board, driven by the **Brico16Bits** host firmware (stock
firmware works; `brico16bits/` holds an optional patch so 68000 exceptions are reported cleanly).
It is a BIOS-socket diagnostic for Neo Geo AES and MVS consoles. Its 68000 code follows what the
Brico16Bits code expects (see "How the ROM must talk to the BricoNeo" below).

| Path | What it is |
|---|---|
| `Brico68k_Compiler.py` | Brico68k Compiler 1.5 (Python 3.8+, standard library only, Tk window) |
| `Brico68k_Emulator.py` | Brico68k Emulator 1.22 (pure Python, no DLL): tests the ROM on an emulated AES (cartridge or diagnostic PROG board included), no MAME and no BricoNeo needed |
| `rom/ROM.BIO` | Ready-to-use ROM, 128 KB: 32 KB of code + CRC32 + 3 mirrors, exactly what the BricoNeo builds itself for header flag `$0004` (SHA-256 in `rom/ROM.BIO.sha256`) |
| `brico16bits/` | Optional Brico16Bits patch (EXCPT: 68000 exception reports). Syntax-checked only, not built for the Pico, not run |
| `source/` | Firmware source used to build that ROM (vasm Motorola syntax) |
| `tools/` | MAME test bench and its synthetic test cartridge (game header + security code) |
| `emulator/` | Emulator core source (Neo Geo model + host) and its build script |
| `bench/` | Session to paste into the real BricoNeo console, and the expected healthy output |
| `CHANGELOG.md` | What changed, release by release, with checksums and checks |

## Quick start

1. Install Python 3.8 or newer (python.org; on Windows tick "Add to PATH").
2. Double-click `Brico68k_Compiler.py`, or run `python Brico68k_Compiler.py`.
3. Click **Build**. The result is `output/ROM.BIO`.
4. Plug the BricoNeo in over USB, then click **Detect** and **Copy ROM.BIO**.
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
run `python Brico68k_Emulator.py [ROM]`. It opens `rom/ROM.BIO` by default. Then type the
same commands as on the Brico16Bits console: `Help`, `Echo 1234`, `TestWRAM`, `TestDAC 1`,
`Dump $100000 16`.

The file is pure Python (standard library only, any OS with Python 3.8+): no DLL, nothing to
extract or install. Its core is a Python port of the Musashi 68000 (exact cycle counts), the part
of the superzazu/z80 Z80 that the model's Z80 programs use, and a Neo Geo AES model written from
MAME's driver. The port gives the same results as the C Musashi word for word (see "Checking the
Python core" below).

Speed, measured (one core of a cloud x86 server, 1.21): 88 to 102 frames/s idle and 68 to 79
during TestWRAM / TestVRAM, for 59.2 in real time, with Python 3.11 to 3.13 (1.20 on the same
machine: 46 to 57 idle, 49 to 56 in the tests). TestWRAM (0.38 s emulated) takes 0.3 s. Slow with
this core: `--diagnose` (and the same search in the window), which replays a log on 290 simulated
faults: much longer than with the C core, so use the C core for it. For speed, the
C build of the same core is still supported: put `neocore.dll` (Windows) or `libneocore.so`
(Linux) built by `emulator/build_core.py` next to the script, or give its path in the
`BRICO68K_CORE` environment variable (`BRICO68K_CORE=python` forces the Python core). The first
line of the window says which core runs.

- **Emulated**: BIOS ROM, WRAM, both palette banks, the system latch, LSPC registers and VRAM,
  the line counter and frame timing, the auto-animation counter, AES inputs with nothing
  plugged in, and open bus.
- **Host**: modelled on the Brico16Bits code. The command and P1-P3 are cleared after 1 ms
  (`sleep_ms(1)` in `CommandExtension.cpp`), the timeout is 3 s. The port watcher is modelled
  access by access (`PioBusWatcherPort.pio`): the read at `$C1FF02` arms it, one more socket access
  goes by (the opcode prefetch) and the next one is the value, so an interrupt in between would
  corrupt the value as on the board. The input buffer is a ring of 2048 words: past 2047 words
  only the tail is left, as on the BricoNeo. An exception report (`EXCPT`) is shown the way the
  patched Brico16Bits shows it.
- **Z80**: 4 MHz, wired as on the board: sound latch on port `$00` (NMI when a command is
  pending and the NMI is enabled with `out ($08)` / `out ($18)`), reply latch on port `$0C`,
  2 KB RAM. It runs a built-in test M1 that answers the standard handshake
  (`$03` silence + reset gives `$00`, `$01` gives `$01`) and programs the YM2610 SSG for the
  sound commands: `$5C` / `$5D` / `$5E` (TestAudio's left / right / centre beeps) give a
  1000 / 1506 / 749 Hz tone until the next command, `$02` (TestFM) a short jingle (C E G C)
  standing in for a cartridge's eyecatcher music, `$7F` (TestSsg) a two-note chime standing in
  for the coin chime. Its listing is in `emulator/neo_py.py`
  (`TEST_M1_PARTS`); the MAME bench cartridge (`tools/make_test_cart.py`) carries the same M1. It
  can also run without any program, like an AES with no cartridge.
- **Sound** (1.19): the SSG square-wave tones the Z80 programmed (ports `$04` / `$05`, registers
  `$00`-`$0F`) are played through the PC speakers: winsound on Windows, `paplay` / `pw-play` /
  `aplay` / `afplay` elsewhere (Settings > Sound to switch off). The status bar shows the tone
  (`♪ 1000 Hz`) and the console notes each change. So a sound is heard only when the 68000 sent the
  command, the Z80 took the NMI, read the latch and wrote the sound chip. The beeps are mono: the
  SSG has no panning (left / right on a real board come from the driver's FM / ADPCM channels).
- **Watchdog**: on by default. Real AES and MVS boards both have it, in NEO-B1 (kicked by any
  write to `REG_DIPSW` `$300001`, about 135 ms, it resets the whole system, Z80 included).
  MAME's `aes` driver has none: switch it off in Settings, or `--no-watchdog`, to compare with it.
- **Palette RAM byte writes** set both bytes of the word, as on the board (UDS/LDS are ignored
  for palette writes and the 68000 puts the byte on both halves of the bus; neogeodev wiki,
  "Palettes"). MAME writes one byte only. The ROM tests use word accesses; only `WriteB` to the
  palette shows the difference.
- **Options**: the watchdog, the Z80 program and the cartridge.
- **Cartridge** (Cartridge tab, one choice at a time; `--cart` in text mode). Changing it powers the
  console off and on, as you would with a real cartridge:
  - **No cartridge**: P1 and P2 read `$FFFF`.
  - **Built-in test cartridge**: a generated 3 MB P ROM (NEO-GEO header, NGH `0999`, the
    security code at `$186`, two P2 banks), the same bytes as the MAME bench cartridge.
  - **Game cartridge**: a ROM set, as a folder or a MAME zip. P1 and P2 go on the 68000 bus.
    The P2 bank latch follows the wiki ("Bankswitching"): a word or odd-byte write anywhere in
    `$200000-$2FFFFF` (/PORTWEL) latches the bank, and the slot reset brings back bank 0. MAME
    decodes only `$2FFFF0-$2FFFFF`; the ROM writes there, so both agree. S, C, V and M1 are
    loaded, and their size and CRC32 are listed. Give the official MAME list
    (`hash/neogeo.xml`, **Official MAME list** in the Cartridge tab or `--cart-list`) and the set is
    identified by its CRC32s, loaded with the list's layout (word swap, `ROM_CONTINUE` halves),
    and every chip is marked OK, BAD CRC, MISSING or "not in the list". Without the list, P1/P2 are found by name, and the byte
    order and layout by the NEO-GEO header.
  - **Diagnostic PROG board** (jwestfall69 `neogeo-diag-aes-prog`): one 1 MiB 16-bit SRAM read
    in both P windows and written through P2, with the board's byte-lane decoding from its
    KiCad netlist (UB, LB, OE, WE from /ROMOEU-L, /PORTOEU-L, /PORTWEU-L).
- **Screen**: the backdrop colour of each line (TestDAC, Color), and over it the fix
  layer and the sprites drawn from VRAM (TestGfx). The tiles are the cartridge's S and C ROMs when
  the ROM set has them (not decrypted: a CMC / PCM set shows noise); the built-in test cartridge
  has generated tiles (a 5 x 7 font at the ASCII codes, numbered sprite tiles with an F); no
  cartridge or the PROG board: no tile. It is a drawing for the ROM's test screens, not a game
  renderer: vertical shrink is approximated (the real table is the L0 ROM, SNK's, not included),
  no auto-animation, no 96 sprites per line limit. With the same tiles and the same table, MAME
  gives the same picture pixel for pixel (`emulator/compare_mame_gfx.py`).
  `--png FILE` saves the screen after `--run` / `--script`.
- **Not emulated**: the rest of the YM2610 (FM, ADPCM, SSG noise and envelopes, status reads
  0), Z80 ROM banking,
  protected cartridges (SMA, PVC, CMC, encrypted P: their extra registers read
  as P ROM) and a memory card. V and M1 are checked, not used: the cartridge's M1 does
  not replace the built-in test M1.
- **Interrupts** (1.9): VBLANK (level 1, line `$F0` + 58 mclk), LSPC timer (level 2, 6 MHz
  pixel clock, `REG_LSPCMODE` bits 4-7, `REG_TIMERHIGH/LOW`, reloads as in MAME) and level 3
  pending from power-on, acknowledged through `REG_IRQACK`. Taken from MAME `neogeo.cpp`.
- **TestChip progress**: while TestChip runs, the status bar shows its percentage (the test
  writes it in WRAM, `$10FFF0`). The real BricoNeo console cannot show it: Brico16Bits displays
  an extension's output only once it has ended.
- **Not modelled either, in MAME or here**: the LSPC VRAM access delays of real boards (a read
  is valid 16 CPU cycles after the address write; 12 cycles between two writes). Code that
  accesses VRAM too fast passes in both and can fail on a real console.
- **Scripts**: the console accepts `; comment` and `Delay ms` like the BricoNeo console, and
  **Run script...** (or `--script FILE` in text mode) plays a whole file, such as
  `bench/real_aes_session.txt`.

Checked against MAME, 38 test commands each time (`emulator/compare_mame.py`, an address
error report included), with word-for-word identical output (measured on 1.35-nic034-09,
with CartTest, Version and PlayEyeSnd; not re-run since):

- `aes` without a cartridge, against the Z80 without a program: 38 out of 38;
- `aes` with the bench test cartridge, whose real MAME Z80 runs the same M1, against the
  built-in test cartridge and test M1: 38 out of 38. This covers TestZ80, TestAudio,
  PlayEyeSnd (now TestFM) and CartTest (removed since).

Nothing to install with pip: the emulator uses only the Python standard library. The window needs Tkinter. It comes with Python on Windows (python.org installer); on
Linux it may be a separate package (`sudo apt install python3-tk`), and the tool says so if it is
missing.

The window (light theme) is a diagnostic dashboard:

- **Sidebar**: the tests grouped by Memory, Video, Sound, Inputs and system, Cartridge and Tools, each with a
  result badge, plus a live thumbnail of the screen (click it to enlarge).
- **Check rules** runs the same sequence in a separate Python core and checks every test against
  the Brico16Bits rules (see "Writing and testing a new extension"); the findings go to each
  test's report and badge.
- **Run all tests** chains every test in a sensible order: memory, video, Z80 and audio (with a
  4 s wait for the beeps), inputs, TestWatchdog in two passes (only when the watchdog option is
  on), then TestDAC last so its pattern stays on screen. The tools (Echo, Read, Write, Dump...)
  need parameters and are not part of it. **Stop** ends the sequence.
- **Report** tab: the verdict of the selected test in a coloured banner, its description, its
  raw output and its emulated duration, with Run again and Copy.
- **Console** tab: the Brico16Bits-like terminal. Commands typed there also update the badges.
- **Screen** tab: the screen, scaled to the window and keeping the 320:224 ratio.
- **Cartridge** tab: what is in the slot (see above), with the chip list.
- **Faults** and **Settings** tabs: see below; Settings also holds the ROM path, the Z80 program,
  the watchdog and the speed.
- A status bar with lamps (68000, host, Z80, cartridge, faults), a busy indicator that counts the emulated
  time against the 3 s host limit, and the frame rate.

Badges are read from the text the ROM prints, the way a technician would read it:

| Badge | Meaning |
|---|---|
| PASS | the last `=>` line says success; TestAudio got its Z80 ACK |
| FAIL | failure line, `ERROR` line, 68000 exception, or timeout |
| CHECK | inconclusive, out of tolerance, or the test could not run |
| N/A | not applicable here: TestBRAM on AES, TestWatchdog with the watchdog off |
| LOOK | TestDAC and TestGfx: only your eyes can judge the screen; TestFM and TestSsg: your ears |
| INFO | report only (TestInp, TestStatusA, TestSystype, tools): read the output |
| ARMED | first TestWatchdog pass; run it again for the result |

A badge is a reading aid, not a second opinion: the raw output in the Report tab is what the ROM
said. With the Z80 option set to no program, the Z80 failures are marked as expected.
Keys: Enter sends, Up/Down browses the history, F5 resets, F8 pauses, Ctrl+L clears the console.

### Which chip? References on the AES (RAM tests and TestDecode)

TestWRAM, TestPRAM and TestVRAM name the chip of the bad data bits and, for TestDecode and address
lines, the parts in the path. The references come from the **Board-Folk NeoGeoAES-3.5** KiCad
schematic (BF1.5, a recreation of the AES main board: sheets CPU, GRAPHICS, VIDEO, ROM), read pin by
pin and checked against the rendered PDF pages and the neogeodev wiki (NEO-C1, NEO-G0, NEO-E0,
NEO-B1, LSPC2-A2, Palettes, VRAM, Memory mapped registers). Per Nic034 it is valid for the AES 3-3, 3-5 and 3-6
boards (his message listed 3-5 twice: 3-4 is not confirmed). The messages say "AES" and never a
revision; on an MVS the references do not apply (backup RAM prints none).

| Data bits | WRAM | Palette RAM | Slow VRAM | Fast VRAM |
|---|---|---|---|---|
| D0-D7 (lower chip) | U1 | U7 (PC0-7) | U17 (E0-7) | U19 (F0-7) |
| D8-D15 (upper chip) | U2 | U6 (PC8-15) | U18 (E8-15) | U20 (F8-15) |

Read off the schematic:
- WRAM U1/U2 (43256): data pins on the 68000 D0-D7 / D8-D15, address pins on the 68000 A1-A15 (chip
  pin A(k-1) = 68000 Ak), CE to ground; OE/WE from NEO-C1 U4: RAOL/RAWL to U1, RAOU/RAWU to U2. The
  D bus is shared with the LSPC2 U21, NEO-G0 U5, the ROM U36 (27C1024) and the cartridge slot.
- NEO-C1 U4 has address inputs A17-A21 and A22' / A23' (NEO-E0 U34 makes them: on the wiki, "altered address lines for the 68k vector table swap");
  no A16. The WRAM chips see A1-A15 only, so A16 reaches neither of them.
- Palette RAM U6/U7 (4364): addresses PA0-PA11 from NEO-B1 U13, A12 = PALBNK (74HC259 U35 output Q7),
  data PC8-15 / PC0-7. PC goes to NEO-G0 U5 (also on the D bus and the cartridge data bus) and to the
  74LS273 U9/U10; the RAMs' WE is shared with NEO-G0's WE pin, and NEO-C1's PAL output goes to NEO-G0's G1.
- VRAM: slow U17/U18 (43256) addresses B0-B14, data E0-E7 / E8-E15; fast U19/U20 (5863 / 5814)
  addresses C0-C10, data F0-F7 / F8-F15; all of it only to/from the LSPC2 U21. The LSPC2 has
  address inputs A1-A3 only; its OE/WE come from NEO-C1 (LSPOE, LSPWE).

Cross-check with an independent source, the Delta Island "NeoGeo Pinouts" workbook (traced from a
board, French labels): it agrees on the nets above (NEO-C1 RAOU/RAWU to the WRAM chip on D8-D15,
RAOL/RAWL to the one on D0-D7, no A16 on NEO-C1, LSPC2 address inputs A1-A3, LSPOE/LSPWE from NEO-C1,
palette PA0-PA11 from NEO-B1, A12 from the 74HC259 pin 12, palette WE shared with NEO-G0 pin 41, PC0-7 /
PC8-15 on the two palette chips). It has no U-numbers: it calls the WRAM chips "WORK RAM 1" (D8-D15,
the upper one) and "WORK RAM 2" (D0-D7), the opposite order of U1 / U2, so do not read "1" as "U1". It
also holds a few evident typos (VRAM pins in the LSPC2 sheet), so only its nets were used.

The wiki adds: NEO-G0 is a quad 245 bidirectional buffer (a 245 keeps the bit order), with a lower palette
bus PALD0-7 and an upper one PAUD0-7, and makes the palette /WE as PAL OR R/W; NEO-C1's WRU/WRL/WWU/WWL
cover `$100000-$1FFFFF` (the schematic names the same pins RAOU/RAOL/RAWU/RAWL), PAL `$400000-$7FFFFF`,
LSPOE/LSPWE `$3C0000-$3DFFFF`; slow VRAM is 2x 62256/43256, fast VRAM 2x 5814/5863/6116. The messages use the
wiki's strobe names.

**Not proven**: the bit pairing inside NEO-G0 (D0-D7 = PC0-PC7: the 245 structure and the wiki's lower /
upper buses say so, no source lists it pin by pin); that E0 / F0 are VRAM data bit 0 (pin names only); that the
U-numbers of a given board are those of the KiCad file (it is a reproduction); that A17-A19 are really
ignored for WRAM, palette and LSPC (inside NEO-C1). The messages show the net names (PC0-7, E0-7...)
so that each reference can be probed on the board. A bad data bit still points at the chip, its pin,
its track, or the other parts on that bus: the message cannot tell which.

### Writing and testing a new extension

**Space first.** The ROM uses the NeoDiag layout (header flag `$0004`): code must end before
`$7FFA` (32 KiB, copied 4 times). With the 26 extensions of 1.35-nic034-15, **4134 bytes are
free** (TestDecode took 854 bytes and the chip references and hints of the RAM tests about 1 KB; CartTest, Version and TestBus were removed and the code shrunk before). Brico68k Compiler prints the free space after
each build.

Nothing to add to the emulator: it reads the extension table of the ROM. A new extension:
1. `source/ExtMyTest.s` + a `DECLARE_EXTENSION` line in `source/Brico68k.s`, then build.
2. `python Brico68k_Emulator.py --test MyTest` (or `--test "MyTest 3"` with parameters, several
   lines at once, `--test` alone for everything): verdict, emulated time and rule check of each,
   exit code 1 on a FAIL. Add `--fault ...` (see below) to see that the test catches the fault it is
   written for, `--cart test|diag|<set>` for cartridge tests. In the window: **Check rules**.
3. It shows in the window's "Other" group, Run all runs it once, and its badge comes from its last
   `=> ...` line (`Test success` / `Test Failure` / `CHECK` / `N/A`, as the other tests print).
   Only to change that (group, a wait after it, a LOOK note...), add one line to `TESTS` in
   `emulator/emulator_main.py`.

The rule check (`emu_host.check_command`, Python core) watches the bus while the command runs:

| Finding | Rule |
|---|---|
| FAIL output with interrupts enabled | port writes with the IRQ mask at 3 or more (`$2700`) |
| FAIL output from code outside the ROM | the BricoNeo skips the next socket access, the opcode fetch only from ROM code |
| WARN P1-P3 read after the 1 ms clear | read the parameters first |
| FAIL no EOT / watchdog reset before the EOT | one EOT within 3 s; `WatchDog` in every loop > ~100 ms |
| WARN several EOTs, output after the EOT | one EOT, nothing after it |
| FAIL more than 2047 words | the ring buffer wraps |
| WARN result does not fit the declared type | word = 1 word, void = none, dump = address + data |
| WARN over 1.5 s | half of the 3 s timeout |
| FAIL / WARN command block not read for 1 ms / 0.75 ms after the EOT | a command is held 1 ms: code that keeps running polls it |
| FAIL loop-mode repeat missed | the same command sent 20 us after the EOT (`*MyTest`) must run |

`emulator/test/test_ext_check.py` builds the ROM with `test/ExtCheckBad.s` (one broken rule per
P1) and shows that each finding fires, and that the real ROM gives none (the last one, TestVRAM
at 1.77 s, is gone since 1.35-nic034-12: 1.47 s). Limits:
the rules are the Brico16Bits code as modelled here, and the 20 us loop-mode delay is an
assumption, not measured on a BricoNeo; only a real console confirms a finding.

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
- **address decoding** (what TestDecode checks): `wram:sel:17:0`, `pal:sel:15:0`, `lspc:sel:6:0`.
  The decoder of that chip uses an address line it should ignore (WRAM A16-A19, palette A13-A21,
  LSPC registers A4-A16), so the chip answers only when the line is at the given level; elsewhere
  reads give the open bus and writes are lost. At level 1 the chip never answers at its normal
  addresses. `wram:leak`: every WRAM write also changes the palette RAM cell with the same A1-A12
  (a decoder output selecting both chips).
- **BIOS socket address line** A1-A16 between the 68000 and the BricoNeo, stuck at 0 or 1
  (`bios:addr:15:1`) or unstable (`bios:float:15`, a random level on each access). The BricoNeo
  sees the faulty address too (command block, port, EOT). A1-A14 stop the boot, as on a board.
- **Cartridge slot** (needs a cartridge or the PROG board): data line D0-D15 stuck
  (`cart:data:3:0`) or unstable (`cart:float:7`), address line A1-A19 stuck (`cart:addr:19:0`),
  or a strobe dead (`cart:strobe:portwel`, `portweu`, `romoel`, `romoeu`, `portoel`, `portoeu`; for an
  output enable the 68000 then reads the word it prefetched, which is what the diag BIOS assumes).
  With the suffix `245` (`romoel245` ... `portoeu245`) the dead output sits behind a 245 / NEO-G0 /
  NEO-BUF: the lane gives back the last value written to the cartridge side. The same pins serve
  P1, P2 and the PROG board, reads and writes.
- **Vector table switch** held on the system ROM (`vec:stuck:bios`) or on the cartridge
  (`vec:stuck:cart`): `$000000-$00007F` is always read from that side, whatever the 68000 writes
  to `REG_SWPBIOS` / `REG_SWPROM`. TestVectors names it. Held on the cartridge **at power-on**,
  the console does not start with a game inserted: the 68000 takes the cartridge's reset vector
  (`$C00402`, an entry of SNK's system ROM), and this ROM has no code there. The built-in test
  cartridge has vectors like a game's, so the emulator shows the same thing.

The tab also has presets for typical AES faults. Faults stay active across power cycles, like
a real hardware fault; a red lamp and the tab title show how many are active. Example:

```
python Brico68k_Emulator.py --fault wram:lane:upper --fault pal:data:11:0 --run TestWRAM TestPRAM
python Brico68k_Emulator.py --fault help
```

Checked against the MAME bench with the same fault injected (`emulator/compare_mame_faults.py`):
27 out of 28 outputs are identical without a cartridge, 24 out of 25 with the test cartridge,
TestChip included. That covers WRAM data bits, a dead chip and address lines, palette data and
address lines, the line counter, VRAM data, cartridge slot data lines (CartTest on the test
cartridge, in 1.35-nic034-09), and the PROG board (CartDiag): MAME has no such board, so the bench's shadow RAM over
`$000080-$2FFFFF` with A21 masked off plays it (one RAM seen at `$0xxxxx` and `$2xxxxx`, written
by byte lanes), healthy and with slot A5 or A19 stuck at 0. MAME's probes cannot model the
palette bank select, VRAM address lines or the on-screen effect, so those were checked by hand:
TestPRAM reports bank independence, TestVRAM names the zone and the line, and the R4
band turns black. The one difference: the bench's palette address fault shares one store
between both banks, so MAME's TestChip also reports a bank-select fault that a real board
would not have.

Text mode: `python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234"` and `--check`.
Optional C core: `python3 emulator/build_core.py` (needs git and `pip install ziglang`; clones
already at the pinned commits in `emulator/build/` are reused, so a rebuild works offline). It
fetches Musashi and the Z80 core at pinned commits; the build is reproducible. The C core is not
embedded in `Brico68k_Emulator.py` any more (`emulator/package_emulator.py` builds the one file
from `emulator_main.py`, `m68k_tables.py`, `m68k_py.py`, `neo_py.py` and `emu_host.py`).

Checking the Python core:
- `emulator/build_m68k_tables.py` writes `m68k_tables.py` from Musashi itself (which handler and
  how many cycles for each of the 65536 opcodes), so the Python decode cannot drift from it.
- `emulator/test/test_m68k_py.py` runs the Python 68000 and the C Musashi side by side on the
  same random memory: random opcodes (every one of the 1704 handlers is hit), random registers,
  supervisor or user mode, trace bit, interrupt requests, odd addresses (address errors, double
  faults), STOP, one or several instructions per call. It compares the cycles, every register and
  the full ordered list of bus accesses. 1 million cases, 0 differences.
- `emulator/test/test_neo_py.py` runs the Python and C AES models in lockstep (commands, reset
  button, Z80 options, cartridges, faults, test inputs) and compares cycles, PC, output words,
  screen lines, VRAM and palette after every slice: 0 differences.
- `emulator/regress_rom.py` with `CORE=python` against the C core: 474 scenarios, 2281 commands,
  0 differences (about 45 minutes on 2 cores, 1 minute with the C core). The scenarios the check
  sets apart as chaotic (random unstable lines, a crashed 68000) are not word-for-word between the
  two runs because the C library keeps its random generator and CPU registers from one scenario
  to the next in a worker (10 such scenarios in the last run; they were not re-run one by one
  from a fresh process for this ROM).
- `emulator/test/test_chip_hints.py`: the chip references and hint lines of TestWRAM, TestPRAM and
  TestVRAM under data and address faults (U1/U2, U7/U6, U17/U18, U19/U20), and none on a healthy console.
- `emulator/test/test_decode.py`: TestDecode under every decoding fault (`wram:sel`, `pal:sel`,
  `lspc:sel` at both levels, `wram:leak`) and a few faults of the RAMs themselves: each one must
  give exactly the expected line and no other, healthy must say "Test success". 0 failures.
- `emulator/test/test_ext_check.py`: the rule check sees each of 12 broken cases (see "Writing and
  testing a new extension").
- `emulator/test/bench_fuzz.py` (bug hunt / unexpected input): every command with extreme and random
  parameters (0, $FFFF, $FFFFFFFF, odd addresses, mirrors, unmapped space, counts over the buffer),
  random sequences, random combinations of 1-3 faults; after each command: an EOT or an exception
  report (never the 3 s timeout), at most 2047 words, a result that fits its type, and `Echo` answers
  right after (the 68000 is back in the dispatcher). `--check N` adds N random lines under the
  Brico16Bits rule check (Python core). `--seed` replays a failure. C test core by default (`--core python`).
- `emulator/guiverify.py`: 200/200 with the C core; with the Python core 187/191, the 4 misses
  being the diagnosis step that exceeds its 10 minute limit.

ROM regression check, for a source change meant to keep every output (a size or speed change):
`python3 emulator/regress_rom.py run OLD.BIO old.json`, the same for the new ROM, then
`python3 emulator/regress_rom.py compare old.json new.json`. 474 scenarios (no cartridge, test
cartridge, PROG board, every single fault the core models, every slot fault), each command's
output words, screen lines, Z80 commands and cartridge writes; about 1 minute on 2 cores.
`python3 emulator/build_test_core.py` (Linux, gcc) builds a test-only C core with settable joypad,
DIP, STATUS_A/B and SYSTYPE ports and an MVS backup RAM; the Python core has the same test hook.
With `CORE=python` or `CORE=emulator/build/libneocore_test.so` the check adds 10 input sets (MVS,
buttons, memory card states), which the AES model never reaches otherwise. With the Python core
the check takes much longer than with the C core.

## ROM contents: 26 extensions

Commands are typed on the Brico16Bits console. "No WRAM" means the test never relies on
work RAM (no stack), so it still runs on a board with dead WRAM.

| Command | No WRAM | What it does |
|---|:-:|---|
| **TestChip** | partly | Quick state of the board, one line per part, < 1 s (see below) |
| Echo, Read, Write, WriteB, Dump | yes | Link check and raw memory access. Odd addresses are handled. Dump: at most 2045 words (BricoNeo buffer: 2048 words, address included). |
| TestInp | yes | Controllers, memory card detect, AES/MVS mode |
| TestWRAM / TestBRAM / TestPRAM | yes | One suite (see below): data bus walking 1/0, byte writes (not palette), each address line named, March C- $5555/$AAAA on every word. PRAM: both banks + bank select. TestBRAM is MVS only and destructive. |
| **TestVRAM** | yes | All VRAM in one test, replaces TestVRAML/U and MarchVRAML/U (see below) |
| TestLSPC | yes | LSPC2-A2 registers, VRAM auto-increment |
| **TestDecode** | yes | Address decoding: the mirrors of WRAM (A16-A19), palette RAM (A13-A21) and the LSPC registers (A4-A16) name the line a decoder does not ignore; WRAM and palette RAM must not change each other (see below). Every word is put back |
| Color | yes | Whole screen in one colour (upstream) |
| TestStatusA / TestSystype | yes | Coin, service and RTC bits / TEST and JAMMA sense, AES/MVS aware |
| TestAudio | no | Z80 handshake, then left / right / centre beeps (upstream, reworked). A new command stops the beeps and runs. |
| TestFM | yes | Eyecatcher music, sound command `$02`, FM1-FM4 (upstream; was PlayEyeSnd) |
| TestSsg | yes | Coin chime, sound command `$7F`: timer A, SSG A-C, noise (upstream). On an AES the cartridge M1 decides what `$7F` plays |
| **TestZ80** | yes | Z80 handshake 03/01/03: needs 16 stable fresh replies, flags a latch echo |
| **TestDAC** | yes | RGB DAC pattern: 16 bands, one colour bit each. `P1=1` adds the dark bit; `P1=$10+n` fills the screen with band n for a scope or multimeter. |
| **TestTiming** | yes | LSPC line counter (+1 steps, range, lines per frame, stuck bits named), CPU cycles per frame, auto-animation counter |
| **TestWatchdog** | no | First run starves the watchdog; the second run reports the reset and its delay |
| **CartDiag** | yes | "p-bus test (diag cart)" on the jwestfall69 PROG board, **writes** its SRAM: /ROMOE and /PORTOE (prefetch, bus hold), write/read test of D0-D15, both byte lanes, A1-A19 (see below) |
| **TestVectors** | yes | Vector table switch `$000000-$00007F`, system ROM / cartridge (`REG_SWPBIOS`, `REG_SWPROM`): compares the 32 vectors with `$C00000` in both positions and back. Read only |
| **TestGfx** | yes | Test screen for the fix layer and the sprites, with the cartridge tiles (first C tile = P1): labels, fix tiles `$00-$FF`, flips, 8 x 4 tiles, H and V shrink. P2 = 1: the whole screen in tiles. Read on the screen (see below) |

Bold entries are new in this repository.

The code ends 4134 bytes under `$7FFA` (fork 1.35-nic034-15). The 32 KB limit is the NeoDiag
layout (header flag `$0004`), not the BricoNeo.

Removed in 1.35-nic034-11: **TestBus** (BIOS socket path, A15/A16 by the NeoDiag copies, CRC32)
and its check at boot: nothing tests the socket lines any more; a dead line shows as a console
that does not answer (BricoNeo `Trace`, continuity meter). Removed in 1.35-nic034-10: **CartTest**
(game cartridge P bus, read only) and **Version**. The fork
version is no longer in the ROM image: the SHA-256 in `rom/ROM.BIO.sha256` and this README tell
the builds apart (Brico16Bits shows the header version, 1.35, as before).

`ChipCheck` was renamed **TestChip** in 1.35-nic034-07 (same test, same output).

### TestDecode

The March tests walk the lines the RAM chips are wired to (WRAM A1-A15, one palette bank A1-A12).
The upper lines never reach a RAM chip: the decoders use them to pick which chip answers (on the
AES, NEO-C1 U4 sees A17-A23 and NEO-E0 U34 sees A1-A23, see the schematic notes below), and ignore some on purpose, so a RAM also answers at mirror addresses. A line
the decoder ignores badly is invisible to every other test. TestDecode checks the mirrors:

| Region | Mirrors | Lines |
|---|---|---|
| Work RAM | `$100000-$10FFFF` up to `$1FFFFF` | A16-A19 |
| Palette RAM (bank 0) | `$400000-$401FFF` up to `$7FFFFF` | A13-A21 |
| LSPC registers (`REG_VRAMMOD`) | `$3C0000-$3C000F` up to `$3DFFFF` | A4-A16 |

For each line, a word written at the base address must read back at base + 2^n, and a word written
there must read back at the base (`> Work RAM ... FAIL: not a mirror on A17`: this address answers
somewhere else). A base word that does not hold a value at all is reported as "the word itself is
bad" (a RAM fault, not a decoder one: run TestWRAM, TestPRAM or TestLSPC). The last line writes a
WRAM word and a palette word that share A1-A12, in both orders: neither may change the other (a
decoder output selecting two chips at once). Every word is saved and put back; the palette word is
colour 3072 (palette 192), not the reference colour or the backdrop. No WRAM, no stack, 2 ms.

**What it cannot see**: the lines the decoder uses to choose the region (A20-A23): a fault there
sends the access to another chip and stops the console much earlier. **Not verified on a real
console, nor against MAME yet**: the ranges (WRAM `$100000-$1FFFFF`, palette `$400000-$7FFFFF`, LSPC
`$3C0000-$3DFFFF`) are those of the wiki's NEO-C1 page, the LSPC mirrors follow its decode mask `$FE0001`
(the wiki says its decode masks are not verified), and the emulator models them after MAME's `neogeo`
address map (not re-read from MAME's source; `emulator/compare_mame.py` now runs TestDecode in MAME to
settle it).
If a healthy AES reports a mirror, the assumption is wrong, not the console: tell which line and on
which board.

### TestVectors and TestGfx

**TestVectors**: the 68000 reads its 32 exception vectors at `$000000-$00007F` from the system ROM
or from the cartridge; system latch output Q1 chooses (wiki "Memory mapped registers"). A system
ROM starts a game by switching to the cartridge, so a dead switch gives a console that shows its
start-up screen and a game that hangs. Three steps, each comparing the 32 long words with
`$C00000`: system ROM (all equal), cartridge (must differ: without a cartridge the open bus is
read, which differs as well), system ROM again. It prints the cartridge's SP, reset and VBLANK
vectors. The table is back on the system ROM before anything is printed; during the cartridge
step (under 1 ms, interrupts masked) an exception would use the cartridge vectors and would not be
reported as `EXCPT`: that is the test itself, nothing in that step can raise one on a sound board.

**TestGfx** shows what no other test shows: tiles. LSPC2, cartridge S ROM (fix) and C ROMs
(sprites), line buffers, palette. The tiles are the cartridge's (an AES has none on board), so
their content is not known to the ROM: the labels need the ASCII font that S ROMs hold, and the
sprites show the C tiles from P1 up through 15 different colours. On screen: `FLIP 0 H V HV` (one
tile, mirrored / upside down / both), `SPRITES 8X4` (32 tiles in reading order), `H SHRINK F-0`
(16 down to 1 pixel wide), `V SHRINK FF-3F` (a column of 16 tiles squeezed through the L0 ROM
table: 4 to 16 tiles show), and the fix tiles `$00-$FF`, 16 per row. Blank tiles: try another P1.
The screen stays until TestDAC. Uses sprites 1-35, palettes 0 and 1.
`TestGfx <tile> 1` fills the whole screen instead: 20 sprites of 14 tiles (320 x 224), no label.
The zones only cover parts of the screen; a fault that depends on the position (a line buffer
bit, a column of pixels) shows wherever it is in this mode.

### CartDiag: the cartridge P bus on the PROG board

**CartDiag, diagnostic PROG board** (the "p-bus test (diag cart)", destroys its content). A
command of its own, no automatic detection. Do not run `CartDiag` on a game cartridge: it writes,
and a word written in P2 latches the bank. The test prints its name and the board's address,
<https://github.com/jwestfall69/neogeo-diag-aes-prog> (jwestfall69, the board and the diag BIOS
whose P bus tests it follows). Its SRAM answers in both windows, so the test can write. It starts at once, without
probing, and the bad lines or a dead strobe it finds are named. In order:

1. **output enable (prefetch)**, the BIOS's method: a byte read three times, each time followed
   by another opcode, and compared with that opcode's byte on the same lane; a chip that drives
   nothing leaves the 68000 reading the word it prefetched, so all three agree (dead after 50
   rounds). P1 D0-D7, P1 D8-D15, P2 D0-D7, P2 D8-D15, in the BIOS order;
2. **output behind a 245 (bus hold)**: `$5555` written at +4, `$AAAA` at +8, each followed by a
   read at +0 under the lane mask; a dead output behind a 245 / NEO-G0 / NEO-BUF gives back the
   last value written, dead only if it does both times;
3. the RAM suite of TestWRAM on `$200000`: data lines walking 1/0, each byte written alone
   (/PORTWEU, /PORTWEL), each address line A1-A19 named, March C- on 64 KB;
4. 32 words written through P2 and read back through P1 (`$000200`): /ROMOEU, /ROMOEL.

Fidelity to the diag BIOS P bus tests (`sp1/p_rom_bus.asm`, read for the method; the code is our
own, that repository has no licence): the two output enable tests use the same method and order.
The other tests (data patterns, byte write, address lines) are equivalent or stronger than the
BIOS's (walking 1/0, March C-, every address line named). The BIOS labels its lanes LOWER/UPPER
the other way round from the 68000 lanes (D0-D7 = odd byte = LDS) as far as I can tell, but I
have not confirmed it; this ROM names the lanes by their data lines (D0-D7, D8-D15) and by the
signal (/ROMOEL = D0-D7), as the wiki does.

Every case was run in the emulator (each data line, A1-A19 at 0 and 1, each strobe) and the
healthy board, A5 and A19 in MAME too. **The PROG board itself has not been run with this ROM.**
The two output enable tests can only be checked against the assumption they make (the prefetched
word, the held value): the emulator models exactly that, MAME models neither, and no real board
has confirmed it. A healthy board that failed them would mean the assumption is wrong on your
hardware, not necessarily the board. 

### RAM and VRAM tests: what each step finds

Every memory is two 8-bit chips on the 16-bit bus: upper byte D8-D15 and lower byte D0-D7
(neogeodev wiki: two CXK5814 for the fast VRAM, two CXK5864 for the palette RAM; 64 KiB on a
16-bit bus for WRAM and slow VRAM). On an error the test prints the address, expected and read
words, the bad bits by name (`D3 D12`) and **which chip**: upper, lower or both.

| Step | Finds | Where |
|---|---|---|
| Data bus walking 1/0 on the first word (the complement goes to the next word before each read, so a floating bus cannot fake a pass) | Data line stuck, open or shorted to another | all |
| Byte writes: `$A5` to the upper byte alone, `$5A` to the lower byte alone, then the same to `$00` | A chip written by the other byte's write, or not written: write strobes (NEO-C1 WWU/WWL, 68000 UDS/LDS) | WRAM, BRAM. Not palette RAM or VRAM: there a byte write sets both bytes (wiki "Palettes", "Memory mapped registers") |
| Address lines: word at base + 2^k holds k; the base write must not change them (line stuck at 1); writing them must not change the base (stuck at 0) | Each bad line named (A9) | WRAM A1-A15, palette A1-A12 per bank, slow VRAM A0-A14, fast VRAM A0-A10 |
| March C- on every word, data background $5555/$AAAA: up(w B) up(r B,w ~B) up(r ~B,w B) dn(r B,w ~B) dn(r ~B,w B) up(r B) | Stuck cells, transition faults, coupling between cells, address decoder faults, and shorts between neighbouring data lines (always opposite values) | all |
| Bank 0 / bank 1 independence | Palette bank select (system latch, palette RAM A12) | palette |

The former fixed patterns ($0000/$FFFF/$AAAA/$5555) and the increment test are covered by the
March C- and the named address lines. Durations (3 s host limit): TestWRAM 0.38 s, TestPRAM
0.15 s, TestVRAM 1.47 s (1.35-nic034-12; were 0.42 / 0.16 / 1.77 s).

TestVRAM follows the wiki's VRAM rules with at least 8 cycles of margin: a read 24 CPU cycles
or more after the address write (16 required), a new address 24 cycles after a data write (16),
the next data write 20 cycles after the previous one (12). These are worst cases, counting only
the instructions in between (since 1.35-nic034-12; the March loops use address registers, and
`lsl.l` on a free register as a 2-byte wait, instead of absolute addresses and nops). The address is set before every read
(the wiki does not describe a read buffer, so none is relied on). It covers $0000-$7FFF,
$8000-$85FF and $8700-$87FF; $8600-$86FF holds the sprite lists the LSPC2 rewrites during the
display and cannot be tested from the 68000. Each zone is cleared to 0 afterwards.

### TestChip: quick state of the board

One line per part, what to suspect when it fails, and the test to run next. About 0.35 s
(0.6 s when the Z80 does not answer). The long tests stay the reference for a failing line.

| Line | How it is checked | A failure points to |
|---|---|---|
| Work RAM | Walking 1/0 on both bytes, then each address line A1-A15 (stuck at 0 and at 1) | The bits (D3, D8-D15...) or lines (A9) named; upper/lower chip or NEO-C1 WRU/WRL/WWU/WWL |
| WRAM byte writes | Each byte written alone must change only its own chip | That chip's write strobe: NEO-C1 WWU/WWL, 68000 UDS/LDS |
| Palette RAM | Same on both banks (A1-A12), plus bank select | Data bits: that palette RAM chip, or NEO-G0 (palette data buffer and write enable); address lines: NEO-B1 address switch; bank: system latch |
| VRAM slow / fast | Same through the LSPC2 (A0-A14 / A0-A10), with the LSPC access delays | The VRAM chip, LSPC2-A2 B/E or C/F bus |
| LSPC2 registers | `REG_VRAMMOD` write and read-back | LSPC2-A2, NEO-C1 LSPOE/LSPWE |
| NEO-C1 ports | P1, P2, STATUS_B, SOUND/STATUS_A each read from two places followed by different opcodes: a port nobody drives returns the open bus (the next opcode) | NEO-C1 input buffers |
| VBLANK / timer IRQ | The 68000 takes level 1 and level 2 interrupts (needs WRAM for the stack: skipped if WRAM fails) | LSPC2-A2 interrupt outputs IP0/IP1, its timer |
| Z80 | Standard sound driver handshake, as TestZ80 | No cartridge (inconclusive), else Z80, M1, Z80 RAM, latches |
| NEO-D0: 68KCLK 12 MHz | `n/a`: the 68000 has no time reference of its own (the BricoNeo's 1 ms command hold is not a clock). Measure it with the BricoNeo `Freq` command, probe on the extension input pin | - |
| NEO-D0: 24 MHz > LSPC2 | CPU cycles per video frame, 202,752 expected (same crystal: checks the dividers) | LSPC2 line counter or the 24 MHz path |
| NEO-D0: 6 MHz pixel | CPU cycles per LSPC timer tick, 2.00 expected | Pixel clock |
| NEO-D0: Z80 control | Shown by the Z80 answer | - |

Not visible from the 68000, so not in the table: the YM2610 interface, the 12 MHz to the
cartridge (NEO-ZMC2), the memory card bank select (needs a multi-bank card), the joypad
outputs, the LSPC2 -> NEO-B1 pixel pipeline (sprites, fix: TestDAC covers palette RAM to the
DAC only), the watchdog (TestWatchdog; the wiki notes it can be disabled by jumper J2) and the
sound itself (TestAudio). A part that stops the console from booting cannot be checked at all:
then nothing answers.

Limits: the floating-port check can only miss a dead port, not flag a healthy one (a bus pulled
to a fixed value would hide it). Absolute frequencies: BricoNeo `Freq`. Failures of several parts at once (e.g. WRAM chip or NEO-C1 select) are listed
together: the test cannot tell them apart.

### How the ROM must talk to the BricoNeo

Read from the Brico16Bits code (and Aurelien's review):

- **Command block** (`$90` address, `$94-$9F` P1-P3): written by the BricoNeo in 32-bit stores,
  held **1 ms**, then cleared. An extension reads its parameters first; code that keeps running
  after its EOT (TestDAC, TestAudio's beeps) must poll the block at least every ms or the
  next command is lost and times out. No re-read loops on the 68000 side: the BricoNeo is in
  charge of that timing; `*command` (loop mode) is how a test is repeated.
- **Output port**: a read at `$C1FF02` arms the watcher, one socket access goes by, the next
  one's address is the value (`InlinePortWriteD0`). Back to back, from code in the socket, with
  interrupts masked. EOT = a read at `$C1FF00`. One EOT per command, within **3 s**.
- **Buffer**: a ring of **2048 words**; more than 2047 words in one command and the start is lost.
- **Exceptions**: reported as the 68k command `EXCPT` (vector, SR, PC, access address) + EOT,
  through the "68k sends commands" channel (flag `$0002`), like `PRTXT`. Stock Brico16Bits does
  not know `EXCPT`: idle it ignores it, during an extension the raw words end the output. With
  the patch in `brico16bits/`, the output before the exception is shown, then the report.
- **Reset**: Brico16Bits `Reset` stops answering for 500 ms and relies on the watchdog: the ROM
  kicks it in every loop.
- **Image**: 128 KB, loaded whole; a shorter file only overwrites the start of the previous
  image, hence the full NeoDiag-layout image.
- **Absolute frequencies**: BricoNeo `Freq` on the extension input pin, not the 68000.

### Changes compared with upstream Brico68k 1.35

- **Exceptions**: every 68000 exception vector used to point to address 0. They now send an
  `EXCPT` report to the BricoNeo (see above) and return to the command loop. Vector 9 stays
  the upstream TRACE debugger.
- **Command dispatch**: as upstream (`jmp JUMP_TO_COMMAND`). A re-read loop added earlier was
  removed: the torn read it fixed came from the MAME test host, not from the BricoNeo.
- **Header flag `$0004`** (NeoDiag CRC32 + mirrors) set: it was there for TestBus (removed in -11); the BricoNeo still builds the copies and the CRC.
- **Palette bank registers**: `$3A000F` selects bank 0 and `$3A001F` bank 1. This was checked
  in MAME (`snk/neogeo.cpp`, `write_a3`); upstream 1.35 still has them swapped.
- **TestAudio**: the Brico16Bits host waits for one EOT with a fixed 3 s timeout. The 1.35
  version sent an EOT after its first line, so its later messages were lost. It now sends
  one EOT before the beeps, polls the command block during them (a new command stops them),
  and no longer leaks stack on the error path.
- **Dump**: limited to 2045 words, the BricoNeo buffer.
- **Read / Dump**: the two BricoNeo output port words (`$C1FF00-$C1FF03`, and the same offsets in every
  128 KB mirror of `$C00000-$CFFFFF`) are sent as `$0000`, not read: reading `$1FF00` is the end of the
  command (EOT) for the BricoNeo and `$1FF02` arms an output word, so the rest of the answer used to land
  in the next command.
- **Write**: odd addresses no longer crash with a 68000 address error.
- **VRAM tests**: merged into TestVRAM, which follows the wiki's access delays with margin (the
  1.35 tests read 12 cycles after the end of the address write, 16 required; MAME does not
  model this delay, so only a real board could show it). Upper data bits are now exercised
  (the old increment pattern never set D11-D15 in the fast VRAM, D15 in the slow one) and
  $8700-$87FF is tested.
- **RAM tests**: byte writes, named address lines, March C-; reports name the bad bits and
  the chip.
- **TestTiming**: a line counter change is confirmed by a second read before the step is
  judged, so a read landing during the change cannot report a false bad step.

## References

| Component | Version used |
|---|---|
| Brico16Bits host firmware | [Aurelien34/Brico16Bits](https://github.com/Aurelien34/Brico16Bits) at `84f7840` (2026-11-09; since `5859d6b` only the byte-swap detection changed, it now also accepts reset vectors above the first 64 KB: no effect here, ours is `$00C0xxxx`). Works unmodified; the `brico16bits/` patch only improves exception reports. |
| Brico68k upstream | [Aurelien34/Brico68k](https://github.com/Aurelien34/Brico68k) `main` at `52c1c92` (2026-11-02, BricoNeo 1.35 + PlayEyeSnd), plus `5643191` / `1b72deb` (2026-11-08: PlayEyeSnd renamed TestFM, new TestSsg). The `v1.34` tag (`434a447`) actually announces 1.33 with 13 extensions. |
| This ROM | fork version **1.35-nic034-15** (not in the image); the header announces **1.35**, the upstream base; 26 extensions, flags `$0007`, SHA-256 `8dcd66e4c2f2240032dd022eb6006244a61dded0acdde137abb564bc61bad69a` |
| vasm / vlink | vasm 1.9d (Volker Barthelmann, Frank Wille), vlink 0.17a (Frank Wille), built from source with zig 0.17.0 |
| Emulation | MAME 0.264, drivers `aes` and `neogeo` (MVS) |

**Versioning**: the fork version is `1.35-nic034-NN` (upstream base 1.35, fork build NN, +1 for
every published ROM). Since 1.35-nic034-10 (Version command removed) it is not in the ROM image:
the SHA-256 identifies a build. The header keeps the upstream base, so Brico16Bits shows "Found BricoNeo ROM
version 1.35" (it prints two numbers, `%d.%d`, and has no room for a suffix). The string is
`FORK_VERSION` in `source/inc/define.inc`; `build.py` and the Compiler check that the header
(`BRICONEO_VERSION` in `source/Brico68k.s`) equals its base.

The ROM keeps the BricoNeo header and the BricoExt layout (magic at `$80`, flags at `$8C`,
`jmp` at `$8E`, extension table at `$A0`). The reset vector upper word is `$00C0`, so
Brico16Bits recognises the byte order.

## Testing on a real console (BricoNeo running Brico16Bits)

1. Console off. Put the BricoNeo in the SP1 (BIOS) socket, pin 1 the right way. Insert a game
   cartridge: on an AES the Z80 program comes from the cartridge, so TestZ80 and TestAudio need one.
2. Connect the USB cable. Open the first serial port with PuTTY or Tera Term and **turn session
   logging on** (PuTTY: Session > Logging > All session output).
3. Drop `rom/ROM.BIO` at the root of the `BricoNeo` USB drive. The root loads it in RAM only
   and resets the console: your bank 0 is untouched, and the next power cycle brings it back.
   (Put it in a bank folder to keep it.)
4. Type `?`: the Extensions section must list the 25 commands.
5. Paste the whole of `bench/real_aes_session.txt` into the terminal. The `;` lines are comments
   and `Delay` waits, both built into the BricoNeo console.
6. In the emulator, **Compare** tab > **Open real console log...** (or
   `python Brico68k_Emulator.py --compare putty.log`). Every command of the log is replayed in the
   emulator and the outputs are compared, command by command: `same`, `varies` (TestInp,
   TestStatusA and TestSystype depend on what is plugged in), `same verdict` (TestTiming: cycle
   counts may differ slightly) or `DIFFERENT`, with the diff. Look at the screen for TestDAC.
   `bench/expected_healthy_aes.txt` (and `..._no_cartridge.txt`) give the same reference as text.
7. If something differs: **Find the fault** (or `--diagnose putty.log`). The log is replayed under
   each of the 343 single faults the emulator models (data bit or address line stuck at 0 or 1 in
   WRAM, palette RAM, VRAM and the line counter, WRAM chip dead, BIOS socket A1-A16, decoding of
   WRAM, palette RAM and the LSPC registers), and the faults are ranked by how
   many commands they explain. **Apply to Faults** puts the best one in the emulator. It takes
   about 1.5 min on 2 cores, much less with more cores (the work is spread over processes).
   Limits: one stuck-at fault at a time, modelled chips only. Intermittent faults, shorts between
   lines, timing faults and the other chips are not in the dictionary, so "no candidate" does not
   mean "no fault".

## Testing

`tools/mame_bench.py` runs the ROM in a real MAME, with a simulated Brico16Bits host written
in Lua. It needs your own BIOS dumps: `000-lo.lo`, plus `sm1.sm1` and `sfix.sfix` for MVS.

```
python3 tools/make_test_cart.py /tmp/testcart          # synthetic cartridge (header, security code, tiny Z80 M1), nothing copyrighted
BRICO_SOUND_ROM=000-lo.lo python3 tools/mame_bench.py rom/ROM.BIO
BRICO_SOUND_ROM=000-lo.lo BRICO_CART=/tmp/testcart python3 tools/mame_bench.py rom/ROM.BIO TestZ80 TestAudio
BRICO_SOUND_ROM=000-lo.lo BRICO_DRIVER=neogeo BRICO_MVS_DIR=dumps/ python3 tools/mame_bench.py rom/ROM.BIO TestWatchdog Echo:1 TestWatchdog
```

Verified in MAME, on `aes`, `aes` with the test cartridge, and `neogeo`: all extensions,
each well under the 3 s host limit.

- TestChip: identical to MAME (`aes`, with and without the test cartridge), and under every
  bench fault but one: the bench's palette address fault shares one store between both banks,
  so MAME also reports a bank-select fault that a real board would not have.

- TestDAC: 16 exact colours on screenshots.
- TestTiming: 202,724 cycles per frame against 202,752 expected (within the resolution of its 58-cycle measuring loop). Injected stuck counter bits,
  at 0 and at 1, are named exactly.
- TestWatchdog: reset after ~133 ms on MVS (MAME: 135 ms).
- TestZ80: passes with a real SM1 and with the test M1.

### Known limits (read before trusting a result)

- **Real hardware**: fork 1.35-nic034-06 was run on a real AES by Nicolas (2026-11-10): reported
  working, and **CartDiag** passes on the jwestfall69 PROG board (its /ROMOE and /PORTOE prefetch
  and bus hold tests exist nowhere else: MAME and the emulator cannot check them). No console log
  was compared word for word, and no board with a known fault has been tested yet: that the tests
  name a real fault correctly is still shown in simulation only. MAME stays the reference.
  **1.35-nic034-07 to -09 (TestVectors, TestGfx) and -14 (TestDecode, chip references) have not run on real hardware yet.** In MAME
  0.264 both give the same words as in the emulator, and TestGfx the same picture pixel for pixel
  with the test cartridge. Not shown by that: the real L0 ROM (vertical shrink), real S and C
  tiles, and what a real LSPC does with sprite 0 (MAME draws it in the unused sprite slots of
  each line, 1 pixel wide at x = 0, even with a height of 0: the screen tests now put it off
  screen, as SNK's system ROM does for every sprite).
- **CartDiag**: MAME has no PROG board (the bench plays it with a shadow RAM) and no
  slot address faults on a ROM. The test cartridge's softlist entry needs `<feature name="slot"
  value="rom"/>`: without it MAME 0.264 maps `$000100-$000103` to a protection handler that reads
  `$FFFF`.
- **TestWatchdog**: MAME emulates the watchdog on MVS only, although the AES has the same
  NEO-B1 watchdog (Brico16Bits' own `Reset` command relies on it). On AES in MAME the test
  reports "no reset"; on a real AES it must pass. Commands sent during the 1.5 s starve window
  are lost. The reset is modelled as instant, as in MAME; on the board /RESET then stays low a
  while (about 200 ms by Charles MacDonald's measures, unverified per the wiki).
- **TestTiming** on PAL boards: the expected 312 lines is not verified (MAME is NTSC only).
  The CPU cycle check assumes no bus wait states, so it reports CHECK, not FAIL, when it is
  off by more than 0.5 %.
- **MAME bench port model**: the Lua host takes the first `$C2xxxx` read after the arm, not
  "skip one access, take the next" like the BricoNeo PIO (the emulator does the latter). Both give
  the same values for `InlinePortWriteD0`.
- **Brico16Bits patch** (`brico16bits/`): only syntax-checked with stub headers; not built with
  the Pico SDK, not run on a BricoNeo.
- **TestDAC levels** (100 / 47 / 22 / 10 / 6 %) come from MAME's resistor model
  (220 / 470 / 1k / 2k2 / 3k9 ohm). Real boards will differ slightly.

## Licences

- Brico68k Emulator core: Musashi 68000, MIT, © Karl Stenerud (`emulator/MUSASHI_LICENSE.txt`),
  ported to Python in `emulator/m68k_py.py` (its tables generated from Musashi); Z80 core
  superzazu/z80, MIT, © Nicolas Allemand (`emulator/Z80_LICENSE.txt`), the part used ported in
  `emulator/neo_py.py`; `emulator/neocore.c` and its Python port `neo_py.py` are written from
  MAME's Neo Geo driver behaviour (no MAME code is copied).
- Brico68k firmware source: MIT, © Aurelien34. See `source/LICENSE`; the changes in this
  repository are under the same licence.
- vasm and vlink: their authors' terms. They are free for non-commercial use; ask the authors
  before any commercial redistribution of the embedded binaries.
- MAME, BIOS and cartridge dumps are **not** included. Use your own.
