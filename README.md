# Brico68k Compiler and ROM

A one-file tool that builds the **Brico68k** Neo Geo diagnostic ROM, and a ready-to-use build
of an extended Brico68k (BricoNeo 1.35 + review fixes + new tests).

The ROM runs on the **BricoNeo** board, driven by the **Brico16Bits** host firmware (stock
firmware works; `brico16bits/` holds an optional patch so 68000 exceptions are reported cleanly).
It is a BIOS-socket diagnostic for Neo Geo AES and MVS consoles. Its 68000 code follows what the
Brico16Bits code expects (see "How the ROM must talk to the BricoNeo" below).

| Path | What it is |
|---|---|
| `Brico68k_Compiler.py` | Brico68k Compiler 1.4 (Python 3.8+, standard library only, Tk window) |
| `Brico68k_Emulator.py` | Brico68k Emulator 1.15: tests the ROM on an emulated AES (cartridge or diagnostic PROG board included), no MAME and no BricoNeo needed |
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

The file embeds a small emulator core for Windows x64 and Linux x64. The core is the Musashi
68000 (exact cycle counts), a real Z80 (superzazu/z80) and a Neo Geo AES model written from
MAME's driver:

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
- **Not emulated**: the YM2610 (ports `$04`-`$07` read 0) and sound, Z80 ROM banking, sprites,
  the fix layer, protected cartridges (SMA, PVC, CMC, encrypted P: their extra registers read
  as P ROM) and a memory card. S, C, V and M1 are checked, not used: the cartridge's M1 does
  not replace the built-in test M1. The screen shows the backdrop colour of each line, which is
  enough for TestDAC and Color.
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

Checked against MAME, 38 test commands each time (`emulator/compare_mame.py`, an address
error report and CartTest included), with word-for-word identical output:

- `aes` without a cartridge, against the Z80 without a program: 38 out of 38;
- `aes` with the bench test cartridge, whose real MAME Z80 runs the same M1, against the
  built-in test cartridge and test M1: 38 out of 38. This covers TestZ80, TestAudio,
  PlayEyeSnd and CartTest.

Nothing to install with pip: the emulator uses only the Python standard library, and its core is
embedded. The window needs Tkinter. It comes with Python on Windows (python.org installer); on
Linux it may be a separate package (`sudo apt install python3-tk`), and the tool says so if it is
missing.

The window (light theme) is a diagnostic dashboard:

- **Sidebar**: the tests grouped by Memory, Video, Sound, Inputs and system, Cartridge and Tools, each with a
  result badge, plus a live thumbnail of the screen (click it to enlarge).
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

The tab also has presets for typical AES faults. Faults stay active across power cycles, like
a real hardware fault; a red lamp and the tab title show how many are active. Example:

```
python Brico68k_Emulator.py --fault wram:lane:upper --fault pal:data:11:0 --run TestWRAM TestPRAM
python Brico68k_Emulator.py --fault help
```

Checked against the MAME bench with the same fault injected (`emulator/compare_mame_faults.py`):
27 out of 28 outputs are identical without a cartridge, 24 out of 25 with the test cartridge,
ChipCheck included. That covers WRAM data bits, a dead chip and address lines, palette data and
address lines, the line counter, VRAM data, cartridge slot data lines (CartTest on the test
cartridge), and the PROG board (CartDiag): MAME has no such board, so the bench's shadow RAM over
`$000080-$2FFFFF` with A21 masked off plays it (one RAM seen at `$0xxxxx` and `$2xxxxx`, written
by byte lanes), healthy and with slot A5 or A19 stuck at 0. MAME's probes cannot model the
palette bank select, VRAM address lines or the on-screen effect, so those were checked by hand:
TestPRAM reports bank independence, TestVRAM names the zone and the line, and the R4
band turns black. The one difference: the bench's palette address fault shares one store
between both banks, so MAME's ChipCheck also reports a bank-select fault that a real board
would not have.

Text mode: `python Brico68k_Emulator.py --run "TestWRAM" "Echo 1234"` and `--check`.
Rebuild the core: `python3 emulator/build_core.py` (needs git and `pip install ziglang`; clones
already at the pinned commits in `emulator/build/` are reused, so a rebuild works offline). The
build is reproducible: the same sources give the same core checksums.
It fetches Musashi and the Z80 core at pinned commits.
The build is reproducible: it gives the same binaries.

ROM regression check, for a source change meant to keep every output (a size or speed change):
`python3 emulator/regress_rom.py run OLD.BIO old.json`, the same for the new ROM, then
`python3 emulator/regress_rom.py compare old.json new.json`. 501 scenarios (no cartridge, test
cartridge, PROG board, every single fault the core models, every slot fault), each command's
output words, screen lines, Z80 commands and cartridge writes; about 1 minute on 2 cores.
`python3 emulator/build_test_core.py` (Linux, gcc) builds a test-only core with settable joypad,
DIP, STATUS_A/B and SYSTYPE ports and an MVS backup RAM: with
`CORE=emulator/build/libneocore_test.so` the check adds 10 input sets (MVS, buttons, memory
card states), which the shipped AES core never reaches.

## ROM contents: 25 extensions

Commands are typed on the Brico16Bits console. "No WRAM" means the test never relies on
work RAM (no stack), so it still runs on a board with dead WRAM.

| Command | No WRAM | What it does |
|---|:-:|---|
| **ChipCheck** | partly | Quick state of the board, one line per part, < 1 s (see below) |
| **Version** | yes | The only place with the fork version: says it is the Nic034 fork, `1.35-nic034-06`, the upstream base and the source. Also in the `?` list. |
| **TestBus** | yes | BIOS socket, 68000 -> BricoNeo, as NeoDiag does it: A15/A16 from the mirror bytes, A1-A14/D0-D15 by CRC32; text and 16 screen bands (see below). Also run at boot. |
| Echo, Read, Write, WriteB, Dump | yes | Link check and raw memory access. Odd addresses are handled. Dump: at most 2045 words (BricoNeo buffer: 2048 words, address included). |
| TestInp | yes | Controllers, memory card detect, AES/MVS mode |
| TestWRAM / TestBRAM / TestPRAM | yes | One suite (see below): data bus walking 1/0, byte writes (not palette), each address line named, March C- $5555/$AAAA on every word. PRAM: both banks + bank select. TestBRAM is MVS only and destructive. |
| **TestVRAM** | yes | All VRAM in one test, replaces TestVRAML/U and MarchVRAML/U (see below) |
| TestLSPC | yes | LSPC2-A2 registers, VRAM auto-increment |
| Color | yes | Whole screen in one colour (upstream) |
| TestStatusA / TestSystype | yes | Coin, service and RTC bits / TEST and JAMMA sense, AES/MVS aware |
| TestAudio | no | Z80 handshake, then left / right / centre beeps (upstream, reworked). A new command stops the beeps and runs. |
| PlayEyeSnd | yes | Eyecatcher music, sound command `$02` (upstream) |
| **TestZ80** | yes | Z80 handshake 03/01/03: needs 16 stable fresh replies, flags a latch echo |
| **TestDAC** | yes | RGB DAC pattern: 16 bands, one colour bit each. `P1=1` adds the dark bit; `P1=$10+n` fills the screen with band n for a scope or multimeter. |
| **TestTiming** | yes | LSPC line counter (+1 steps, range, lines per frame, stuck bits named), CPU cycles per frame, auto-animation counter |
| **TestWatchdog** | no | First run starves the watchdog; the second run reports the reset and its delay |
| **CartTest** | yes | Game cartridge P bus D0-D15, read only (never writes): P1 by the security code (names stuck / open lines), P2 activity |
| **CartDiag** | yes | "p-bus test (diag cart)" on the jwestfall69 PROG board, **writes** its SRAM: /ROMOE and /PORTOE (prefetch, bus hold), write/read test of D0-D15, both byte lanes, A1-A19 (see below) |

Bold entries are new in this repository.

The code ends 2552 bytes under `$7FFA` (fork 1.35-nic034-06, after a size review that kept every
output word for word: shared end of command, shared print routines, PC-relative jumps). The 32 KB
limit is the NeoDiag layout (header flag `$0004`), not the BricoNeo.

### CartTest and CartDiag: the cartridge P bus

**CartTest, game cartridge** (read only):

- Header (`$100` "NEO-GEO", NGH at `$108`, P ROM size at `$10A`, wiki "68k program header") is
  printed as read: a bad data line changes it too.
- P1 (`$000000-$0FFFFF`, /ROMOE): every cartridge holds the same 61-word security code, at the
  address in the long at `$182` (wiki "Security code"). The words were checked against the
  system ROM's own copy (`neo-epo.bin` `$C12C7C`, `sp-s2.sp1` `$C146A2`): the wiki listing has a
  typo at word 25 (`$0606` for `$6606`). Every data bit is 1 in some words and 0 in others, so
  each line is judged both ways: reads 0 where 1 is expected (stuck at 0 or open), reads 1
  where 0 is expected (stuck at 1 or open), wrong in some words only (bad contact, short).
  A bad line also corrupts the pointer, so the code is looked for at the pointer and at the
  pointer with any one or two bits A1-A19 flipped (210 places, the pointer as read first).
- P1 without the code: its activity is sampled like P2, which names lines that never toggle.
- P2 (`$200000-$2FFFFF`, /PORTOE): the content depends on the game, so only activity is
  checked, one word every 16 bytes up to the header size (all of it with `CartTest 1`), never
  `$2FE000-$2FFFFF` (NEO-SMA registers there: random number generators that step on reads).
- Verdict: the same lines on P1 and P2 point to the edge, the slot or the console (another
  cartridge with the same lines = console side); P1 only or P2 only point to that chip.
- **CartTest never writes.** On a cartridge without a header it says so and points to `CartDiag`.
- Limits: an address line fault on a game cartridge shows as "P1 answers but reads wrong", not
  named (the PROG board names it). Protected cartridges answer the same way as long as their P1
  is not encrypted.

**CartDiag, diagnostic PROG board** (the "p-bus test (diag cart)", destroys its content). A
command of its own: two choices, `CartTest` for a game cartridge (read only) and `CartDiag` for
the PROG board, no automatic detection. Do not run `CartDiag` on a game cartridge: it writes,
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
March C- and the named address lines. Durations (3 s host limit): TestWRAM 0.42 s, TestPRAM
0.16 s, TestVRAM 1.8 s.

TestVRAM follows the wiki's VRAM rules with at least 8 cycles of margin: a read 28 CPU cycles
after the address write (16 required), a new address 28 cycles after a data write (16), the
next data write 28 cycles after the previous one (12). The address is set before every read
(the wiki does not describe a read buffer, so none is relied on). It covers $0000-$7FFF,
$8000-$85FF and $8700-$87FF; $8600-$86FF holds the sprite lists the LSPC2 rewrites during the
display and cannot be tested from the 68000. Each zone is cleared to 0 afterwards.

### ChipCheck: quick state of the board

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

### TestBus: the BIOS socket path

The BricoNeo already knows the NeoDiag layout: with header flag `$0004` it writes, at load
time, the CRC-32 of `$0000-$7FFA` at `$7FFC` and copies the 32 KB to `$8000`, `$10000` and
`$18000` with the copy number (1, 2, 3) in the byte at `$7FFA` (Brico16Bits
`NeoDiagImageBuilder.cpp`). The ROM sets that flag, keeps its code below `$7FFA`, and our build
tools (`build.py`, CMake, the Compiler, `tools/neodiag_image.py`) write the same 128 KB, so a
`SendROMPart` upload (which skips the BricoNeo builder), MAME and the emulator see the same bytes.

| Lines | How | Result |
|---|---|---|
| A15, A16 | The copy number read at `$C07FFA`, `$C0FFFA`, `$C17FFA`, `$C1FFFA` says which copy the BricoNeo served. The code runs in every copy, so the console still boots with A15/A16 stuck | The line and its level: reads 0 (red band), reads 1 (blue), both in one pass (orange) |
| A1-A14, D0-D15 | The code itself needs them: a cut stops the boot (then BricoNeo `Trace`, and a continuity meter). A marginal line shows as a CRC32 error (the wiki: "BIOS CRC error could be faulty NEO-E0") | CRC32 OK / FAIL (yellow bands A1-A14); the line cannot be named |

One pass, no retry: `*TestBus` (the BricoNeo loop mode) repeats it and refreshes the output
when it changes. The command block `$90-$9F`, written live by the BricoNeo, is counted as zeros.
The screen shows 16 bands, A1 at the top, groups of 4, until the next command. At boot the
firmware reads the four copy numbers (< 1 ms) and shows the screen only on a fault: with A15 or
A16 stuck at 1, the command block read lands in a copy and no command can ever arrive.

### How the ROM must talk to the BricoNeo

Read from the Brico16Bits code (and Aurelien's review):

- **Command block** (`$90` address, `$94-$9F` P1-P3): written by the BricoNeo in 32-bit stores,
  held **1 ms**, then cleared. An extension reads its parameters first; code that keeps running
  after its EOT (TestDAC, TestBus, TestAudio's beeps) must poll the block at least every ms or the
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
- **Header flag `$0004`** (NeoDiag CRC32 + mirrors) set, for TestBus.
- **Palette bank registers**: `$3A000F` selects bank 0 and `$3A001F` bank 1. This was checked
  in MAME (`snk/neogeo.cpp`, `write_a3`); upstream 1.35 still has them swapped.
- **TestAudio**: the Brico16Bits host waits for one EOT with a fixed 3 s timeout. The 1.35
  version sent an EOT after its first line, so its later messages were lost. It now sends
  one EOT before the beeps, polls the command block during them (a new command stops them),
  and no longer leaks stack on the error path.
- **Dump**: limited to 2045 words, the BricoNeo buffer.
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
| Brico16Bits host firmware | [Aurelien34/Brico16Bits](https://github.com/Aurelien34/Brico16Bits) at `5859d6b` (2026-10-22, "Fixed remote keyboard detection"). Works unmodified; the `brico16bits/` patch only improves exception reports. |
| Brico68k upstream | [Aurelien34/Brico68k](https://github.com/Aurelien34/Brico68k) `main` at `52c1c92` (2026-11-02, BricoNeo 1.35 + PlayEyeSnd). The `v1.34` tag (`434a447`) actually announces 1.33 with 13 extensions. |
| This ROM | fork version **1.35-nic034-06** (Version command only); the header announces **1.35**, the upstream base; 25 extensions, flags `$0007`, SHA-256 `01b128ee3fb64ebe246d98ac2a58d6c0f315236e8349fa9b2f794019d29fa99b` |
| vasm / vlink | vasm 1.9d (Volker Barthelmann, Frank Wille), vlink 0.17a (Frank Wille), built from source with zig 0.17.0 |
| Emulation | MAME 0.264, drivers `aes` and `neogeo` (MVS) |

**Versioning**: the fork version is `1.35-nic034-NN` (upstream base 1.35, fork build NN, +1 for
every published ROM), shown only by the `Version` command and its `?` description, which say it
is the Nic034 fork. The header keeps the upstream base, so Brico16Bits shows "Found BricoNeo ROM
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
4. Type `?`: the Extensions section must list the 25 commands; `Version` says which build runs. All screen bands green after
   `TestBus` = the BIOS socket path is fine.
5. Paste the whole of `bench/real_aes_session.txt` into the terminal. The `;` lines are comments
   and `Delay` waits, both built into the BricoNeo console.
6. In the emulator, **Compare** tab > **Open real console log...** (or
   `python Brico68k_Emulator.py --compare putty.log`). Every command of the log is replayed in the
   emulator and the outputs are compared, command by command: `same`, `varies` (TestInp,
   TestStatusA and TestSystype depend on what is plugged in), `same verdict` (TestTiming: cycle
   counts may differ slightly) or `DIFFERENT`, with the diff. Look at the screen for TestDAC.
   `bench/expected_healthy_aes.txt` (and `..._no_cartridge.txt`) give the same reference as text.
7. If something differs: **Find the fault** (or `--diagnose putty.log`). The log is replayed under
   each of the 288 single faults the emulator models (data bit or address line stuck at 0 or 1 in
   WRAM, palette RAM, VRAM and the line counter, WRAM chip dead, BIOS socket A1-A16), and the faults are ranked by how
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

- ChipCheck: identical to MAME (`aes`, with and without the test cartridge), and under every
  bench fault but one: the bench's palette address fault shares one store between both banks,
  so MAME also reports a bank-select fault that a real board would not have.
- TestBus: `emulator/compare_mame_bus.py` injects the same BIOS socket fault in MAME
  (`BRICO_SOCKET=15,1`) and in the emulator and compares the screen bands: 7/7 identical
  (healthy, A15/A16 stuck at 0 and 1, two lines at once).

- TestDAC: 16 exact colours on screenshots.
- TestTiming: 202,724 cycles per frame against 202,752 expected (within the resolution of its 58-cycle measuring loop). Injected stuck counter bits,
  at 0 and at 1, are named exactly.
- TestWatchdog: reset after ~133 ms on MVS (MAME: 135 ms).
- TestZ80: passes with a real SM1 and with the test M1.

### Known limits (read before trusting a result)

- **Nothing here has been validated on real hardware yet.** MAME is the reference used.
- **CartTest / CartDiag**: MAME has no PROG board (the bench plays it with a shadow RAM) and no
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

- Brico68k Emulator core: Musashi 68000, MIT, © Karl Stenerud (`emulator/MUSASHI_LICENSE.txt`);
  Z80 core superzazu/z80, MIT, © Nicolas Allemand (`emulator/Z80_LICENSE.txt`);
  `emulator/neocore.c` is written from MAME's Neo Geo driver behaviour (no MAME code is copied).
- Brico68k firmware source: MIT, © Aurelien34. See `source/LICENSE`; the changes in this
  repository are under the same licence.
- vasm and vlink: their authors' terms. They are free for non-commercial use; ask the authors
  before any commercial redistribution of the embedded binaries.
- MAME, BIOS and cartridge dumps are **not** included. Use your own.
