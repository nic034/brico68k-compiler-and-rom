# Changelog

Newest first. Release notes used to be kept on Google Drive; they now live here only.
Upstream references stay the same unless stated: Aurelien34/Brico68k `52c1c92`,
Aurelien34/Brico16Bits `5859d6b`.

## 2026-11-06 - Fork version in the Version command only

ROM SHA-256 `7f88cd8d6ac9916a30caf1c635ceb52559ecdf91e6cfb4bca39369bff54be5b8` (fork 1.35-nic034-01), rebuilt from `source/` to the same checksum.

- The header is back to **1.35**, the upstream base: Brico16Bits shows "Found BricoNeo ROM
  version 1.35". 1.3501 would have sorted after a future upstream 1.36. The fork version and the
  "Nic034 fork" mention are only in the `Version` command and its description.
- `build.py` and the Compiler check that the header equals the base of `FORK_VERSION`.
- Checks: 35/35 identical to MAME with and without the test cartridge, GUI 168/168.

## 2026-11-06 - Header version 1.3501, Version says "Nic034 fork"

ROM SHA-256 `083455becae63b8fc09e914679777ddf69aa8fdade61ec2dea356f6fb570e6db` (fork 1.35-nic034-01, header 1.3501), rebuilt from `source/` to the same
checksum.

- Header version 1.3501 (minor = 35 x 100 + build): Brico16Bits now shows "Found BricoNeo ROM
  version 1.3501" for this fork. `build.py` and the Compiler check that it matches `FORK_VERSION`.
- `Version` says it is the Nic034 fork (not an Aurelien34 release), the upstream base and the
  source repository.
- Checks: 35/35 identical to MAME with and without the test cartridge, GUI 168/168.

## 2026-11-06 - Fork version 1.35-nic034-01

ROM SHA-256 `7713a97e1696240246582df40f05ccb75a98b9746dd5fda69c92b82e2605d3c5` (fork
**1.35-nic034-01**, BricoExt header 1.35, 23 extensions), rebuilt from `source/` to the same
checksum.

- The fork now has a version. Brico16Bits shows the header version as two numbers
  (`%d.%d`), so the header keeps the upstream base, 1.35. `FORK_VERSION` (`inc/define.inc`) is the
  single definition, used by the new **Version** command and its description in the `?` list.
  The Compiler log prints it. Earlier builds of this repository had no fork version.
- `bench/real_aes_session.txt` starts with `Version`, so a console log says which build ran.
- Checks: 35/35 identical to MAME with and without the test cartridge, GUI 168/168.

## 2026-11-06 - Aligned with the Brico16Bits code, TestBus, Compiler 1.3, Emulator 1.11

ROM SHA-256 `faba564c2502f6fc464156326a200cbb7765fad25fea6a4df43706e895b2e41e` (BricoNeo 1.35,
22 extensions, flags `$0007`), rebuilt from `source/` to the same checksum; `build.py`, CMake and
the Compiler give the same bytes.

After Aurelien's review and a full read of the Brico16Bits sources:

- **Command dispatch back to upstream** (`jmp JUMP_TO_COMMAND`). The command re-read loop
  (earlier review fix) is gone: the BricoNeo writes the address in one 32-bit store and holds it 1 ms; the
  torn read came from the MAME test host.
- **Exceptions** are sent as the 68k command `EXCPT` (vector, SR, PC, access address) + EOT
  instead of plain text. `brico16bits/` holds a Brico16Bits patch that shows them (syntax-checked
  only).
- **TestBus** (new): BIOS socket path, built on the NeoDiag layout the BricoNeo already makes for
  header flag `$0004` (CRC32 at `$7FFC`, copy number at `$7FFA` of the copies at `$8000`,
  `$10000`, `$18000`). Names A15/A16 stuck at 0/1; CRC32 for A1-A14/D0-D15. Text and 16 screen
  bands; also checked at boot (screen only on a fault). One pass: `*TestBus` repeats.
  Code limited to `$7FFA`. `tools/neodiag_image.py` replaces nothing upstream; it writes what the
  BricoNeo writes, for SendROMPart, MAME and the emulator.
- **ChipCheck**: no more absolute 68KCLK / frame rate from the BricoNeo's 1 ms hold (not a clock):
  `n/a`, measure with BricoNeo `Freq`. Cycles per frame and the 6 MHz check unchanged.
- **TestAudio**: the beeps poll the command block; a new command stops them and runs (it used to
  time out).
- **Dump**: at most 2045 words (BricoNeo ring buffer of 2048 words).
- **Emulator 1.11**: port watcher modelled access by access (PIO), 2048-word ring buffer, BIOS
  socket faults (`bios:addr:N:V`, `bios:float:N`, 3 presets), `EXCPT` display, TestBus in Overview.
  Diagnosis: when every command timed out it points to the boot screen.
- **Compiler 1.3**: NeoDiag layout when the header has flag `$0004`; a relative `--source`
  folder works.
- **MAME bench**: `BRICO_SOCKET` injects BIOS socket faults; `emulator/compare_mame_bus.py`.
- Checks: 34/34 identical to MAME with and without the test cartridge (an address error report
  included), 22/23 with faults (known bench palette artifact), TestBus screen 7/7, GUI 168/168
  (the "command during the beeps times out" checks became "it runs").
- Not verified: anything on a real AES or BricoNeo; the Brico16Bits patch was not built.

## 2026-11-06 - Palette diagnosis names NEO-G0

ROM SHA-256 `0b406cc34a85815a57d3a2a7214c784c4b59c9d33afd5e571b7c999b3e9fe3da`.

- Palette RAM data errors (ChipCheck and TestPRAM) now point to the chip of the bad bits or
  NEO-G0, which buffers the palette data and makes the palette RAM write enable on the AES
  (neogeodev wiki, "NEO-G0"). They used to blame the NEO-B1 bus switch, which only handles
  the palette address. Address errors still name the NEO-B1, bank errors the system latch.
- Every other diagnostic text checked against the wiki (NEO-C1 selects, LSPC2 VRAM buses and
  IP0/IP1, NEO-D0 clocks): unchanged.
- Checks: 30/30 identical to MAME, 22/23 with faults (known bench palette artifact).

## 2026-11-06 - Merged RAM and VRAM tests, hardened LSPC2 tests, Emulator 1.10

ROM SHA-256 `c69eb140111ee70c75d9651e4470c8a81a1f66fc21ba23653294fa7f805f5ad1` (BricoNeo 1.35,
21 extensions), rebuilt from `source/` to the same checksum.

- **TestVRAM** replaces TestVRAML, TestVRAMU, MarchVRAML and MarchVRAMU: per zone (slow, fast)
  data bus walking 1/0, each address line named (stuck at 0 / 1), March C- with data background
  $5555/$AAAA on every word, then the zone is cleared. Covers $8700-$87FF (never tested before);
  $8600-$86FF (sprite lists rewritten by the LSPC2) is skipped. 1.8 s, where the four old tests
  took 2.25 s together. The old increment pattern never set D11-D15 of the fast VRAM nor D15 of
  the slow VRAM: those stuck at 0 went unseen.
- **TestWRAM / TestPRAM / TestBRAM** (one suite): walking 1/0, byte writes (WRAM/BRAM only: each
  byte written alone, finds write strobe faults that word tests cannot), each address line
  named, March C- $5555/$AAAA (coupling faults; replaces the fixed patterns and the increment
  test). TestWRAM 0.42 s (was 0.47 s).
- **Every error names the chip**: upper (D8-D15), lower (D0-D7) or both, with the bad bits by
  name; address errors name the lines.
- **Wiki rules** (VRAM access delays, no byte test where byte writes fill both bytes, no
  read-buffer assumption, sprite list area skipped) applied with >= 8 cycles of margin. ChipCheck
  VRAM reads now 28 cycles after the address (was 20).
- **ChipCheck**: WRAM byte-write line; a timer IRQ left pending is cleared after starting the
  timer, so it cannot shorten the 6 MHz measure.
- **TestTiming**: a line counter change is confirmed by a second read before the step is judged.
- Checks: 30/30 identical to MAME without and with the test cartridge (the former TestTiming
  one-pass difference is gone); 22/23 with faults (the known bench palette artifact); every
  emulator fault preset named with the right chip; `guiverify.py` 168/168.

## 2026-11-06 - ChipCheck, Emulator 1.9 (interrupts, progress)

ROM SHA-256 `cadca47e7e621b019d66391bd41ea24a05a41de0785712f059e924ad2cacab07` (BricoNeo 1.35,
24 extensions), rebuilt from `source/` to the same checksum.

- **ChipCheck** (new extension): quick state of the board, one line per part, < 1 s:
  WRAM, palette RAM (both banks + bank select), VRAM slow and fast (data bits and address
  lines named, stuck at 0 or 1), LSPC2 registers, NEO-C1 ports driven (open-bus check),
  VBLANK and timer interrupts, Z80 handshake, NEO-D0 outputs (68KCLK against the BricoNeo's
  1 ms, 24 MHz to the LSPC2 by cycles per frame, 6 MHz pixel by the LSPC timer). Each failure
  names what to suspect and the test to run next. Level 1/2 vectors now go to handlers that
  count only during ChipCheck (otherwise unchanged: unexpected interrupt report).
- **Emulator core**: VBLANK, LSPC timer and IRQ3 interrupts timed as in MAME `neogeo.cpp`.
  Fixed time base: outside an execution slice the core counted the last slice twice, so the
  host's 1 ms clear came up to ~0.6 ms early (outputs of the existing tests unchanged). The
  1 ms clear now lands exactly.
- **Emulator 1.9**: Overview category (ChipCheck first in Run all); the status bar shows
  ChipCheck's progress in % (read from WRAM `$10FFF0`). The real BricoNeo console cannot:
  Brico16Bits shows an output only at the end.
- **MAME bench**: the command is cleared at the first read after 1 ms of machine time, as on
  the real host, instead of one frame later.
- Checks: 33/33 identical to MAME without cartridge; 32/33 with the test cartridge (TestTiming:
  one loop pass, scheduling phase); 25/26 with faults (bench palette alias artifact, see README);
  every emulator fault preset named exactly by ChipCheck; floating-port detection checked on a
  variant reading unmapped addresses (emulator and MAME). `guiverify.py` 174/174.
- Not checked on a real AES: the open-bus behaviour of an undriven port, the 1 ms pickup delay
  (90 cycles assumed), and everything else on real hardware.

## 2026-11-05 - Emulator 1.8: compare with the real console, fault dictionary

- **Compare** tab and `--compare LOG`: reads a PuTTY / Tera Term session log of the BricoNeo
  console (colour codes, CR LF, prompt redraws and backspace corrections handled), replays every
  command in the emulator with the current settings and faults, and compares the outputs command
  by command (`same`, `varies`, `same verdict`, `DIFFERENT`, with a diff).
- **Find the fault** and `--diagnose LOG`: replays the log under each of the 256 single faults the
  core models and ranks them by commands explained; a fault that explains less than a healthy
  console is dropped early. The Z80 setting (cartridge or not) is chosen automatically. **Apply
  to Faults** loads the best candidate. Work runs in a separate process (worker processes for the
  dictionary), so the machine shown in the window keeps its state.
- `--json` for both, used by the window.
- `emulator/make_fake_console_log.py`: test helper that writes the log a real console would give
  (the Brico16Bits console output, reproduced from its source).
- Checks: a simulated log of a console with a dead upper WRAM chip gives 4 different commands
  against a healthy emulator, 18/18 same with that fault, and the dictionary ranks
  `wram:lane:upper` first (the only fault explaining every command). `guiverify.py` 171/171.
- Not checked: worker processes on real Windows (spawn mode); a failure falls back to one process,
  a hang would not.

## 2026-11-05 - Emulator 1.7 (`19f195d`)

Checked against the neogeodev wiki.

- **Watchdog on by default.** Real AES and MVS boards both have the NEO-B1 watchdog: kicked by
  writing `REG_DIPSW` (`$300001`), about 8 frames (3 244 030 mclk), it resets the whole system,
  Z80 included (already modelled). `--no-watchdog` or Settings give the behaviour of MAME's `aes`
  driver, which has none. Settings saved by older versions are migrated to on.
- **Palette RAM byte writes** set both bytes of the word, as on the board (UDS/LDS ignored, the
  68000 puts the byte on both halves of the bus). MAME writes one byte. The ROM tests use words;
  only `WriteB` to the palette differs.
- Consistent with the wiki, nothing to change: colour word layout, line counter range
  `$0F8`-`$1FF`, 68k/Z80 latches and NMI.
- Not modelled: /RESET held low about 200 ms after a watchdog timeout (Charles MacDonald's
  measure, marked unverified on the wiki; MAME does not model it either).
- `build_core.py` reuses clones already at the pinned commits (offline rebuild). The unchanged
  core rebuilt to the same checksums before the change.
- Cores: Windows DLL `70b6c05d…`, Linux `.so` `c97dd30a…`.
- Checks: 32/32 identical to MAME, 15/15 with faults (watchdog off, as MAME `aes`);
  `guiverify.py` 156/156; Windows DLL under Wine (palette byte write gives `$1212`).

## 2026-11-05 - ROM VRAM timing + Emulator 1.6 (`91793a2`)

ROM SHA-256 `79c5fb48de32345ddca940e232949d07d749e641cfa82bb7f3d9754ca6f02075`
(BricoNeo 1.35, 23 extensions), rebuilt from `source/` to the same checksum.

- **ROM: VRAM read too close to the address write.** The LSPC returns valid data 16 CPU cycles
  after `REG_VRAMADDR` is written (neogeodev wiki, "VRAM"). TestVRAML/U and MarchVRAML/U read
  12 cycles after the end of the write (16 start to start). Two `nop` now give a margin either
  way, as jwestfall69's diag BIOS does. Every other VRAM access already had margin. MAME does
  not model the delay, so the output is unchanged there (32/32, 15/15 with faults); only a real
  board can show the difference. MarchVRAML: 1.64 s -> 1.75 s of the 3 s host limit.
- **Emulator 1.6**
  - Console accepts `; comment` and `Delay ms` like the BricoNeo console; **Run script...** and
    `--script FILE` play `bench/real_aes_session.txt`.
  - Any `--option` selects text mode (`--fault help` and `--script` used to open the window).
  - Window position restored only when it is on this screen; tick timer cancelled on close.
  - Core extracted under a checksum name, so a running older window (Windows locks loaded DLLs)
    no longer blocks an update; older cores are removed.
  - Help text no longer points to the removed Faults... dialog.
  - `compare_mame.py` no longer overrides `BRICO_SOUND_ROM` with a local path.
  - `guiverify.py`: 152 checks.

## 2026-11-05 - Real console session (`3763e80`)

- `bench/real_aes_session.txt`: every test, to paste into the BricoNeo serial console.
- `bench/expected_healthy_aes.txt` (cartridge in) and `expected_healthy_aes_no_cartridge.txt`:
  what a healthy console should answer, produced by the emulator.
- README: step-by-step procedure.

## 2026-11-04 - Emulator 1.5: diagnostic dashboard (`ec31bc2`)

- Sidebar with the tests grouped by category, a result badge per test (PASS, FAIL, CHECK, N/A,
  LOOK, INFO, ARMED, RUNNING) and a live screen thumbnail.
- **Run all tests**: memory, video, Z80, audio (4 s wait for the beeps), inputs, TestWatchdog in
  two passes when the watchdog is on, TestDAC last. Stop button.
- Tabs: Report, Console, Screen, Faults (inline, was a dialog), Settings.
- Fixes found while testing: a 68000 exception (stack in a dead WRAM, e.g. TestAudio) is FAIL
  and points to TestWRAM; "Cannot run" is CHECK; Z80 failures with "no program" are marked as
  expected; power on and reset boot 60 frames like `--run`; the report shows RUNNING instead of
  the previous result.
- `guiverify.py`: 141 checks.

## 2026-11-04 - Emulator 1.4: simulated faults (`de0f0ed`)

- Faults... button, or `--fault` in text mode:
  - data bit stuck at 0 or 1: WRAM, palette RAM (also visible on screen), VRAM lower and upper,
    LSPC line counter;
  - address line stuck at 0 or 1: WRAM, palette (bank select included), VRAM;
  - WRAM chip dead (lower or upper byte).
- Typical AES faults as presets; faults kept across power cycles and saved in the settings.
- Example: `python Brico68k_Emulator.py --fault wram:lane:upper --run TestWRAM`
- Checks: 15/15 identical to MAME with the same fault injected; palette bank, VRAM address lines
  and the on-screen effect checked by hand (MAME cannot inject them); 32/32 without fault;
  window 72/72; Windows DLL under Wine.

## 2026-11-03 - Emulator 1.0 to 1.3, Compiler 1.2, ROM (`a06469c` to `c769399`)

- **ROM**: BricoNeo 1.35 from upstream `52c1c92` (1.35 + PlayEyeSnd) with the review merged and
  new tests TestDAC, TestTiming, TestWatchdog, TestZ80. TestCart added then removed:
  23 extensions. SHA-256 `f5db7a23…` (superseded on 2026-11-05).
- **Compiler 1.2**: vasm/vlink built in, English interface.
- **Emulator 1.0**: one `.py`, no MAME and no BricoNeo needed; Musashi 68000, AES model written
  from MAME, Brico16Bits-like host (1 ms clear, 3 s timeout).
- **1.1**: real Z80 running a built-in test M1.
- **1.2**: redesigned window. `guiverify.py` added.
- **1.3**: light theme, clear message when Tkinter is missing.
- Checks: 32/32 identical to MAME with and without a Z80 program; window 59/59; Windows core
  under Wine; reproducible build.

## Still open

- Not tested on a real console or on real Windows.
- PAL timing (312 lines) not verified.
