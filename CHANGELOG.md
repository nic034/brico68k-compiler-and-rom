# Changelog

Newest first. Release notes used to be kept on Google Drive; they now live here only.
Upstream references stay the same unless stated: Aurelien34/Brico68k `52c1c92`,
Aurelien34/Brico16Bits `5859d6b`.

## 2026-11-23 - ROM 1.35-nic034-18: TestGfx by columns (game pictures)

**ROM 1.35-nic034-18** (SHA-256 `511f6466609ed5c20129af07d63915c4bffe0348ef72d3c0438a3f7fc64a3047`, 31 extensions, 92876 bytes free)
- **TestGfx P2 = N (2-64)**: the whole screen by columns, column c showing tiles P1 + c x N
  downwards. Games store their sprites as columns of consecutive tiles, so their characters and
  scenery come out recognisable (TestGfx colours: the game's palettes are in its program). P2 = 1
  (by rows) unchanged. With World Heroes Perfect `TestGfx 0 8 $FF` shows whole characters;
  with Samurai Shodown III (`samsho3`) `TestGfx $10000 8 $FF` shows its characters.
- Checked: rule check (25 runs and `TestGfx $100 16`), regression -17 against -18 (only the new
  report lines of TestGfx, the Version string and dumps of the ROM itself).
- The samsho3 archive received was truncated (no central directory, V2 cut): C1-C8, S1, M1, P
  recovered from the local headers, CRC-32 checked; enough for the graphics.

## 2026-11-23 - ROM 1.35-nic034-17: TestGfxRom, TestSnd, TestGfx P3; Emulator 1.24

Checked with a game set, World Heroes Perfect (`whp`: P1, S1, C1-C8, M1, V1-V3, not encrypted).

**Colour / video tests reviewed**
- **TestGfx**: it fills the fix layer with tile `$20`, "blank in the usual fonts". In whp's S ROM
  tile `$20` is solid colour 2: the fix layer (always above the sprites) covered the whole screen
  and hid every sprite (emulator picture white). New **P3 = fix tile for empty cells** (default
  `$20`); whp needs `$FF`. One more line in the report says so. The labels need an ASCII font at
  `$20-$5F`: whp's is not one, they stay unreadable (the zones are documented in the text).
- **TestDAC**: robust: each band sets the backdrop and palette 0 colours 1-15, so fix tiles of any
  font take the band colour (16 colours per line with and without whp).
- **Color**: robust: every palette entry and the backdrop.

**ROM 1.35-nic034-17** (SHA-256 `bc355868f6b5ee39da97ddc46ac74691f21caebb328d90450142d8aa4c6e0fac`, 31 extensions, 93016 bytes free before `$1FF00`)
- **TestGfxRom** (new, `ExtTestGfx.s`): the game's C ROMs and S ROM through the cartridge port.
  The 68000 has no path back from the CHA / fix buses (nor from the V ROMs or M1): no pass / fail
  is possible, so it is a reference picture. 17 sprites x P2 rows: row r = chip pair r (tile
  r << P1), column 0 the pair's first tile, column c that tile with tile address bit c-1 flipped.
  Below, 2 x 2 fix cells: S ROM tile 0, then tiles `$1-$800` (bits 0-11). Palettes coded per bit
  plane (bit 0 red, 1 green, 2 blue, 3 brighter): a dead data line / plane removes one colour in
  its pair's row; a stuck address line makes its column a copy of column 0. Compare the TV with
  `Brico68k_Emulator.py --cart SET --run TestGfxRom --png ref.png` (same game set). P1 tile bits
  per pair (16: 4 MB chips, whp), P2 pairs (8; whp 4), P3 blank fix tile. Rows past the last pair
  differ by nature (no ROM). The tile-to-pair order is MAME's (C1/C2 first, linear).
- **TestSnd** (new, `ExtTestSnd.s`): the game's M1 / V ROMs through its own driver: Z80 commands
  P1 to P2 (default `$20-$2F`), P3 tenths of a second each (default 15, max 100), after the EOT,
  polling the command block every 0.65 ms; a new command sends `$03` and runs. Listen: a sound
  silent / cut / noisy while the others play = its V ROM area. The codes are the game's (its sound
  test numbers). Checked in the emulator: one code every P3 tenths, `$03` at the end, an Echo sent
  during the sweep stops it and answers. Not heard there (no FM / ADPCM; test M1). The rule check
  caught a first version that waited for the command block to read 0 before accepting a command:
  the loop-mode repeat 20 us after the EOT was lost; now any command is taken (TestSnd's own
  command is cleared 1 ms after it came, its text takes ~3 ms).

**Emulator 1.24**: TestGfxRom (Video, LOOK) and TestSnd (Sound, LOOK) in Run all;
`regress_rom.py` appends `TestGfxRom`, `TestGfxRom 15 2 $FF`, `TestSnd $20 $21 1`;
`bench/real_aes_session.txt` runs both before TestDAC; `guiverify.py` counts 31 extensions, 6 look,
26 compared commands.

**Checks** (emulation only)
- `--test` rule check: 25 runs, no rule broken (CartDiag FAIL: no PROG board, as always).
- Regression -16 against -17, new commands set aside: identical except the TestGfx line and the
  Version string; chaotic scenarios (WRAM stack, floating lines, BIOS socket address faults: the
  console then runs random code, which changes with the code layout).
- `test_chip_hints`, `test_decode`, `test_ext_check`, `test_neo_py`: 0 failures.
  `bench_fuzz.py` seeds 9 and 41: 0 failures over 6724 commands (80 lines under the rule check).
  `guiverify.py` 207/207 (C core, Xvfb).
- README: the 7fc1faf commit (Emulator 1.23) had cut a block of the README by mistake (the
  guiverify line replaced up to the next list item, far below): rebuilt from 681bb38 with every
  change since; nothing else lost (775 lines).

Not done: real AES, MAME. On the AES with whp: `TestGfxRom 16 4 $FF` against the emulator picture,
`TestSnd` (codes to find with the game), `TestGfx 0 0 $FF`.

## 2026-11-23 - Emulator 1.23: the three commands back, GUI check 205/205

ROM unchanged (1.35-nic034-16).
- Version 1.23. Run all now has TestBus (Overview) and CartTest (Cartridge); Version is a tool.
- `compare_mame.py`: Version, TestBus, CartTest, CartTest 1 added to the commands run in MAME
  and the emulator. `compare_mame_faults.py`: the slot data faults run CartTest again (and the
  header dump). Not run here (no MAME).
- `guiverify.py`: CartTest PASS on the test cartridge, slot D3 stuck -> CartTest FAIL naming D3,
  CartTest on a game set, Version shows the fork version, TestBus PASS in Run all. Its counts were
  stale since -12 (25 extensions, "10 pass", 20 compared commands, TestDecode missing from the dead
  WRAM chip log): now 29, 12 pass (11 with the watchdog off), 24, 6 different.
- Checked: `guiverify.py` 205/205 with the C core under Xvfb (python3.12 with Tk). A first run
  with the Python core: 188/205, the known case (diagnosis over its 10 minutes, then the checks
  after it) plus the stale counts.
- Seen: with an unstable BIOS socket line (`bios:float:N`) every read is random, code fetches
  too: the console crashes before TestBus can run (as in -15). A limit of the model.

## 2026-11-23 - ROM 1.35-nic034-16: 128 KB image, Version / CartTest / TestBus back; Compiler 1.7

Aurelien confirmed that the Brico68k ROM limit is 128 KB, not 32 KB. The 32 KB came from header
flag `$0004` (NeoDiag layout), kept since -11 for nothing.

**Checked in Brico16Bits** (`bf426f9`, 2026-11-18): the image is 128 KB (`FLASH_IMAGE_SIZE`),
loaded whole; `NeoDiagImageBuilder` only acts with flag `$0004`, else the image is served as it
is; the output ports are offsets `$1FF00` / `$1FF02` (`DebugLink.cpp`, same mask as `IsHostPort`);
header offsets unchanged; the new 68000 debugger patches only the official SNK BIOS.

**ROM 1.35-nic034-16** (SHA-256 `56eba171004e9586c440a99cebc6b163fa209f19ae41210bd0a778e3e8691791`, 29 extensions, 95332 bytes free before `$1FF00`)
- Flag `$0004` removed (flags `$0003`); linker: code up to `$1FF00` (was `$7FFA`).
- Calls between files are absolute (`JsrA6`, `PrintText`, 34 `jmp EOT_AND_WAIT/WAIT_FOR_COMMAND/
  DISPATCH_COMMAND/RAM_SUITE`): a PC-relative jump only reaches +/-32 KB (vlink stops with
  "doesn't fit into 16 bits", checked). 2 bytes and 4 cycles per call.
- **Version** back (as in -09; upstream base now `1b72deb`).
- **CartTest** back (game cartridge P bus, read only), unchanged; shares nothing but EOT_AND_WAIT.
- **TestBus** back, redesigned (no NeoDiag copies any more):
  - Command: CRC-32 of each 32 KB quarter (command block `$90-$9F` and the table's data as zeros,
    quarter 3 up to `$1FEFF`: the ports are never read) against `BUS_TABLE`, filled by the
    Compiler; then the A15/A16 probes. 0.92 s (byte table, 1 KB blocks by `dbra`, watchdog
    between blocks; a first version took 1.14 s).
  - Boot (`busCheck`, 4 reads, < 1 ms): the Compiler picks an offset where the four quarters
    differ and stores each quarter's long word there. A quarter read as another = A15 / A16
    stuck at 0. Then the output ports (A15 = A16 = 1) are out of reach and no text can come
    back, so the screen shows the 16 bands of the old TestBus (A1 at the top, the bad line red)
    until a command. Checked: A15 / A16 stuck at 0 give band 15 / 16 red.
  - Not covered any more: A15 / A16 stuck at 1 (quarter 0 unreadable: no boot) - the old
    TestBus booted on a NeoDiag copy and named it. A1-A14 / D0-D15 cut: no boot, as before.
  - `Brico68k.ld` puts the header, Tools, Trace, Screen, TestBus and Echo in the first 32 KB.
  - Checked on altered images: a byte changed in quarter 2, at `$1FEFF` and at `$A0` -> that
    quarter FAILs.

**Compiler 1.7**
- Without flag `$0004`: checks that the code ends before `$1FF00` and prints the free space.
- Image with TestBus (`BUSCRC32` found once, in the first 32 KB): each quarter padded with its
  own byte (`$FF`, `$FE`, `$FD`, `$FC`), CRC-32 of each quarter and the probe written into
  `BUS_TABLE`. Other images: plain `$FF` padding, as before.

**Emulator, tests, bench**
- TestBus (Overview), CartTest (Cartridge), Version (Tools) back in the lists; Find the fault's
  BIOS socket message points to the boot screen.
- `regress_rom.py`: Version, TestBus, CartTest, CartTest 1 appended to the healthy list,
  TestBus in the line / BIOS socket scenarios, CartTest under every slot fault (570 scenarios,
  2509 commands).
- `test_ext_check.py`: no longer widens the 32 KB linker length (the fixture fits).
- `bench_fuzz.py`: a WRAM fault under a command that uses the stack (TestAudio, TestChip IRQs,
  TestWatchdog) is undefined (a corrupted return address), not a failure.
- `bench/real_aes_session.txt`: Version, TestBus, CartTest; expected outputs regenerated.

**Checks** (emulation only: no real AES, no MAME)
- Regression -15 against -16 (C test core), the new commands set aside: every other command
  answers word for word as before, except 6 measured watchdog counts, 6 `Dump $C0...` (the ROM
  itself), and the scenarios that are chaotic by nature: in each, the first difference is
  TestAudio / TestWatchdog under a WRAM fault (stack) or CartDiag on a floating slot line.
  Example: with `wram:data:3:0 wram:data:11:1`, TestAudio's corrupted return now loops in its
  delay routine (kicking the watchdog: no reset) where -15 hit an exception.
- `--test` rule check: 23 runs, no rule broken. `test_chip_hints`, `test_decode`,
  `test_ext_check`, `test_neo_py` (lockstep): 0 failures.
- `bench_fuzz.py`, seeds 5, 7, 23, 41: 0 failures over about 14000 commands, about 800 fault
  sequences, 200 random lines under the rule check.

Not done: real AES, MAME, guiverify (no Tk). On the real AES: `Version`, `TestBus` (expect 4 x OK,
about 1 s), `CartTest` with a game.

## 2026-11-18 - ROM 1.35-nic034-15: Read / Dump spare the BricoNeo ports, TestChip survives a dead IRQ acknowledge; bug-hunt and unexpected-input benches

**ROM 1.35-nic034-15** (SHA-256 `8dcd66e4c2f2240032dd022eb6006244a61dded0acdde137abb564bc61bad69a`, 26 extensions,
4134 bytes free before `$7FFA`, was 4324)
- **Read / Dump**: reading the BricoNeo output ports is no longer possible by accident. Any read at
  socket offset `$1FF00` is an EOT for the BricoNeo and `$1FF02` arms an output word (Brico16Bits
  watches A1-A16, so in `$C00000-$CFFFFF` and every 128 KB mirror). `Read $C1FF00` ended the command
  before its value (0 words), and `Dump $C1FF00 n` ended it at once while the 68000 kept sending: the
  rest of the dump went into the next command's answer. Both now send `$0000` for those two words
  without reading them (new macro `IsHostPort`, 36 bytes). Found by the new bench.
- **TestChip**: with an LSPC2 register fault on D0-D2 (`lspc:sel:4..16:1` in the emulator: the
  registers do not answer at `$3C0000`), the write to `REG_IRQACK` is lost, the level 3 interrupt
  pending since reset is never acknowledged, and the IRQ test aborted TestChip with an exception
  (vector 24-31) before the Z80, NEO-D0 and verdict lines. When VRAMMOD read-back shows D0, D1 or D2
  bad, the two IRQ lines now say `SKIP    LSPC2 D0-D2 bad: no IRQ acknowledge` and the report
  goes to its end (`=> Test failure: ... LSPC2 ...`). 154 bytes. Other faults on VRAMMOD bits keep
  the IRQ test. Not verified on a real console: the pending level 3 after reset is from the wiki
  (68k interrupts) and the emulator's model of it.
- Regression -14 against -15 (C test core, 474 scenarios, 2281 commands, every modelled fault, 10
  input sets): 13 differences, all TestChip under `lspc:sel:N:1` (the exception replaced by the full
  report); 3 measured TestWatchdog loop counts move by one (code moved). Nothing else.
  `bench/expected_healthy_aes.txt` unchanged; `expected_healthy_aes_no_cartridge.txt`: only the
  watchdog loop count.
- `test_chip_hints.py`, `test_decode.py`, `test_ext_check.py`, `test_neo_py.py` (lockstep): 0 failures.
  `--test` (rule check of every extension): no rule broken.

**New bench: `emulator/test/bench_fuzz.py`** (bug hunt and unexpected input)
- Every command with extreme and random P1-P3 (0, 1, $FFFF, $FFFFFFFF, odd addresses, RAM mirrors,
  unmapped space, I/O, BIOS socket, counts over the buffer), random sequences, and random sequences
  under 1-3 random faults. Checked after each command: EOT or exception report, never the 3 s
  timeout (except a user write into the stack / vectors / I/O, TestWatchdog, BIOS socket faults);
  at most 2047 words; result fits its type; `Echo` right after returns its value.
- On -14: the two Read / Dump failures above, nothing else. On -15: 0 failures over 3774 + 3094
  commands (seeds 7 and 23) including about 350 fault sequences, and 120 random lines under the
  Brico16Bits rule check.

**Unexpected input to the tools** (no code change needed)
- Emulator: empty, short, oversize, zeroed, corrupted ROMs; missing files and folders; damaged
  logs for `--compare` (truncated, garbled lines, holes, CRLF, BOM, binary, UTF-16, unknown
  commands); 13 malformed `--fault` specs; bad cartridges, cartridge list, PNG path: every case
  gives a readable message and an exit code, no Python traceback. Parameters are parsed like
  Brico16Bits (`Read $zz` reads address 0, `Echo 99999999999999999999` gives `$FFFF`).
  Known: a script `Delay 99999999` really waits that long in emulated time (about 28 h).
- Compiler: syntax error, unknown symbol, missing include / linker script / main source, empty
  source file, code over `$7FFA`, CRLF, UTF-8 and Latin-1 comments, paths with spaces: every error
  names the file and line, no traceback; the good ones build byte-identical ROMs.

**Speed**: nothing new to gain without changing the design (see Compiler 1.6 entry). Dump is
about 50 cycles per word slower (the port check): 2045 words take 0.1 ms more.

Not run: real AES, MAME (`compare_mame.py`), guiverify (no Tk).

## 2026-11-17 - Compiler 1.6, test fix: review of the Compiler and the Emulator, ROM unchanged (1.35-nic034-14)

Review only, no new feature. ROM rebuilt by the Compiler: byte-identical
(SHA-256 `cf4af7837a2a1e56b32f93f467ae9f149e0ab1fb1fb88043a592190b2139afd3`), every Brico16Bits check OK.

**Compiler 1.6**
- The `.tar.gz` fallback for the vasm / vlink sources (`sun.hasenbraten.de`, plain http) was
  unpacked with no filter: an altered archive could write outside the work folder (`../`,
  absolute paths, links). Now `filter="data"` (Python 3.12+ and the 3.8-3.11 security releases);
  on an older Python every entry is checked first and the archive refused if one points outside.
  Checked: a normal archive unpacks, one with `../escape.txt` is refused. Only used on systems with
  no embedded vasm / vlink (macOS...) when the GitHub zip and git both fail. Zip archives were
  already safe (`zipfile` drops `..` and absolute paths).

**Emulator** (no code change, version stays 1.22)
- `emulator/test/test_m68k_py.py` looked for the Musashi sources in `build/src` only, which
  `build_core.py` makes; `build_test_core.py`, named in its docstring, makes `build/src_test`, so
  after that one the test stopped with a gcc error. It now takes either, or says what to run.

**Checks**
- `test_m68k_py.py`: 20000 cases, 0 mismatches against Musashi, 1703/1704 handlers covered.
- `test_neo_py.py` (Python core lockstep with the C core), `test_chip_hints.py`,
  `test_decode.py`, `test_ext_check.py`: 0 failures. `package_emulator.py` rebuilds
  `Brico68k_Emulator.py` byte for byte. pyflakes on both tools: nothing.
- Speed: inlining the hot bus paths of the Python core (watchdog kick, VRAM write, `now()`) was
  tried and measured: no gain beyond noise (TestVRAM + TestWRAM 1.63-1.72 s CPU against
  1.52-1.65 s), so it was not kept. The Python core runs about 2 M 68000 instructions per second
  (TestVRAM: 1.47 s emulated in 1.2 s); a real speed-up would need a different design (block
  translation), not touch-ups. Not run: full `regress_rom.py` (nothing in the cores changed), real
  AES, MAME, guiverify (no Tk).

## 2026-11-17 - ROM 1.35-nic034-14: TestDecode, chip references; Emulator 1.22: decoding faults

**ROM 1.35-nic034-14** (SHA-256 `cf4af7837a2a1e56b32f93f467ae9f149e0ab1fb1fb88043a592190b2139afd3`, 26 extensions,
4324 bytes free before `$7FFA`, was 6250: TestDecode 854 bytes, the chip references about 1 KB)
- **TestDecode** (new, `source/ExtTestDecode.s`, 854 bytes with its table entry): address decoding,
  the one thing the March tests cannot see (they walk the lines the chips are wired to, A1-A15 for
  WRAM and A1-A12 for a palette bank, never A16 and up). For each line n of the mirrors of WRAM
  (A16-A19, `$100000-$1FFFFF`), palette RAM (A13-A21, `$400000-$7FFFFF`) and the LSPC registers
  (A4-A16, `$3C0000-$3DFFFF`), a word written at the base must read back at base + 2^n and the
  other way round: `FAIL: not a mirror on A17` names the line. A base word that holds no value is
  "the word itself is bad" (a RAM fault: TestWRAM, TestPRAM, TestLSPC). Then a WRAM word and a
  palette word sharing A1-A12 are written in both orders: neither may change the other (a decoder
  output selecting two chips). Words are saved and put back, no WRAM, no stack, 2 ms,
  `=> Test success` / `=> Test failure` like the other tests.
- Code: a table of three regions walked by one loop, two shared routines (`aliasTest`, `verdict`).
- **Chip references** (TestWRAM, TestPRAM, TestVRAM, TestDecode), from the Board-Folk NeoGeoAES-3.5
  schematic (read pin by pin and checked on the rendered PDF; valid for the AES 3-3, 3-5 and 3-6
  according to Nic034, 3-4 not confirmed): `Chip : lower chip (D0-D7) = AES U1` (WRAM U1/U2, palette
  U7 (PC0-7) / U6 (PC8-15), slow VRAM U17 (E0-7) / U18 (E8-15), fast VRAM U19 (F0-7) / U20 (F8-15),
  none for the MVS backup RAM). Hints: the shared D bus for a WRAM data bit, NEO-G0 / 74LS273 for a
  palette bit, the LSPC2 as the only driver of the VRAM address pins, NEO-B1 for the palette address,
  the WRAM write strobe as the wiki names it (NEO-C1 U4 WWU/WWL; RAWU/RAWL on the schematic). TestDecode prints one
  hint line per failing group (e.g. NEO-C1 U4 sees A17-A23, not A16; the LSPC2 sees only A1-A3).
  Checked against the wiki too (NEO-G0 is a quad 245; NEO-E0 makes A22'/A23'). Not proven (README):
  the bit pairing inside NEO-G0 (D0-D7 = PC0-7), E0/F0 = VRAM data bit 0.
- **Not verified on a real console, nor in MAME**: the ranges are those of the wiki's NEO-C1 page
  (WRAM `$100000-$1FFFFF`, palette `$400000-$7FFFFF`, LSPC `$3C0000-$3DFFFF`) and its decode mask
  `$FE0001` for the LSPC (the wiki says its masks are not verified); the emulator models them after
  MAME's `neogeo` address map (not re-read from MAME's source here). A healthy AES that reports a mirror means a wrong assumption.
  `emulator/compare_mame.py` now runs TestDecode in MAME for that.
- Regression -12 against -14 (474 scenarios, 2281 commands, every modelled fault, 10 input sets, C test
  core): 238 differences, every one a text line added by the chip references (Chip / Hint lines of
  TestWRAM, TestPRAM, TestVRAM), none elsewhere; chaotic scenarios (WRAM stack faults, socket faults)
  counted apart. `test_chip_hints.py` (15 cases) and `test_decode.py` (hint lines per group): 0 failures.

**Emulator 1.22** (pure Python core and C core)
- New decoding faults, `wram:sel:LINE:0|1` (A16-A19), `pal:sel:LINE:0|1` (A13-A21),
  `lspc:sel:LINE:0|1` (A4-A16): the decoder uses an address line it should ignore, the chip answers
  only when the line is at that level (open bus elsewhere, writes lost); `wram:leak`: WRAM writes
  also land in the palette RAM cell with the same A1-A12. 53 new faults, 343 in the dictionary for
  Find the fault (the README said 288; the count was 290). Appended at the end of the list: the
  ranking of the earlier candidates does not change. Faults tab: "LSPC registers (decoding)",
  "Decoder uses a line", "Writes also reach palette". `--fault help` lists them.
- `emulator/test/test_decode.py` (new): TestDecode under all 53, at both levels, and under RAM
  faults (data bit, dead chip, stuck address line): each gives the expected line and no other.
- Lockstep `test_neo_py.py`: 4 sequences with the new faults, 0 failures. `regress_rom.py` runs
  TestDecode in every healthy scenario and in the WRAM, palette and LSPC fault scenarios.
- `bench/real_aes_session.txt` runs TestDecode after TestLSPC; `bench/expected_healthy_aes*.txt`
  regenerated (only TestDecode and the measured loops / auto-animation timings move).
- Python core regression against the C core: 474 scenarios, 2281 commands, 0 differences (10 chaotic scenarios set apart: random unstable lines or a crashed 68000, not word-for-word between the two runs).
- Bug hunt on -14 (simulation only): output invariants over 393 recorded outputs (max 624 words, under the
  2047 limit), 300 random fault combinations, 25 combinations compared between the two cores: 0 violations,
  0 differences. Known gap: a palette bank-independence failure prints the chip line but no hint
  (the PALBNK latch, 74HC259 U35 Q7, is the likely culprit).
- Not run: real AES, MAME, guiverify (no Tk), Find the fault on injected-fault logs (too slow on the shared machine). The bench's MAME fault probes (`BRICO_STUCK`,
  `BRICO_ALIAS`) are shadow stores: they cannot inject a decoding fault, so only the healthy
  console is compared with MAME (`compare_mame.py`).

## 2026-11-16 - Emulator 1.21, Compiler 1.5: faster, ROM unchanged (1.35-nic034-12)

**Emulator 1.21** (pure Python core; the C core is unchanged)
- **About 1.7 times faster**: 88-102 frames/s idle instead of 46-57 (Python 3.11-3.13, same
  machine), 68-79 instead of 49-56 during TestWRAM / TestVRAM; real time is 59.2.
  - Opcode and extension word fetches from the BIOS socket read a word table (`FW`) instead of
    calling the bus, while nothing has to see those reads (`FAST`: host port not armed, no
    BIOS socket fault, no rule-check hook). The table is kept equal to the BIOS (ROM load, command
    block written / cleared by the host). Other faults keep the fast path (`--diagnose`).
  - Watchdog kick (`move.b d0,$300001`) handled first in the byte write; VRAM read / write without
    the fault lookups when no fault is set.
  - Start-up: the test cartridge (3 MB) and the PROG board SRAM (1 MB) are generated in 0.1 s
    instead of 1.5 s, same bytes (`getrandbits(32 n)` packs the same Mersenne Twister outputs).
- Checks: lockstep Python vs C core (`test_neo_py.py`): 0 failures; full regression on the
  Python core (`CORE=python regress_rom.py`, 421 scenarios, every fault, input sets, rule-check
  hook off) compared with the C test core: 0 differences (5 chaotic scenarios differ, the known
  C worker reuse issue); same outputs as 1.20 on TestWRAM / TestVRAM / TestChip. guiverify not run
  (no Tk on the machine).

**Compiler 1.5** (ROM byte-identical: SHA-256 `c70bdf08...2071`)
- Sources assembled in parallel (one vasm per file, up to 8 at once); link order and log order
  unchanged. Mostly felt on Windows, where each vasm start is slow.
- The vasm / vlink self-test runs once per session for unchanged tools, not at every build.
- Fork version check again: since 1.35-nic034-10 the version is not in the image, so the
  Compiler now reads `FORK_VERSION` from `inc/define.inc` and checks the header announces its base
  ("Header version 1.35 = base of the fork version 1.35-nic034-12").
- `urllib` imported only when something is downloaded (faster start).

## 2026-11-16 - ROM 1.35-nic034-12: smaller and faster extensions, same outputs

**ROM 1.35-nic034-12** (SHA-256 `c70bdf08f01f2bda43a370f9ae73735d08fd906c1136c112c5126526ac732071`, 25 extensions)
- **Same outputs**: regression -11 against -12 (421 scenarios, 1721 commands, every modelled
  fault, 10 input sets, C test core): **0 differences**. Only the measured TestWatchdog loop
  count moves by a few loops (it depends on the print time, as before).
- **Code**: 27774 -> 26384 bytes; **6250 bytes free** before `$7FFA` (was 4860).
  - `PrintText` (define.inc): consecutive Print / PrintLn calls merged into one (44 calls, 8
    bytes each).
  - `Delay reg,cycles` (define.inc): `lsl.l #n,reg` = 8 + 2n cycles in 2 bytes, only an opcode
    prefetch on the bus; replaces the Nop4 / Nop6 / Nop8 VRAM waits where d0 is free
    (TestVRAM, TestChip, TestLSPC; same cycle counts).
  - Tools.s: `printBitList` (" D3 D12" / " A19" lists), `printMismatch` / `printMismatchL`
    (Address / Expected / Read / Bad bits block of TestWRAM-BRAM-PRAM, CartDiag's RAM part and
    TestVRAM), `printFlagNames` (TestChip verdict and floating ports), `printLong` (8 hex digits).
  - TestZ80 and TestChip share the sound driver handshake (`z80Handshake`, `z80Quiet` in
    ExtTestZ80.s): same loops, same timing, same classification. TestZ80 prints the reset reply
    after the handshake instead of in the middle (same text).
  - TestTiming: the mid-frame wait is a routine instead of a macro expanded 3 times.
  - TestChip reads the four NEO-C1 ports in the reverse order (SOUND first) so the bit order fits
    the name table; same result.
- **Speed** (emulated, healthy AES): TestVRAM 1.77 -> 1.47 s, TestWRAM / TestBRAM 0.42 -> 0.38 s,
  CartDiag 0.43 -> 0.38 s, TestPRAM 0.16 -> 0.15 s. TestVRAM is no longer flagged by the rule
  check (it was the only finding: 1.77 s of the 3 s).
  - TestVRAM March: LSPC2 registers and watchdog through address registers, 8 words per loop,
    92 cycles per word of a read/write element instead of 114. VRAM gaps, worst case whatever
    the bus order inside each MOVE: address -> read 24 cycles, data write -> new address 24,
    data write -> data write 20 (wiki: 16 / 16 / 12, so >= 8 cycles of margin kept). The read ->
    write gap (no rule in the wiki) is 20 cycles (was 36).
  - RAM March (WRAM, BRAM, PRAM, CartDiag SRAM): short branches to a local exit, watchdog
    through a0, background written as longs (any order is allowed in M0).
  - Unchanged on purpose: the Z80 waits (2 x 130 ms in TestZ80 / TestChip, the driver reset
    time), the cycle-counted loops of TestTiming / TestChip / TestWatchdog (their results are
    calibrated on them), upstream TestAudio / TestFM / TestSsg (only two Print calls of TestAudio
    merged).
  - TestTiming's duration depends on the auto-animation phase left by the previous commands
    (up to 64 frames of wait, as before): from the same start it takes exactly as long as -11.
- Not run: real console, MAME (none on the machine), guiverify (no Tk on the machine). Run:
  regression (above), `--test` rule check (every extension clean; CartDiag on the PROG board
  clean), `emulator/test/test_ext_check.py` (12 cases + real ROM: 0 failures), a TestChip run
  with P2 and SOUND forced to open bus (floating-ports path, not in the regression): identical
  to -11. The VRAM timing margins are by cycle count only.
- Tests updated: guiverify and test_ext_check no longer expect the TestVRAM finding; bench
  expected outputs regenerated (only the emulated times and the watchdog loop count change).

## 2026-11-11 - ROM 1.35-nic034-11: TestBus removed

**ROM 1.35-nic034-11** (SHA-256 `cbcfdd2422d8e303c5a59752b1cb1d295600bb65c8e505c569e5f05b68060fcb`, 25 extensions)
- **TestBus removed**, with its check at boot (A15/A16 by the NeoDiag copy numbers). Nothing
  tests the BIOS socket lines any more. Its screen helpers, used by TestDAC and TestGfx, moved to
  `source/Screen.s` (`busBand` renamed `screenBand`).
- Texts that named TestBus: TestGfx "TestDAC clears the screen.", TestVectors "or the BIOS socket".
- Header flag `$0004` (NeoDiag layout) kept; it no longer serves a test.
- 4860 bytes free before `$7FFA`.
- Upstream: nothing newer than `1b72deb` (checked); TestFM and TestSsg are in since -10.
- Checks: regression -09 against -11 (421 scenarios): differences only in TestFM / TestSsg (new)
  and the two text lines above. Lockstep 0 differences, guiverify 199/199, rule check: only the
  known TestVRAM 1.77 s. `emulator/compare_mame_bus.py` removed. Not run on a real console nor in
  MAME.

## 2026-11-11 - ROM 1.35-nic034-10: upstream TestFM / TestSsg, CartTest and Version removed

**ROM 1.35-nic034-10** (SHA-256 `66d9e05f8284eb950b3859462facdecfa16dd5fdbd05e82b73f81ac7abd80ce0`, 26 extensions)
- Upstream `5643191` / `1b72deb` (Aurelien34, 2026-11-08) brought in: **PlayEyeSnd renamed
  TestFM** (same code: Z80 command `$02`, FM1-FM4) and **TestSsg** added (Z80 command `$7F`, coin
  chime: timer A, SSG A-C, noise; upstream code as is). On an AES the cartridge M1 decides what
  `$7F` plays; upstream describes the MVS SM1.
- **CartTest removed** (game cartridge P bus, read only). CartDiag (PROG board) stays, now in
  `source/ExtCartDiag.s` with the routines it uses (OE_DEAD, OE_HOLD245).
- **Version removed**: the fork version is no longer in the image (FORK_VERSION stays in
  `inc/define.inc` for the build tools); the SHA-256 identifies a build.
- Code space in the NeoDiag layout: 3158 bytes free (was 18).
- Checks: regression -09 against -10, 421 scenarios (the CartTest-only cartridge-fault scenarios
  dropped): every output identical except TestFM and TestSsg, unknown to -09. Rule check
  (`--test`): TestFM and TestSsg clean; the known TestBus and TestVRAM findings unchanged.
  Not run on a real console, nor in MAME.

**Emulator** (same 1.20)
- Test M1: command `$7F` plays a two-note chime on the SSG (1984 Hz then 1563 Hz, ~0.14 s),
  in the Python and C cores and the MAME bench cartridge; TestSsg is LOOK ("listen") in Run all.
- Test lists (Run all, guiverify 202/202, lockstep, regression, MAME scripts, the real-console
  session and its expected outputs) follow the new extension list.

## 2026-11-11 - Emulator 1.20: testing new extensions (rule check), one test table

**Emulator 1.20** (ROM unchanged: 1.35-nic034-09)
- `--test [COMMAND ...]`: runs the tests (all, as Run all, or the given command lines) with their
  verdict and a check against the Brico16Bits rules, on the Python core; exit code 1 on a FAIL.
  The window's **Check rules** button runs it in a separate process and fills the badges and
  reports. What is checked: output with interrupts enabled or from code outside the ROM, P1-P3
  read after the 1 ms clear, no EOT or several, output after the EOT, more than 2047 words, a
  result that does not fit the declared type, over 1.5 s, a watchdog reset, the command block not
  polled after the EOT, and a loop-mode repeat (`*Command`) sent 20 us after the EOT being missed.
- Python core: `neo_watch` hook (off by default; on, the emulation is unchanged: lockstep test
  and an on/off comparison give identical results). The C core has no hook.
- One `TESTS` table in `emulator_main.py` replaces the separate category, LOOK, "varies" and
  Run-all lists (same Run all plan and badges as 1.19, checked). A new extension needs no entry.
- `emulator/test/test_ext_check.py` + `ExtCheckBad.s`: a fixture extension breaking one rule per
  P1 (12 cases); each finding fires.
- Found on the ROM (not changed here): **TestBus misses a command sent within ~2.7 ms of its EOT**
  (screen cleared before the polling starts; `*TestBus` loop mode times out), and TestVRAM takes
  1.77 s of the 3 s. Only 18 bytes of code space are left in the NeoDiag layout.
- Brico68k Compiler: prints the free code space before `$7FFA` when the NeoDiag flag is set.
- TestAudio's PASS text no longer says the beeps are not emulated (they are since 1.19).

## 2026-11-11 - Emulator 1.19: sound (YM2610 SSG tones)

**Emulator 1.19** (ROM unchanged: 1.35-nic034-09)
- The built-in test M1 now programs the YM2610 SSG for the sound commands: `$5C` / `$5D` / `$5E`
  (TestAudio) give a 1000 / 1506 / 749 Hz tone until the next command, `$02` (PlayEyeSnd) a short
  jingle, `$03` silences before the reset. `$01` / `$03` replies and timings are unchanged
  (regress_rom.py, C core, old vs new: 0 differences).
- The cores (C and Python) latch the SSG registers the Z80 writes (ports `$04` / `$05`), new API
  `neo_ssg_regs`; the Python Z80 gains the opcodes of the jingle (ld b/d, djnz, dec d, jr nz).
- The window plays the tones (winsound on Windows, paplay / pw-play / aplay / afplay elsewhere;
  Settings > Sound), shows them in the status bar (`♪ 1000 Hz`) and notes them in the console.
  A tone is heard only if the Z80 took the NMI, read the command and wrote the sound chip.
- PlayEyeSnd runs in "Run all tests" (LOOK: listen) instead of N/A.
- Not emulated: FM, ADPCM, SSG noise and envelopes, panning (the beeps are mono). The MAME bench
  cartridge (`tools/make_test_cart.py`) has the same M1; not re-run in MAME this time.
- Checks: test_neo_py.py lockstep Python vs C (SSG registers included), 0 differences;
  guiverify 193/193 (C core); tones checked by measuring the generated WAV frequencies; the
  speaker output itself could not be heard here (no audio device on the test machine).

## 2026-11-11 - Emulator 1.18: status lamps, screen preview in the console

**Emulator 1.18** (ROM unchanged: 1.35-nic034-09)
- Status bar: the lamps are coloured pills with white text when on (green / orange / red) and
  pale grey with a hollow dot when off; the small coloured dot was hard to read.
- Console tab: a screen preview at the top right (click: Screen tab).
- Screen tab: says so when the cartridge has no tiles. Without a cartridge (the default), TestGfx
  gives a black screen: the fix layer and the sprites come from the cartridge's S and C ROMs, as
  on a real AES; the test cartridge (Cartridge tab) shows the test screen. Its stale "sprites and
  fix layer are not drawn" text is corrected.
- Power on / Reset: busy cursor and a status message during the 1 to 3 s of core build and boot
  (the window looked frozen).

## 2026-11-11 - Emulator 1.17: pure Python, no DLL

**Emulator 1.17** (ROM unchanged: 1.35-nic034-09)
- `Brico68k_Emulator.py` is now pure Python: no embedded DLL / shared library, nothing extracted,
  works on any OS with Python 3.8+ (checked with 3.8, 3.11, 3.12, 3.13). The file shrinks from
  750 KB to 250 KB.
- New `emulator/m68k_py.py`: a line-for-line Python port of the Musashi 68000 as the C core built
  it (address error, trace, RESET, interrupts with Musashi's auto-clear, STOP, halt on a double
  fault). Its decode and cycle tables (`emulator/m68k_tables.py`) are generated from Musashi itself
  by `emulator/build_m68k_tables.py`. New `emulator/neo_py.py`: the port of `neocore.c` (same API)
  and of the part of the superzazu/z80 Z80 the model's programs use.
- Checked: `emulator/test/test_m68k_py.py` runs the Python 68000 and the C Musashi side by side on
  random code (all 1704 handlers, user / supervisor, trace, interrupts, odd addresses, STOP):
  cycles, registers and the ordered list of bus accesses, 1 million cases, 0 differences.
  `emulator/test/test_neo_py.py` runs the Python and C AES models in lockstep (commands, reset
  button, Z80 options, cartridges, faults, test inputs): 0 differences.
  `emulator/regress_rom.py` with `CORE=python` against the C core: 517 scenarios, 1937 commands,
  0 differences. `guiverify.py`: 191/191 with the C core, 187/191 with the Python core (the 4
  misses are the diagnosis step, too slow for its 10 minute limit).
- Speed: about real time (53 to 60 frames/s for 59.2 with Python 3.11 to 3.13, 38 with 3.8, one
  cloud x86 core). `--diagnose` takes hours with the Python core instead of minutes: use the C
  core for it.
- The C core is optional: a `neocore.dll` / `libneocore.so` next to the script (or
  `BRICO68K_CORE=path`) is used instead, for speed. The window's first line names the core.
- Tests: `regress_rom.py` takes `CORE=python` (inputs scenarios included, the Python core has the
  test input hook); the MAME comparison scripts use the Python core by default.

## 2026-11-11 - Emulator 1.16 draws the tile layers; fork 1.35-nic034-09

**Emulator 1.16**
- The screen now shows the fix layer and the sprites, drawn from VRAM over the backdrop lines, so
  TestGfx is visible. Tiles: the cartridge's S and C ROMs when the set has them, generated tiles
  for the built-in test cartridge, none without a cartridge. Not a game renderer: vertical shrink
  approximated (no L0 ROM), no auto-animation. Redrawn when VRAM, the palette or the cartridge
  change, not while a command runs.
- New fault: the vector table switch held on the system ROM or on the cartridge
  (`vec:stuck:bios`, `vec:stuck:cart`; Faults tab: "Vector table switch"). It is in the fault
  dictionary of `--diagnose` (290 single faults).
- `--png FILE` saves the screen after `--run` / `--script`.
- Built-in test cartridge: vectors like a game's (SP `$10F300`, reset `$C00402`, exceptions to the
  system ROM entry points) instead of random words, and tile numbers wrap at the chip sizes.
- Core: `neo_get_vram`, `neo_get_palette`, fault region 7. Both cores rebuilt with zig 0.17.1.

**ROM 1.35-nic034-09**, SHA-256 `24d124f2d880572c5f2368fd58b8f847af23d95862884979068cea4b39871684`, 18 bytes under `$7FFA`
- The screen clear shared by TestDAC, TestBus and TestGfx also puts sprite 0 off screen (x = 380).
  Found with MAME: it draws sprite 0 in the unused sprite slots of each line even with a height of
  0, so TestGfx had a white column 1 pixel wide at x = 0. Whether a real LSPC does the same is not
  known; SNK's system ROM parks every sprite at that x.

**Tools**: `tools/make_test_cart.py` gives the MAME bench cartridge the same tiles and vectors as
the emulator's; new `emulator/compare_mame_gfx.py` (TestGfx in MAME against the emulator's drawing,
pixel by pixel); `emulator/regress_rom.py` records the picture too, has the vector faults, and
clears the faults before each power-on (a worker kept the previous scenario's fault while
starting the next one; it only mattered for a fault that acts at power-on, which the vector
switch is the first to be); the test-only core no longer needs its own latch and VRAM functions.

**Found, not fixed**: with the vector table switch held on the cartridge at power-on and a game
inserted, this ROM does not start (the cartridge's reset vector is `$C00402`, an entry of SNK's
system ROM; Brico68k has text there). `INITIAL_PC_ORG equ $402` exists upstream but is not used.
A jump to the start at `$C00402` would let the ROM start in that case and report the fault; it
needs the layout around `$400` moved, and room (18 bytes left).

Checks:
- MAME 0.264 (installed for this session; L0 ROM = a generated table, see compare_mame_gfx.py):
  44/44 commands identical without a cartridge, 44/44 with the test cartridge (TestVectors and
  TestGfx included), 27/28 with injected faults (the known palette difference), and the three
  TestGfx screens identical pixel for pixel (0 of 71680).
- ROM -08 against -09, 517 scenarios, 1937 commands: 15 differences, all intended (3 Version,
  12 TestGfx VRAM checksums: sprite 0's x; the drawn picture is the same). Two runs of -09: 0.
- New core against the previous one, same ROM: identical on every scenario.
- `guiverify.py` (Tk under Xvfb): 191/191, with new checks for the tile layers on both screens
  and for the vector fault from the Faults form.

Not checked: real hardware; a real game ROM set's tiles (none here: the S and C decoders were
checked by a round trip on the generated tiles and through MAME); the real L0 ROM; Windows (the
DLL is cross-built, not run); `build.py` and CMake.

## 2026-11-10 - TestGfx: whole-screen mode (fork 1.35-nic034-08)

ROM SHA-256 `7c63dc6c5c539ca9797273d82b7c944d532bafde45d73438d142e945c3ecbf92` (fork **1.35-nic034-08**, header 1.35, 27 extensions). The code ends
30 bytes under `$7FFA`: the ROM is full.

- `TestGfx <tile> 1` (P2 = 1): 20 sprites of 14 tiles cover the 320 x 224 screen, tile = P1 +
  column + 20 x row, no label. The test zones only cover parts of the screen; a fault that depends
  on the position (line buffer bit, a column of pixels) shows wherever it is.
- The sprite writes are one routine (`gfxSprite`) for both modes; the report is shorter.

Why this and not an animation or a colour gradient: an AES ROM in the BIOS socket has no tile of
its own, so it cannot draw shapes; a still, full screen is easier to read for a fault than moving
sprites, and a gradient would repeat TestDAC.

Checks, emulator only: -07 against -08 over 517 scenarios: only the TestGfx text and Version
differ; in the zones mode the VRAM and palette words are identical to -07 (same checksum). The
whole-screen mode was checked on its VRAM words and on a picture drawn from them with synthetic
tiles. Not run on real hardware.

## 2026-11-10 - TestChip (renamed), TestVectors, TestGfx (fork 1.35-nic034-07)

ROM SHA-256 `99e0853f9716f851e1957617119a31332e43a3b0c348b722f24ef6554e0dd8f4` (fork **1.35-nic034-07**, header 1.35, 27 extensions), built with the
Compiler. The code ends 150 bytes under `$7FFA`.

- **ChipCheck is renamed TestChip**: same test, same output. Emulator, bench session, tools and
  README follow (source file `ExtTestChip.s`).
- **TestVectors** (new): the vector table switch `$000000-$00007F`, system ROM / cartridge
  (`REG_SWPBIOS` / `REG_SWPROM`, system latch Q1). Read only, no WRAM, 3 ms.
- **TestGfx** (new): test screen for the fix layer and the sprites with the cartridge tiles, first
  C tile = P1: labels, fix tiles `$00-$FF`, flips, 8 x 4 tiles, H and V shrink. No WRAM, 11 ms; the
  screen stays. VRAM writes keep the wiki "VRAM" rules (new address 16 cycles after a data write,
  12 between data writes) with at least 8 cycles of margin.

Brico16Bits: its source was read again at `84f7840` (2026-11-09) for both commands. Parameters
read first, one EOT, output through the port only with interrupts masked, at most 461 words (ring
of 2048), nothing runs after the EOT, exceptions through the common `EXCPT` report as every other
extension. The port watcher compares the 16 address pins of each ROM access with the port
(`$1FF02`) and the EOT trigger (`$1FF00`): the reads TestVectors adds (`$000000-$00007F`,
`$C00000-$C0007F`) never match them. Upstream's only change since `5859d6b` (byte-swap detection)
does not affect this ROM. Names up to 15 characters and descriptions up to 300 are respected.

Checks, emulator only:
- 1.35-nic034-06 against -07, 517 scenarios, 1926 commands (test core): 27 differences, all
  intended (24 runs of the two new commands, 3 Version). Every other output is identical word for
  word, TestChip included; durations unchanged.
- TestVectors with latch Q1 held at 0 and at 1 (new `neo_test_latch` in the test core), without a
  cartridge, with the test cartridge and with the PROG board: failure named in each case.
- TestGfx: the core draws no tile, so the check is on the VRAM and palette words (checksum in
  `regress_rom.py`, new `neo_test_vram`), and on a picture drawn from them with synthetic tiles.
  TestDAC after it leaves no sprite and no fix tile.

Not checked: real hardware (TestGfx is a screen: only a console can judge it), MAME (not
installed in this session), `guiverify.py` (no Tk here; its expected badges are updated),
`build.py` and CMake (local firmware repository).

## 2026-11-10 - First run on a real AES (fork 1.35-nic034-06)

No ROM change. Nicolas ran 1.35-nic034-06 on a real AES: reported working, and CartDiag passes on
the jwestfall69 PROG board. First real-hardware validation of this ROM, and of the size review of
2026-11-07. Not done yet: a console log compared word for word with
`bench/expected_healthy_aes.txt`, and a board with a known fault.

## 2026-11-07 - Code review: 1884 bytes freed, same outputs (fork 1.35-nic034-06)

ROM SHA-256 `01b128ee3fb64ebe246d98ac2a58d6c0f315236e8349fa9b2f794019d29fa99b` (fork
**1.35-nic034-06**, header 1.35, 25 extensions), built with the Compiler.

Code 32094 -> 30210 bytes: it now ends **2552 bytes** under `$7FFA` (NeoDiag layout limit).
Correction: the previous entry gave 712 bytes for 1.35-nic034-05; it was 668 (code end `$7D5E`).

What changed, every output kept word for word unless listed below:
- One end of command, `EOT_AND_WAIT` in Brico68k.s (EOT, then the command loop):
  `jmp EOT_AND_WAIT(pc)` replaces `WriteEOT` + `jmp WAIT_FOR_COMMAND` (4 bytes instead of 12).
- Jumps to `WAIT_FOR_COMMAND`, `DISPATCH_COMMAND`, `RAM_SUITE` and `BUS_SCREEN` from other files
  are PC-relative (4 bytes instead of 6), as `JsrA6` already was: the code is under 32 KB.
- A line feed printed alone next to another print joins it: `PrintLn ""` + `Print "x"` is now
  `NlPrint "x"` (new `NlPrint` / `NlPrintLn` macros), `Print "x"` + `PrintLn ""` is `PrintLn "x"`.
- Exception report: its six port writes are called (`PortWriteD0`) instead of inlined.
- TestInp, TestStatusA, TestSystype: shared `printBits` / `printButtons` (Tools.s, replacing
  `getButtonStateStr`) and a `PrintBit` macro; the P1 and P2 button labels are stored once; the
  memory card, write protect and hardware mode prefixes are printed once. The ports are read at
  the same points as before.
- TestDAC uses the TestBus screen routines (`screenBlank`, `busBand`, `bandColour`): same VRAM and
  palette writes; the band colour is now computed before the line wait, so it is written 12 CPU
  cycles earlier, still during the line before the band.
- TestLSPC: the 4 VRAMMOD patterns in one loop. TestVRAM: a no-op instruction removed.

Output changes:
- ChipCheck: the VRAM hints said "Next: MarchVRAML" / "MarchVRAMU", commands that TestVRAM
  replaced: they now say "Next: TestVRAM".
- Version: 1.35-nic034-06.

Left alone on purpose: every loop whose timing matters (VRAM access margins of TestVRAM and
ChipCheck, the cycle-counting loops of TestTiming and ChipCheck, the CartDiag prefetch and bus hold
tests, the TestWatchdog starve loop) and Trace.s (upstream). Durations are unchanged (TestInp -4 %,
TestStatusA -3 %). TestVRAM stays the longest, 1.77 s of the host's 3 s, set by those margins.

New tools: `emulator/regress_rom.py` (record every scenario with one ROM, then compare two ROMs)
and `emulator/build_test_core.py` (test-only core with settable input ports and an MVS backup RAM,
never packaged in the emulator).

Checks: old ROM against new ROM, 511 scenarios, 1890 commands, with the test core: 119
differences, all intended (116 ChipCheck VRAM hint lines, 3 Version). TestWatchdog counts a few
loops less (44572 -> 44562, 133 ms both). Not compared, chaotic by construction: BIOS socket A1-A14
stuck or any socket line unstable (the 68000 reads its own code wrong) and, with a WRAM fault, the
commands from TestAudio on (stack in the bad WRAM); what happens there depends on where each code
byte is, and 5 of them already differ between two runs of the same ROM. Compiler image checks OK;
bench logs regenerated.

Not checked here: MAME (not installed in this session), `guiverify.py` (no Tk), `build.py` and
CMake (in the local firmware repository), real hardware.

## 2026-11-07 - Two commands: CartTest and CartDiag (fork 1.35-nic034-05, Emulator 1.15)

ROM SHA-256 `26f517773add88740cce238eebbe3421dc6b037ec505d8091d33a118b95dceb4` (fork
**1.35-nic034-05**, header 1.35, **25** extensions), the same checksum from the Compiler,
`build.py` and CMake.

- **CartTest** (game cartridge) never writes any more: the automatic PROG board probe is gone. On a
  cartridge without a header it prints "diag PROG board: use CartDiag". Run in the emulator on
  the test cartridge, no cartridge and the PROG board: 0 cartridge writes each time.
- **CartDiag** (new): the p-bus test (diag cart) on the PROG board, started directly. It writes:
  on a game cartridge it would latch banks (words written in P2), so it is for the PROG board only.
  Checked: on the test cartridge it writes 4 times and fails, which is the expected misuse.
- Code ends 712 bytes under `$7FFA`.
- Emulator 1.15: CartDiag in the Cartridge category, `compare_mame_faults.py` and `guiverify.py`
  call it for the PROG board; 184 GUI checks, bench logs regenerated.

Checks: 38/38 identical to MAME with the test cartridge and 38/38 without; faults 24/25 and 27/28
(the known palette artifact); TestBus screen 7/7; GUI 184/184. The PROG board itself has not run it.

## 2026-11-07 - CartCRC removed (fork 1.35-nic034-04, Emulator 1.14)

ROM SHA-256 `fb0bf47b507c6160f3e4cc0c9a3b857dbcc1cb6c57f70926c09b55901372c995` (fork
**1.35-nic034-04**, header 1.35, **24** extensions), the same checksum from the Compiler,
`build.py` and CMake.

- ROM: the **CartCRC** extension is gone (`ExtCartCRC.s`, its declaration, the WRAM tables). CartTest,
  with the p-bus test (diag cart), is untouched. The code now ends 728 bytes under `$7FFA`
  (it was 4); the texts shortened for the previous release were not restored.
- Emulator 1.14: `--crc-plan` and the CartCRC plan shown in the Cartridge tab are gone, with
  their code. What stays: the cartridge loading, identification by CRC32 against the official
  MAME list and the per-chip check (OK, BAD CRC, MISSING).
- `compare_mame.py` runs 38 commands; `guiverify.py` 184 checks; bench logs regenerated.

Checks: 38/38 identical to MAME with the test cartridge and 38/38 without; faults 24/25 and
27/28 (the known palette artifact); TestBus screen 7/7; GUI 184/184.

## 2026-11-06 - p-bus test (diag cart): output enable tests (fork 1.35-nic034-03, Emulator 1.13)

ROM SHA-256 `1f8ad9602bfef06a5f003f5942c4deae6bce68e7eb2b5220e4727240457d6ec0` (fork
**1.35-nic034-03**, header 1.35, 25 extensions), rebuilt from `source/` to the same checksum with
the Compiler, `build.py` and CMake. The code is 32758 bytes, 4 under the `$7FFA` limit: the next
addition needs room first.

ROM:
- CartTest on the jwestfall69 diagnostic PROG board, now named **"p-bus test (diag cart)"** on
  the console, with the board's address (<https://github.com/jwestfall69/neogeo-diag-aes-prog>).
- Two tests added before the RAM suite, after the method of the diag BIOS P bus tests (own code,
  that repository has no licence): **output enable (prefetch)** (a byte read three times, each
  followed by another opcode, compared with that opcode's byte on the same lane; dead if all
  agree, 50 rounds) and **output behind a 245 (bus hold)** (`$5555` at +4 and `$AAAA` at +8, each
  followed by a read at +0 under the lane mask; dead only if it gives back both). P1 D0-D7,
  P1 D8-D15, P2 D0-D7, P2 D8-D15, in the BIOS order. This was the gap of the previous release:
  a dead /ROMOE or /PORTOE was only seen by the P1 read-back, and a dead /PORTOE not at all.
- Texts shortened elsewhere to make room (ChipCheck hints, extension descriptions, BRAM and
  SYSTYPE / STATUS_A headings): no test changed.

Emulator 1.13:
- Slot faults `cart:strobe:portoel`, `portoeu` (P2 output enable) and the `...245` variants
  (`romoel245`, `romoeu245`, `portoel245`, `portoeu245`): without a 245 a dead output enable
  gives the word the 68000 prefetched; behind a 245 it gives the last value written to the
  cartridge side (P1 writes included). Before, a dead /ROMOE read as `$FF` (floating high),
  which the new test would not have seen.
- `guiverify.py`: the PROG board checks follow the new output; the "log matches with the fault
  applied" check skips TestAudio (it needs the stack in WRAM, so with a dead WRAM chip the 68000
  runs wild and what it prints depends on the timing of the host's reads; it matched before by
  luck of timing, I did not prove it).
- `bench/expected_healthy_aes*.txt` regenerated.

Checks: all ten strobe faults run on the PROG board and found by the right test, window and
lane, healthy board passes; 46/46 identical to MAME with the test cartridge and 46/46 without;
faults 24/25 and 27/28 (the known palette artifact); TestBus screen 7/7; GUI 187/187.

Not validated: the PROG board has not run this ROM; MAME models neither the prefetched word nor
the bus hold, so these two tests are checked against the BIOS's assumption in the emulator only.
The BIOS's LOWER/UPPER labels look inverted from the 68000 lanes; not confirmed.

## 2026-11-06 - CartTest, CartCRC, cartridges in the emulator (fork 1.35-nic034-02, Emulator 1.12)

ROM SHA-256 `2f39023ed427e36035236b03480a176a152720d0120a56d10a82e07f0e2d1c55` (fork
**1.35-nic034-02**, header 1.35, 25 extensions), rebuilt from `source/` to the same checksum with
the Compiler and `build.py`.

ROM:
- **CartTest**: cartridge P bus D0-D15. On a game cartridge, read only: P1 checked against the
  61-word security code (each line judged both ways: stuck at 0, stuck at 1, wrong in some words),
  found even when bad lines corrupt its pointer (pointer with up to two bits flipped); P1 and P2
  activity; a verdict that tells slot/console from cartridge. On the jwestfall69 diagnostic PROG
  board (SRAM): the TestWRAM suite on `$200000` (D0-D15, both byte lanes, A1-A19, March C-) and
  a P1 (/ROMOE) read-back. The board probe tolerates bad lines and a dead strobe, and on a game
  cartridge can at most latch bank 0 (D0-D2 = 0).
- **CartCRC**: CRC32 of P ROM in the byte order of the MAME files, 256 KB per command, continued
  with `P3 = -1` / `-2` (CRC kept in WRAM, with its complement), the P2 bank in P1 bits 24-26,
  and the cartridge's vector table selected while reading `$000000-$00007F`. Tables in 4 KB of
  WRAM, verified. Emulator `--crc-plan GAME --cart-list hash/neogeo.xml`: the console script
  (set name, clones, or NGH number), and with `--cart` the plan is run and compared.
- RAM suite: region type 3 (cartridge P bus); the address-line flags are tested as a long (a
  `tst.w` would have missed A16-A19: found when MAME and the emulator both passed a stuck A19);
  "All bits: address line A1?" when every bit of a walking-test word is wrong.
- `Print`: the string follows the call (one shared print routine, 10 bytes per Print instead of
  18), `jmp` to the helpers is PC-relative. That freed the room for the two extensions; the code
  is now 14 bytes under `$7FFA`. `moveq #0,d0` on return, which exposed and fixed a ChipCheck
  display bug (pixel ratio fraction lost its leading zero).
- Every extension description rewritten, shorter and accurate (TestWRAM and ChipCheck said
  things the code no longer does).

Emulator 1.12:
- Cartridge choice in Settings (one at a time, changing it power-cycles) and `--cart`: none,
  built-in test cartridge, a game ROM set (folder or MAME zip) or the PROG board. P1/P2 on the
  68000 bus with the P2 bank latch of the wiki; S, C, V, M1 loaded with size and CRC32; with the
  official MAME list (`--cart-list`, `hash/neogeo.xml`) the set is identified, loaded with the
  list's layout, every chip checked, and the CartCRC plan of each P file shown.
- Slot faults: `cart:data`, `cart:float`, `cart:addr` (A1-A19), `cart:strobe` (PORTWEL, PORTWEU,
  ROMOEL, ROMOEU), in the Faults tab too. Lamp for the cartridge.
- The unstable-line form no longer shows level 1 instead of "random".

Bench: the test cartridge has a game header and the security code, and declares
`<feature name="slot" value="rom"/>` (without it MAME 0.264 reads `$FFFF` at `$000100-$000103`).
`compare_mame.py` runs 46 commands (CartTest, CartCRC with its continuation added); `compare_mame_faults.py` adds slot
data faults and the PROG board (the bench's shadow RAM plays it). `real_aes_session.txt` runs
CartTest.

Checks: 46/46 identical to MAME with the test cartridge and 46/46 without; faults 24/25 and 27/28 (known palette artifact); TestBus screen 7/7; GUI 191/191; Compiler, build.py and CMake give the same ROM.

## 2026-11-06 - The ROM is named ROM.BIO, Compiler 1.4

ROM SHA-256 `7f88cd8d6ac9916a30caf1c635ceb52559ecdf91e6cfb4bca39369bff54be5b8` (unchanged content,
fork 1.35-nic034-01).

- The built ROM is now `ROM.BIO` (the BricoNeo drive accepts `.BIN`, `.BIO` and `.ROM`):
  `rom/ROM.BIO` (+ `.sha256`), the Compiler output and its "Copy ROM.BIO" button, `build.py`
  and CMake (`build/rom/ROM.BIO`). The Emulator opens `rom/ROM.BIO` by default and still finds
  an older `Brico68k.bin`.

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
