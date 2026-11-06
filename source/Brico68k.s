; https://wiki.neogeodev.org/index.php?title=68k_memory_map
; Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
; C:\Users\Aurelien\AppData\Local\Microsoft\WindowsApps>winget install GnuWin32.Make
; Base address: 0xc00000

; External screen
; PIO trace swap KO => potentially fixed
; BRAM backup and switch
; Pas d'erreur sur commande inconnue?
; Commande RESET RP2040>68000

	include "inc/define.inc"
	include "inc/trace.inc"

	section vectors,data

	dc.l	RAM_RESERVED_SYS_ROM	; 0  initial SSP (same value as the SNK BIOS)
	dc.l	START				; 1  initial PC
	; Every exception used to point to address 0: an odd address passed to
	; Read/Write/Dump (address error), or any real CPU fault caused by bad
	; hardware, made the 68000 run garbage and the firmware never answered
	; again until a reset (confirmed in MAME: every later command timed
	; out). Each vector now reports the exception to the BricoNeo console
	; and goes back to the command loop.
	dc.l	EXC_BUS_ERROR		; 2
	dc.l	EXC_ADDRESS_ERROR	; 3
	dc.l	EXC_ILLEGAL			; 4
	dc.l	EXC_ZERO_DIVIDE		; 5
	dc.l	EXC_CHK				; 6
	dc.l	EXC_TRAPV			; 7
	dc.l	EXC_PRIVILEGE		; 8
	dc.l	TRACE				; 9  trace: BricoNeo step debugger (Trace.s, upstream 1.35)
	dc.l	EXC_LINE_A			; 10
	dc.l	EXC_LINE_F			; 11
	dc.l	EXC_OTHER			; 12 (reserved)
	dc.l	EXC_OTHER			; 13 (reserved)
	dc.l	EXC_OTHER			; 14 (format error, 68010+)
	dc.l	EXC_OTHER			; 15 uninitialized interrupt
	dc.l	EXC_OTHER			; 16 (reserved)
	dc.l	EXC_OTHER			; 17 (reserved)
	dc.l	EXC_OTHER			; 18 (reserved)
	dc.l	EXC_OTHER			; 19 (reserved)
	dc.l	EXC_OTHER			; 20 (reserved)
	dc.l	EXC_OTHER			; 21 (reserved)
	dc.l	EXC_OTHER			; 22 (reserved)
	dc.l	EXC_OTHER			; 23 (reserved)
	dc.l	EXC_INTERRUPT		; 24 spurious interrupt
	dc.l	IRQ1_HANDLER		; 25 level 1 (VBLANK) - masked (SR=$2700) except during ChipCheck
	dc.l	IRQ2_HANDLER		; 26 level 2 (timer) - masked except during ChipCheck
	dc.l	EXC_INTERRUPT		; 27 level 3 - masked
	dc.l	EXC_INTERRUPT		; 28 level 4 - masked
	dc.l	EXC_INTERRUPT		; 29 level 5 - masked
	dc.l	EXC_INTERRUPT		; 30 level 6 - masked
	dc.l	EXC_INTERRUPT		; 31 level 7 (NMI, not wired on Neo Geo)

	; Could be used by extension functions
	global BRICO_COMMAND_IN
	global BRICO_COMMAND_PARAM_1
	global BRICO_COMMAND_PARAM_2
	global BRICO_COMMAND_PARAM_3
	; Used to return after the execution of a extension function
	global  WAIT_FOR_COMMAND
	; Entry for extensions that keep running until the next command arrives
	; (e.g. TestDAC): jump here with d0 = a non-zero BRICO_COMMAND_IN read
	global  DISPATCH_COMMAND
	; Unexpected interrupt report, also used by the ChipCheck IRQ handlers
	global  EXC_INTERRUPT

	section	text,code

	; Magic word - 8 bytes
	dc.b "BricoNeo"
	; Version - 4 bytes
	BRICONEO_VERSION 1,35			; upstream base; the fork version is only in the Version command
	; Special modes
	dc.w BRICO_SPECIAL_FLAG_ENABLE_EXTENSIONS + BRICO_SPECIAL_FLAG_68K_SENDS_COMMANDS + BRICO_SPECIAL_FLAG_NEODIAG_MIRRORS

JUMP_TO_COMMAND:
	dc.w $4ef9 ; jmp opcode, in order to jump directly to the following address
BRICO_COMMAND_IN:
	dc.l $0000 ; Address of the next extension to be launched - 4 bytes set by the BricoNeo card at runtime
BRICO_COMMAND_PARAM_1:
	dc.l $0000 ; Address the extension parameters - 3 times 4 bytes set by the BricoNeo card at runtime
BRICO_COMMAND_PARAM_2:
	dc.l $0000
BRICO_COMMAND_PARAM_3:
	dc.l $0000

EXTENSIONS_TABLE:
	; Available extensions list. Ends with address $ffffffff
	DECLARE_EXTENSION EXT_ECHO, 			BRICO_EXT_OUTPUT_TYPE_WORD,		"Echo",				"Echo test. Place value to be returned in P1 (no WRAM used)"
	DECLARE_EXTENSION EXT_READ, 			BRICO_EXT_OUTPUT_TYPE_WORD,		"Read",				"Read word at address P1. Odd address: reads the byte (e.g. $320001). (no WRAM used)"
	DECLARE_EXTENSION EXT_WRITE, 			BRICO_EXT_OUTPUT_TYPE_VOID,		"Write",			"Write word P1 at address P2. Odd address: writes the low byte of P1. (no WRAM used)"
	DECLARE_EXTENSION EXT_WRITE_B, 			BRICO_EXT_OUTPUT_TYPE_VOID,		"WriteB",			"Write the low byte of P1 at address P2, even or odd (no WRAM used)"
	DECLARE_EXTENSION EXT_MEMDUMP, 			BRICO_EXT_OUTPUT_TYPE_DUMP,		"Dump",				"Memory dump. Start address in P1 (forced even), word count in P2, at most 2045 (BricoNeo buffer: 2048 words). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_INPUTS,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestInp",			"Inputs tests, NEO-F0 / NEO-C1 (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_AUDIO,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestAudio",		"Audio test (UniBIOS-like): Z80 handshake, then left, right and center beeps, ~1 s each; a new command stops them. Uses WRAM (stack)."
	DECLARE_EXTENSION EXT_EYE_SND,			BRICO_EXT_OUTPUT_TYPE_VOID,		"PlayEyeSnd",		"Plays the eyecatcher music (Z80 sound command $02: SM1 driver on MVS, cartridge M1 on AES)"
	DECLARE_EXTENSION EXT_TEST_WRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWRAM",			"Work RAM test: data bus walking 1/0, 0000/FFFF/AAAA/5555, increment (address lines). On error: address, expected, read, bad bits, byte (D0-D7/D8-D15). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_BRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestBRAM",			"MVS Backup RAM test, same tests as TestWRAM. DESTRUCTIVE: erases bookkeeping/settings. N/A on AES (no backup RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_PRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestPRAM",			"Palette RAM test on BOTH banks (same tests as TestWRAM) + bank 0/1 independence (bank select line). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_VRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestVRAM",		"All VRAM, slow and fast: data bus walking 1/0, each address line (A0-A14 / A0-A10), March C- $5555/$AAAA on every word; names the bad bits and the chip (upper/lower byte). $8600-$86FF (sprite lists) skipped. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_LSPC,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestLSPC",			"LSPC2-A2 chip test: VRAMMOD write/readback, VRAMADD+VRAMRW round-trip, VRAM auto-inc. (no WRAM used)"
	DECLARE_EXTENSION EXT_COLOR,			BRICO_EXT_OUTPUT_TYPE_VOID,		"Color",			"Fill the screen using only palette RAM with the given color value, in NeoGeo color format. Red is $CF00, Green is $20F0, Blue is $900F, White is $7FFF, Black is $8000. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_STATUSA,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestStatusA",		"STATUS_A breakdown, AES/MVS-aware: coin 1/2, service button, RTC bits on MVS; N/A messages on AES (bit layout per MAME neogeo.cpp). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_Z80,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestZ80",			"Z80 handshake without WRAM: 03 reset, 01 request, needs 16 stable fresh 01 replies; flags a latch echo. STOPS SOUND. Needs a standard SM1/M1 driver. A timeout does not prove the Z80 is dead. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_DAC,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestDAC",			"RGB DAC test pattern: 16 bands, one colour bit each (R4..R0, G4..G0, B4..B0, white), shown until the next command. P1=1: dark bit set. P1=$10+n: full screen band n (n=0..15), for scope/multimeter. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_TIMING,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestTiming",		"Video timing: LSPC line counter alive, +1 steps (stuck bit), $F8-$1FF range, lines per frame, NTSC/PAL bit, auto-animation counter, CPU cycles per frame. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_WATCHDOG,	BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWatchdog",		"Watchdog: 1st run stops kicking it (expect a reset in ~0.13 s on MVS), run again to read the result and time. Uses WRAM $10FFE0. Not emulated by MAME on AES."
	DECLARE_EXTENSION EXT_CHIP_CHECK,		BRICO_EXT_OUTPUT_TYPE_STRING,	"ChipCheck",		"Quick state of the board, one line per part (< 1 s): WRAM, palette RAM, VRAM slow/fast, LSPC2 registers, NEO-C1 ports, VBLANK/timer IRQ, Z80, NEO-D0 clocks (68KCLK vs the BricoNeo 1 ms, 24 MHz, 6 MHz). IRQs use WRAM (stack)."
	DECLARE_EXTENSION EXT_TEST_SYSTYPE,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestSystype",		"SYSTYPE breakdown, AES/MVS-aware: TEST button, JAMMA sense on MVS; unmapped/open-bus on AES (bit layout per MAME neogeo.cpp). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_BUS,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestBus",			"BIOS socket, 68000 -> BricoNeo, as NeoDiag: A15/A16 from the mirror bytes, A1-A14/D0-D15 by CRC32. Text + 16 screen bands (A1 at the top) until the next command. Also run at boot. (no WRAM used)"
	; Version: written by hand (not DECLARE_EXTENSION) so that the description
	; takes the fork version from FORK_VERSION, its only definition
	dc.l EXT_VERSION
	dc.w BRICO_EXT_OUTPUT_TYPE_STRING
	dc.b "Version",0
	align 1
	dc.b "Fork version "
	FORK_VERSION
	dc.b ": Nic034 fork of Aurelien34/Brico68k 1.35 (the header keeps 1.35). Prints it with its source. (no WRAM used)",0
	align 1
	dc.l $ffffffff ; No more extensions

START:
	move #$2700,sr					; Supervisor mode + all interrupts disabled
	WatchDog 						; kick watchdog
	move.w	#7,(REG_IRQACK).l 		; ack all IRQs
	move.w  #$4000,(REG_LSPCMODE).l ; stop animations
	lea RAM_RESERVED_SYS_ROM,sp		; Set stack pointer to BIOS_WORKRAM
	DisableInterrupts 				; Interrupts are disabled by default
	; BIOS socket A15/A16 (TestBus mirror bytes, no WRAM, < 1 ms): on a fault,
	; show it on screen at once - with A15/A16 stuck at 1 the command block
	; read lands in a mirror and no command can ever arrive. No mirror
	; layout (d4 bit 2): nothing shown here, TestBus says it.
	JsrA6 busCheck
	tst.l d5
	beq.s WAIT_FOR_COMMAND
	jmp BUS_SCREEN

WAIT_FOR_COMMAND:
	; Wait for the command to be 0 again
	DisableInterrupts ; Interrupts are disabled in extensions by default as the work RAM might not work
.loop_wait_for_no_command:
	WatchDog
	move.l (BRICO_COMMAND_IN).l,d0	; move sets Z: no separate cmp needed
	bne.s .loop_wait_for_no_command

.loop_wait_for_command:
	WatchDog
	; Read command number from the BricoNeo port
	move.l (BRICO_COMMAND_IN).l,d0
	beq.s .loop_wait_for_command

DISPATCH_COMMAND:
	; As upstream: jump through the header jmp, which reads the command
	; address again from the BricoNeo. No retry here: the BricoNeo writes
	; the address in one 32-bit store and keeps it 1 ms, it is the one in
	; charge (a torn read was an artefact of the MAME test host).
	; There will be no RTS as we are not sure the work RAM is working
	jmp JUMP_TO_COMMAND

; ---------------------------------------------------------------------------
; 68000 exception handlers. The exception is reported to the BricoNeo as a
; 68k command (BricoExt "68k sends commands" channel, flag $0002): the
; 5-letter name EXCPT, then one word each: vector number, SR, PC high, PC
; low, access address high, access address low (bus/address errors only,
; else 0), then EOT. The BricoNeo shows it to the user (Brico16Bits
; Command68kException; during an extension, CommandExtension hands it over
; instead of printing it as the extension output).
; SR/PC come from the exception frame the CPU pushed in WRAM: if WRAM is the
; faulty part they may be wrong, the vector number is always right.
; No stack used, no RTE: SP is reset and the 68000 goes back to the command
; loop, ready for the next command.
; d7 = vector number.
; ---------------------------------------------------------------------------
EXC_BUS_ERROR:
	moveq #2,d7
	bra.s EXC_COMMON
EXC_ADDRESS_ERROR:
	moveq #3,d7
	bra.s EXC_COMMON
EXC_ILLEGAL:
	moveq #4,d7
	bra.s EXC_COMMON
EXC_ZERO_DIVIDE:
	moveq #5,d7
	bra.s EXC_COMMON
EXC_CHK:
	moveq #6,d7
	bra.s EXC_COMMON
EXC_TRAPV:
	moveq #7,d7
	bra.s EXC_COMMON
EXC_PRIVILEGE:
	moveq #8,d7
	bra.s EXC_COMMON
EXC_LINE_A:
	moveq #10,d7
	bra.s EXC_COMMON
EXC_LINE_F:
	moveq #11,d7
	bra.s EXC_COMMON
EXC_INTERRUPT:
	moveq #24,d7				; vectors 24-31 share this handler
	bra.s EXC_COMMON
EXC_OTHER:
	moveq #-1,d7				; reserved vectors: $FFFF

EXC_COMMON:
	move #$2700,sr
	WatchDog
	movea.l sp,a2				; exception frame
	moveq #0,d6					; access address (bus/address error only)
	cmp.w #3,d7
	bhi.s .short
	tst.w d7
	bmi.s .short
	move.l 2(a2),d6				; group 0: status word, address, IR, SR, PC
	addq.l #8,a2
.short:
	move.w (a2),d5				; SR
	move.l 2(a2),d4				; PC
	lea RAM_RESERVED_SYS_ROM,sp
	lea EXC_CMD(pc),a1
	PrintA1						; "EXCPT", one word per letter
	move.w d7,d0
	InlinePortWriteD0
	move.w d5,d0
	InlinePortWriteD0
	move.l d4,d0
	swap d0
	InlinePortWriteD0
	move.w d4,d0
	InlinePortWriteD0
	move.l d6,d0
	swap d0
	InlinePortWriteD0
	move.w d6,d0
	InlinePortWriteD0
	WriteEOT
	jmp WAIT_FOR_COMMAND

EXC_CMD:	dc.b "EXCPT",0
	even
