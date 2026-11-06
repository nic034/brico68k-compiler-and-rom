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
	BRICONEO_VERSION 1,35
	; Special modes
	dc.w BRICO_SPECIAL_FLAG_ENABLE_EXTENSIONS + BRICO_SPECIAL_FLAG_68K_SENDS_COMMANDS

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
	DECLARE_EXTENSION EXT_MEMDUMP, 			BRICO_EXT_OUTPUT_TYPE_DUMP,		"Dump",				"Memory dump. Start address in P1 (forced even), word count in P2. The host buffer holds ~2000 words. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_INPUTS,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestInp",			"Inputs tests, NEO-F0 / NEO-C1 (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_AUDIO,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestAudio",		"Audio test (UniBIOS-like): Z80 handshake, then left, right and center beeps, ~1 s each. Wait ~4 s before the next command. Uses WRAM (stack)."
	DECLARE_EXTENSION EXT_EYE_SND,			BRICO_EXT_OUTPUT_TYPE_VOID,		"PlayEyeSnd",		"Plays the eyecatcher music (Z80 sound command $02: SM1 driver on MVS, cartridge M1 on AES)"
	DECLARE_EXTENSION EXT_TEST_WRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWRAM",			"Work RAM test: data bus walking 1/0, 0000/FFFF/AAAA/5555, increment (address lines). On error: address, expected, read, bad bits, byte (D0-D7/D8-D15). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_BRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestBRAM",			"MVS Backup RAM test, same tests as TestWRAM. DESTRUCTIVE: erases bookkeeping/settings. N/A on AES (no backup RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_PRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestPRAM",			"Palette RAM test on BOTH banks (same tests as TestWRAM) + bank 0/1 independence (bank select line). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_VRAM_LOWER,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestVRAML",		"Video RAM test (lower / slow RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_VRAM_UPPER,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestVRAMU",		"Video RAM test (upper / fast RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_MARCH_VRAM_LOWER,	BRICO_EXT_OUTPUT_TYPE_STRING,	"MarchVRAML",		"March-C VRAM test (lower / slow RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_MARCH_VRAM_UPPER,	BRICO_EXT_OUTPUT_TYPE_STRING,	"MarchVRAMU",		"March-C VRAM test (upper / fast RAM). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_LSPC,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestLSPC",			"LSPC2-A2 chip test: VRAMMOD write/readback, VRAMADD+VRAMRW round-trip, VRAM auto-inc. (no WRAM used)"
	DECLARE_EXTENSION EXT_COLOR,			BRICO_EXT_OUTPUT_TYPE_VOID,		"Color",			"Fill the screen using only palette RAM with the given color value, in NeoGeo color format. Red is $CF00, Green is $20F0, Blue is $900F, White is $7FFF, Black is $8000. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_STATUSA,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestStatusA",		"STATUS_A breakdown, AES/MVS-aware: coin 1/2, service button, RTC bits on MVS; N/A messages on AES (bit layout per MAME neogeo.cpp). (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_Z80,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestZ80",			"Z80 handshake without WRAM: 03 reset, 01 request, needs 16 stable fresh 01 replies; flags a latch echo. STOPS SOUND. Needs a standard SM1/M1 driver. A timeout does not prove the Z80 is dead. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_DAC,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestDAC",			"RGB DAC test pattern: 16 bands, one colour bit each (R4..R0, G4..G0, B4..B0, white), shown until the next command. P1=1: dark bit set. P1=$10+n: full screen band n (n=0..15), for scope/multimeter. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_TIMING,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestTiming",		"Video timing: LSPC line counter alive, +1 steps (stuck bit), $F8-$1FF range, lines per frame, NTSC/PAL bit, auto-animation counter, CPU cycles per frame. (no WRAM used)"
	DECLARE_EXTENSION EXT_TEST_WATCHDOG,	BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWatchdog",		"Watchdog: 1st run stops kicking it (expect a reset in ~0.13 s on MVS), run again to read the result and time. Uses WRAM $10FFE0. Not emulated by MAME on AES."
	DECLARE_EXTENSION EXT_CHIP_CHECK,		BRICO_EXT_OUTPUT_TYPE_STRING,	"ChipCheck",		"Quick state of the board, one line per part (< 1 s): WRAM, palette RAM, VRAM slow/fast, LSPC2 registers, NEO-C1 ports, VBLANK/timer IRQ, Z80, NEO-D0 clocks (68KCLK vs the BricoNeo 1 ms, 24 MHz, 6 MHz). IRQs use WRAM (stack)."
	DECLARE_EXTENSION EXT_TEST_SYSTYPE,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestSystype",		"SYSTYPE breakdown, AES/MVS-aware: TEST button, JAMMA sense on MVS; unmapped/open-bus on AES (bit layout per MAME neogeo.cpp). (no WRAM used)"
	dc.l $ffffffff ; No more extensions

START:
	move #$2700,sr					; Supervisor mode + all interrupts disabled
	WatchDog 						; kick watchdog
	move.w	#7,(REG_IRQACK).l 		; ack all IRQs
	move.w  #$4000,(REG_LSPCMODE).l ; stop animations
	lea RAM_RESERVED_SYS_ROM,sp		; Set stack pointer to BIOS_WORKRAM
	DisableInterrupts 				; Interrupts are disabled by default

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
	; A move.l from ROM is TWO 16-bit bus reads. If the host writes the
	; command between them, d0 is torn (e.g. $0000084A instead of
	; $00C0084A - seen in MAME with a simulated host, 1 command out of
	; ~6). Re-read until two consecutive reads agree, then jump through
	; the register with that stable value. This also never depends on
	; BRICO_COMMAND_IN still being set when we jump (the host clears it
	; 1 ms after launch, Brico16Bits CommandExtension.cpp).
	; JUMP_TO_COMMAND stays in the header unchanged (BricoExt layout).
.stable:
	move.l d0,d1
	move.l (BRICO_COMMAND_IN).l,d0
	cmp.l d0,d1
	bne.s .stable
	tst.l d0						; cleared by the host meanwhile: wait again
	beq WAIT_FOR_COMMAND
	; There will be no RTS as we are not sure the work RAM is working
	movea.l d0,a0
	jmp (a0)

; ---------------------------------------------------------------------------
; 68000 exception handlers. They never use the stack (WRAM may be the faulty
; part), never return with RTE: they reset SP, print which exception hit,
; send EOT so the host doesn't wait for its 3 s timeout, and go back to the
; command loop. The CPU itself still pushes its exception frame below SP
; (WRAM): harmless even if WRAM is broken, nothing reads it back.
; a5 = exception name string.
; ---------------------------------------------------------------------------
EXC_BUS_ERROR:
	lea EXC_TXT_BUS(pc),a5
	bra.s EXC_COMMON
EXC_ADDRESS_ERROR:
	lea EXC_TXT_ADDR(pc),a5
	bra.s EXC_COMMON
EXC_ILLEGAL:
	lea EXC_TXT_ILL(pc),a5
	bra.s EXC_COMMON
EXC_ZERO_DIVIDE:
	lea EXC_TXT_DIV(pc),a5
	bra.s EXC_COMMON
EXC_CHK:
	lea EXC_TXT_CHK(pc),a5
	bra.s EXC_COMMON
EXC_TRAPV:
	lea EXC_TXT_TRAPV(pc),a5
	bra.s EXC_COMMON
EXC_PRIVILEGE:
	lea EXC_TXT_PRIV(pc),a5
	bra.s EXC_COMMON
EXC_LINE_A:
	lea EXC_TXT_LINEA(pc),a5
	bra.s EXC_COMMON
EXC_LINE_F:
	lea EXC_TXT_LINEF(pc),a5
	bra.s EXC_COMMON
EXC_INTERRUPT:
	lea EXC_TXT_INT(pc),a5
	bra.s EXC_COMMON
EXC_OTHER:
	lea EXC_TXT_OTHER(pc),a5

EXC_COMMON:
	move #$2700,sr
	lea RAM_RESERVED_SYS_ROM,sp
	WatchDog
	Print "*** 68000 EXCEPTION: "
	move.l a5,a1
	PrintA1
	PrintLn " - extension aborted ***"
	WriteEOT
	jmp WAIT_FOR_COMMAND

EXC_TXT_BUS:	dc.b "bus error",0
EXC_TXT_ADDR:	dc.b "address error (odd address?)",0
EXC_TXT_ILL:	dc.b "illegal instruction",0
EXC_TXT_DIV:	dc.b "divide by zero",0
EXC_TXT_CHK:	dc.b "CHK",0
EXC_TXT_TRAPV:	dc.b "TRAPV",0
EXC_TXT_PRIV:	dc.b "privilege violation",0
EXC_TXT_LINEA:	dc.b "line A opcode",0
EXC_TXT_LINEF:	dc.b "line F opcode",0
EXC_TXT_INT:	dc.b "unexpected interrupt",0
EXC_TXT_OTHER:	dc.b "reserved/unknown vector",0
	even
