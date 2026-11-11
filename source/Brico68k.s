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
	dc.l	IRQ1_HANDLER		; 25 level 1 (VBLANK) - masked (SR=$2700) except during TestChip
	dc.l	IRQ2_HANDLER		; 26 level 2 (timer) - masked except during TestChip
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
	; Same, after sending the EOT: "jmp EOT_AND_WAIT(pc)" (4 bytes) replaces
	; "WriteEOT" + "jmp WAIT_FOR_COMMAND" (12 bytes)
	global  EOT_AND_WAIT
	; Entry for extensions that keep running until the next command arrives
	; (e.g. TestDAC): jump here with d0 = a non-zero BRICO_COMMAND_IN read
	global  DISPATCH_COMMAND
	; Unexpected interrupt report, also used by the TestChip IRQ handlers
	global  EXC_INTERRUPT

	section	text,code

	; Magic word - 8 bytes
	dc.b "BricoNeo"
	; Version - 4 bytes
	BRICONEO_VERSION 1,35			; upstream base; the fork version (FORK_VERSION) is not in the image
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
	DECLARE_EXTENSION EXT_ECHO, 			BRICO_EXT_OUTPUT_TYPE_WORD,		"Echo",				"Returns P1. No WRAM."
	DECLARE_EXTENSION EXT_READ, 			BRICO_EXT_OUTPUT_TYPE_WORD,		"Read",				"Word at address P1 (odd address: the byte). No WRAM."
	DECLARE_EXTENSION EXT_WRITE, 			BRICO_EXT_OUTPUT_TYPE_VOID,		"Write",			"Writes word P1 at address P2 (odd address: low byte). No WRAM."
	DECLARE_EXTENSION EXT_WRITE_B, 			BRICO_EXT_OUTPUT_TYPE_VOID,		"WriteB",			"Writes the low byte of P1 at address P2. No WRAM."
	DECLARE_EXTENSION EXT_MEMDUMP, 			BRICO_EXT_OUTPUT_TYPE_DUMP,		"Dump",				"Words from address P1 (even), count P2, max 2045 (BricoNeo buffer). No WRAM."
	DECLARE_EXTENSION EXT_TEST_INPUTS,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestInp",			"Controllers, memory card detect, AES/MVS (NEO-F0, NEO-C1). No WRAM."
	DECLARE_EXTENSION EXT_TEST_AUDIO,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestAudio",		"Z80 handshake, then left/right/centre beeps ~1 s each; a new command stops them. Needs WRAM (stack)."
	DECLARE_EXTENSION EXT_TEST_FM,			BRICO_EXT_OUTPUT_TYPE_VOID,		"TestFM",			"Eyecatcher music, Z80 command $02 (SM1 on MVS, cartridge M1 on AES), channels FM1-FM4. No WRAM."
	DECLARE_EXTENSION EXT_TEST_SSG,			BRICO_EXT_OUTPUT_TYPE_VOID,		"TestSsg",			"Coin chime, Z80 command $7F (SM1 on MVS; on AES the cartridge M1 decides): timer A, SSG A-C, noise. No WRAM."
	DECLARE_EXTENSION EXT_TEST_WRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWRAM",			"Work RAM: data walking 1/0, byte writes, each address line, March C-. Names bits and chip. No WRAM."
	DECLARE_EXTENSION EXT_TEST_BRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestBRAM",			"MVS backup RAM, as TestWRAM. ERASES settings. N/A on AES. No WRAM."
	DECLARE_EXTENSION EXT_TEST_PRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestPRAM",			"Palette RAM, both banks, as TestWRAM (no byte test) + bank select. No WRAM."
	DECLARE_EXTENSION EXT_TEST_VRAM,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestVRAM",		"Slow and fast VRAM, as TestWRAM; names bits and chip. $8600-$86FF skipped. No WRAM."
	DECLARE_EXTENSION EXT_TEST_LSPC,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestLSPC",			"LSPC2-A2: VRAMMOD read-back, VRAM address/data round trip, auto-increment. No WRAM."
	DECLARE_EXTENSION EXT_COLOR,			BRICO_EXT_OUTPUT_TYPE_VOID,		"Color",			"Whole screen in colour P1 (palette RAM only), e.g. red $CF00, green $20F0, blue $900F. No WRAM."
	DECLARE_EXTENSION EXT_TEST_STATUSA,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestStatusA",		"STATUS_A: coins, service, RTC (MVS). No WRAM."
	DECLARE_EXTENSION EXT_TEST_Z80,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestZ80",			"Z80 handshake 03/01/03, 16 stable replies, latch echo flagged. Stops sound. Needs the SM1/M1 driver. No WRAM."
	DECLARE_EXTENSION EXT_TEST_DAC,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestDAC",			"RGB DAC: 16 bands, one colour bit each. P1=1: dark bit. P1=$10+n: band n full screen. No WRAM."
	DECLARE_EXTENSION EXT_TEST_TIMING,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestTiming",		"LSPC line counter (steps, range, lines/frame, NTSC/PAL), auto-animation, CPU cycles per frame. No WRAM."
	DECLARE_EXTENSION EXT_TEST_WATCHDOG,	BRICO_EXT_OUTPUT_TYPE_STRING,	"TestWatchdog",		"Run 1 stops kicking the watchdog (reset ~0.13 s), run 2 reports it. Uses WRAM $10FFE0."
	DECLARE_EXTENSION EXT_TEST_CHIP,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestChip",		"One line per part, < 1 s: WRAM, palette, VRAM, LSPC2, NEO-C1, IRQs, Z80, NEO-D0 clocks. IRQs need WRAM."
	DECLARE_EXTENSION EXT_TEST_SYSTYPE,		BRICO_EXT_OUTPUT_TYPE_STRING,	"TestSystype",		"SYSTYPE: TEST button, JAMMA sense (MVS). No WRAM."
	DECLARE_EXTENSION EXT_CART_DIAG,		BRICO_EXT_OUTPUT_TYPE_STRING,	"CartDiag",			"p-bus test (diag cart), github.com/jwestfall69/neogeo-diag-aes-prog. WRITES the SRAM: /ROMOE, /PORTOE, D0-D15, lanes, A1-A19. No WRAM."
	DECLARE_EXTENSION EXT_TEST_VECTORS,	BRICO_EXT_OUTPUT_TYPE_STRING,	"TestVectors",		"Vector table switch, system ROM / cartridge (REG_SWPBIOS / REG_SWPROM). No WRAM."
	DECLARE_EXTENSION EXT_TEST_GFX,			BRICO_EXT_OUTPUT_TYPE_STRING,	"TestGfx",			"Screen: fix tiles, sprites (flips, 8x4, H/V shrink), cartridge tiles from P1. P2=1: whole screen. No WRAM."
	dc.l $ffffffff ; No more extensions

START:
	move #$2700,sr					; Supervisor mode + all interrupts disabled
	WatchDog 						; kick watchdog
	move.w	#7,(REG_IRQACK).l 		; ack all IRQs
	move.w  #$4000,(REG_LSPCMODE).l ; stop animations
	lea RAM_RESERVED_SYS_ROM,sp		; Set stack pointer to BIOS_WORKRAM
	DisableInterrupts 				; Interrupts are disabled by default
	bra.s WAIT_FOR_COMMAND

EOT_AND_WAIT:
	WriteEOT
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
	PortWriteD0					; called, not inlined: 96 bytes less, same words
	move.w d5,d0
	PortWriteD0
	move.l d4,d0
	swap d0
	PortWriteD0
	move.w d4,d0
	PortWriteD0
	move.l d6,d0
	swap d0
	PortWriteD0
	move.w d6,d0
	PortWriteD0
	bra EOT_AND_WAIT

EXC_CMD:	dc.b "EXCPT",0
	even
