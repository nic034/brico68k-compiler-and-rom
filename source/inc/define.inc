SYSTEM_ROM	equ $C00000
SYSTEM_ROM_MIRROR	equ $C20000
RAM_RESERVED_SYS_ROM	equ $10F300

RAM_START	equ $100000
RAM_USER_END	equ $10F300;
RAM_END	equ $110000

BACKUP_RAM_START equ $d00000
BACKUP_RAM_END equ $d10000

PALETTE_RAM_START equ $400000
PALETTE_RAM_END equ $402000
PALETTE_BACKDROP equ $401FFE

; Palette bank select (system latch, odd-byte write, data ignored).
; Previously swapped here (unused until TestPRAM started testing both
; banks). Verified against MAME neogeo.cpp: the system latch is an HC259
; written with write_a3 (A1-A3 = output, A4 = value), output Q7 drives
; set_palette_bank -> $3A000F = Q7<-0 = bank 0, $3A001F = Q7<-1 = bank 1.
; Same as the neogeodev wiki "Memory mapped registers" page.
; Vector table $000000-$00007F (same latch, Q1, wiki "Memory mapped
; registers"): $3A0003 = system ROM (REG_SWPBIOS), $3A0013 = cartridge.
REG_SWPBIOS equ $3A0003
REG_SWPROM  equ $3A0013
REG_PALBANK0 equ $3A000F
REG_PALBANK1 equ $3A001F

; Board / cartridge fix layer + audio ROM select (same HC259 latch, output Q5):
; $3A000B = board SFIX/SM1, $3A001B = cartridge. MVS only: in MAME, Q5 is
; wired (set_use_cart_audio) on ngarcade only, not on AES. Used by TestAudio.
REG_BRDFIX equ $3A000B


; VRAM layout (word addresses for REG_VRAMADD)
VRAM_SCB1   equ $0000		; sprite tilemaps
VRAM_FIXMAP equ $7000		; fix layer map, 40 x 32 words ($7000-$74FF)
VRAM_SCB2   equ $8000		; sprite shrink
VRAM_SCB3   equ $8200		; sprite Y / sticky / height (512 words)
VRAM_SCB4   equ $8400		; sprite X

; Palette (bank 0 as seen by the CPU)
PALETTE_0   equ $400000		; palette 0, colours 0-15 (colour 0 = transparent)

; WRAM words kept across a watchdog reset by TestWatchdog (system ROM area,
; above the stack: SP starts at $10F300 and grows down)
WDOG_MAGIC  equ $10FFE0		; 4 words
WDOG_COUNT  equ $10FFE8
; TestChip (BIOS work RAM area, above the stack)
CHK_PROGRESS   equ $10FFF0	; word 0-100, read by the emulator
CHK_PROG_MAGIC equ $10FFF2	; word $C4EC while TestChip runs
CHK_VBL_COUNT  equ $10FFF4	; word, IRQ1 count
CHK_TMR_COUNT  equ $10FFF6	; word, IRQ2 count
CHK_IRQ_MAGIC  equ $10FFF8	; long: the IRQ handlers count only when it holds CHK_IRQ_MAGIC_VAL
CHK_IRQ_MAGIC_VAL equ $43484B49	; "CHKI"		; long: loop iterations before the reset

; Backup RAM write protection (MVS only, same HC259 latch, output Q6)
REG_SRAMLOCK   equ $3A000D
REG_SRAMUNLOCK equ $3A001D

ROM_NAME_SECTION_ORG	equ $100
INITIAL_PC_ORG          equ $402

REG_WATCHDOG	equ $300001
REG_LSPCMODE	equ $3C0006
REG_IRQACK		equ $3C000C
REG_TIMERHIGH	equ $3C0008
REG_TIMERLOW	equ $3C000A

BRICO_PORT_OUT	equ SYSTEM_ROM + $1FF02
BRICO_PORT_EOT	equ BRICO_PORT_OUT - 2

BRICO_EXT_OUTPUT_TYPE_VOID equ $0
BRICO_EXT_OUTPUT_TYPE_WORD equ $1
BRICO_EXT_OUTPUT_TYPE_STRING equ $2
BRICO_EXT_OUTPUT_TYPE_DUMP equ $3

; BricoNeo special flags
BRICO_SPECIAL_FLAG_ENABLE_EXTENSIONS equ $0001		; Command extensions are active
BRICO_SPECIAL_FLAG_68K_SENDS_COMMANDS equ $0002		; The 68k can send commands using the output port
BRICO_SPECIAL_FLAG_NEODIAG_MIRRORS equ $0004		; The BricoNeo writes the CRC32 at $7FFC and the 3 mirrors (NeoDiagImageBuilder).
												; Not set since 1.35-nic034-16: the code uses the whole 128 KB image

; VRAM memory mapped registers
REG_VRAMADD	equ $3C0000
REG_VRAMRW	equ $3C0002
REG_VRAMMOD	equ $3C0004

; Inputs memory mapped registers
REG_P1CNT_REG_DIPSW equ $300000
REG_SYSTYPE equ $300080
REG_SOUND equ $320000
REG_STATUS_A equ $320001
REG_P2CNT equ $340000
REG_STATUS_B equ $380000

	; Version of this fork (nic034/brico68k-compiler-and-rom): upstream base
	; 1.35 + build NN. Not in the ROM image since the Version command was removed
	; (1.35-nic034-10): README / CHANGELOG and the ROM SHA-256 identify a build.
	; The header (BRICONEO_VERSION in Brico68k.s) keeps the upstream base:
	; Brico16Bits shows "Found BricoNeo ROM version 1.35". build.py and the
	; Compiler check that the header equals the base of this string.
	macro FORK_VERSION
		dc.b "1.35-nic034-18"
	endm

	macro BRICONEO_VERSION
		dc.w \1	; Major
		dc.w \2	; Minor
	endm

	macro DECLARE_EXTENSION
		dc.l \1	; Extension address
		dc.w \2	; Return type
		dc.b \3	; Command name (0 terminated)
		dc.b 0
		align 1	; Parity
		dc.b \4	; Description (0 terminated)
		dc.b 0
		align 1	; Parity
	endm

	; Z set when address register/Dn \1 points at the BricoNeo output ports: offsets $1FF00-$1FF03
	; of the BIOS socket, in $C00000-$CFFFFF and every 128 KB mirror (the BricoNeo sees A1-A16 only).
	; A read there is an EOT ($1FF00) or arms an output word ($1FF02): Read / Dump must not do it.
	; Destroys d2.
	macro IsHostPort
		move.l \1,d2
		andi.l #$F1FFFC,d2
		cmpi.l #SYSTEM_ROM+$1FF00,d2
	endm

	macro WatchDog
		move.b	d0,(REG_WATCHDOG).l
	endm

	macro WriteEOT
		move.w (BRICO_PORT_EOT).l,d0
	endm

    macro JsrA6
		lea .\@(pc),a6					; PC-relative: 4 bytes / 8 cycles instead of 6 / 12
		jmp \1_JsrA6					; absolute: since -16 the code is over 32 KiB (128 KB image)
.\@:
	endm

	macro RtsA6
		jmp (a6)
	endm

	macro PortWriteD0
		JsrA6 port_write_d0
	endm

	; Clobbers d0 and a0 (unchanged contract).
	; BricoNeo side (Brico16Bits PioBusWatcherPort.pio): the read at the port
	; arms the watcher, ONE more socket access goes by (the opcode prefetch
	; between these two instructions) and the address of the next one is
	; the value. Keep the two reads back to back, from code in the BIOS
	; socket, with interrupts masked (the firmware runs at SR=$2700; the
	; upstream Trace.s port_write_d0 masks them itself): an interrupt or a
	; trace exception in between would shift the captured value.
	macro InlinePortWriteD0
		and.l #$0000ffff,d0				; cleanup high word
		add.l d0,d0						; times 2 (16 bits ROM) - add.l Dn,Dn: 8 cycles vs 10 for lsl.l #1
		add.l #SYSTEM_ROM_MIRROR,d0		; locate in ROM mirror range to trigger the /OE line (under 0x0100, OE will not be triggered on non mirror location)
		movea.l d0,a0					; value -> address register, as data is read on the address bus! (movea 4 cycles vs exg 6; also avoids EXG, mis-emulated by Unicorn)
		move.w (BRICO_PORT_OUT).l,d0	; trigger port write
		move.w (a0),d0					; write value
	endm

	macro Print							; String constant passed as a parameter
		PrintHandleCRLF \1,0,0
	endm

	macro PrintLn						; String constant passed as a parameter
		PrintHandleCRLF \1,1,0
	endm

	; A line feed first, then the string: the same words as PrintLn "" followed
	; by Print / PrintLn, in one call (saves the 10 bytes of the PrintLn "").
	macro NlPrint
		PrintHandleCRLF \1,0,1
	endm

	macro NlPrintLn
		PrintHandleCRLF \1,1,1
	endm

	macro PrintHandleCRLF				; P1 string constant, P2 = 1: LF after it, P3 = 1: LF before it
		; The string follows the call: printInline prints it and returns
		; after it (8 bytes of code per Print, was 18). Destroys d0, a0, a6
		; (a6 was already destroyed by the JsrA6 of the previous version).
		lea .\@StringAddress(pc),a6
		jmp printInline_JsrA6
	.\@StringAddress:
		ifc "\3","1"
		dc.b 10
		endc
		dc.b \1
		ifc "\2","1"
		dc.b 10
		endc
		dc.b 0
		align 1
	endm

	; Several lines in one call: the text follows as dc.b (0-terminated), then
	; "even". Same words as the Print / PrintLn calls it replaces, 8 bytes each
	; saved.
	macro PrintText
		lea .\@StringAddress(pc),a6
		jmp printInline_JsrA6
	.\@StringAddress:
	endm

	macro PrintA1
		JsrA6 print_a1
	endm

	; string address in a1. On exit a1 points one byte PAST the terminating
	; 0 (it used to point AT it - no caller reuses a1 after printing).
	macro InlinePrintA1
	.\@lbl0000PrintStart:
		moveq #0,d0
		move.b (a1)+,d0				; sets Z on the terminating 0: no separate cmp.b #0,(a1)
		beq.s .\@lbl0000PrintEnd
		InlinePortWriteD0
		bra.s .\@lbl0000PrintStart
	.\@lbl0000PrintEnd:
	endm

	macro PrintBit						; \1 = bit number: "0" or "1" for that bit of d1
		moveq #'0',d0					; destroys d0, a0, a6 (d0 is not 0 after it)
		btst #\1,d1
		beq.s .\@
		moveq #'1',d0
.\@:
		PortWriteD0
	endm

	macro EnableInterrupts
		move #$2000,sr				; Supervisor mode + all interrupts enabled
	endm

	macro DisableInterrupts
		move #$2700,sr				; Supervisor mode + all interrupts disabled
	endm

	; Waits \2 CPU cycles (10 to 24, even) in one 2-byte instruction: lsl.l #n,\1
	; takes 8 + 2n cycles and its only bus cycle is the opcode prefetch from the
	; ROM, like a nop. Destroys \1. Nop6 (24 cycles) is 12 bytes, Delay d0,24 is 2.
	macro Delay
		lsl.l #(\2-8)/2,\1
	endm

	macro Nop2
		nop
		nop
	endm

	macro Nop4
		Nop2
		Nop2
	endm

	macro Nop6
		Nop2
		Nop4
	endm

	macro Nop8
		Nop4
		Nop4
	endm

	macro Nop12
		Nop8
		Nop4
	endm

	macro Nop16
		Nop8
		Nop8
	endm
