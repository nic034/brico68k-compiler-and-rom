	include "inc/define.inc"

	global EXT_TEST_BUS
	global busCheck_JsrA6
	global BUS_SCREEN
	global screenBlank_JsrA6		; also used by TestDAC
	global busBand_JsrA6
	global bandColour_JsrA6

	section text

; ------------------------------------------------------------------------
; TestBus - the BIOS socket path, 68000 -> BricoNeo, as NeoDiag checks it.
;
; It uses what the BricoNeo already does for NeoDiag images (header flag
; $0004, Brico16Bits NeoDiagImageBuilder.cpp): the image is 32 KB, the
; BricoNeo writes its CRC32 at $7FFC and copies it to $8000, $10000 and
; $18000 with the mirror number (1, 2, 3) in the byte at $7FFA of each copy
; (0 in the first one). Our build tools write the same 128 KB image, so a
; ROM loaded with SendROMPart, or run in MAME / the emulator, is identical.
;
;  - A15, A16: the mirror byte read at $C07FFA, $C0FFFA, $C17FFA, $C1FFFA
;    says which copy the BricoNeo served: a stuck line is named, with its
;    level. The code itself runs in every copy, so it still boots.
;  - A1-A14, D0-D15: the code needs them to run at all: a cut there stops
;    the boot (BricoNeo Trace, then a continuity meter). A marginal line
;    shows as a CRC32 error over $0000-$7FFA (the wiki: "BIOS CRC error
;    could be faulty NEO-E0"); the line cannot be named.
; One pass, no retry: `*TestBus` (BricoNeo loop mode) repeats it and
; refreshes the screen when the result changes (an unstable line).
; The command block $90-$9F is live (the BricoNeo writes it): counted as
; zeros, as when the CRC was computed.
;
; Also run at boot (mirror bytes only, < 1 ms), from Brico68k.s START: the
; screen shows only on a fault, because with A15/A16 stuck at 1 the
; command block read lands in a copy and no command can ever arrive.
; No WRAM, no stack.
; ------------------------------------------------------------------------
BUS_LINE_MASK  equ $FF80
BUS_FIRST_LINE equ $110			; first visible line (as TestDAC)
BUS_BAND_LINES equ 14			; 16 bands x 14 = 224 lines
MIRROR_BYTE    equ $7FFA		; 68000 view of NeoDiagImageBuilder MIRROR_OFFSET
CRC_LONG       equ $7FFC		; CRC32_OFFSET
CRC_END        equ $7FFB		; the CRC covers $0000-$7FFA
CMD_BLOCK      equ $90			; BricoExt command block $90-$9F (written by the BricoNeo)

EXT_TEST_BUS:
	JsrA6 busCheck
	PrintLn "BIOS socket, 68000 -> BricoNeo (NeoDiag mirrors + CRC32)"
	btst #2,d4
	beq .layoutOk
	PrintLn "=> CHECK: no mirror bytes: image loaded without the NeoDiag"
	PrintLn "   layout (header flag $0004), or several lines bad"
	jmp EOT_AND_WAIT(pc)
.layoutOk:
	; A15 / A16
	moveq #14,d7
.line:
	Print "A"
	moveq #1,d0
	add.w d7,d0
	JsrA6 printDec
	move.w d7,d6
	add.w #16,d6
	btst d7,d5
	bne .r0
	btst d6,d5
	bne .r1
	PrintLn "      OK"
	bra .next
.r0:
	btst d6,d5
	bne .unst
	PrintLn "      FAIL reads 0: cut, or short to GND (red band)"
	bra .next
.r1:
	PrintLn "      FAIL reads 1: cut, or short to +5V (blue band)"
	bra .next
.unst:
	PrintLn "      FAIL unstable: cut/floating, bad contact (orange band)"
.next:
	addq.w #1,d7
	cmp.w #16,d7
	bne .line
	; CRC32, only meaningful when A15/A16 are right
	tst.l d5
	beq.s .crc
	PrintLn "CRC32    not checked (A15/A16 first)"
	bra .verdict
.crc:
	JsrA6 busCrc
	move.l d0,d6				; Print destroys d0
	Print "CRC32    "
	cmp.l (SYSTEM_ROM+CRC_LONG).l,d6
	bne .crcBad
	PrintLn "OK (A1-A14, D0-D15)"
	bra .verdict
.crcBad:
	bset #0,d4
	PrintLn "FAIL: a marginal line A1-A14 / D0-D15, NEO-E0, or a patched"
	PrintLn "         image (SetRomW) (yellow bands A1-A14)"
.verdict:
	move.l d5,d0
	or.w d4,d0
	tst.l d0					; or.w only flags the low word
	bne .bad
	PrintLn "=> Test success: the BIOS socket path works"
	bra .legend
.bad:
	PrintLn "=> Test failure: reseat the BricoNeo, then check the traces"
.legend:
	PrintLn "Screen: 16 bands, A1 at the top, groups of 4. Green OK, red reads 0,"
	PrintLn "blue reads 1, orange unstable, yellow CRC error. *TestBus repeats."
	WriteEOT
	jmp BUS_SCREEN(pc)

; ------------------------------------------------------------------------
; busCheck: reads the 4 mirror bytes once.
; Out: d5 low word  = lines read as 0 when 1 was sent (bit k-1 = Ak)
;      d5 high word = lines read as 1 when 0 was sent
;      d4 bit 2 = no mirror layout (a byte is not 0-3)
; Healthy: d5 = d4 = 0. Destroys d0-d5, a0.
; ------------------------------------------------------------------------
busCheck_JsrA6:
	moveq #0,d5
	moveq #0,d4
	moveq #0,d3					; mirror number m: bit 0 = A15, bit 1 = A16
.mirror:
	move.l d3,d0
	swap d0						; m x $10000 ...
	lsr.l #1,d0					; ... / 2 = m x $8000
	add.l #SYSTEM_ROM+MIRROR_BYTE,d0
	movea.l d0,a0
	moveq #0,d1
	move.b (a0),d1				; the copy the BricoNeo served
	cmp.w #3,d1
	bhi.s .noLayout
	eor.w d3,d1					; lines that came out wrong
	beq.s .nextM
	lsl.w #8,d1
	lsl.w #6,d1					; bit 0 -> bit 14 (A15), bit 1 -> bit 15 (A16)
	move.w d3,d2
	lsl.w #8,d2
	lsl.w #6,d2					; levels the 68000 sent
	move.w d1,d0
	and.w d2,d0					; sent 1, read 0
	or.w d0,d5
	not.w d2
	and.w d2,d1					; sent 0, read 1
	swap d5
	or.w d1,d5
	swap d5
.nextM:
	addq.w #1,d3
	cmp.w #4,d3
	bne.s .mirror
	RtsA6
.noLayout:
	moveq #0,d5
	moveq #4,d4
	RtsA6

; ------------------------------------------------------------------------
; busCrc: CRC-32 (zlib, as NeoDiagImageBuilder) of $C00000-$C07FFA, the
; command block $90-$9F counted as zeros, in the byte order the BricoNeo
; stores it at $7FFC ([B2 B3 B0 B1] of the 68000 long). ~0.4 s.
; Out: d0. Destroys d1-d3, a0, a1, a3.
; ------------------------------------------------------------------------
busCrc_JsrA6:
	movea.l a6,a3
	moveq #-1,d0
	lea SYSTEM_ROM,a0
	move.l #CMD_BLOCK,d3
	JsrA6 crcBytes
	lea BUS_ZERO16(pc),a0
	moveq #16,d3
	JsrA6 crcBytes
	lea SYSTEM_ROM+CMD_BLOCK+16,a0
	move.l #CRC_END-(CMD_BLOCK+16),d3
	JsrA6 crcBytes
	not.l d0
	rol.w #8,d0
	swap d0
	rol.w #8,d0
	swap d0
	jmp (a3)

; d0 = CRC, a0 = bytes, d3 = count (> 0). Destroys d1, d2, d3, a1.
crcBytes_JsrA6:
	lea BUS_CRC_NIBBLES(pc),a1
.byte:
	moveq #0,d1
	move.b (a0)+,d1
	eor.b d1,d0
	rept 2
	moveq #15,d2
	and.w d0,d2
	add.w d2,d2
	add.w d2,d2
	lsr.l #4,d0
	move.l (a1,d2.w),d2
	eor.l d2,d0
	endr
	move.w d3,d1
	and.w #$03FF,d1
	bne.s .noKick
	WatchDog					; ~0.4 s in all: the watchdog needs it
.noKick:
	subq.l #1,d3
	bne.s .byte
	RtsA6

BUS_ZERO16:
	dcb.b 16,0
	even
BUS_CRC_NIBBLES:				; CRC-32 (reflected $EDB88320), one nibble
	dc.l $00000000,$1DB71064,$3B6E20C8,$26D930AC
	dc.l $76DC4190,$6B6B51F4,$4DB26158,$5005713C
	dc.l $EDB88320,$F00F9344,$D6D6A3E8,$CB61B38C
	dc.l $9B64C2B0,$86D3D2D4,$A00AE278,$BDBDF21C

; ------------------------------------------------------------------------
; BUS_SCREEN: shows d5/d4 (busCheck) as 16 bands, A1 at the top, a black
; line between bands and a thicker one every 4 bands. Runs until the next
; command arrives (as TestDAC). Backdrop and palette 0 only: sprites
; hidden, fix tiles on palette 0, so it works without a cartridge.
; ------------------------------------------------------------------------
	macro BandColour			; d6 = line field, d1 = colour
		JsrA6 busBand
	endm

BUS_SCREEN:
	JsrA6 screenBlank
	move.w #BUS_LINE_MASK,d3
	moveq #0,d2					; 1 once BRICO_COMMAND_IN was seen at 0
.frame:
	move.w #(BUS_FIRST_LINE-1)<<7,d6
	moveq #0,d7
.band:
	move.w #$8000,d1			; black separator
	BandColour
	; band colour index -> d0
	moveq #0,d0
	btst d7,d5
	beq.s .n0
	addq.w #1,d0
.n0:
	move.w d7,d1
	add.w #16,d1
	btst d1,d5
	beq.s .n1
	addq.w #2,d0
.n1:
	tst.w d0
	beq.s .ok
	btst #1,d4
	bne.s .orange
	cmp.w #3,d0
	beq.s .orange
	moveq #2*2,d0				; red: reads 0
	btst d7,d5
	bne.s .pick
	moveq #3*2,d0				; blue: reads 1
	bra.s .pick
.orange:
	moveq #4*2,d0
	bra.s .pick
.ok:
	btst #2,d4
	bne.s .grey
	btst #0,d4
	beq.s .green
	cmp.w #13,d7				; CRC error: A1-A14 = bands 0-13
	bhi.s .green
	moveq #5*2,d0				; yellow
	bra.s .pick
.grey:
	moveq #6*2,d0
	bra.s .pick
.green:
	move.w d7,d0
	and.w #1,d0
	add.w d0,d0					; bright / dim, alternating
.pick:
	lea BUS_COLOURS(pc),a2
	move.w (a2,d0.w),d1
	; colour after 1 black line, 4 at the start of each group of 4
	move.w d6,d0
	add.w #1<<7,d0
	move.w d7,d6
	and.w #3,d6
	bne.s .gap1
	tst.w d7
	beq.s .gap1
	add.w #3<<7,d0
.gap1:
	move.w d0,d6
	BandColour
	; next band: back to its first line
	move.w d7,d0
	mulu #BUS_BAND_LINES<<7,d0
	add.w #(BUS_FIRST_LINE-1+BUS_BAND_LINES)<<7,d0
	move.w d0,d6
	addq.w #1,d7
	cmp.w #16,d7
	bne .band
	; bottom border black again
	move.w #$8000,d1
	BandColour
	bra .frame

; screenBlank: palette bank 0, every sprite hidden (SCB3 Y/height = 0, sprite 0
; also off screen), every
; fix tile = $20 (blank in the usual fonts) on palette 0. Destroys d0, d1, a0.
screenBlank_JsrA6:
	move.b d0,(REG_PALBANK0).l
	move.w #VRAM_SCB3,(REG_VRAMADD).l
	move.w #1,(REG_VRAMMOD).l
	lea (REG_VRAMRW).l,a0
	moveq #0,d0
	move.w #512-1,d1
.clrSprites:
	move.w d0,(a0)
	dbra d1,.clrSprites
	; sprite 0 off screen (x = 380, as the system ROM's LSP_1st does for every
	; sprite): MAME draws sprite 0 in the unused slots of each line even with
	; a height of 0, 1 pixel wide at x = 0 with whatever SCB1 holds.
	move.w #VRAM_SCB4,(REG_VRAMADD).l
	move.w #$BE00,(a0)
	move.w #VRAM_FIXMAP,(REG_VRAMADD).l
	move.w #$0020,d0
	move.w #40*32-1,d1
.clrFix:
	move.w d0,(a0)
	dbra d1,.clrFix
	WatchDog
	RtsA6

; busBand: waits for line field d6 (d3 = line mask; polling for the next
; command, which it runs: d2 = 1 once BRICO_COMMAND_IN was seen at 0), then
; sets backdrop + palette 0 colours 1-15 to d1. Destroys d0, a1.
; bandColour: the colour part only.
busBand_JsrA6:
	WatchDog
	move.l (BRICO_COMMAND_IN).l,d0
	beq.s .clear
	tst.w d2
	bne.s .command
	bra.s .poll
.command:
	move.l (BRICO_COMMAND_IN).l,d0
	jmp DISPATCH_COMMAND(pc)
.clear:
	moveq #1,d2
.poll:
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d6,d0
	bne.s busBand_JsrA6
bandColour_JsrA6:
	move.w d1,(PALETTE_BACKDROP).l
	lea (PALETTE_0+2).l,a1
	rept 15
	move.w d1,(a1)+
	endr
	RtsA6

	even
BUS_COLOURS:
	dc.w $20F0					; 0 green (A1, A3...)
	dc.w $0060					; 1 dim green (A2, A4...)
	dc.w $4F00					; 2 red: reads 0
	dc.w $108F					; 3 blue: reads 1
	dc.w $4F80					; 4 orange: unstable
	dc.w $6FF0					; 5 yellow: BIOS CRC error (A1-A14, D0-D15)
	dc.w $0888					; 6 grey: no mirror layout
