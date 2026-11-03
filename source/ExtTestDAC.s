	include "inc/define.inc"

	global EXT_TEST_DAC

	section text

; ------------------------------------------------------------------------
; TestDAC - RGB DAC test pattern, one colour bit per band.
; Colour word (MAME neogeo_v.cpp paletteram_w): bit 15 = dark,
; R0/G0/B0 = bits 14/13/12, R4-R1 = bits 11-8, G4-G1 = 7-4, B4-B1 = 3-0.
; Only the backdrop and palette 0 are shown: sprites are hidden (SCB3
; height 0) and every fix tile is set to palette 0, whose 15 colours are
; changed together with the backdrop, so whatever tiles the fix ROM holds
; (SFIX, cartridge S1, or nothing) take the band colour too.
; Bars mode: the colour changes at 16 line positions per frame (raster,
; no interrupt), until the next command arrives: the polling loop jumps
; to DISPATCH_COMMAND. Full-screen mode: one colour, back to the loop.
; No WRAM: everything is in registers, ROM tables, VRAM and palette RAM.
; ------------------------------------------------------------------------
LINE_MASK  equ $FF80
FIRST_LINE equ $110				; first visible line (MAME VBEND $10 + $100)
BAND_LINES equ 14				; 16 bands x 14 = 224 visible lines

EXT_TEST_DAC:
	move.l (BRICO_COMMAND_PARAM_1).l,d7	; read P1 at once (host clears it)
	move.b d0,(REG_PALBANK0).l			; CPU and display on palette bank 0

	; hide every sprite: SCB3 (Y / height) = 0
	move.w #VRAM_SCB3,(REG_VRAMADD).l
	move.w #1,(REG_VRAMMOD).l
	lea (REG_VRAMRW).l,a0
	moveq #0,d0
	move.w #512-1,d1
.clrSprites:
	move.w d0,(a0)
	dbra d1,.clrSprites
	; fix map: tile $20 (blank in the usual fonts), palette 0
	move.w #VRAM_FIXMAP,(REG_VRAMADD).l
	move.w #$0020,d0
	move.w #40*32-1,d1
.clrFix:
	move.w d0,(a0)
	dbra d1,.clrFix
	WatchDog

	; d6 = $8000 when the dark bit is requested
	moveq #0,d6
	move.l d7,d0
	cmp.l #1,d0
	bne .notDarkBars
	move.w #$8000,d6
	bra .bars
.notDarkBars:
	and.l #$FFFFFFF0,d0
	cmp.l #$10,d0
	beq .full
	cmp.l #$30,d0
	beq .fullDark
	tst.l d7
	beq .bars
	PrintLn "Unknown P1: showing the bars (P1=0)."

.bars:
	PrintLn "RGB DAC test pattern, top to bottom:"
	PrintLn "  R4 R3 R2 R1 R0 | G4 G3 G2 G1 G0 | B4 B3 B2 B1 B0 | white"
	tst.w d6
	beq .legend
	PrintLn "  with the DARK bit set (each band slightly darker than P1=0)"
.legend:
	PrintLn "A black band = that bit never reaches the screen (DAC resistor,"
	PrintLn "palette RAM data line, buffer/latch, trace). Relative level per"
	PrintLn "bit, MAME model (220/470/1k/2k2/3k9 ohm): 100/47/22/10/6 %."
	PrintLn "Shown until the next command."
	WriteEOT

	move.w #LINE_MASK,d3
	moveq #0,d2					; d2 = 1 once BRICO_COMMAND_IN was seen at 0:
.frame:							; the command that started TestDAC is still
								; there until the host clears it
	lea BAND_COLOURS(pc),a2
	move.w #(FIRST_LINE-1)<<7,d4	; colour set during the line before
	moveq #16-1,d5
.band:
	; wait for line d4, polling for the next command
.wait:
	WatchDog
	move.l (BRICO_COMMAND_IN).l,d1
	beq .cmdClear
	tst.w d2
	bne .command				; a NEW command: run it
	bra .noCmd
.cmdClear:
	moveq #1,d2
.noCmd:
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d4,d0
	bne .wait
	; set backdrop + palette 0 colours 1-15 to the band colour (~17 us)
	move.w (a2)+,d0
	or.w d6,d0
	move.w d0,(PALETTE_BACKDROP).l
	lea (PALETTE_0+2).l,a1
	rept 15
	move.w d0,(a1)+
	endr
	add.w #BAND_LINES<<7,d4
	dbra d5,.band
	bra .frame

.command:
	move.l d1,d0
	jmp DISPATCH_COMMAND

.fullDark:
	move.w #$8000,d6
.full:
	move.l d7,d0
	and.w #$000F,d0
	add.w d0,d0
	lea BAND_COLOURS(pc),a2
	move.w (a2,d0.w),d0
	or.w d6,d0
	move.w d0,(PALETTE_BACKDROP).l
	lea (PALETTE_0+2).l,a1
	rept 15
	move.w d0,(a1)+
	endr
	move.w d0,d5					; keep the colour for the message
	Print "Full screen, band "
	move.l d7,d0
	and.l #$F,d0
	JsrA6 printDec
	Print ", colour word $"
	move.w d5,d0
	JsrA6 printWord
	PrintLn ""
	PrintLn "Measure R, G and B at the video output (scope / multimeter)."
	WriteEOT
	jmp WAIT_FOR_COMMAND

	even
BAND_COLOURS:
	dc.w $0800,$0400,$0200,$0100,$4000	; R4 R3 R2 R1 R0
	dc.w $0080,$0040,$0020,$0010,$2000	; G4 G3 G2 G1 G0
	dc.w $0008,$0004,$0002,$0001,$1000	; B4 B3 B2 B1 B0
	dc.w $7FFF							; white (all bits)
