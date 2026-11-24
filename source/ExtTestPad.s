	include "inc/define.inc"

	global EXT_TEST_PAD

	section text

; ------------------------------------------------------------------------
; TestPad - the controllers, live.
;  - Console: both pads drawn in ASCII (pressed: the label shows, released:
;    blank), plus the raw bytes. One drawing per command: "*TestPad" in the
;    BricoNeo console (loop mode) redraws it again and again: live.
;  - Screen, after the EOT, until another command: 16 colour bands, one per
;    line, top to bottom: P1 up, down, left, right, A, B, C, D, then P2 the
;    same (a gap between the players). Pressed: P1 green / P2 blue,
;    released: grey. Read every frame. Backdrop and palette only: works with
;    no cartridge (text on the screen would need the cartridge S ROM).
; Inputs (wiki "Memory mapped registers"): REG_P1CNT $300000, REG_P2CNT
; $340000: bit 0 up, 1 down, 2 left, 3 right, 4-7 A B C D; REG_STATUS_B
; $380000: bit 0 P1 start, 1 P1 select, 2 P2 start, 3 P2 select. All at 0
; when pressed. No WRAM.
; ------------------------------------------------------------------------
PAD_LINE_MASK  equ $FF80
PAD_FIRST_LINE equ $110			; first visible line (as TestDAC / TestBus)
PAD_BAND_LINES equ 14

EXT_TEST_PAD:
	JsrA6 screenBlank				; before the EOT: ~2.7 ms without polling
	moveq #0,d5
	move.b (REG_STATUS_B).l,d5
	not.b d5						; 1 = pressed
	moveq #0,d1
	move.b (REG_P1CNT_REG_DIPSW).l,d1
	not.b d1
	move.w d5,d4
	and.w #3,d4						; P1 start, select
	PrintLn "P1"
	lea PAD_ART(pc),a1
	JsrA6 padArt
	moveq #0,d1
	move.b (REG_P2CNT).l,d1
	not.b d1
	move.w d5,d4
	lsr.w #2,d4
	and.w #3,d4						; P2 start, select
	PrintLn "P2"
	lea PAD_ART(pc),a1
	JsrA6 padArt
	Print "Raw (0 = pressed): P1 $"
	moveq #0,d0
	move.b (REG_P1CNT_REG_DIPSW).l,d0
	JsrA6 printWord
	Print "  P2 $"
	moveq #0,d0
	move.b (REG_P2CNT).l,d0
	JsrA6 printWord
	Print "  STATUS_B $"
	moveq #0,d0
	move.b (REG_STATUS_B).l,d0
	JsrA6 printWord
	PrintText
	dc.b 10,"Live: *TestPad here (redraws), and the screen: 16 bands, P1 then P2",10
	dc.b "(up down left right A B C D), lit while pressed, until a command.",10,0
	even
	WriteEOT

	; --- screen: one band per input, until another command -------------
	move.w #PAD_LINE_MASK,d3
	moveq #1,d2						; TestPad's own command was cleared 1 ms after it
									; came: any command now is new (loop mode too)
.frame:
	moveq #0,d5
	move.b (REG_P2CNT).l,d5
	lsl.w #8,d5
	move.b (REG_P1CNT_REG_DIPSW).l,d5
	not.w d5						; bits 0-7 P1, 8-15 P2: 1 = pressed
	move.w #(PAD_FIRST_LINE-1)<<7,d6
	moveq #0,d7
.band:
	move.w #$8000,d1				; black line between bands
	JsrA6 screenBand
	move.w #$0333,d1				; released: grey
	btst d7,d5
	beq.s .colour
	move.w #$20F0,d1				; P1 pressed: green
	cmp.w #8,d7
	blo.s .colour
	move.w #$108F,d1				; P2 pressed: blue
.colour:
	move.w d6,d0
	add.w #1<<7,d0
	cmp.w #8,d7
	bne.s .gap
	add.w #3<<7,d0					; 4 black lines between P1 and P2
.gap:
	move.w d0,d6
	JsrA6 screenBand
	move.w d7,d0
	mulu #PAD_BAND_LINES<<7,d0
	add.w #(PAD_FIRST_LINE-1+PAD_BAND_LINES)<<7,d0
	move.w d0,d6
	addq.w #1,d7
	cmp.w #16,d7
	bne.s .band
	move.w #$8000,d1				; bottom border
	JsrA6 screenBand
	bra.s .frame

; ------------------------------------------------------------------------
; padArt: prints the template at a1; bytes 1-10 are inputs: drawn pressed
; or released (PAD_ITEMS). d1 = pad bits (1 = pressed), d4 = bit 0 start,
; bit 1 select (1 = pressed). Destroys d0, d2, a0, a2, a3.
; ------------------------------------------------------------------------
padArt_JsrA6:
	movea.l a6,a3					; nested JsrA6 (PortWriteD0)
.char:
	moveq #0,d0
	move.b (a1)+,d0
	beq.s .done
	cmp.b #10,d0					; line feed
	beq.s .plain
	cmp.b #16,d0
	bhs.s .plain
	subq.w #1,d0					; item: 16 bytes each
	lsl.w #4,d0
	lea PAD_ITEMS(pc),a2
	adda.w d0,a2
	move.b (a2),d2					; input bit; bit 7 set: in d4 (start / select)
	bmi.s .status
	btst d2,d1
	bra.s .which
.status:
	and.w #7,d2
	btst d2,d4
.which:
	movea.l a2,a0					; the item (movea leaves the flags)
	beq.s .released
	addq.l #4,a2					; pressed text
	bra.s .text
.released:
	lea 10(a2),a2					; released text
.text:
	moveq #0,d2
	move.b 1(a0),d2					; width
	subq.w #1,d2
.out:
	moveq #0,d0
	move.b (a2)+,d0
	PortWriteD0						; destroys d0, a0
	dbra d2,.out
	bra.s .char
.plain:
	PortWriteD0
	bra.s .char
.done:
	jmp (a3)

; Template: 1 up, 2 down, 3 left, 4 right, 5-8 A B C D, 9 start, 11 select
; (10 is the line feed).
PAD_ART:
	dc.b " .-------------------------------------.",10
	dc.b " |      ",1,"                            |",10
	dc.b " |   ",3,"   ",4,"       ",5," ",6," ",7," ",8,"   |",10
	dc.b " |      ",2,"                            |",10
	dc.b " |              ",11,"  ",9,"         |",10
	dc.b " '-------------------------------------'",10,0
	even
; Items: bit, width, 0, 0, pressed text (6 bytes), released text (6 bytes)
PAD_ITEMS:
	dc.b 0,3,0,0,"[^]   [ ]   "
	dc.b 1,3,0,0,"[v]   [ ]   "
	dc.b 2,3,0,0,"[<]   [ ]   "
	dc.b 3,3,0,0,"[>]   [ ]   "
	dc.b 4,3,0,0,"(A)   ( )   "
	dc.b 5,3,0,0,"(B)   ( )   "
	dc.b 6,3,0,0,"(C)   ( )   "
	dc.b 7,3,0,0,"(D)   ( )   "
	dc.b $80,6,0,0,"START start "
	dc.b 0,0,0,0,"            "		; code 10 = line feed, never an item
	dc.b $81,6,0,0,"SELECTselect"
	even
