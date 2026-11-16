	include "inc/define.inc"

	global EXT_TEST_GFX

	section text

; ------------------------------------------------------------------------
; TestGfx - test screen for the two tile layers, which no other test shows:
; LSPC2 -> cartridge S ROM (fix) and C ROMs (sprites) -> line buffers ->
; palette -> DAC. Everything before it only tested VRAM, registers and
; colours. The verdict is read on the screen.
; The tiles come from the cartridge: the AES has none on board (on MVS the
; fix tiles are the board SFIX or the cartridge S ROM, as the latch is).
; So their content is not known here: the fix labels need the ASCII font
; that S ROMs hold at tiles $20-$5F, and the sprites show whatever the C
; ROMs hold from tile P1 up, through a palette of 15 different colours.
;
; Layout (visible area 320 x 224, fix cell 8 x 8), neogeodev wiki "Sprites",
; "Fix layer", "Sprite shrinking", MAME neogeo_spr.cpp:
;   fix map $7000 + column * 32 + row, word = palette << 12 | tile,
;     rows 2-29 visible (y = (row - 2) * 8)
;   SCB1 $0000 + sprite * 64: per tile, tile bits 15-0, then palette << 8 |
;     tile bits 19-16 << 4 | V flip << 1 | H flip
;   SCB2 $8000 + sprite: H shrink << 8 | V shrink ($F / $FF = full size)
;   SCB3 $8200 + sprite: (496 - y) << 7 | sticky << 6 | height in tiles
;   SCB4 $8400 + sprite: x << 7
; Sprites 1-35 are used. V shrink: the 16 tiles of the column are squeezed
; by the L0 ROM table into a 4-tile window, so at $3F all 16 show.
; P2 = 1: the whole screen instead, 20 sprites of 14 tiles (320 x 224), no
; label: a fault that depends on the position (line buffer, a column of
; pixels) shows wherever it is; the test zones only cover parts of the screen.
; The screen stays (nothing is animated): TestDAC clears it.
; No WRAM: registers, ROM tables, VRAM and palette RAM.
; ------------------------------------------------------------------------
GFX_COUNT    equ 35
GFX_FIX_COL  equ 1					; 16 x 16 fix tile block: first column
GFX_FIX_ROW  equ 12					; and first row (y = 80)

	macro FixText					; \1 = column, \2 = row, \3 = text
		dc.w VRAM_FIXMAP+(\1)*32+(\2)
		dc.b \3,0
		even
	endm

EXT_TEST_GFX:
	move.l (BRICO_COMMAND_PARAM_1).l,d7	; read P1 at once (host clears it)
	and.l #$000FFFFF,d7					; first C ROM tile, 20 bits
	move.l (BRICO_COMMAND_PARAM_2).l,d5	; 1 = whole screen
	; palette bank 0, sprites hidden, fix map = tile $20 on palette 0;
	; leaves a0 = REG_VRAMRW and REG_VRAMMOD = 1 (Screen.s)
	JsrA6 screenBlank

	; --- palettes: backdrop dark blue, palette 0 (fix) all white,
	;     palette 1 (sprites) 15 colours ----------------------------------
	move.w #$0113,(PALETTE_BACKDROP).l
	lea (PALETTE_0+2).l,a1
	moveq #15-1,d1
.white:
	move.w #$7FFF,(a1)+
	dbra d1,.white
	addq.l #2,a1					; palette 1, colour 0 is transparent
	lea GFX_COLOURS(pc),a2
	moveq #15-1,d1
.colours:
	move.w (a2)+,(a1)+
	dbra d1,.colours

	tst.l d5
	bne .full

	; --- fix layer: labels (left to right: + 32 per character) -----------
	move.w #32,(REG_VRAMMOD).l
	lea GFX_TEXT(pc),a2
.text:
	move.w (a2)+,d0
	beq.s .textDone
	move.w d0,(REG_VRAMADD).l
.char:
	moveq #0,d0
	move.b (a2)+,d0
	beq.s .textNext
	move.w d0,(a0)
	bra.s .char
.textNext:
	move.l a2,d0					; next entry: on an even address
	addq.l #1,d0
	bclr #0,d0
	movea.l d0,a2
	bra.s .text
.textDone:

	; --- fix layer: tiles $00-$FF, 16 per row (top to bottom: + 1) -------
	move.w #1,(REG_VRAMMOD).l
	moveq #0,d2						; column 0-15
.fixCol:
	move.w d2,d0
	lsl.w #5,d0
	add.w #VRAM_FIXMAP+GFX_FIX_COL*32+GFX_FIX_ROW,d0
	move.w d0,(REG_VRAMADD).l
	move.w d2,d0					; tile = row * 16 + column
	moveq #16-1,d1
.fixRow:
	move.w d0,(a0)
	add.w #16,d0
	dbra d1,.fixRow
	addq.w #1,d2
	cmp.w #16,d2
	bne.s .fixCol

	; --- sprites: the test zones, from the table -------------------------
	lea GFX_SPRITES(pc),a2
	moveq #1,d6						; sprite number
	moveq #8,d5						; tile step down a column
.sprite:
	move.w (a2)+,d3					; x
	movea.w (a2)+,a4				; y
	movea.w (a2)+,a3				; shrink
	moveq #0,d0
	move.b (a2)+,d0
	movea.w d0,a1					; height
	move.b (a2)+,d0
	move.w d0,d2
	lsr.w #4,d0						; first tile, 0-7
	and.w #3,d2						; flips
	move.l d7,d4
	add.l d0,d4
	JsrA6 gfxSprite
	cmp.w #GFX_COUNT+1,d6
	bne.s .sprite
	bra.s .report

	; --- sprites: the whole screen, 20 columns of 14 tiles ---------------
.full:
	moveq #1,d6
	moveq #20,d5					; tile = P1 + column + 20 * row
	moveq #0,d3						; x
	moveq #0,d2						; no flip
	suba.l a4,a4					; y = 0
	movea.w #$0FFF,a3				; full size
	movea.w #14,a1
.fullSprite:
	move.l d7,d4
	add.l d6,d4
	subq.l #1,d4
	JsrA6 gfxSprite
	add.w #16,d3
	cmp.w #20+1,d6
	bne.s .fullSprite

	; --- report ----------------------------------------------------------
.report:
	WatchDog
	PrintLn "Graphics test screen: fix layer and sprites (cartridge tiles)"
	cmp.l #$4E454F2D,($000100).l	; "NEO-"
	beq.s .hasCart
	PrintLn "No NEO-GEO header at $100: no cartridge = no tiles to show."
.hasCart:
	Print "Sprites (C ROMs) from tile $"
	move.l d7,d0
	JsrA6 printLong
	PrintText
	dc.b " (P1). P2=1: whole screen, 20 x 14 tiles.",10
	dc.b "Zones: flips, 8 x 4 tiles, H shrink $F-$0, V shrink $FF-$3F (L0 ROM),",10
	dc.b "fix tiles $00-$FF (S ROM). Look for missing, shifted or wrong tiles,",10
	dc.b "vertical bars, no flip, no shrink. Blank tiles: try another P1.",10
	dc.b "TestDAC clears the screen.",10,0
	even
	jmp EOT_AND_WAIT(pc)

; gfxSprite: writes sprite d6 and adds 1 to d6. d3 = x, a4 = y (visible
; area), a3 = SCB2 shrink word, a1 = height in tiles, d2 = flips, d4 = first
; tile (20 bits), d5 = tile step down the column, a0 = REG_VRAMRW,
; REG_VRAMMOD = 1. Destroys d0, d1, d4.
gfxSprite_JsrA6:
	; SCB1: the whole 16-tile column (only "height" tiles are in the
	; window; V shrink brings the others in)
	move.w d6,d0
	lsl.w #6,d0
	move.w d0,(REG_VRAMADD).l
	moveq #16-1,d1
.tile:
	move.w d4,(a0)					; tile bits 15-0
	move.l d4,d0
	swap d0
	and.w #$000F,d0					; tile bits 19-16
	lsl.w #4,d0
	or.w d2,d0
	or.w #$0100,d0					; palette 1
	move.w d0,(a0)
	add.l d5,d4
	dbra d1,.tile
	; SCB2: shrink
	move.w d6,d0
	add.w #VRAM_SCB2,d0
	move.w d0,(REG_VRAMADD).l
	move.w a3,(a0)
	; SCB4: x
	move.w d6,d0
	add.w #VRAM_SCB4,d0
	move.w d0,(REG_VRAMADD).l
	move.w d3,d0
	lsl.w #7,d0
	move.w d0,(a0)
	; SCB3 last (it makes the sprite visible): y and height
	move.w d6,d0
	add.w #VRAM_SCB3,d0
	move.w d0,(REG_VRAMADD).l
	move.w #496,d0
	sub.w a4,d0
	lsl.w #7,d0
	move.w a1,d1
	or.w d1,d0
	move.w d0,(a0)
	addq.w #1,d6
	RtsA6

	even
GFX_COLOURS:						; palette 1, colours 1-15 ($0RGB, 4 bits each)
	dc.w $0F00,$0F80,$0FF0,$08F0,$00F0,$00F8,$00FF,$008F
	dc.w $000F,$080F,$0F0F,$0F08,$0FFF,$0888,$0444

GFX_TEXT:							; fix labels: VRAM address, text, 0; ends with 0
	FixText 1,3,"BRICO68K TESTGFX"
	FixText 1,5,"FLIP 0 H V HV"
	FixText 1,10,"FIX TILES 00-FF"
	FixText 20,5,"SPRITES 8X4"
	FixText 20,15,"H SHRINK F-0"
	FixText 20,18,"V SHRINK FF-3F"
	dc.w 0

; One entry per sprite, from sprite 1: x, y (visible area), SCB2 shrink
; word, height in tiles, first tile << 4 | V flip << 1 | H flip.
GFX_SPRITES:
	dc.w 8,32,$0FFF
	dc.b 1,$00		; flip none
	dc.w 32,32,$0FFF
	dc.b 1,$01		; flip H
	dc.w 56,32,$0FFF
	dc.b 1,$02		; flip V
	dc.w 80,32,$0FFF
	dc.b 1,$03		; flip H+V
	dc.w 160,32,$0FFF
	dc.b 4,$00		; grid column 0
	dc.w 176,32,$0FFF
	dc.b 4,$10		; grid column 1
	dc.w 192,32,$0FFF
	dc.b 4,$20		; grid column 2
	dc.w 208,32,$0FFF
	dc.b 4,$30		; grid column 3
	dc.w 224,32,$0FFF
	dc.b 4,$40		; grid column 4
	dc.w 240,32,$0FFF
	dc.b 4,$50		; grid column 5
	dc.w 256,32,$0FFF
	dc.b 4,$60		; grid column 6
	dc.w 272,32,$0FFF
	dc.b 4,$70		; grid column 7
	dc.w 160,112,$0FFF
	dc.b 1,$00		; H shrink $F: 16 pixels
	dc.w 177,112,$0EFF
	dc.b 1,$00		; H shrink $E: 15 pixels
	dc.w 193,112,$0DFF
	dc.b 1,$00		; H shrink $D: 14 pixels
	dc.w 208,112,$0CFF
	dc.b 1,$00		; H shrink $C: 13 pixels
	dc.w 222,112,$0BFF
	dc.b 1,$00		; H shrink $B: 12 pixels
	dc.w 235,112,$0AFF
	dc.b 1,$00		; H shrink $A: 11 pixels
	dc.w 247,112,$09FF
	dc.b 1,$00		; H shrink $9: 10 pixels
	dc.w 258,112,$08FF
	dc.b 1,$00		; H shrink $8: 9 pixels
	dc.w 268,112,$07FF
	dc.b 1,$00		; H shrink $7: 8 pixels
	dc.w 277,112,$06FF
	dc.b 1,$00		; H shrink $6: 7 pixels
	dc.w 285,112,$05FF
	dc.b 1,$00		; H shrink $5: 6 pixels
	dc.w 292,112,$04FF
	dc.b 1,$00		; H shrink $4: 5 pixels
	dc.w 298,112,$03FF
	dc.b 1,$00		; H shrink $3: 4 pixels
	dc.w 303,112,$02FF
	dc.b 1,$00		; H shrink $2: 3 pixels
	dc.w 307,112,$01FF
	dc.b 1,$00		; H shrink $1: 2 pixels
	dc.w 310,112,$00FF
	dc.b 1,$00		; H shrink $0: 1 pixels
	dc.w 160,136,$0FFF
	dc.b 4,$00		; V shrink $FF
	dc.w 180,136,$0FDF
	dc.b 4,$00		; V shrink $DF
	dc.w 200,136,$0FBF
	dc.b 4,$00		; V shrink $BF
	dc.w 220,136,$0F9F
	dc.b 4,$00		; V shrink $9F
	dc.w 240,136,$0F7F
	dc.b 4,$00		; V shrink $7F
	dc.w 260,136,$0F5F
	dc.b 4,$00		; V shrink $5F
	dc.w 280,136,$0F3F
	dc.b 4,$00		; V shrink $3F
