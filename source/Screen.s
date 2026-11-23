	include "inc/define.inc"

	global screenBlank_JsrA6		; TestDAC, TestGfx
	global screenBand_JsrA6			; TestDAC
	global bandColour_JsrA6			; TestDAC

	section text

; ------------------------------------------------------------------------
; Screen helpers shared by the screen tests (from TestBus, removed in
; 1.35-nic034-11). No WRAM.
; ------------------------------------------------------------------------
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

; screenBand: waits for line field d6 (d3 = line mask; polling for the next
; command, which it runs: d2 = 1 once BRICO_COMMAND_IN was seen at 0), then
; sets backdrop + palette 0 colours 1-15 to d1. Destroys d0, a1.
; bandColour: the colour part only.
screenBand_JsrA6:
	WatchDog
	move.l (BRICO_COMMAND_IN).l,d0
	beq.s .clear
	tst.w d2
	bne.s .command
	bra.s .poll
.command:
	move.l (BRICO_COMMAND_IN).l,d0
	jmp DISPATCH_COMMAND
.clear:
	moveq #1,d2
.poll:
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d6,d0
	bne.s screenBand_JsrA6
bandColour_JsrA6:
	move.w d1,(PALETTE_BACKDROP).l
	lea (PALETTE_0+2).l,a1
	rept 15
	move.w d1,(a1)+
	endr
	RtsA6
