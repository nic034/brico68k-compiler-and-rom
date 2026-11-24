	include "inc/define.inc"

	global EXT_TEST_SND

	section text

; ------------------------------------------------------------------------
; TestSnd - sound ROM access through the game's own sound driver: sends
; Z80 commands P1 to P2 (REG_SOUND $320000), each held P3 tenths of a
; second, after the EOT, like a sound test menu, then again from P1 (a
; driver reset $03 in between) until the BricoNeo sends another command. The Z80 runs the
; cartridge M1 (AES) and plays from the V ROMs (YM2610 ADPCM) or FM / SSG.
; The 68000 cannot read M1 or the V ROMs, nor hear the result: no pass /
; fail, listen. The codes are the game's: its own sound test numbers (MVS
; test mode, MAME) give them. $01-$07 are driver control in SNK drivers
; (slot switch, eyecatcher $02, reset $03): not sounds. A sound that never
; plays, or plays noise / cut, while the others do: its V ROM area (data
; or address line of a V chip, NEO-PCM2 on MVS) - the same codes on a good
; cartridge or in MAME tell the console from the cartridge.
; Defaults: P1 = $20, P2 = P1 + 15, P3 = 15 (1.5 s); P3 at most 600 (a whole
; piece of music: TestSnd $code $code 600).
; A new command stops the sweep (Z80 $03) and runs. Not heard in the
; emulator (no FM / ADPCM; its test M1 only knows $02 and $7F).
; No WRAM: registers only, no stack.
; ------------------------------------------------------------------------
EXT_TEST_SND:
	move.l (BRICO_COMMAND_PARAM_1).l,d5	; first code
	move.l (BRICO_COMMAND_PARAM_2).l,d6	; last code
	move.l (BRICO_COMMAND_PARAM_3).l,d7	; tenths of a second per code
	and.l #$FF,d5
	bne.s .first
	moveq #$20,d5
.first:
	and.l #$FF,d6
	bne.s .last
	move.l d5,d6
	add.w #15,d6
	cmp.w #$FF,d6
	bls.s .last
	move.w #$FF,d6
.last:
	cmp.w d5,d6
	bhs.s .order
	move.w d5,d6
.order:
	tst.l d7
	beq.s .time15
	cmp.l #600,d7
	bls.s .timeOk
	move.l #600,d7
	bra.s .timeOk
.time15:
	moveq #15,d7
.timeOk:
	Print "Sound sweep: Z80 commands $"
	move.w d5,d0
	JsrA6 printWord
	Print " to $"
	move.w d6,d0
	JsrA6 printWord
	Print ", "
	move.l d7,d0
	JsrA6 printDec
	PrintText
	dc.b " tenths of a second each.",10
	dc.b "Listen. No pass/fail: the 68000 cannot read M1 / V ROMs nor hear.",10
	dc.b "Codes: the game's own (its sound test numbers); $01-$07 = driver",10
	dc.b "control. One sound silent, cut or noisy: its V ROM area. Compare",10
	dc.b "with a good cartridge or MAME. Loops until another command.",10,0
	even
	WriteEOT
	move.w d5,d4					; first code, for the next round

.code:
	move.b d5,(REG_SOUND).l
	move.w d7,d3					; tenths
	subq.w #1,d3
.tenth:
	move.w #154-1,d2				; 154 x ~0.65 ms = 0.1 s
.poll:
	move.w #$0300,d0				; 769 x 10 cycles, as TestAudio
.inner:
	dbra d0,.inner
	WatchDog
	move.l (BRICO_COMMAND_IN).l,d0	; TestSnd's own command was cleared 1 ms after it came
	beq.s .wait						; (the text above takes longer): anything here is new,
	move.b #3,(REG_SOUND).l			; a loop-mode repeat 20 us after the EOT included.
	jmp DISPATCH_COMMAND			; Stop the sound, run it.
.wait:
	dbra d2,.poll
	dbra d3,.tenth
	addq.w #1,d5
	cmp.w d6,d5
	bls.s .code
	move.b #3,(REG_SOUND).l			; driver reset: silence, then the codes again
	move.w d4,d5
	bra .code
