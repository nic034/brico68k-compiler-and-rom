	include "inc/define.inc"

	global EXT_TEST_Z80
	global z80Handshake_JsrA6
	global z80Quiet_JsrA6

	section text

; ------------------------------------------------------------------------
; TestZ80 - standard Neo Geo sound driver handshake, no WRAM.
; Ported from the bricobanc v1.34.nico.1 line (logic unchanged, English).
; Complements TestAudio (which needs WRAM for its stack and plays beeps):
; this one never uses the stack and checks the reply more strictly.
;   $03 soft reset -> read the reply latch -> $01 request -> 16 consecutive
;   $01 reads required, and an $01 already present before the request is
;   never taken as a fresh answer -> $03 clean-up.
; Writing REG_SOUND raises the Z80 NMI; there is no shared Z80 RAM, so a
; missing reply does not tell WHICH part is faulty (Z80, M1/SM1, Z80 RAM,
; latches, NMI, clock/reset). Delays assume the stock 12 MHz 68000.
; ------------------------------------------------------------------------
EXT_TEST_Z80:
	PrintText
	dc.b "Z80 handshake test (ACTIVE: stops any sound)",10
	dc.b "Needs a standard SM1/M1 sound driver.",10,0
	even
	JsrA6 z80Handshake			; d3 = reply after the reset, d2 = result
	move.w d2,d6				; kept: printWord destroys d2
	Print "> Reply after $03 reset: $"
	move.l d3,d0
	JsrA6 printWord				; destroys d0, d2, d4, a0
	PrintLn ""
	subq.w #1,d6
	beq .freshReply			; 1: fresh stable $01
	bpl .possibleEcho			; 2: the reset also "answered" $03
	PrintText
	dc.b "=> Test INCONCLUSIVE: no fresh, stable $01 reply",10
	dc.b "Check M1/SM1, Z80, Z80 RAM, NMI, sound latches, clock/reset.",10,0
	even
	bra .cleanup

.freshReply:
	; A read path that echoes the 68000 writes could mimic the handshake:
	; if the reset also "answered" $03, do not claim the Z80 runs (d2 = 2).
	PrintText
	dc.b "=> Test success: fresh stable $01 reply (Z80 runs its driver)",10
	dc.b "Not covered: full Z80 RAM, YM2610, samples, audio output.",10,0
	even
	bra .cleanup
.possibleEcho:
	PrintText
	dc.b "=> Test INCONCLUSIVE: the reply follows the $03/$01 writes",10
	dc.b "Possible latch/bus echo (some drivers also answer $03).",10,0
	even

.cleanup:
	JsrA6 z80Quiet
	jmp EOT_AND_WAIT(pc)

; ------------------------------------------------------------------------
; Standard sound driver handshake, shared by TestZ80 and TestChip: $03
; (stop sound, driver reset), ~130 ms, read the reply; then $01 and up to
; 65536 polls for 16 consecutive $01 replies that were not already there
; before the $01 (a stale $01 in the latch does not count).
; out: d3 = reply after the reset (byte, high bits 0), d2 = 1 fresh stable
;      $01, 2 fresh but the reset reply was $03 (the reply follows the
;      writes: latch echo?), 0 no answer. Destroys d0-d4. No WRAM.
; z80Quiet: $03 then ~130 ms. Destroys d4.
; ------------------------------------------------------------------------
z80Handshake_JsrA6:
	move.b #$03,(REG_SOUND).l
	move.w #59999,d4			; ~130 ms
.resetWait:
	WatchDog
	dbra d4,.resetWait
	moveq #0,d3
	move.b (REG_SOUND).l,d3		; reply after the reset
	moveq #0,d1					; 0 while the latch holds a stale $01
	cmpi.b #$01,d3
	beq.s .send
	moveq #1,d1
.send:
	moveq #0,d2
	move.b #$01,(REG_SOUND).l
	move.w #$FFFF,d4
.poll:
	WatchDog
	moveq #0,d0
	move.b (REG_SOUND).l,d0
	cmpi.b #$01,d0
	bne.s .notReady
	tst.w d1
	beq.s .nextPoll
	addq.w #1,d2				; 16 consecutive reads: one glitch cannot pass
	cmpi.w #16,d2
	beq.s .fresh
	bra.s .nextPoll
.notReady:
	moveq #1,d1
	moveq #0,d2
.nextPoll:
	dbra d4,.poll
	moveq #0,d2					; no answer
	RtsA6
.fresh:
	moveq #1,d2
	cmpi.b #$03,d3
	bne.s .done
	moveq #2,d2
.done:
	RtsA6

z80Quiet_JsrA6:
	move.b #$03,(REG_SOUND).l
	move.w #59999,d4
.wait:
	WatchDog
	dbra d4,.wait
	RtsA6
