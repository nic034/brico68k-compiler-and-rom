	include "inc/define.inc"

	global EXT_TEST_Z80

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
	PrintLn "Z80 handshake test (ACTIVE: stops any sound)"
	PrintLn "Needs a standard SM1/M1 sound driver."
	move.b #$03,(REG_SOUND).l
	move.w #59999,d4			; ~130 ms
.resetWait:
	WatchDog
	dbra d4,.resetWait

	moveq #0,d5
	move.b (REG_SOUND).l,d5
	Print "> Reply after $03 reset: $"
	move.l d5,d0
	JsrA6 printWord				; destroys d0, d2, d4, a0
	PrintLn ""

	; d6 = 0 while the latch still holds a stale $01
	moveq #0,d6
	cmpi.b #$01,d5
	beq .send
	moveq #1,d6
.send:
	moveq #0,d2
	move.b #$01,(REG_SOUND).l
	move.w #$FFFF,d4
.poll:
	WatchDog
	moveq #0,d1
	move.b (REG_SOUND).l,d1
	cmpi.b #$01,d1
	bne .notReady
	tst.w d6
	beq .nextPoll
	addq.w #1,d2				; 16 consecutive reads: one glitch cannot pass
	cmpi.w #16,d2
	beq .freshReply
	bra .nextPoll
.notReady:
	moveq #1,d6
	moveq #0,d2
.nextPoll:
	dbra d4,.poll
	PrintLn "=> Test INCONCLUSIVE: no fresh, stable $01 reply"
	PrintLn "Check M1/SM1, Z80, Z80 RAM, NMI, sound latches, clock/reset."
	bra .cleanup

.freshReply:
	; A read path that echoes the 68000 writes could mimic the handshake:
	; if the reset also "answered" $03, do not claim the Z80 runs.
	cmpi.b #$03,d5
	beq .possibleEcho
	PrintLn "=> Test success: fresh stable $01 reply (Z80 runs its driver)"
	PrintLn "Not covered: full Z80 RAM, YM2610, samples, audio output."
	bra .cleanup
.possibleEcho:
	PrintLn "=> Test INCONCLUSIVE: the reply follows the $03/$01 writes"
	PrintLn "Possible latch/bus echo (some drivers also answer $03)."

.cleanup:
	move.b #$03,(REG_SOUND).l
	move.w #59999,d4
.cleanupWait:
	WatchDog
	dbra d4,.cleanupWait
	WriteEOT
	jmp WAIT_FOR_COMMAND
