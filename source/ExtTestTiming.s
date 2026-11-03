	include "inc/define.inc"

	global EXT_TEST_TIMING

	section text

; ------------------------------------------------------------------------
; TestTiming - video timing chain, read through the LSPC line counter.
; REG_LSPCMODE ($3C0006) read = AAAA AAAA A??? BCCC (MAME neogeo_v.cpp):
;   A = 9-bit raster line counter, counts $F8..$1FF then wraps (NTSC:
;       264 lines), B = PAL flag (LSPC2), C = auto-animation counter.
; Checks: counter alive, every step is +1 (a stuck or shorted counter bit
; makes jumps), top at $1FF, lines per frame, then measures how many CPU
; cycles one frame lasts and that the auto-animation counter steps once
; per frame. CPU and video both come from the 24 MHz crystal: this checks
; the dividers / LSPC chain, NOT the crystal frequency itself.
; Registers kept across the printing routines: d5-d7, a2-a5.
; ------------------------------------------------------------------------
LINE_MASK   equ $FF80
LINE_TOP    equ $FF80			; line $1FF << 7
CYC_LOOP    equ 58				; addq.l 8 + WatchDog 16 + move.w abs.l 16 + and 4 + cmp 4 + bcc 10
CYC_FRAMES  equ 4				; frames measured
ANIM_LINE   equ $180<<7			; mid-frame line for the auto-animation reads
CYC_NTSC    equ 202752			; 384 px x 264 lines x 2 CPU clocks per pixel

EXT_TEST_TIMING:
	PrintLn "Video timing test (LSPC line counter, $3C0006)"
	move.w #LINE_MASK,d3

	; --- 1. counter alive (~24 ms, ~380 lines) ---------------------------
	move.w (REG_LSPCMODE).l,d1
	and.w d3,d1
	move.w #4999,d7
.alive:
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d1,d0
	bne .isAlive
	dbra d7,.alive
	Print "=> FAIL: line counter frozen, raw $"
	move.w (REG_LSPCMODE).l,d0
	JsrA6 printWord
	PrintLn ""
	PrintLn "Check LSPC2-A2, its clocks (24M/6M from the clock chain) and sync."
	bra .end

.isAlive:
	; --- 2. ~1.3 frames of samples: AND / OR of every line value, kept in
	;        the high words of d5 / d6. A healthy frame takes every counter
	;        bit through 0 and 1 (AND = 0, OR = $1FF).
	moveq #-1,d5
	moveq #0,d6
	move.w #4500-1,d7			; x 58 cycles ~ 1.3 frames
.sample:
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	and.w d0,d5
	or.w d0,d6
	dbra d7,.sample
	swap d5
	swap d6

	; --- 3. sync: wait for line $1FF, then the wrap --------------------------
	move.w #20000,d7			; ~3 frames
.waitTop:
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w #LINE_TOP,d0
	beq .atTop
	dbra d7,.waitTop
	Print "=> FAIL: line $1FF never reached. Counter bits never at 1: $"
	move.l d6,d0
	swap d0
	not.w d0
	and.w #LINE_MASK,d0
	lsr.w #7,d0
	JsrA6 printWord
	PrintLn ""
	PrintLn "  (line counter bit stuck at 0: LSPC2-A2 or its clock)"
	bra .end
.atTop:
	move.w #2000,d7
.waitWrap:
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w #LINE_TOP,d0
	dbne d7,.waitWrap
	move.w d0,d5				; d5 = first line of the frame (<< 7)

	; --- 4. one full frame: every change must be +1 ------------------------
	move.w d5,d1				; d1 = previous line
	move.w #1,d6				; d6 = lines seen (low word; high word = OR)
	moveq #0,d7					; d7 = bad steps
	suba.l a3,a3
	suba.l a4,a4
.scanReset:
	move.w #2000,d4				; ~6 lines without change = stopped
.scan:
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d1,d0
	bne .changed
	dbra d4,.scan
	Print "=> FAIL: counter stopped mid-frame at line $"
	move.w d1,d0
	lsr.w #7,d0
	JsrA6 printWord
	PrintLn ""
	bra .end
.changed:
	cmp.w #LINE_TOP,d1
	beq .frameEnd				; $1FF -> wrap: frame complete
	move.w d1,d2
	add.w #$80,d2
	cmp.w d2,d0
	beq .stepOk
	tst.w d7
	bne .notFirst
	movea.w d1,a3				; first bad step: from (a3) to (a4)
	movea.w d0,a4
.notFirst:
	addq.w #1,d7
.stepOk:
	addq.w #1,d6
	move.w d0,d1
	bra .scanReset

.frameEnd:
	; d0 = first line of the next frame; it must match d5
	cmp.w d5,d0
	beq .measure
	addq.w #1,d7
	cmpa.l #0,a3
	bne .measure
	movea.w d1,a3
	movea.w d0,a4

	; --- 5. CPU cycles over CYC_FRAMES frames (we are at a frame start) ----
	; A broken sequence (stuck counter bit) makes the next measures
	; meaningless and some lines never occur: skip them.
.measure:
	tst.w d7
	bne .skipMeasures
	moveq #0,d1
	moveq #CYC_FRAMES-1,d2
.frame:
.inFirst:						; same body in both loops: CYC_LOOP cycles
	addq.l #1,d1
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d5,d0
	beq .inFirst
.untilFirst:
	addq.l #1,d1
	WatchDog
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w d5,d0
	bne .untilFirst
	dbra d2,.frame
	movea.l d1,a5				; a5 = loop count

	; --- 6. auto-animation counter: speed 0 = +1 every frame ---------------
	; START set speed $40: the LSPC frame countdown already loaded may run
	; up to 64 more frames before the first step (MAME: timer reloads the
	; countdown only when it reaches 0). Wait for one step, then check 8.
	macro WaitMidFrame			; out: d1 = raw $3C0006 read at line $180
	or.l #$FFFF0000,d3			; d3 high word = time-out (~0.3 s per wait)
.\@in:							; (mid-frame: the counter steps at line $F8,
	WatchDog					;  MAME VSSTART timer - reading there races)
	sub.l #$10000,d3
	bcs .animTimeout
	move.w (REG_LSPCMODE).l,d0
	and.w d3,d0
	cmp.w #ANIM_LINE,d0
	beq .\@in
.\@until:
	WatchDog
	sub.l #$10000,d3
	bcs .animTimeout
	move.w (REG_LSPCMODE).l,d0
	move.w d0,d1
	and.w d3,d0
	cmp.w #ANIM_LINE,d0
	bne .\@until
	endm

	move.w #$0000,(REG_LSPCMODE).l	; speed 0, auto-animation enabled
	suba.l a2,a2				; a2 = good steps (out of 8)
	WaitMidFrame
	move.w d1,d4
	and.w #7,d4					; d4 = value before the first step
	moveq #80-1,d2
.animSync:
	WaitMidFrame
	and.w #7,d1
	cmp.w d4,d1
	bne .animSynced
	dbra d2,.animSync
	bra .animDone				; never stepped in 80 frames: a2 = 0
.animSynced:
	move.w d1,d4				; d4 = previous value
	moveq #8-1,d2				; 8 more frames -> 8 steps
.animFrame:
	WaitMidFrame
	and.w #7,d1
	addq.w #1,d4
	and.w #7,d4
	cmp.w d4,d1
	bne .animMiss
	addq.w #1,a2
.animMiss:
	move.w d1,d4
	dbra d2,.animFrame
.animTimeout:
.animDone:
	bra .measuresDone
.skipMeasures:
	suba.l a5,a5				; no cycle count
	suba.l a2,a2				; no auto-animation result
.measuresDone:
	move.w #$4000,(REG_LSPCMODE).l	; back to the START value
	swap d7						; keep the result in the high word of d7:
	move.w a2,d7				; a2 is destroyed by printDec
	swap d7

	; --- results -----------------------------------------------------------
	Print "> Lines per frame: "
	moveq #0,d0
	move.w d6,d0
	JsrA6 printDec
	move.w (REG_LSPCMODE).l,d0
	btst #3,d0
	bne .pal
	PrintLn " (NTSC flag, expected 264)"
	move.w #264,d4
	bra .lines
.pal:
	PrintLn " (PAL flag, expected 312 - not verified in MAME)"
	move.w #312,d4
.lines:
	Print "> Line counter range: $"
	move.w d5,d0
	lsr.w #7,d0
	JsrA6 printWord
	PrintLn " - $01FF"
	tst.w d7
	bne .seqBad
	PrintLn "> Sequence: every line step is +1"
	bra .cycles
.seqBad:
	Print "> Sequence errors: "
	moveq #0,d0
	move.w d7,d0
	JsrA6 printDec
	Print ", first $"
	move.w a3,d0
	lsr.w #7,d0
	JsrA6 printWord
	Print " -> $"
	move.w a4,d0
	lsr.w #7,d0
	JsrA6 printWord
	PrintLn ""
	Print "> Counter bits always 1: $"
	move.l d5,d0
	swap d0
	lsr.w #7,d0
	JsrA6 printWord
	Print ", always 0: $"
	move.l d6,d0
	swap d0
	not.w d0
	and.w #LINE_MASK,d0
	lsr.w #7,d0
	JsrA6 printWord
	PrintLn ""
	PrintLn "  (stuck or shorted line counter bit: LSPC2-A2)"

.cycles:
	tst.w d7
	beq .doCycles
	PrintLn "> CPU cycles, auto-animation: skipped (line sequence errors)"
	bra .fail
.doCycles:
	Print "> CPU cycles per frame: "
	move.l a5,d0
	mulu.w #CYC_LOOP,d0			; loop count < 65536
	lsr.l #2,d0					; / CYC_FRAMES (4)
	move.l d0,d1
	movea.l d0,a5				; a5 = cycles per frame
	JsrA6 printDec
	PrintLn " (expected 202752 = 384 x 264 x 2)"
	Print "> Auto-animation counter: "
	move.l d7,d0
	swap d0
	and.l #$FFFF,d0
	JsrA6 printDec
	PrintLn "/8 frame steps OK"

	; --- verdict (d4 was destroyed by printWord: recompute the line count) --
	move.w #264,d0
	btst #3,(REG_LSPCMODE+1).l
	beq .ntscLines
	move.w #312,d0
.ntscLines:
	cmp.w d0,d6
	bne .fail
	tst.w d7
	bne .fail
	move.l d7,d0
	swap d0
	cmp.w #8,d0
	bne .fail
	move.l a5,d0
	sub.l #CYC_NTSC,d0
	bpl .absOk
	neg.l d0
.absOk:
	cmp.l #CYC_NTSC/200,d0		; +-0.5%
	bhi .check
	PrintLn "=> Test success"
	bra .end
.check:
	PrintLn "=> CHECK: frame length off by more than 0.5% (clock divider? or"
	PrintLn "   bus wait states on this board: compare with a known good one)"
	bra .end
.fail:
	PrintLn "=> Test FAIL"

.end:
	WriteEOT
	jmp WAIT_FOR_COMMAND
