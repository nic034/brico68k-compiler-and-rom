	include "inc/define.inc"

	global EXT_TEST_WATCHDOG

	section text

; ------------------------------------------------------------------------
; TestWatchdog - two runs.
; 1st run ("arm"): writes a signature in WRAM ($10FFE0, above the stack,
;   kept across a reset: START never clears WRAM), sends EOT, then stops
;   kicking the watchdog and counts loops into WRAM. The watchdog should
;   reset the system (MAME MVS: 3244030 / 24 MHz = 135 ms). If nothing
;   happens within ~1.5 s, it records "no reset" and returns to the
;   command loop.
; 2nd run: reads the signature and reports PASS + the time before the
;   reset, or FAIL, then clears it (a 3rd run arms again).
; Commands sent while the watchdog is starved are lost (up to 1.5 s).
; Needs WRAM (checked first). MAME emulates the watchdog on MVS only.
; ------------------------------------------------------------------------
MAGIC_ARMED_HI equ 'WDAR'
MAGIC_ARMED_LO equ 'MED!'
MAGIC_NORST_HI equ 'WDNO'
MAGIC_NORST_LO equ 'RST!'
STARVE_CYCLES  equ 36			; addq.l 8 + move.l Dn,(An) 12 + cmp.l Dn,Dn 6 + bne 10
STARVE_LIMIT   equ 500000		; x 36 cycles / 12 MHz = 1.5 s

EXT_TEST_WATCHDOG:
	lea (WDOG_MAGIC).l,a3
	cmp.l #MAGIC_ARMED_HI,(a3)
	bne .notArmed
	cmp.l #MAGIC_ARMED_LO,4(a3)
	beq .wasReset
.notArmed:
	cmp.l #MAGIC_NORST_HI,(a3)
	bne .arm
	cmp.l #MAGIC_NORST_LO,4(a3)
	beq .noReset

; --- 1st run: arm ----------------------------------------------------------
.arm:
	move.l #MAGIC_ARMED_HI,(a3)
	move.l #MAGIC_ARMED_LO,4(a3)
	clr.l (WDOG_COUNT).l
	cmp.l #MAGIC_ARMED_HI,(a3)		; WRAM must hold the signature
	bne .wramBad
	cmp.l #MAGIC_ARMED_LO,4(a3)
	bne .wramBad
	PrintText
	dc.b "Watchdog test ARMED: the 68000 stops kicking the watchdog now.",10
	dc.b "Expect a reset in ~0.13 s. Wait 2 s, then run TestWatchdog",10
	dc.b "again to read the result (commands sent meanwhile are lost).",10,0
	even
	WriteEOT
	lea (WDOG_COUNT).l,a1
	moveq #0,d7
	move.l #STARVE_LIMIT,d6
.starve:						; no WatchDog in this loop, on purpose
	addq.l #1,d7
	move.l d7,(a1)
	cmp.l d6,d7
	bne .starve
	; still alive after ~1.5 s: no reset happened
	WatchDog
	move.l #MAGIC_NORST_HI,(a3)
	move.l #MAGIC_NORST_LO,4(a3)
	jmp WAIT_FOR_COMMAND			; EOT already sent

; --- 2nd run: results ------------------------------------------------------
.wasReset:
	clr.l (a3)
	clr.l 4(a3)
	PrintText
	dc.b "Watchdog test result:",10
	dc.b "> The watchdog reset the 68000 after ~",0
	even
	move.l (WDOG_COUNT).l,d0
	move.l d0,d7
	move.l d0,d1					; loops x 36 cycles / 12 MHz = loops x 3 us
	add.l d0,d0						; (32-bit x3: mulu.w is only 16-bit and a
	add.l d1,d0						;  late reset can exceed 65535 loops)
	divu.w #1000,d0				; us -> ms (quotient <= 1500: no overflow)
	and.l #$FFFF,d0
	JsrA6 printDec
	Print " ms ("
	move.l d7,d0
	JsrA6 printDec
	PrintText
	dc.b " loops of 3 us)",10
	dc.b "  MAME MVS: 135 ms. Real boards: about 0.13 s.",10
	dc.b "=> Test success (run again to re-arm)",10,0
	even
	bra .end

.noReset:
	clr.l (a3)
	clr.l 4(a3)
	PrintText
	dc.b "Watchdog test result:",10
	dc.b "=> FAIL: no reset within 1.5 s while the watchdog was starved.",10
	dc.b "  Expected in MAME on AES (watchdog not emulated there). On a",10
	dc.b "  real board: watchdog circuit, its clock, or the /RESET path.",10,0
	even
	bra .end

.wramBad:
	PrintLn "=> Cannot run: WRAM does not hold the signature. Run TestWRAM."

.end:
	jmp EOT_AND_WAIT
