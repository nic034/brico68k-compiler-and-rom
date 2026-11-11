; Test fixture for emulator/test/test_ext_check.py, NOT part of the ROM: one extension that breaks a
; Brico16Bits rule on purpose, chosen by P1, so the emulator's extension checker can be shown to see it.
;   0  good: one word, EOT                     6  after the EOT, 3 ms without polling
;   1  output with IRQ 3 unmasked              7  2100 words (ring buffer is 2047)
;   2  no EOT (keeps kicking the watchdog)      8  a word after the EOT
;   3  two EOTs                                 9  2 s before the EOT (watchdog kicked)
;   4  P1 read after the 1 ms clear            10  output written from code in WRAM
;   5  200 ms without watchdog before the EOT  11  3 words from a word extension
	include "inc/define.inc"

	global EXT_CHECK_BAD

	section text

EXT_CHECK_BAD:
	move.l (BRICO_COMMAND_PARAM_1).l,d7
	cmp.w #4,d7
	bne.s .not4
	move.w #2*1200,d1			; ~2 ms, then read P1 again (too late: 0)
.w4:
	dbra d1,.w4
	move.l (BRICO_COMMAND_PARAM_1).l,d0
	PortWriteD0
	jmp EOT_AND_WAIT(pc)
.not4:
	cmp.w #1,d7
	bne.s .not1
	move #$2200,sr				; IRQ mask 2 while writing: IRQ 3 could come (none pending here)
	moveq #1,d0
	InlinePortWriteD0
	move #$2700,sr
	jmp EOT_AND_WAIT(pc)
.not1:
	cmp.w #2,d7
	bne.s .not2
.w2:
	WatchDog
	bra.s .w2
.not2:
	cmp.w #3,d7
	bne.s .not3
	moveq #3,d0
	PortWriteD0
	WriteEOT
	jmp EOT_AND_WAIT(pc)
.not3:
	cmp.w #5,d7
	bne.s .not5
	move.l #200000,d1			; 200000 x subq.l + bne (18 cycles) = 0.3 s: the watchdog bites
.w5:
	subq.l #1,d1
	bne.s .w5
	moveq #5,d0
	PortWriteD0
	jmp EOT_AND_WAIT(pc)
.not5:
	cmp.w #6,d7
	bne.s .not6
	moveq #6,d0
	PortWriteD0
	WriteEOT
	move.w #3*1200,d1			; ~3 ms, no polling
.w6:
	dbra d1,.w6
	jmp WAIT_FOR_COMMAND(pc)
.not6:
	cmp.w #7,d7
	bne.s .not7
	move.w #2100-1,d6
.w7:
	move.w d6,d0
	PortWriteD0
	WatchDog
	dbra d6,.w7
	jmp EOT_AND_WAIT(pc)
.not7:
	cmp.w #8,d7
	bne.s .not8
	moveq #8,d0
	PortWriteD0
	WriteEOT
	moveq #9,d0
	PortWriteD0
	jmp WAIT_FOR_COMMAND(pc)
.not8:
	cmp.w #9,d7
	bne.s .not9
	move.w #2000-1,d6			; 2000 x ~1 ms
.w9o:
	move.w #1200-1,d1
.w9:
	dbra d1,.w9
	WatchDog
	dbra d6,.w9o
	moveq #9,d0
	PortWriteD0
	jmp EOT_AND_WAIT(pc)
.not9:
	cmp.w #10,d7
	bne.s .not10
	lea .snip(pc),a1			; copy the port write to WRAM and run it there
	lea RAM_START,a2
	moveq #(.snipEnd-.snip)/2-1,d1
.c10:
	move.w (a1)+,(a2)+
	dbra d1,.c10
	move.l #SYSTEM_ROM_MIRROR+2*10,a0
	lea .back(pc),a5
	jmp RAM_START
.back:
	jmp EOT_AND_WAIT(pc)
.snip:
	move.w (BRICO_PORT_OUT).l,d0
	move.w (a0),d0
	jmp (a5)
.snipEnd:
.not10:
	cmp.w #11,d7
	bne.s .not11
	moveq #2,d6
.w11:
	move.w d6,d0
	PortWriteD0
	dbra d6,.w11
	jmp EOT_AND_WAIT(pc)
.not11:
	moveq #0,d0					; 0 and anything else: good
	PortWriteD0
	jmp EOT_AND_WAIT(pc)
