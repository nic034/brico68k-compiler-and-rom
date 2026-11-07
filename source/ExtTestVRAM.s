	include "inc/define.inc"

	global EXT_TEST_VRAM

	section	text

; =============================================================================
; TestVRAM - all VRAM in one test (replaces TestVRAML/U and MarchVRAML/U).
; No WRAM used, no stack.
;
; Zones (neogeodev wiki, "VRAM"):
;   slow  $0000-$7FFF  32K words, two 8-bit chips (upper byte D8-D15, lower
;                      byte D0-D7), address lines A0-A14;
;   fast  $8000-$85FF and $8700-$87FF, two CXK5814 2 KiB chips, A0-A10.
;         $8600-$86FF holds the sprite lists the LSPC2 rewrites during the
;         display: not testable by the 68000, skipped.
; Steps per zone:
;   1. data bus walking 1 / walking 0 on the first word (the complement is
;      written to the next word before reading, so a floating bus cannot
;      keep the written value);
;   2. address lines (slow A0-A14, fast A0-A10), each named, stuck at 0 or
;      at 1: words at base + 2^k hold k; writing the base must not change
;      them (stuck at 1), writing them must not change the base (stuck at 0);
;   3. March C- on every word with data background $5555 / $AAAA: each bit
;      sees 0 and 1, neighbouring data lines always hold opposite values
;      (shorts between them), and the march order finds coupling and
;      address decoder faults:
;        up(w B) up(r B,w ~B) up(r ~B,w B) dn(r B,w ~B) dn(r ~B,w B) up(r B)
;   then the zone is cleared to 0 (no garbage tiles or sprites left).
; Access rules (wiki "VRAM"), each kept with >= 8 cycles of margin:
;   read valid >= 16 CPU cycles after the address write   -> Nop4 (28 here)
;   new address >= 16 cycles after a data write           -> Nop2 (24 here)
;   next data write >= 12 cycles after a data write       -> Nop4 (28 here)
;   VRAMMOD is added after writes only; reads never move the address. The
;   address is set before every read, so no read-buffer behaviour is
;   assumed (the wiki does not describe one).
; On the first error: zone, step, address, expected, read, bad bits and
; which chip (upper / lower byte) the bad bits belong to.
;
; Registers: a5 = zone table entry, d7 = zone base, d6 = word count,
;            d5 = step id (high word) / zone id (low word),
;            d1 = expected, d2 = value to write, d4 = address, d3 = counter.
;            Print: a0/a1/d0/a6, printWord: d0/d2/d4/a0/a6.
; =============================================================================

ZONE_SLOW   equ 0
ZONE_FAST   equ 1
BG          equ $5555			; March C- data background

	macro VSet					; \1 = address (Dn or #imm)
		move.w \1,(REG_VRAMADD).l
	endm
	macro VRead					; read the word at the address just set -> d0
		Nop4
		move.w (REG_VRAMRW).l,d0
	endm
	macro VWrite				; \1 = data; then >= 28 cycles before a new address or write
		move.w \1,(REG_VRAMRW).l
		Nop4
	endm
	macro CallA3				; WRAM-free call: return address in a3
		lea .\@(pc),a3
		bra \1
.\@:
	endm
	macro ZoneName
		cmp.w #ZONE_FAST,d5
		beq.s .\@f
		Print "> Slow VRAM: "
		bra.s .\@e
.\@f:
		Print "> Fast VRAM: "
.\@e:
	endm
	macro Step					; \1 = step id (for the error report)
		swap d5
		move.w #\1,d5
		swap d5
	endm

EXT_TEST_VRAM:
	WatchDog
	PrintLn "VRAM test: slow $0000-$7FFF, fast $8000-$85FF + $8700-$87FF"
	move.w #1,(REG_VRAMMOD).l
	lea VRAM_ZONES(pc),a5
.zone:
	move.w (a5)+,d7				; base
	move.w (a5)+,d6				; word count
	move.w (a5)+,d5				; zone id
	move.w (a5)+,d3				; address lines (0 = skip), kept in a4 below
	movea.w d3,a4
	tst.w d6
	beq .allOk

	; --- 1. data bus walking 1 / walking 0 ---------------------------------
	tst.w d3
	beq .march					; second fast range: steps 1-2 done on the first
	Step 1
	moveq #1,d1
.walk:
	WatchDog
	move.w d1,d2
	not.w d2
	VSet d7
	Nop4
	VWrite d1					; base <- pattern (address -> base + 1)
	VWrite d2					; base + 1 <- complement: drives the bus
	VSet d7
	VRead
	cmp.w d1,d0
	bne .errWalk
	VSet d7
	Nop4
	VWrite d2
	VWrite d1
	VSet d7
	VRead
	cmp.w d2,d0
	bne .errWalk2
	add.w d1,d1
	bne .walk
	ZoneName
	PrintLn "data bus walking 1/0 OK"

	; --- 2. address lines --------------------------------------------------
	Step 2
	moveq #0,d3					; d3 = bad lines
	moveq #0,d6					; d6 = bad bits seen (chip), restored below
	moveq #0,d4
.a1:							; word at base + 2^k = k
	WatchDog
	moveq #1,d0
	lsl.w d4,d0
	or.w d7,d0
	VSet d0
	Nop4
	VWrite d4
	addq.w #1,d4
	cmp.w a4,d4
	bne .a1
	VSet d7
	Nop4
	VWrite #$A5A5
	moveq #0,d4
.a2:							; still k after the base write? else stuck at 1
	moveq #1,d0
	lsl.w d4,d0
	or.w d7,d0
	VSet d0
	VRead
	eor.w d4,d0
	beq .a2ok
	or.w d0,d6
	bset d4,d3
.a2ok:
	addq.w #1,d4
	cmp.w a4,d4
	bne .a2
	moveq #0,d4
.a3:							; writing base + 2^k must not change the base: else stuck at 0
	WatchDog
	moveq #1,d0
	lsl.w d4,d0
	or.w d7,d0
	VSet d0
	Nop4
	VWrite #$5A5A
	VSet d7
	VRead
	eor.w #$A5A5,d0
	beq .a3ok
	or.w d0,d6
	bset d4,d3
	VSet d7
	Nop4
	VWrite #$A5A5
.a3ok:
	addq.w #1,d4
	cmp.w a4,d4
	bne .a3
	tst.w d3
	bne .errAddr
	move.w -6(a5),d6			; word count back
	ZoneName
	Print "address lines A0-A"
	move.l a4,d0
	subq.w #1,d0
	and.l #$FFFF,d0
	JsrA6 printDec
	PrintLn " OK"

	; --- 3. March C-, background $5555 / $AAAA -------------------------------
.march:
	move.w #0,(REG_VRAMMOD).l	; read then write the same word
	; M0 up(w B), with VRAMMOD = 1 (auto-increment after each write)
	Step 10
	move.w #1,(REG_VRAMMOD).l
	VSet d7
	Nop4
	move.w d6,d3
	lsr.w #2,d3
	subq.w #1,d3
	move.w #BG,d2
.m0:
	WatchDog
	rept 4
	move.w d2,(REG_VRAMRW).l
	Nop4
	endr
	dbra d3,.m0
	Nop4
	move.w #0,(REG_VRAMMOD).l
	; M1 up(r B, w ~B)
	Step 11
	move.w #BG,d1
	move.w #~BG&$FFFF,d2
	CallA3 .marchUp
	; M2 up(r ~B, w B)
	Step 12
	move.w #~BG&$FFFF,d1
	move.w #BG,d2
	CallA3 .marchUp
	; M3 dn(r B, w ~B)
	Step 13
	move.w #BG,d1
	move.w #~BG&$FFFF,d2
	CallA3 .marchDn
	; M4 dn(r ~B, w B)
	Step 14
	move.w #~BG&$FFFF,d1
	move.w #BG,d2
	CallA3 .marchDn
	; M5 up(r B)
	Step 15
	move.w #BG,d1
	move.w d7,d4
	move.w d6,d3
	lsr.w #2,d3
	subq.w #1,d3
.m5:
	WatchDog
	rept 4
	VSet d4
	VRead
	cmp.w d1,d0
	bne .errMarch
	addq.w #1,d4
	endr
	dbra d3,.m5
	; clear the zone (VRAMMOD = 1)
	move.w #1,(REG_VRAMMOD).l
	VSet d7
	Nop4
	move.w d6,d3
	lsr.w #2,d3
	subq.w #1,d3
.clr:
	WatchDog
	rept 4
	move.w #0,(REG_VRAMRW).l
	Nop4
	endr
	dbra d3,.clr
	Nop4
	ZoneName
	Print "March C- $"
	move.w d7,d0
	JsrA6 printWord
	Print "-$"
	move.w d7,d0
	add.w d6,d0
	subq.w #1,d0
	JsrA6 printWord
	PrintLn " OK"
	bra .zone

; March elements over [d7, d7 + d6): read d1, write d2. Called with CallA3
; (return address in a3): no stack, no WRAM.
.marchUp:
	move.w d7,d4
	move.w d6,d3
	lsr.w #2,d3
	subq.w #1,d3
.mu:
	WatchDog
	rept 4
	VSet d4
	VRead
	cmp.w d1,d0
	bne .errMarch
	Nop2						; read -> write: no rule in the wiki, kept apart anyway
	VWrite d2
	addq.w #1,d4
	endr
	dbra d3,.mu
	jmp (a3)
.marchDn:
	move.w d7,d4
	add.w d6,d4					; last word + 1
	move.w d6,d3
	lsr.w #2,d3
	subq.w #1,d3
.md:
	WatchDog
	rept 4
	subq.w #1,d4
	VSet d4
	VRead
	cmp.w d1,d0
	bne .errMarch
	Nop2						; read -> write: no rule in the wiki, kept apart anyway
	VWrite d2
	endr
	dbra d3,.md
	jmp (a3)

.allOk:
	move.w #1,(REG_VRAMMOD).l
	PrintLn "Not testable: $8600-$86FF (sprite lists written by the LSPC2 during display)."
	PrintLn "=> Test success"
	bra .done

; --- errors -----------------------------------------------------------------
.errWalk:						; expected d1, read d0
	bra.s .errData
.errWalk2:
	move.w d2,d1
.errData:
	move.w d7,d4				; failing word = base
.errMarch:						; d4 = address, d1 = expected, d0 = read
	movea.w d4,a4				; address (sign-extended: only its low word is printed)
	move.w d0,d7				; read      (d6/d7 no longer needed: printDec/printWord keep them)
	move.w d1,d6				; expected
	PrintLn "=> Test failure"
	ZoneName
	swap d5
	cmp.w #1,d5
	bne .eS2
	PrintLn "data bus walking 1/0"
	bra .eS
.eS2:
	Print "March C- element M"
	moveq #0,d0
	move.w d5,d0
	sub.w #10,d0
	JsrA6 printDec
	PrintLn ""
.eS:
	swap d5
	Print "  Address  : $"
	move.l a4,d0
	JsrA6 printWord
	NlPrint "  Expected : $"
	move.w d6,d0
	JsrA6 printWord
	NlPrint "  Read     : $"
	move.w d7,d0
	JsrA6 printWord
	PrintLn ""
	eor.w d7,d6					; d6 = bad bits
	Print "  Bad bits : $"
	move.w d6,d0
	JsrA6 printWord
	Print " ="
	moveq #0,d4
.ebL:
	btst d4,d6
	beq .ebN
	Print " D"
	moveq #0,d0
	move.w d4,d0
	JsrA6 printDec				; keeps d4, d6
.ebN:
	addq.w #1,d4
	cmp.w #16,d4
	bne .ebL
	PrintLn ""
	bra .chips

.errAddr:						; d3 = bad lines, d6 = bad bits seen
	PrintLn "=> Test failure"
	ZoneName
	Print "address line(s):"
	movea.w d3,a4
	moveq #0,d4
.eaL:
	move.l a4,d0
	btst d4,d0
	beq .eaN
	Print " A"
	moveq #0,d0
	move.w d4,d0
	JsrA6 printDec				; keeps d4, a4, d6
.eaN:
	addq.w #1,d4
	cmp.w #16,d4
	bne .eaL
	NlPrintLn "  Both chips: the bad bits below show which chip(s) see it."

.chips:							; d6 = bad bits, d5.w = zone
	Print "  Chip     : "
	cmp.w #ZONE_FAST,d5
	beq .cF
	Print "slow VRAM "
	bra .cL
.cF:
	Print "fast VRAM (CXK5814) "
.cL:
	move.w d6,d0
	and.w #$FF00,d0
	beq .cLow
	move.w d6,d0
	and.w #$00FF,d0
	beq .cUp
	PrintLn "BOTH chips (D0-D15): LSPC2-A2 VRAM bus or common lines"
	bra .done
.cUp:
	PrintLn "upper chip (D8-D15)"
	bra .done
.cLow:
	PrintLn "lower chip (D0-D7)"

.done:
	move.w #1,(REG_VRAMMOD).l
	jmp EOT_AND_WAIT(pc)

	even
VRAM_ZONES:						; base, words, zone id, address lines
	dc.w $0000, $8000, ZONE_SLOW, 15
	dc.w $8000, $0600, ZONE_FAST, 11
	dc.w $8700, $0100, ZONE_FAST, 0
	dc.w 0, 0, 0, 0
