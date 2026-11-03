	include "inc/define.inc"

	global EXT_TEST_CART

	section text

; ------------------------------------------------------------------------
; TestCart - cartridge program ROM, read from the 68000 side.
; P1=0: P1 area $000000-$0FFFFF read with the cartridge vectors selected
;       (REG_SWPROM), position-dependent checksum (s1 = sum of words,
;       s2 = sum of s1, both mod 2^32) - the same as tools/cart_checksum.py
;       on a dump -, data bits always 0 / always 1 over the first 128 KB,
;       and the mirror size (smaller ROM, or a stuck / open address line).
; P1=1: P2 window $200000-$2FFFFF: a short checksum of each bank 0-7
;       selected through the standard register $2FFFF0, then the checksum
;       of the whole window for bank 0.
; ~1.1 s per MB at 12 MHz without ROM wait states (the 3 s host limit
; leaves room for slow cartridges). Interrupts stay masked while the
; cartridge vectors are mapped. No WRAM.
; Registers kept across the printing routines: d5-d7, a2-a5.
; ------------------------------------------------------------------------
SAMPLE_WORDS equ 32

	; prints the 32-bit register \1 (not d0/d2/d4) as 8 hex digits
	macro PrintLongHex
	move.l \1,d0
	swap d0
	JsrA6 printWord
	move.l \1,d0
	JsrA6 printWord
	endm

	; s1/s2 checksum of \2 x 16 words from (a0)+ into d6 (s1) / d7 (s2)
	macro SumBlocks
	moveq #0,d6
	moveq #0,d7
	moveq #0,d1					; high word stays 0 (move.w only writes the low word)
	move.w #\2-1,d3
.\@loop:
	rept 16
	move.w (a0)+,d1
	add.l d1,d6
	add.l d6,d7
	endr
	WatchDog
	dbra d3,.\@loop
	endm

	; compares SAMPLE_WORDS words at (a0) and (a1), no stack: Z=1 if equal.
	; destroys d1, a0, a1
	macro CompareSamples
	moveq #SAMPLE_WORDS-1,d1
.\@cmp:
	cmpm.w (a0)+,(a1)+
	dbne d1,.\@cmp
	endm

EXT_TEST_CART:
	move.l (BRICO_COMMAND_PARAM_1).l,d0
	cmp.l #1,d0
	beq P2_TEST

	PrintLn "Cartridge P1 ROM test ($000000-$0FFFFF, cartridge vectors)"
	move.b d0,(REG_SWPROM).l	; $000000-$00007F = cartridge vectors

	; --- stuck data bits, first 128 KB -------------------------------------
	lea (CART_P1_START).l,a0
	moveq #-1,d4				; d4 = AND of all words (bits always 1)
	moveq #0,d5					; d5 = OR of all words (bits always 0 = ~d5)
	move.w #4096-1,d3			; 4096 x 16 words = 128 KB
.stuckLoop:
	rept 16
	move.w (a0)+,d0
	and.w d0,d4
	or.w d0,d5
	endr
	WatchDog
	dbra d3,.stuckLoop
	movea.w d4,a2				; a2 = AND
	movea.w d5,a3				; a3 = OR

	; --- mirror size: first S where two samples repeat at +S ----------------
	move.l #$10000,d5			; 64 KB .. 512 KB
.mirrorTry:
	lea ($000100).l,a0
	movea.l d5,a1
	lea ($100,a1),a1
	CompareSamples
	bne .mirrorNext
	lea ($008000).l,a0
	movea.l d5,a1
	adda.l #$8000,a1
	CompareSamples
	beq .mirrorFound
.mirrorNext:
	add.l d5,d5
	cmp.l #$100000,d5
	bne .mirrorTry
.mirrorFound:
	movea.l d5,a4				; a4 = mirror size ($100000 = none)

	; --- checksum of the whole 1 MB ---------------------------------------
	lea (CART_P1_START).l,a0
	SumBlocks d6,32768			; 32768 x 16 words = 1 MB (dbra: max 32768 ok)
	move.b d0,(REG_SWPBIOS).l	; back to the BIOS vectors

	; --- report -------------------------------------------------------------
	move.w a2,d0
	cmp.w #$FFFF,d0
	bne .notFF
	PrintLn "=> No cartridge? Everything reads $FFFF (open bus / pull-ups)"
	bra CART_END
.notFF:
	move.w a3,d0
	bne .notZero
	PrintLn "=> No cartridge? Everything reads $0000"
	bra CART_END
.notZero:
	Print "> Checksum s1=$"
	PrintLongHex d6
	Print " s2=$"
	PrintLongHex d7
	PrintLn ""
	PrintLn "  compare: python tools/cart_checksum.py <dump>.p1"
	Print "> Mirror: "
	move.l a4,d0
	cmp.l #$100000,d0
	bne .hasMirror
	PrintLn "none (1 MB of distinct data)"
	bra .bits
.hasMirror:
	lsr.l #8,d0
	lsr.l #2,d0					; bytes -> KB
	JsrA6 printDec
	PrintLn " KB: smaller P1 ROM, or the next address line stuck/open"
.bits:
	Print "> Data bits always 1: $"
	move.w a2,d0
	JsrA6 printWord
	Print ", always 0: $"
	move.w a3,d0
	not.w d0
	JsrA6 printWord
	PrintLn ""
	move.w a2,d0
	bne .stuck
	move.w a3,d0
	not.w d0
	bne .stuck
	PrintLn "=> No stuck data bit. Checksum: compare with a known good dump."
	bra CART_END
.stuck:
	PrintLn "=> FAIL: data bit(s) stuck (slot pin, cartridge PCB, buffer)."
	bra CART_END

; ------------------------------------------------------------------------
P2_TEST:
	PrintLn "Cartridge P2 window test ($200000-$2FFFFF, bank register $2FFFF0)"
	moveq #0,d5					; bank number
.bankLoop:
	move.w d5,(REG_CART_BANK).l
	lea (CART_P2_START).l,a0
	SumBlocks d6,64				; 64 x 16 words = 2 KB
	lea (CART_P2_START+$80000).l,a0
	moveq #0,d1
	move.w #64*16-1,d3
.bankMid:
	move.w (a0)+,d1				; and 2 KB in the middle of the window
	add.l d1,d6
	add.l d6,d7
	dbra d3,.bankMid
	tst.w d5
	bne .notBank0
	movea.l d7,a5				; a5 = bank 0 signature
.notBank0:
	Print "> Bank "
	moveq #0,d0
	move.w d5,d0
	JsrA6 printDec
	Print ": $"
	PrintLongHex d7
	cmpa.l d7,a5
	bne .differs
	tst.w d5
	beq .eol
	Print " (same as bank 0)"
	bra .eol
.differs:
	Print " (distinct)"
.eol:
	PrintLn ""
	addq.w #1,d5
	cmp.w #8,d5
	bne .bankLoop

	move.w #0,(REG_CART_BANK).l
	lea (CART_P2_START).l,a0
	SumBlocks d6,32768
	Print "> Bank 0 window checksum s1=$"
	PrintLongHex d6
	Print " s2=$"
	PrintLongHex d7
	PrintLn ""
	PrintLn "Distinct banks = extra MB of P ROM. All the same: no bank"
	PrintLn "switching (P ROM <= 2 MB) or a bank select fault."
	PrintLn "Real hardware without P2 data reads open bus; MAME mirrors P1."

CART_END:
	WriteEOT
	jmp WAIT_FOR_COMMAND
