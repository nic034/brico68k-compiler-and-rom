	include "inc/define.inc"

    global EXT_TEST_WRAM
    global EXT_TEST_BRAM
    global EXT_TEST_PRAM

	section	text

; =============================================================================
; Work RAM / Backup RAM / Palette RAM tests. No WRAM used, no stack.
;
; Per region (and per palette bank for PRAM):
;   1. Data bus walking 1 / walking 0 on the first word. After each write,
;      the complement is written to the NEXT word before reading back, so a
;      floating data bus (dead chip, open trace) can't fake a pass by
;      keeping the last written value on the bus.
;   2. Fill + verify with $0000, $FFFF, $AAAA, $5555 (stuck bits, adjacent
;      bit shorts inside a word).
;   3. Increment (address) test: each word holds its own address/2 -
;      detects address lines stuck/shorted/open (aliasing).
;   PRAM only: both palette banks are tested (the previous version only
;   tested whichever bank happened to be selected = half of the palette
;   RAM, and never the bank select line), then a bank independence test:
;   bank 0 = increment, bank 1 = its complement, both verified.
;
; On the first error the test stops and reports the address, the expected
; and read words, the bad bits (XOR) and which byte they are in. Each of
; these RAMs is two 8-bit chips (upper byte D8-D15, lower byte D0-D7): the
; byte tells which chip / side to look at.
;
; The fill/verify loops use long accesses unrolled x8. A long access is
; exactly two consecutive word bus cycles (same addresses, same data):
; identical test from the RAM's point of view, half the loop overhead. The
; BricoNeo host gives up after 3 s (Brico16Bits CommandExtension.cpp), so
; the extra coverage above had to be paid for with faster loops.
;
; SIMULATOR NOTE: tools/bricosim.py runs this code on Unicorn 2.1.4, whose
; M68K backend crashes (UC_ERR_EXCEPTION) on NOT.B/.W, NEG.B/.W, NEGX.W,
; EOR.W Dn,Dn, ADDA.W and the d8(An,Dn) addressing mode - each confirmed
; with an isolated one-instruction repro, while the same code runs fine in
; MAME. Exact 68000 equivalents that Unicorn handles are used instead
; (not.l / eor.l when only the low word matters, a pointer instead of an
; index). Zero effect on real hardware.
;
; Registers:  a5 = region start, a4 = region end (exclusive)
;             d7.b = 0 WRAM / 1 BRAM / 2 PRAM, bit 8 of d7 = palette bank
;             a3 = return address of RAM_SUITE, a2 = return of the helpers
;             Print/PrintA1 clobber a0/a1/d0/a6, printWord d0/d2/d4/a0/a6.
; =============================================================================

	; Return through a2 / a3 (a6 is used by Print/JsrA6)
	macro CallA2
		lea .\@(pc),a2
		jmp \1
.\@:
	endm

	macro CallA3
		lea .\@(pc),a3
		jmp \1
.\@:
	endm

EXT_TEST_WRAM:
	moveq #0,d7 ; Work test
	move.l #RAM_START, a5
	move.l #RAM_END, a4
	jmp START_TEST

EXT_TEST_BRAM:
	moveq #1,d7 ; Backup test
	move.l #BACKUP_RAM_START, a5
	move.l #BACKUP_RAM_END, a4
	jmp START_TEST

EXT_TEST_PRAM:
	moveq #2,d7 ; Palette test
	move.l #PALETTE_RAM_START, a5
	move.l #PALETTE_RAM_END, a4
	jmp START_TEST

START_TEST:
	WatchDog
	cmp.b #1, d7	; 1 is BRAM test
	beq .titleBRAM
	cmp.b #2, d7	; 2 is PRAM test
	beq .titlePRAM

	; --- WRAM ---
	move.l #RAMT_TXT_WRAM,a1
	PrintA1
	CallA3 RAM_SUITE
	jmp RAM_ALL_OK

	; --- BRAM ---
.titleBRAM
	move.l #RAMT_TXT_BRAM,a1
	PrintA1
	; The AES has no backup RAM at all ($D00000 is unmapped, the AES saves
	; to the memory card): reporting "Failure" there was a false fault.
	move.b REG_STATUS_B,d0
	btst #7,d0
	bne.s .bramIsMVS
	move.l #RAMT_TXT_BRAM_AES,a1
	PrintA1
	jmp RAM_END_OF_TEST
.bramIsMVS:
	move.b d0,REG_SRAMUNLOCK			; unprotect backup RAM (data ignored)
	CallA3 RAM_SUITE
	jmp RAM_ALL_OK

	; --- PRAM: both banks, then bank independence ---
.titlePRAM
	move.l #RAMT_TXT_PRAM,a1
	PrintA1
	move.b d0,REG_PALBANK0				; data ignored
	andi.w #$00ff,d7
	move.l #RAMT_TXT_BANK0,a1
	PrintA1
	CallA3 RAM_SUITE
	move.b d0,REG_PALBANK1
	ori.w #$0100,d7
	move.l #RAMT_TXT_BANK1,a1
	PrintA1
	CallA3 RAM_SUITE
	move.l #RAMT_TXT_BANKS,a1
	PrintA1
	move.b d0,REG_PALBANK0
	andi.w #$00ff,d7
	moveq #0,d3
	CallA2 FILL_INC
	move.b d0,REG_PALBANK1
	ori.w #$0100,d7
	moveq #-1,d3
	CallA2 FILL_INC
	move.b d0,REG_PALBANK0
	andi.w #$00ff,d7
	moveq #0,d3
	CallA2 CHECK_INC
	move.b d0,REG_PALBANK1
	ori.w #$0100,d7
	moveq #-1,d3
	CallA2 CHECK_INC
	move.b d0,REG_PALBANK0				; leave bank 0 selected
	andi.w #$00ff,d7
	move.l #RAMT_TXT_SUCCESS,a1
	PrintA1
	jmp RAM_ALL_OK

; -----------------------------------------------------------------------------
; RAM_SUITE: walking 1/0, 4 patterns, increment test on [a5,a4).
; Returns through a3. On error jumps to RAM_ERROR (never returns).
; -----------------------------------------------------------------------------
RAM_SUITE:
	; --- 1. data bus walking 1 / walking 0 on the first word ---
	Print "> Data bus walking 1/0 Test "
	moveq #1,d1
.walk:
	WatchDog
	move.w d1,d2
	not.l d2					; d2.w = complement (not.l: see SIMULATOR NOTE)
	move.w d1,(a5)
	move.w d2,2(a5)				; drive the bus with the opposite value
	move.w (a5),d6
	cmp.w d1,d6
	bne .walkErr1
	move.w d2,(a5)
	move.w d1,2(a5)
	move.w (a5),d6
	cmp.w d2,d6
	bne .walkErr0
	add.w d1,d1
	bne.s .walk
	move.l #RAMT_TXT_SUCCESS,a1
	PrintA1

	; --- 2. fill / verify patterns (pointer kept in d5: a0-a2/a6 are
	;     clobbered by the helpers and Print, a3-a5 are reserved) ---
	lea RAMT_PATTERNS(pc),a1
	move.l a1,d5
.patternLoop:
	movea.l d5,a1
	move.w (a1),d1
	Print "> "
	move.w d1,d0
	JsrA6 printWord
	Print " Test "
	move.w d1,d0
	swap d1
	move.w d0,d1				; d1 = pattern:pattern
	CallA2 FILL_L
	CallA2 CHECK_L
	move.l #RAMT_TXT_SUCCESS,a1
	PrintA1
	addq.l #2,d5
	cmpi.l #RAMT_PATTERNS+8,d5
	bne .patternLoop

	; --- 3. increment (address) test ---
	Print "> Increment Test "
	moveq #0,d3
	CallA2 FILL_INC
	CallA2 CHECK_INC
	move.l #RAMT_TXT_SUCCESS,a1
	PrintA1
	jmp (a3)

.walkErr1:
	movea.l a5,a1
	move.w d1,d5
	jmp RAM_ERROR
.walkErr0:
	movea.l a5,a1
	move.w d2,d5
	jmp RAM_ERROR

; -----------------------------------------------------------------------------
; Helpers (return through a2, never print)
; -----------------------------------------------------------------------------
; FILL_L: [a5,a4) <- long d1. Uses a1.
FILL_L:
	movea.l a5,a1
.loop:
	WatchDog
	rept 8
	move.l d1,(a1)+
	endr
	cmpa.l a4,a1
	bne.s .loop
	jmp (a2)

; CHECK_L: verify [a5,a4) == long d1. Uses a1, d2, d4.
CHECK_L:
	movea.l a5,a1
.loop:
	WatchDog
	rept 8
	move.l (a1)+,d2
	cmp.l d1,d2
	bne.s .mismatch
	endr
	cmpa.l a4,a1
	bne.s .loop
	jmp (a2)
.mismatch:
	move.l d1,d4
	jmp LONG_MISMATCH

; Increment pattern: word at address A holds (A & $FFFF) >> 1, XOR d3
; (d3 = 0 or $FFFFFFFF). Same values as the original test.
; FILL_INC uses a1, d1, d2. CHECK_INC uses a1, d1, d2, d4.
FILL_INC:
	movea.l a5,a1
	move.w a1,d1
	lsr.w #1,d1
	move.w d1,d2
	addq.w #1,d2
	swap d1
	move.w d2,d1				; d1 = v : v+1
.loop:
	WatchDog
	move.l d1,d2
	eor.l d3,d2
	move.l d2,(a1)+
	addi.l #$00020002,d1		; never carries: v+1 <= $7FFF
	cmpa.l a4,a1
	bne.s .loop
	jmp (a2)

CHECK_INC:
	movea.l a5,a1
	move.w a1,d1
	lsr.w #1,d1
	move.w d1,d2
	addq.w #1,d2
	swap d1
	move.w d2,d1
.loop:
	WatchDog
	move.l d1,d4
	eor.l d3,d4					; d4 = expected long
	move.l (a1)+,d2
	cmp.l d4,d2
	bne LONG_MISMATCH
	addi.l #$00020002,d1
	cmpa.l a4,a1
	bne.s .loop
	jmp (a2)

; A long compare failed: expected long d4, read long d2, a1 = address
; after the long. Pick the word that differs (high word is at the lower
; address on the 68000) and report it.
LONG_MISMATCH:
	subq.l #4,a1
	move.l d4,d5
	move.l d2,d6
	swap d5
	swap d6
	cmp.w d5,d6
	bne.s RAM_ERROR				; first word differs
	swap d5
	swap d6
	addq.l #2,a1				; second word differs

; -----------------------------------------------------------------------------
; RAM_ERROR: a1 = failing word address, d5 = expected word, d6 = read word.
; -----------------------------------------------------------------------------
RAM_ERROR:
	movea.l a1,a2				; a1 is clobbered by Print
	PrintLn "Failure"
	Print "  Address  : $"
	move.l a2,d0
	swap d0
	JsrA6 printWord
	move.l a2,d0
	JsrA6 printWord
	PrintLn ""
	Print "  Expected : $"
	move.w d5,d0
	JsrA6 printWord
	PrintLn ""
	Print "  Read     : $"
	move.w d6,d0
	JsrA6 printWord
	PrintLn ""
	Print "  Bad bits : $"
	move.w d5,d1
	eor.l d6,d1					; d1.w = bad bits (eor.l: see SIMULATOR NOTE)
	move.w d1,d0
	JsrA6 printWord
	move.l d1,d3
	andi.l #$000000ff,d3		; lower byte bad?
	beq.s .upperOnly
	andi.l #$0000ff00,d1		; upper byte bad too?
	beq.s .lowerOnly
	PrintLn " (BOTH bytes: D0-D7 and D8-D15)"
	bra.s .bank
.upperOnly:
	PrintLn " (upper byte: D8-D15)"
	bra.s .bank
.lowerOnly:
	PrintLn " (lower byte: D0-D7)"
.bank:
	cmp.b #2,d7
	bne.s .final
	btst #8,d7
	bne.s .bank1
	PrintLn "  Palette bank : 0"
	bra.s .final
.bank1:
	PrintLn "  Palette bank : 1"
.final:
	move.l #RAMT_TXT_FINAL,a1
	PrintA1
	move.l #RAMT_TXT_FAILURE,a1
	PrintA1
	jmp RAM_END_OF_TEST

RAM_ALL_OK:
	move.l #RAMT_TXT_FINAL,a1
	PrintA1
	move.l #RAMT_TXT_SUCCESS,a1
	PrintA1

RAM_END_OF_TEST:
	move.b d0,REG_SRAMLOCK				; protect backup RAM (data ignored)
	move.b d0,REG_PALBANK0				; palette bank 0, as after the PRAM test
    ; End of transmission
    WriteEOT
    ; Jump back to the command loop
	jmp WAIT_FOR_COMMAND

RAMT_PATTERNS:
	dc.w $0000,$FFFF,$AAAA,$5555
RAMT_TXT_WRAM:
	dc.b "Work RAM (WRAM) test",10,0
RAMT_TXT_BRAM:
	dc.b "Backup RAM (BRAM) test - DESTRUCTIVE: erases the MVS backup RAM (bookkeeping, settings, scores)",10,0
RAMT_TXT_BRAM_AES:
	dc.b "  N/A: AES detected (STATUS_B bit7=0) - the AES has no backup RAM ($D00000 unmapped, saves go to the memory card)",10
	dc.b "=> Test N/A (AES)",10,0
RAMT_TXT_PRAM:
	dc.b "Palette RAM (PRAM) test - both banks",10,0
RAMT_TXT_BANK0:
	dc.b "-- Palette bank 0 --",10,0
RAMT_TXT_BANK1:
	dc.b "-- Palette bank 1 --",10,0
RAMT_TXT_BANKS:
	dc.b "> Bank 0 / bank 1 independence Test ",0
RAMT_TXT_SUCCESS:
	dc.b "Success",10,0
RAMT_TXT_FAILURE:
	dc.b "Failure",10,0
RAMT_TXT_FINAL:
	dc.b "=> Test ",0
	even
