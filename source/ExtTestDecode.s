	include "inc/define.inc"

	global EXT_TEST_DECODE

	section text

; ------------------------------------------------------------------------
; TestDecode - address decoding of the RAMs and of the LSPC registers.
;
; The March tests of TestWRAM / TestPRAM / TestVRAM walk the address lines
; the RAM chips are wired to (A1-A15 for WRAM, A1-A12 for one palette bank).
; The upper lines (A16-A23) never reach the chips: the decoders (NEO-C1,
; NEO-E0, NEO-D0, 74xx) use them to choose which chip answers, and ignore
; some of them on purpose, so a RAM answers at several addresses (mirrors):
;
;   Work RAM       $100000-$10FFFF, mirrored up to $1FFFFF   A16-A19 ignored
;   Palette RAM    $400000-$401FFF, mirrored up to $7FFFFF   A13-A21 ignored
;                  (A1-A12 pick the colour, the bank comes from the latch)
;   LSPC registers $3C0000-$3C000F, mirrored up to $3DFFFF   A4-A16 ignored
;                  (neogeodev wiki "Memory mapped registers", mask $FE0001)
;
; The ranges are those of the neogeodev wiki (NEO-C1: WRU/WRL/WWU/WWL $100000-
; $1FFFFF, PAL $400000-$7FFFFF, LSPOE/LSPWE $3C0000-$3DFFFF; the wiki itself says
; its decode masks, $FE0001 for the LSPC, are not verified) and of the emulator's
; model. Not checked on a real console yet: a healthy board that reports a
; mirror means a wrong assumption here, not a fault.
;
; For every line n of a region: a word is written at the base address and
; must read back at base + 2^n, then another word is written at base + 2^n
; and must read back at the base. A line that fails is one the decoder does
; not ignore (or ignores badly): "FAIL: not a mirror on A17" = this address
; answers somewhere else. A base word that holds no value is a bad RAM, not
; a decoder (d1 = -1). Then the two RAMs are written one after the other, in
; both orders: a write to one must not change the other (a decoder output
; that selects two chips at once, as a bus fight).
;
; Every word is saved and put back: nothing is lost (the palette word is
; colour 3072, in the middle of the table). The LSPC alias writes go to
; REG_VRAMMOD's mirrors: on a console where a mirror is a different register
; the pattern lands there (a harmless one: it is rewritten by the next test).
; No WRAM, no stack: registers only. About 2 ms, nearly all of it printing.
; d7 <> 0 when something failed: bit n = group n (hint line), bit 3 = isolation, bit 4 = a bad RAM.
; ------------------------------------------------------------------------
DEC_WRAM equ $10F800		; above the stack ($10F300), below the words of TestWatchdog
DEC_PAL  equ $401800		; palette 192, colour 0: same A1-A12 as DEC_WRAM (a bus fight needs the same low lines)

	; One record per region: base word, first and last alias line, title (32 bytes)
	macro Group
		dc.l \1
		dc.b \2,\3
.\@s:
		dc.b \4,0
.\@e:
		ds.b 32-(.\@e-.\@s)
	endm

EXT_TEST_DECODE:
	moveq #0,d7
	move.b d0,(REG_PALBANK0).l		; bank 0 (data ignored): the bank is the latch, not a line
	PrintLn "Address decoding: RAM and LSPC mirrors"
	lea .groups(pc),a2
	lea .groupsEnd(pc),a4
	movea.w #1,a5				; a5 = the bit of the group (verdict puts it in d7 on failure)
.g:
	lea 6(a2),a1
	PrintA1						; the title first: it destroys a0
	movea.l (a2)+,a0
	moveq #0,d4
	move.b (a2)+,d4
	moveq #0,d5
	move.b (a2)+,d5
	lea 32(a2),a2
	JsrA6 aliasTest
	JsrA6 verdict
	adda.l a5,a5
	cmpa.l a4,a2
	bne.s .g

	Print "> WRAM / palette independent   "
	lea (DEC_WRAM).l,a0
	lea (DEC_PAL).l,a1
	JsrA6 isolate
	tst.l d1
	beq.s .isoOk
	ori.w #8,d7
	PrintLn "FAIL: a word lost or changed by the other"
	bra.s .end
.isoOk:
	PrintLn "OK"
.end:
	tst.w d7
	beq .success
	btst #0,d7
	beq.s .h1
	PrintLn "  WRAM: U1/U2 see A1-A15; NEO-C1 U4 sees A17-A23, not A16 (AES)"
.h1:
	btst #1,d7
	beq.s .h2
	PrintLn "  Palette: NEO-C1 U4 PAL -> NEO-G0 U5; PA0-PA11 from NEO-B1 U13 (AES)"
.h2:
	btst #2,d7
	beq.s .h3
	PrintLn "  LSPC regs: NEO-C1 U4 LSPOE/LSPWE -> LSPC2 U21, which sees only A1-A3"
.h3:
	btst #3,d7
	beq.s .h4
	PrintLn "  Two RAMs on at once: NEO-C1 U4 WRx/WWx (WRAM), PAL -> NEO-G0 (palette)"
.h4:
	PrintText
	dc.b "  Next: TestChip",10
	dc.b "=> Test failure",10,0
	even
	jmp EOT_AND_WAIT
.success:
	PrintLn "=> Test success"
	jmp EOT_AND_WAIT

.groups:
	Group DEC_WRAM,16,19,"> Work RAM    $100000-$1FFFFF  "
	Group DEC_PAL,13,21,"> Palette RAM $400000-$7FFFFF  "
	Group REG_VRAMMOD,4,16,"> LSPC regs   $3C0000-$3DFFFF  "
.groupsEnd:

; a0 = word address (base), d4 = first and d5 = last address line to use as
; an alias bit. Out: d1.l = bit n at 1 when base + 2^n is not the same word,
; or -1 when the base word does not even hold a value (a bad RAM, not a
; decoder: TestWRAM, TestPRAM, TestLSPC say more). The word at the base is
; put back. Destroys d0, d2, d3, d6, a1.
aliasTest_JsrA6:
	moveq #0,d1
	move.w (a0),d6
	move.w #$A5C3,d3
	move.w d3,(a0)
	cmp.w (a0),d3
	bne.s .self
	not.w d3
	move.w d3,(a0)
	cmp.w (a0),d3
	bne.s .self
	move.w d4,d2
.n:
	moveq #1,d0
	lsl.l d2,d0
	lea (a0,d0.l),a1
	move.w #$A5C3,d3
	move.w d3,(a0)
	cmp.w (a1),d3				; written at the base, read at the alias
	bne.s .bad
	not.w d3
	move.w d3,(a1)
	cmp.w (a0),d3				; written at the alias, read at the base
	beq.s .ok
.bad:
	bset d2,d1
.ok:
	addq.w #1,d2
	cmp.w d5,d2
	bls.s .n
.end:
	move.w d6,(a0)
	RtsA6
.self:
	moveq #-1,d1
	bra.s .end

; d1.l = failing alias lines (0 = OK, -1 = the word itself is bad): prints the
; verdict, sets d7 on failure. Destroys d0-d4, a0, a1, a3, a6.
verdict_JsrA6:
	movea.l a6,a3
	tst.l d1
	bmi.s .self
	bne.s .fail
	PrintLn "OK"
	jmp (a3)
.self:
	ori.w #16,d7				; failure with no decoder hint (bit 4)
	PrintLn "FAIL: the word itself is bad (RAM test)"
	jmp (a3)
.fail:
	move.w a5,d0
	or.w d0,d7
	Print "FAIL: not a mirror on"
	moveq #'A',d3
	JsrA6 printBitList
	PrintLn ""
	jmp (a3)

; a0, a1 = words in two different RAMs. Out: d1 <> 0 when a write to one
; changed the other, in either order (a bus fight leaves both words wrong).
; Both words are put back. Destroys d2-d4, a0, a1 swapped twice (unchanged).
isolate_JsrA6:
	moveq #0,d1
	move.w (a0),d2
	move.w (a1),d3
	moveq #1,d4
.p:
	move.w #$A5C3,(a0)
	move.w #$5A3C,(a1)
	cmpi.w #$A5C3,(a0)
	bne.s .bad
	cmpi.w #$5A3C,(a1)
	beq.s .ok
.bad:
	moveq #1,d1
.ok:
	exg a0,a1					; second pass: the other order
	dbra d4,.p
	move.w d2,(a0)
	move.w d3,(a1)
	RtsA6
