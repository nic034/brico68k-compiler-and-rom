	include "inc/define.inc"

	global EXT_CART_TEST

	section text

; ------------------------------------------------------------------------
; CartTest - cartridge P bus data lines D0-D15 of a game cartridge, read only.
; (CartDiag, ExtCartDiag.s: the same bus on the diagnostic PROG board, with writes.)
;
; P1 ($000000-$0FFFFF, /ROMOE, wiki "Signals"): every cartridge holds the
; same 61-word security code, at the address in the header long $182
; (wiki "68k program header", "Security code": the system ROM compares it
; word per word). The words below were checked against the system ROM's own
; copy (neo-epo.bin $C12C7C, sp-s2.sp1 $C146A2): the wiki listing has a typo
; at word 25 ($0606 for $6606). Every data bit is 1 in some words and 0 in
; others, so each line is judged both ways:
;   reads 0 in every word expecting 1 -> stuck at 0 or open
;   reads 1 in every word expecting 0 -> stuck at 1 or open
;   wrong in some words only          -> bad contact, or short between lines
; A bad line also corrupts the pointer at $182 (one data line can change two
; pointer bits: one in each word): the code is looked for at the pointer and
; at the pointer with any one or two of its bits A1-A19 flipped, the best
; match wins. One bad line is always found; two, when they change at most
; two pointer bits; more than five lines are not reported as a code.
;
; P2 ($200000-$2FFFFF, /PORTOEU): content depends on the game, so only
; activity is checked: every data line must take both levels over the
; window (sampled every 16 bytes). Bank 0 is mapped at reset and nothing is
; written (wiki "Bankswitching"). $2FE000-$2FFFFF is never read: NEO-SMA
; carts answer there (protection value at $2FE447, random number registers
; that step on each read, wiki "NEO-SMA"). Tested when the header P ROM size
; ($10A) is over 1 MB, or with P1=1.
;
; Header ($100 "NEO-GEO", $108 NGH number, $10A P ROM size) is printed as
; read: a bad data line changes it too.
; CartTest never writes. The diagnostic PROG board (SRAM) has its own
; command, CartDiag (ExtCartDiag.s; OE_DEAD is shared from there).
; P1 without the security code: its activity is sampled like P2 (a dead
; window, or lines that never toggle; else an address line or a strobe).
; No WRAM, no stack. ROM mode < 0.5 s.
; ------------------------------------------------------------------------
SEC_N       equ 61
P1_END      equ $100000
P2_START    equ $200000
P2_STOP     equ $2FE000			; NEO-SMA registers above
FOUND_MAX   equ 5				; more bad lines than this: not the security code

EXT_CART_TEST:
	move.l (BRICO_COMMAND_PARAM_1).l,d0		; parameters first: cleared after 1 ms
	movea.l d0,a5							; P1 = 1: test P2 whatever the header says
	PrintLn "Cartridge P bus data lines D0-D15"

	; --- header ----------------------------------------------------------
	Print "Header   "
	cmp.l #$4E454F2D,($000100).l	; "NEO-"
	bne .hdrBad
	cmp.w #$4745,($000104).l		; "GE"
	bne .hdrBad
	cmp.b #$4F,($000106).l			; "O"
	bne .hdrBad
	Print "NEO-GEO, NGH "
	move.w ($000108).l,d0
	JsrA6 printWord
	Print ", P ROM size $"
	move.w ($00010A).l,d0
	JsrA6 printWord
	move.w ($00010C).l,d0
	JsrA6 printWord
	PrintLn " (as read)"
	bra .secSearch
.hdrBad:
	Print "no NEO-GEO at $100, read $"
	move.w ($000100).l,d0
	JsrA6 printWord
	Print " $"
	move.w ($000102).l,d0
	JsrA6 printWord
	Print " $"
	move.w ($000104).l,d0
	JsrA6 printWord
	Print " $"
	move.w ($000106).l,d0
	JsrA6 printWord
	NlPrintLn "  (diag PROG board: use CartDiag)"

	; no header: nothing is written here (the diagnostic PROG board has its own
	; command, CartDiag)

	; --- P1: find the security code ----------------------------------------
	; a5 bit 31 = P1 option (kept), a3 = best address, a4 = best count,
	; a2 = k2<<8 | k1: the pointer bits flipped (bit 0 and bit 20 are masked
	; off, so k1 = 0 or k2 = 20 means "no flip"): every candidate with 0, 1
	; or 2 of the bits A1-A19 flipped, 210 of them. The pointer as read comes
	; first and wins a tie (a P1 chip under 1 MB is mirrored: same count).
	macro CandidateD0
		move.l a5,d0
		move.l a2,d1
		bchg d1,d0				; k1 (Dn bit number: modulo 32)
		lsr.w #8,d1
		bchg d1,d0				; k2
		and.l #P1_END-2,d0
	endm
.secSearch:
	move.l a5,d0				; P1 option -> bit 31 of the pointer register
	beq.s .noOpt
	moveq #1,d0
	ror.l #1,d0					; $80000000
.noOpt:
	move.l ($000182).l,d1
	and.l #P1_END-2,d1			; in P1, even (bits 20-31 can only be bad lines)
	or.l d1,d0
	movea.l d0,a5
	movea.l #$FFFF,a4
	suba.l a3,a3
	movea.w #20<<8,a2			; k1 = 0, k2 = 20: the pointer as read
.cand:
	WatchDog
	CandidateD0
	cmp.l #$000100,d0			; not in the vector table
	blo.s .nextCand
	cmp.l #P1_END-2*SEC_N,d0
	bhi.s .nextCand
	movea.l d0,a0
	JsrA6 secCmp
	cmp.l a4,d0
	bhs.s .nextCand
	movea.l d0,a4				; best so far
	CandidateD0
	movea.l d0,a3
.nextCand:						; k2 = 20 down to k1 + 1, then k1 + 1
	move.l a2,d1
	sub.w #$0100,d1				; k2 - 1
	move.w d1,d0
	lsr.w #8,d0
	cmp.b d1,d0					; k2 = k1: this k1 is done
	bne.s .setCand
	addq.b #1,d1
	cmp.b #20,d1
	beq.s .candDone
	and.w #$00FF,d1
	or.w #20<<8,d1
.setCand:
	movea.w d1,a2
	bra .cand
.candDone:

	cmpa.w #FOUND_MAX,a4
	bls	.found
	Print "P1       no security code. Activity $000100-$0FFFFF"
	movea.l #$000100,a0
	movea.l #P1_END,a2
	lea .p1Act(pc),a1
	jmp PACT
.p1Act:
	moveq #-1,d0				; P1 result: -1 nothing answers,
	cmp.l d0,d5
	beq.s .p1Dead
	moveq #-2,d0				; -2 answers, content wrong
.p1Dead:
	movea.l d0,a4
	bra .p2
.found:
	Print "P1       security code at $"
	move.l a3,d0
	swap d0
	JsrA6 printWord
	move.l a3,d0
	JsrA6 printWord
	move.l a3,d0
	cmp.l ($000182).l,d0		; the pointer as read
	beq.s .ptrOk
	Print " (pointer at $182 reads wrong)"
.ptrOk:
	PrintLn ""
	movea.l a3,a0
	JsrA6 secCmp				; d4 low, d5 high, d6 seen 1, d7 seen 0
	swap d5
	move.w d4,d5				; d5 = high:low
	swap d7
	move.w d6,d7				; d7 = seen0:seen1
	move.l d7,d6
	move.l d5,d0
	swap d0
	or.w d5,d0
	and.l #$FFFF,d0
	movea.l d0,a4				; P1 bad lines
	tst.w d0
	bne.s .p1Lines
	PrintLn "         61 words exact: D0-D15 OK on P1"
	bra .p2
.p1Lines:
	moveq #0,d7
.p1Line:
	move.l d5,d4
	swap d4
	or.w d5,d4
	btst d7,d4
	beq .p1Next
	Print "         D"
	moveq #0,d0
	move.w d7,d0
	JsrA6 printDec
	cmp.w #10,d7
	bhs.s .p1Pad
	Print " "
.p1Pad:
	move.w d7,d1
	add.w #16,d1
	btst d7,d5					; low: read 0 where 1 expected
	beq.s .p1NotLow
	btst d1,d5
	bne	.p1Some				; also high: wrong both ways
	btst d7,d6					; ever read 1 where 1 expected?
	bne	.p1Some
	PrintLn " reads 0 for every 1 expected: stuck at 0 or open"
	bra	.p1Next
.p1NotLow:
	btst d1,d6					; ever read 0 where 0 expected?
	bne.s .p1Some
	PrintLn " reads 1 for every 0 expected: stuck at 1 or open"
	bra.s .p1Next
.p1Some:
	PrintLn " wrong in some words: bad contact, or short to another line"
.p1Next:
	addq.w #1,d7
	cmp.w #16,d7
	bne .p1Line

	; --- P2: activity -------------------------------------------------------
	; a4 = P1 bad lines ($FFFFFFFF: not found), a5 bit 31 = P1 option
.p2:
	move.l ($00010A).l,d0		; header P ROM size, as read
	cmp.l #P1_END,d0
	bhi .p2Size
	move.l a5,d1
	bmi .p2Forced
	Print "P2       not tested: header P ROM size $"
	move.l ($00010A).l,d0
	swap d0
	JsrA6 printWord
	move.w ($00010C).l,d0
	JsrA6 printWord
	PrintLn " (P1=1 forces it)"
	moveq #0,d5					; P2 bad lines: none
	moveq #0,d7					; bit 1 = P2 tested: no
	bra .verdict
.p2Forced:
	move.l #P2_STOP,d0
	bra.s .p2Go
.p2Size:
	cmp.l #P1_END+P2_STOP-P2_START,d0	; size as read can be anything: no overflow
	bhs.s .p2Forced
	add.l #P2_START-P1_END,d0
.p2Go:
	movea.l d0,a2				; end of the window
	Print "P2       activity $200000-$"
	move.l a2,d0
	subq.l #1,d0
	swap d0
	JsrA6 printWord
	move.l a2,d0
	subq.l #1,d0
	JsrA6 printWord
	movea.l #P2_START,a0
	lea .p2Act(pc),a1
	jmp PACT
.p2Act:
	moveq #2,d7					; bit 1 = P2 tested

	; --- verdict --------------------------------------------------------------
	; a4 = P1 bad lines (-1 nothing answers, -2 answers but no security
	; code), d5 = P2 bad lines (-1 every word the same, 0 also when not
	; tested), d7 bit 1 = P2 tested
.verdict:
	move.l a4,d0
	cmp.l #-1,d0
	bne .vAnswers
	btst #1,d7
	beq.s .vNone
	cmp.l d0,d5
	beq.s .vNone
	PrintLn "=> Test failure: P2 answers, P1 not: /ROMOE, P1 chip or lines"
	bra .end
.vNone:
	PrintLn "=> CHECK: no cartridge seen. Clean the edge, try another one"
	bra .end
.vAnswers:
	cmp.l #-2,d0
	bne .vP1
	PrintLn "=> Test failure: P1 reads wrong: lines above, slot A1-A19,"
	PrintLn "   /ROMOEU-L or P1 chip (the diag PROG board tests A1-A19)"
	bra .end
.vP1:
	tst.w d0
	bne .vP1Bad
	tst.w d5
	bne.s .vP2Only
	PrintLn "=> Test success: P1 security code exact, P2 lines active or untested"
	bra .end
.vP2Only:
	cmp.l #-1,d5
	beq.s .vP2Dead
	PrintLn "=> Test failure: P2 only (P1 fine): the P2 chip or its traces"
	bra .end
.vP2Dead:
	PrintLn "=> CHECK: P2 does not answer while P1 is fine (P2 chip, /PORTOE)"
	bra .end
.vP1Bad:
	btst #1,d7
	beq .vP1Only
	cmp.l #-1,d5				; P2 does not answer: nothing to compare
	beq .vP1Only
	and.w d5,d0
	beq .vP1Only
	PrintLn "=> Test failure: same lines on P1 and P2: cart edge, slot or console"
	PrintLn "   traces. Another cartridge: same lines = console"
	bra .end
.vP1Only:
	PrintLn "=> Test failure: P1 lines: slot, cart edge or P1 chip. Another"
	PrintLn "   cartridge: same lines = console side"
.end:
	jmp EOT_AND_WAIT

; ------------------------------------------------------------------------
; PACT: data line activity of a window, one word every 16 bytes: every
; line must take both levels. In: a0 = start, a2 = end (exclusive), a1 =
; return (Print and printDec keep a1). Prints the sample count, then "every
; word reads $xxxx", or the lines that never toggle, or "all take both".
; Out: d5 = lines that never toggle (-1: every word the same).
; Destroys d0-d7, a0, a2, a6.
; ------------------------------------------------------------------------
PACT:
	move.w (a0),d3				; first word
	moveq #0,d7					; OR: bits seen at 1
	moveq #-1,d6				; AND: bits always 1
	moveq #0,d4					; 1 = some word differs from the first
	moveq #0,d5					; sample count
.loop:
	move.w (a0),d0
	or.w d0,d7
	and.w d0,d6
	cmp.w d3,d0
	beq.s .same
	moveq #1,d4
.same:
	addq.l #1,d5
	lea 16(a0),a0
	move.w a0,d0
	and.w #$7FF0,d0
	bne.s .noKick
	WatchDog
.noKick:
	cmpa.l a2,a0
	blo.s .loop
	Print ", "
	move.l d5,d0
	JsrA6 printDec				; keeps d4-d7
	PrintLn " words"
	tst.w d4
	bne.s .varies
	Print "         every word reads $"
	move.w d6,d0
	JsrA6 printWord
	PrintLn ": nothing answers (chip, output enable), or blank"
	moveq #-1,d5
	jmp (a1)
.varies:
	move.l d7,d5
	not.l d5					; bits never 1
	or.l d6,d5					; + bits never 0
	and.l #$FFFF,d5
	bne.s .lines
	PrintLn "         D0-D15 all take both levels"
	jmp (a1)
.lines:
	moveq #0,d7
.line:
	btst d7,d5
	beq .next
	Print "         D"
	moveq #0,d0
	move.w d7,d0
	JsrA6 printDec
	cmp.w #10,d7
	bhs.s .pad
	Print " "
.pad:
	btst d7,d6
	bne.s .always1
	PrintLn " never 1: stuck at 0 or open"
	bra.s .next
.always1:
	PrintLn " never 0: stuck at 1 or open"
.next:
	addq.w #1,d7
	cmp.w #16,d7
	bne .line
	jmp (a1)


; ------------------------------------------------------------------------
; secCmp: compares the 61 words at a0 with the security code.
; Out: d4 = bits read 0 where 1 was expected (any word)
;      d5 = bits read 1 where 0 was expected (any word)
;      d6 = bits read 1 where 1 was expected (any word)
;      d7 = bits read 0 where 0 was expected (any word)
;      d0 = number of wrong lines (bits set in d4 | d5)
; Destroys d0-d7, a0, a1.
; ------------------------------------------------------------------------
secCmp_JsrA6:
	moveq #0,d4
	moveq #0,d5
	moveq #0,d6
	moveq #0,d7
	lea SEC_CODE(pc),a1
	moveq #SEC_N-1,d3
.word:
	move.w (a0)+,d0				; read
	move.w (a1)+,d1				; expected
	move.w d1,d2
	and.w d0,d2
	or.w d2,d6					; 1 read as 1
	move.w d1,d2
	or.w d0,d2
	not.w d2
	or.w d2,d7					; 0 read as 0
	eor.w d0,d1					; wrong bits
	move.w d1,d2
	and.w d0,d2
	or.w d2,d5					; wrong and read 1
	eor.w d2,d1
	or.w d1,d4					; wrong and read 0
	dbra d3,.word
	move.w d4,d1
	or.w d5,d1
	moveq #0,d0
.count:
	lsr.w #1,d1
	bcc.s .zero
	addq.w #1,d0
.zero:
	tst.w d1
	bne.s .count
	RtsA6


; Security code: 61 words, as in the system ROM (see the header comment)
SEC_CODE:
	dc.w $7600,$4A6D,$0A14,$6600,$003C,$206D,$0A04,$3E2D,$0A08,$13C0
	dc.w $0030,$0001,$3210,$0C01,$00FF,$671A,$3028,$0002,$B02D,$0ACE
	dc.w $6610,$3028,$0004,$B02D,$0ACF,$6606,$B22D,$0AD0,$6708,$5088
	dc.w $51CF,$FFD4,$3607,$4E75,$206D,$0A04,$3E2D,$0A08,$3210,$E049
	dc.w $0C01,$00FF,$671A,$3010,$B02D,$0ACE,$6612,$3028,$0002,$E048
	dc.w $B02D,$0ACF,$6606,$B22D,$0AD0,$6708,$5888,$51CF,$FFD8,$3607
	dc.w $4E75
