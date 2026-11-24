	include "inc/define.inc"

	global EXT_STRESS_RAM

	section text

; ------------------------------------------------------------------------
; StressRam - every RAM the 68000 can reach on an AES, one pass, a new
; random pattern each pass: "*StressRam" in the BricoNeo console (loop mode)
; repeats it until stopped there, one report per pass (the rule: a test makes
; ONE pass and reports, the console repeats).
;   WRAM      $100000-$10FFFF  32768 words
;   Palette   $400000-$401FFF  bank 0 and bank 1, 2 x 4096 words
;   VRAM      $0000-$7FFF slow, $8000-$87FF fast but $8600-$86FF (sprite
;             lists, rewritten by the LSPC2), through REG_VRAMADD/RW
; Each: a 16-bit LFSR pattern written then read back, as is when the seed
; is even, complemented when it is odd (one polarity a pass keeps a pass at
; ~1.1 s, the 3 s EOT limit; the loop covers both). The seed mixes the line
; counter and the last WRAM word of the previous pass: each pass differs.
; On an error: how many words, the first one (address, expected, read, bad
; bits). No WRAM, no stack (WRAM is under
; test); the screen shows the garbage while VRAM / palette are tested, then
; is cleared. Not covered: Z80 RAM (no 68000 path), memory card, MVS
; backup RAM (TestBRAM).
; ------------------------------------------------------------------------
SR_WRAM  equ 16					; d7 high word: failed regions
SR_PAL   equ 17
SR_VRAM  equ 18

	macro LfsrD0				; 16-bit Galois LFSR step, taps $B400
		lsr.w #1,d0
		bcc.s .\@n
		eor.w #$B400,d0
.\@n:
	endm

EXT_STRESS_RAM:
	move.w ($10FFFE).l,d7			; seed: the last WRAM word the previous pass
	move.w (REG_LSPCMODE).l,d0		; wrote (its own seed's sequence), mixed with
	eor.w d0,d7						; the line counter: each pass differs
	eor.w #$ACE1,d7
	bne.s .seed
	moveq #1,d7
.seed:
	and.l #$0000FFFF,d7
	Print "StressRam pass, seed $"
	move.w d7,d0
	JsrA6 printWord

	; --- WRAM -------------------------------------------------------------
	lea $100000,a2
	move.w #32768-1,d6
	JsrA6 stressMem
	NlPrint "WRAM     $100000-$10FFFF  "
	tst.l d4
	beq.s .wramOk
	bset #SR_WRAM,d7
	JsrA6 srFail
	bra.s .pal
.wramOk:
	PrintLn "OK"

	; --- palette RAM, both banks ---------------------------------------
.pal:
	move.b d0,(REG_PALBANK1).l
	lea $400000,a2
	move.w #4096-1,d6
	JsrA6 stressMem
	move.b d0,(REG_PALBANK0).l
	Print "Palette  bank 1           "
	tst.l d4
	beq.s .pal1Ok
	bset #SR_PAL,d7
	JsrA6 srFail
	bra.s .pal0
.pal1Ok:
	PrintLn "OK"
.pal0:
	lea $400000,a2
	move.w #4096-1,d6
	JsrA6 stressMem
	Print "Palette  bank 0           "
	tst.l d4
	beq.s .pal0Ok
	bset #SR_PAL,d7
	JsrA6 srFail
	bra.s .vram
.pal0Ok:
	PrintLn "OK"

	; --- VRAM ---------------------------------------------------------------
.vram:
	JsrA6 stressVram
	Print "VRAM     $0000-$87FF (-$86xx) "
	tst.l d4
	beq.s .vramOk
	bset #SR_VRAM,d7
	JsrA6 srFail
	bra.s .end
.vramOk:
	PrintLn "OK"
.end:
	JsrA6 screenBlank				; sprites off, fix map tile $20
	lea (PALETTE_0).l,a0			; palette 0 black: no garbage colours left
	move.w #16-1,d0
.black:
	move.w #$8000,(a0)+
	dbra d0,.black
	move.w #$8000,(PALETTE_BACKDROP).l
	swap d7
	tst.w d7
	bne.s .bad
	PrintLn "=> Test success"
	jmp EOT_AND_WAIT
.bad:
	PrintLn "=> Test failure (the first bad word of each region above)"
	jmp EOT_AND_WAIT

; ------------------------------------------------------------------------
; srFail: "FAIL n word(s)" then the first one (printMismatchL).
; In: d4 = count, a4 = address, a5 = expected, d3 = read. Keeps d7.
; ------------------------------------------------------------------------
srFail_JsrA6:
	movea.l a6,a1					; printMismatchL keeps d5, d7, a4 only:
	exg a1,d5						; our link goes in d5
	move.w d3,d6					; the read word: printDec destroys d0-d3
	Print "FAIL "
	move.l d4,d0
	JsrA6 printDec
	PrintLn " word(s), the first:"
	JsrA6 printMismatchL			; a4 address, a5 expected, d6 read
	movea.l d5,a6
	RtsA6

; ------------------------------------------------------------------------
; stressMem: a2 = first word, d6 = words - 1, d7.w = seed. The pattern
; (complemented if the seed is odd): write all, read all. Out: d4 = bad words, a4 / a5 / d3
; = first bad address / expected / read. Destroys d0-d2, d5, a1.
; ------------------------------------------------------------------------
stressMem_JsrA6:
	moveq #0,d4
	moveq #0,d5						; the polarity: the seed's bit 0
	btst #0,d7
	beq.s .pol
	moveq #-1,d5
.pol:
	move.w d7,d0
	movea.l a2,a1
	move.w d6,d1
.write:
	LfsrD0
	move.w d0,d2
	eor.w d5,d2
	move.w d2,(a1)+
	WatchDog
	dbra d1,.write
	move.w d7,d0
	movea.l a2,a1
	move.w d6,d1
.read:
	LfsrD0
	move.w d0,d2
	eor.w d5,d2
	cmp.w (a1)+,d2
	bne.s .bad
.next:
	WatchDog
	dbra d1,.read
	RtsA6
.bad:
	tst.l d4
	bne.s .count
	lea -2(a1),a4
	movea.w d2,a5
	move.w -2(a1),d3
.count:
	addq.l #1,d4
	bra.s .next

; ------------------------------------------------------------------------
; stressVram: the same on VRAM $0000-$87FF (slow 32768 + fast 1792 words:
; $8600-$86FF skipped, the LSPC2 writes its sprite lists there while it draws),
; with the access delays of TestVRAM (>= 16 cycles address -> read, write
; -> write / address: the loop's own instructions). The address is written again at $8000: the
; auto-increment wraps inside the slow VRAM. Out as stressMem (a4 = VRAM
; word address).
; Destroys d0-d2, d5, a0, a1.
; ------------------------------------------------------------------------
stressVram_JsrA6:
	moveq #0,d4
	moveq #0,d5						; the polarity: the seed's bit 0
	btst #0,d7
	beq.s .pol
	moveq #-1,d5
.pol:
	lea (REG_VRAMRW).l,a0
	lea (REG_VRAMADD).l,a1
	move.w #1,(REG_VRAMMOD).l
	move.w #0,(a1)					; the auto-increment stays in the 32K slow VRAM
	move.w d7,d0					; ($7FFF + 1 = $0000): the fast VRAM gets its
	moveq #0,d1						; own address write at $8000
.write:
	cmp.w #$8000,d1
	beq.s .addr
	cmp.w #$8600,d1					; sprite lists: the LSPC2 rewrites them
	bne.s .same						; during display (TestVRAM skips them too)
	move.w #$8700,d1
.addr:
	move.w d1,(a1)					; the LFSR step below is the >= 16 cycles
.same:
	LfsrD0
	move.w d0,d2
	eor.w d5,d2
	move.w d2,(a0)					; >= 16 cycles to the next access: the loop
	WatchDog
	addq.w #1,d1
	cmp.w #$8800,d1
	bne.s .write
	move.w d7,d0
	moveq #0,d1						; address
.read:
	move.w d1,(a1)					; address first: the LFSR step (>= 26 cycles)
	LfsrD0							; is the address -> read delay
	move.w d0,d2
	eor.w d5,d2
	cmp.w (a0),d2
	bne.s .bad
.next:
	WatchDog
	addq.w #1,d1
	cmp.w #$8600,d1
	bne.s .rd8800
	move.w #$8700,d1
.rd8800:
	cmp.w #$8800,d1
	bne.s .read
	RtsA6
.bad:
	tst.l d4
	bne.s .count
	movea.l d1,a4
	movea.w d2,a5
	move.w (a0),d3
.count:
	addq.l #1,d4
	bra.s .next
