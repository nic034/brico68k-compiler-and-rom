	include "inc/define.inc"

	global EXT_CART_DIAG

	section text

; ------------------------------------------------------------------------
; CartDiag - cartridge P bus on the diagnostic PROG board (SRAM), with writes
; (CART_BOARD, below). The game-cartridge test CartTest was removed in
; 1.35-nic034-10.
; No WRAM, no stack.
; ------------------------------------------------------------------------
P2_START    equ $200000

; ------------------------------------------------------------------------
; OE_DEAD: a chip that never drives the bus leaves the CPU reading the word
; it prefetched, the opcode after the move. The byte read three times, each
; time followed by another opcode and compared with that opcode's byte of the
; same lane: dead if all three are equal, on any of 50 rounds.
; In: a0 = address, d0 = 1 odd byte (D0-D7) / 0 even byte (D8-D15), a1 = return.
; Out: d0 = 0 pass / -1 dead. Destroys d1-d2, a0.
; ------------------------------------------------------------------------
OE_DEAD:
	adda.w d0,a0
	moveq #49,d2
.again:
	move.b (a0),d1
.c1:
	cmp.b .c1(pc,d0.w),d1
	bne.s .live
	move.b (a0),d1
.c2:
	nop
	cmp.b .c2(pc,d0.w),d1
	bne.s .live
	move.b (a0),d1
.c3:
	tst.w d2
	cmp.b .c3(pc,d0.w),d1
.live:
	dbeq d2,.again
	seq d0
	jmp (a1)

; ------------------------------------------------------------------------
; OE_HOLD245: behind a transceiver the dead output reads back the last value
; written. $5555 at +4 then $AAAA at +8, each followed by a read of +0 under
; the lane mask: dead if the read equals the written value both times.
; In: a0 = address, d0 = 1 odd byte / 0 even byte, a1 = return.
; Out: d0 = 0 pass / -1 dead. Destroys d1-d3.
; ------------------------------------------------------------------------
OE_HOLD245:
	move.w #$00FF,d3
	tst.b d0
	bne.s .mask
	move.w #$FF00,d3
.mask:
	move.w #$5555,4(a0)
	move.w (a0),d1
	and.w d3,d1
	move.w #$5555,d2
	and.w d3,d2
	cmp.w d1,d2
	bne.s .live
	move.w #$AAAA,8(a0)
	move.w (a0),d1
	and.w d3,d1
	move.w #$AAAA,d2
	and.w d3,d2
	cmp.w d1,d2
	bne.s .live
	moveq #-1,d0
	jmp (a1)
.live:
	moveq #0,d0
	jmp (a1)

; ------------------------------------------------------------------------
; CartDiag, CART_BOARD: diagnostic PROG board (jwestfall69 neogeo-diag-aes-prog: one
; 1 MiB 16-bit SRAM, A0-A18 = slot A1-A19, D0-D15 = slot D0-D15, read by
; /ROMOE and /PORTOE, written by /PORTWEU and /PORTWEL). Destroys its content.
; Console name: "p-bus test (diag cart)", with the board's GitHub address.
;   0. output enable, the method of the diag BIOS (own code): OE_DEAD
;      (prefetch) then OE_HOLD245 (bus hold), P1 D0-D7, P1 D8-D15, P2 D0-D7,
;      P2 D8-D15;
;   1. RAM_SUITE (ExtTestBWPRAM.s, type 3) at $200000: data lines walking
;      1/0, byte lanes (PORTWEU / PORTWEL), A1-A19, March C- on 64 KiB;
;   2. P1 window: 32 words written through P2 ($200200, walking 1 then
;      walking 0) read back through P1 ($000200): /ROMOEU, /ROMOEL.
; ------------------------------------------------------------------------
EXT_CART_DIAG:
CART_BOARD:
	PrintText
	dc.b "p-bus test (diag cart): SRAM $200000, ERASED",10
	dc.b "https://github.com/jwestfall69/neogeo-diag-aes-prog",10,0
	even

	; --- output enable, as the diag BIOS does first (docs/tests/68k/p_rom_output.md):
	; pass 0: the byte read must not be the prefetched opcode (OE_DEAD);
	; pass 1: behind a 245/NEO-G0/NEO-BUF the dead output gives back the last
	; write (HOLD_245). Windows and lanes in the BIOS order: P1 D0-D7, P1 D8-D15,
	; P2 D0-D7, P2 D8-D15 (index d5: bit 1 = P2, bit 0 = D8-D15).
	moveq #0,d4
.oePass:
	tst.b d4
	bne.s .t245
	Print "> Output enable (prefetch) Test "
	bra.s .tTitle
.t245:
	Print "> Output behind a 245 (hold) Test "
.tTitle:
	moveq #0,d5
.oeNext:
	movea.l #$000200,a0			; the same SRAM words in both windows
	btst #1,d5
	beq.s .win
	movea.l #P2_START,a0
.win:
	moveq #1,d0					; D0-D7: odd byte
	btst #0,d5
	beq.s .lane
	moveq #0,d0					; D8-D15: even byte
.lane:
	lea .oeBack(pc),a1
	tst.b d4
	bne OE_HOLD245
	jmp OE_DEAD
.oeBack:
	tst.b d0
	bne.s .oeDead
	addq.b #1,d5
	cmp.b #4,d5
	bne.s .oeNext
	PrintLn "Success"
	addq.b #1,d4
	cmp.b #2,d4
	bne .oePass
	bra .ramTests
.oeDead:
	PrintText
	dc.b "Failure",10
	dc.b "  P",0
	even
	moveq #1,d0
	btst #1,d5
	beq.s .p1w
	moveq #2,d0
.p1w:
	JsrA6 printDec				; keeps d4-d7
	btst #0,d5
	bne.s .hi
	Print " D0-D7"
	bra.s .sig
.hi:
	Print " D8-D15"
.sig:
	PrintText
	dc.b ": output dead (/ROMOE or /PORTOE)",10
	dc.b "=> Test failure: P bus output enable",10,0
	even
	jmp CART_END

.ramTests:
	moveq #3,d7					; RAM_SUITE region type 3: cartridge P bus
	movea.l #P2_START,a5
	movea.l #P2_START+$10000,a4
	lea .p1(pc),a3				; RAM_SUITE returns through a3
	jmp RAM_SUITE
.p1:
	Print "> P1 window (/ROMOE) read back Test "
	movea.l #P2_START+$200,a0	; write: walking 1, then walking 0
	moveq #0,d3
.wPass:
	moveq #1,d1
.w:
	move.w d1,d2
	eor.l d3,d2
	move.w d2,(a0)+
	add.w d1,d1
	bne.s .w
	not.l d3
	tst.w d3
	bne.s .wPass
	WatchDog
	movea.l #$000200,a0			; read through P1 (same SRAM words)
	moveq #0,d4					; bits read 0 where 1 expected
	moveq #0,d5					; bits read 1 where 0 expected
	moveq #0,d3
.rPass:
	moveq #1,d1
.r:
	move.w d1,d2
	eor.l d3,d2					; expected
	move.w (a0)+,d0
	move.l d0,d6
	eor.l d2,d6					; wrong bits
	and.w d6,d0
	or.w d0,d5
	and.w d2,d6
	or.w d6,d4
	add.w d1,d1
	bne.s .r
	not.l d3
	tst.w d3
	bne.s .rPass
	move.w d4,d0
	or.w d5,d0
	bne.s .p1Bad
	PrintText
	dc.b "Success",10
	dc.b "=> Test success: P bus D0-D15, A1-A19, strobes, /PORTOE, /ROMOE",10,0
	even
	jmp CART_END
.p1Bad:
	PrintLn "Failure"
	moveq #0,d7
.line:
	move.w d4,d0
	or.w d5,d0
	btst d7,d0
	beq .next
	Print "  D"
	moveq #0,d0
	move.w d7,d0
	JsrA6 printDec				; keeps d4-d7
	btst d7,d5
	bne.s .one
	PrintLn " reads 0 where 1 expected"
	bra.s .next
.one:
	btst d7,d4
	bne.s .both
	PrintLn " reads 1 where 0 expected"
	bra.s .next
.both:
	PrintLn " wrong both ways"
.next:
	addq.w #1,d7
	cmp.w #16,d7
	bne .line
	PrintText
	dc.b "  P2 fine: /ROMOEU (D8-D15), /ROMOEL (D0-D7): slot or board U2",10
	dc.b "=> Test failure: P1 window (/ROMOE)",10,0
	even
CART_END:
	jmp EOT_AND_WAIT
