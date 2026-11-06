	include "inc/define.inc"

	global EXT_CART_CRC

	section text

; ------------------------------------------------------------------------
; CartCRC - CRC32 of cartridge P ROM, in the byte order of the MAME ROM
; files, to compare with the official MAME list (hash/neogeo.xml, CRC of
; each P file). The list is not in this ROM (32 KB): the host side
; (Brico68k emulator: --crc-plan GAME --cart-list neogeo.xml) gives the
; commands to run for a game and the CRC32 each file must give.
;
; P1 = start address (P1 $000000-$0FFFFF, P2 $200000-$2FFFFF), even.
;      Bits 24-26 (1-7): P2 bank to select first (word write at $2FFFF0,
;      wiki "Bankswitching"; bank 0 is selected again at the end).
; P2 = byte count, 0 or above $40000 = $40000 (256 KiB, < 1.4 s: the
;      BricoNeo gives up after 3 s), rounded down to 4.
; P3 = CRC32 of the bytes before (0 = start): a P file larger than 256 KiB
;      takes several commands. P3 = -1 ($FFFFFFFF): continue the previous
;      CartCRC (CRC kept in WRAM with its complement), P1 must be where it
;      stopped; P3 = -2: continue at another address (a file whose halves
;      are swapped, ROM_CONTINUE). So a plan (Brico68k emulator --crc-plan,
;      from the MAME list) is a fixed list of lines, pasted at once into the
;      BricoNeo console; the last CRC32 printed is the file's.
;
; MAME P files are word-swapped (load16_word_swap): each 68000 word is
; taken low byte first, so the CRC equals the file's. CRC32 = zlib/MAME
; (reflected, polynomial $EDB88320), 4 bytes per step ("slicing by 4").
; Uses WRAM $100000-$100FFF for its 4 tables (T0-T3, 4 KiB), each entry
; written, read back, then all checked again: a WRAM fault is reported,
; never a wrong CRC. Run TestWRAM if it is.
; $000000-$00007F is the system ROM's vector table at run time: the
; cartridge's is selected while reading (REG_SWPROM), interrupts masked,
; and the system ROM's again after.
; Not for protected carts whose P is encrypted (the list has the file CRC).
; d8(An,Dn) mode: fine on the 68000 and MAME, not on the Unicorn simulator
; of tools/bricosim.py (see ExtTestBWPRAM.s).
; ------------------------------------------------------------------------
CRC_TAB     equ RAM_START			; T0, T1 = +$400, T2 = +$800, T3 = +$C00
CRC_STATE   equ RAM_START+$1000		; "CRCC", next P1, CRC so far, ~CRC
CRC_MAGIC   equ $43524343
CRC_MAX     equ $40000

	macro CrcStore				; pass 0: write; both passes: must read back
		tst.b d4
		bne.s .\@c
		move.l d1,(a1)
.\@c:
		cmp.l (a1)+,d1
		bne .wramBad
	endm

EXT_CART_CRC:
	move.l (BRICO_COMMAND_PARAM_1).l,d5		; parameters first: cleared after 1 ms
	move.l (BRICO_COMMAND_PARAM_2).l,d6
	move.l (BRICO_COMMAND_PARAM_3).l,d7

	; --- tables: pass 0 writes + reads back, pass 1 checks them all ---------
	moveq #0,d4
.pass:
	lea CRC_TAB,a1
	moveq #0,d0					; T0[i]: 8 shift steps of i
.t0:
	move.l d0,d1
	moveq #7,d2
.bit:
	lsr.l #1,d1
	bcc.s .noPoly
	eor.l #$EDB88320,d1
.noPoly:
	dbra d2,.bit
	CrcStore
	addq.b #1,d0
	bne.s .t0
	lea CRC_TAB,a0				; Tk[i] = (Tk-1[i] >> 8) ^ T0[Tk-1[i] & $FF]
	lea CRC_TAB,a2
	move.w #3*256-1,d3
.tk:
	move.l (a0)+,d1
	moveq #0,d2
	move.b d1,d2
	add.w d2,d2
	add.w d2,d2
	lsr.l #8,d1
	move.l (a2,d2.w),d2
	eor.l d2,d1
	CrcStore
	dbra d3,.tk
	WatchDog
	addq.b #1,d4
	cmp.b #2,d4
	bne.s .pass
	bra.s .tabOk
.wramBad:
	PrintLn "=> WRAM error ($100000-$100FFF): run TestWRAM"
	bra .end

.tabOk:
	; --- P3 = -1 / -2: continue the previous command ------------------------
	lea CRC_STATE,a0
	moveq #-2,d0
	cmp.l d0,d7
	beq.s .cont					; -2: any address
	addq.l #1,d0
	cmp.l d0,d7
	bne.s .range				; a CRC (0 = start)
	cmp.l 4(a0),d5				; -1: where the previous one stopped
	bne.s .noPrev
.cont:
	cmp.l #CRC_MAGIC,(a0)
	bne.s .noPrev
	move.l 8(a0),d7
	move.l 12(a0),d0
	not.l d0
	cmp.l d0,d7
	beq.s .range
.noPrev:
	PrintLn "=> Nothing to continue: start the plan again"
	bra .end

.range:
	; --- bank, range ------------------------------------------------------
	move.l d5,d0
	rol.l #8,d0
	and.w #7,d0
	beq.s .noBank
	move.w d0,($2FFFF0).l
.noBank:
	move.l d5,d0
	and.l #$FFFFFE,d0
	movea.l d0,a0
	tst.l d6
	beq.s .max
	cmp.l #CRC_MAX,d6
	bls.s .lenOk
.max:
	move.l #CRC_MAX,d6
.lenOk:
	and.w #$FFFC,d6
	tst.l d6
	bne.s .lenSet
	moveq #4,d6
.lenSet:
	move.l d6,d3
	lsr.l #2,d3
	subq.l #1,d3				; dbra count: up to $FFFF (65536 longs)
	not.l d7					; CRC register
	lea CRC_TAB,a1				; T0
	lea $400(a1),a2				; T1
	lea $800(a1),a3				; T2
	lea $C00(a1),a4				; T3
	move.b d0,REG_SWPROM		; $000000-$00007F = the cartridge's own vectors

	; --- 4 bytes per step: file order lo0 hi0 lo1 hi1 = SWAP of the long ----
.loop:
	move.l (a0)+,d1
	swap d1
	eor.l d7,d1
	moveq #0,d2
	move.b d1,d2				; byte 0 -> T3
	add.w d2,d2
	add.w d2,d2
	move.l (a4,d2.w),d7
	move.w d1,d2				; byte 1 -> T2
	lsr.w #8,d2
	add.w d2,d2
	add.w d2,d2
	move.l (a3,d2.w),d0
	eor.l d0,d7
	swap d1
	moveq #0,d2
	move.b d1,d2				; byte 2 -> T1
	add.w d2,d2
	add.w d2,d2
	move.l (a2,d2.w),d0
	eor.l d0,d7
	move.w d1,d2				; byte 3 -> T0
	lsr.w #8,d2
	add.w d2,d2
	add.w d2,d2
	move.l (a1,d2.w),d0
	eor.l d0,d7
	WatchDog
	dbra d3,.loop
	move.b d0,REG_SWPBIOS		; back to the system ROM vectors (exceptions)
	not.l d7

	move.l d5,d0
	rol.l #8,d0
	and.w #7,d0
	beq.s .noBank0
	move.w #0,($2FFFF0).l		; back to bank 0, as after reset
.noBank0:
	; --- result; state for P3 = -1 / -2 --------------------------------------
	add.l d6,d5					; same bank bits, next address
	lea CRC_STATE,a0
	move.l #CRC_MAGIC,(a0)+
	move.l d5,(a0)+
	move.l d7,(a0)+
	move.l d7,d0
	not.l d0
	move.l d0,(a0)
	Print "CRC32 $"
	move.l d7,d0
	swap d0
	JsrA6 printWord
	move.l d7,d0
	JsrA6 printWord
	Print " of $"
	move.l d6,d0
	swap d0
	JsrA6 printWord
	move.l d6,d0
	JsrA6 printWord
	PrintLn " bytes"
.end:
	WriteEOT
	jmp WAIT_FOR_COMMAND
