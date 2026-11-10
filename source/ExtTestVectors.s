	include "inc/define.inc"

	global EXT_TEST_VECTORS

	section text

; ------------------------------------------------------------------------
; TestVectors - the vector table switch.
; The 68000 reads $000000-$00007F (its 32 exception vectors) either from the
; system ROM (same words as $C00000-$C0007F) or from the cartridge. System
; latch output Q1 chooses (neogeodev wiki "Memory mapped registers"):
;   $3A0003 REG_SWPBIOS = system ROM, $3A0013 REG_SWPROM = cartridge.
; The system ROM starts a game by switching to the cartridge: if the switch
; is dead, the console shows its start-up screen and the game then hangs
; (its VBLANK and timer vectors are never used).
;
; Three steps, each compares the 32 long words at $000000 with $C00000:
;   1. REG_SWPBIOS: all 32 must be equal
;   2. REG_SWPROM:  must differ (a cartridge has its own vectors; without
;      a cartridge the open bus is read, which differs as well)
;   3. REG_SWPBIOS: all 32 equal again
; Read only (two latch writes). The table is back on the system ROM before
; anything is printed: during step 2 an exception would use the cartridge
; vectors (interrupts are masked, the window is under 1 ms).
; No WRAM: registers only. d7 = failure flags.
; ------------------------------------------------------------------------
VEC_LONGS equ 32

	macro PrintLongA				; \1 = address register: 8 hex digits
		move.l \1,d0
		swap d0
		JsrA6 printWord
		move.l \1,d0
		JsrA6 printWord
	endm

EXT_TEST_VECTORS:
	moveq #0,d7
	PrintLn "Vector table $000000-$00007F: system ROM or cartridge"

	; --- 1. system ROM ---------------------------------------------------
	move.b d0,(REG_SWPBIOS).l
	JsrA6 vecCompare
	Print "> System ROM (REG_SWPBIOS)  "
	cmp.w #VEC_LONGS,d5
	beq .romOk
	bset #0,d7
	JsrA6 vecCount
	PrintLn "  = still the cartridge, or the BIOS socket (TestBus)"
	bra .cart
.romOk:
	PrintLn "OK"

	; --- 2. cartridge ----------------------------------------------------
.cart:
	move.b d0,(REG_SWPROM).l
	JsrA6 vecCompare
	movea.l ($000000).l,a3			; cartridge SP, reset and VBLANK vectors
	movea.l ($000004).l,a4
	movea.l ($000064).l,a5
	move.b d0,(REG_SWPBIOS).l		; back at once, before any print
	move.w d5,d6					; equal count of step 2

	; --- 3. system ROM again ---------------------------------------------
	JsrA6 vecCompare

	Print "> Cartridge  (REG_SWPROM)   "
	tst.w d6
	bne .cartSome
	PrintLn "OK"
	bra .cartShow
.cartSome:
	cmp.w #VEC_LONGS,d6
	bne .cartPart
	bset #1,d7
	PrintLn "FAIL: still the 32 system ROM vectors"
	PrintLn "  = no switch to the cartridge (latch Q1, decoding): games hang"
	bra .back
.cartPart:							; some vectors equal: possible, not a fault
	PrintLn "OK"
.cartShow:
	Print "    read: SP $"
	PrintLongA a3
	Print "  reset $"
	PrintLongA a4
	Print "  VBLANK $"
	PrintLongA a5
	PrintLn ""
	cmp.l #$4E454F2D,($000100).l	; "NEO-": a game cartridge is there
	beq .back
	PrintLn "    no NEO-GEO header at $100: not a game cartridge (none: open bus)"

.back:
	Print "> System ROM again          "
	cmp.w #VEC_LONGS,d5
	beq .backOk
	bset #2,d7
	JsrA6 vecCount
	PrintLn "  = no switch back to the system ROM"
	bra .end
.backOk:
	PrintLn "OK"

.end:
	tst.w d7
	bne .failed
	PrintLn "=> Test success"
	jmp EOT_AND_WAIT(pc)
.failed:
	PrintLn "=> Test failure"
	jmp EOT_AND_WAIT(pc)

; vecCompare: d5 = number of long words (0-32) equal at $000000 and $C00000.
; Destroys d0, d1, a1, a2.
vecCompare_JsrA6:
	suba.l a1,a1
	lea (SYSTEM_ROM).l,a2
	moveq #0,d5
	moveq #VEC_LONGS-1,d1
.loop:
	move.l (a1)+,d0
	cmp.l (a2)+,d0
	bne .next
	addq.w #1,d5
.next:
	dbra d1,.loop
	RtsA6

; vecCount: prints "FAIL: n of 32 vectors differ from $C00000" + line feed,
; n = 32 - d5. Destroys d0-d3, a0, a2, a5 (printDec: d0-d3, a0, a2).
vecCount_JsrA6:
	movea.l a6,a5
	Print "FAIL: "
	moveq #VEC_LONGS,d0
	sub.w d5,d0
	JsrA6 printDec
	PrintLn " of 32 vectors differ from $C00000"
	jmp (a5)
