	include "inc/define.inc"

    global EXT_TEST_SYSTYPE

	section	text

; =====================================================================
; EXT_TEST_SYSTYPE - decode REG_SYSTYPE
;
; IMPORTANT (found while re-checking this against MAME's full address
; map, not just the "neogeo"/arcade ioport table used by a previous
; version of this test): $300080-$300081 ("TEST" port: TEST switch +
; JAMMA sense) is only mapped in ngarcade_base_state::neogeo_main_map
; (the MVS/arcade memory map). aes_base_main_map/aes_main_map - the
; map actually used on a real AES console - has NO handler there at
; all. On real AES hardware this address is simply unmapped: reading
; it returns open-bus/undefined data, not a real TEST/JAMMA signal.
; A BricoNeo plugged into an AES console would otherwise get a
; confident-looking but meaningless "TEST button: PRESSED/released"
; verdict from garbage bus noise - worse than printing nothing.
;
; Since BricoNeo targets both AES and MVS (per HARDWARE_NOTES.md), this
; test now checks the hardware-type bit first (REG_STATUS_B bit 7,
; AES=0/MVS=1 - this one IS reliably mapped on both: aes_in2_r's bit
; 0x8000 and the arcade SYSTEM port's bit 0x8000 are the same signal)
; and only trusts/decodes the TEST/JAMMA bits when it detects MVS.
;
;   Low byte  ($300081), MVS/arcade only:
;     bits 0-5  unused
;     bit  6    "sense: JAMMA" (active HIGH)
;     bit  7    TEST switch (active LOW, PORT_SERVICE_NO_TOGGLE)
;   High byte ($300080): entirely unused even on MVS (PORT_BIT 0xff00
;   IPT_UNUSED).
; =====================================================================

EXT_TEST_SYSTYPE:
	move.l #.lblTitle,a1
	PrintA1

	; Hardware type first (reliable on both AES and MVS - see
	; ExtTestInputs.s's memcard/hwmode section for the same bit).
	move.b REG_STATUS_B,d7
	btst #7,d7
	beq .isAES

	; --- MVS: the TEST/JAMMA bits are real, decode them ---
	move.w REG_SYSTYPE,d1

	Print "  Hardware detected          : MVS (STATUS_B bit7=1) - TEST/JAMMA bits below are real"
	PrintLn ""

	Print "  Raw word at $300080: 0x"
	move.l d1,d0
	JsrA6 printWord
	PrintLn ""

	Print "  TEST button (bit7, active low)      : "
	btst #7,d1
	beq .testPressed
	move.l #.lblReleased,a1
	PrintA1
	jmp .jammaSense
.testPressed:
	move.l #.lblPressed,a1
	PrintA1

.jammaSense:
	PrintLn ""
	Print "  JAMMA sense (bit6, active high)     : "
	btst #6,d1
	beq .jamma0
	move.l #.lbl1,a1
	PrintA1
	jmp .endOfTest
.jamma0:
	move.l #.lbl0,a1
	PrintA1
	jmp .endOfTest

.isAES:
	; --- AES: $300080 is unmapped per MAME's aes_main_map. Still show
	; the raw value (might help spot an always-same floating-bus
	; pattern), but make the "don't trust this" caveat impossible to
	; miss instead of printing a confident wrong verdict.
	Print "  Hardware detected          : AES (STATUS_B bit7=0)"
	PrintLn ""
	Print "  $300080 is NOT a real register on AES (unmapped in MAME's"
	PrintLn ""
	Print "  aes_main_map - no TEST switch / no JAMMA harness on AES)."
	PrintLn ""
	Print "  Raw word below is open-bus/undefined, NOT a TEST/JAMMA value: 0x"
	move.w REG_SYSTYPE,d1
	move.l d1,d0
	JsrA6 printWord
	PrintLn ""

.endOfTest:
	PrintLn ""

	; End of transmission
	WriteEOT

	jmp .data
.lblTitle:
	dc.b "SYSTYPE breakdown ($300080/$300081), AES/MVS-aware (MAME neogeo.cpp)", 10, 0
.lblPressed:
	dc.b "PRESSED", 0
.lblReleased:
	dc.b "released", 0
.lbl0;
	dc.b "0", 0
.lbl1;
	dc.b "1", 0
	even
.data

	; Jump back to the command loop
	jmp WAIT_FOR_COMMAND
