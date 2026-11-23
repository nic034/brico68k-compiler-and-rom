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
	lea .lblTitle(pc),a1
	PrintA1

	; Hardware type first (reliable on both AES and MVS - see
	; ExtTestInputs.s's memcard/hwmode section for the same bit).
	move.b REG_STATUS_B,d7
	btst #7,d7
	beq .isAES

	; --- MVS: the TEST/JAMMA bits are real, decode them ---
	move.w REG_SYSTYPE,d1

	PrintLn "  Hardware detected          : MVS (STATUS_B bit7=1) - TEST/JAMMA bits below are real"

	Print "  Raw word at $300080: 0x"
	move.l d1,d0
	JsrA6 printWord
	NlPrint "  TEST button (bit7, active low)      : "

	lea .lblReleased(pc),a1
	btst #7,d1
	bne.s .test
	lea .lblPressed(pc),a1
.test:
	PrintA1
	NlPrint "  JAMMA sense (bit6, active high)     : "
	PrintBit 6
	bra .endOfTest

.isAES:
	; --- AES: $300080 is unmapped per MAME's aes_main_map. Still show
	; the raw value (might help spot an always-same floating-bus
	; pattern), but make the "don't trust this" caveat impossible to
	; miss instead of printing a confident wrong verdict.
	PrintText
	dc.b "  Hardware detected          : AES (STATUS_B bit7=0)",10
	dc.b "  $300080 is NOT a real register on AES (unmapped in MAME's",10
	dc.b "  aes_main_map - no TEST switch / no JAMMA harness on AES).",10
	dc.b "  Raw word below is open-bus/undefined, NOT a TEST/JAMMA value: 0x",0
	even
	move.w REG_SYSTYPE,d1
	move.l d1,d0
	JsrA6 printWord
	PrintLn ""

.endOfTest:
	PrintLn ""

	; End of transmission
	jmp EOT_AND_WAIT
.lblTitle:
	dc.b "SYSTYPE breakdown ($300080/$300081), AES/MVS-aware (MAME neogeo.cpp)", 10, 0
.lblPressed:
	dc.b "PRESSED", 0
.lblReleased:
	dc.b "released", 0
	even
