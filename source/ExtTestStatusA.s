	include "inc/define.inc"

    global EXT_TEST_STATUSA

	section	text

; =====================================================================
; EXT_TEST_STATUSA - detailed breakdown of REG_STATUS_A ($320001)
;
; IMPORTANT: $320000-$320001 is a DIFFERENT ioport on AES than on MVS/
; arcade in MAME's neogeo.cpp - not just a documentation nuance, a
; different address_map install (aes_base_main_map overrides
; base_main_map's audio_command_w with its own portr("AUDIO") read for
; AES; the arcade map instead uses portr("AUDIO_COIN")). An earlier
; version of this test decoded it as "AUDIO_COIN" (coin1/coin2/service/
; 4-slot-sense/RTC) unconditionally - correct for MVS, but wrong for
; AES, where:
;
;   PORT_START("AUDIO")  [[ used by MAME's aes_main_map ]]
;   Bit  Meaning
;   0-2  unused (AES has no coin slots - it's a home console)
;   3-4  "unknown" per MAME's own comment: "what is this? Universe
;        BIOS uses these bits to detect MVS or AES hardware" - i.e.
;        even MAME's maintainers don't have a full description of
;        this one, just that UniBIOS reads it for hw detection. Shown
;        raw only, no verdict invented.
;   5-7  unused (AES has no uPD4990a RTC chip)
;
;   PORT_START("AUDIO_COIN")  [[ used by MAME's ngarcade/MVS map ]]
;   Bit  Active  Meaning
;    0    low    Coin 1
;    1    low    Coin 2
;    2    low    Service button (IPT_SERVICE1)
;   3-4   low    unused in the generic map, COIN3/COIN4 in MAME's
;                neogeo_mvs input set (separate coin chutes)
;    5     -     slot-count sense (MAME "sense: 4-slot"/"6-slot";
;                neogeodev: 0 = 4-slot, 1 = 6-slot)
;    6    high   RTC (uPD4990A) time pulse (tp_r)
;    7    high   RTC (uPD4990A) data bit (data_out_r)
;
; Since BricoNeo targets both AES and MVS (HARDWARE_NOTES.md), this
; test reads the hardware-type bit first (REG_STATUS_B bit 7, see
; ExtTestInputs.s - the one register that reliably means the same
; thing on both platforms) and picks the right table instead of
; guessing "coin 1 pressed" out of a bit that may not be a coin input
; at all on the board actually under test.
; =====================================================================

EXT_TEST_STATUSA:
	lea .lblTitle(pc),a1
	PrintA1
	move.b REG_STATUS_A,d1

	; Raw byte, bit 7 down to bit 0 - always shown, independent of the
	; AES/MVS verdict below, so nothing is hidden if you want to
	; cross-check by hand.
	Print "  Raw bits 76543210: "
	moveq #'1',d3				; printBits (Tools.s): "1" for a bit at 1
	moveq #7,d2
	JsrA6 printBits
	PrintLn ""

	; Hardware type (reliable on both platforms - see ExtTestInputs.s)
	move.b REG_STATUS_B,d7
	btst #7,d7
	bne .isMVS

	; --- AES: per MAME's "AUDIO" port, none of these are coin/RTC bits ---
	PrintText
	dc.b "  Hardware detected : AES (STATUS_B bit7=0)",10
	dc.b "  Bits 0-2: N/A on AES (no coin slots - home console, not arcade)",10
	dc.b "  Bits 3-4: hw-detect bits, exact meaning undocumented even in",10
	dc.b "            MAME ('what is this?' - UniBIOS uses them for",10
	dc.b "            AES/MVS sensing). Raw value above, no verdict guessed.",10
	dc.b "  Bits 5-7: N/A on AES (no uPD4990A RTC chip on this board)",10,0
	even
	bra .endOfTest

.isMVS:
	; --- MVS/arcade: the real AUDIO_COIN decode ---
	PrintLn "  Hardware detected : MVS (STATUS_B bit7=1)"

	; Bits 0-4, one line each, PRESSED for a bit at 0 (printButtons, Tools.s).
	; Bits 3-4: MAME's generic "AUDIO_COIN" port marks them unused, but its
	; neogeo_mvs input set (real MVS boards) maps them as COIN3/COIN4
	; ("P1 coin 2 / P2 coin 2, separate coin chutes"), active low.
	lea .lblCoins(pc),a1
	JsrA6 printButtons

	Print "  Slot-count sense (bit5, raw; neogeodev: 0 = 4-slot, 1 = 6-slot): "
	PrintBit 5
	NlPrint "  RTC time pulse (bit6, raw) : "
	PrintBit 6
	NlPrint "  RTC data bit (bit7, raw)   : "
	PrintBit 7

.endOfTest:
	PrintLn ""

	; End of transmission
	jmp EOT_AND_WAIT
.lblTitle:
	dc.b "STATUS_A breakdown ($320001), AES/MVS-aware (MAME neogeo.cpp)", 10, 0
.lblCoins:						; bits 0-4
	dc.b "  Coin 1         : ",0,"  Coin 2         : ",0,"  Service button : ",0
	dc.b "  Coin 3 (P1 coin 2): ",0,"  Coin 4 (P2 coin 2): ",0,0
	even
