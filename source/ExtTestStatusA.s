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
	move.l #.lblTitle,a1
	PrintA1
	move.b REG_STATUS_A,d1

	; Raw byte, bit 7 down to bit 0 - always shown, independent of the
	; AES/MVS verdict below, so nothing is hidden if you want to
	; cross-check by hand.
	Print "  Raw bits 76543210: "
	move.w #7,d2
.loopRaw:
	btst d2,d1
	beq .showRaw0
	move.l #.lbl1,a1
	PrintA1
	jmp .endShowRaw
.showRaw0:
	move.l #.lbl0,a1
	PrintA1
.endShowRaw:
	dbra d2,.loopRaw
	PrintLn ""

	; Hardware type (reliable on both platforms - see ExtTestInputs.s)
	move.b REG_STATUS_B,d7
	btst #7,d7
	bne .isMVS

	; --- AES: per MAME's "AUDIO" port, none of these are coin/RTC bits ---
	Print "  Hardware detected : AES (STATUS_B bit7=0)"
	PrintLn ""
	Print "  Bits 0-2: N/A on AES (no coin slots - home console, not arcade)"
	PrintLn ""
	Print "  Bits 3-4: hw-detect bits, exact meaning undocumented even in"
	PrintLn ""
	Print "            MAME ('what is this?' - UniBIOS uses them for"
	PrintLn ""
	Print "            AES/MVS sensing). Raw value above, no verdict guessed."
	PrintLn ""
	Print "  Bits 5-7: N/A on AES (no uPD4990A RTC chip on this board)"
	PrintLn ""
	jmp .endOfTest

.isMVS:
	; --- MVS/arcade: the real AUDIO_COIN decode ---
	Print "  Hardware detected : MVS (STATUS_B bit7=1)"
	PrintLn ""

	Print "  Coin 1         : "
	move.w #0,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Coin 2         : "
	move.w #1,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Service button : "
	move.w #2,d2
	JsrA6 getButtonStateStr
	PrintA1

	; Bits 3-4: MAME's generic "AUDIO_COIN" port marks them unused, but its
	; neogeo_mvs input set (real MVS boards) maps them as COIN3/COIN4
	; ("P1 coin 2 / P2 coin 2, separate coin chutes"), active low.
	Print "  Coin 3 (P1 coin 2): "
	move.w #3,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Coin 4 (P2 coin 2): "
	move.w #4,d2
	JsrA6 getButtonStateStr
	PrintA1

.slotTypeNoLn:
	Print "  Slot-count sense (bit5, raw; neogeodev: 0 = 4-slot, 1 = 6-slot): "
	btst #5,d1
	beq .slot0
	move.l #.lbl1,a1
	PrintA1
	jmp .rtcBits
.slot0:
	move.l #.lbl0,a1
	PrintA1

.rtcBits:
	PrintLn ""
	Print "  RTC time pulse (bit6, raw) : "
	btst #6,d1
	beq .pulse0
	move.l #.lbl1,a1
	PrintA1
	jmp .rtcData
.pulse0:
	move.l #.lbl0,a1
	PrintA1
.rtcData:
	PrintLn ""
	Print "  RTC data bit (bit7, raw)   : "
	btst #7,d1
	beq .data0
	move.l #.lbl1,a1
	PrintA1
	jmp .endOfTest
.data0:
	move.l #.lbl0,a1
	PrintA1

.endOfTest:
	PrintLn ""

	; End of transmission
	WriteEOT

	jmp .data
.lblTitle:
	dc.b "STATUS_A breakdown ($320001) - AES/MVS-aware (bits per MAME neogeo.cpp)", 10, 0
.lbl0;
	dc.b "0", 0
.lbl1;
	dc.b "1", 0
	even
.data

	; Jump back to the command loop
	jmp WAIT_FOR_COMMAND
