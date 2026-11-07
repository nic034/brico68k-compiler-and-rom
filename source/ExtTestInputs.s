	include "inc/define.inc"

    global EXT_TEST_INPUTS

	section	text

EXT_TEST_INPUTS:

	; DIP switches - AES has no cabinet DIP switch bank at all (it's a
	; home console, not an arcade board). Per MAME's neogeo.cpp, the
	; real word-wide P1/DIP composition ((edge&ctrl1)<<8 | dsw->read())
	; is only ever installed by ngarcade_base_state::machine_start()
	; (MVS/arcade); aes_base_main_map maps just a single BYTE handler
	; at $300000 (ctrl1->read_ctrl(), the high byte / P1 side) and
	; nothing for the low byte - so on real AES hardware the low byte
	; dumped below is open-bus/unmapped, not real switch state. Check
	; the hardware-type bit first (see ExtTestInputs.s's own memcard/
	; hwmode section below, or ExtTestStatusA.s) and flag it rather
	; than silently printing noise as if it meant something.
	move.b REG_STATUS_B,d7
	btst #7,d7
	bne .dipIsReal
	PrintLn "  (AES: no DIP bank - bits below are open bus, not real switches)"
.dipIsReal:
	; Bits are printed 7 to 0, "1" for a line at 0 (active low: pressed,
	; switch on), as before. printBits: d1 = value, d2 = highest bit,
	; d3 = character for a bit at 1. printButtons: one line per bit from
	; bit 0, label list in a1 (see Tools.s).
	moveq #'0',d3
	lea .lblDipSwitches(pc),a1
	PrintA1
	move.w REG_P1CNT_REG_DIPSW,d1
	moveq #7,d2
	JsrA6 printBits

	; Player 1 controls
	lea .lblP1Controls(pc),a1
	PrintA1
	move.b REG_P1CNT_REG_DIPSW,d1
	moveq #7,d2
	JsrA6 printBits
	PrintLn ""

	; Player 1 controls - clear breakdown
	move.b REG_P1CNT_REG_DIPSW,d1
	lea .lblButtons(pc),a1
	JsrA6 printButtons

	; Player 2 controls
	lea .lblP2Controls(pc),a1
	PrintA1
	move.b REG_P2CNT,d1
	moveq #7,d2
	JsrA6 printBits
	PrintLn ""

	; Player 2 controls - clear breakdown
	move.b REG_P2CNT,d1
	lea .lblButtons(pc),a1
	JsrA6 printButtons

	; StartSelect
	lea .lblStartSelect(pc),a1
	PrintA1
	move.b REG_STATUS_B,d1
	moveq #3,d2
	JsrA6 printBits
	PrintLn ""

	; Start / Select - clear breakdown, per player
	move.b REG_STATUS_B,d1
	lea .lblStartSel(pc),a1
	JsrA6 printButtons

	; CoinsService - bits printed 2,1,0 = Service, Coin 2, Coin 1 (the
	; header used to list them in the opposite order). Not inputs at all
	; on AES (MAME "AUDIO" port: unused, no coin slots): flagged instead
	; of showing "111" as if every coin switch were pressed.
	lea .lblCoinsService(pc),a1
	PrintA1
	btst #7,d7
	bne.s .coinsAreReal
	lea .lblCoinsAES(pc),a1
	PrintA1
.coinsAreReal:
	move.b REG_STATUS_A,d1
	moveq #2,d2
	JsrA6 printBits

	; Memory card / hardware mode (STATUS_B = high byte of the 16-bit
	; "SYSTEM" port at $380000/$380001, per MAME's neogeo.cpp:
	;   map(0x380000,0x380001)...portr("SYSTEM")
	;   PORT_BIT(0x00ff, ...IPT_UNUSED)                         -> low byte unused
	;   PORT_BIT(0x0f00, ...startsel_edge_joy_r)                -> byte bits 3-0
	;   PORT_BIT(0x7000, ...CUSTOM_MEMBER(get_memcard_status))  -> byte bits 6-4
	;   PORT_BIT(0x8000, ...hardware type AES=0/MVS=1)          -> byte bit 7
	; get_memcard_status's actual body is:
	;   return (!m_memcard || !m_memcard->present()) ? 0x07 : 0x00;
	; i.e. it is NOT three independent bits and there is no separate
	; "write protect" bit anywhere in this field - it's ONE 3-bit field
	; whose bits always move together: 000 = card present, 111 = no
	; card. An earlier version of this test read it as bits 5-4 (2-bit
	; status) plus a standalone bit 6 "write protect" - both wrong;
	; corrected here against the MAME source directly.
	lea .lblMemCard(pc),a1
	PrintA1
	move.b REG_STATUS_B,d1

	; Raw high nibble in binary, bit 7 down to bit 4 ("1" for a bit at 1)
	Print "  Bits 7654 (raw)           : "
	move.b d1,d6				; kept: the bits are shifted down for printBits
	lsr.b #4,d1
	moveq #'1',d3
	moveq #3,d2
	JsrA6 printBits
	move.b d6,d1
	PrintLn ""

	; Bits 6-4 (corrected): bit 4 = CD1, bit 5 = CD2 (card detect, both 0
	; when the card is fully inserted), bit 6 = WP (1 = card write
	; protected). Sources: MAME neogeo.cpp get_memcard_status() comment
	; "D0 and D1 are memcard 1 and 2 presence indicators, D2 indicates
	; memcard write protect status" (MAME itself only returns 000/111,
	; it never emulates WP), and the neogeodev wiki "Memory card" page.
	; A previous version treated 6-4 as one 3-bit field and reported a
	; correctly inserted WRITE-PROTECTED card (100) as "INCONSISTENT -
	; possible signal issue": a false fault indication.
	; CD1 != CD2 is the real diagnostic case: card half inserted, or a
	; bad contact on one end of the card connector.
	Print "  Memory card (CD1 bit4, CD2 bit5) : "
	move.b d1,d3
	lsr.b #4,d3
	andi.b #3,d3			; d3 = CD2:CD1, flags set
	beq.s .mcInserted
	lea .lblMcNoCard(pc),a1
	cmpi.b #3,d3
	beq.s .mcPrint
	lea .lblMcOnlyCD1(pc),a1
	btst #4,d1
	beq.s .mcPrint
	lea .lblMcOnlyCD2(pc),a1
.mcPrint:
	PrintA1
	bra.s .hwMode
.mcInserted:
	lea .lblMcOk(pc),a1
	PrintA1
	Print "  Write protect (WP bit6)          : "
	lea .lblMcWE(pc),a1
	btst #6,d1
	beq.s .mcWP
	lea .lblMcWP(pc),a1
.mcWP:
	PrintA1

.hwMode:
	; Bit 7: hardware mode, 0 = AES, 1 = MVS
	Print "  Hardware mode             : "
	btst #7,d1
	bne.s .hwMVS
	PrintLn "AES"
	jmp EOT_AND_WAIT(pc)
.hwMVS:
	PrintLn "MVS"
	jmp EOT_AND_WAIT(pc)

.lblButtons:					; P1 and P2, bits 0-7
	dc.b "  Up      : ",0,"  Down    : ",0,"  Left    : ",0,"  Right   : ",0
	dc.b "  Button A: ",0,"  Button B: ",0,"  Button C: ",0,"  Button D: ",0,0
.lblStartSel:					; STATUS_B bits 0-3
	dc.b "  P1 Start : ",0,"  P1 Select: ",0,"  P2 Start : ",0,"  P2 Select: ",0,0
.lblDipSwitches:
	dc.b "87654321 DIP Switches (NEO-F0)", 10, 0
.lblP1Controls:
	dc.b 10, 10, "DCBARLDU Player 1 controls (NEO-C1)", 10, 0
.lblP2Controls:
	dc.b 10, 10, "DCBARLDU Player 2 controls (NEO-C1)", 10, 0
.lblStartSelect:
	dc.b 10, 10, "P2 Select, P2 Start, P1 Select, P1 Start (NEO-C1)", 10, 0
.lblCoinsService:
	dc.b 10, 10, "Service button, Coin-in 2, Coin-in 1 (STATUS_A bits 2-0, 1 = pressed)", 10, 0
.lblCoinsAES:
	dc.b "  (AES detected: no coin slots / service button - bits below are not inputs)", 10, 0
.lblMemCard:
	dc.b 10, 10, "Memory card / Hardware mode (STATUS_B $380000)", 10, 0
.lblMcOk:
	dc.b "inserted correctly (CD1=0, CD2=0)", 10, 0
.lblMcNoCard:
	dc.b "no card (CD1=1, CD2=1)", 10, 0
.lblMcOnlyCD1:
	dc.b "ONLY CD1 detected (CD1=0, CD2=1) - card not fully inserted or bad CD2 contact", 10, 0
.lblMcOnlyCD2:
	dc.b "ONLY CD2 detected (CD1=1, CD2=0) - card not fully inserted or bad CD1 contact", 10, 0
.lblMcWP:
	dc.b "card WRITE PROTECTED", 10, 0
.lblMcWE:
	dc.b "write enabled", 10, 0
	even
