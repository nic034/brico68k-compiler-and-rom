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
	Print "  (AES detected: no physical DIP bank - bits below are open-bus, not real switches)"
	PrintLn ""
.dipIsReal:
	move.l #.lblDipSwitches,a1
    PrintA1
	move.w REG_P1CNT_REG_DIPSW,d1
	; Loop on data bits
	move.w #7,d2
.loopDip:
	btst d2, d1
	beq .showDip1
	move.l #.lbl0, a1
    PrintA1
	jmp .endShowDip
.showDip1
	move.l #.lbl1, a1
    PrintA1
.endShowDip
	dbra d2, .loopDip

	; Player 1 controls
	move.l #.lblP1Controls,a1
    PrintA1
	move.b REG_P1CNT_REG_DIPSW,d1
	; Loop on data bits
	move.w #7,d2
.loopP1Controls:
	btst d2, d1
	beq .showP1Controls1
	move.l #.lbl0, a1
    PrintA1
	jmp .endShowP1Controls
.showP1Controls1
	move.l #.lbl1, a1
    PrintA1
.endShowP1Controls
	dbra d2, .loopP1Controls
	PrintLn ""

	; Player 1 controls - clear breakdown
	move.b REG_P1CNT_REG_DIPSW,d1
	Print "  Up      : "
	move.w #0,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Down    : "
	move.w #1,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Left    : "
	move.w #2,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Right   : "
	move.w #3,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button A: "
	move.w #4,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button B: "
	move.w #5,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button C: "
	move.w #6,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button D: "
	move.w #7,d2
	JsrA6 getButtonStateStr
	PrintA1

	; Player 2 controls
	move.l #.lblP2Controls,a1
    PrintA1
	move.b REG_P2CNT,d1
	; Loop on data bits
	move.w #7,d2
.loopP2Controls:
	btst d2, d1
	beq .showP2Controls1
	move.l #.lbl0, a1
    PrintA1
	jmp .endShowP2Controls
.showP2Controls1
	move.l #.lbl1, a1
    PrintA1
.endShowP2Controls
	dbra d2, .loopP2Controls
	PrintLn ""

	; Player 2 controls - clear breakdown
	move.b REG_P2CNT,d1
	Print "  Up      : "
	move.w #0,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Down    : "
	move.w #1,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Left    : "
	move.w #2,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Right   : "
	move.w #3,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button A: "
	move.w #4,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button B: "
	move.w #5,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button C: "
	move.w #6,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  Button D: "
	move.w #7,d2
	JsrA6 getButtonStateStr
	PrintA1

	; StartSelect
	move.l #.lblStartSelect,a1
    PrintA1
	move.b REG_STATUS_B,d1
	; Loop on data bits
	move.w #3,d2
.loopStartSelect:
	btst d2, d1
	beq .showStartSelect1
	move.l #.lbl0, a1
    PrintA1
	jmp .endShowStartSelect
.showStartSelect1
	move.l #.lbl1, a1
    PrintA1
.endShowStartSelect
	dbra d2, .loopStartSelect
	PrintLn ""

	; Start / Select - clear breakdown, per player
	move.b REG_STATUS_B,d1
	Print "  P1 Start : "
	move.w #0,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  P1 Select: "
	move.w #1,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  P2 Start : "
	move.w #2,d2
	JsrA6 getButtonStateStr
	PrintA1
	Print "  P2 Select: "
	move.w #3,d2
	JsrA6 getButtonStateStr
	PrintA1

	; CoinsService - bits printed 2,1,0 = Service, Coin 2, Coin 1 (the
	; header used to list them in the opposite order). Not inputs at all
	; on AES (MAME "AUDIO" port: unused, no coin slots): flagged instead
	; of showing "111" as if every coin switch were pressed.
	move.l #.lblCoinsService,a1
    PrintA1
	btst #7,d7
	bne.s .coinsAreReal
	move.l #.lblCoinsAES,a1
    PrintA1
.coinsAreReal:
	move.b REG_STATUS_A,d1
	; Loop on data bits
	move.w #2,d2
.loopCoinsService:
	btst d2, d1
	beq .showCoinsService1
	move.l #.lbl0, a1
    PrintA1
	jmp .endShowCoinsService
.showCoinsService1
	move.l #.lbl1, a1
    PrintA1
.endShowCoinsService
	dbra d2, .loopCoinsService

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
	move.l #.lblMemCard,a1
    PrintA1
	move.b REG_STATUS_B,d1

	; Raw high nibble in binary, bit 7 down to bit 4
	Print "  Bits 7654 (raw)           : "
	move.w #7,d3
	move.w #3,d2
.loopMcBits:
	btst d3,d1
	beq .showMcBit0
	move.l #.lbl1,a1
    PrintA1
	jmp .endShowMcBit
.showMcBit0:
	move.l #.lbl0,a1
    PrintA1
.endShowMcBit:
	sub.w #1,d3
	dbra d2,.loopMcBits
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
	move.b d1,d3
	lsr.b #4,d3
	andi.b #3,d3			; d3 = CD2:CD1, flags set
	beq.s .mcInserted
	cmpi.b #3,d3
	beq.s .mcNoCard
	btst #4,d1
	bne.s .mcOnlyCD2
	move.l #.lblMcOnlyCD1,a1
    PrintA1
	jmp .hwMode
.mcOnlyCD2:
	move.l #.lblMcOnlyCD2,a1
    PrintA1
	jmp .hwMode
.mcNoCard:
	move.l #.lblMcNoCard,a1
    PrintA1
	jmp .hwMode
.mcInserted:
	move.l #.lblMcOk,a1
    PrintA1
	btst #6,d1
	beq.s .mcWriteEnabled
	move.l #.lblMcWP,a1
    PrintA1
	jmp .hwMode
.mcWriteEnabled:
	move.l #.lblMcWE,a1
    PrintA1

.hwMode:
	; Bit 7: hardware mode, 0 = AES, 1 = MVS
	btst #7,d1
	bne .hwMVS
	move.l #.lblHwAES,a1
    PrintA1
	jmp .endOfTest
.hwMVS:
	move.l #.lblHwMVS,a1
    PrintA1

.endOfTest:
    ; End of transmission
    WriteEOT

	jmp .data
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
	dc.b "  Memory card (CD1 bit4, CD2 bit5) : inserted correctly (CD1=0, CD2=0)", 10, 0
.lblMcNoCard:
	dc.b "  Memory card (CD1 bit4, CD2 bit5) : no card (CD1=1, CD2=1)", 10, 0
.lblMcOnlyCD1:
	dc.b "  Memory card (CD1 bit4, CD2 bit5) : ONLY CD1 detected (CD1=0, CD2=1) - card not fully inserted or bad CD2 contact", 10, 0
.lblMcOnlyCD2:
	dc.b "  Memory card (CD1 bit4, CD2 bit5) : ONLY CD2 detected (CD1=1, CD2=0) - card not fully inserted or bad CD1 contact", 10, 0
.lblMcWP:
	dc.b "  Write protect (WP bit6)          : card WRITE PROTECTED", 10, 0
.lblMcWE:
	dc.b "  Write protect (WP bit6)          : write enabled", 10, 0
.lblHwAES:
	dc.b "  Hardware mode             : AES", 10, 0
.lblHwMVS:
	dc.b "  Hardware mode             : MVS", 10, 0
.lbl0;
	dc.b "0", 0
.lbl1;
	dc.b "1", 0
	even
.data

    ; Jump back to the command loop
    jmp WAIT_FOR_COMMAND