    include "inc/define.inc"

    global port_write_d0_JsrA6
    global print_a1_JsrA6
    global printWord_JsrA6
    global printLong_JsrA6
    global printBits_JsrA6
    global printButtons_JsrA6
    global printDec_JsrA6
    global printInline_JsrA6
    global printBitList_JsrA6
    global printMismatch_JsrA6
    global printMismatchL_JsrA6
    global printFlagNames_JsrA6

	section	text

port_write_d0_JsrA6:
    InlinePortWriteD0
    RtsA6

print_a1_JsrA6:			; string address in a1
    InlinePrintA1
    RtsA6

printInline_JsrA6:		; a6 = 0-terminated string, the code goes on after it (even)
.loop:
    moveq #0,d0
    move.b (a6)+,d0
    beq.s .end
    InlinePortWriteD0
    bra.s .loop
.end:
    move.l a6,d0
    addq.l #1,d0
    bclr #0,d0				; next even address
    movea.l d0,a6
    moveq #0,d0				; d0 = 0 after a Print, as with InlinePrintA1 (callers rely on it)
    jmp (a6)

printLong_JsrA6:
;input : d0 = 32-bit value; output: 8 hex digits. Same registers as printWord.
    move.l d0,d2
    moveq #28,d4                ; most significant nibble of the long
    bra.s printHex

printWord_JsrA6: 
;input : d0 = 16-bit word - 0x8642 for example
;output : print a 4 digit hex value of d0
;destroys d0, d2, d4, a0

    move.l d0, d2    ; save d0 to d2
    moveq.l #12, d4  ; initialize loop counter to 12 for the most significant nibble
printHex:
    .hexloop:
        move.l d2, d0
        lsr.l d4, d0            ; shift right by the current value of d4
        and.l #$F, d0           ; nibble (and.l: andi.w on Dn is mis-emulated by Unicorn)
        move.b .hexDigits(pc,d0.l),d0 ; ASCII digit from table (no compare/branch)
        InlinePortWriteD0       ; masks d0 to 16 bits itself

        subq.l #4, d4           ; decrement counter by 4 bits (subq: 2 bytes / 8 cycles, was subi.l)
        bpl.s .hexloop          ; continue loop if d4 >= 0

    RtsA6

.hexDigits:
    dc.b "0123456789ABCDEF"

printBits_JsrA6:
; input:  d1 = value, d2.w = highest bit to print, d3.b = character for a
;         bit at 1 ('0' for active-low inputs, '1' to print the raw bit)
; output: bits d2 down to 0, one character each. Destroys d0, d2 (-1), a0.
.loop:
    moveq #0,d0
    move.b d3,d0
    btst d2,d1
    bne.s .print
    eori.b #1,d0                ; '0' <-> '1'
.print:
    InlinePortWriteD0
    dbra d2,.loop
    RtsA6

printButtons_JsrA6:
; input:  d1 = byte holding the button/switch bits (active low), a1 = labels,
;         0-terminated strings back to back, an empty one ends the list
; output: for bit 0, 1, 2...: the label, then "PRESSED" (bit at 0) or
;         "released" (bit at 1) and a line feed. Destroys d0, d2, a0-a2.
    moveq #0,d2
.next:
    tst.b (a1)
    beq.s .end
    InlinePrintA1               ; the label: a1 -> the next one
    movea.l a1,a2
    lea .lblReleased(pc),a1
    btst d2,d1
    bne.s .state
    lea .lblPressed(pc),a1
.state:
    InlinePrintA1
    movea.l a2,a1
    addq.w #1,d2
    bra.s .next
.end:
    RtsA6

.lblPressed:
    dc.b "PRESSED",10,0
.lblReleased:
    dc.b "released",10,0
    even


printDec_JsrA6:
; input : d0.l = unsigned 32-bit value
; output: prints it in decimal, no leading zeros ("0" for 0)
; destroys d0, d1, d2, d3, a0, a2. No WRAM, no division (repeated
; subtraction of powers of ten: at most 9 per digit).
    move.l d0,d1                ; d1 = remaining value
    lea .pow10(pc),a2
    moveq #0,d3                 ; d3 = 1 once a non-zero digit was printed
.nextPower:
    move.l (a2)+,d2             ; current power of ten (0 = end of table)
    beq.s .done
    moveq #'0',d0
.sub:
    cmp.l d2,d1
    bcs.s .digit                ; d1 < power: digit complete
    sub.l d2,d1
    addq.b #1,d0
    bra.s .sub
.digit:
    cmp.b #'0',d0
    bne.s .print
    tst.b d3
    bne.s .print
    cmp.l #1,d2                 ; last digit: always printed
    bne.s .nextPower
.print:
    moveq #1,d3
    InlinePortWriteD0           ; destroys d0, a0
    bra.s .nextPower
.done:
    RtsA6

    even
.pow10:
    dc.l 1000000000,100000000,10000000,1000000,100000,10000,1000,100,10,1,0


printBitList_JsrA6:
; input:  d1.l = bits, d3.w = letter ('D' data bit, 'A' address line)
; output: " <letter><n>" for each bit n at 1, lowest first (" D3 D12", " A19").
;         Same words as the Print " D" + printDec loops it replaces.
; destroys d0-d4, a0, a1. No WRAM.
    moveq #0,d2                 ; d2 = bit number
.next:
    lsr.l #1,d1
    bcc.s .skip
    moveq #' ',d0
    lea .letter(pc),a1
    bra.s .emit
.letter:
    move.w d3,d0
    lea .number(pc),a1
    bra.s .emit
.number:
    moveq #0,d4
    move.w d2,d4
    divu #10,d4                 ; d4 = remainder : tens
    tst.w d4
    beq.s .ones                 ; no leading zero
    moveq #'0',d0
    add.w d4,d0
    lea .ones(pc),a1
    bra.s .emit
.ones:
    swap d4
    moveq #'0',d0
    add.w d4,d0
    lea .skip(pc),a1
.emit:
    InlinePortWriteD0           ; destroys d0, a0
    jmp (a1)
.skip:
    addq.w #1,d2
    tst.l d1
    bne.s .next
    RtsA6

printMismatchL_JsrA6:
; A word that read wrong, as TestWRAM / TestVRAM report it:
;   "  Address  : $aaaaaaaa" (L: 8 digits) or "$aaaa" (4 digits)
;   "  Expected : $eeee" / "  Read     : $rrrr" / "  Bad bits : $bbbb = Dn Dn..."
; input:  a4 = address, a5.w = expected word, d6.w = read word
; output: d6.w = bad bits (expected XOR read). The text ends with a line feed.
; keeps d5, d7, a4; destroys d0-d4, a0-a3, a5.
    movea.l a6,a3               ; link (Print / JsrA6 below use a6)
    Print "  Address  : $"
    move.l a4,d0
    JsrA6 printLong
    bra.s pmData
printMismatch_JsrA6:
    movea.l a6,a3
    Print "  Address  : $"
    move.l a4,d0
    JsrA6 printWord
pmData:
    NlPrint "  Expected : $"
    move.l a5,d0
    JsrA6 printWord
    NlPrint "  Read     : $"
    move.w d6,d0
    JsrA6 printWord
    NlPrint "  Bad bits : $"
    move.l a5,d1
    eor.l d6,d1                 ; d1.w = bad bits
    move.w d1,d6
    move.w d1,d0
    JsrA6 printWord
    Print " ="
    moveq #0,d1
    move.w d6,d1
    moveq #'D',d3
    JsrA6 printBitList
    PrintLn ""
    jmp (a3)

printFlagNames_JsrA6:
; input:  d1 = flags, a1 = names: 0-terminated strings back to back, one per
;         bit from bit 0, an empty one ends the list
; output: the name of each bit at 1, lowest bit first. Destroys d0, d2, a0, a1.
    moveq #0,d2
.next:
    tst.b (a1)
    beq.s .end
    btst d2,d1
    bne.s .print
.skip:
    tst.b (a1)+
    bne.s .skip
    bra.s .bump
.print:
    InlinePrintA1               ; a1 -> the next name
.bump:
    addq.w #1,d2
    bra.s .next
.end:
    RtsA6
