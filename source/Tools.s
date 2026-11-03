    include "inc/define.inc"

    global port_write_d0_JsrA6
    global print_a1_JsrA6
    global printWord_JsrA6
    global getButtonStateStr_JsrA6
    global printDec_JsrA6

	section	text

port_write_d0_JsrA6:
    InlinePortWriteD0
    RtsA6

print_a1_JsrA6:			; string address in a1
    InlinePrintA1
    RtsA6

printWord_JsrA6: 
;input : d0 = 16-bit word - 0x8642 for example
;output : print a 4 digit hex value of d0
;d1 d7 d3 are used for vram test errors

    move.l d0, d2    ; save d0 to d2
    moveq.l #12, d4  ; initialize loop counter to 12 for the most significant nibble

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

getButtonStateStr_JsrA6:
; input:  d1 = byte holding the button/switch bits, d2 = bit index to test
; output: a1 = address of "PRESSED"/"released" string (0-terminated)
    btst d2,d1
    beq .buttonIsPressed
    lea .lblReleased(pc),a1
    RtsA6
.buttonIsPressed:
    lea .lblPressed(pc),a1
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
