	include "inc/define.inc"

    global EXT_READ

	section	text

EXT_READ:

    ; Read address (immediately: the host clears P1-P3 1 ms after launch)
    move.l (BRICO_COMMAND_PARAM_1).l,d1
    movea.l d1,a0

    ; Even address: word read. Odd address: byte read (zero-extended).
    ; A word read at an odd address is a 68000 address error: it used to
    ; kill the firmware until the next reset. Byte reads also make the
    ; odd-byte registers usable directly (e.g. STATUS_A at $320001).
    ; The BricoNeo output ports ($C1FF00-$C1FF03 and mirrors) are not read:
    ; the read would end the command early (EOT) or arm an output. 0 is sent.
    moveq #0,d0
    IsHostPort d1
    beq.s .send
    btst #0,d1
    bne.s .oddAddress
    move.w (a0),d0
    bra.s .send
.oddAddress:
    move.b (a0),d0
.send:

    ; Send value
    PortWriteD0

    ; End of transmission
    jmp EOT_AND_WAIT

    ; Jump back to the command loop
