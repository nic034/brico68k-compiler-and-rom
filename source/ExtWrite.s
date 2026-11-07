	include "inc/define.inc"

    global EXT_WRITE
    global EXT_WRITE_B

	section	text

EXT_WRITE:

    ; Read word to be written and address (immediately: the host clears
    ; P1-P3 1 ms after launch)
    move.l (BRICO_COMMAND_PARAM_1).l,d0
    move.l (BRICO_COMMAND_PARAM_2).l,d1
    movea.l d1,a0

    ; Even address: word write. Odd address: byte write of P1's low byte
    ; (a word write at an odd address is a 68000 address error, which
    ; used to kill the firmware until the next reset).
    btst #0,d1
    bne.s .oddAddress
    move.w d0,(a0)
    bra.s .done
.oddAddress:
    move.b d0,(a0)
.done:

    ; End of transmission
    jmp EOT_AND_WAIT(pc)

    ; Jump back to the command loop

; WriteB (upstream 1.35): writes the low byte of P1 at P2, even or odd
; address. Write already handles odd addresses; WriteB is the only way to
; write a single byte at an EVEN address (upper byte lane).
EXT_WRITE_B:
    move.l (BRICO_COMMAND_PARAM_1).l,d0
    move.l (BRICO_COMMAND_PARAM_2).l,a0
    move.b d0,(a0)
    jmp EOT_AND_WAIT(pc)
