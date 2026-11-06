	include "inc/define.inc"

    global EXT_MEMDUMP

	section	text

EXT_MEMDUMP:

	; Read both parameters immediately (the host clears P1-P3 1 ms after
	; launch). Start address forced even: a word read at an odd address
	; is a 68000 address error (used to kill the firmware until reset).
    move.l (BRICO_COMMAND_PARAM_1).l,d0
    move.l (BRICO_COMMAND_PARAM_2).l,d3
	bclr #0,d0
    movea.l d0,a2					; a2 = (even) base address

	; Return address to the host (low word, then high word)
    PortWriteD0
    move.l a2,d0
	swap d0
    PortWriteD0

	; The BricoNeo keeps the output in a ring of 2048 words (Brico16Bits
	; InputBuffer): past 2047 words in all it wraps and the host shows only
	; the tail, without the address. 2 address words + 2045 = 2047.
	cmp.l #2045,d3
	bls.s .countOk
	move.l #2045,d3
.countOk:
	; Compute end of dump address => a3
	add.l d3,d3						; word count x2 = byte length
	movea.l a2,a3
	adda.l d3,a3

	; Now iterate from a2 to a3. The watchdog is kicked on every word:
	; it never was before, so on MVS (watchdog ~0.135 s) a dump longer
	; than ~10000 words reset the console in the middle of the dump.
.loop
	cmpa.l a2,a3
	beq.s .endloop
	WatchDog
	move.w (a2)+,d0
	PortWriteD0
	bra.s .loop
.endloop:

    ; End of transmission
    WriteEOT

    ; Jump back to the command loop
    jmp WAIT_FOR_COMMAND
