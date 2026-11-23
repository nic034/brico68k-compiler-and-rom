	include "inc/define.inc"

	global EXT_TEST_BUS
	global busCheck_JsrA6			; Brico68k.s START
	global BUS_SCREEN

	section text

; ------------------------------------------------------------------------
; TestBus - the BIOS socket path, 68000 -> BricoNeo, over the whole image.
;
; Since 1.35-nic034-16 the code uses the full 128 KB image the BricoNeo
; serves (Brico16Bits FLASH_IMAGE_SIZE; no NeoDiag flag $0004, so no copies
; of the first 32 KB any more). BUS_TABLE below is filled by Brico68k
; Compiler: the CRC-32 (zlib) of each 32 KB quarter as the 68000 reads it
; (quarter 0 with the command block $90-$9F and BUS_TABLE's own 36 data
; bytes as zeros, quarter 3 up to $1FEFF: $1FF00 / $1FF02 are the BricoNeo
; output ports, a read there is an EOT / arms an output), then a probe
; offset and the long word found there in each quarter (the compiler picks
; an offset where the four differ; each quarter is padded with its own byte).
; The linker script puts this file, the dispatcher, the print and screen
; routines in quarter 0.
;
;  - A15 / A16 stuck at 0: the BricoNeo serves another quarter; the output
;    ports ($1FF00, A15 = A16 = 1) are out of reach, so NO text can come
;    back. Checked at boot (busCheck, 4 reads, < 1 ms): on a fault the
;    screen shows 16 bands, A1 at the top, A15/A16 red, until a command.
;  - A15 / A16 stuck at 1: quarter 0 (vectors, boot) is not readable: no
;    boot. Nor with A1-A14 / D0-D15 cut: BricoNeo Trace, continuity meter.
;  - The command (protocol works): CRC-32 of each quarter. A wrong one is a
;    marginal line A1-A16 / D0-D15, NEO-E0, or a patched image (SetRomW):
;    the line cannot be named. Then the probes (A15 / A16).
; One pass, about 0.9 s; `*TestBus` repeats it. No WRAM, no stack.
; ------------------------------------------------------------------------
BUS_LINE_MASK  equ $FF80
BUS_FIRST_LINE equ $110			; first visible line (as TestDAC)
BUS_BAND_LINES equ 14			; 16 bands x 14 = 224 lines
CMD_BLOCK      equ $90			; BricoExt command block $90-$9F (written by the BricoNeo)
Q3_LENGTH      equ $7F00		; $18000-$1FEFF: the ports at $1FF00 are never read
TABLE_DATA     equ 36			; 4 CRCs + probe offset + 4 probe longs

EXT_TEST_BUS:
	PrintLn "BIOS socket, 68000 -> BricoNeo: CRC32 of each 32 KB of the image"
	lea BUS_TABLE+8(pc),a4			; the 4 CRCs
	move.l (a4),d0
	or.l 4(a4),d0
	or.l 8(a4),d0
	or.l 12(a4),d0
	beq .noTable
	moveq #0,d6						; quarters with a CRC error (bits 0-3)
	moveq #0,d7						; quarter
.quarter:
	JsrA6 quarterCrc
	move.l d0,d4					; Print destroys d0
	Print "Quarter "
	move.w d7,d0
	JsrA6 printDec
	move.w d7,d1
	add.w d1,d1
	add.w d1,d1
	cmp.l (a4,d1.w),d4
	beq.s .qOk
	bset d7,d6
	PrintLn "  FAIL CRC: a marginal line A1-A16 / D0-D15, NEO-E0, or SetRomW"
	bra.s .nextQ
.qOk:
	PrintLn "  OK"
.nextQ:
	addq.w #1,d7
	cmp.w #4,d7
	bne .quarter
	movea.l d6,a5					; the line loop below uses d6
	JsrA6 busCheck					; A15 / A16 probes (d5); destroys d0-d4, a0, a1
	tst.l d5
	beq .verdict
	moveq #14,d7
.line:
	Print "A"
	moveq #1,d0
	add.w d7,d0
	JsrA6 printDec
	move.w d7,d6
	add.w #16,d6
	btst d7,d5
	bne .r0
	btst d6,d5
	bne .r1
	PrintLn "      OK"
	bra .next
.r0:
	btst d6,d5
	bne .unst
	PrintLn "      FAIL reads 0: cut, or short to GND"
	bra .next
.r1:
	PrintLn "      FAIL reads 1: cut, or short to +5V"
	bra .next
.unst:
	PrintLn "      FAIL unstable: cut/floating, bad contact"
.next:
	addq.w #1,d7
	cmp.w #16,d7
	bne .line
.verdict:
	move.l a5,d0					; quarters with a CRC error
	or.l d5,d0
	bne.s .bad
	PrintLn "=> Test success: the BIOS socket path works (A1-A16, D0-D15)"
	jmp EOT_AND_WAIT
.bad:
	PrintLn "=> Test failure: reseat the BricoNeo, then check the traces"
	jmp EOT_AND_WAIT
.noTable:
	PrintLn "=> CHECK: no CRC table: image not built by Brico68k Compiler 1.7+"
	jmp EOT_AND_WAIT

; ------------------------------------------------------------------------
; busCheck: reads the probe long of quarters 1-3 once (< 1 ms). A quarter
; whose probe is another quarter's: the lines that differ are wrong.
; Out: d5 low word  = lines read as 0 when 1 was sent (bit 14 A15, 15 A16)
;      d5 high word = lines read as 1 when 0 was sent
; Healthy, or no table: d5 = 0. d4 = 0 (no CRC error, for BUS_SCREEN).
; Destroys d0-d5, a0, a1.
; ------------------------------------------------------------------------
busCheck_JsrA6:
	moveq #0,d5
	moveq #0,d4
	lea BUS_TABLE+24(pc),a0
	move.l (a0)+,d0					; probe offset (0: no table); a0 = the 4 probe longs
	beq.s .done
	moveq #1,d3						; quarter asked
.quarter:
	move.l d3,d1
	swap d1
	lsr.l #1,d1						; x $8000
	add.l d0,d1
	add.l #SYSTEM_ROM,d1
	movea.l d1,a1
	move.l (a1),d2					; what the BricoNeo served
	moveq #12,d1					; whose probe is it? (quarter x 4)
.which:
	cmp.l (a0,d1.w),d2
	beq.s .found
	subq.w #4,d1
	bpl.s .which
	bra.s .next						; nobody's: not A15/A16 (the CRC says it)
.found:
	lsr.w #2,d1						; quarter served
	eor.w d3,d1						; lines that came out wrong: bit 0 A15, bit 1 A16
	beq.s .next
	lsl.w #8,d1
	lsl.w #6,d1						; -> bits 14, 15
	move.w d3,d2
	lsl.w #8,d2
	lsl.w #6,d2						; levels the 68000 sent
	move.w d1,d4
	and.w d2,d4						; sent 1, read 0
	or.w d4,d5
	not.w d2
	and.w d2,d1						; sent 0, read 1
	swap d5
	or.w d1,d5
	swap d5
.next:
	addq.w #1,d3
	cmp.w #4,d3
	bne.s .quarter
	moveq #0,d4
.done:
	RtsA6

; ------------------------------------------------------------------------
; quarterCrc: CRC-32 (zlib) of quarter d7 (0-3) as the 68000 reads it.
; Out: d0. Destroys d1-d3, a0, a1, a3.
; ------------------------------------------------------------------------
quarterCrc_JsrA6:
	movea.l a6,a3					; nested JsrA6
	moveq #-1,d0
	lea BUS_CRC_TABLE(pc),a1
	move.l d7,d1
	swap d1
	lsr.l #1,d1						; quarter x $8000
	add.l #SYSTEM_ROM,d1
	movea.l d1,a0
	move.l #$8000,d3
	tst.w d7
	bne.s .notQ0
	move.l #CMD_BLOCK,d3
	JsrA6 crcBytes
	lea BUS_ZERO(pc),a0				; the live command block counts as zeros
	moveq #16,d3
	JsrA6 crcBytes
	lea SYSTEM_ROM+CMD_BLOCK+16,a0
	move.l #BUS_TABLE+8-(SYSTEM_ROM+CMD_BLOCK+16),d3
	JsrA6 crcBytes
	lea BUS_ZERO(pc),a0				; so does the table's own data
	moveq #TABLE_DATA,d3
	JsrA6 crcBytes
	lea BUS_TABLE+8+TABLE_DATA(pc),a0
	move.l #SYSTEM_ROM+$8000,d3
	sub.l a0,d3
	bra.s .last
.notQ0:
	cmp.w #3,d7
	bne.s .last
	move.l #Q3_LENGTH,d3
.last:
	JsrA6 crcBytes
	not.l d0
	jmp (a3)

; crcBytes: d0 = CRC over d3 bytes at a0 (a0 advances, d3 > 0), a1 = table.
; Blocks of 1 KB walked by dbra, the watchdog kicked between them (84 cycles
; a byte: the whole image in about 0.9 s). Destroys d1-d3.
crcBytes_JsrA6:
.block:
	move.l #1024,d2
	cmp.l d2,d3
	bhs.s .full
	move.l d3,d2
.full:
	sub.l d2,d3
	subq.w #1,d2
.byte:
	moveq #0,d1
	move.b (a0)+,d1
	eor.b d0,d1
	add.w d1,d1
	add.w d1,d1
	lsr.l #8,d0
	move.l (a1,d1.w),d1
	eor.l d1,d0
	dbra d2,.byte
	WatchDog
	tst.l d3
	bne.s .block
	RtsA6

	macro BandColour			; d6 = line field, d1 = colour
		JsrA6 screenBand
	endm

BUS_SCREEN:
	JsrA6 screenBlank
	move.w #BUS_LINE_MASK,d3
	moveq #0,d2					; 1 once BRICO_COMMAND_IN was seen at 0
.frame:
	move.w #(BUS_FIRST_LINE-1)<<7,d6
	moveq #0,d7
.band:
	move.w #$8000,d1			; black separator
	BandColour
	; band colour index -> d0
	moveq #0,d0
	btst d7,d5
	beq.s .n0
	addq.w #1,d0
.n0:
	move.w d7,d1
	add.w #16,d1
	btst d1,d5
	beq.s .n1
	addq.w #2,d0
.n1:
	tst.w d0
	beq.s .ok
	btst #1,d4
	bne.s .orange
	cmp.w #3,d0
	beq.s .orange
	moveq #2*2,d0				; red: reads 0
	btst d7,d5
	bne.s .pick
	moveq #3*2,d0				; blue: reads 1
	bra.s .pick
.orange:
	moveq #4*2,d0
	bra.s .pick
.ok:
	btst #2,d4
	bne.s .grey
	btst #0,d4
	beq.s .green
	cmp.w #13,d7				; CRC error: A1-A14 = bands 0-13
	bhi.s .green
	moveq #5*2,d0				; yellow
	bra.s .pick
.grey:
	moveq #6*2,d0
	bra.s .pick
.green:
	move.w d7,d0
	and.w #1,d0
	add.w d0,d0					; bright / dim, alternating
.pick:
	lea BUS_COLOURS(pc),a2
	move.w (a2,d0.w),d1
	; colour after 1 black line, 4 at the start of each group of 4
	move.w d6,d0
	add.w #1<<7,d0
	move.w d7,d6
	and.w #3,d6
	bne.s .gap1
	tst.w d7
	beq.s .gap1
	add.w #3<<7,d0
.gap1:
	move.w d0,d6
	BandColour
	; next band: back to its first line
	move.w d7,d0
	mulu #BUS_BAND_LINES<<7,d0
	add.w #(BUS_FIRST_LINE-1+BUS_BAND_LINES)<<7,d0
	move.w d0,d6
	addq.w #1,d7
	cmp.w #16,d7
	bne .band
	; bottom border black again
	move.w #$8000,d1
	BandColour
	bra .frame


	even
BUS_COLOURS:
	dc.w $20F0					; 0 green (A1, A3...)
	dc.w $0060					; 1 dim green (A2, A4...)
	dc.w $4F00					; 2 red: reads 0
	dc.w $108F					; 3 blue: reads 1
	dc.w $4F80					; 4 orange: unstable
	dc.w $6FF0					; 5 yellow: BIOS CRC error (A1-A14, D0-D15)
	dc.w $0888					; 6 grey: no CRC table

BUS_TABLE:							; filled by Brico68k Compiler (quarter 0, see Brico68k.ld)
	dc.b "BUSCRC32"
	dcb.l 9,0						; 4 CRCs, probe offset, 4 probe longs
BUS_ZERO:
	dcb.b TABLE_DATA,0
	even
BUS_CRC_TABLE:						; CRC-32, reflected polynomial $EDB88320, one byte
	dc.l $00000000,$77073096,$EE0E612C,$990951BA,$076DC419,$706AF48F,$E963A535,$9E6495A3
	dc.l $0EDB8832,$79DCB8A4,$E0D5E91E,$97D2D988,$09B64C2B,$7EB17CBD,$E7B82D07,$90BF1D91
	dc.l $1DB71064,$6AB020F2,$F3B97148,$84BE41DE,$1ADAD47D,$6DDDE4EB,$F4D4B551,$83D385C7
	dc.l $136C9856,$646BA8C0,$FD62F97A,$8A65C9EC,$14015C4F,$63066CD9,$FA0F3D63,$8D080DF5
	dc.l $3B6E20C8,$4C69105E,$D56041E4,$A2677172,$3C03E4D1,$4B04D447,$D20D85FD,$A50AB56B
	dc.l $35B5A8FA,$42B2986C,$DBBBC9D6,$ACBCF940,$32D86CE3,$45DF5C75,$DCD60DCF,$ABD13D59
	dc.l $26D930AC,$51DE003A,$C8D75180,$BFD06116,$21B4F4B5,$56B3C423,$CFBA9599,$B8BDA50F
	dc.l $2802B89E,$5F058808,$C60CD9B2,$B10BE924,$2F6F7C87,$58684C11,$C1611DAB,$B6662D3D
	dc.l $76DC4190,$01DB7106,$98D220BC,$EFD5102A,$71B18589,$06B6B51F,$9FBFE4A5,$E8B8D433
	dc.l $7807C9A2,$0F00F934,$9609A88E,$E10E9818,$7F6A0DBB,$086D3D2D,$91646C97,$E6635C01
	dc.l $6B6B51F4,$1C6C6162,$856530D8,$F262004E,$6C0695ED,$1B01A57B,$8208F4C1,$F50FC457
	dc.l $65B0D9C6,$12B7E950,$8BBEB8EA,$FCB9887C,$62DD1DDF,$15DA2D49,$8CD37CF3,$FBD44C65
	dc.l $4DB26158,$3AB551CE,$A3BC0074,$D4BB30E2,$4ADFA541,$3DD895D7,$A4D1C46D,$D3D6F4FB
	dc.l $4369E96A,$346ED9FC,$AD678846,$DA60B8D0,$44042D73,$33031DE5,$AA0A4C5F,$DD0D7CC9
	dc.l $5005713C,$270241AA,$BE0B1010,$C90C2086,$5768B525,$206F85B3,$B966D409,$CE61E49F
	dc.l $5EDEF90E,$29D9C998,$B0D09822,$C7D7A8B4,$59B33D17,$2EB40D81,$B7BD5C3B,$C0BA6CAD
	dc.l $EDB88320,$9ABFB3B6,$03B6E20C,$74B1D29A,$EAD54739,$9DD277AF,$04DB2615,$73DC1683
	dc.l $E3630B12,$94643B84,$0D6D6A3E,$7A6A5AA8,$E40ECF0B,$9309FF9D,$0A00AE27,$7D079EB1
	dc.l $F00F9344,$8708A3D2,$1E01F268,$6906C2FE,$F762575D,$806567CB,$196C3671,$6E6B06E7
	dc.l $FED41B76,$89D32BE0,$10DA7A5A,$67DD4ACC,$F9B9DF6F,$8EBEEFF9,$17B7BE43,$60B08ED5
	dc.l $D6D6A3E8,$A1D1937E,$38D8C2C4,$4FDFF252,$D1BB67F1,$A6BC5767,$3FB506DD,$48B2364B
	dc.l $D80D2BDA,$AF0A1B4C,$36034AF6,$41047A60,$DF60EFC3,$A867DF55,$316E8EEF,$4669BE79
	dc.l $CB61B38C,$BC66831A,$256FD2A0,$5268E236,$CC0C7795,$BB0B4703,$220216B9,$5505262F
	dc.l $C5BA3BBE,$B2BD0B28,$2BB45A92,$5CB36A04,$C2D7FFA7,$B5D0CF31,$2CD99E8B,$5BDEAE1D
	dc.l $9B64C2B0,$EC63F226,$756AA39C,$026D930A,$9C0906A9,$EB0E363F,$72076785,$05005713
	dc.l $95BF4A82,$E2B87A14,$7BB12BAE,$0CB61B38,$92D28E9B,$E5D5BE0D,$7CDCEFB7,$0BDBDF21
	dc.l $86D3D2D4,$F1D4E242,$68DDB3F8,$1FDA836E,$81BE16CD,$F6B9265B,$6FB077E1,$18B74777
	dc.l $88085AE6,$FF0F6A70,$66063BCA,$11010B5C,$8F659EFF,$F862AE69,$616BFFD3,$166CCF45
	dc.l $A00AE278,$D70DD2EE,$4E048354,$3903B3C2,$A7672661,$D06016F7,$4969474D,$3E6E77DB
	dc.l $AED16A4A,$D9D65ADC,$40DF0B66,$37D83BF0,$A9BCAE53,$DEBB9EC5,$47B2CF7F,$30B5FFE9
	dc.l $BDBDF21C,$CABAC28A,$53B39330,$24B4A3A6,$BAD03605,$CDD70693,$54DE5729,$23D967BF
	dc.l $B3667A2E,$C4614AB8,$5D681B02,$2A6F2B94,$B40BBE37,$C30C8EA1,$5A05DF1B,$2D02EF8D
