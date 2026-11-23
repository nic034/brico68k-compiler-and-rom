MEMORY {
	VECTORS: org=0xc00000, len=0x80
	ROM: org=0xc00080, len=0x1fe80	/* code ends before $C1FF00: $1FF00/$1FF02 are the BricoNeo output ports; $1FFE8-$1FFFF: TestBus CRC table (Brico68k Compiler) */
}

SECTIONS {
	.vectors: {
		*(vectors)
	} >VECTORS

	.rom: {
		*Brico68k.o(text)
		/* first 32 KB: what TestBus and the dispatcher need, so that they still
		   run with A15/A16 stuck at 0 (a quarter then reads as quarter 0) */
		*Tools.o(text)
		*Trace.o(text)
		*ExtTestBus.o(text)
		*Screen.o(text)
		*ExtEcho.o(text)
		*(text)
	} >ROM
}
