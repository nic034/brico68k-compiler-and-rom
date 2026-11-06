MEMORY {
	VECTORS: org=0xc00000, len=0x80
	ROM: org=0xc00080, len=0x7f7a	/* code ends at $C07FFA: $7FFA mirror byte, $7FFC CRC32 (NeoDiag layout, header flag $0004) */
}

SECTIONS {
	.vectors: {
		*(vectors)
	} >VECTORS

	.rom: {
		*(text)
	} >ROM
}
