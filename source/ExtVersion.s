	include "inc/define.inc"

	global EXT_VERSION

	section text

; ------------------------------------------------------------------------
; Version: the fork version (FORK_VERSION in inc/define.inc) and where the
; source comes from. Brico16Bits only shows the BricoExt header version
; (1.35, the upstream base it is built on).
; ------------------------------------------------------------------------
EXT_VERSION:
	Print "Brico68k "
	lea VERSION_TXT(pc),a1
	PrintA1
	PrintLn " - Nic034 fork (Nicolas), not an Aurelien34 release"
	PrintLn "Based on Aurelien34/Brico68k 1.35 (1b72deb): the BricoNeo shows 1.35"
	PrintLn "Source: github.com/nic034/brico68k-compiler-emulator-and-rom"
	jmp EOT_AND_WAIT

VERSION_TXT:
	FORK_VERSION
	dc.b 0
	even
