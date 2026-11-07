	include "inc/define.inc"
	include "inc/trace.inc"

	global EXT_TEST_AUDIO

	section text

; ------------------------------------------------------------------------
; TestAudio - UniBIOS-like audio test (upstream 1.35, reworked).
;
; Why the rework: the Brico16Bits host waits for ONE EOT, with a fixed 3 s
; timeout (CommandExtension.cpp), then stops reading. The 1.35 version sent
; an EOT right after its first line, so every later line was lost ("cette
; trace ne s'affiche pas !"), and each later EOT was taken by the host as a
; command sent by the 68k (68K_SENDS_COMMANDS flag). The beeps take more
; than 3 s, so a single EOT at the end would time out instead.
; Now: handshake + Z80 init (~0.15 s), print everything, ONE EOT, then play
; the beeps silently (~3.5 s). The host should wait ~4 s before the next
; command (the 68k does not poll for commands while beeping).
;
; Uses the stack (bsr/rts): needs working WRAM, unlike most extensions.
; ------------------------------------------------------------------------
EXT_TEST_AUDIO:
	PrintLn "Neo-Geo UniBIOS-like audio test"

	; Select the board SM1 + SFIX like the UniBIOS does (MVS only; this
	; latch output is not wired on AES, the cartridge M1 answers there)
	move.b #0,(REG_BRDFIX).l

	; Step 1: send $01 to the Z80 and wait for ACK $01
	bsr.w SM1_Send01AndWaitAck
	tst.b d0
	bne.s .ackOk
	PrintLn "ERROR: no Z80 ACK $01 (Z80, M1/SM1 ROM or NEO-D0/sound latch?)"
	jmp EOT_AND_WAIT(pc)

.ackOk:
	PrintLn "Z80 ACK $01 received"

	; Step 2: UniBIOS BIOSF_Z80_InitSeq: $01 -> long delay -> $03 ->
	; long delay -> $07 -> short delay
	move.b #1,(REG_SOUND).l
	bsr.w SM1_CommandDelay
	move.b #3,(REG_SOUND).l
	bsr.w SM1_CommandDelay
	move.b #$07,(REG_SOUND).l
	bsr.w SM1_ShortWait
	PrintLn "Z80 init sequence sent ($01, $03, $07)"
	PrintLn "Now playing: left, right, center beeps (~1 s each)."
	PrintLn "Listen to the audio output. A new command stops the beeps."

	; Single EOT: the host prints the report now, the beeps follow.
	WriteEOT

	; Step 3: left / right / center beep commands. The BricoNeo keeps a
	; command in the block for 1 ms only (Brico16Bits CommandExtension):
	; the waits poll it, else a command typed during the beeps would be
	; lost and time out. A new command stops the beeps and runs.
	move.b #$5C,(REG_SOUND).l
	bsr.w Wait_1Second
	move.b #$5D,(REG_SOUND).l
	bsr.w Wait_1Second
	move.b #$5E,(REG_SOUND).l
	bsr.w Wait_1Second

	; Step 4: stop / reset the Z80 sound driver
	move.b #3,(REG_SOUND).l
	bsr.w SM1_CommandDelay

	jmp WAIT_FOR_COMMAND(pc)

; ------------------------------------------------------------------------
; SM1_Send01AndWaitAck
; Out: d0.b = 1 ACK $01 received, 0 timeout. Destroys d0, d1, a0.
; ------------------------------------------------------------------------
SM1_Send01AndWaitAck:
	lea (REG_SOUND).l,a0
	bsr.w SM1_ShortWait			; BIOS short wait before sending
	move.b #1,(a0)				; PREPARE / ACK request
	bsr.w SM1_ShortWait			; let the Z80 handle the port
	move.w #$0FFF,d1
.poll:
	cmpi.b #1,(a0)
	beq.s .ack
	dbra d1,.poll
	moveq #0,d0
	rts
.ack:
	moveq #1,d0
	rts

; Short wait, BIOSF_Menu_ShortWait equivalent (~14 ms at 12 MHz).
; Kicks the watchdog (1.35 wrote to REG_SYSTYPE, a read-only input port).
SM1_ShortWait:
	moveq #$0F,d1
.outer:
	move.w #$0400,d0
.inner:
	dbra d0,.inner
	WatchDog
	dbra d1,.outer
	rts

; BIOSF_Menu_Scroll equivalent with d1=$40: 65 x 1025 loops (~55 ms).
SM1_CommandDelay:
	move.w #$0040,d1
.outer:
	move.w #$0400,d0
.inner:
	dbra d0,.inner
	WatchDog
	dbra d1,.outer
	rts

; ~1 s: 1536 x ~0.65 ms, polling the BricoNeo command block in between
; (it holds a command 1 ms).
; A command arrives: stop the sound (Z80 $03), reset SP (the bsr frames are
; dropped) and run it.
Wait_1Second:
	move.w #1536-1,d2
.loop:
	move.w #$0300,d0			; 769 x 10 cycles = ~0.64 ms
.inner:
	dbra d0,.inner
	WatchDog
	tst.l (BRICO_COMMAND_IN).l
	bne.s .command
	dbra d2,.loop
	rts
.command:
	move.b #3,(REG_SOUND).l
	lea RAM_RESERVED_SYS_ROM,sp
	jmp DISPATCH_COMMAND(pc)
