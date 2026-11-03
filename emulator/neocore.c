/*
 * neocore.c - Neo Geo AES model around the Musashi 68000 core, for testing
 * the Brico68k ROM without a BricoNeo / Brico16Bits.
 *
 * Modelled after MAME (src/mame/snk/neogeo.cpp, neogeo_v.cpp, neogeo_spr.cpp):
 *   68000 @ 12 MHz, 384 x 264 frame = 202752 CPU cycles, line = 768 cycles
 *   BIOS ROM $C00000 (128 KB, mirrored to $CFFFFF), WRAM $100000 (64 KB,
 *   mirrored), palette RAM $400000 (2 banks, HC259 latch Q7), system latch
 *   $3A0000 (A1-A3 = output, A4 = value), LSPC $3C0000 (VRAMADD / VRAMRW /
 *   VRAMMOD with MAME's read buffer and A15-preserving increment, video
 *   control with the 9-bit line counter $F8-$1FF and the auto-animation
 *   counter), inputs as read by MAME "aes" with nothing plugged in, open bus
 *   = word under the PC (prefetch).
 * NOT emulated: Z80 / YM2610 (replaced by a responder that behaves like the
 *   standard SM1/M1 driver handshake, or stays silent), sprites and fix layer
 *   (only the backdrop colour is rendered, one colour per line), interrupts
 *   (Brico68k keeps them masked), cartridge, memory card.
 * Brico16Bits host (Commands/CommandExtension.cpp): writes the command and
 * P1-P3 into the ROM image, clears them 1 ms later, collects the words sent
 * through the $C1FF02 port (value = address of the next read in the
 * $C20000 mirror), stops at the EOT read ($C1FF00) or after 3 s.
 */
#include <stdint.h>
#include <string.h>
#include "m68k.h"

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif

#define CPU_HZ        12000000u
#define LINE_CYCLES   768u
#define FRAME_LINES   264u
#define FRAME_CYCLES  (LINE_CYCLES * FRAME_LINES)
#define VIS_FIRST     16u                    /* MAME NEOGEO_VBEND */
#define VIS_LINES     224u
#define VSSTART       256u                   /* auto-animation tick line */
#define HOST_CLEAR    (CPU_HZ / 1000u)       /* 1 ms */
#define HOST_TIMEOUT  (CPU_HZ * 3u)          /* 3 s */
#define HOST_WORDS    2048                   /* Brico16Bits input buffer */
#define WDOG_CYCLES   1622015u               /* 3244030 ticks of 24 MHz */
#define Z80_DELAY     (CPU_HZ / 500u)        /* 2 ms answer delay */

static uint8_t  bios[0x20000];               /* big-endian, as the 68000 sees it */
static uint8_t  wram[0x10000];
static uint16_t pal[0x2000];                 /* 2 banks x 4096 words */
static uint16_t vram[0x10000];
static uint16_t vram_offset, vram_read_buffer, vram_modulo;
static uint8_t  latch[8];                    /* system latch HC259 outputs */
static uint8_t  anim_speed, anim_disabled, anim_frame_counter, anim_counter;
static uint64_t now_base;                    /* cycles before the running slice */
static uint64_t wdog_kick;
static int      wdog_enabled;
static int      wdog_resets;

/* Z80 responder */
static int      z80_mode = 1;                /* 0 = no answer, 1 = standard driver */
static uint8_t  z80_reply;
static int      z80_pending = -1;
static uint64_t z80_due;
static uint32_t z80_commands;

/* host */
enum { H_IDLE = 0, H_SENT = 1, H_WAIT = 2, H_DONE = 3, H_TIMEOUT = 4 };
static int      h_state;
static uint64_t h_t0;
static int      h_armed;
static int      h_clear_pending;            /* the 1 ms clear happens whatever the state */
static uint16_t h_values[HOST_WORDS];
static int      h_count, h_overflow;
static uint64_t h_done_cycles;

/* video output: backdrop colour per visible line */
static uint16_t line_colour[VIS_LINES];
static uint16_t frame_lines[VIS_LINES];
static uint32_t frames;
static uint32_t last_line;                   /* absolute line index of the last line event */

static uint64_t now(void) { return now_base + (uint64_t)m68k_cycles_run(); }
static unsigned pal_bank(void) { return latch[7] ? 0x1000 : 0; }

static unsigned vpos_now(void) { return (unsigned)((now() % FRAME_CYCLES) / LINE_CYCLES); }

static uint16_t video_control(void)
{
	unsigned v = vpos_now() + 0x100;
	if (v >= 0x200) v -= FRAME_LINES;
	return (uint16_t)((v << 7) | (anim_counter & 7));
}

static uint16_t open_bus(void)
{
	unsigned pc = m68k_get_reg(NULL, M68K_REG_PC) & 0xFFFFFE;
	if (pc >= 0xC00000 && pc < 0xD00000) {
		unsigned o = pc & 0x1FFFF;
		return (uint16_t)((bios[o] << 8) | bios[o + 1]);
	}
	return 0xFFFF;
}

static void z80_command(uint8_t c)
{
	z80_commands++;
	if (z80_mode == 0) return;
	if (c == 0x01 || c == 0x03) {         /* $01: answer $01, $03: reset -> $00 */
		z80_pending = (c == 0x01) ? 0x01 : 0x00;
		z80_due = now() + Z80_DELAY;
	}
}

static void z80_update(void)
{
	if (z80_pending >= 0 && now() >= z80_due) {
		z80_reply = (uint8_t)z80_pending;
		z80_pending = -1;
	}
}

static void vram_set_offset(uint16_t d)
{
	vram_offset = (d & 0x8000) ? (d & 0x87FF) : d;
	vram_read_buffer = vram[vram_offset];
}

static void vram_write(uint16_t d)
{
	vram[vram_offset] = d;
	vram_set_offset((uint16_t)((vram_offset & 0x8000) | ((vram_offset + vram_modulo) & 0x7FFF)));
}

static void host_port_read(unsigned a)
{
	if (a == 0xC1FF02) { h_armed = 1; return; }
	if (a == 0xC1FF00) {
		if (h_state == H_SENT || h_state == H_WAIT) { h_state = H_DONE; h_done_cycles = now() - h_t0; }
		return;
	}
	if (h_armed && a >= 0xC20000 && a < 0xC40000) {
		h_armed = 0;
		if (h_state == H_SENT || h_state == H_WAIT) {
			if (h_count < HOST_WORDS) h_values[h_count++] = (uint16_t)((a - 0xC20000) >> 1);
			else h_overflow = 1;
		}
	}
}

/* ---- 16-bit bus ------------------------------------------------------- */
static unsigned read16(unsigned a, int lsb_only)
{
	a &= 0xFFFFFE;
	if (a < 0x000080) return latch[1] ? 0xFFFF : ((bios[a] << 8) | bios[a + 1]);
	if (a < 0x100000) return 0xFFFF;                        /* no cartridge */
	if (a < 0x200000) { unsigned o = a & 0xFFFF; return (wram[o] << 8) | wram[o + 1]; }
	if (a < 0x300000) return 0xFFFF;                        /* no cartridge (P2) */
	if (a < 0x320000) return 0xFF00;                        /* P1: nothing pressed */
	if (a < 0x340000) { z80_update(); return (unsigned)z80_reply << 8; }
	if (a < 0x360000) return 0xFF00;                        /* P2 */
	if (a < 0x380000) return open_bus();
	if (a < 0x3A0000) return 0x7FFF;                        /* STATUS_B: AES, no memory card */
	if (a < 0x3C0000) return open_bus();
	if (a < 0x3E0000) {
		if (lsb_only) return open_bus() & 0xFF;
		switch ((a >> 1) & 3) {
		case 0: case 1: return vram_read_buffer;
		case 2: return vram_modulo;
		default: return video_control();
		}
	}
	if (a < 0x400000) return open_bus();
	if (a < 0x800000) return pal[pal_bank() + ((a >> 1) & 0xFFF)];
	if (a < 0xC00000) return 0xFFFF;                        /* memory card: none */
	if (a < 0xD00000) {
		host_port_read(a);
		unsigned o = a & 0x1FFFF;
		return (bios[o] << 8) | bios[o + 1];
	}
	return open_bus();                                      /* AES: no backup RAM */
}

static void write16(unsigned a, unsigned d, unsigned mask)  /* mask: 0xFF00 / 0x00FF / 0xFFFF */
{
	a &= 0xFFFFFE;
	if (a >= 0x100000 && a < 0x200000) {
		unsigned o = a & 0xFFFF;
		if (mask & 0xFF00) wram[o] = (uint8_t)(d >> 8);
		if (mask & 0x00FF) wram[o + 1] = (uint8_t)d;
		return;
	}
	if (a >= 0x300000 && a < 0x320000) { if (mask & 0x00FF) wdog_kick = now(); return; }
	if (a >= 0x320000 && a < 0x340000) { if (mask & 0xFF00) z80_command((uint8_t)(d >> 8)); return; }
	if (a >= 0x3A0000 && a < 0x3C0000) {
		if (mask & 0x00FF) { unsigned off = (a >> 1) & 0xF; latch[off & 7] = (uint8_t)((off & 8) >> 3); }
		return;
	}
	if (a >= 0x3C0000 && a < 0x3E0000) {
		switch ((a >> 1) & 7) {
		case 0: vram_set_offset((uint16_t)d); break;
		case 1: vram_write((uint16_t)d); break;
		case 2: vram_modulo = (uint16_t)d; break;
		case 3: anim_speed = (uint8_t)(d >> 8); anim_disabled = (uint8_t)((d >> 3) & 1); break;
		default: break;                                     /* timer / IRQ ack: no interrupts modelled */
		}
		return;
	}
	if (a >= 0x400000 && a < 0x800000) {
		uint16_t *p = &pal[pal_bank() + ((a >> 1) & 0xFFF)];
		*p = (uint16_t)((*p & ~mask) | (d & mask));
		return;
	}
	/* ROM, cartridge, memory card, unmapped: ignored */
}

unsigned int m68k_read_memory_8(unsigned int a)
{
	unsigned w = read16(a, !(a & 1) ? 0 : 1);
	return (a & 1) ? (w & 0xFF) : (w >> 8);
}
unsigned int m68k_read_memory_16(unsigned int a) { return read16(a, 0); }
unsigned int m68k_read_memory_32(unsigned int a) { unsigned h = read16(a, 0); return (h << 16) | read16(a + 2, 0); }
void m68k_write_memory_8(unsigned int a, unsigned int v)
{
	if (a & 1) write16(a, v & 0xFF, 0x00FF); else write16(a, (v & 0xFF) << 8, 0xFF00);
}
void m68k_write_memory_16(unsigned int a, unsigned int v) { write16(a, v & 0xFFFF, 0xFFFF); }
void m68k_write_memory_32(unsigned int a, unsigned int v) { write16(a, v >> 16, 0xFFFF); write16(a + 2, v & 0xFFFF, 0xFFFF); }
unsigned int m68k_read_disassembler_8(unsigned int a) { return m68k_read_memory_8(a); }
unsigned int m68k_read_disassembler_16(unsigned int a) { return m68k_read_memory_16(a); }
unsigned int m68k_read_disassembler_32(unsigned int a) { return m68k_read_memory_32(a); }

static void reset_peripherals(void)
{
	memset(latch, 0, sizeof latch);
	z80_pending = -1;
	z80_reply = 0;
}

void neo_reset_instr(void) { z80_pending = -1; z80_reply = 0; }   /* RESET line: audio side */

/* ---- line events ------------------------------------------------------ */
static void line_event(uint32_t line_abs)
{
	unsigned vpos = line_abs % FRAME_LINES;
	if (vpos >= VIS_FIRST && vpos < VIS_FIRST + VIS_LINES)
		line_colour[vpos - VIS_FIRST] = pal[pal_bank() + 0xFFF];
	if (vpos == VSSTART) {
		if (anim_frame_counter == 0) { anim_frame_counter = anim_speed; anim_counter++; }
		else anim_frame_counter--;
	}
	if (vpos == 0) {
		memcpy(frame_lines, line_colour, sizeof frame_lines);
		frames++;
	}
}

static void host_update(void)
{
	uint64_t t = now();
	if (h_clear_pending && t - h_t0 >= HOST_CLEAR) {   /* CommandExtension.cpp: sleep_ms(1) */
		memset(&bios[0x90], 0, 16);                     /* then SetExtParameters(0,0,0,0) */
		h_clear_pending = 0;
		if (h_state == H_SENT) h_state = H_WAIT;
	}
	if ((h_state == H_SENT || h_state == H_WAIT) && t - h_t0 >= HOST_TIMEOUT)
		h_state = H_TIMEOUT;
}

/* ---- exported API ----------------------------------------------------- */
EXPORT int neo_version(void) { return 1; }

EXPORT int neo_load_bios(const uint8_t *data, int len)
{
	if (len <= 0 || len > (int)sizeof bios) return -1;
	memset(bios, 0xFF, sizeof bios);
	memcpy(bios, data, (size_t)len);
	return 0;
}

EXPORT void neo_power_on(void)
{
	memset(wram, 0, sizeof wram);
	memset(pal, 0, sizeof pal);
	memset(vram, 0, sizeof vram);
	vram_offset = vram_read_buffer = vram_modulo = 0;
	anim_speed = anim_disabled = anim_frame_counter = anim_counter = 0;
	memset(line_colour, 0, sizeof line_colour);
	memset(frame_lines, 0, sizeof frame_lines);
	reset_peripherals();
	h_state = H_IDLE; h_count = 0; h_overflow = 0; h_armed = 0; h_clear_pending = 0;
	m68k_init();
	m68k_set_cpu_type(M68K_CPU_TYPE_68000);
	m68k_set_reset_instr_callback(neo_reset_instr);
	now_base = 0; last_line = 0; frames = 0; wdog_resets = 0;
	m68k_pulse_reset();
	wdog_kick = 0;
}

EXPORT void neo_reset(void)                  /* console reset button: RAM kept */
{
	reset_peripherals();
	h_state = H_IDLE;
	if (h_clear_pending) { memset(&bios[0x90], 0, 16); h_clear_pending = 0; }
	m68k_pulse_reset();
	wdog_kick = now();
}

EXPORT void neo_set_options(int z80, int watchdog) { z80_mode = z80; wdog_enabled = watchdog; }

/* run for `cycles` CPU cycles, cut at every line boundary */
EXPORT void neo_run(uint32_t cycles)
{
	uint64_t end = now_base + cycles;
	while (now_base < end) {
		uint64_t next_line = ((now_base / LINE_CYCLES) + 1) * LINE_CYCLES;
		uint64_t stop = next_line < end ? next_line : end;
		int used = m68k_execute((int)(stop - now_base));
		now_base += (uint64_t)used;
		while ((uint64_t)(last_line + 1) * LINE_CYCLES <= now_base) {
			last_line++;
			line_event(last_line);
		}
		host_update();
		z80_update();
		if (wdog_enabled && now_base - wdog_kick > WDOG_CYCLES) {
			wdog_resets++;
			neo_reset();
		}
	}
}

EXPORT void neo_run_frame(void) { neo_run(FRAME_CYCLES); }

EXPORT int neo_host_send(uint32_t addr, uint32_t p1, uint32_t p2, uint32_t p3)
{
	uint32_t v[4] = { addr, p1, p2, p3 };
	if (h_state == H_SENT || h_state == H_WAIT || h_clear_pending) return -1;
	/* command at $90, P1 $94, P2 $98, P3 $9C (big-endian) */
	for (int i = 0; i < 4; i++) {
		bios[0x90 + 4 * i + 0] = (uint8_t)(v[i] >> 24);
		bios[0x90 + 4 * i + 1] = (uint8_t)(v[i] >> 16);
		bios[0x90 + 4 * i + 2] = (uint8_t)(v[i] >> 8);
		bios[0x90 + 4 * i + 3] = (uint8_t)v[i];
	}
	h_count = 0; h_overflow = 0; h_armed = 0;
	h_t0 = now_base;
	h_state = H_SENT;
	h_clear_pending = 1;
	return 0;
}

EXPORT int neo_host_state(void) { return h_state; }
EXPORT int neo_host_values(uint16_t *out, int max)
{
	int n = h_count < max ? h_count : max;
	memcpy(out, h_values, (size_t)n * 2);
	return n;
}
EXPORT int neo_host_overflow(void) { return h_overflow; }
EXPORT uint32_t neo_host_cycles(void) { return (uint32_t)h_done_cycles; }
EXPORT void neo_host_ack(void) { if (h_state == H_DONE || h_state == H_TIMEOUT) h_state = H_IDLE; }

EXPORT void neo_get_lines(uint16_t *out) { memcpy(out, frame_lines, sizeof frame_lines); }
EXPORT uint32_t neo_frames(void) { return frames; }
EXPORT uint32_t neo_pc(void) { return m68k_get_reg(NULL, M68K_REG_PC); }
EXPORT uint32_t neo_reg(int r) { return m68k_get_reg(NULL, (m68k_register_t)r); }
EXPORT uint64_t neo_cycles(void) { return now_base; }
EXPORT int neo_watchdog_resets(void) { return wdog_resets; }
EXPORT uint32_t neo_z80_commands(void) { return z80_commands; }
EXPORT uint16_t neo_peek16(uint32_t a) { return (uint16_t)read16(a, 0); }
