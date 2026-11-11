/* Test harness: the C Musashi of the emulator core on a flat 16 MB memory that logs every
 * bus access, for emulator/test/test_m68k_py.py (differential test of m68k_py.py). */
#include <stdint.h>
#include <string.h>
#include "m68k.h"
static uint8_t mem[0x1000000];
#define LOGMAX 4096
static uint32_t lg[LOGMAX][3]; static int nlog;
static void L(uint32_t kind, uint32_t a, uint32_t v) { if (nlog < LOGMAX) { lg[nlog][0] = kind; lg[nlog][1] = a; lg[nlog][2] = v; nlog++; } }
static unsigned r16(unsigned a) { a &= 0xFFFFFE; unsigned v = (mem[a] << 8) | mem[a + 1]; L(1, a, v); return v; }
static void w16(unsigned a, unsigned v) { a &= 0xFFFFFE; mem[a] = v >> 8; mem[a + 1] = v; L(3, a, v & 0xFFFF); }
unsigned int m68k_read_memory_8(unsigned int a) { a &= 0xFFFFFF; L(0, a, mem[a]); return mem[a]; }
unsigned int m68k_read_memory_16(unsigned int a) { return r16(a); }
unsigned int m68k_read_memory_32(unsigned int a) { unsigned h = r16(a); return (h << 16) | r16(a + 2); }
void m68k_write_memory_8(unsigned int a, unsigned int v) { a &= 0xFFFFFF; mem[a] = v; L(2, a, v & 0xFF); }
void m68k_write_memory_16(unsigned int a, unsigned int v) { w16(a, v); }
void m68k_write_memory_32(unsigned int a, unsigned int v) { w16(a, v >> 16); w16(a + 2, v & 0xFFFF); }
unsigned int m68k_read_disassembler_8(unsigned int a) { return mem[a & 0xFFFFFF]; }
unsigned int m68k_read_disassembler_16(unsigned int a) { a &= 0xFFFFFE; return (mem[a] << 8) | mem[a + 1]; }
unsigned int m68k_read_disassembler_32(unsigned int a) { return (m68k_read_disassembler_16(a) << 16) | m68k_read_disassembler_16(a + 2); }
static int nresets;
void neo_reset_instr(void) { nresets++; }
void h_init(void) { m68k_init(); m68k_set_cpu_type(M68K_CPU_TYPE_68000); m68k_set_reset_instr_callback(neo_reset_instr); }
void h_poke(uint32_t a, const uint8_t *d, int n) { memcpy(mem + a, d, n); }
void h_peek(uint32_t a, uint8_t *d, int n) { memcpy(d, mem + a, n); }
void h_reset(void) { nlog = 0; m68k_pulse_reset(); }
int h_exec(int c) { nlog = 0; return m68k_execute(c); }
void h_set_reg(int r, uint32_t v) { m68k_set_reg((m68k_register_t)r, v); }
uint32_t h_get_reg(int r) { return m68k_get_reg(NULL, (m68k_register_t)r); }
void h_set_irq(int l) { m68k_set_irq(l); }
int h_log(uint32_t *out) { memcpy(out, lg, nlog * 12); return nlog; }
int h_nresets(void) { return nresets; }
int h_regno(int which) { return which == 0 ? M68K_REG_PPC : which == 1 ? M68K_REG_IR : M68K_REG_CPU_TYPE; }
