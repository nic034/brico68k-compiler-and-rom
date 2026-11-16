# ---------------------------------------------------------------------------
# Pure-Python Neo Geo AES model: a line-for-line port of neocore.c (same API: neo_*), on the
# Python 68000 of m68k_py.py, with the part of the superzazu/z80 core (Nicolas Allemand, MIT
# licence) that the Z80 programs of the model run (the built-in test M1, or no program: $FF).
# Same timings, same results word for word as the C core (checked by emulator/regress_rom.py
# with CORE=python, emulator/test/test_neo_py.py).
# PyNeoLib() is used like the ctypes library: lib.neo_run_frame(), lib.neo_host_send(...);
# the output buffers can be ctypes arrays or lists.
#
# superzazu/z80: Copyright (c) 2019 Nicolas Allemand. MIT licence, same
# permission notice as Musashi's in m68k_py.py (full text: emulator/Z80_LICENSE.txt).
# ---------------------------------------------------------------------------
try:                            # one-file build: M68K is defined above
    M68K
except NameError:
    from m68k_py import M68K

CPU_HZ = 12000000
LINE_CYCLES = 768
FRAME_LINES = 264
FRAME_CYCLES = LINE_CYCLES * FRAME_LINES
VIS_FIRST = 16
VIS_LINES = 224
VSSTART = 256
HOST_CLEAR = CPU_HZ // 1000
HOST_TIMEOUT = CPU_HZ * 3
HOST_WORDS = 2048
WDOG_CYCLES = 1622015
VBSTART = 0xF0
VBL_IRQ_AT = VBSTART * LINE_CYCLES + 29
TMR_RELOAD_AT = VBSTART * LINE_CYCLES + 573
H_IDLE, H_SENT, H_WAIT, H_DONE, H_TIMEOUT = range(5)
# The built-in test M1 (Z80 program; same bytes in neocore.c and in tools/make_test_cart.py's
# MAME bench cartridge). YM2610 SSG: port $04 = register, $05 = data; f = 125 kHz / period.
#   $0000 boot: di / ld sp,$ffff / xor a / out ($0c),a / out ($08),a (NMI on) / ei / idle: jp idle
#   $0066 NMI: in a,($00) / cp 3 / jp z,stop / cp 1 / jp nz,other / ld a,1 / out ($0c),a / retn
#   $0090 stop ($03): SSG mixer $3F (all off), volume A 0 / jp 0 (reboot: reply $00)
#   $00B0 other: $5C / $5D / $5E: beeps / $02: jingle / $7F: chime / else retn
#   $0100 / $0130 / $0160 beep ($5C left 1000 Hz, $5D right 1506 Hz, $5E centre 749 Hz): tone A
#         period, mixer $3E (tone A on), volume A 15 / retn: the tone lasts until the next command
#   $0200 jingle ($02, TestFM; stand-in for the eyecatcher music of a real M1): ld sp,$ffff /
#         C5 E5 G5 (120 ms each) C6 (214 ms): ld d,n / loop: ld b,0 / djnz $ / dec d / jr nz,loop /
#         then silence / jp idle
#   $0290 chime ($7F, TestSsg; stand-in for the coin chime of a real M1): as the jingle, 1984 Hz
#         (~54 ms) then 1563 Hz (~81 ms), then silence / jp idle
TEST_M1_PARTS = (
    (0x0000, bytes.fromhex("f331ffffafd30cd308fbc30a00")),
    (0x0066, bytes.fromhex("db00fe03ca9000fe01c2b0003e01d30ced45")),
    (0x0090, bytes.fromhex("3e07d3043e3fd3053e08d3043e00d305c30000")),
    (0x00B0, bytes.fromhex("fe5cca0001fe5dca3001fe5eca6001fe02ca0002fe7fca9002ed45")),
    (0x0100, bytes.fromhex("3e00d3043e7dd3053e01d3043e00d3053e07d3043e3ed3053e08d3043e0fd305ed45")),
    (0x0130, bytes.fromhex("3e00d3043e53d3053e01d3043e00d3053e07d3043e3ed3053e08d3043e0fd305ed45")),
    (0x0160, bytes.fromhex("3e00d3043ea7d3053e01d3043e00d3053e07d3043e3ed3053e08d3043e0fd305ed45")),
    (0x0200, bytes.fromhex(
        "31ffff3e07d3043e3ed3053e08d3043e0fd3053e00d3043eefd3053e01d3043e00d305168f060010fe1520f9"
        "3e00d3043ebed3053e01d3043e00d305168f060010fe1520f93e00d3043e9fd3053e01d3043e00d305168f06"
        "0010fe1520f93e00d3043e77d3053e01d3043e00d3051600060010fe1520f93e07d3043e3fd3053e08d3043e"
        "00d305c30a00")),
    (0x0290, bytes.fromhex(
        "31ffff3e07d3043e3ed3053e08d3043e0fd3053e00d3043e3fd3053e01d3043e00d3051640060010fe1520f9"
        "3e00d3043e50d3053e01d3043e00d3051660060010fe1520f93e07d3043e3fd3053e08d3043e00d305c30a00")),
)
CART_MAX = 0x1000000
MAX_FAULTS = 16


def _make_neo():
    bios = bytearray(0x20000)
    wram = bytearray(0x10000)
    pal = [0] * 0x2000
    vram = [0] * 0x10000
    vram_offset = vram_read_buffer = vram_modulo = 0
    latch = [0] * 8
    anim_speed = anim_disabled = anim_frame_counter = anim_counter = 0
    irq_vbl = irq_tmr = irq3 = tmr_ctrl = 0
    tmr_load = 0
    tmr_next = 0
    now_base = 0
    wdog_kick = 0
    wdog_enabled = 0
    wdog_resets = 0
    # Z80 side
    z80_mode = 1
    m1 = bytearray(b"\xff" * 0x10000)
    z80ram = bytearray(0x800)
    snd_latch = snd_pending = nmi_enable = nmi_line = 0
    z80_reply = 0
    z80_commands = 0
    z80_time = 0
    zpc = 0; zsp = 0xFFFF; za = 0xFF; zzf = 1; zb = zd = 0
    ziff1 = ziff2 = ziff_delay = zhalted = znmi = 0
    ssg = [0] * 16              # YM2610 SSG registers as the Z80 wrote them
    ssg_addr = 0
    ssg_writes = 0
    # host
    h_state = H_IDLE
    h_t0 = 0
    h_armed = 0
    h_clear_pending = 0
    h_values = [0] * HOST_WORDS
    h_count = h_overflow = 0
    h_done_cycles = 0
    watch = None                # extension checker hook (emu_host.ExtCheck): watch(offset, cycle)
    # faults: list of (region, kind, bit, value)
    faults = []
    # cartridge
    cart_mode = 0
    cart = bytearray(b"\xff" * CART_MAX)
    cart_size = cart_banks = cart_bank = 0
    cart_writes = cart_latch_writes = 0
    cart_hold = 0xFFFF
    float_rng = 0x2545F491
    # video
    line_colour = [0] * VIS_LINES
    frame_lines = [0] * VIS_LINES
    frames = 0
    last_line = 0
    in_exec = False
    # test-only inputs (build_test_core.py's neo_test_inputs)
    t_p1, t_dip, t_p2, t_sa, t_sb, t_sys, t_mvs = 0xFF, 0x00, 0xFF, 0x00, 0x7F, 0xFF00, 0
    t_bram = bytearray(0x10000)

    cpu = None
    # Opcode fetch fast path for the 68000 (m68k_py _build): FW = the BIOS as words, at their byte
    # offset; FAST[0] = 1 while no BIOS socket read has to be seen by the model.
    FW = [0] * 0x20000
    FAST = [1]

    def fw_sync(lo=0, hi=0x20000):
        for o in range(lo & ~1, hi, 2):
            FW[o] = (bios[o] << 8) | bios[o + 1]

    def upd_fast():
        # read16 reads the BIOS through socket_addr, which only region 5 (BIOS socket) faults change
        FAST[0] = 0 if (h_armed or watch or any(f[0] == 5 for f in faults)) else 1

    def fault_data(region, w):
        for r, k, b, v in faults:
            if r == region and k == 0:
                w = (w | (1 << b)) if v else (w & ~(1 << b))
        return w

    def vectors_from_cart():
        for r, k, b, v in faults:
            if r == 7:
                return v
        return latch[1]

    def fault_addr(region, idx, shift):
        for r, k, b, v in faults:
            if r == region and k == 1:
                m = 1 << (b - shift)
                idx = (idx | m) if v else (idx & ~m)
        return idx

    def rng_bit():
        nonlocal float_rng
        x = float_rng
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        float_rng = x
        return x & 1

    def socket_addr(o):
        for r, k, b, v in faults:
            if r == 5:
                m = 1 << b
                if k == 3:
                    v = rng_bit()
                o = (o | m) if v else (o & ~m)
        return o & 0x1FFFE

    def slot_strobe_dead(s):
        for r, k, b, v in faults:
            if r == 6 and k == 2 and v == s:
                return True
        return False

    def slot_data(w):
        for r, k, b, v in faults:
            if r == 6 and k == 3:
                w = (w | (1 << b)) if rng_bit() else (w & ~(1 << b))
        return fault_data(6, w) & 0xFFFF

    def cart_read(a):
        if not cart_mode:
            return 0xFFFF
        p2 = a >= 0x200000
        o = fault_addr(6, a & 0xFFFFE, 0) & 0xFFFFE
        if cart_mode == 1:
            if p2 and not cart_banks:
                return slot_data(0xFFFF)
            o += (0x100000 + cart_bank * 0x100000) if p2 else 0
        w = (cart[o] << 8) | cart[o + 1]
        if faults:
            oe, h = (4, 8) if p2 else (2, 6)
            if slot_strobe_dead(oe):
                w = (w & 0xFF00) | (open_bus() & 0x00FF)
            if slot_strobe_dead(oe + 1):
                w = (w & 0x00FF) | (open_bus() & 0xFF00)
            if slot_strobe_dead(h):
                w = (w & 0xFF00) | (cart_hold & 0x00FF)
            if slot_strobe_dead(h + 1):
                w = (w & 0x00FF) | (cart_hold & 0xFF00)
        return slot_data(w)

    def cart_write(a, d, mask):
        nonlocal cart_writes, cart_hold, cart_latch_writes, cart_bank
        cart_writes += 1
        cart_hold = (cart_hold & ~mask) | (d & mask)
        if mask & 0x00FF:
            cart_latch_writes += 1
            if cart_mode == 1 and cart_banks:
                cart_bank = (slot_data(d) & 7) % cart_banks
        if cart_mode != 2:
            return
        o = fault_addr(6, a & 0xFFFFE, 0) & 0xFFFFE
        d = slot_data(d)
        if (mask & 0xFF00) and not slot_strobe_dead(1):
            cart[o] = (d >> 8) & 0xFF
        if (mask & 0x00FF) and not slot_strobe_dead(0):
            cart[o + 1] = d & 0xFF

    def lane_dead(lane):
        for r, k, b, v in faults:
            if r == 0 and k == 2 and v == lane:
                return True
        return False

    def now():
        return now_base + (cpu.cycles_run() if in_exec else 0)

    def pal_bank():
        return 0x1000 if latch[7] else 0

    def pal_index(a):
        return fault_addr(1, pal_bank() | ((a >> 1) & 0xFFF), 1) & 0x1FFF

    def wram_index(a):
        return fault_addr(0, a & 0xFFFF, 0) & 0xFFFE

    def vram_phys(v):
        if v & 0x8000:
            return 0x8000 | (fault_addr(3, v & 0x7FF, 0) & 0x7FF)
        return fault_addr(2, v & 0x7FFF, 0) & 0x7FFF

    def vram_read(v):
        if not faults:                           # = the line below with no fault
            return vram[(0x8000 | (v & 0x7FF)) if v & 0x8000 else (v & 0x7FFF)] & 0xFFFF
        return fault_data(3 if v & 0x8000 else 2, vram[vram_phys(v)]) & 0xFFFF

    def vpos_now():
        return (now() % FRAME_CYCLES) // LINE_CYCLES

    def video_control():
        v = vpos_now() + 0x100
        if v >= 0x200:
            v -= FRAME_LINES
        v = fault_data(4, v) & 0x1FF
        return ((v << 7) | (anim_counter & 7)) & 0xFFFF

    def open_bus():
        p = cpu.pc() & 0xFFFFFE
        if 0xC00000 <= p < 0xD00000:
            o = socket_addr(p & 0x1FFFE)
            return (bios[o] << 8) | bios[o + 1]
        return 0xFFFF

    # ---- Z80 (superzazu/z80 semantics for the opcodes the model's programs use)
    def zrb(a):
        return m1[a] if a < 0xF800 else z80ram[a - 0xF800]

    def zwb(a, v):
        if a >= 0xF800:
            z80ram[a - 0xF800] = v

    def update_nmi():
        nonlocal nmi_line, znmi
        line = 1 if (snd_pending and nmi_enable) else 0
        if line and not nmi_line:
            znmi = 1
        nmi_line = line

    def z_in(port):
        nonlocal snd_pending
        if port == 0x00:
            snd_pending = 0
            update_nmi()
            return snd_latch
        if 0x04 <= port <= 0x07:
            return 0
        if 0x08 <= (port & 0x0F) <= 0x0B:
            return 0
        return 0xFF

    def z_out(port, v):
        nonlocal snd_latch, nmi_enable, z80_reply, ssg_addr, ssg_writes
        if port == 0x04:                         # YM2610 address (port A)
            ssg_addr = v
            return
        if port == 0x05:                         # YM2610 data (port A): registers $00-$0F = SSG
            if ssg_addr < 0x10:
                ssg[ssg_addr] = v
                ssg_writes += 1
            return
        if port == 0x00:
            snd_latch = 0
            return
        if port == 0x08 or port == 0x18:
            nmi_enable = 1 if port == 0x08 else 0
            update_nmi()
            return
        if port == 0x0C:
            z80_reply = v

    def zpush(v):
        nonlocal zsp
        zsp = (zsp - 2) & 0xFFFF
        zwb(zsp, v & 0xFF)
        zwb((zsp + 1) & 0xFFFF, v >> 8)

    def znext():
        nonlocal zpc
        v = zrb(zpc)
        zpc = (zpc + 1) & 0xFFFF
        return v

    def znextw():
        lo = znext()
        return lo | (znext() << 8)

    def z80_step():
        """One z80_step(): an instruction (NOP when halted) then process_interrupts. Returns T-states."""
        nonlocal zpc, zsp, za, zzf, zb, zd, ziff1, ziff2, ziff_delay, zhalted, znmi
        if zhalted:
            cyc = 4
        else:
            op = znext()
            if op == 0xC3:                       # jp nn
                zpc = znextw(); cyc = 10
            elif op == 0xFF:                     # rst 38h
                zpush(zpc); zpc = 0x38; cyc = 11
            elif op == 0xDB:                     # in a,(n)
                za = z_in(znext()); cyc = 11
            elif op == 0xD3:                     # out (n),a
                z_out(znext(), za); cyc = 11
            elif op == 0xFE:                     # cp n (only Z is used by the programs)
                zzf = 1 if ((za - znext()) & 0xFF) == 0 else 0; cyc = 7
            elif op == 0xCA or op == 0xC2:       # jp z / jp nz
                t = znextw()
                if (zzf == 1) == (op == 0xCA):
                    zpc = t
                cyc = 10
            elif op == 0x3E:                     # ld a,n
                za = znext(); cyc = 7
            elif op == 0x31:                     # ld sp,nn
                zsp = znextw(); cyc = 10
            elif op == 0xAF:                     # xor a
                za = 0; zzf = 1; cyc = 4
            elif op == 0xF3:                     # di
                ziff1 = ziff2 = 0; cyc = 4
            elif op == 0xFB:                     # ei
                ziff_delay = 1; cyc = 4
            elif op == 0x00:
                cyc = 4
            elif op == 0x76:                     # halt
                zhalted = 1; cyc = 4
            elif op == 0x06:                     # ld b,n
                zb = znext(); cyc = 7
            elif op == 0x16:                     # ld d,n
                zd = znext(); cyc = 7
            elif op == 0x10:                     # djnz e
                e = znext(); zb = (zb - 1) & 0xFF; cyc = 8
                if zb:
                    zpc = (zpc + e - ((e & 0x80) << 1)) & 0xFFFF; cyc = 13
            elif op == 0x15:                     # dec d (only Z is used)
                zd = (zd - 1) & 0xFF; zzf = 1 if zd == 0 else 0; cyc = 4
            elif op == 0x20:                     # jr nz,e
                e = znext(); cyc = 7
                if not zzf:
                    zpc = (zpc + e - ((e & 0x80) << 1)) & 0xFFFF; cyc = 12
            elif op == 0xED:
                op2 = znext()
                if op2 == 0x45:                  # retn
                    ziff1 = ziff2
                    lo = zrb(zsp); hi = zrb((zsp + 1) & 0xFFFF)
                    zsp = (zsp + 2) & 0xFFFF
                    zpc = lo | (hi << 8)
                    cyc = 14
                else:
                    raise RuntimeError(f"Z80 opcode ED {op2:02X} not modelled (pc {zpc:04X})")
            else:
                raise RuntimeError(f"Z80 opcode {op:02X} not modelled (pc {(zpc - 1) & 0xFFFF:04X})")
        # process_interrupts
        if ziff_delay > 0:
            ziff_delay -= 1
            if ziff_delay == 0:
                ziff1 = ziff2 = 1
            return cyc
        if znmi:
            znmi = 0
            zhalted = 0
            ziff1 = 0
            cyc += 11
            zpush(zpc)
            zpc = 0x66
        return cyc

    def z80_reset():
        nonlocal zpc, zsp, za, zzf, zb, zd, ziff1, ziff2, ziff_delay, zhalted, znmi, snd_pending, nmi_enable, nmi_line
        nonlocal z80_reply, ssg_addr
        zpc = 0; zsp = 0xFFFF; za = 0xFF; zzf = 1; zb = zd = 0
        ziff1 = ziff2 = ziff_delay = zhalted = znmi = 0
        snd_pending = nmi_enable = nmi_line = 0
        z80_reply = 0
        ssg[:] = [0] * 16          # the YM2610 is reset with the console (/IC on the reset line)
        ssg_addr = 0

    def z80_load_program():
        m1[:] = b"\xff" * 0x10000
        if z80_mode == 1:
            for a, b in TEST_M1_PARTS:
                m1[a:a + len(b)] = b

    def z80_sync():
        nonlocal z80_time, zsp
        target = now() // 3
        while z80_time < target:
            # idle loops, run in one go (same result as stepping: nothing else can happen in them)
            if not znmi and not ziff_delay and not zhalted:
                if zpc == 0x0A and m1[0x0A] == 0xC3 and m1[0x0B] == 0x0A and m1[0x0C] == 0x00:
                    n = (target - z80_time + 9) // 10            # jp $000A
                    z80_time += 10 * n
                    return
                if zpc == 0x38 and m1[0x38] == 0xFF:            # rst 38h at $38: the stack only moves
                    n = (target - z80_time + 10) // 11
                    z80_time += 11 * n
                    for _ in range(min(n, 0x8000)):            # stack writes land in RAM as stepping does
                        zpush(0x39)
                    if n > 0x8000:
                        zsp = (zsp - 2 * (n - 0x8000)) & 0xFFFF
                    return
            z80_time += z80_step()

    def z80_command(c):
        nonlocal z80_commands, snd_latch, snd_pending
        z80_sync()
        z80_commands += 1
        snd_latch = c
        snd_pending = 1
        update_nmi()

    def vram_set_offset(d):
        nonlocal vram_offset, vram_read_buffer
        vram_offset = (d & 0x87FF) if (d & 0x8000) else d
        vram_read_buffer = vram_read(vram_offset)

    def vram_write(d):
        v = vram_offset
        vram[((0x8000 | (v & 0x7FF)) if v & 0x8000 else (v & 0x7FFF)) if not faults else vram_phys(v)] = d & 0xFFFF
        vram_set_offset((vram_offset & 0x8000) | ((vram_offset + vram_modulo) & 0x7FFF))

    def host_port_read(o):
        nonlocal h_armed, h_count, h_overflow, h_state, h_done_cycles
        if watch:
            watch(o, now())
            if o < 0xA0 and not h_armed:        # a command block read, seen only because of the hook
                return
        if h_armed:
            h_armed -= 1
            if h_armed:
                return
            upd_fast()
            if h_state == H_SENT or h_state == H_WAIT:
                h_values[h_count % HOST_WORDS] = (o >> 1) & 0xFFFF
                h_count += 1
                if h_count >= HOST_WORDS:
                    h_overflow = 1
            return
        if o == 0x1FF02:
            h_armed = 2
            FAST[0] = 0
            return
        if o == 0x1FF00:
            if h_state == H_SENT or h_state == H_WAIT:
                h_state = H_DONE
                h_done_cycles = now() - h_t0

    # ---- 16-bit bus
    def read16(a, lsb_only=0):
        a &= 0xFFFFFE
        if 0xC00000 <= a < 0xD00000:                                  # BIOS socket (most accesses)
            o = socket_addr(a & 0x1FFFE) if faults else (a & 0x1FFFE)
            if h_armed or o == 0x1FF02 or o == 0x1FF00 or (o < 0xA0 and watch):
                host_port_read(o)
            return (bios[o] << 8) | bios[o + 1]
        if a < 0x000080:
            if vectors_from_cart():
                return cart_read(a)
            o = socket_addr(a)
            if h_armed or o == 0x1FF02 or o == 0x1FF00:
                host_port_read(o)
            return (bios[o] << 8) | bios[o + 1]
        if a < 0x100000:
            return cart_read(a)
        if a < 0x200000:
            if not faults:
                o = a & 0xFFFE
                return (wram[o] << 8) | wram[o + 1]
            o = wram_index(a)
            w = (wram[o] << 8) | wram[o + 1]
            if lane_dead(1):
                w |= 0xFF00
            if lane_dead(0):
                w |= 0x00FF
            return fault_data(0, w)
        if a < 0x300000:
            return cart_read(a)
        if a < 0x320000:
            return t_sys if a == 0x300080 else ((t_p1 << 8) | t_dip)
        if a < 0x340000:
            z80_sync()
            return (z80_reply << 8) | t_sa
        if a < 0x360000:
            return t_p2 << 8
        if a < 0x380000:
            return open_bus()
        if a < 0x3A0000:
            return (t_sb << 8) | 0xFF
        if a < 0x3C0000:
            return open_bus()
        if a < 0x3E0000:
            if lsb_only:
                return open_bus() & 0xFF
            r = (a >> 1) & 3
            if r < 2:
                return vram_read_buffer
            if r == 2:
                return vram_modulo
            return video_control()
        if a < 0x400000:
            return open_bus()
        if a < 0x800000:
            return fault_data(1, pal[pal_index(a)]) & 0xFFFF
        if a < 0xC00000:
            return 0xFFFF
        if t_mvs and a < 0xD10000:
            return (t_bram[a & 0xFFFE] << 8) | t_bram[(a & 0xFFFE) + 1]
        return open_bus()

    def write16(a, d, mask=0xFFFF):
        nonlocal cart_hold, wdog_kick, vram_modulo, anim_speed, anim_disabled, tmr_ctrl, tmr_load
        nonlocal irq3, irq_tmr, irq_vbl
        a &= 0xFFFFFE
        if 0x100000 <= a < 0x200000:
            if not faults:
                o = a & 0xFFFE
                if mask & 0xFF00:
                    wram[o] = (d >> 8) & 0xFF
                if mask & 0x00FF:
                    wram[o + 1] = d & 0xFF
                return
            o = wram_index(a)
            if (mask & 0xFF00) and not lane_dead(1):
                wram[o] = (d >> 8) & 0xFF
            if (mask & 0x00FF) and not lane_dead(0):
                wram[o + 1] = d & 0xFF
            return
        if a < 0x100000:
            cart_hold = (cart_hold & ~mask) | (d & mask)
            return
        if a < 0x300000:
            cart_write(a, d, mask)
            return
        if a < 0x320000:
            if mask & 0x00FF:
                wdog_kick = now()
            return
        if a < 0x340000:
            if mask & 0xFF00:
                z80_command((d >> 8) & 0xFF)
            return
        if 0x3A0000 <= a < 0x3C0000:
            if mask & 0x00FF:
                off = (a >> 1) & 0xF
                latch[off & 7] = (off & 8) >> 3
            return
        if 0x3C0000 <= a < 0x3E0000:
            r = (a >> 1) & 7
            if r == 0:
                vram_set_offset(d & 0xFFFF)
            elif r == 1:
                vram_write(d & 0xFFFF)
            elif r == 2:
                vram_modulo = d & 0xFFFF
            elif r == 3:
                anim_speed = (d >> 8) & 0xFF
                anim_disabled = (d >> 3) & 1
                tmr_ctrl = d & 0xF0
            elif r == 4:
                tmr_load = (tmr_load & 0x0000FFFF) | ((d & 0xFFFF) << 16)
            elif r == 5:
                tmr_load = (tmr_load & 0xFFFF0000) | (d & 0xFFFF)
                if tmr_ctrl & 0x20:
                    tmr_arm(now())
            elif r == 6:
                if d & 1:
                    irq3 = 0
                if d & 2:
                    irq_tmr = 0
                if d & 4:
                    irq_vbl = 0
                update_irq()
            return
        if 0x400000 <= a < 0x800000:
            i = pal_index(a)
            pal[i] = ((pal[i] & ~mask) | (d & mask)) & 0xFFFF
            return
        if t_mvs and 0xD00000 <= a < 0xD10000:
            if mask & 0xFF00:
                t_bram[a & 0xFFFE] = (d >> 8) & 0xFF
            if mask & 0x00FF:
                t_bram[(a & 0xFFFE) + 1] = d & 0xFF
            return
        # ROM, cartridge, memory card, unmapped: ignored

    def bus8(a):
        w = read16(a, a & 1)
        return (w & 0xFF) if (a & 1) else (w >> 8)

    def wbus8(a, v):
        nonlocal wdog_kick
        if a == 0x300001:                        # WatchDog macro (move.b d0,$300001): most byte writes
            wdog_kick = now()
            return
        if 0x400000 <= a < 0x800000:
            write16(a & ~1, (v & 0xFF) * 0x0101, 0xFFFF)
            return
        if a & 1:
            write16(a, v & 0xFF, 0x00FF)
        else:
            write16(a, (v & 0xFF) << 8, 0xFF00)

    def update_irq():
        cpu.set_irq(3 if irq3 else 2 if irq_tmr else 1 if irq_vbl else 0)

    def tmr_arm(t):
        nonlocal tmr_next
        tmr_next = t + 2 * (tmr_load + 1)

    def frame_event(t, at):
        f = t // FRAME_CYCLES * FRAME_CYCLES + at
        return f if f >= t else f + FRAME_CYCLES

    def reset_peripherals():
        nonlocal cart_bank, z80_time
        latch[:] = [0] * 8
        cart_bank = 0
        z80_reset()
        z80_time = now() // 3

    def line_event(line_abs):
        nonlocal anim_frame_counter, anim_counter, frames
        vpos = line_abs % FRAME_LINES
        if VIS_FIRST <= vpos < VIS_FIRST + VIS_LINES:
            line_colour[vpos - VIS_FIRST] = fault_data(1, pal[fault_addr(1, pal_bank() | 0xFFF, 1) & 0x1FFF]) & 0xFFFF
        if vpos == VSSTART:
            if anim_frame_counter == 0:
                anim_frame_counter = anim_speed
                anim_counter = (anim_counter + 1) & 0xFF
            else:
                anim_frame_counter -= 1
        if vpos == 0:
            frame_lines[:] = line_colour
            frames = (frames + 1) & 0xFFFFFFFF

    def host_update():
        nonlocal h_clear_pending, h_state
        t = now()
        if h_clear_pending and t - h_t0 >= HOST_CLEAR:
            bios[0x90:0xA0] = bytes(16)
            fw_sync(0x90, 0xA0)
            h_clear_pending = 0
            if h_state == H_SENT:
                h_state = H_WAIT
        if (h_state == H_SENT or h_state == H_WAIT) and t - h_t0 >= HOST_TIMEOUT:
            h_state = H_TIMEOUT

    # ---- API
    def neo_version():
        return 1

    def neo_load_bios(data, length=None):
        n = len(data) if length is None else length
        if n <= 0 or n > len(bios):
            return -1
        bios[:] = b"\xff" * len(bios)
        bios[:n] = bytes(data[:n])
        fw_sync()
        return 0

    def neo_power_on():
        nonlocal vram_offset, vram_read_buffer, vram_modulo, anim_speed, anim_disabled, anim_frame_counter
        nonlocal anim_counter, h_state, h_count, h_overflow, h_armed, h_clear_pending, now_base, last_line
        nonlocal frames, wdog_resets, irq_vbl, irq_tmr, irq3, tmr_ctrl, tmr_load, tmr_next, wdog_kick, ssg_writes
        ssg_writes = 0                              # SSG write count: since power on
        wram[:] = bytes(0x10000)
        pal[:] = [0] * 0x2000
        vram[:] = [0] * 0x10000
        vram_offset = vram_read_buffer = vram_modulo = 0
        anim_speed = anim_disabled = anim_frame_counter = anim_counter = 0
        line_colour[:] = [0] * VIS_LINES
        frame_lines[:] = [0] * VIS_LINES
        z80ram[:] = bytes(0x800)
        z80_load_program()
        h_state = H_IDLE; h_count = 0; h_overflow = 0; h_armed = 0; h_clear_pending = 0
        upd_fast()
        now_base = 0; last_line = 0; frames = 0; wdog_resets = 0
        irq_vbl = irq_tmr = 0; irq3 = 1; tmr_ctrl = 0; tmr_load = 0; tmr_next = 0
        reset_peripherals()
        cpu.pulse_reset()
        update_irq()
        wdog_kick = 0

    def neo_reset():
        nonlocal h_state, h_clear_pending, wdog_kick
        reset_peripherals()
        h_state = H_IDLE
        if h_clear_pending:
            bios[0x90:0xA0] = bytes(16)
            fw_sync(0x90, 0xA0)
            h_clear_pending = 0
        cpu.pulse_reset()
        update_irq()
        wdog_kick = now()

    def neo_set_options(z80, watchdog):
        nonlocal z80_mode, wdog_enabled
        if z80 != z80_mode:
            z80_mode = z80
            z80_load_program()
            reset_peripherals()
        wdog_enabled = watchdog

    def neo_run(cycles):
        nonlocal now_base, in_exec, irq_vbl, irq_tmr, tmr_next, last_line, wdog_resets
        end = now_base + cycles
        execute = cpu.execute
        while now_base < end:
            next_line = (now_base // LINE_CYCLES + 1) * LINE_CYCLES
            stop = next_line if next_line < end else end
            ev_vbl = frame_event(now_base, VBL_IRQ_AT)
            ev_rl = frame_event(now_base, TMR_RELOAD_AT)
            if ev_vbl == now_base:
                ev_vbl += FRAME_CYCLES
            if ev_rl == now_base:
                ev_rl += FRAME_CYCLES
            if ev_vbl < stop:
                stop = ev_vbl
            if ev_rl < stop:
                stop = ev_rl
            if tmr_next and now_base < tmr_next < stop:
                stop = tmr_next
            if h_clear_pending and now_base < h_t0 + HOST_CLEAR < stop:
                stop = h_t0 + HOST_CLEAR
            before = now_base
            in_exec = True
            used = execute(stop - now_base)
            in_exec = False
            now_base += used
            changed = False
            if frame_event(before + 1, VBL_IRQ_AT) <= now_base:
                irq_vbl = 1
                changed = True
            r = frame_event(before + 1, TMR_RELOAD_AT)
            if r <= now_base and (tmr_ctrl & 0x40):
                tmr_arm(r)
            while tmr_next and tmr_next <= now_base:
                if tmr_ctrl & 0x10:
                    irq_tmr = 1
                    changed = True
                if tmr_ctrl & 0x80:
                    tmr_arm(tmr_next)
                else:
                    tmr_next = 0
            if changed:
                update_irq()
            while (last_line + 1) * LINE_CYCLES <= now_base:
                last_line = (last_line + 1) & 0xFFFFFFFF
                line_event(last_line)
            host_update()
            z80_sync()
            if wdog_enabled and now_base - wdog_kick > WDOG_CYCLES:
                wdog_resets += 1
                neo_reset()

    def neo_run_frame():
        neo_run(FRAME_CYCLES)

    def neo_host_send(addr, p1, p2, p3):
        nonlocal h_count, h_overflow, h_armed, h_t0, h_state, h_clear_pending
        if h_state == H_SENT or h_state == H_WAIT or h_clear_pending:
            return -1
        for i, v in enumerate((addr, p1, p2, p3)):
            bios[0x90 + 4 * i:0x94 + 4 * i] = (v & 0xFFFFFFFF).to_bytes(4, "big")
        fw_sync(0x90, 0xA0)
        h_count = 0; h_overflow = 0; h_armed = 0
        upd_fast()
        h_t0 = now_base
        h_state = H_SENT
        h_clear_pending = 1
        return 0

    def neo_host_state():
        return h_state

    def neo_host_values(out, maxn):
        n = h_count % HOST_WORDS
        if n > maxn:
            n = maxn
        base = h_count - (h_count % HOST_WORDS)
        for i in range(n):
            out[i] = h_values[(base + i) % HOST_WORDS]
        return n

    def neo_host_overflow():
        return h_overflow

    def neo_host_cycles():
        return h_done_cycles & 0xFFFFFFFF

    def neo_host_ack():
        nonlocal h_state
        if h_state == H_DONE or h_state == H_TIMEOUT:
            h_state = H_IDLE

    def neo_get_lines(out):
        out[:VIS_LINES] = frame_lines

    def neo_get_vram(out):
        if not faults:
            out[:0x8800] = vram[:0x8800]
        else:
            out[:0x8800] = [vram_read(v) for v in range(0x8800)]

    def neo_get_palette(out):
        if not faults:
            b = pal_bank()
            out[:0x1000] = pal[b:b + 0x1000]
        else:
            out[:0x1000] = [fault_data(1, pal[pal_index(i << 1)]) & 0xFFFF for i in range(0x1000)]

    def neo_cart_load(mode, data, length=None):
        nonlocal cart_mode, cart_size, cart_banks, cart_bank, cart_writes, cart_latch_writes, cart_hold
        n = (len(data) if data else 0) if length is None else length
        if mode < 0 or mode > 2 or n < 0 or n > CART_MAX:
            return -1
        if mode == 1 and (n < 0x100000 or (n & 0xFFFFF)):
            return -1
        if mode == 2 and n > 0x100000:
            return -1
        cart_mode = mode
        cart[:] = b"\xff" * CART_MAX
        cart_size = n
        if data and n:
            cart[:n] = bytes(data[:n])
        cart_banks = (cart_size - 0x100000) // 0x100000 if mode == 1 else 0
        cart_bank = 0
        cart_writes = cart_latch_writes = 0
        cart_hold = 0xFFFF
        return 0

    def neo_fault_clear():
        faults.clear()
        upd_fast()

    def neo_fault_add(region, kind, bit, value):
        data_bits = (15, 15, 15, 15, 8, -1, 15, 0)
        addr_lo = (1, 1, 0, 0, -1, 1, 1, -1)
        addr_hi = (15, 13, 14, 10, -1, 16, 19, -1)
        if kind < 0 or kind > 3 or len(faults) >= MAX_FAULTS or region < 0 or region > 7:
            return -1
        if region == 7 and kind != 0:
            return -1
        if value < 0 or value > (9 if (region == 6 and kind == 2) else 1):
            return -1
        if kind == 0 and (bit < 0 or bit > data_bits[region]):
            return -1
        if kind == 1 and (addr_lo[region] < 0 or bit < addr_lo[region] or bit > addr_hi[region]):
            return -1
        if kind == 2 and region != 0 and region != 6:
            return -1
        if kind == 3 and region == 5 and (bit < 1 or bit > 16):
            return -1
        if kind == 3 and region == 6 and (bit < 0 or bit > 15):
            return -1
        if kind == 3 and region != 5 and region != 6:
            return -1
        faults.append((region, kind, bit, value))
        upd_fast()
        return 0

    def neo_ssg_regs(out):
        """The 16 YM2610 SSG registers into out[0..15]; returns the count of SSG register writes."""
        out[:16] = ssg
        return ssg_writes & 0xFFFFFFFF

    def neo_watch(fn):
        """Python core only: fn(offset, cycle) on every read of the host ports ($1FF00 / $1FF02 and the
        armed reads after them) and of the command block $90-$9F; None to stop."""
        nonlocal watch
        watch = fn
        upd_fast()

    def neo_test_inputs(p1, dip, p2, sa, sb, sys_, mvs):
        """Test hook (as build_test_core.py's core): input ports, MVS backup RAM."""
        nonlocal t_p1, t_dip, t_p2, t_sa, t_sb, t_sys, t_mvs
        t_p1, t_dip, t_p2, t_sa, t_sb, t_sys, t_mvs = p1, dip, p2, sa, sb, sys_, mvs

    api = dict(
        neo_version=neo_version, neo_load_bios=neo_load_bios, neo_power_on=neo_power_on, neo_reset=neo_reset,
        neo_set_options=neo_set_options, neo_run=neo_run, neo_run_frame=neo_run_frame,
        neo_host_send=neo_host_send, neo_host_state=neo_host_state, neo_host_values=neo_host_values,
        neo_host_overflow=neo_host_overflow, neo_host_cycles=neo_host_cycles, neo_host_ack=neo_host_ack,
        neo_get_lines=neo_get_lines, neo_get_vram=neo_get_vram, neo_get_palette=neo_get_palette,
        neo_frames=lambda: frames, neo_pc=lambda: cpu.pc(), neo_reg=lambda r: cpu.get_reg(r),
        neo_cycles=lambda: now_base, neo_watchdog_resets=lambda: wdog_resets,
        neo_z80_commands=lambda: z80_commands, neo_z80_pc=lambda: zpc,
        neo_ssg_regs=neo_ssg_regs,
        neo_peek16=lambda a: read16(a & 0xFFFFFFFF, 0) & 0xFFFF,
        neo_cart_load=neo_cart_load, neo_cart_bank=lambda: cart_bank, neo_cart_writes=lambda: cart_writes,
        neo_cart_latch_writes=lambda: cart_latch_writes, neo_fault_clear=neo_fault_clear,
        neo_fault_count=lambda: len(faults), neo_fault_add=neo_fault_add, neo_test_inputs=neo_test_inputs, neo_watch=neo_watch)

    def attach(c):
        nonlocal cpu
        cpu = c

    return api, attach, read16, bus8, write16, wbus8, (FAST, FW)


class PyNeoLib:
    """The neocore.c API in Python: lib.neo_xxx(...) as with the ctypes library."""

    def __init__(self):
        api, attach, bus16, bus8, wbus16, wbus8, fast = _make_neo()
        attach(M68K(bus16, bus8, wbus16, wbus8, fast=fast))
        self.__dict__.update(api)
