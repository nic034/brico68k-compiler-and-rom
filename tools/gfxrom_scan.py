"""gfxrom_scan.py - reads a Neo Geo game set and writes a BricoNeo console script that shows
pictures from every C ROM chip pair with TestGfxRom's picture mode (1.35-nic034-19+).

    python tools/gfxrom_scan.py SET [-o script.txt] [--addr $10E000] [--palette N] [--list]

SET: the game's ROM set (zip or folder), as Brico68k Emulator loads it (P, S, C files).

What it does (the 68000 cannot read the C ROMs, so this is done on the PC):
  - C ROMs, per chip pair (C1/C2, C3/C4..., MAME's linear order): a game stores its sprites as
    columns of consecutive 16 x 16 tiles, each picture with its own height (no common height:
    measured on whp and samsho3). A column ends where the bottom row of a tile and the top row
    of the next are both transparent; the tool cuts the tiles there (14 at most, the screen) and
    picks, per pair, the stretch with the tallest columns.
  - P ROM: palettes are tables of 16-word blocks (colour 0 = $0000 or $8000, many different
    colours, blocks one after the other). The candidates are ranked; --list prints them,
    --palette N picks another one (default: the best). A guess: the game picks the palette of
    each sprite in its program, which is not decoded here.
  - The screen: one vertical band per pair (20 / pairs columns of 16 pixels), one sprite column
    per screen column, from the top. The script writes the table into WRAM with Write commands,
    then runs "TestGfxRom <addr>".
Reference picture: python Brico68k_Emulator.py --cart SET --script script.txt --png ref.png
Not proof of a good cartridge by itself: compare the TV with that picture, band by band.
"""
import argparse
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_SPRITES = 96                      # ExtTestGfx.s picture mode limit


def load_emulator():
    spec = importlib.util.spec_from_file_location("bemu", ROOT / "Brico68k_Emulator.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def tile_masks(c, first, count):
    """Per tile: (non-empty, top row mask, bottom row mask), 16 bits = pixel != 0."""
    out = []
    for t in range(first, first + count):
        o = t * 128
        g = c[o:o + 128]
        if len(g) < 128 or g.count(0) == 128:
            out.append((False, 0, 0))
            continue
        top = (g[0x40] | g[0x41] | g[0x42] | g[0x43]) << 8 | (g[0] | g[1] | g[2] | g[3])
        bot = (g[0x7C] | g[0x7D] | g[0x7E] | g[0x7F]) << 8 | (g[0x3C] | g[0x3D] | g[0x3E] | g[0x3F])
        out.append((True, top, bot))
    return out


def columns(masks, start, end, want, maxh=14):
    """Cuts the tiles from `start` into sprite columns: a column ends where the bottom row of a
    tile and the top row of the next are both transparent (the usual gap between two columns
    of a sprite), or at maxh tiles. Empty tiles between columns are skipped.
    Returns up to `want` (first tile index, height, ended by a transparent gap)."""
    out, t = [], start
    while t < end and len(out) < want:
        while t < end and not masks[t][0]:
            t += 1
        if t >= end:
            break
        h = 1
        while h < maxh and t + h < end and masks[t + h][0] and (masks[t + h - 1][2] or masks[t + h][1]):
            h += 1
        out.append((t, h, h < maxh))
        t += h
    return out


def best_start(masks, want, step=64):
    """Start of the stretch whose first `want` columns look most like sprites: columns 4-13
    tiles tall that end with a transparent gap (characters, objects). Columns that run into
    the 14-tile limit are mostly scenery textures: they count little."""
    best, start = -1, 0
    for s in range(0, max(1, len(masks) - want * 14), step):
        cols = columns(masks, s, min(len(masks), s + want * 40), want)
        sc = sum(h if gap and h >= 4 else h // 4 for _, h, gap in cols) if len(cols) == want else 0
        if sc > best:
            best, start = sc, s
    return start


def palettes(p):
    """Candidate palettes in the P ROM: (score, offset, 16 words), best first."""
    words = [p[i] << 8 | p[i + 1] for i in range(0, len(p) - 1, 2)]
    ok = []
    for w0 in range(0, len(words) - 16, 16):
        blk = words[w0:w0 + 16]
        if blk[0] not in (0x0000, 0x8000):
            ok.append(None)
            continue
        cols = blk[1:]
        d = len(set(cols))
        if d < 8 or sum(1 for c in cols if c in (0, 0xFFFF)) > 3:
            ok.append(None)
            continue
        ok.append(blk)
    cands = []
    for i, blk in enumerate(ok):
        if blk is None:
            continue
        run = 1                                           # tables: neighbours are palettes too
        j = i - 1
        while j >= 0 and ok[j] is not None:
            run, j = run + 1, j - 1
        j = i + 1
        while j < len(ok) and ok[j] is not None:
            run, j = run + 1, j + 1
        if run < 3:
            continue
        lum = sorted(((c >> 8 & 15) + (c >> 4 & 15) + (c & 15)) for c in blk[1:])
        spread = lum[-1] - lum[0]
        cands.append((min(run, 16) + len(set(blk[1:])) + spread / 4, i * 32, blk))
    cands.sort(key=lambda x: -x[0])
    return cands


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("set")
    ap.add_argument("-o", "--out")
    ap.add_argument("--addr", default="$10E000", help="WRAM address of the table (default $10E000)")
    ap.add_argument("--palette", type=int, default=0, help="candidate palette number (see --list)")
    ap.add_argument("--list", action="store_true", help="print the palette candidates")
    a = ap.parse_args()
    E = load_emulator()
    cart = E.load_cartridge(a.set)
    tiles = cart.tiles
    if not tiles or not getattr(tiles, "c", None):
        sys.exit("no C ROMs in this set")
    c = tiles.c
    cs = sorted((ch for ch in cart.chips if ch["chip"] == "C"), key=lambda ch: ch["file"])
    pairs, first = [], 0
    for i in range(0, len(cs) - 1, 2):
        cnt = 2 * min(cs[i]["size"], cs[i + 1]["size"]) // 128
        pairs.append((cs[i]["file"], cs[i + 1]["file"], first, cnt))
        first += cnt
    if not pairs:
        sys.exit("the C ROMs do not come in pairs")
    npairs = min(len(pairs), 8)
    cols = max(1, 20 // npairs)
    sprites, report = [], []
    for k, (fa, fb, first, cnt) in enumerate(pairs[:npairs]):
        masks = tile_masks(c, first, cnt)
        start = best_start(masks, cols)
        cuts = columns(masks, start, cnt, cols)
        report.append(f"pair {k + 1} {fa}/{fb}: tiles ${first:05X}-${first + cnt - 1:05X}, shown from "
                      f"${first + start:05X}: {len(cuts)} columns, {sum(h for _, h, _ in cuts)} tiles")
        for col, (t, h, _) in enumerate(cuts):
            sprites.append(((first + t) & 0xFFFFF, k * cols * 16 + col * 16, 0, h))
    cands = palettes(cart.data)
    if a.list:
        for i, (sc, off, blk) in enumerate(cands[:40]):
            print(f"{i:3d}  P ROM ${off:06X}  score {sc:5.1f}  " + " ".join(f"{w:04X}" for w in blk))
        return
    if cands:
        pi = min(a.palette, len(cands) - 1)
        pal, pnote = cands[pi][2], f"palette {pi} of {len(cands)} candidates, P ROM ${cands[pi][1]:06X}"
    else:
        pal = [0x8000] + [((i * 2) << 8) | ((i * 2) << 4) | (i * 2) for i in range(1, 16)]
        pnote = "no palette found in the P ROM: grey ramp"
    addr = int(a.addr.lstrip("$"), 16) if a.addr.startswith("$") else int(a.addr, 0)
    if not (0x100000 <= addr < 0x10F000 - (8 + 12 * len(sprites) + 32)) or addr & 1:
        sys.exit("--addr: even, in WRAM $100000-$10EFFF (below the stack)")
    srom = getattr(tiles, "s", b"") or b""
    blank = 0x20
    if srom and any(srom[0x20 * 32:0x21 * 32]):
        free = [n for n in [0xFF] + list(range(len(srom) // 32)) if not any(srom[n * 32:n * 32 + 32])]
        blank = free[0] if free else 0x20
    words = [0x4752, len(sprites), blank, 0]
    for t, x, y, h in sprites:
        words += [t >> 16, t & 0xFFFF, x, y, h, 0]
    words += list(pal)
    lines = [f"; Brico68k TestGfxRom pictures for {Path(a.set).name} (tools/gfxrom_scan.py)",
             f"; {len(sprites)} sprites, {npairs} chip pair band(s), {pnote}"]
    lines += ["; " + r for r in report]
    lines += [f"; table at ${addr:06X}: {len(words)} words written with Write (WRAM: run TestWRAM first",
              f";   if in doubt), then TestGfxRom shows it. Blank fix tile ${blank:02X} (found in the S ROM)."]
    lines += [f"Write ${w:04X} ${addr + 2 * i:06X}" for i, w in enumerate(words)]
    lines += [f"TestGfxRom ${addr:06X}"]
    text = "\n".join(lines) + "\n"
    if a.out:
        Path(a.out).write_text(text)
        print(f"{a.out}: {len(words)} Write commands + TestGfxRom")
    else:
        sys.stdout.write(text)
    for r in report:
        print(r, file=sys.stderr)
    print(pnote, file=sys.stderr)


if __name__ == "__main__":
    main()
