#!/usr/bin/env python3
"""Turn one x86-64 ELF relocatable object into a static Linux program.

The frozen part of EnvMap Move is a freestanding C program: no C library, no
runtime, nothing loaded at start. Apple's clang compiles it for Linux on this
Mac but has no ELF linker, and a single self-contained object needs very
little linking: lay the sections out, resolve the relocations between them,
write two program headers. That is all this does, and it refuses anything it
does not understand instead of guessing.

usage: ld.py core.o core.bin
"""
from __future__ import annotations

import struct
import sys

BASE = 0x400000
PAGE = 0x1000

SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_RELA, SHT_NOBITS = 1, 2, 3, 4, 8
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 1, 2, 4
SHN_UNDEF, SHN_ABS, SHN_COMMON = 0, 0xFFF1, 0xFFF2

R_64, R_PC32, R_PLT32, R_GOTPCREL, R_32, R_32S, R_PC64, R_GOTPCRELX, R_REX_GOTPCRELX = 1, 2, 4, 9, 10, 11, 24, 41, 42


def fail(msg: str) -> None:
    raise SystemExit("ld.py: " + msg)


def main(src: str, dst: str) -> None:
    b = bytearray(open(src, "rb").read())
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        fail("not a 64-bit little-endian ELF file")
    e_type, e_machine = struct.unpack_from("<HH", b, 16)
    if e_type != 1 or e_machine != 62:
        fail("not an x86-64 relocatable object")
    e_shoff, = struct.unpack_from("<Q", b, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", b, 58)
    secs = []
    for i in range(e_shnum):
        name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from("<IIQQQQIIQQ", b, e_shoff + i * e_shentsize)
        secs.append(dict(i=i, name=name, type=typ, flags=flags, off=off, size=size, link=link, info=info, align=max(align, 1), entsize=entsize))
    shstr = secs[e_shstrndx]

    def sname(s: dict) -> str:
        o = shstr["off"] + s["name"]
        return b[o:b.index(0, o)].decode()

    for s in secs:
        s["n"] = sname(s)

    # Layout: text and read-only data in one segment, writable data and zeroed data in the next.
    rx = [s for s in secs if s["flags"] & SHF_ALLOC and not s["flags"] & SHF_WRITE and s["type"] != SHT_NOBITS]
    rw = [s for s in secs if s["flags"] & SHF_ALLOC and s["flags"] & SHF_WRITE and s["type"] != SHT_NOBITS]
    bss = [s for s in secs if s["flags"] & SHF_ALLOC and s["type"] == SHT_NOBITS]
    if any(s["flags"] & SHF_EXECINSTR and s["flags"] & SHF_WRITE for s in secs):
        fail("a section is both writable and executable")
    for s in secs:
        if s["n"] in (".init_array", ".fini_array", ".ctors", ".dtors", ".tdata", ".tbss"):
            if s["size"]:
                fail(f"section {s['n']} needs start-up code this program does not have")

    def align(v: int, a: int) -> int:
        return (v + a - 1) // a * a

    hdr = 64 + 2 * 56
    off = align(hdr, 16)
    image = bytearray(off)
    for s in rx:
        off = align(off, s["align"])
        image += bytes(off - len(image))
        s["addr"] = BASE + off
        image += b[s["off"]:s["off"] + s["size"]]
        off += s["size"]
    rx_end = off
    off = align(off, PAGE)
    image += bytes(off - len(image))
    rw_off = off
    for s in rw:
        off = align(off, s["align"])
        image += bytes(off - len(image))
        s["addr"] = BASE + off
        image += b[s["off"]:s["off"] + s["size"]]
        off += s["size"]
    file_end = off
    mem = off
    for s in bss:
        mem = align(mem, s["align"])
        s["addr"] = BASE + mem
        mem += s["size"]

    # Symbols.
    symtab = next((s for s in secs if s["type"] == SHT_SYMTAB), None)
    if symtab is None:
        fail("no symbol table")
    strtab = secs[symtab["link"]]
    syms = []
    for k in range(symtab["size"] // 24):
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", b, symtab["off"] + 24 * k)
        o = strtab["off"] + st_name
        nm = b[o:b.index(0, o)].decode()
        if st_shndx == SHN_UNDEF:
            addr = None
        elif st_shndx == SHN_ABS:
            addr = st_value
        elif st_shndx == SHN_COMMON:
            fail(f"common symbol {nm}: compile with -fno-common")
        else:
            t = secs[st_shndx]
            if "addr" not in t:
                addr = None if t["size"] else 0
                if t["size"]:
                    fail(f"symbol {nm} is in section {t['n']}, which is not loaded")
            else:
                addr = t["addr"] + st_value
        syms.append((nm, addr))

    # Relocations.
    for r in secs:
        if r["type"] != SHT_RELA:
            continue
        t = secs[r["info"]]
        if "addr" not in t:
            continue  # relocations for a section that is not loaded (debug info)
        if t["type"] == SHT_NOBITS:
            fail("relocation against zeroed data")
        base_in_image = t["addr"] - BASE
        for k in range(r["size"] // 24):
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, r["off"] + 24 * k)
            typ, si = r_info & 0xFFFFFFFF, r_info >> 32
            nm, S = syms[si]
            if S is None:
                fail(f"undefined symbol {nm!r}")
            P = t["addr"] + r_off
            at = base_in_image + r_off
            if typ in (R_GOTPCRELX, R_REX_GOTPCRELX, R_GOTPCREL):
                # mov foo@GOTPCREL(%rip), %reg  ->  lea foo(%rip), %reg
                if image[at - 2] != 0x8B:
                    fail(f"cannot relax a GOT load at {P:#x} for {nm}")
                image[at - 2] = 0x8D
                typ = R_PC32
            if typ == R_64:
                struct.pack_into("<Q", image, at, (S + r_add) & 0xFFFFFFFFFFFFFFFF)
            elif typ in (R_PC32, R_PLT32):
                v = S + r_add - P
                if not -(1 << 31) <= v < (1 << 31):
                    fail(f"PC-relative reference out of range for {nm}")
                struct.pack_into("<i", image, at, v)
            elif typ == R_32:
                v = S + r_add
                if not 0 <= v < (1 << 32):
                    fail(f"32-bit reference out of range for {nm}")
                struct.pack_into("<I", image, at, v)
            elif typ == R_32S:
                v = S + r_add
                if not -(1 << 31) <= v < (1 << 31):
                    fail(f"32-bit signed reference out of range for {nm}")
                struct.pack_into("<i", image, at, v)
            elif typ == R_PC64:
                struct.pack_into("<q", image, at, S + r_add - P)
            else:
                fail(f"relocation type {typ} for {nm} is not handled")

    entry = dict(syms).get("_start")
    if entry is None:
        fail("no _start")
    # ELF header and the two program headers.
    struct.pack_into("<4sBBBBB7xHHIQQQIHHHHHH", image, 0, b"\x7fELF", 2, 1, 1, 0, 0,
                     2, 62, 1, entry, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    PF_X, PF_W, PF_R = 1, 2, 4
    struct.pack_into("<IIQQQQQQ", image, 64, 1, PF_R | PF_X, 0, BASE, BASE, rx_end, rx_end, PAGE)
    struct.pack_into("<IIQQQQQQ", image, 64 + 56, 1, PF_R | PF_W, rw_off, BASE + rw_off, BASE + rw_off,
                     file_end - rw_off, mem - rw_off, PAGE)
    open(dst, "wb").write(image)
    print(f"{dst}: {len(image)} bytes, entry {entry:#x}, {(mem - rw_off) >> 10} KiB writable")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
