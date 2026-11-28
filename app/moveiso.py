"""The receiver CD for one move (EnvMap Move), written here, in memory.

The new machine starts once from this CD: Alpine Linux's kernel with the
engine (envmove) as its first process, the network drivers it needs, and this
move's settings (ENVMOVE.JSN). It waits on its transfer card for the moving
system, takes the moving system's own kernel from it and restarts into that
(envmove/boot.go). One CD, BIOS and UEFI alike: a target's firmware keeps no
memory for a second one, and a second CD was measured to cost a 4 KiB gap in
the memory a moving system can be placed in.

WHY WRITTEN BY HAND
    ISO 9660 with El Torito is a few hundred lines; the alternatives are a tool
    in the image (xorriso, genisoimage: more code that runs as the portal) or
    a library. Plain names (capitals, digits, underscore) are enough: the boot
    loaders and Linux read them whatever the case. The same writer made every
    receiver CD of the lab rounds (reports/vm-move).

WHERE THE PARTS ARE
    /opt/envmove in the image (Dockerfile, stages envmove and envmove-rx), or
    PORTAL_ENVMOVE_DIR. `parts()` says what is missing instead of failing late.
"""
from __future__ import annotations

import json
import os
import struct
import threading
import time
from pathlib import Path

SECTOR = 2048
_LOCK = threading.Lock()
_BOOT: dict = {}            # path -> (mtime, the boot initramfs bytes)
APPEND = ("rdinit=/envmove envmove.role=boot kexec_load_disabled=0 console=tty0 "
          "console=ttyS0,115200 loglevel=6 panic=0")
RX_FILES = ("vmlinuz", "initrd", "isolinux.bin", "ldlinux.c32", "efi.img",
            "bootx64.efi", "mods/order")


def engine_dir() -> Path:
    return Path(os.environ.get("PORTAL_ENVMOVE_DIR") or "/opt/envmove")


def parts() -> tuple[bool, str]:
    """(True, "") when the engine and the receiver are in place, else why not."""
    d = engine_dir()
    missing = [f for f in ["envmove"] + [f"rx/{n}" for n in RX_FILES]
               if not (d / f).is_file()]
    if missing:
        return False, (f"EnvMap Move's engine is not in this installation "
                       f"({', '.join(missing)} missing under {d})")
    return True, ""


def engine() -> bytes:
    return (engine_dir() / "envmove").read_bytes()


def _both16(v: int) -> bytes:
    return struct.pack("<H", v) + struct.pack(">H", v)


def _both32(v: int) -> bytes:
    return struct.pack("<I", v) + struct.pack(">I", v)


def _dirdate() -> bytes:
    t = time.gmtime()
    return bytes([t.tm_year - 1900, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, 0])


def _voldate() -> bytes:
    return time.strftime("%Y%m%d%H%M%S00", time.gmtime()).encode() + b"\x00"


class _Node:
    def __init__(self, name: str, data: bytes | None = None):
        self.name, self.data = name, data      # data None: a directory
        self.children: list[_Node] = []
        self.lba = 0
        self.size = 0
        self.parent: _Node | None = None

    @property
    def isdir(self) -> bool:
        return self.data is None

    def isoname(self) -> bytes:
        if self.isdir:
            return self.name.upper().encode()
        n = self.name.upper()
        if "." not in n:
            n += "."
        return (n + ";1").encode()


def _record(name: bytes, lba: int, size: int, isdir: bool) -> bytes:
    pad = b"\x00" if len(name) % 2 == 0 else b""
    return (bytes([33 + len(name) + len(pad), 0]) + _both32(lba) + _both32(size) + _dirdate()
            + bytes([2 if isdir else 0, 0, 0]) + _both16(1) + bytes([len(name)]) + name + pad)


def build(files: dict[str, bytes], *, bios: str | None = None, efi: str | None = None,
          label: str = "ENVMAP") -> bytes:
    """An ISO 9660 image of `files` (ISO path like 'BOOT/VMLINUZ' -> bytes),
    with an El Torito catalog for a BIOS entry (ISOLINUX, which gets its boot
    information table) and a UEFI entry (a FAT image) when named."""
    root = _Node("")
    for path, data in sorted(files.items()):
        cur = root
        bits = path.strip("/").split("/")
        for d in bits[:-1]:
            nxt = next((c for c in cur.children if c.isdir and c.name == d.upper()), None)
            if nxt is None:
                nxt = _Node(d.upper())
                nxt.parent = cur
                cur.children.append(nxt)
            cur = nxt
        f = _Node(bits[-1].upper(), data)
        f.parent = cur
        cur.children.append(f)

    dirs: list[_Node] = []

    def walk(d: _Node) -> None:
        d.children.sort(key=lambda c: c.isoname())
        dirs.append(d)
        for c in d.children:
            if c.isdir:
                walk(c)
    walk(root)
    bfs = [root]
    for d in bfs:
        bfs.extend(c for c in d.children if c.isdir)

    def dir_bytes(d: _Node) -> int:
        size, used = 0, 0
        for e in [34, 34] + [len(_record(c.isoname(), 0, 0, c.isdir)) for c in d.children]:
            if used + e > SECTOR:
                size += SECTOR - used
                used = 0
            used += e
            size += e
        return (size + SECTOR - 1) // SECTOR * SECTOR

    for d in dirs:
        d.size = dir_bytes(d)

    def path_table(big: bool) -> bytes:
        out = b""
        index = {id(d): i + 1 for i, d in enumerate(bfs)}
        for d in bfs:
            name = d.name.encode() if d is not root else b"\x00"
            parent = index[id(d.parent)] if d.parent else 1
            out += (bytes([len(name), 0]) + struct.pack(">IH" if big else "<IH", d.lba, parent)
                    + name + (b"\x00" if len(name) % 2 else b""))
        return out

    boot = bool(bios or efi)
    pt_size = len(path_table(False))
    pt_sectors = (pt_size + SECTOR - 1) // SECTOR
    lba = 19 + (1 if boot else 0)              # after the descriptors (and the boot catalog)
    cat_lba = 19 if boot else 0
    l_pt, m_pt = lba, lba + pt_sectors
    lba += 2 * pt_sectors
    for d in dirs:
        d.lba = lba
        lba += d.size // SECTOR
    filenodes: list[_Node] = []

    def collect(d: _Node) -> None:
        for c in d.children:
            if c.isdir:
                collect(c)
            else:
                filenodes.append(c)
    collect(root)
    for f in filenodes:
        f.lba = lba
        f.size = len(f.data or b"")
        lba += max(1, (f.size + SECTOR - 1) // SECTOR)
    total = lba

    def find(path: str) -> _Node:
        cur = root
        for p in path.strip("/").split("/"):
            cur = next(c for c in cur.children if c.name == p.upper())
        return cur

    img = bytearray(total * SECTOR)
    pvd = bytearray(SECTOR)
    pvd[0:7] = b"\x01CD001\x01"
    pvd[8:40] = b"LINUX".ljust(32)
    pvd[40:72] = label.encode()[:32].ljust(32)
    pvd[80:88] = _both32(total)
    pvd[120:124] = _both16(1)
    pvd[124:128] = _both16(1)
    pvd[128:132] = _both16(SECTOR)
    pvd[132:140] = _both32(pt_size)
    pvd[140:144] = struct.pack("<I", l_pt)
    pvd[148:152] = struct.pack(">I", m_pt)
    rr = _record(b"\x00", root.lba, root.size, True)
    pvd[156:156 + len(rr)] = rr
    for off, n in ((190, 128), (318, 128), (446, 128), (574, 128), (702, 37), (739, 37), (776, 37)):
        pvd[off:off + n] = b" " * n
    for off in (813, 830, 847, 864):
        pvd[off:off + 17] = _voldate() if off != 847 else b"0" * 16 + b"\x00"
    pvd[881] = 1
    img[16 * SECTOR:17 * SECTOR] = pvd
    nxt = 17
    if boot:
        br = bytearray(SECTOR)
        br[0:7] = b"\x00CD001\x01"
        br[7:39] = b"EL TORITO SPECIFICATION".ljust(32, b"\x00")
        br[71:75] = struct.pack("<I", cat_lba)
        img[17 * SECTOR:18 * SECTOR] = br
        nxt = 18
    term = bytearray(SECTOR)
    term[0:7] = b"\xffCD001\x01"
    img[nxt * SECTOR:(nxt + 1) * SECTOR] = term
    if boot:
        cat = bytearray(SECTOR)
        val = bytearray(32)
        val[0], val[1] = 1, 0
        val[4:28] = b"ENVMAP".ljust(24, b"\x00")
        val[30], val[31] = 0x55, 0xAA
        s = sum(struct.unpack("<16H", bytes(val))) & 0xFFFF
        val[28:30] = struct.pack("<H", (-s) & 0xFFFF)
        cat[0:32] = val
        o = 32
        if bios:
            b = find(bios)
            cat[o:o + 32] = (bytes([0x88, 0x00]) + struct.pack("<H", 0) + bytes([0, 0])
                             + struct.pack("<H", 4) + struct.pack("<I", b.lba) + bytes(20))
            o += 32
        if efi:
            e = find(efi)
            cat[o:o + 32] = bytes([0x91, 0xEF]) + struct.pack("<H", 1) + b"UEFI".ljust(28, b"\x00")
            o += 32
            sectors = (e.size + 511) // 512
            cat[o:o + 32] = (bytes([0x88, 0x00]) + struct.pack("<H", 0) + bytes([0, 0])
                             + struct.pack("<H", sectors if sectors < 0x10000 else 0)
                             + struct.pack("<I", e.lba) + bytes(20))
        img[cat_lba * SECTOR:(cat_lba + 1) * SECTOR] = cat
    lpt, mpt = path_table(False), path_table(True)
    img[l_pt * SECTOR:l_pt * SECTOR + len(lpt)] = lpt
    img[m_pt * SECTOR:m_pt * SECTOR + len(mpt)] = mpt
    for d in dirs:
        parent = d.parent or d
        recs = [_record(b"\x00", d.lba, d.size, True), _record(b"\x01", parent.lba, parent.size, True)]
        recs += [_record(c.isoname(), c.lba, c.size, c.isdir) for c in d.children]
        pos, used = d.lba * SECTOR, 0
        for r in recs:
            if used + len(r) > SECTOR:
                pos += SECTOR - used
                used = 0
            img[pos:pos + len(r)] = r
            pos += len(r)
            used += len(r)
    bnode = find(bios) if bios else None
    for f in filenodes:
        data = bytearray(f.data or b"")
        if f is bnode:
            # ISOLINUX's boot information table: where it is and its checksum
            body = bytes(data[64:]) + b"\x00" * ((-len(data[64:])) % 4)
            csum = 0
            for (w,) in struct.iter_unpack("<I", body):
                csum = (csum + w) & 0xFFFFFFFF
            data[8:24] = struct.pack("<IIII", 16, f.lba, len(f.data or b""), csum)
        img[f.lba * SECTOR:f.lba * SECTOR + len(data)] = data
    return bytes(img)


def cpio(entries: list[tuple[str, int, bytes]]) -> bytes:
    """newc cpio: (path, mode, data); directories have mode 0o040755 and no data."""
    out = bytearray()
    ino = 1
    for path, mode, data in entries + [("TRAILER!!!", 0, b"")]:
        name = path.encode() + b"\x00"
        hdr = "070701" + "".join(f"{v:08X}" for v in (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0))
        out += hdr.encode() + name
        out += b"\x00" * ((-len(out)) % 4)
        out += data
        out += b"\x00" * ((-len(out)) % 4)
        ino += 1
    return bytes(out)


def boot_initramfs() -> bytes:
    """The second initramfs: the engine as /envmove and the network drivers in
    the order they load. The same for every move, so made once per engine."""
    d = engine_dir()
    key = str(d)
    mtime = (d / "envmove").stat().st_mtime
    with _LOCK:
        hit = _BOOT.get(key)
        if hit and hit[0] == mtime:
            return hit[1]
    order = [n for n in (d / "rx" / "mods" / "order").read_text().split() if n.endswith(".ko") and "/" not in n]
    entries = [("envmove", 0o100755, engine()), ("envmove-mods", 0o040755, b"")]
    entries += [(f"envmove-mods/{n}", 0o100644, (d / "rx" / "mods" / n).read_bytes()) for n in order]
    entries.append(("envmove-mods/order", 0o100644, "\n".join(order).encode()))
    data = cpio(entries)
    with _LOCK:
        _BOOT[key] = (mtime, data)
    return data


def receiver_iso(settings: dict) -> bytes:
    """The CD for one move. `settings` is what the receiver reads from
    ENVMOVE.JSN: ip (IP/BITS of its transfer card), gw, mac (the transfer
    card), port, token, verdict (IP:PORT of the moving system's verdict) and
    vtoken."""
    ok, why = parts()
    if not ok:
        raise FileNotFoundError(why)
    rx = engine_dir() / "rx"
    syslinux = (f"DEFAULT envmap\nPROMPT 0\nTIMEOUT 1\nLABEL envmap\nKERNEL /boot/vmlinuz\n"
                f"INITRD /boot/initrd,/boot/envboot.img\nAPPEND {APPEND}\n")
    grub = (f'set timeout=1\nmenuentry "EnvMap receiver" {{\nlinux /boot/vmlinuz {APPEND}\n'
            f"initrd /boot/initrd /boot/envboot.img\n}}\n")
    files = {
        "BOOT/VMLINUZ": (rx / "vmlinuz").read_bytes(),
        "BOOT/INITRD": (rx / "initrd").read_bytes(),
        "BOOT/ENVBOOT.IMG": boot_initramfs(),
        "BOOT/SYSLINUX/ISOLINUX.BIN": (rx / "isolinux.bin").read_bytes(),
        "BOOT/SYSLINUX/LDLINUX.C32": (rx / "ldlinux.c32").read_bytes(),
        "BOOT/SYSLINUX/SYSLINUX.CFG": syslinux.encode(),
        "BOOT/GRUB/GRUB.CFG": grub.encode(),
        "BOOT/GRUB/EFI.IMG": (rx / "efi.img").read_bytes(),
        "EFI/BOOT/BOOTX64.EFI": (rx / "bootx64.efi").read_bytes(),
        "ENVMOVE.JSN": json.dumps(settings).encode(),
    }
    return build(files, bios="BOOT/SYSLINUX/ISOLINUX.BIN", efi="BOOT/GRUB/EFI.IMG", label="ENVMAP_RX")
