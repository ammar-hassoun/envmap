//go:build linux

package main

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// The first page of a hibernation image is a header the restoring kernel
// checks before it touches anything else. On x86-64 it starts with a small
// record whose shape changed over the years:
//
//	old kernels:   jump_address, cr3, magic                      (magic at byte 16)
//	Linux 4.8 on:  jump_address, jump_address_phys, cr3, magic   (magic at byte 24)
//	Linux 4.9 on:  the same, then a checksum of the firmware memory map the
//	               image was made under, at byte 32 (a 16-byte MD5 at first,
//	               a 4-byte CRC-32 from Linux 5.13; distributions backport)
//
// and in every version the total memory in pages (num_physpages) at byte 400.
//
// The checks exist so that an image is never restored onto a machine whose
// memory changed. A move does change the machine, on purpose. So the receiver
// first proves the property the checks stand for (every range the sender used
// as memory is memory here too) and then writes its own values into the
// header. The image data itself is never altered.
const (
	offChecksum  = 32
	offPhysPages = 400
)

type headerKind struct {
	name     string
	magic    uint64
	magicOff int
	checksum bool // a memory-map checksum follows the magic
}

var headerKinds = []headerKind{
	{"Linux 5.13 or later", 0x23456789ABCDEF02, 24, true},
	{"Linux 4.9 to 5.12", 0x23456789ABCDEF01, 24, true},
	{"Linux 4.8", 0x123456789ABCDEF0, 24, false},
	{"before Linux 4.8", 0x123456789ABCDEF0, 16, false},
	{"before Linux 4.8", 0x0123456789ABCDEF, 16, false},
}

func headerOf(pg []byte) *headerKind {
	for i := range headerKinds {
		k := &headerKinds[i]
		if binary.LittleEndian.Uint64(pg[k.magicOff:]) == k.magic {
			return k
		}
	}
	return nil
}

// tableBytes is struct e820_table as the kernel checksums it: a 32-bit count,
// then 20-byte entries (address, size, type).
func tableBytes(m []region) []byte {
	b := make([]byte, 4+20*len(m))
	le := binary.LittleEndian
	le.PutUint32(b, uint32(len(m)))
	for i, r := range m {
		o := 4 + 20*i
		le.PutUint64(b[o:], r.Start)
		le.PutUint64(b[o+8:], r.End-r.Start+1)
		le.PutUint32(b[o+16:], r.Type)
	}
	return b
}

func mapCRC(m []region) uint32 {
	// the kernel computes ~crc32_le(~0, table, size); Go's IEEE checksum is
	// ~crc32_le(~0, ...) already
	return crc32.ChecksumIEEE(tableBytes(m))
}

func mapMD5(m []region) [16]byte { return md5.Sum(tableBytes(m)) }

// usesMD5 reports whether the running kernel predates the CRC-32 check (5.13).
func usesMD5() bool {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return false
	}
	var rel []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		rel = append(rel, byte(c))
	}
	parts := strings.SplitN(string(rel), ".", 3)
	if len(parts) < 2 {
		return false
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(strings.TrimRight(parts[1], "-+abcdefghijklmnopqrstuvwxyz"))
	return major < 5 || (major == 5 && minor < 13)
}

// physPages is what the kernel calls get_num_physpages(): the pages present in
// every memory zone.
func physPages() (uint64, error) {
	b, err := os.ReadFile("/proc/zoneinfo")
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "present" {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			total += n
		}
	}
	if total == 0 {
		return 0, errors.New("could not read memory zones")
	}
	return total, nil
}

// endOfMemory is the other way kernels have counted "total memory": the page
// number just past the last memory range, holes included. Kernels before 3.11
// (Red Hat 7's among them) compare this instead of the pages present.
func endOfMemory(m []region) uint64 {
	var end uint64
	for _, r := range m {
		if r.Type == 1 && r.End+1 > end {
			end = r.End + 1
		}
	}
	return end >> 12
}

// uncovered lists the parts of the sender's memory that are not memory here.
func uncovered(from, here []region) []region {
	var out []region
	for _, r := range from {
		if r.Type != 1 {
			continue
		}
		at := r.Start
		for at <= r.End {
			var hit *region
			for i := range here {
				h := &here[i]
				if h.Type == 1 && at >= h.Start && at <= h.End {
					hit = h
					break
				}
			}
			if hit != nil {
				if hit.End >= r.End {
					at = r.End + 1
					break
				}
				at = hit.End + 1
				continue
			}
			// not memory here: find where coverage starts again
			next := r.End + 1
			for _, h := range here {
				if h.Type == 1 && h.Start > at && h.Start < next {
					next = h.Start
				}
			}
			out = append(out, region{at, next - 1, 1})
			at = next
		}
	}
	return out
}

// fits reports whether an image made under the sender's memory map could be
// restored here. It needs no image, so it can run before anything is frozen.
func fits(fromMap string) error {
	here, err := readMemmap()
	if err != nil {
		return err
	}
	from, err := parseMap(fromMap)
	if err != nil {
		return err
	}
	gaps := uncovered(from, here)
	for _, g := range gaps {
		fmt.Printf("memory the sender uses that is not memory here: %x-%x (%d KiB)\n", g.Start, g.End, (g.End-g.Start+1)>>10)
	}
	if len(gaps) > 0 {
		return errors.New("this machine cannot receive that system: its memory does not cover the sender's")
	}
	fmt.Println("fits: every memory range the sender uses is memory here")
	return nil
}

// adjustHeader makes an image's first page acceptable to this kernel, after
// proving that the image fits here. It changes pg in place and reports whether
// anything changed. Nothing is changed when it returns an error.
func adjustHeader(pg []byte, from, here []region, force bool) (bool, error) {
	le := binary.LittleEndian
	kind := headerOf(pg)
	if kind == nil {
		return false, fmt.Errorf("the image header has a shape this tool does not know (first bytes %x); nothing was changed", pg[:48])
	}
	fmt.Printf("image header shape: %s\n", kind.name)
	// Which rule made the checksum in the header? Decided from the sender's map.
	rule, zero := "", true
	for _, c := range pg[offChecksum : offChecksum+16] {
		zero = zero && c == 0
	}
	if kind.checksum && !zero {
		if from == nil {
			if !force {
				return false, errors.New("refusing to adjust the header without the sender's map to check against (-from)")
			}
			rule = "CRC-32"
			if usesMD5() {
				rule = "MD5"
			}
		} else {
			d := mapMD5(from)
			switch {
			case le.Uint32(pg[offChecksum:]) == mapCRC(from):
				rule = "CRC-32"
			case string(pg[offChecksum:offChecksum+16]) == string(d[:]):
				rule = "MD5"
			default:
				return false, fmt.Errorf("the sender's map reproduces neither a CRC-32 nor an MD5 in the image header (%x): "+
					"this image is not from that sender, or this kernel checks something else; nothing was changed",
					pg[offChecksum:offChecksum+16])
			}
			fmt.Printf("checksum rule confirmed (%s): the sender's map reproduces the value in the image\n", rule)
		}
	} else {
		fmt.Println("this kernel stores no memory-map checksum; it checks the amount of memory only")
	}
	sum := func(m []region) string {
		switch rule {
		case "MD5":
			d := mapMD5(m)
			return fmt.Sprintf("%x", d[:])
		case "CRC-32":
			return fmt.Sprintf("%08x", mapCRC(m))
		}
		return "none"
	}
	stored := "none"
	switch rule {
	case "MD5":
		stored = fmt.Sprintf("%x", pg[offChecksum:offChecksum+16])
	case "CRC-32":
		stored = fmt.Sprintf("%08x", le.Uint32(pg[offChecksum:]))
	}
	mine := sum(here)
	storedPages := le.Uint64(pg[offPhysPages:])
	myPages, err := physPages()
	if err != nil {
		return false, err
	}
	// Which count is in the image? Decided by which one the sender's map reproduces.
	counted := "pages present"
	if from != nil && storedPages == endOfMemory(from) {
		myPages, counted = endOfMemory(here), "where memory ends"
	}
	fmt.Printf("image:        memory-map checksum %s, %d pages of memory (counted as %s)\n", stored, storedPages, counted)
	fmt.Printf("this machine: memory-map checksum %s, %d pages of memory\n", mine, myPages)

	if from != nil {
		if gaps := uncovered(without(from, removedRanges), here); len(gaps) > 0 {
			for _, g := range gaps {
				fmt.Printf("memory the sender used that is not memory here: %x-%x (%d KiB)\n", g.Start, g.End, (g.End-g.Start+1)>>10)
			}
			if !force {
				return false, errors.New("the receiver is missing memory the sender used; nothing was changed")
			}
		} else {
			fmt.Println("every memory range the sender used is memory here")
		}
	} else if !force {
		return false, errors.New("refusing to adjust the header without the sender's map to check against (-from)")
	}
	if stored == mine && storedPages == myPages {
		fmt.Println("nothing to adjust")
		return false, nil
	}
	switch rule {
	case "MD5":
		d := mapMD5(here)
		copy(pg[offChecksum:], d[:])
	case "CRC-32":
		le.PutUint32(pg[offChecksum:], mapCRC(here))
	}
	le.PutUint64(pg[offPhysPages:], myPages)
	return true, nil
}

// imgFix finds the image header on dev and makes it acceptable to this kernel.
func imgFix(dev, fromMap string, force, dry bool) error {
	here, err := readMemmap()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	le := binary.LittleEndian
	pg := make([]byte, page)
	var at int64 = -1
	// The swap header at the end of the first page names the image's first index
	// page (in pages); the first entry of that index is the image header.
	if n, _ := f.ReadAt(pg, 0); n == page && string(pg[page-10:page-1]) == "S1SUSPEND" {
		idx := int64(le.Uint64(pg[page-32:])) * page
		if n, _ := f.ReadAt(pg, idx); n == page {
			first := int64(le.Uint64(pg)) * page
			if n, _ := f.ReadAt(pg, first); n == page {
				at = first
			}
		}
	}
	if at < 0 {
		return errors.New("no hibernation image on " + dev)
	}
	fmt.Printf("header at byte %d\n", at)
	var from []region
	if fromMap != "" {
		if from, err = parseMap(fromMap); err != nil {
			return err
		}
	}
	changed, err := adjustHeader(pg, from, here, force)
	if err != nil || !changed || dry {
		return err
	}
	if _, err := f.WriteAt(pg, at); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	fmt.Println("header adjusted for this machine")
	return nil
}
