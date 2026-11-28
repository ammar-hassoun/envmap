//go:build linux

package main

// Reading the running kernel, so corrections can be aimed anywhere in it.
//
// A correction in transit is made to a page frame of the memory image, so it
// needs the physical address of what it changes. For the kernel's own code and
// data that is simple arithmetic (patch.go). Code in a loaded module, and the
// kernel's per-processor data, live elsewhere: their physical pages are known
// only to the kernel's page tables. This file reads those tables, and any
// kernel memory, through /proc/kcore, which the kernel offers to root as a
// read-only view of itself. Nothing here writes anything.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type ksym struct {
	addr   uint64
	module string // empty for the kernel itself
}

// allSymbols reads every symbol the kernel lists, modules included, and the
// address of the symbol that follows each one (where its code ends).
func allSymbols() (map[string]ksym, []uint64, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	syms := map[string]ksym{}
	var addrs []uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 3 {
			continue
		}
		a, err := strconv.ParseUint(p[0], 16, 64)
		if err != nil {
			continue
		}
		mod := ""
		if len(p) > 3 {
			mod = strings.Trim(p[3], "[]")
		}
		if _, dup := syms[p[2]]; !dup {
			syms[p[2]] = ksym{a, mod}
		}
		addrs = append(addrs, a)
	}
	if s, ok := syms["_text"]; ok && s.addr == 0 {
		return nil, nil, errors.New("this kernel hides its symbol addresses (kernel.kptr_restrict); they are needed to make corrections in transit")
	}
	sortU64(addrs)
	return syms, addrs, nil
}

func sortU64(a []uint64) {
	// a shell sort is plenty for a hundred thousand addresses
	for gap := len(a) / 2; gap > 0; gap /= 2 {
		for i := gap; i < len(a); i++ {
			for j := i; j >= gap && a[j-gap] > a[j]; j -= gap {
				a[j], a[j-gap] = a[j-gap], a[j]
			}
		}
	}
}

// symbolEnd is where the code of the symbol at addr ends: the next symbol's address.
func symbolEnd(addrs []uint64, addr uint64) uint64 {
	lo, hi := 0, len(addrs)
	for lo < hi {
		m := (lo + hi) / 2
		if addrs[m] <= addr {
			lo = m + 1
		} else {
			hi = m
		}
	}
	if lo < len(addrs) {
		return addrs[lo]
	}
	return addr + 4096
}

type kseg struct{ va, off, size uint64 }

type kernelMem struct {
	f          *os.File
	segs       []kseg
	syms       map[string]ksym
	textVA     uint64 // _text
	textEnd    uint64 // _end: the kernel image ends here; loaded modules live above it
	textPA     uint64 // where the kernel's code was loaded
	pageOffset uint64 // where all physical memory is mapped
	root       uint64 // physical address of the top page table
	levels     int
}

// openKernel prepares to read the running kernel's memory.
func openKernel(syms map[string]ksym) (*kernelMem, error) {
	f, err := os.Open("/proc/kcore")
	if err != nil {
		return nil, fmt.Errorf("/proc/kcore: %w (the kernel's own view of its memory is needed for this correction)", err)
	}
	k := &kernelMem{f: f, syms: syms}
	var eh [64]byte
	if _, err := f.ReadAt(eh[:], 0); err != nil || string(eh[:4]) != "\x7fELF" {
		f.Close()
		return nil, errors.New("/proc/kcore does not read as an ELF file")
	}
	le := binary.LittleEndian
	phoff, phent, phnum := le.Uint64(eh[32:]), uint64(le.Uint16(eh[54:])), uint64(le.Uint16(eh[56:]))
	ph := make([]byte, phent*phnum)
	if _, err := f.ReadAt(ph, int64(phoff)); err != nil {
		f.Close()
		return nil, err
	}
	for i := uint64(0); i < phnum; i++ {
		p := ph[i*phent:]
		if le.Uint32(p) != 1 { // PT_LOAD
			continue
		}
		k.segs = append(k.segs, kseg{va: le.Uint64(p[16:]), off: le.Uint64(p[8:]), size: le.Uint64(p[32:])})
	}
	t, ok := syms["_text"]
	if !ok {
		f.Close()
		return nil, errors.New("the kernel's symbol table has no _text")
	}
	k.textVA = t.addr
	k.textEnd = 0xffffffffc0000000 // where module space starts, if the kernel does not say where it ends
	if e, ok := syms["_end"]; ok && e.addr > k.textVA && e.addr < k.textEnd {
		k.textEnd = e.addr
	}
	if k.textPA, err = kernelCodeAt(); err != nil {
		f.Close()
		return nil, err
	}
	// Where physical memory is mapped: a variable on kernels that move it
	// around, otherwise one of the fixed places used over the years. Proved by
	// reading the kernel's first code page both ways.
	var cands []uint64
	if s, ok := syms["page_offset_base"]; ok {
		if v, err := k.u64(s.addr); err == nil {
			cands = append(cands, v)
		}
	}
	cands = append(cands, 0xffff888000000000, 0xffff880000000000, 0xff11000000000000)
	want := make([]byte, 256)
	if err := k.read(k.textVA, want); err != nil {
		f.Close()
		return nil, fmt.Errorf("reading the kernel's code: %w", err)
	}
	for _, c := range cands {
		got := make([]byte, 256)
		if k.read(c+k.textPA, got) == nil && string(got) == string(want) {
			k.pageOffset = c
			break
		}
	}
	if k.pageOffset == 0 {
		f.Close()
		return nil, errors.New("cannot tell where this kernel maps physical memory")
	}
	// The kernel's own page tables.
	top := ""
	for _, n := range []string{"init_top_pgt", "init_level4_pgt"} {
		if _, ok := syms[n]; ok {
			top = n
			break
		}
	}
	if top == "" {
		f.Close()
		return nil, errors.New("cannot find the kernel's page tables")
	}
	k.root = syms[top].addr - k.textVA + k.textPA
	k.levels = 4
	if s, ok := syms["__pgtable_l5_enabled"]; ok {
		var b [4]byte
		if k.read(s.addr, b[:]) == nil && le.Uint32(b[:]) != 0 {
			k.levels = 5
		}
	}
	return k, nil
}

func (k *kernelMem) close() { k.f.Close() }

// read copies kernel memory at virtual address va.
func (k *kernelMem) read(va uint64, b []byte) error {
	for len(b) > 0 {
		var s *kseg
		for i := range k.segs {
			if va >= k.segs[i].va && va < k.segs[i].va+k.segs[i].size {
				s = &k.segs[i]
				break
			}
		}
		if s == nil {
			return fmt.Errorf("kernel address %#x is not in /proc/kcore", va)
		}
		n := s.va + s.size - va
		if n > uint64(len(b)) {
			n = uint64(len(b))
		}
		if _, err := k.f.ReadAt(b[:n], int64(s.off+(va-s.va))); err != nil {
			return err
		}
		b, va = b[n:], va+n
	}
	return nil
}

func (k *kernelMem) u64(va uint64) (uint64, error) {
	var b [8]byte
	if err := k.read(va, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

// phys is the physical address behind a kernel virtual address.
func (k *kernelMem) phys(va uint64) (uint64, error) {
	if va >= k.textVA && va < k.textEnd {
		return va - k.textVA + k.textPA, nil
	}
	if k.pageOffset != 0 && va >= k.pageOffset && va < k.pageOffset+(1<<46) {
		return va - k.pageOffset, nil
	}
	// Anything else (module code and data, other mapped areas): walk the tables.
	table := k.root
	for level := k.levels; level >= 1; level-- {
		shift := 12 + 9*uint(level-1)
		idx := (va >> shift) & 511
		e, err := k.u64(k.pageOffset + table + idx*8)
		if err != nil {
			return 0, err
		}
		if e&1 == 0 {
			return 0, fmt.Errorf("kernel address %#x is not mapped", va)
		}
		addr := e & 0x000ffffffffff000
		if level == 1 || (level <= 3 && e&0x80 != 0) { // a page, or a large page at this level
			mask := uint64(1)<<shift - 1
			return (addr &^ mask) | (va & mask), nil
		}
		table = addr
	}
	return 0, fmt.Errorf("kernel address %#x: page tables did not resolve", va)
}

// verified is phys, proved: the bytes at the virtual address and at the
// physical address found for it (read through the map of all physical memory)
// must be the same. An address that fails this is never corrected.
func (k *kernelMem) verified(va uint64, n int) (uint64, error) {
	pa, err := k.phys(va)
	if err != nil {
		return 0, err
	}
	a, b := make([]byte, n), make([]byte, n)
	if err := k.read(va, a); err != nil {
		return 0, err
	}
	if err := k.read(k.pageOffset+pa, b); err != nil {
		return 0, err
	}
	if string(a) != string(b) {
		return 0, fmt.Errorf("kernel address %#x: the physical address found for it (%#x) holds other bytes; not corrected", va, pa)
	}
	return pa, nil
}
