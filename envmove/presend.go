//go:build linux

package main

// Memory sent ahead: most of the system's memory crosses while it still runs.
//
// The freeze is short only if little has to cross during it. A guest cannot
// see which of its pages change the way a hypervisor can, but it can read all
// of its memory (through /proc/kcore, the kernel's read-only view of itself)
// and remember a fingerprint of each page. So:
//
//  1. While the system runs, every page that is not all zeros is sent to the
//     receiver, which keeps it, and its fingerprint is noted here.
//  2. The same again, sending only pages whose fingerprint changed, until
//     little changes from one pass to the next.
//  3. During the freeze envmove-core fingerprints each page of the memory image
//     and sends only those that differ from what the receiver already holds;
//     for the rest it sends one bit. The receiver puts each page together from
//     the two.
//
// Fingerprints are two 64-bit hashes of the page with secret seeds chosen for
// this move only, so a program inside the guest cannot make a changed page
// look unchanged. A receiver missing a page that the sender believes it has
// refuses the image; the system then simply thaws where it was.

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// memfd is an anonymous file in memory that a child process can map too.
func memfd(name string, size int64) (*os.File, []byte, error) {
	n := []byte(name + "\x00")
	fd, _, e := syscall.RawSyscall(319, uintptr(unsafe.Pointer(&n[0])), 0, 0)
	if e != 0 {
		return nil, nil, fmt.Errorf("memfd_create: %w", e)
	}
	f := os.NewFile(fd, name)
	if err := f.Truncate(size); err != nil {
		f.Close()
		return nil, nil, err
	}
	if size == 0 {
		return f, nil, nil
	}
	m, err := syscall.Mmap(int(fd), 0, int(size), syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, m, nil
}

type ramRange struct{ va, pa, size uint64 }

// ramRanges is every range of the machine's memory, as the kernel lists it
// ("System RAM" in /proc/iomem), where the kernel's view of itself shows it.
// The view also holds other areas (32 TiB of address space for vmalloc on
// some kernels); only memory is read.
func (k *kernelMem) ramRanges() []ramRange {
	b, _ := os.ReadFile("/proc/iomem")
	var out []ramRange
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, " ") || !strings.Contains(line, ": System RAM") {
			continue
		}
		span := strings.TrimSpace(strings.SplitN(line, ":", 2)[0])
		lo, hi, ok := strings.Cut(span, "-")
		if !ok {
			continue
		}
		s, err1 := strconv.ParseUint(lo, 16, 64)
		e, err2 := strconv.ParseUint(hi, 16, 64)
		if err1 != nil || err2 != nil || e <= s {
			continue
		}
		s = (s + page - 1) &^ (page - 1)
		size := (e + 1 - s) &^ (page - 1)
		if size == 0 {
			continue
		}
		var probe [8]byte
		if k.read(k.pageOffset+s, probe[:]) != nil {
			continue
		}
		out = append(out, ramRange{k.pageOffset + s, s, size})
	}
	return out
}

type presend struct {
	conn         net.Conn
	r            *bufio.Reader
	k            *kernelMem
	ranges       []ramRange
	maxPFN       uint64
	seedA, seedB uint64
	tableF       *os.File
	table        []byte // 16 bytes per page frame: the fingerprint of what the receiver holds (0 = nothing)
	sent         uint64
}

// sendAhead sends the memory to the receiver while the system runs, pass after
// pass, and returns the session for the core to finish.
func sendAhead(to string) (*presend, error) {
	syms, _, err := allSymbols()
	if err != nil {
		return nil, err
	}
	k, err := openKernel(syms)
	if err != nil {
		return nil, err
	}
	p := &presend{k: k, ranges: k.ramRanges()}
	for _, r := range p.ranges {
		if end := (r.pa + r.size) / page; end > p.maxPFN {
			p.maxPFN = end
		}
	}
	if len(p.ranges) == 0 {
		k.close()
		return nil, errors.New("the kernel's view of itself shows no memory")
	}
	var seed [16]byte
	if _, err := rand.Read(seed[:]); err != nil {
		k.close()
		return nil, err
	}
	p.seedA, p.seedB = binary.LittleEndian.Uint64(seed[:]), binary.LittleEndian.Uint64(seed[8:])
	if p.tableF, p.table, err = memfd("envmove-fingerprints", int64(p.maxPFN*16)); err != nil {
		k.close()
		return nil, err
	}
	c, err := net.Dial("tcp", to)
	if err != nil {
		p.close()
		return nil, fmt.Errorf("the receiver at %s does not answer: %w", to, err)
	}
	p.conn, p.r = c, bufio.NewReader(c)
	var max [8]byte
	binary.LittleEndian.PutUint64(max[:], p.maxPFN)
	if _, err := c.Write(append(kindAndToken("ENVMOVEM"), max[:]...)); err != nil {
		p.close()
		return nil, err
	}
	// Clean file cache is dropped first: the kernel drops it anyway when it
	// takes the image, and sending it ahead would only fill the receiver.
	os.WriteFile("/proc/sys/vm/drop_caches", []byte("1"), 0)
	for pass := 1; ; pass++ {
		t0 := time.Now()
		changed, err := p.pass()
		if err != nil {
			p.close()
			return nil, err
		}
		if err := p.sync(); err != nil {
			p.close()
			return nil, err
		}
		fmt.Printf("memory: pass %d sent %d MiB of pages new or changed, in %.1f s\n", pass, changed*page>>20, time.Since(t0).Seconds())
		if changed*page < 16<<20 || pass >= 8 {
			break
		}
	}
	return p, nil
}

// pass reads every page, and sends those whose fingerprint differs from what the receiver holds.
func (p *presend) pass() (uint64, error) {
	const batch = 64
	buf := make([]byte, 1<<20)
	var pfns, zeros []uint64
	var pages []byte
	le := binary.LittleEndian
	za, zb := xxh64(make([]byte, page), p.seedA), xxh64(make([]byte, page), p.seedB) // a page of zeros
	flushZeros := func() error {                                                     // pages that are zeros: named, not sent
		if len(zeros) == 0 {
			return nil
		}
		msg := make([]byte, 8+8*len(zeros))
		le.PutUint32(msg[0:], 3)
		le.PutUint32(msg[4:], uint32(len(zeros)))
		for i, f := range zeros {
			le.PutUint64(msg[8+8*i:], f)
		}
		zeros = zeros[:0]
		_, err := p.conn.Write(msg)
		return err
	}
	flush := func() error {
		if len(pfns) == 0 {
			return nil
		}
		var h [8]byte
		le.PutUint32(h[0:], 1)
		le.PutUint32(h[4:], uint32(len(pfns)))
		msg := append(h[:], make([]byte, 8*len(pfns))...)
		for i, f := range pfns {
			le.PutUint64(msg[8+8*i:], f)
		}
		if _, err := p.conn.Write(msg); err != nil {
			return err
		}
		if _, err := p.conn.Write(pages); err != nil {
			return err
		}
		pfns, pages = pfns[:0], pages[:0]
		return nil
	}
	var changed uint64
	for _, r := range p.ranges {
		for off := uint64(0); off < r.size; off += uint64(len(buf)) {
			n := uint64(len(buf))
			if off+n > r.size {
				n = r.size - off
			}
			if err := p.k.read(r.va+off, buf[:n]); err != nil {
				// a stretch the kernel will not show (not really memory): not sent ahead
				continue
			}
			for o := uint64(0); o+page <= n; o += page {
				pg := buf[o : o+page]
				pfn := (r.pa + off + o) / page
				zero := allZero(pg)
				a, b := za, zb
				if !zero {
					a, b = xxh64(pg, p.seedA), xxh64(pg, p.seedB)
				}
				if a == 0 && b == 0 {
					a = 1 // 0,0 means "the receiver holds nothing"
				}
				t := p.table[pfn*16:]
				if le.Uint64(t) == a && le.Uint64(t[8:]) == b {
					continue
				}
				le.PutUint64(t, a)
				le.PutUint64(t[8:], b)
				if zero {
					// Older kernels put pages of zeros into the image like any other;
					// the receiver is told which, and makes them itself.
					zeros = append(zeros, pfn)
					if len(zeros) == 512 {
						if err := flushZeros(); err != nil {
							return 0, err
						}
					}
					continue
				}
				pfns = append(pfns, pfn)
				pages = append(pages, pg...)
				changed++
				if len(pfns) == batch {
					if err := flush(); err != nil {
						return 0, err
					}
				}
			}
		}
	}
	if err := flush(); err != nil {
		return 0, err
	}
	if err := flushZeros(); err != nil {
		return 0, err
	}
	p.sent += changed
	return changed, nil
}

func (p *presend) sync() error {
	var h [8]byte
	binary.LittleEndian.PutUint32(h[0:], 2)
	if _, err := p.conn.Write(h[:]); err != nil {
		return err
	}
	line, err := p.r.ReadString('\n')
	if err != nil || line != "SYNCED\n" {
		return fmt.Errorf("the receiver did not confirm the memory sent ahead (%q, %v)", strings.TrimSpace(line), err)
	}
	return nil
}

func (p *presend) close() {
	if p.conn != nil {
		p.conn.Close()
	}
	if p.table != nil {
		syscall.Munmap(p.table)
	}
	if p.tableF != nil {
		p.tableF.Close()
	}
	p.k.close()
}

// planLine tells the core where the fingerprints are (its fd) and the seeds.
func (p *presend) planLine(fd int) string {
	return fmt.Sprintf("presend %d %d %d %d\n", fd, p.maxPFN, p.seedA, p.seedB)
}

// ---- receiver ----

type memState struct {
	started, done bool
	maxPFN        uint64
	slotsF        *os.File // the pages, one slot each
	indexF        *os.File // per page frame: its slot + 1 (0 = none)
	index         []byte
	slots         uint64
}

var memIn = &memState{}

// zeroSlot marks, in the receiver's index, a page known to be all zeros.
const zeroSlot = 0xFFFFFFFF

// takeMemory keeps the pages sent ahead, in files in memory the core will map.
func takeMemory(c net.Conn, r *bufio.Reader) {
	defer c.Close()
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return
	}
	m := memIn
	m.maxPFN = binary.LittleEndian.Uint64(h[:])
	var err error
	if m.indexF, m.index, err = memfd("envmove-index", int64(m.maxPFN*4)); err != nil {
		fmt.Println("memory: cannot keep pages here:", err)
		return
	}
	if m.slotsF, _, err = memfd("envmove-pages", 0); err != nil {
		fmt.Println("memory: cannot keep pages here:", err)
		return
	}
	m.started = true
	le := binary.LittleEndian
	pg := make([]byte, 64*page)
	pfns := make([]byte, 8*64)
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			fmt.Println("memory: the sender stopped sending ahead:", err)
			return
		}
		switch le.Uint32(h[0:]) {
		case 1:
			n := int(le.Uint32(h[4:]))
			if n > 64 {
				fmt.Println("memory: a malformed batch arrived; abandoned")
				return
			}
			if _, err := io.ReadFull(r, pfns[:8*n]); err != nil {
				return
			}
			if _, err := io.ReadFull(r, pg[:n*page]); err != nil {
				return
			}
			for i := 0; i < n; i++ {
				pfn := le.Uint64(pfns[8*i:])
				if pfn >= m.maxPFN {
					fmt.Println("memory: a page beyond the sender's memory arrived; abandoned")
					return
				}
				slot := uint64(le.Uint32(m.index[pfn*4:]))
				if slot == 0 || slot == zeroSlot {
					m.slots++
					slot = m.slots
					le.PutUint32(m.index[pfn*4:], uint32(slot))
				}
				if _, err := m.slotsF.WriteAt(pg[i*page:(i+1)*page], int64((slot-1)*page)); err != nil {
					fmt.Println("memory: cannot keep a page here:", err)
					return
				}
			}
		case 3:
			n := int(le.Uint32(h[4:]))
			if n > 512 {
				fmt.Println("memory: a malformed list arrived; abandoned")
				return
			}
			zl := make([]byte, 8*n)
			if _, err := io.ReadFull(r, zl); err != nil {
				return
			}
			for i := 0; i < n; i++ {
				pfn := le.Uint64(zl[8*i:])
				if pfn < m.maxPFN {
					le.PutUint32(m.index[pfn*4:], zeroSlot)
				}
			}
		case 2:
			fmt.Fprint(c, "SYNCED\n")
			m.done = true
		default:
			fmt.Println("memory: unknown message; abandoned")
			return
		}
	}
}
