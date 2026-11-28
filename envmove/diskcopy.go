//go:build linux

package main

// Live disk copy: the moving system copies its own disks to the receiver's
// blank disks while it runs.
//
// Two hypervisors never share storage, so a move must carry the disks too. A
// hypervisor would copy them from outside; here the guest does it from inside,
// which works the same on ESXi and on Proxmox:
//
//  1. Every disk is read from start to end and sent; stretches that are all
//     zeros are skipped (the receiver's disks are new and read as zeros).
//  2. Meanwhile the kernel's own block-I/O tracer (blktrace) reports every write
//     to those disks, by place and length, as it happens. What was written
//     during a pass is sent again in the next one, until little is left.
//  3. The rest is sent by envmove-core while the system is frozen: by then no
//     program can write, and the tracer still shows anything the kernel itself
//     wrote. The core checks once more after the memory image is taken and
//     tells the receiver the disks are final before any memory crosses.
//
// The receiver writes what arrives straight to its disks and confirms each
// "sync" only after the data is on them.

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	blkTraceSetup    = 0xC0481273
	blkTraceStart    = 0x1274
	blkTraceStop     = 0x1275
	blkTraceTeardown = 0x1276

	chunkData  = 1
	chunkZero  = 2
	chunkSync  = 3
	chunkFinal = 4

	copyChunk = 1 << 20
)

type copyDisk struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
	Slot  string `json:"slot"`
}

// diskList is every real disk of this system, in the order of where it is plugged in.
func diskList() []copyDisk {
	var out []copyDisk
	ents, _ := os.ReadDir("/sys/block")
	for _, e := range ents {
		n := e.Name()
		for _, p := range []string{"dm-", "loop", "ram", "sr", "zram", "nbd", "md", "fd"} {
			if strings.HasPrefix(n, p) {
				n = ""
				break
			}
		}
		if n == "" {
			continue
		}
		size := readU("/sys/block/"+n+"/size") * 512
		if size == 0 {
			continue
		}
		slot, _ := pciOf("/sys/block/" + n + "/device")
		out = append(out, copyDisk{n, size, slot})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slot != out[j].Slot {
			return out[i].Slot < out[j].Slot
		}
		return out[i].Name < out[j].Name
	})
	return out
}

type extent struct{ start, end uint64 } // bytes, end exclusive

// tracer follows the writes to one disk through the kernel's block-I/O tracer.
type tracer struct {
	disk  copyDisk
	idx   int
	dev   *os.File // the disk, read without the page cache
	dir   string   // the tracer's files
	files []*os.File
	tails [][]byte
	drops uint64
}

func debugfs() (string, error) {
	const d = "/sys/kernel/debug"
	if _, err := os.Stat(d + "/block"); err == nil {
		return d, nil
	}
	if err := syscall.Mount("debugfs", d, "debugfs", 0, ""); err != nil && err != syscall.EBUSY {
		return "", fmt.Errorf("the kernel's debug filesystem is needed to follow disk writes: %w", err)
	}
	if _, err := os.Stat(d + "/block"); err != nil {
		return "", errors.New("this kernel offers no block-I/O tracer (blktrace); writes during the copy cannot be followed")
	}
	return d, nil
}

func startTracer(d copyDisk, idx int) (*tracer, error) {
	dbg, err := debugfs()
	if err != nil {
		return nil, err
	}
	dev, err := os.OpenFile("/dev/"+d.Name, os.O_RDONLY|syscall.O_DIRECT, 0)
	if err != nil {
		return nil, err
	}
	var setup [72]byte
	le := binary.LittleEndian
	le.PutUint16(setup[32:], 1<<1|1<<13) // writes and discards
	le.PutUint32(setup[36:], 1<<20)      // 1 MiB buffers,
	le.PutUint32(setup[40:], 16)         // 16 of them per processor
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), blkTraceSetup, uintptr(unsafe.Pointer(&setup[0]))); e != 0 {
		dev.Close()
		if e == syscall.EBUSY {
			return nil, fmt.Errorf("%s is already being traced by something else", d.Name)
		}
		return nil, fmt.Errorf("cannot follow writes to %s: %w", d.Name, e)
	}
	name := cstr(setup[:32])
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), blkTraceStart, 0); e != 0 {
		syscall.Syscall(syscall.SYS_IOCTL, dev.Fd(), blkTraceTeardown, 0)
		dev.Close()
		return nil, fmt.Errorf("cannot start following writes to %s: %w", d.Name, e)
	}
	t := &tracer{disk: d, idx: idx, dev: dev, dir: dbg + "/block/" + name}
	fs, _ := filepath.Glob(t.dir + "/trace*")
	sort.Slice(fs, func(i, j int) bool { return traceCPU(fs[i]) < traceCPU(fs[j]) })
	for _, f := range fs {
		h, err := os.Open(f)
		if err != nil {
			t.stop()
			return nil, err
		}
		t.files = append(t.files, h)
		t.tails = append(t.tails, nil)
	}
	return t, nil
}

func traceCPU(path string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(path), "trace"))
	return n
}

func (t *tracer) stop() {
	for _, f := range t.files {
		f.Close()
	}
	syscall.Syscall(syscall.SYS_IOCTL, t.dev.Fd(), blkTraceStop, 0)
	syscall.Syscall(syscall.SYS_IOCTL, t.dev.Fd(), blkTraceTeardown, 0)
	t.dev.Close()
}

func (t *tracer) dropped() uint64 {
	b, _ := os.ReadFile(t.dir + "/dropped")
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

// drain reads what the tracer has gathered and returns the places written.
func (t *tracer) drain() ([]extent, error) {
	var out []extent
	buf := make([]byte, 1<<20)
	for i, f := range t.files {
		for {
			n, err := f.Read(buf)
			if n > 0 {
				t.tails[i] = append(t.tails[i], buf[:n]...)
			}
			if n == 0 || err != nil {
				break
			}
		}
		b := t.tails[i]
		for len(b) >= 48 {
			le := binary.LittleEndian
			if le.Uint32(b[0:])&0xffffff00 != 0x65617400 {
				return nil, fmt.Errorf("the write tracer of %s returned something unreadable", t.disk.Name)
			}
			pdu := int(le.Uint16(b[46:]))
			if len(b) < 48+pdu {
				break
			}
			action, bytes := le.Uint32(b[28:]), uint64(le.Uint32(b[24:]))
			if (action>>16)&(1<<1|1<<13) != 0 && (action>>16)&(1<<10) == 0 && bytes > 0 {
				s := le.Uint64(b[16:]) * 512
				out = append(out, extent{s, s + bytes})
			}
			b = b[48+pdu:]
		}
		t.tails[i] = append([]byte(nil), b...)
	}
	if d := t.dropped(); d != t.drops {
		t.drops = d
		return nil, errLostTrack
	}
	return merge(out), nil
}

var errLostTrack = errors.New("the write tracer lost track")

func merge(x []extent) []extent {
	if len(x) == 0 {
		return nil
	}
	for i := range x { // whole pages, so they can be read without the page cache
		x[i].start &^= 4095
		x[i].end = (x[i].end + 4095) &^ 4095
	}
	sort.Slice(x, func(i, j int) bool { return x[i].start < x[j].start })
	out := []extent{x[0]}
	for _, e := range x[1:] {
		last := &out[len(out)-1]
		if e.start <= last.end {
			if e.end > last.end {
				last.end = e.end
			}
			continue
		}
		out = append(out, e)
	}
	return out
}

func alignedBuf(n int) []byte {
	b, err := syscall.Mmap(-1, 0, n, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		panic(err)
	}
	return b
}

func allZero(b []byte) bool {
	for len(b) >= 8 {
		if binary.LittleEndian.Uint64(b) != 0 {
			return false
		}
		b = b[8:]
	}
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// diskSession is the sender's side of the copy.
type diskSession struct {
	conn    net.Conn
	r       *bufio.Reader
	tracers []*tracer
	buf     []byte
	sent    uint64 // bytes of data sent
	zeros   uint64 // bytes skipped or sent as zeros
}

func (s *diskSession) chunk(kind uint32, disk int, off, n uint64, data []byte) error {
	var h [24]byte
	le := binary.LittleEndian
	le.PutUint32(h[0:], kind)
	le.PutUint32(h[4:], uint32(disk))
	le.PutUint64(h[8:], off)
	le.PutUint64(h[16:], n)
	if _, err := s.conn.Write(h[:]); err != nil {
		return err
	}
	if data != nil {
		_, err := s.conn.Write(data)
		return err
	}
	return nil
}

// send reads a stretch of a disk and sends it; with skipZero, stretches of
// zeros are not sent at all (the first pass, onto blank disks).
func (s *diskSession) send(t *tracer, e extent, skipZero bool) error {
	for off := e.start; off < e.end; {
		n := uint64(len(s.buf))
		if off+n > e.end {
			n = e.end - off
		}
		if off+n > t.disk.Bytes {
			n = t.disk.Bytes - off
		}
		if n == 0 {
			return nil
		}
		k, err := syscall.Pread(int(t.dev.Fd()), s.buf[:n], int64(off))
		if err != nil {
			return fmt.Errorf("reading %s at %d: %w", t.disk.Name, off, err)
		}
		if k == 0 {
			return nil
		}
		b := s.buf[:k]
		switch {
		case allZero(b) && skipZero:
			s.zeros += uint64(k)
		case allZero(b):
			s.zeros += uint64(k)
			if err := s.chunk(chunkZero, t.idx, off, uint64(k), nil); err != nil {
				return err
			}
		default:
			s.sent += uint64(k)
			if err := s.chunk(chunkData, t.idx, off, uint64(k), b); err != nil {
				return err
			}
		}
		off += uint64(k)
	}
	return nil
}

func (s *diskSession) sync() error {
	if err := s.chunk(chunkSync, 0, 0, 0, nil); err != nil {
		return err
	}
	line, err := s.r.ReadString('\n')
	if err != nil || line != "SYNCED\n" {
		return fmt.Errorf("the receiver did not confirm its disks (%q, %v)", strings.TrimSpace(line), err)
	}
	return nil
}

func (s *diskSession) stop() {
	for _, t := range s.tracers {
		t.stop()
	}
	s.conn.Close()
}

// copyDisks copies every disk to the receiver while the system runs, until
// what is left to send is small. It returns the session for the core to finish.
func copyDisks(to string) (*diskSession, error) {
	disks := diskList()
	if len(disks) == 0 {
		return nil, errors.New("no disk to copy")
	}
	c, err := net.Dial("tcp", to)
	if err != nil {
		return nil, fmt.Errorf("the receiver at %s does not answer: %w", to, err)
	}
	b, _ := json.Marshal(map[string]any{"disks": disks})
	if _, err := c.Write(append(append(kindAndToken("ENVMOVED"), b...), '\n')); err != nil {
		c.Close()
		return nil, err
	}
	s := &diskSession{conn: c, r: bufio.NewReader(c), buf: alignedBuf(copyChunk)}
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			c.Close()
			return nil, errors.New("the receiver hung up before taking the disks")
		}
		line = strings.TrimSpace(line)
		if line == "OK" {
			break
		}
		if strings.HasPrefix(line, "REFUSE") {
			c.Close()
			return nil, errors.New("the receiver cannot take these disks: " + strings.TrimSpace(strings.TrimPrefix(line, "REFUSE")))
		}
		fmt.Println("receiver:", line)
	}
	for i, d := range disks {
		t, err := startTracer(d, i)
		if err != nil {
			s.stop()
			return nil, err
		}
		s.tracers = append(s.tracers, t)
	}
	// Pass 1: everything.
	t0 := time.Now()
	for _, t := range s.tracers {
		if err := s.send(t, extent{0, t.disk.Bytes}, true); err != nil {
			s.stop()
			return nil, err
		}
	}
	if err := s.sync(); err != nil {
		s.stop()
		return nil, err
	}
	fmt.Printf("disks: pass 1 sent %d MiB and skipped %d MiB of zeros in %.0f s\n", s.sent>>20, s.zeros>>20, time.Since(t0).Seconds())
	// Then what changed meanwhile, until it is little.
	for pass := 2; ; pass++ {
		t1 := time.Now()
		var changed uint64
		for _, t := range s.tracers {
			ext, err := t.drain()
			if err == errLostTrack {
				fmt.Printf("disks: the write tracer of %s lost track; sending that disk whole again\n", t.disk.Name)
				ext = []extent{{0, t.disk.Bytes}}
			} else if err != nil {
				s.stop()
				return nil, err
			}
			for _, e := range ext {
				changed += e.end - e.start
				if err := s.send(t, e, false); err != nil {
					s.stop()
					return nil, err
				}
			}
		}
		if err := s.sync(); err != nil {
			s.stop()
			return nil, err
		}
		fmt.Printf("disks: pass %d sent %d KiB written meanwhile, in %.1f s\n", pass, changed>>10, time.Since(t1).Seconds())
		if changed < 8<<20 || pass >= 12 {
			break
		}
	}
	return s, nil
}

// release closes this process's handles on the disks and the tracer while
// leaving the tracing itself running in the kernel. The frozen part reopens what
// it needs. No handle of ours may stay open on a disk whose controller is let
// go: on old kernels (3.10) the last close of a removed disk frees its host a
// second time, and the memory is then reused while still in use (seen as a
// crash a few seconds after the thaw).
func (s *diskSession) release() {
	for _, t := range s.tracers {
		for _, f := range t.files {
			f.Close()
		}
		t.files = nil
		t.dev.Close()
	}
}

// planLines is what the core needs to finish the copy while the system is frozen.
func (s *diskSession) planLines() string {
	var b strings.Builder
	b.WriteString("dcopy 6\n")
	for _, t := range s.tracers {
		fmt.Fprintf(&b, "disk %d %s %d %s %d %s\n", t.idx, t.disk.Name, t.disk.Bytes, t.dir, t.drops, t.disk.Slot)
		for cpu, tail := range t.tails {
			if len(tail) > 0 {
				fmt.Fprintf(&b, "dtail %d %d %x\n", t.idx, cpu, tail)
			}
		}
	}
	return b.String()
}

// stopTracing ends write tracing on these disks, wherever the system now runs.
func stopTracing(names []string) {
	for _, n := range names {
		f, err := os.OpenFile("/dev/"+n, os.O_RDONLY, 0)
		if err != nil {
			continue
		}
		syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkTraceStop, 0)
		syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkTraceTeardown, 0)
		f.Close()
	}
}

// ---- receiver ----

// diskState is what the receiver knows about the copy: an image is accepted
// only when no copy was started, or the copy was declared final and is on disk.
type diskState struct {
	started, final bool
	err            error
	done           chan struct{}
}

var disksIn = &diskState{done: make(chan struct{})}

// takeDisks is the receiver's side: it maps the sender's disks onto blank
// disks of the same size here, then writes what arrives.
func takeDisks(c net.Conn, r *bufio.Reader) {
	defer c.Close()
	fail := func(why string) {
		fmt.Fprintln(c, "REFUSE "+why)
		fmt.Println("disks: refused:", why)
	}
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	var req struct {
		Disks []copyDisk `json:"disks"`
	}
	if json.Unmarshal(line, &req) != nil || len(req.Disks) == 0 {
		fail("no disks named")
		return
	}
	mine := diskList()
	used := map[string]bool{}
	var out []*os.File
	for _, d := range req.Disks {
		var pick *copyDisk
		for i := range mine {
			if !used[mine[i].Name] && mine[i].Bytes == d.Bytes {
				pick = &mine[i]
				break
			}
		}
		if pick == nil {
			// A hypervisor may round a new disk up (to a whole gigabyte, to its
			// allocation unit): the smallest larger free disk takes it, and its
			// end stays unused.
			for i := range mine {
				if !used[mine[i].Name] && mine[i].Bytes > d.Bytes && (pick == nil || mine[i].Bytes < pick.Bytes) {
					pick = &mine[i]
				}
			}
		}
		if pick == nil {
			var have []string
			for _, m := range mine {
				have = append(have, fmt.Sprintf("%s %d", m.Name, m.Bytes))
			}
			fail(fmt.Sprintf("no free disk of %d bytes here for %s (disks here: %s)", d.Bytes, d.Name, strings.Join(have, ", ")))
			return
		}
		used[pick.Name] = true
		f, err := os.OpenFile("/dev/"+pick.Name, os.O_RDWR|syscall.O_DIRECT, 0)
		if err != nil {
			fail(fmt.Sprintf("%s: %v", pick.Name, err))
			return
		}
		defer f.Close()
		out = append(out, f)
		msg := fmt.Sprintf("disk %s (%d MiB) is copied to %s here", d.Name, d.Bytes>>20, pick.Name)
		if pick.Bytes > d.Bytes {
			msg += fmt.Sprintf(" (%d MiB larger; the end stays unused)", (pick.Bytes-d.Bytes)>>20)
		}
		fmt.Println("disks:", msg)
		fmt.Fprintln(c, msg)
	}
	fmt.Fprintln(c, "OK")
	disksIn.started = true
	buf := alignedBuf(copyChunk)
	zero := alignedBuf(copyChunk)
	var h [24]byte
	le := binary.LittleEndian
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			fmt.Println("disks: the sender stopped before the copy was final:", err)
			return
		}
		kind, disk, off, n := le.Uint32(h[0:]), int(le.Uint32(h[4:])), le.Uint64(h[8:]), le.Uint64(h[16:])
		switch kind {
		case chunkData, chunkZero:
			if disk >= len(out) || n > copyChunk || n%512 != 0 || off%512 != 0 {
				fmt.Println("disks: a malformed piece arrived; copy abandoned")
				return
			}
			b := zero[:n]
			if kind == chunkData {
				if _, err := io.ReadFull(r, buf[:n]); err != nil {
					fmt.Println("disks: the sender stopped mid-piece:", err)
					return
				}
				b = buf[:n]
			}
			if _, err := syscall.Pwrite(int(out[disk].Fd()), b, int64(off)); err != nil {
				fmt.Println("disks: writing here failed:", err)
				disksIn.err = err
				return
			}
		case chunkSync, chunkFinal:
			for _, f := range out {
				if err := f.Sync(); err != nil {
					fmt.Println("disks: flushing failed:", err)
					disksIn.err = err
					return
				}
			}
			if kind == chunkFinal {
				disksIn.final = true
				fmt.Println("disks: final; everything the sender wrote is on the disks here")
				fmt.Fprint(c, "SYNCED\n")
				close(disksIn.done)
				return
			}
			fmt.Fprint(c, "SYNCED\n")
		default:
			fmt.Println("disks: unknown piece; copy abandoned")
			return
		}
	}
}

// ownDrivers loads drivers for this machine's own devices. The receiver runs
// in an early boot shell where no device manager has done that, and it needs
// its disks to take the copy.
func ownDrivers() {
	for pass := 0; pass < 3; pass++ { // a bus driver loaded in one pass may show more devices in the next
		for _, bus := range []string{"pci", "virtio", "scsi"} {
			ents, _ := os.ReadDir("/sys/bus/" + bus + "/devices")
			for _, e := range ents {
				dir := "/sys/bus/" + bus + "/devices/" + e.Name()
				if _, err := os.Stat(dir + "/driver"); err == nil {
					continue
				}
				if a, err := os.ReadFile(dir + "/modalias"); err == nil && len(a) > 1 {
					modprobeCmd("-q", "-b", strings.TrimSpace(string(a))).Run()
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	// Disks show up a little after their controller: wait until the count holds still.
	last, still := -1, 0
	for i := 0; i < 50 && still < 5; i++ {
		if n := len(diskList()); n == last {
			still++
		} else {
			last, still = n, 0
		}
		time.Sleep(200 * time.Millisecond)
	}
}
