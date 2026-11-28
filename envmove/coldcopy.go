package main

// The copy of a powered-off machine's disks (EnvMap Move for a VM that is not
// running).
//
// A VM that is off has no system that could copy itself, so EnvMap starts two
// small helper machines from its CD: the giver on the old host, with the VM's
// disks attached to it, and the taker on the new host, with the new VM's blank
// disks. The VM itself is never started, on either host. This file is what the
// two helpers say to each other; cold_linux.go finds the disks and tells
// EnvMap how it goes.
//
//	giver                                    taker
//	ENVCOLD1, token, disk sizes     ─────►   are my disks large enough?
//	                                ◄─────   yes, or no and why
//	DATA  disk, place, bytes, sum   ─────►   checks the sum, writes
//	ZERO  disk, place, length       ─────►   makes sure it reads as zeros
//	SYNC  disk, place               ─────►   flushes: "on disk up to here"
//	END   disk, digest              ─────►   flushes, reads the whole disk back
//	                                ◄─────   the same digest, or not
//	DONE                            ─────►   every disk was confirmed
//
// RULES
//   - The giver only reads. Nothing in this file writes to a giver's disk.
//   - A disk counts only when the taker has read all of it back from the device
//     and its digest equals the giver's. What was sent proves nothing about
//     what is stored.
//   - A stretch of zeros is not sent, and not assumed either: the taker reads
//     its own disk there and writes zeros where it finds anything else. A new
//     thin disk reads as zeros already and stays thin; a reused one is cleaned.
//   - A broken connection is not a failure. The giver connects again and goes
//     on from the last place the taker confirmed; a piece sent twice lands in
//     the same place.
//   - A refusal is a failure with its reason, and is not tried again.
//
// No build tag: the tests (coldcopy_test.go) run wherever Go does.

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net"
	"sync"
	"time"
)

const (
	coldMagic = "ENVCOLD1"
	coldGrid  = 1 << 20 // zeros are found, and sums are counted, on this grid

	fData = 1
	fZero = 2
	fSync = 3
	fEnd  = 4
	fDone = 5

	frameLen  = 40
	frameSeed = 0x454E56434F4C4431
	badLimit  = 5 // damaged pieces in a row before the taker gives up
)

// coldAck: the taker confirms what is on its disks this often, and a copy that
// lost its connection goes on from the last such place.
var coldAck uint64 = 256 << 20

// coldDev is a disk as the copy needs it. *os.File is one.
type coldDev interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
}

// coldState is what a helper tells EnvMap, as one line of JSON.
type coldState struct {
	Role    string   `json:"role"`
	State   string   `json:"state"` // starting, waiting, copying, checking, done, failed
	Disk    int      `json:"disk"`  // the one being worked on, counted from 1
	Disks   int      `json:"disks"`
	Done    uint64   `json:"done"`    // bytes of the disks dealt with so far
	Total   uint64   `json:"total"`   // bytes of all the disks
	Sent    uint64   `json:"sent"`    // bytes that crossed (zeros do not)
	Checked uint64   `json:"checked"` // bytes read back from the new disks
	Breaks  int      `json:"breaks"`  // connections lost and made again
	Why     string   `json:"why,omitempty"`
	Digests []string `json:"digests,omitempty"`
	Beat    uint64   `json:"beat"` // goes up with every report: a line that stays the same is an old one
}

type coldStatus struct {
	mu sync.Mutex
	s  coldState
}

func (c *coldStatus) set(f func(*coldState)) {
	c.mu.Lock()
	f(&c.s)
	c.mu.Unlock()
}

func (c *coldStatus) get() coldState {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.s
	s.Digests = append([]string(nil), c.s.Digests...)
	return s
}

// line is the status as EnvMap reads it; every call counts as a report.
func (c *coldStatus) line() string {
	c.mu.Lock()
	c.s.Beat++
	b, _ := json.Marshal(c.s)
	c.mu.Unlock()
	return string(b)
}

func (c *coldStatus) fail(why string) {
	c.set(func(s *coldState) {
		if s.State != "failed" {
			s.State, s.Why = "failed", why
		}
	})
}

// refusal is a failure that trying again cannot cure.
type refusal struct{ why string }

func (r *refusal) Error() string { return r.why }

func refuse(f string, a ...any) error { return &refusal{fmt.Sprintf(f, a...)} }

func isZero(b []byte) bool {
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

var (
	zeroMu   sync.Mutex
	zeroSums = map[int]uint64{}
)

// zeroSum is the sum of n zero bytes, worked out once per length.
func zeroSum(n int) uint64 {
	zeroMu.Lock()
	defer zeroMu.Unlock()
	if v, ok := zeroSums[n]; ok {
		return v
	}
	v := xxh64(make([]byte, n), 0)
	zeroSums[n] = v
	return v
}

// digestStep folds one grid piece (its sum, and which piece it is) into a
// disk's digest. The place is part of it: two pieces swapped give another
// digest.
func digestStep(d, sum, idx uint64) uint64 {
	m := (sum ^ (idx+1)*p1) * p2
	return bits.RotateLeft64(d^m, 27)*p1 + p4
}

// pieceSum is the sum of one grid piece.
func pieceSum(b []byte) uint64 {
	if isZero(b) {
		return zeroSum(len(b))
	}
	return xxh64(b, 0)
}

type frame struct {
	kind, disk uint32
	off, n     uint64
	sum        uint64
}

func (f frame) bytes() []byte {
	b := make([]byte, frameLen)
	le := binary.LittleEndian
	le.PutUint32(b[0:], f.kind)
	le.PutUint32(b[4:], f.disk)
	le.PutUint64(b[8:], f.off)
	le.PutUint64(b[16:], f.n)
	le.PutUint64(b[24:], f.sum)
	le.PutUint64(b[32:], xxh64(b[:32], frameSeed))
	return b
}

func readFrame(r io.Reader) (frame, error) {
	var b [frameLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return frame{}, err
	}
	le := binary.LittleEndian
	if le.Uint64(b[32:]) != xxh64(b[:32], frameSeed) {
		return frame{}, errors.New("a damaged frame")
	}
	return frame{le.Uint32(b[0:]), le.Uint32(b[4:]), le.Uint64(b[8:]), le.Uint64(b[16:]), le.Uint64(b[24:])}, nil
}

type coldHello struct {
	Sizes []uint64 `json:"sizes"`
	Grid  int      `json:"grid"`
}

type coldReply struct {
	OK     bool   `json:"ok"`
	Why    string `json:"why,omitempty"`
	Off    uint64 `json:"off,omitempty"`
	Digest string `json:"digest,omitempty"`
}

func putPart(w io.Writer, b []byte) {
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(b)))
	w.Write(n[:])
	w.Write(b)
}

func getPart(r io.Reader, max uint32) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(n[:])
	if size > max {
		return nil, fmt.Errorf("a part of %d bytes is too large", size)
	}
	b := make([]byte, size)
	_, err := io.ReadFull(r, b)
	return b, err
}

func sendReply(w io.Writer, r coldReply) error {
	b, _ := json.Marshal(r)
	_, err := w.Write(append(b, '\n'))
	return err
}

func readReply(r *bufio.Reader) (coldReply, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return coldReply{}, err
	}
	var out coldReply
	if err := json.Unmarshal(line, &out); err != nil {
		return coldReply{}, fmt.Errorf("an answer that cannot be read: %w", err)
	}
	return out, nil
}

// ── the giver ──────────────────────────────────────────────────

type giver struct {
	token string
	disks []io.ReaderAt // read, never written
	sizes []uint64
	st    *coldStatus
	alloc func(int) []byte
	dial  func() (net.Conn, error)
	wait  time.Duration // how long a taker may stay silent before the copy is given up
	pause time.Duration // between two tries
	say   func(string, ...any)

	at     []uint64 // per disk: up to where the taker confirmed
	dig    []uint64 // and the digest up to there
	done   []bool
	passes []int
}

func (g *giver) run() error {
	n := len(g.disks)
	g.at, g.dig, g.done, g.passes = make([]uint64, n), make([]uint64, n), make([]bool, n), make([]int, n)
	var total uint64
	for _, s := range g.sizes {
		total += s
	}
	g.st.set(func(s *coldState) {
		s.Role, s.State, s.Disks, s.Total = "give", "waiting", n, total
		s.Digests = make([]string, n)
	})
	last := time.Now()
	for {
		c, err := g.dial()
		if err != nil {
			if time.Since(last) > g.wait {
				return refuse("the helper on the new host did not answer for %s: %v", g.wait.Round(time.Second), err)
			}
			time.Sleep(g.pause)
			continue
		}
		err = g.session(c)
		c.Close()
		if err == nil {
			g.st.set(func(s *coldState) { s.State, s.Done = "done", total })
			return nil
		}
		var r *refusal
		if errors.As(err, &r) {
			return err
		}
		last = time.Now()
		g.st.set(func(s *coldState) { s.Breaks++; s.State = "waiting" })
		g.say("the connection broke (%v): connecting again and going on from what was confirmed", err)
		time.Sleep(g.pause)
	}
}

func (g *giver) session(c net.Conn) error {
	w := bufio.NewWriterSize(c, 1<<20)
	r := bufio.NewReaderSize(c, 1<<16)
	w.WriteString(coldMagic)
	putPart(w, []byte(g.token))
	hello, _ := json.Marshal(coldHello{g.sizes, coldGrid})
	putPart(w, hello)
	if err := w.Flush(); err != nil {
		return err
	}
	rep, err := readReply(r)
	if err != nil {
		return err
	}
	if !rep.OK {
		return refuse("the helper on the new host refused: %s", rep.Why)
	}
	for d := range g.disks {
		for !g.done[d] {
			if err := g.disk(d, w, r); err != nil {
				return err
			}
		}
	}
	w.Write(frame{kind: fDone}.bytes())
	if err := w.Flush(); err != nil {
		return err
	}
	rep, err = readReply(r)
	if err != nil {
		return err
	}
	if !rep.OK {
		return refuse("the helper on the new host did not confirm the copy: %s", rep.Why)
	}
	return nil
}

// disk sends one disk from where the taker last confirmed, and asks for the
// read-back. It returns nil with done[d] unset when the read-back did not
// match and the disk is to be sent once more.
func (g *giver) disk(d int, w *bufio.Writer, r *bufio.Reader) error {
	size, off, dig := g.sizes[d], g.at[d], g.dig[d]
	var base uint64
	for _, s := range g.sizes[:d] {
		base += s
	}
	g.st.set(func(s *coldState) { s.State, s.Disk, s.Done = "copying", d+1, base+off })
	buf := g.alloc(coldGrid)
	var zstart, zlen, since uint64
	flushZero := func() {
		if zlen > 0 {
			w.Write(frame{kind: fZero, disk: uint32(d), off: zstart, n: zlen}.bytes())
			zlen = 0
		}
	}
	for off < size {
		n := uint64(coldGrid)
		if size-off < n {
			n = size - off
		}
		if got, err := g.disks[d].ReadAt(buf[:n], int64(off)); uint64(got) != n {
			return refuse("disk %d of the VM cannot be read at byte %d: %v", d+1, off, err)
		}
		idx := off / coldGrid
		if isZero(buf[:n]) {
			if zlen == 0 {
				zstart = off
			}
			zlen += n
			dig = digestStep(dig, zeroSum(int(n)), idx)
		} else {
			flushZero()
			sum := xxh64(buf[:n], 0)
			w.Write(frame{kind: fData, disk: uint32(d), off: off, n: n, sum: sum}.bytes())
			if _, err := w.Write(buf[:n]); err != nil {
				return err
			}
			dig = digestStep(dig, sum, idx)
			g.st.set(func(s *coldState) { s.Sent += n })
		}
		off += n
		since += n
		pos := base + off
		g.st.set(func(s *coldState) { s.Done = pos })
		if since >= coldAck && off < size {
			flushZero()
			w.Write(frame{kind: fSync, disk: uint32(d), off: off}.bytes())
			if err := w.Flush(); err != nil {
				return err
			}
			rep, err := readReply(r)
			if err != nil {
				return err
			}
			if !rep.OK {
				return refuse("the helper on the new host stopped: %s", rep.Why)
			}
			g.at[d], g.dig[d], since = off, dig, 0
		}
	}
	flushZero()
	w.Write(frame{kind: fEnd, disk: uint32(d), off: size, sum: dig}.bytes())
	if err := w.Flush(); err != nil {
		return err
	}
	g.st.set(func(s *coldState) { s.State = "checking" })
	rep, err := readReply(r)
	if err != nil {
		return err
	}
	if rep.OK {
		g.done[d] = true
		g.st.set(func(s *coldState) { s.Digests[d] = fmt.Sprintf("%016x", dig) })
		g.say("disk %d: the new disk was read back and is the same (%016x)", d+1, dig)
		return nil
	}
	if rep.Why != "" {
		return refuse("the helper on the new host stopped: %s", rep.Why)
	}
	g.passes[d]++
	if g.passes[d] >= 2 {
		return refuse("disk %d: the new disk does not hold what was written to it, twice (digest %016x here, %s there). "+
			"Its storage on the new host is not to be trusted", d+1, dig, rep.Digest)
	}
	g.say("disk %d: the new disk read back differently (%016x here, %s there): sending it once more", d+1, dig, rep.Digest)
	g.at[d], g.dig[d] = 0, 0
	return nil
}

// ── the taker ──────────────────────────────────────────────────

type taker struct {
	token string
	disks []coldDev     // written
	read  []io.ReaderAt // read back: the device itself, not what is still in memory
	sizes []uint64      // of these disks
	st    *coldStatus
	alloc func(int) []byte
	say   func(string, ...any)

	want []uint64 // the sizes the giver named
	ok   []bool
	seen []uint64 // per disk: the furthest place a piece reached
	bad  int
	why  string // set once the copy cannot go on here
}

// serve takes connections until a giver has had every disk confirmed. It
// returns nil then, and the reason when the copy cannot go on here.
func (t *taker) serve(ln net.Listener) error {
	n := len(t.disks)
	t.ok, t.seen = make([]bool, n), make([]uint64, n)
	t.st.set(func(s *coldState) {
		s.Role, s.State, s.Disks = "take", "waiting", n
		s.Digests = make([]string, n)
	})
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			tc.SetKeepAlive(true)
			tc.SetKeepAlivePeriod(20 * time.Second)
		}
		done, err := t.session(c)
		c.Close()
		if done {
			t.st.set(func(s *coldState) { s.State = "done"; s.Done = s.Total })
			return nil
		}
		if err != nil {
			t.say("a connection ended: %v", err)
		}
		if t.why == "" {
			t.st.set(func(s *coldState) {
				if s.State != "waiting" {
					s.State = "waiting"
					s.Breaks++
				}
			})
		}
	}
}

func (t *taker) stop(why string) {
	if t.why == "" {
		t.why = why
		t.st.fail(why)
		t.say("stopped: %s", why)
	}
}

func (t *taker) session(c net.Conn) (bool, error) {
	r := bufio.NewReaderSize(c, 1<<20)
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil || string(magic[:]) != coldMagic {
		return false, errors.New("not a copy")
	}
	tok, err := getPart(r, 256)
	if err != nil {
		return false, err
	}
	hb, err := getPart(r, 1<<16)
	if err != nil {
		return false, err
	}
	if t.token == "" || subtle.ConstantTimeCompare(tok, []byte(t.token)) != 1 {
		sendReply(c, coldReply{Why: "this is not the move this helper was started for"})
		return false, errors.New("wrong token")
	}
	if t.why != "" {
		sendReply(c, coldReply{Why: t.why})
		return false, nil
	}
	var h coldHello
	if err := json.Unmarshal(hb, &h); err != nil || h.Grid != coldGrid {
		sendReply(c, coldReply{Why: "the two helpers are not of the same version"})
		return false, errors.New("another version")
	}
	if len(h.Sizes) != len(t.disks) {
		t.stop(fmt.Sprintf("the VM has %d disks and the new VM has %d", len(h.Sizes), len(t.disks)))
		sendReply(c, coldReply{Why: t.why})
		return false, nil
	}
	for i, s := range h.Sizes {
		if t.sizes[i] < s {
			t.stop(fmt.Sprintf("disk %d of the new VM holds %d bytes and must hold %d", i+1, t.sizes[i], s))
			sendReply(c, coldReply{Why: t.why})
			return false, nil
		}
		if t.want != nil && t.want[i] != s {
			sendReply(c, coldReply{Why: "another copy is under way here"})
			return false, errors.New("other sizes than before")
		}
	}
	if t.want == nil {
		t.want = append([]uint64(nil), h.Sizes...)
		var total uint64
		for _, s := range t.want {
			total += s
		}
		t.st.set(func(s *coldState) { s.Total = total })
	}
	if err := sendReply(c, coldReply{OK: true}); err != nil {
		return false, err
	}
	t.st.set(func(s *coldState) { s.State = "copying" })
	buf := t.alloc(coldGrid)
	for {
		f, err := readFrame(r)
		if err != nil {
			return false, err
		}
		d := int(f.disk)
		if f.kind != fDone && d >= len(t.disks) {
			return false, fmt.Errorf("a piece for disk %d, which is not here", d+1)
		}
		switch f.kind {
		case fData:
			if f.n == 0 || f.n > coldGrid || f.off%512 != 0 || f.off+f.n > t.want[d] {
				return false, errors.New("a piece that does not fit its disk")
			}
			if _, err := io.ReadFull(r, buf[:f.n]); err != nil {
				return false, err
			}
			if xxh64(buf[:f.n], 0) != f.sum {
				t.bad++
				if t.bad >= badLimit {
					t.stop(fmt.Sprintf("what arrives is damaged on the way, %d times in a row: the transfer network is not to be trusted", t.bad))
				}
				return false, errors.New("a piece arrived damaged")
			}
			t.bad = 0
			if _, err := t.disks[d].WriteAt(buf[:f.n], int64(f.off)); err != nil {
				t.stop(fmt.Sprintf("disk %d of the new VM cannot be written at byte %d: %v", d+1, f.off, err))
				return false, nil
			}
			t.reached(d, f.off+f.n, f.n)
		case fZero:
			if f.off%512 != 0 || f.off+f.n > t.want[d] || f.off+f.n < f.off {
				return false, errors.New("a stretch that does not fit its disk")
			}
			if err := t.zero(d, f.off, f.n, buf); err != nil {
				t.stop(err.Error())
				return false, nil
			}
			t.reached(d, f.off+f.n, 0)
		case fSync:
			if err := t.disks[d].Sync(); err != nil {
				t.stop(fmt.Sprintf("disk %d of the new VM did not take what was written to it: %v", d+1, err))
				sendReply(c, coldReply{Why: t.why})
				return false, nil
			}
			if err := sendReply(c, coldReply{OK: true, Off: f.off}); err != nil {
				return false, err
			}
		case fEnd:
			if err := t.disks[d].Sync(); err != nil {
				t.stop(fmt.Sprintf("disk %d of the new VM did not take what was written to it: %v", d+1, err))
				sendReply(c, coldReply{Why: t.why})
				return false, nil
			}
			t.st.set(func(s *coldState) { s.State, s.Disk = "checking", d+1 })
			got, err := t.readBack(d, buf)
			if err != nil {
				t.stop(err.Error())
				sendReply(c, coldReply{Why: t.why})
				return false, nil
			}
			t.ok[d] = got == f.sum
			if t.ok[d] {
				t.st.set(func(s *coldState) { s.Digests[d] = fmt.Sprintf("%016x", got); s.State = "copying" })
				t.say("disk %d: read back from the device, the same as the original (%016x)", d+1, got)
			} else {
				t.seen[d] = 0
				t.say("disk %d: read back from the device, NOT the same (%016x, the original is %016x)", d+1, got, f.sum)
			}
			if err := sendReply(c, coldReply{OK: t.ok[d], Digest: fmt.Sprintf("%016x", got)}); err != nil {
				return false, err
			}
		case fDone:
			for i, ok := range t.ok {
				if !ok {
					sendReply(c, coldReply{Why: fmt.Sprintf("disk %d was never confirmed", i+1)})
					return false, errors.New("done was said too early")
				}
			}
			return true, sendReply(c, coldReply{OK: true})
		default:
			return false, fmt.Errorf("a frame of kind %d", f.kind)
		}
	}
}

// reached moves this helper's own count along. It is what was dealt with,
// not what was confirmed.
func (t *taker) reached(d int, end, sent uint64) {
	if end > t.seen[d] {
		t.seen[d] = end
	}
	var pos uint64
	for i, s := range t.seen {
		if t.ok[i] {
			pos += t.want[i]
		} else {
			pos += s
		}
	}
	t.st.set(func(s *coldState) { s.Done, s.Sent, s.Disk = pos, s.Sent+sent, d+1 })
}

// zero makes [off, off+n) of disk d read as zeros, writing only where it does not.
func (t *taker) zero(d int, off, n uint64, buf []byte) error {
	var blank []byte
	for n > 0 {
		k := uint64(coldGrid) - off%coldGrid
		if n < k {
			k = n
		}
		if got, err := t.read[d].ReadAt(buf[:k], int64(off)); uint64(got) != k {
			return fmt.Errorf("disk %d of the new VM cannot be read at byte %d: %v", d+1, off, err)
		}
		if !isZero(buf[:k]) {
			if blank == nil {
				blank = t.alloc(coldGrid)
				for i := range blank {
					blank[i] = 0
				}
			}
			if _, err := t.disks[d].WriteAt(blank[:k], int64(off)); err != nil {
				return fmt.Errorf("disk %d of the new VM cannot be written at byte %d: %v", d+1, off, err)
			}
		}
		off += k
		n -= k
	}
	return nil
}

// readBack reads the whole of disk d from the device and returns its digest.
func (t *taker) readBack(d int, buf []byte) (uint64, error) {
	var dig, off uint64
	size := t.want[d]
	var before uint64
	for i := range t.want[:d] {
		before += t.want[i]
	}
	for off < size {
		n := uint64(coldGrid)
		if size-off < n {
			n = size - off
		}
		if got, err := t.read[d].ReadAt(buf[:n], int64(off)); uint64(got) != n {
			return 0, fmt.Errorf("disk %d of the new VM cannot be read back at byte %d: %v", d+1, off, err)
		}
		dig = digestStep(dig, pieceSum(buf[:n]), off/coldGrid)
		off += n
		pos := before + off
		t.st.set(func(s *coldState) { s.Checked = pos })
	}
	return dig, nil
}
