package main

// The powered-off copy, proven on disks held in memory and a real TCP
// connection on this machine. Each test names the rule it holds
// (coldcopy.go, RULES): a rule whose code is removed must fail its test.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type memDisk struct {
	mu       sync.Mutex
	b        []byte
	writes   int
	at       map[int64]int // writes that began at each place
	flip     int64         // a write that covers this place is stored with one byte changed (-1: none)
	flips    int           // how many more times
	readFail int64         // reads that cover this place fail (-1: none)
	lie      int64         // reads that cover this place return one byte changed (-1: none)
	readOnly bool          // a write here is the test's failure
	wrote    bool
}

func newDisk(b []byte) *memDisk {
	return &memDisk{b: b, at: map[int64]int{}, flip: -1, readFail: -1, lie: -1}
}

func (m *memDisk) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	if m.readFail >= off && m.readFail < off+int64(len(p)) {
		return 0, errors.New("input/output error")
	}
	n := copy(p, m.b[off:])
	if m.lie >= off && m.lie < off+int64(n) {
		p[m.lie-off] ^= 0x40
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memDisk) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.readOnly {
		m.wrote = true
		return 0, errors.New("this disk is the VM's own: nothing may write to it")
	}
	if off+int64(len(p)) > int64(len(m.b)) {
		return 0, errors.New("no space left on device")
	}
	copy(m.b[off:], p)
	m.writes++
	m.at[off]++
	if m.flips > 0 && m.flip >= off && m.flip < off+int64(len(p)) {
		m.b[m.flip] ^= 0x01
		m.flips--
	}
	return len(p), nil
}

func (m *memDisk) Sync() error { return nil }

func (m *memDisk) snapshot() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte(nil), m.b...)
}

// pattern is n bytes that are different everywhere, with the stretches named
// in zeros (pairs of start, length) left as zeros.
func pattern(n int, seed uint64, zeros ...int) []byte {
	b := make([]byte, n)
	x := seed*0x9E3779B97F4A7C15 + 1
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x) | 1
	}
	for i := 0; i+1 < len(zeros); i += 2 {
		for j := zeros[i]; j < zeros[i]+zeros[i+1] && j < n; j++ {
			b[j] = 0
		}
	}
	return b
}

func filled(n int, v byte) []byte { return bytes.Repeat([]byte{v}, n) }

// link carries what one side writes, and can break or damage it once.
type link struct {
	net.Conn
	mu     *sync.Mutex
	sent   *int64
	cutAt  *int64 // the connection dies when this many bytes went out (0: never)
	flipAt *int64 // the byte at this place of the stream is changed once (0: never)
}

func (l link) Write(p []byte) (int, error) {
	l.mu.Lock()
	start := *l.sent
	*l.sent += int64(len(p))
	cut, flip := *l.cutAt, *l.flipAt
	if cut > 0 && start+int64(len(p)) > cut {
		*l.cutAt = 0
		l.mu.Unlock()
		keep := cut - start
		if keep > 0 {
			l.Conn.Write(p[:keep])
		}
		l.Conn.Close()
		return int(keep), errors.New("connection reset by peer")
	}
	if flip > 0 && flip >= start && flip < start+int64(len(p)) {
		*l.flipAt = 0
		q := append([]byte(nil), p...)
		q[flip-start] ^= 0x10
		p = q
	}
	l.mu.Unlock()
	return l.Conn.Write(p)
}

type rig struct {
	t      *testing.T
	ln     net.Listener
	tk     *taker
	gv     *giver
	gst    *coldStatus
	tst    *coldStatus
	mu     sync.Mutex
	sent   int64
	cutAt  int64
	flipAt int64
	took   chan error
	log    []string
}

func (r *rig) say(f string, a ...any) {
	r.mu.Lock()
	r.log = append(r.log, f)
	r.mu.Unlock()
}

func newRig(t *testing.T, src, dst []*memDisk, token string) *rig {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r := &rig{t: t, ln: ln, gst: &coldStatus{}, tst: &coldStatus{}, took: make(chan error, 1)}
	mk := func(n int) []byte { return make([]byte, n) }
	r.tk = &taker{token: "the-move's-own-token", st: r.tst, alloc: mk, say: r.say}
	for _, d := range dst {
		r.tk.disks = append(r.tk.disks, d)
		r.tk.read = append(r.tk.read, d)
		r.tk.sizes = append(r.tk.sizes, uint64(len(d.b)))
	}
	r.gv = &giver{token: token, st: r.gst, alloc: mk, wait: 3 * time.Second, pause: 5 * time.Millisecond, say: r.say}
	for _, d := range src {
		d.readOnly = true
		r.gv.disks = append(r.gv.disks, d)
		r.gv.sizes = append(r.gv.sizes, uint64(len(d.b)))
	}
	r.gv.dial = func() (net.Conn, error) {
		c, err := net.DialTimeout("tcp4", ln.Addr().String(), time.Second)
		if err != nil {
			return nil, err
		}
		return link{c, &r.mu, &r.sent, &r.cutAt, &r.flipAt}, nil
	}
	go func() { r.took <- r.tk.serve(ln) }()
	return r
}

// both runs the giver and waits for the taker to finish too.
func (r *rig) both() error {
	r.t.Helper()
	if err := r.gv.run(); err != nil {
		return err
	}
	select {
	case err := <-r.took:
		return err
	case <-time.After(5 * time.Second):
		r.t.Fatal("the giver finished and the taker did not")
		return nil
	}
}

func same(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: differs at byte %d (and maybe further)", what, i)
			}
		}
	}
}

const mib = 1 << 20

// Every byte of every disk arrives, zeros included, into disks that held
// something else before; sizes need not be whole megabytes, and the new disk
// may be larger.
func TestCopiesEveryDisk(t *testing.T) {
	a := pattern(3*mib+1536, 1, 0, 4096, mib+512, 2*mib-512)
	b := pattern(2*mib, 2, mib, mib)
	src := []*memDisk{newDisk(append([]byte(nil), a...)), newDisk(append([]byte(nil), b...))}
	dst := []*memDisk{newDisk(filled(len(a)+mib, 0xAA)), newDisk(filled(len(b), 0x55))}
	r := newRig(t, src, dst, "the-move's-own-token")
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "disk 1", dst[0].snapshot()[:len(a)], a)
	same(t, "disk 2", dst[1].snapshot(), b)
	same(t, "disk 1 of the VM itself", src[0].snapshot(), a)
	g, k := r.gst.get(), r.tst.get()
	if g.State != "done" || k.State != "done" {
		t.Fatalf("states %q and %q, want done and done", g.State, k.State)
	}
	if g.Digests[0] == "" || g.Digests[0] != k.Digests[0] || g.Digests[1] != k.Digests[1] {
		t.Fatalf("digests differ: %v and %v", g.Digests, k.Digests)
	}
	if g.Sent >= g.Total || g.Sent == 0 {
		t.Fatalf("sent %d of %d: zeros must not cross, and the rest must", g.Sent, g.Total)
	}
	if g.Done != g.Total || k.Checked != k.Total {
		t.Fatalf("done %d of %d, checked %d of %d", g.Done, g.Total, k.Checked, k.Total)
	}
}

// RULE: the giver only reads.
func TestGiverNeverWrites(t *testing.T) {
	a := pattern(2*mib, 3, 4096, mib)
	src := []*memDisk{newDisk(append([]byte(nil), a...))}
	dst := []*memDisk{newDisk(filled(len(a), 0xAA))}
	r := newRig(t, src, dst, "the-move's-own-token")
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	if src[0].wrote || src[0].writes != 0 {
		t.Fatal("something wrote to the VM's own disk")
	}
}

// RULE: a stretch of zeros is not sent and not assumed: it is written only
// where the new disk does not read as zeros already.
func TestZerosAreMadeSureOfNotAssumed(t *testing.T) {
	blank := make([]byte, 4*mib)
	clean := newDisk(make([]byte, 4*mib))
	r := newRig(t, []*memDisk{newDisk(append([]byte(nil), blank...))}, []*memDisk{clean}, "the-move's-own-token")
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	if clean.writes != 0 {
		t.Fatalf("%d writes to a disk that read as zeros already: a thin disk would have been filled", clean.writes)
	}
	if r.gst.get().Sent != 0 {
		t.Fatal("zeros crossed")
	}
	dirty := newDisk(filled(4*mib, 0xAA))
	r = newRig(t, []*memDisk{newDisk(append([]byte(nil), blank...))}, []*memDisk{dirty}, "the-move's-own-token")
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "a reused disk", dirty.snapshot(), blank)
}

// RULE: a broken connection is not a failure, and the copy goes on from the
// last confirmed place, not from the start.
func TestBrokenConnectionGoesOnFromWhatWasConfirmed(t *testing.T) {
	old := coldAck
	coldAck = mib
	defer func() { coldAck = old }()
	a := pattern(6*mib, 4)
	src := []*memDisk{newDisk(append([]byte(nil), a...))}
	dst := []*memDisk{newDisk(make([]byte, len(a)))}
	r := newRig(t, src, dst, "the-move's-own-token")
	r.cutAt = 3*mib + mib/2
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "the disk", dst[0].snapshot(), a)
	if r.gst.get().Breaks != 1 {
		t.Fatalf("%d breaks, want 1", r.gst.get().Breaks)
	}
	if n := dst[0].at[0]; n != 1 {
		t.Fatalf("the first megabyte was written %d times: the copy started again instead of going on", n)
	}
	if n := dst[0].at[5*mib]; n != 1 {
		t.Fatalf("the last megabyte was written %d times", n)
	}
}

// RULE: what arrives damaged is not written; it is sent again.
func TestDamagedOnTheWayIsNotWritten(t *testing.T) {
	a := pattern(3*mib, 5)
	src := []*memDisk{newDisk(append([]byte(nil), a...))}
	dst := []*memDisk{newDisk(make([]byte, len(a)))}
	r := newRig(t, src, dst, "the-move's-own-token")
	r.flipAt = 600 + mib + mib/2 // inside the second piece's bytes
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "the disk", dst[0].snapshot(), a)
	if r.gv.passes[0] != 0 {
		t.Fatal("the damaged piece was written and only the read-back found it")
	}
	if r.gst.get().Breaks == 0 {
		t.Fatal("the damaged piece was not noticed")
	}
}

// RULE: a disk counts only when it was read back and is the same. Stored
// wrongly once: sent once more. Stored wrongly again: refused.
func TestStoredWronglyIsFoundByReadingBack(t *testing.T) {
	a := pattern(3*mib, 6)
	once := newDisk(make([]byte, len(a)))
	once.flip, once.flips = mib+77, 1
	r := newRig(t, []*memDisk{newDisk(append([]byte(nil), a...))}, []*memDisk{once}, "the-move's-own-token")
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "the disk after its second pass", once.snapshot(), a)
	if r.gv.passes[0] != 1 {
		t.Fatalf("%d extra passes, want 1", r.gv.passes[0])
	}
	always := newDisk(make([]byte, len(a)))
	always.flip, always.flips = mib+77, 1000
	r = newRig(t, []*memDisk{newDisk(append([]byte(nil), a...))}, []*memDisk{always}, "the-move's-own-token")
	err := r.gv.run()
	var ref *refusal
	if !errors.As(err, &ref) || !strings.Contains(err.Error(), "does not hold what was written") {
		t.Fatalf("a disk that stores wrongly twice must be refused, got %v", err)
	}
	if r.gst.get().State == "done" || r.tst.get().State == "done" {
		t.Fatal("a copy that does not match was called done")
	}
}

// RULE: the read-back comes from the device, not from what was written.
func TestReadBackIsFromTheDevice(t *testing.T) {
	a := pattern(2*mib, 7)
	w := newDisk(make([]byte, len(a)))
	r := newRig(t, []*memDisk{newDisk(append([]byte(nil), a...))}, []*memDisk{w}, "the-move's-own-token")
	device := newDisk(w.b) // the same bytes, read by another road that returns one of them wrong
	device.lie = mib + 5
	r.tk.read[0] = device
	err := r.gv.run()
	if err == nil || !strings.Contains(err.Error(), "does not hold what was written") {
		t.Fatalf("the device reads differently from what was written and the copy passed: %v", err)
	}
}

func TestWrongTokenIsRefusedAndTheRightOneStillServed(t *testing.T) {
	a := pattern(mib, 8)
	dst := []*memDisk{newDisk(make([]byte, len(a)))}
	r := newRig(t, []*memDisk{newDisk(append([]byte(nil), a...))}, dst, "somebody-else")
	err := r.gv.run()
	var ref *refusal
	if !errors.As(err, &ref) || !strings.Contains(err.Error(), "not the move") {
		t.Fatalf("a wrong token must be refused, got %v", err)
	}
	if dst[0].writes != 0 {
		t.Fatal("a stranger wrote to the new disk")
	}
	if r.tst.get().State == "failed" {
		t.Fatal("a stranger's knock stopped the helper")
	}
	r.gv.token = "the-move's-own-token"
	r.gst = &coldStatus{}
	r.gv.st = r.gst
	if err := r.both(); err != nil {
		t.Fatal(err)
	}
	same(t, "the disk", dst[0].snapshot(), a)
}

func TestNewDiskTooSmallIsRefusedWithItsReason(t *testing.T) {
	a := pattern(2*mib, 9)
	dst := []*memDisk{newDisk(make([]byte, len(a)-512))}
	r := newRig(t, []*memDisk{newDisk(append([]byte(nil), a...))}, dst, "the-move's-own-token")
	err := r.gv.run()
	if err == nil || !strings.Contains(err.Error(), "must hold 2097152") {
		t.Fatalf("got %v", err)
	}
	if s := r.tst.get(); s.State != "failed" || !strings.Contains(s.Why, "disk 1") {
		t.Fatalf("the helper on the new host says %q %q", s.State, s.Why)
	}
	if dst[0].writes != 0 {
		t.Fatal("something was written to a disk that is too small")
	}
	// one disk fewer than the VM has
	r = newRig(t, []*memDisk{newDisk(append([]byte(nil), a...)), newDisk(append([]byte(nil), a...))},
		[]*memDisk{newDisk(make([]byte, len(a)))}, "the-move's-own-token")
	if err := r.gv.run(); err == nil || !strings.Contains(err.Error(), "has 2 disks and the new VM has 1") {
		t.Fatalf("got %v", err)
	}
}

func TestUnreadableDiskStopsWithItsPlace(t *testing.T) {
	a := pattern(3*mib, 10)
	bad := newDisk(append([]byte(nil), a...))
	bad.readFail = mib + 10
	r := newRig(t, []*memDisk{bad}, []*memDisk{newDisk(make([]byte, len(a)))}, "the-move's-own-token")
	err := r.gv.run()
	var ref *refusal
	if !errors.As(err, &ref) || !strings.Contains(err.Error(), "cannot be read at byte 1048576") {
		t.Fatalf("got %v", err)
	}
	if r.tst.get().State == "done" {
		t.Fatal("the helper on the new host called a part of a disk done")
	}
}

// a hand-made giver, for what an honest one never sends
func knock(t *testing.T, r *rig, sizes []uint64, frames ...[]byte) (coldReply, *bufio.Reader, net.Conn) {
	t.Helper()
	c, err := net.DialTimeout("tcp4", r.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	var b bytes.Buffer
	b.WriteString(coldMagic)
	putPart(&b, []byte("the-move's-own-token"))
	h, _ := json.Marshal(coldHello{sizes, coldGrid})
	putPart(&b, h)
	c.Write(b.Bytes())
	rd := bufio.NewReader(c)
	rep, err := readReply(rd)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range frames {
		c.Write(f)
	}
	return rep, rd, c
}

// RULE: done is said only when every disk was confirmed.
func TestDoneIsNotBelievedBeforeEveryDiskWasConfirmed(t *testing.T) {
	dst := []*memDisk{newDisk(make([]byte, mib))}
	r := newRig(t, nil, dst, "the-move's-own-token")
	rep, rd, _ := knock(t, r, []uint64{mib}, frame{kind: fDone}.bytes())
	if !rep.OK {
		t.Fatal(rep.Why)
	}
	got, err := readReply(rd)
	if err != nil || got.OK || !strings.Contains(got.Why, "disk 1 was never confirmed") {
		t.Fatalf("got %+v %v", got, err)
	}
	if r.tst.get().State == "done" {
		t.Fatal("done without a confirmed disk")
	}
}

func TestPieceOutsideItsDiskIsNotWritten(t *testing.T) {
	dst := []*memDisk{newDisk(make([]byte, 2*mib))}
	r := newRig(t, nil, dst, "the-move's-own-token")
	piece := pattern(mib, 11)
	// the giver named a disk of one megabyte: a piece in the second megabyte is outside it
	f := frame{kind: fData, off: mib, n: mib, sum: xxh64(piece, 0)}.bytes()
	_, rd, _ := knock(t, r, []uint64{mib}, f, piece)
	if _, err := rd.ReadByte(); err == nil {
		t.Fatal("the connection stayed open after a piece outside its disk")
	}
	if dst[0].writes != 0 {
		t.Fatal("a piece outside the disk the giver named was written")
	}
}

func TestDamagedFrameIsNotRead(t *testing.T) {
	b := frame{kind: fZero, disk: 0, off: 0, n: mib}.bytes()
	b[9] ^= 1
	if _, err := readFrame(bytes.NewReader(b)); err == nil {
		t.Fatal("a frame with a changed place was read")
	}
}

// The digest names the place of each piece: two pieces swapped are another disk.
func TestSwappedPiecesAreAnotherDigest(t *testing.T) {
	x, y := xxh64(pattern(mib, 12), 0), xxh64(pattern(mib, 13), 0)
	if digestStep(digestStep(0, x, 0), y, 1) == digestStep(digestStep(0, y, 0), x, 1) {
		t.Fatal("two pieces swapped give the same digest")
	}
	if digestStep(0, zeroSum(mib), 0) == digestStep(0, zeroSum(mib), 1) {
		t.Fatal("a zero piece gives the same step wherever it is")
	}
	if pieceSum(make([]byte, 4096)) != xxh64(make([]byte, 4096), 0) {
		t.Fatal("the sum of zeros differs between the two sides")
	}
}

func TestStatusLineIsWhatEnvMapReads(t *testing.T) {
	st := &coldStatus{}
	st.set(func(s *coldState) { s.Role, s.State, s.Total, s.Done = "give", "copying", 100, 40 })
	var a, b coldState
	json.Unmarshal([]byte(st.line()), &a)
	json.Unmarshal([]byte(st.line()), &b)
	if a.State != "copying" || a.Done != 40 || b.Beat != a.Beat+1 {
		t.Fatalf("got %+v then %+v", a, b)
	}
	st.fail("first reason")
	st.fail("second reason")
	if s := st.get(); s.State != "failed" || s.Why != "first reason" {
		t.Fatalf("got %+v", s)
	}
}
