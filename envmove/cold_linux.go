//go:build linux

package main

// A helper machine of a powered-off move: what the CD's first process does
// when its settings (ENVMOVE.JSN) name a role.
//
//	role "give"   on the old host, with the VM's disks attached: reads them
//	role "take"   on the new host, with the new VM's disks: writes, reads back
//
// The copy itself is coldcopy.go. Here: which disk is which, how it is opened,
// and how EnvMap is told how it goes.
//
// WHICH DISK IS WHICH
//     EnvMap attaches every disk at a place it chose and names that place in
//     the settings (SCSI target and unit). A disk is taken by its place, never
//     by the order it showed up in or by its size: two disks of the same size
//     swapped would be a VM that starts from the wrong one.
//
// THE VM'S OWN DISKS ARE NOT WRITTEN
//     A giver sets each disk read-only in the kernel before it reads a byte,
//     checks that the kernel says so, and opens it for reading only.
//
// NOTHING COMES FROM MEMORY
//     Disks are opened without the page cache, so what the taker reads back is
//     what the device holds, not what this kernel still remembers writing.
//
// HOW ENVMAP IS TOLD
//     One line of JSON (coldState), two ways, because the two hypervisors
//     offer different roads into a VM that has no tools in it:
//       - on the console, "envcold: {...}". On ESXi the helper's serial port
//         is a file on the datastore, which EnvMap reads.
//       - as the answer to the QEMU guest agent's guest-exec, on the port
//         Proxmox gives a VM whose agent option is on. This program answers
//         the handful of agent commands Proxmox sends; it runs nothing.
//     A helper never powers itself off when it is done or has failed: it stays
//     and keeps answering until EnvMap has read the outcome and stops it. A
//     helper that is off has therefore said nothing about its copy.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	blkROSet     = 0x125D
	blkROGet     = 0x125E
	blkGetSize64 = 0x80081272
	oDirect      = 0x4000
)

// coldSlot is where EnvMap attached one disk, and the least it must hold.
type coldSlot struct {
	T     int    `json:"t"` // SCSI target
	L     int    `json:"l"` // unit (LUN)
	Bytes uint64 `json:"bytes"`
}

type scsiDisk struct {
	name     string
	host, ch int
	t, l     int
	bytes    uint64
}

// scsiDisks is every SCSI disk here with the place it is attached at.
func scsiDisks() []scsiDisk {
	var out []scsiDisk
	ents, _ := os.ReadDir("/sys/block")
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "sd") {
			continue
		}
		link, err := filepath.EvalSymlinks("/sys/block/" + n + "/device")
		if err != nil {
			continue
		}
		p := strings.Split(filepath.Base(link), ":")
		if len(p) != 4 {
			continue
		}
		var v [4]int
		ok := true
		for i := range p {
			if v[i], err = strconv.Atoi(p[i]); err != nil {
				ok = false
			}
		}
		if !ok {
			continue
		}
		out = append(out, scsiDisk{n, v[0], v[1], v[2], v[3], readU("/sys/block/"+n+"/size") * 512})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// coldFind is the device of each slot, in the settings' order. Every slot
// must be answered by exactly one disk.
func coldFind(slots []coldSlot) ([]scsiDisk, error) {
	var have []scsiDisk
	for i := 0; i < 100; i++ { // disks show up a moment after their controller
		have = scsiDisks()
		if len(have) >= len(slots) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	seen := make([]string, len(have))
	for i, d := range have {
		seen[i] = fmt.Sprintf("target %d unit %d (%d bytes)", d.t, d.l, d.bytes)
	}
	here := strings.Join(seen, ", ")
	if here == "" {
		here = "none"
	}
	if len(have) != len(slots) {
		return nil, fmt.Errorf("%d disks are attached to this helper and the move names %d (attached: %s)", len(have), len(slots), here)
	}
	out := make([]scsiDisk, len(slots))
	for i, s := range slots {
		var hit []scsiDisk
		for _, d := range have {
			if d.t == s.T && d.l == s.L {
				hit = append(hit, d)
			}
		}
		if len(hit) != 1 {
			return nil, fmt.Errorf("disk %d should be at target %d unit %d, and %d disks are there (attached: %s)", i+1, s.T, s.L, len(hit), here)
		}
		if hit[0].bytes < s.Bytes {
			return nil, fmt.Errorf("disk %d holds %d bytes and the move expects at least %d: it is not the disk the move means", i+1, hit[0].bytes, s.Bytes)
		}
		out[i] = hit[0]
	}
	return out, nil
}

func ioctlInt(f *os.File, req uintptr, v *int32) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), req, uintptr(unsafe.Pointer(v))); e != 0 {
		return e
	}
	return nil
}

func devBytes(f *os.File) (uint64, error) {
	var n uint64
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), blkGetSize64, uintptr(unsafe.Pointer(&n))); e != 0 {
		return 0, e
	}
	return n, nil
}

// openToRead opens one of the VM's own disks: read-only in the kernel first,
// then for reading, past the page cache.
func openToRead(name string) (*os.File, uint64, error) {
	f, err := os.OpenFile("/dev/"+name, os.O_RDONLY|oDirect, 0)
	if err != nil {
		return nil, 0, err
	}
	one := int32(1)
	if err := ioctlInt(f, blkROSet, &one); err != nil {
		f.Close()
		return nil, 0, fmt.Errorf("it could not be set read-only: %v", err)
	}
	var ro int32
	if err := ioctlInt(f, blkROGet, &ro); err != nil || ro == 0 {
		f.Close()
		return nil, 0, fmt.Errorf("the kernel does not say it is read-only (%v)", err)
	}
	n, err := devBytes(f)
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, n, nil
}

// coldLog keeps the helper's last lines, for EnvMap to show.
type coldLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *coldLog) say(f string, a ...any) {
	s := fmt.Sprintf(f, a...)
	fmt.Println("envcold: " + s)
	l.mu.Lock()
	l.lines = append(l.lines, s)
	if len(l.lines) > 20 {
		l.lines = l.lines[len(l.lines)-20:]
	}
	l.mu.Unlock()
}

func (l *coldLog) tail() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// coldInit is a helper's whole life. It never returns.
func coldInit(cfg *bootConfig) {
	st, lg := &coldStatus{}, &coldLog{}
	st.set(func(s *coldState) { s.Role, s.State, s.Disks = cfg.Role, "starting", len(cfg.Disks) })
	go coldReport(st)
	go qgaServe(st, lg)
	fail := func(f string, a ...any) {
		why := fmt.Sprintf(f, a...)
		st.fail(why)
		lg.say("stopped: %s", why)
		fmt.Println("envcold: " + st.line())
		halt()
	}
	if cfg.Role != "give" && cfg.Role != "take" {
		fail("the settings name a role this helper does not know (%q)", cfg.Role)
	}
	if len(cfg.Disks) == 0 {
		fail("the settings name no disk")
	}
	if len(cfg.Token) < 16 {
		fail("the settings carry no token for this move")
	}
	id, err := netFromConfig(cfg.IP, cfg.GW, cfg.MAC)
	if err != nil {
		fail("the transfer card: %v", err)
	}
	lg.say("helper (%s) on %s", cfg.Role, id)
	found, err := coldFind(cfg.Disks)
	if err != nil {
		fail("%v", err)
	}
	alloc := func(n int) []byte { return alignedBuf(n) }
	if cfg.Role == "give" {
		g := &giver{token: cfg.Token, st: st, alloc: alloc, wait: 30 * time.Minute, pause: 2 * time.Second, say: lg.say}
		for i, d := range found {
			f, n, err := openToRead(d.name)
			if err != nil {
				fail("disk %d of the VM (%s): %v", i+1, d.name, err)
			}
			g.disks, g.sizes = append(g.disks, f), append(g.sizes, n)
			lg.say("disk %d: %s, %d bytes, read-only", i+1, d.name, n)
		}
		g.dial = func() (net.Conn, error) {
			c, err := net.DialTimeout("tcp4", cfg.To, 5*time.Second)
			if err != nil {
				return nil, err
			}
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(20 * time.Second)
			}
			return c, nil
		}
		lg.say("looking for the helper on the new host at %s", cfg.To)
		if err := g.run(); err != nil {
			fail("%v", err)
		}
		lg.say("every disk was read back on the new host and is the same")
	} else {
		t := &taker{token: cfg.Token, st: st, alloc: alloc, say: lg.say}
		for i, d := range found {
			w, err := os.OpenFile("/dev/"+d.name, os.O_RDWR|oDirect|syscall.O_EXCL, 0)
			if err != nil {
				fail("disk %d of the new VM (%s) cannot be opened: %v", i+1, d.name, err)
			}
			r, err := os.OpenFile("/dev/"+d.name, os.O_RDONLY|oDirect, 0)
			if err != nil {
				fail("disk %d of the new VM (%s) cannot be opened to read it back: %v", i+1, d.name, err)
			}
			n, err := devBytes(w)
			if err != nil {
				fail("disk %d of the new VM (%s): %v", i+1, d.name, err)
			}
			t.disks, t.read, t.sizes = append(t.disks, w), append(t.read, io.ReaderAt(r)), append(t.sizes, n)
			lg.say("disk %d: %s, %d bytes", i+1, d.name, n)
		}
		ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", cfg.Port))
		if err != nil {
			fail("%v", err)
		}
		lg.say("waiting on %s port %d for the helper on the old host", id, cfg.Port)
		if err := t.serve(ln); err != nil {
			fail("%v", err)
		}
		for _, d := range t.disks {
			d.Sync()
		}
		syscall.Sync()
		lg.say("every disk was read back from its device and is the same as the original")
	}
	fmt.Println("envcold: " + st.line())
	halt()
}

// coldReport writes the status on the console: at once when the state
// changes, and every fifteen seconds otherwise.
func coldReport(st *coldStatus) {
	last, at := "", time.Time{}
	for {
		s := st.get()
		if s.State != last || time.Since(at) >= 15*time.Second {
			fmt.Println("envcold: " + st.line())
			last, at = s.State, time.Now()
		}
		time.Sleep(time.Second)
	}
}

// ── the QEMU guest agent's port ────────────────────────────────

func qgaPort() string {
	names, _ := filepath.Glob("/sys/class/virtio-ports/*/name")
	for _, n := range names {
		b, _ := os.ReadFile(n)
		if strings.TrimSpace(string(b)) == "org.qemu.guest_agent.0" {
			return "/dev/" + filepath.Base(filepath.Dir(n))
		}
	}
	return ""
}

// qgaServe answers the agent commands Proxmox sends to a VM whose agent
// option is on. guest-exec runs nothing: its output is this helper's status
// line and its last lines.
func qgaServe(st *coldStatus, lg *coldLog) {
	dev := ""
	for i := 0; i < 150 && dev == ""; i++ { // the port shows up when its driver has loaded
		if dev = qgaPort(); dev == "" {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if dev == "" {
		return
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0)
	if err != nil {
		lg.say("the agent port %s cannot be opened: %v", dev, err)
		return
	}
	outs, pid := map[int]string{}, 100
	answer := func(v any, mark bool) {
		b, _ := json.Marshal(v)
		if mark {
			b = append([]byte{0xFF}, b...)
		}
		f.Write(append(b, '\n'))
	}
	var pend []byte
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n == 0 || err != nil {
			time.Sleep(200 * time.Millisecond) // nobody is connected on the host's side
			continue
		}
		pend = append(pend, buf[:n]...)
		if len(pend) > 1<<20 {
			pend = nil
		}
		for {
			i := strings.IndexByte(string(pend), '\n')
			if i < 0 {
				break
			}
			line := strings.TrimSpace(strings.ReplaceAll(string(pend[:i]), "\xff", ""))
			pend = pend[i+1:]
			if line == "" {
				continue
			}
			var req struct {
				Execute   string `json:"execute"`
				Arguments struct {
					ID  json.Number `json:"id"`
					PID int         `json:"pid"`
				} `json:"arguments"`
			}
			if json.Unmarshal([]byte(line), &req) != nil {
				answer(map[string]any{"error": map[string]string{"class": "GenericError", "desc": "not JSON"}}, false)
				continue
			}
			switch req.Execute {
			case "guest-sync-delimited", "guest-sync":
				id, _ := req.Arguments.ID.Int64()
				answer(map[string]any{"return": id}, req.Execute == "guest-sync-delimited")
			case "guest-ping":
				answer(map[string]any{"return": map[string]any{}}, false)
			case "guest-info":
				var cmds []map[string]any
				for _, c := range []string{"guest-sync-delimited", "guest-sync", "guest-ping", "guest-info", "guest-exec", "guest-exec-status", "guest-shutdown"} {
					cmds = append(cmds, map[string]any{"name": c, "enabled": true, "success-response": c != "guest-shutdown"})
				}
				answer(map[string]any{"return": map[string]any{"version": "envmove-helper", "supported_commands": cmds}}, false)
			case "guest-exec":
				pid++
				outs[pid] = st.line() + "\n" + lg.tail() + "\n"
				if len(outs) > 64 {
					for k := range outs {
						if k < pid-32 {
							delete(outs, k)
						}
					}
				}
				answer(map[string]any{"return": map[string]any{"pid": pid}}, false)
			case "guest-exec-status":
				out, ok := outs[req.Arguments.PID]
				if !ok {
					answer(map[string]any{"error": map[string]string{"class": "GenericError", "desc": "no such process"}}, false)
					continue
				}
				answer(map[string]any{"return": map[string]any{"exited": true, "exitcode": 0,
					"out-data": base64.StdEncoding.EncodeToString([]byte(out))}}, false)
			case "guest-shutdown":
				// a person asked this helper to shut down: it holds nothing that
				// needs saving beyond what is already flushed
				lg.say("asked to shut down")
				syscall.Sync()
				syscall.Reboot(syscall.LINUX_REBOOT_CMD_POWER_OFF)
			default:
				answer(map[string]any{"error": map[string]string{"class": "CommandNotFound",
					"desc": "this is an EnvMap Move helper, not a system: it has no " + req.Execute}}, false)
			}
		}
	}
}
