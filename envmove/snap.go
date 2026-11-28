//go:build linux

package main

// The main path: the system's memory travels through this program instead of
// through a hibernation disk.
//
//	sender    envmove send -to HOST:PORT [-keep A,B] [-fix a,b] [-clock NAME]
//	receiver  envmove recv -listen :PORT [-addr IP/BITS -gw IP]
//
// The kernel offers the pieces through /dev/snapshot: freeze every other
// process, take an atomic picture of memory, read the picture out page by
// page; and on the other side, write the pages back and jump into them.
//
// What is ours is everything around that:
//
//   - the receiver is asked first, before anything is frozen;
//   - the picture is taken with no network card in it, then the card is
//     brought back only to carry the picture out, so the arriving system does
//     not believe in hardware that stayed behind;
//   - pages can be corrected while they travel (see patch.go);
//   - the sender is not gone when the picture has left. It waits, frozen, for a
//     verdict: "die" once the system is known to run on the other side, or
//     "thaw" to carry on as if nothing had happened.
//
// After the freeze only the program that asked for it runs, and of its
// threads only that one. That part is envmove-core (core/core.c), a separate
// program with one thread and no runtime, started from this one with a plan
// prepared here (see core.go). This file is everything before and around it:
// the pre-flight, the receiver's listener, and handing over.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
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
	snapFreeze        = 0x3301
	snapUnfreeze      = 0x3302
	snapAtomicRestore = 0x3304
	snapFree          = 0x3305
	snapCreateImage   = 0x40043311
	snapGetImageSize  = 0x8008330E

	offImagePages = 416 // pages of data in the stream
	offPages      = 424 // every page in the stream: header, page lists, data

	zeroPageFlag = uint64(1) << 63 // a listed page that is all zeros and so is not sent
	endOfList    = ^uint64(0)
)

func ioctl(fd int, req, arg uintptr) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, arg); e != 0 {
		return e
	}
	return nil
}

func out(s string) { syscall.Write(1, []byte(s)) }

func nap(ms int) {
	ts := syscall.Timespec{Sec: int64(ms / 1000), Nsec: int64(ms%1000) * 1e6}
	syscall.Nanosleep(&ts, nil)
}

func readFull(fd int, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := syscall.Read(fd, b[n:])
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return n, err
		}
		if k == 0 {
			return n, io.EOF
		}
		n += k
	}
	return n, nil
}

func writeFull(fd int, b []byte) error {
	for len(b) > 0 {
		k, err := syscall.Write(fd, b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		b = b[k:]
	}
	return nil
}

// ---- network cards, by the kernel's oldest interface: one small call each ----

type ifreq [40]byte

func (r *ifreq) name(n string) *ifreq { copy(r[:15], n); return r }

type netID struct {
	Name, MAC    string
	IP, Mask, GW [4]byte
}

func ifNameAt(s, idx int) string {
	var r ifreq
	binary.LittleEndian.PutUint32(r[16:], uint32(idx))
	if ioctl(s, 0x8910, uintptr(unsafe.Pointer(&r))) != nil {
		return ""
	}
	return string(r[:bytes.IndexByte(r[:16], 0)])
}

func ifMAC(s int, name string) string {
	var r ifreq
	if ioctl(s, 0x8927, uintptr(unsafe.Pointer(r.name(name)))) != nil {
		return ""
	}
	const hex = "0123456789abcdef"
	b := make([]byte, 0, 17)
	for i, c := range r[18:24] {
		if i > 0 {
			b = append(b, ':')
		}
		b = append(b, hex[c>>4], hex[c&15])
	}
	return string(b)
}

func ifByMAC(s int, mac string) string {
	for idx := 1; idx <= 256; idx++ {
		if n := ifNameAt(s, idx); n != "" && n != "lo" && ifMAC(s, n) == mac {
			return n
		}
	}
	return ""
}

func ifFirst(s int) string {
	for idx := 1; idx <= 256; idx++ {
		if n := ifNameAt(s, idx); n != "" && n != "lo" {
			return n
		}
	}
	return ""
}

func ifFlags(s int, name string, up bool) error {
	var r ifreq
	if err := ioctl(s, 0x8913, uintptr(unsafe.Pointer(r.name(name)))); err != nil {
		return err
	}
	f := binary.LittleEndian.Uint16(r[16:])
	if up {
		f |= 1
	} else {
		f &^= 1
	}
	binary.LittleEndian.PutUint16(r[16:], f)
	return ioctl(s, 0x8914, uintptr(unsafe.Pointer(&r)))
}

func ifGet(s int, name string, req uintptr) (a [4]byte) {
	var r ifreq
	if ioctl(s, req, uintptr(unsafe.Pointer(r.name(name)))) == nil {
		copy(a[:], r[20:24])
	}
	return
}

func ifSet(s int, name string, req uintptr, a [4]byte) error {
	var r ifreq
	r.name(name)
	binary.LittleEndian.PutUint16(r[16:], syscall.AF_INET)
	copy(r[20:24], a[:])
	return ioctl(s, req, uintptr(unsafe.Pointer(&r)))
}

func ifRename(s int, from, to string) error {
	var r ifreq
	r.name(from)
	copy(r[16:31], to)
	return ioctl(s, 0x8923, uintptr(unsafe.Pointer(&r)))
}

func routeDefault(s int, gw [4]byte) error {
	var rt [120]byte                                        // struct rtentry
	binary.LittleEndian.PutUint16(rt[8:], syscall.AF_INET)  // destination 0.0.0.0
	binary.LittleEndian.PutUint16(rt[24:], syscall.AF_INET) // gateway
	copy(rt[28:32], gw[:])
	binary.LittleEndian.PutUint16(rt[40:], syscall.AF_INET) // mask 0.0.0.0
	binary.LittleEndian.PutUint16(rt[56:], 1|2)             // up, via a gateway
	return ioctl(s, 0x890B, uintptr(unsafe.Pointer(&rt)))
}

// ifConfigure gives a card its address and default route.
func ifConfigure(s int, name string, id netID) error {
	if err := ifSet(s, name, 0x8916, id.IP); err != nil {
		return err
	}
	if err := ifSet(s, name, 0x891c, id.Mask); err != nil {
		return err
	}
	if err := ifFlags(s, name, true); err != nil {
		return err
	}
	if id.GW != [4]byte{} {
		if err := routeDefault(s, id.GW); err != nil && err != syscall.EEXIST {
			return err
		}
	}
	return nil
}

// viaCard, when set, is the address of the card that carries the move (a
// transfer card of its own) instead of the card of the default route.
var viaCard string

// afterLine, when set, is the new machine's transfer card, with which the
// arrived system tells the copy it left behind to power off (core.c, tellold).
var afterLine string

// cards is every network card the system has, by name and address: each is
// found again by its address on arrival and given its old name.
func cards() []netID {
	var out []netID
	dirs, _ := filepath.Glob("/sys/class/net/*")
	sort.Strings(dirs)
	for _, d := range dirs {
		if _, err := os.Stat(d + "/device"); err != nil {
			continue // loopback, bridges, tunnels: nothing on the bus
		}
		b, err := os.ReadFile(d + "/address")
		if err != nil {
			continue
		}
		mac := strings.TrimSpace(string(b))
		if len(mac) != 17 || mac == "00:00:00:00:00:00" {
			continue
		}
		out = append(out, netID{Name: filepath.Base(d), MAC: mac})
	}
	return out
}

// netIdentity is the card that carries the move: the transfer card named with
// -via, otherwise the card of the default route, as the system has it now.
func netIdentity() (netID, error) {
	if viaCard != "" {
		return viaIdentity(viaCard)
	}
	var id netID
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return id, err
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == "00000000" {
			id.Name = f[0]
			g, _ := strconv.ParseUint(f[2], 16, 32)
			binary.LittleEndian.PutUint32(id.GW[:], uint32(g))
			break
		}
	}
	if id.Name == "" {
		return id, errors.New("this system has no default route: cannot tell which network card to carry the image over")
	}
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return id, err
	}
	defer syscall.Close(s)
	id.MAC, id.IP, id.Mask = ifMAC(s, id.Name), ifGet(s, id.Name, 0x8915), ifGet(s, id.Name, 0x891b)
	return id, nil
}

// viaIdentity is the transfer card with this address: its name, address and
// mask, and the gateway of a route through it (a routed transfer network).
func viaIdentity(mac string) (netID, error) {
	var id netID
	mac = strings.ToLower(mac)
	for _, c := range cards() {
		if c.MAC == mac {
			id = c
		}
	}
	if id.Name == "" {
		return id, fmt.Errorf("no network card with address %s here (the transfer card)", mac)
	}
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return id, err
	}
	defer syscall.Close(s)
	id.IP, id.Mask = ifGet(s, id.Name, 0x8915), ifGet(s, id.Name, 0x891b)
	if id.IP == [4]byte{} {
		return id, fmt.Errorf("the transfer card %s has no IPv4 address", id.Name)
	}
	if b, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(line)
			if len(f) > 3 && f[0] == id.Name && f[2] != "00000000" {
				g, _ := strconv.ParseUint(f[2], 16, 32)
				binary.LittleEndian.PutUint32(id.GW[:], uint32(g))
				break
			}
		}
	}
	return id, nil
}

// ---- what the two sides say to each other before anything is frozen ----

type hello struct {
	Map     string   `json:"map"`
	Release string   `json:"release"`
	Flags   []string `json:"flags"`
	Removed string   `json:"removed,omitempty"` // ranges of the sender's memory taken out of use before the move
	// The disk controllers that stay attached through the move, as
	// "ADDRESS VENDOR:DEVICE CLASS": each must be at the same address on the
	// receiver, and be the same device (or, for NVMe and SATA, of the same
	// standard kind), or the arriving system would find another device under
	// a driver that believes in the old one.
	Keep []string `json:"keep,omitempty"`
	// Where the moving system will wait for its verdict (IP:PORT on its
	// transfer card): the receiver must be able to reach it.
	Verdict string `json:"verdict,omitempty"`
}

// answerProbes answers the receiver's "can you be reached?" on the verdict
// port while nothing is frozen. No verdict is taken here.
func answerProbes(l *net.TCPListener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		if strings.TrimSpace(line) == "ENVMOVEV?" {
			c.Write([]byte("ENVMOVEV!\n"))
		} else {
			c.Write([]byte("REFUSED\n"))
		}
		c.Close()
	}
}

// verdictReachable: can this receiver reach the moving system's verdict port?
func verdictReachable(addr string) error {
	c, err := net.DialTimeout("tcp4", addr, 4*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	c.Write([]byte("ENVMOVEV?\n"))
	line, err := bufio.NewReader(c).ReadString('\n')
	if strings.TrimSpace(line) != "ENVMOVEV!" {
		if err == nil {
			err = fmt.Errorf("it answered %q", strings.TrimSpace(line))
		}
		return err
	}
	return nil
}

// pciIdentity is "ADDRESS VENDOR:DEVICE CLASS" for a device on this machine.
func pciIdentity(addr string) string {
	rd := func(f string) string {
		b, _ := os.ReadFile("/sys/bus/pci/devices/" + addr + "/" + f)
		return strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")
	}
	return fmt.Sprintf("%s %s:%s %s", addr, rd("vendor"), rd("device"), rd("class"))
}

// keptHere says what is wrong with the kept controllers on this machine, if anything.
func keptHere(keep []string) []string {
	var bad []string
	for _, k := range keep {
		f := strings.Fields(k)
		if len(f) != 3 {
			continue
		}
		g := strings.Fields(pciIdentity(f[0]))
		switch {
		case len(g) < 3 || g[1] == ":":
			bad = append(bad, fmt.Sprintf("the disk controller %s (%s) the system keeps through the move is not at %s here", f[1], f[2], f[0]))
		case g[1] == f[1]:
			// the same device at the same address
		case f[2] == g[2] && (f[2] == "010802" || f[2] == "010601"):
			// another maker's NVMe or SATA controller: the same standard interface
		default:
			bad = append(bad, fmt.Sprintf("at %s the system keeps a disk controller %s (%s); here it is %s (%s)", f[0], f[1], f[2], g[1], g[2]))
		}
	}
	return bad
}

// removedRanges is what the sender took out of use (receiver side, from its hello).
var removedRanges []region

// without returns the memory ranges of m with the ranges in cut taken out.
func without(m, cut []region) []region {
	var out []region
	for _, r := range m {
		pieces := []region{r}
		for _, c := range cut {
			var next []region
			for _, p := range pieces {
				if p.Type != 1 || c.End < p.Start || c.Start > p.End {
					next = append(next, p)
					continue
				}
				if c.Start > p.Start {
					next = append(next, region{p.Start, c.Start - 1, p.Type})
				}
				if c.End < p.End {
					next = append(next, region{c.End + 1, p.End, p.Type})
				}
			}
			pieces = next
		}
		out = append(out, pieces...)
	}
	return out
}

// takeOutOfUse asks the kernel to stop using these pages: it moves what is in
// them elsewhere and never hands them out again ("soft offline"). A page out
// of use is not saved in the memory image either, so the receiver need not
// have memory there.
func takeOutOfUse(gaps []region) error {
	for _, g := range gaps {
		for a := g.Start &^ (page - 1); a <= g.End; a += page {
			if err := os.WriteFile("/sys/devices/system/memory/soft_offline_page", []byte(fmt.Sprintf("%#x", a)), 0o200); err != nil {
				return fmt.Errorf("the page at %#x cannot be taken out of use here: %w", a, err)
			}
		}
	}
	return nil
}

// errGaps is a refusal for no other reason than memory the receiver does not have.
type errGaps struct{ gaps []region }

func (e errGaps) Error() string {
	return "the receiver refuses this system; nothing was frozen"
}

func release() string {
	var u syscall.Utsname
	syscall.Uname(&u)
	var b []byte
	for _, c := range u.Release {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

func cpuFlags() []string {
	b, _ := os.ReadFile("/proc/cpuinfo")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "flags") {
			f := strings.Fields(line[strings.Index(line, ":")+1:])
			sort.Strings(f)
			return f
		}
	}
	return nil
}

// noMessageInterrupts lists the disk and network devices here that can only
// raise interrupts the old way. The arriving system cannot route those on a
// changed chipset, so such a device would be dead after the move.
func noMessageInterrupts() []string {
	var bad []string
	devs, _ := pciList()
	for _, d := range devs {
		c, err := os.ReadFile(pciRoot + "/" + d.Addr + "/config")
		if err != nil || len(c) < 64 || (c[0x0b] != 1 && c[0x0b] != 2) {
			continue
		}
		found := false
		if c[0x06]&0x10 != 0 {
			for p, hops := int(c[0x34])&^3, 0; p >= 0x40 && p+1 < len(c) && hops < 48; p, hops = int(c[p+1])&^3, hops+1 {
				if c[p] == 0x05 || c[p] == 0x11 {
					found = true
					break
				}
			}
		}
		if !found {
			kind := map[byte]string{1: "disk controller", 2: "network card"}[c[0x0b]]
			bad = append(bad, fmt.Sprintf("%s (%s %s)", d.Addr, kind, d.Live))
		}
	}
	return bad
}

// driverNames lists, for every device here, the name the kernel's module
// loader knows its driver by. The sender loads those drivers before it leaves,
// while it can still read its own disk; on arrival the devices then simply work.
func driverNames() []string {
	var out []string
	devs, _ := pciList()
	for _, d := range devs {
		dir := pciRoot + "/" + d.Addr
		if a, err := os.ReadFile(dir + "/modalias"); err == nil {
			out = append(out, strings.TrimSpace(string(a)))
		}
		// A virtio device shows its real kind one level down, which only exists
		// once the virtio bus driver is loaded. Work it out from the PCI numbers.
		var vendor, device, sub uint64
		fmt.Sscanf(d.Live, "%x:%x", &vendor, &device)
		if vendor != 0x1af4 {
			continue
		}
		kind := device - 0x1040
		if device < 0x1040 {
			b, _ := os.ReadFile(dir + "/subsystem_device")
			sub, _ = strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 32)
			kind = sub
		}
		out = append(out, fmt.Sprintf("virtio:d%08Xv%08X", kind, vendor))
	}
	return out
}

// powerOffCodes reads, from this machine's own ACPI program, the two numbers
// that ask it to power off (the \_S5 package). It only reads the table as
// data; nothing is executed.
func powerOffCodes() (a, b byte, ok bool) {
	d, err := os.ReadFile("/sys/firmware/acpi/tables/DSDT")
	if err != nil {
		return 0, 0, false
	}
	for i := bytes.Index(d, []byte("_S5_")); i > 0 && i+12 < len(d); {
		p := i + 4
		if (d[i-1] == 0x08 || (i > 1 && d[i-1] == 0x5c && d[i-2] == 0x08)) && d[p] == 0x12 { // a Name holding a Package
			p += 1 + 1 + int(d[p+1]>>6) // the package opcode and its length bytes
			p++                         // the element count
			val := func() (byte, bool) {
				if p >= len(d) {
					return 0, false
				}
				switch d[p] {
				case 0x00, 0x01: // Zero, One
					p++
					return d[p-1], true
				case 0x0a: // a byte constant
					p += 2
					return d[p-1], p <= len(d)
				}
				return 0, false
			}
			if a, ok = val(); ok {
				if b, ok = val(); ok {
					return a, b, true
				}
			}
		}
		j := bytes.Index(d[i+4:], []byte("_S5_"))
		if j < 0 {
			break
		}
		i += 4 + j
	}
	return 0, 0, false
}

// judge is the receiver's answer to "may this system come here?".
func judge(h hello, here []region) (lines []string, ok bool) {
	ok = true
	from, err := parseMap(h.Map)
	if err != nil {
		return []string{"cannot read the sender's memory map: " + err.Error()}, false
	}
	if h.Removed != "" {
		cut, err := parseMap(h.Removed)
		if err != nil {
			return []string{"cannot read the ranges the sender took out of use: " + err.Error()}, false
		}
		from = without(from, cut)
		lines = append(lines, fmt.Sprintf("memory: the sender took %d range(s) out of use first", len(cut)))
	}
	if gaps := uncovered(from, here); len(gaps) > 0 {
		for _, g := range gaps {
			lines = append(lines, fmt.Sprintf("memory the sender uses that is not memory here: %x-%x (%d KiB)", g.Start, g.End, (g.End-g.Start+1)>>10))
		}
		ok = false
	} else {
		lines = append(lines, "memory: every range the sender uses is memory here")
	}
	if h.Verdict != "" {
		if err := verdictReachable(h.Verdict); err != nil {
			lines = append(lines, fmt.Sprintf("network: this receiver cannot reach the moving system's verdict port %s (%v): a firewall there? Once frozen, the system could not be told anything", h.Verdict, err))
			ok = false
		} else {
			lines = append(lines, "network: the moving system's verdict port answers from here")
		}
	}
	if bad := keptHere(h.Keep); len(bad) > 0 {
		for _, b := range bad {
			lines = append(lines, "disks: "+b)
		}
		ok = false
	} else if len(h.Keep) > 0 {
		lines = append(lines, fmt.Sprintf("disks: the %d controller(s) kept through the move are the same here", len(h.Keep)))
	}
	if r := release(); r != h.Release {
		lines = append(lines, fmt.Sprintf("kernel: the sender runs %s, this receiver runs %s; they must be the same build", h.Release, r))
		ok = false
	}
	mine := map[string]bool{}
	for _, f := range cpuFlags() {
		mine[f] = true
	}
	var missing []string
	for _, f := range h.Flags {
		if !mine[f] {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		lines = append(lines, "processor: the sender uses features this machine does not offer: "+strings.Join(missing, " "))
		ok = false
	} else {
		lines = append(lines, fmt.Sprintf("processor: all %d features the sender sees are offered here", len(h.Flags)))
	}
	for _, a := range driverNames() {
		lines = append(lines, "MODALIAS="+a) // what this machine's devices ask a driver to answer to
	}
	if d, err := os.ReadFile("/sys/firmware/acpi/tables/DSDT"); err == nil {
		lines = append(lines, fmt.Sprintf("DSDT=%x", sha256.Sum256(d))) // to tell whether this is the same platform
	}
	if a, b, ok := powerOffCodes(); ok {
		lines = append(lines, fmt.Sprintf("S5=%d,%d", a, b)) // what this machine wants written to power off
	}
	if b, err := os.ReadFile("/sys/firmware/acpi/tables/FACP"); err == nil {
		lines = append(lines, fmt.Sprintf("FADT=%x", b)) // this machine's ACPI register addresses, for the acpiports fix
	}
	lines = append(lines, fmt.Sprintf("FDC=%d", floppyControllers())) // a floppy controller here (ISA, announced by ACPI)
	if kvmGuest() {
		lines = append(lines, "KVM=1") // this hypervisor is KVM: KVM's shortcuts keep working here
	} else {
		lines = append(lines, "KVM=0")
	}
	if bad := noMessageInterrupts(); len(bad) > 0 {
		lines = append(lines, "warning: these devices here have no message interrupts and will not work for the arriving system: "+strings.Join(bad, ", "))
	}
	return lines, ok
}

// targetFADT is the receiving machine's ACPI description table, as it sent it,
// and targetDrivers the names its devices ask a driver to answer to.
var (
	targetFADT    []byte
	targetDrivers []string
	targetS5      []byte // the receiver's two power-off codes
	targetDSDT    string // a fingerprint of the receiver's ACPI program
	targetKVM     bool   // the receiver runs on KVM too
)

func preflight(to string, h hello) error {
	c, err := net.Dial("tcp", to)
	if err != nil {
		return fmt.Errorf("the receiver at %s does not answer: %w", to, err)
	}
	defer c.Close()
	b, _ := json.Marshal(h)
	if _, err := c.Write(append(append(kindAndToken("ENVMOVEP"), b...), '\n')); err != nil {
		return err
	}
	sc := bufio.NewScanner(c)
	var gaps []region
	other := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "memory the sender uses that is not memory here: ") {
			var a, b uint64
			if _, err := fmt.Sscanf(strings.TrimPrefix(line, "memory the sender uses that is not memory here: "), "%x-%x", &a, &b); err == nil {
				gaps = append(gaps, region{a, b, 1})
			}
		}
		if strings.HasPrefix(line, "kernel: ") || strings.HasPrefix(line, "processor: the sender uses") || strings.HasPrefix(line, "cannot read") ||
			(strings.HasPrefix(line, "disks: ") && !strings.Contains(line, "are the same here")) ||
			strings.HasPrefix(line, "network: this receiver cannot reach") {
			other = true
		}
		switch line {
		case "OK":
			return nil
		case "REFUSE":
			if len(gaps) > 0 && !other {
				return errGaps{gaps}
			}
			return errors.New("the receiver refuses this system; nothing was frozen")
		default:
			if strings.HasPrefix(line, "FADT=") {
				targetFADT, _ = hex.DecodeString(line[5:])
				continue
			}
			if strings.HasPrefix(line, "MODALIAS=") {
				targetDrivers = append(targetDrivers, line[9:])
				continue
			}
			if strings.HasPrefix(line, "KVM=") {
				targetKVM = line == "KVM=1"
				continue
			}
			if strings.HasPrefix(line, "FDC=") {
				targetFDC = line[4:]
				continue
			}
			if strings.HasPrefix(line, "DSDT=") {
				targetDSDT = line[5:]
				continue
			}
			if strings.HasPrefix(line, "S5=") {
				var a, b int
				if n, _ := fmt.Sscanf(line, "S5=%d,%d", &a, &b); n == 2 {
					targetS5 = []byte{byte(a), byte(b)}
				}
				continue
			}
			fmt.Println("receiver:", line)
		}
	}
	return errors.New("the receiver hung up without an answer; nothing was frozen")
}

// targetFDC is what the receiver said about a floppy controller: "0", "1",
// or "" when it did not say (an older receiver).
var targetFDC string

// floppyControllers counts the floppy controllers the firmware announces.
func floppyControllers() int {
	n := 0
	ids, _ := filepath.Glob("/sys/bus/pnp/devices/*/id")
	for _, f := range ids {
		if b, err := os.ReadFile(f); err == nil && strings.Contains(string(b), "PNP0700") {
			n++
		}
	}
	return n
}

// floppyToDrop: the receiver has no floppy controller and this system has a
// floppy drive whose driver is a module, so it can be unloaded on arrival.
func floppyToDrop() bool {
	if targetFDC != "0" {
		return false
	}
	if _, err := os.Stat("/sys/block/fd0"); err != nil {
		return false
	}
	_, err := os.Stat("/sys/module/floppy/initstate")
	return err == nil
}

// afterArrival tidies what the old machine had and this one has not, once the
// system runs here. A floppy controller is not on a bus the kernel looks at
// again: the drive stays known after the move and every read of it fails, so
// its driver is unloaded when the new machine has none.
func afterArrival() {
	if targetFDC != "0" {
		return
	}
	if _, err := os.Stat("/sys/block/fd0"); err != nil {
		return
	}
	if _, err := os.Stat("/sys/module/floppy/initstate"); err != nil {
		fmt.Println("devices: the old machine's floppy drive stays known here (its driver is built into the kernel); reading it fails")
		return
	}
	for i := 0; i < 10; i++ {
		if kmodCmd("rmmod", "floppy").Run() == nil {
			fmt.Println("devices: the old machine had a floppy drive and this one has none: its driver was unloaded")
			return
		}
		nap(1000)
	}
	fmt.Println("devices: the floppy driver of the old machine is in use and stays loaded")
}

// moveToken is what every connection to the receiver carries after its kind
// (the -boottoken of the move); rxToken is what this receiver expects, empty
// for a receiver started by hand in the lab, which takes any.
var moveToken, rxToken string

// kindAndToken is the start of a connection to the receiver.
func kindAndToken(kind string) []byte {
	t := moveToken
	if len(t) > 255 {
		t = t[:255]
	}
	return append(append([]byte(kind), byte(len(t))), t...)
}

// tokenOK reads the token after a connection's kind and says whether it is
// this move's. A receiver with no token of its own takes any.
func tokenOK(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var n [1]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return false
	}
	got := make([]byte, int(n[0]))
	if _, err := io.ReadFull(c, got); err != nil {
		return false
	}
	return rxToken == "" || subtle.ConstantTimeCompare(got, []byte(rxToken)) == 1
}

// errSaid is returned when the failure has already been printed.
var errSaid = errors.New("")

// errDied is returned by alone when the single-threaded part did not end by itself.
var errDied = errors.New("")

// chooseFixes decides which corrections this move needs, from what the two
// machines said about themselves.
func chooseFixes(kept []string) []string {
	var f []string
	for _, a := range kept {
		// A SCSI controller that stays attached is reset on arrival; the kernel's
		// ten-second wait after that reset is shortened in transit.
		if hs, _ := filepath.Glob(pciRoot + "/" + a + "/host*"); len(hs) > 0 {
			f = append(f, "settle")
			break
		}
		if hs, _ := filepath.Glob(pciRoot + "/" + a + "/*/host*"); len(hs) > 0 { // virtio: the host hangs one level down
			f = append(f, "settle")
			break
		}
	}
	if _, err := os.Stat("/sys/firmware/efi"); err == nil {
		// Started by UEFI firmware: its boot notes and its runtime services stay behind.
		f = append(f, "bootdata", "efioff")
	}
	mine := ""
	if d, err := os.ReadFile("/sys/firmware/acpi/tables/DSDT"); err == nil {
		mine = fmt.Sprintf("%x", sha256.Sum256(d))
	}
	if mine == "" || targetDSDT != mine {
		// Another platform's ACPI program on the other side: stop running ours, take its addresses.
		f = append(f, "acpioff", "acpiports")
	}
	if kvmGuest() && !targetKVM {
		// Started on KVM, landing elsewhere: KVM's shortcuts have to go.
		f = append(f, "kvm")
	}
	if len(f) == 0 {
		fmt.Println("in transit: nothing to correct, the receiver is the same platform")
	}
	return f
}

// ---- sender ----

func send(to string, keep []string, fixes []string, clock string, repoint, copyd, ahead bool) error {
	here, err := readMemmap()
	if err != nil {
		return err
	}
	tcp, err := net.ResolveTCPAddr("tcp4", to)
	if err != nil {
		return err
	}
	id, err := netIdentity()
	if err != nil {
		return err
	}
	h := hello{Map: formatMap(here), Release: release(), Flags: cpuFlags()}
	// The verdict port is opened now, while nothing is frozen: a port that
	// cannot be had stops the move here, not after the image has left. The
	// receiver is asked to reach it too (a firewall in the way would leave
	// nobody able to tell this system anything once it is frozen).
	var vln *net.TCPListener
	if verdictListen > 0 {
		l, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: verdictListen})
		if err != nil {
			return fmt.Errorf("cannot wait for the verdict on port %d: %w; nothing was frozen", verdictListen, err)
		}
		vln = l
		defer func() {
			if vln != nil {
				vln.Close()
			}
		}()
		go answerProbes(l)
		if viaCard != "" {
			h.Verdict = fmt.Sprintf("%d.%d.%d.%d:%d", id.IP[0], id.IP[1], id.IP[2], id.IP[3], verdictListen)
		}
	}
	if !repoint {
		for _, k := range keep {
			h.Keep = append(h.Keep, pciIdentity(k))
		}
	}
	if err := preflight(to, h); err != nil {
		g, ok := err.(errGaps)
		if !ok {
			return err
		}
		// A few pages here are not memory there (firmware keeps different
		// places for itself). Taken out of use here, they are not in the image.
		var total uint64
		for _, r := range g.gaps {
			total += r.End - r.Start + 1
		}
		if total > 64<<20 {
			return fmt.Errorf("%d MiB of this system's memory is not memory on the receiver; nothing was frozen", total>>20)
		}
		if err := takeOutOfUse(g.gaps); err != nil {
			return fmt.Errorf("%w; nothing was frozen", err)
		}
		fmt.Printf("memory: %d KiB here is not memory on the receiver; taken out of use here first\n", total>>10)
		h.Removed = formatMap(g.gaps)
		if err := preflight(to, h); err != nil {
			return err
		}
	}
	if len(targetDrivers) > 0 {
		before, _ := os.ReadFile("/proc/modules")
		for _, a := range targetDrivers {
			modprobeCmd("-q", "-b", a).Run()
		}
		after, _ := os.ReadFile("/proc/modules")
		fmt.Printf("drivers for the receiver's %d devices asked for in advance; %d modules newly loaded\n",
			len(targetDrivers), bytes.Count(after, []byte("\n"))-bytes.Count(before, []byte("\n")))
	}
	var plan *storagePlan
	var stay []string // with re-pointing: the controllers that stay attached all the way
	if repoint {
		if plan, err = planStorage(keep); err != nil {
			return err
		}
		stay = keep
		keep = append(append([]string(nil), keep...), plan.controllers()...) // those are let go later, once the mappings are held
		fmt.Printf("storage: %d mappings will be held and re-pointed, %d plain mounts taken off and put back, resting on %d devices\n",
			len(plan.maps), len(plan.mounts), len(plan.leaves))
	}
	if len(fixes) == 1 && fixes[0] == "auto" {
		kept := keep
		if repoint {
			kept = stay
		}
		fixes = chooseFixes(kept)
	}
	ps, err := resolveFixes(fixes, targetFADT, targetS5)
	if err != nil {
		return err
	}
	for _, n := range ps.notes {
		fmt.Println("in transit:", n)
	}
	if clock != "" {
		if err := os.WriteFile("/sys/devices/system/clocksource/clocksource0/current_clocksource", []byte(clock), 0o644); err != nil {
			return fmt.Errorf("cannot switch the clock to %s: %w", clock, err)
		}
		fmt.Println("clock source switched to", clock)
	}
	snap, err := syscall.Open("/dev/snapshot", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("/dev/snapshot: %w (this kernel does not offer the snapshot device, or hibernation is locked)", err)
	}
	var ds *diskSession
	var extra []int
	if copyd {
		// The disks go first, while the system runs. The network card then stays
		// until the frozen part has sent the last changes; it lets go of it itself.
		if ds, err = copyDisks(to); err != nil {
			syscall.Close(snap)
			return err
		}
		if !repoint {
			stay = append([]string(nil), keep...)
		}
		if nic, err := pciOf("/sys/class/net/" + id.Name + "/device"); err == nil {
			keep = append(keep, nic)
		}
		// Every other card too: the frozen part lets go of them, so the system
		// keeps its network until the moment it freezes.
		for _, c := range cards() {
			if a, err := pciOf("/sys/class/net/" + c.Name + "/device"); err == nil && c.Name != id.Name {
				keep = append(keep, a)
			}
		}
		// The copied disks too: the frozen part reads their last changes, then lets go of them.
		for _, t := range ds.tracers {
			if t.disk.Slot != "" {
				keep = append(keep, t.disk.Slot)
			}
		}
		f, err := ds.conn.(*net.TCPConn).File()
		if err != nil {
			ds.stop()
			syscall.Close(snap)
			return err
		}
		extra = append(extra, int(f.Fd()))
		defer f.Close()
	}
	var pre *presend
	if ahead {
		// Memory last: it changes fastest.
		if pre, err = sendAhead(to); err != nil {
			syscall.Close(snap)
			if ds != nil {
				ds.stop()
			}
			return err
		}
		defer pre.close()
	}
	core := leavePlan(id, tcp.IP.To4().String(), tcp.Port, ps, plan, stay)
	if ds != nil {
		core = append(core, []byte(ds.planLines()+"letgo\n")...)
	}
	if pre != nil {
		fd, err := syscall.Dup(int(pre.tableF.Fd()))
		if err != nil {
			syscall.Close(snap)
			return err
		}
		core = append(core, []byte(pre.planLine(6+len(extra)))...)
		extra = append(extra, fd)
	}
	if err := letGo(keep); err != nil {
		syscall.Close(snap)
		if ds != nil {
			ds.stop()
		}
		os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0o200)
		return err
	}
	// If the frozen part is killed outright, the kernel thaws the system, and
	// this process, which wakes with it, puts the storage back. It may have to
	// do that with the root filesystem still held: nothing of it may be read
	// from disk then, so its memory is pinned and its working directory moved
	// into memory now (see core/core.c, leave, for why).
	syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE)
	if syscall.Chdir("/sys") != nil {
		syscall.Chdir("/proc")
	}
	if ds != nil {
		ds.release()
	}
	if vln != nil {
		// The frozen part takes the verdict on this same socket; this process
		// lets go of its own handle on it.
		f, ferr := vln.File()
		if ferr != nil {
			syscall.Close(snap)
			os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0o200)
			return ferr
		}
		fd, derr := syscall.Dup(int(f.Fd()))
		f.Close()
		if derr != nil {
			syscall.Close(snap)
			os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0o200)
			return derr
		}
		core = append(core, []byte(fmt.Sprintf("vfd %d\n", 6+len(extra)))...)
		extra = append(extra, fd)
		vln.Close()
		vln = nil
	}
	err = runCore("leave", snap, core, extra...)
	if err != nil {
		// Whatever was let go of before the failure comes back.
		os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0o200)
	}
	if ds != nil {
		// Wherever this system now runs, the write tracing ends here, on the
		// disks that are still there.
		var names []string
		for _, t := range ds.tracers {
			names = append(names, t.disk.Name)
		}
		stopTracing(names)
	}
	if err == errDied && plan != nil {
		out("storage: putting back what the frozen part was holding\n")
		os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0o200)
		if e := plan.release(); e != nil {
			out("storage: " + e.Error() + "\n")
		}
		err = errSaid
	}
	return err
}

// ---- receiver ----

func parseCIDR(s string) (ip, mask [4]byte, err error) {
	a, n, err := net.ParseCIDR(s)
	if err != nil {
		return ip, mask, err
	}
	copy(ip[:], a.To4())
	copy(mask[:], n.Mask)
	return ip, mask, nil
}

func recv(listen, addr, gw string, force, hold bool) error {
	here, err := readMemmap()
	if err != nil {
		return err
	}
	if addr != "" {
		var id netID
		if id.IP, id.Mask, err = parseCIDR(addr); err != nil {
			return err
		}
		if gw != "" {
			copy(id.GW[:], net.ParseIP(gw).To4())
		}
		ctl, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		name := ""
		for i := 0; i < 100 && name == ""; i++ {
			if name = ifFirst(ctl); name == "" {
				nap(100)
			}
		}
		if name == "" {
			return errors.New("no network card here: load its driver first")
		}
		if err := ifConfigure(ctl, name, id); err != nil {
			return fmt.Errorf("configuring %s: %w", name, err)
		}
		syscall.Close(ctl)
		fmt.Printf("network: %s is %s\n", name, addr)
	}
	ownDrivers()
	ln, err := net.Listen("tcp4", listen)
	if err != nil {
		return err
	}
	fmt.Println("RECEIVER READY on", listen)
	var from []region
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		var kind [8]byte
		if _, err := io.ReadFull(c, kind[:]); err != nil {
			c.Close()
			continue
		}
		if !tokenOK(c) {
			fmt.Println("refused a connection without this move's token from", c.RemoteAddr())
			c.Close()
			continue
		}
		switch string(kind[:]) {
		case "ENVMOVEP":
			line, _ := bufio.NewReader(c).ReadBytes('\n')
			var h hello
			if json.Unmarshal(line, &h) != nil {
				c.Close()
				continue
			}
			lines, ok := judge(h, here)
			for _, l := range lines {
				if !strings.HasPrefix(l, "FADT=") && !strings.HasPrefix(l, "MODALIAS=") && !strings.HasPrefix(l, "S5=") && !strings.HasPrefix(l, "DSDT=") && !strings.HasPrefix(l, "KVM=") {
					fmt.Println("pre-flight:", l)
				}
				fmt.Fprintln(c, l)
			}
			if ok || force {
				from, _ = parseMap(h.Map)
				removedRanges = nil
				if h.Removed != "" {
					removedRanges, _ = parseMap(h.Removed)
				}
				fmt.Fprintln(c, "OK")
			} else {
				fmt.Fprintln(c, "REFUSE")
			}
			c.Close()
		case "ENVMOVEQ": // are you there?
			c.Write([]byte("READY\n"))
			c.Close()
		case "ENVMOVED":
			go takeDisks(c, bufio.NewReader(c))
		case "ENVMOVEM":
			go takeMemory(c, bufio.NewReader(c))
		case "ENVMOVE1", "ENVMOVE2":
			if string(kind[:]) == "ENVMOVE2" && !(memIn.started && memIn.done) {
				c.Close()
				fmt.Println("image refused: it relies on memory sent ahead, and that did not arrive")
				continue
			}
			if disksIn.started && !disksIn.final {
				c.Close()
				fmt.Println("image refused: the disk copy is not final")
				continue
			}
			if disksIn.err != nil {
				c.Close()
				return fmt.Errorf("the disks here could not be written (%v); the image is refused", disksIn.err)
			}
			if from == nil {
				c.Close()
				return errors.New("an image arrived before any pre-flight; refused")
			}
			format := 1
			if string(kind[:]) == "ENVMOVE2" {
				format = 2
			}
			return restore(c, from, here, force, hold, format)
		default:
			c.Close()
		}
	}
}

func restore(c net.Conn, from, here []region, force, hold bool, format int) error {
	var n [8]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return err
	}
	total := binary.LittleEndian.Uint64(n[:])
	var nc [4]byte
	if _, err := io.ReadFull(c, nc[:]); err != nil {
		return err
	}
	var clocks []byte
	if k := binary.LittleEndian.Uint32(nc[:]); k > 0 {
		if k > 4096 {
			return errors.New("the image names too many clock records")
		}
		clocks = make([]byte, 16*k)
		if _, err := io.ReadFull(c, clocks); err != nil {
			return err
		}
	}
	header := make([]byte, page)
	if _, err := io.ReadFull(c, header); err != nil {
		return fmt.Errorf("the image header did not arrive: %w", err)
	}
	// Nothing is frozen yet: a header that does not fit this machine is refused
	// before the system is touched.
	if _, err := adjustHeader(header, from, here, force); err != nil {
		return err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return errors.New("the image did not arrive over TCP")
	}
	f, err := tc.File() // a plain blocking copy of the connection, for the frozen part
	if err != nil {
		return err
	}
	sock := int(f.Fd())
	snap, err := syscall.Open("/dev/snapshot", syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("/dev/snapshot: %w", err)
	}
	h := 0
	if hold {
		h = 1
	}
	conn, err := syscall.Dup(sock)
	if err != nil {
		return err
	}
	plan := fmt.Sprintf("total %d\nhold %d\nheader %x\n", total, h, header)
	if len(clocks) > 0 {
		hz := tscHz()
		if hz == 0 {
			return errors.New("the arriving system keeps KVM's clock, and this machine's counter frequency is unknown; refused")
		}
		mul, shift := timeScale(hz)
		plan += fmt.Sprintf("pvtime %d %d\n", mul, int(shift)+128)
		for i := 0; i+16 <= len(clocks); i += 16 {
			plan += fmt.Sprintf("pvclock %d %d\n", binary.LittleEndian.Uint64(clocks[i:]), binary.LittleEndian.Uint32(clocks[i+8:]))
		}
		fmt.Printf("clock: %d KVM clock records will describe this machine's counter (%d Hz)\n", len(clocks)/16, hz)
	}
	extra := []int{conn}
	if format == 2 {
		ix, err1 := syscall.Dup(int(memIn.indexF.Fd()))
		sl, err2 := syscall.Dup(int(memIn.slotsF.Fd()))
		if err1 != nil || err2 != nil {
			return errors.New("cannot hand over the memory sent ahead")
		}
		plan += fmt.Sprintf("format 2\npresend 7 %d\npreslots 8\n", memIn.maxPFN)
		extra = append(extra, ix, sl)
	}
	err = runCore("restore", snap, []byte(plan), extra...)
	f.Close()
	return err
}
