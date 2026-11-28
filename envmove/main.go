//go:build linux

// envmove is the engine of EnvMap Move: it moves a running Linux system to
// another virtual machine, on another hypervisor, without stopping it. It runs
// inside the guest as root and has no dependencies; EnvMap copies it in,
// starts it, and builds the receiver CD the new machine starts from (the
// image carries it at /opt/envmove, see the Dockerfile and app/vmmove.py).
//
//	envmove memmap                     print this system's firmware memory map
//	envmove rekexec -map M [...]       restart this kernel with memory map M
//	envmove pci                        devices: remembered id, id answering now, driver
//	envmove letgo [-keep A,B]          detach every device that has a driver
//	envmove refresh                    drop devices that changed, discover again
//	envmove kick                       reset the disk controllers that stayed attached
//	envmove fits -from M               could a system with memory map M be received here?
//	envmove imgfix -dev D -from M      make a sender's image acceptable to this kernel
//	envmove send -to HOST:PORT         leave: stream this running system to a receiver
//	envmove recv -listen :PORT         wait for a system and become it
//
// send and recv are the main path (snap.go, patch.go). letgo, imgfix, kick and
// refresh are the same steps done by hand around the kernel's own hibernation,
// which is the fallback path the first lab rounds used.
//
// The memory map matters because a kernel only accepts an image whose firmware
// memory map is byte-identical to its own. A receiving VM on another
// hypervisor never has the same map, so the receiver proves the image fits and
// then adjusts the image's header (image.go).
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
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

type region struct {
	Start, End uint64 // End is inclusive, as the kernel prints it
	Type       uint32
}

// names the kernel gives firmware map entries in /sys/firmware/memmap, in
// lower case: old kernels write "reserved", newer ones "Reserved"
var typeByName = map[string]uint32{
	"system ram":                 1,
	"reserved":                   2,
	"acpi tables":                3,
	"acpi non-volatile storage":  4,
	"unusable memory":            5,
	"persistent memory":          7,
	"persistent memory (legacy)": 12,
}

func readMemmap() ([]region, error) {
	dirs, err := filepath.Glob("/sys/firmware/memmap/[0-9]*")
	if err != nil || len(dirs) == 0 {
		return nil, errors.New("no /sys/firmware/memmap: this kernel does not expose its firmware memory map")
	}
	sort.Slice(dirs, func(i, j int) bool {
		a, _ := strconv.Atoi(filepath.Base(dirs[i]))
		b, _ := strconv.Atoi(filepath.Base(dirs[j]))
		return a < b
	})
	var out []region
	for _, d := range dirs {
		rd := func(f string) string {
			b, _ := os.ReadFile(filepath.Join(d, f))
			return strings.TrimSpace(string(b))
		}
		s, err1 := strconv.ParseUint(strings.TrimPrefix(rd("start"), "0x"), 16, 64)
		e, err2 := strconv.ParseUint(strings.TrimPrefix(rd("end"), "0x"), 16, 64)
		t, ok := typeByName[strings.ToLower(rd("type"))]
		if err1 != nil || err2 != nil || !ok {
			return nil, fmt.Errorf("%s: cannot read entry (type %q)", d, rd("type"))
		}
		out = append(out, region{s, e, t})
	}
	return out, nil
}

func formatMap(m []region) string {
	parts := make([]string, len(m))
	for i, r := range m {
		parts[i] = fmt.Sprintf("%x-%x:%d", r.Start, r.End, r.Type)
	}
	return strings.Join(parts, ",")
}

func parseMap(s string) ([]region, error) {
	var out []region
	for _, p := range strings.Split(s, ",") {
		var r region
		if _, err := fmt.Sscanf(p, "%x-%x:%d", &r.Start, &r.End, &r.Type); err != nil || r.End < r.Start {
			return nil, fmt.Errorf("bad map entry %q", p)
		}
		out = append(out, r)
	}
	if len(out) == 0 || len(out) > 128 {
		return nil, fmt.Errorf("a boot memory map holds 1 to 128 entries, got %d", len(out))
	}
	return out, nil
}

const page = 4096

func up(v, a uint64) uint64   { return (v + a - 1) &^ (a - 1) }
func down(v, a uint64) uint64 { return v &^ (a - 1) }

// covered reports whether [start, start+size) lies inside one usable region.
func covered(m []region, start, size uint64) bool {
	for _, r := range m {
		if r.Type == 1 && start >= r.Start && start+size-1 <= r.End {
			return true
		}
	}
	return false
}

type segment struct {
	buf   unsafe.Pointer
	bufsz uintptr
	mem   uintptr
	memsz uintptr
}

func padded(b []byte) []byte {
	out := make([]byte, up(uint64(len(b)), page))
	copy(out, b)
	return out
}

func rekexec(mapArg, kernelPath, cmdline string, initrds []string, dry bool) error {
	target, err := parseMap(mapArg)
	if err != nil {
		return err
	}
	// Every address used below must be RAM both for the kernel that is running
	// now (it copies the segments there) and in the map the next kernel gets.
	mine, err := readMemmap()
	if err != nil {
		return err
	}
	both := func(start, size uint64) bool { return covered(target, start, size) && covered(mine, start, size) }

	k, err := os.ReadFile(kernelPath)
	if err != nil {
		return err
	}
	if len(k) < 0x270 || string(k[0x202:0x206]) != "HdrS" {
		return errors.New("not a Linux bzImage")
	}
	le := binary.LittleEndian
	if ver := le.Uint16(k[0x206:]); ver < 0x020c {
		return fmt.Errorf("boot protocol %#x is too old for a 64-bit entry", ver)
	}
	if le.Uint16(k[0x236:])&1 == 0 {
		return errors.New("kernel has no 64-bit entry point")
	}
	setupSects := int(k[0x1f1])
	if setupSects == 0 {
		setupSects = 4
	}
	body := k[(setupSects+1)*512:]
	prefAddr := le.Uint64(k[0x258:])
	initSize := uint64(le.Uint32(k[0x260:]))
	align := uint64(le.Uint32(k[0x230:]))
	kaddr := up(prefAddr, align)
	ksize := up(initSize, page)
	if !both(kaddr, ksize) {
		return fmt.Errorf("the kernel's preferred address %#x (+%#x) is not RAM in both maps", kaddr, ksize)
	}

	var initrd []byte
	for _, p := range initrds {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		initrd = append(initrd, padded(b)[:up(uint64(len(b)), 4)]...)
	}
	isize := up(uint64(len(initrd)), page)
	var iaddr uint64
	for _, r := range target { // highest place below 4 GiB that is RAM in both maps and clear of the kernel
		if r.Type != 1 || r.Start >= 1<<32 {
			continue
		}
		top := r.End + 1
		if top > 1<<32 {
			top = 1 << 32
		}
		if top < isize+(16<<20) {
			continue
		}
		for a := down(top-isize-(16<<20), 2<<20); a >= r.Start && a >= kaddr+ksize; a -= 2 << 20 {
			if both(a, isize) {
				if a > iaddr {
					iaddr = a
				}
				break
			}
			if a < 2<<20 {
				break
			}
		}
	}
	if isize > 0 && iaddr == 0 {
		return errors.New("no room for the initrd below 4 GiB that is RAM in both maps")
	}

	// One low segment: boot parameters, command line, entry stub. Anywhere below
	// 4 GiB that is RAM in both maps and clear of the kernel and the initrd (on
	// UEFI machines the firmware keeps places a BIOS would leave free).
	var low uint64
	clear := func(a uint64) bool {
		over := func(s, n uint64) bool { return a < s+n && s < a+3*page }
		return both(a, 3*page) && !over(kaddr, ksize) && (isize == 0 || !over(iaddr, isize))
	}
	for _, a := range []uint64{0x800000, 0x100000, 0x200000, 0x400000} {
		if clear(a) {
			low = a
			break
		}
	}
	for _, r := range target {
		if low != 0 || r.Type != 1 {
			continue
		}
		for a := up(r.Start, page); a+3*page <= r.End+1 && a+3*page <= 1<<32; a += page {
			if a >= 0x100000 && clear(a) {
				low = a
				break
			}
		}
	}
	if low == 0 {
		return errors.New("no RAM below 4 GiB for the boot parameters")
	}
	bp := make([]byte, 3*page)
	hdrEnd := 0x202 + int(k[0x201])
	copy(bp[0x1f1:hdrEnd], k[0x1f1:hdrEnd])
	bp[0x210] = 0xff                                          // type_of_loader: undefined
	le.PutUint32(bp[0x228:], uint32(low+page))                // cmd_line_ptr
	le.PutUint32(bp[0x218:], uint32(iaddr))                   // ramdisk_image
	le.PutUint32(bp[0x21c:], uint32(len(initrd)))             // ramdisk_size
	le.PutUint32(bp[0x0c0:], uint32(iaddr>>32))               // ext_ramdisk_image
	le.PutUint32(bp[0x0c4:], uint32(uint64(len(initrd))>>32)) // ext_ramdisk_size
	if rsdp := rsdpArg(cmdline); rsdp != 0 && le.Uint16(k[0x206:]) >= 0x020e {
		// Where the ACPI tables are: kernels from 4.20 read it here (boot protocol
		// 2.14). Without it, a kernel started this way on a UEFI machine finds no
		// ACPI tables, and the acpi_rsdp= option is not built into every kernel.
		le.PutUint64(bp[0x070:], rsdp)
	}
	bp[0x1e8] = byte(len(target)) // e820_entries
	for i, r := range target {
		o := 0x2d0 + i*20
		le.PutUint64(bp[o:], r.Start)
		le.PutUint64(bp[o+8:], r.End-r.Start+1)
		le.PutUint32(bp[o+16:], r.Type)
	}
	if len(cmdline)+1 > page {
		return errors.New("command line longer than a page")
	}
	copy(bp[page:], cmdline)
	stub := append([]byte(nil), kexecStub...)
	patch := func(mark byte, v uint64) {
		i := strings.Index(string(stub), strings.Repeat(string([]byte{mark}), 8))
		le.PutUint64(stub[i:], v)
	}
	patch(0x11, low)         // %rsi = boot parameters
	patch(0x22, kaddr+0x200) // 64-bit entry of the kernel
	copy(bp[2*page:], stub)

	kbuf := padded(body)
	segs := []segment{
		{unsafe.Pointer(&bp[0]), uintptr(len(bp)), uintptr(low), uintptr(len(bp))},
		{unsafe.Pointer(&kbuf[0]), uintptr(len(kbuf)), uintptr(kaddr), uintptr(ksize)},
	}
	if isize > 0 {
		ibuf := padded(initrd)
		segs = append(segs, segment{unsafe.Pointer(&ibuf[0]), uintptr(len(ibuf)), uintptr(iaddr), uintptr(isize)})
	}
	fmt.Printf("kernel %#x +%#x, initrd %#x +%#x, params %#x, map %d entries\n",
		kaddr, ksize, iaddr, isize, low, len(target))
	if dry {
		return nil
	}
	const sysKexecLoad, archX8664 = 246, 62 << 16
	if _, _, e := syscall.Syscall6(sysKexecLoad, uintptr(low+2*page), uintptr(len(segs)),
		uintptr(unsafe.Pointer(&segs[0])), archX8664, 0, 0); e != 0 {
		return fmt.Errorf("kexec_load: %w (a locked-down kernel refuses this)", e)
	}
	syscall.Sync()
	fmt.Println("restarting into the new kernel")
	return syscall.Reboot(0x45584543) // LINUX_REBOOT_CMD_KEXEC
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	if asInit() { // started by the kernel as its first process: the generic receiver, or the receiver in the moving system's kernel
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: envmove memmap | rekexec -map M -kernel K [-initrd I]... | pci | pciof PATH | letgo [-keep A,B] | kick | refresh | fits -from M | imgfix -dev D -from M | send -to HOST:PORT | recv -listen :PORT")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "memmap":
		var m []region
		if m, err = readMemmap(); err == nil {
			fmt.Println(formatMap(m))
		}
	case "rekexec":
		fs := flag.NewFlagSet("rekexec", flag.ExitOnError)
		mapArg := fs.String("map", "", "memory map to boot with, as printed by memmap")
		kernel := fs.String("kernel", "", "bzImage to start")
		cmdline := fs.String("cmdline", "", "kernel command line (default: the running one)")
		dry := fs.Bool("n", false, "work out the layout and stop")
		var initrds multi
		fs.Var(&initrds, "initrd", "initrd file; repeat to concatenate")
		fs.Parse(os.Args[2:])
		if *cmdline == "" {
			b, _ := os.ReadFile("/proc/cmdline")
			*cmdline = strings.TrimSpace(string(b))
		}
		err = rekexec(*mapArg, *kernel, *cmdline, initrds, *dry)
	case "pci":
		var devs []pciDev
		if devs, err = pciList(); err == nil {
			pciPrint(devs)
		}
	case "pciof":
		var a string
		if len(os.Args) < 3 {
			err = errors.New("pciof needs a sysfs path")
		} else if a, err = pciOf(os.Args[2]); err == nil {
			fmt.Println(a)
		}
	case "letgo":
		fs := flag.NewFlagSet("letgo", flag.ExitOnError)
		keep := fs.String("keep", "", "comma-separated PCI addresses to leave attached")
		fs.Parse(os.Args[2:])
		var k []string
		if *keep != "" {
			k = strings.Split(*keep, ",")
		}
		err = letGo(k)
	case "refresh":
		err = refresh()
	case "kick":
		err = kick()
	case "mkrx": // build a receiver initramfs for this kernel: envmove mkrx OUT
		if len(os.Args) < 3 {
			err = errors.New("usage: envmove mkrx OUT")
			break
		}
		err = mkrx(os.Args[2])
	case "ramscan": // how the kernel shows its memory, and how fast it can be read
		syms, _, e := allSymbols()
		if e != nil {
			err = e
			break
		}
		k, e := openKernel(syms)
		if e != nil {
			err = e
			break
		}
		var total uint64
		for _, r := range k.ramRanges() {
			fmt.Printf("range va %#x pa %#x size %d MiB\n", r.va, r.pa, r.size>>20)
			total += r.size
		}
		fmt.Printf("page offset %#x, %d segments in all, %d MiB of memory ranges\n", k.pageOffset, len(k.segs), total>>20)
		buf := make([]byte, 1<<20)
		t0 := time.Now()
		var n uint64
		for _, r := range k.ramRanges() {
			for off := uint64(0); off < r.size && n < 256<<20; off += 1 << 20 {
				if k.read(r.va+off, buf) == nil {
					n += 1 << 20
				}
			}
		}
		fmt.Printf("read %d MiB in %.2f s\n", n>>20, time.Since(t0).Seconds())
		t0 = time.Now()
		for i := 0; i+page <= len(buf); i += page {
			xxh64(buf[i:i+page], 1)
		}
		fmt.Printf("fingerprinted 1 MiB in %.4f s\n", time.Since(t0).Seconds())
		k.close()
	case "send":
		fs := flag.NewFlagSet("send", flag.ExitOnError)
		to := fs.String("to", "", "the receiver, HOST:PORT")
		keep := fs.String("keep", "auto", "PCI addresses of the disk controllers that stay attached (comma-separated), none, or auto: the controllers mounted filesystems and swap rest on")
		fix := fs.String("fix", "auto", "corrections to make in transit: auto (decide from what the receiver says), none, or a comma-separated list of bootdata, noacpiirq, efioff, acpioff, acpiports")
		clock := fs.String("clock", "", "switch to this clock source before leaving (for example acpi_pm)")
		repoint := fs.Bool("repoint", false, "the receiver's disk controller is another type: hold the device-mapper mappings and re-point them on arrival")
		copyd := fs.Bool("copy", false, "copy every disk to the receiver's blank disks while running, the rest while frozen (no shared storage)")
		ahead := fs.Bool("ahead", false, "send the memory to the receiver while running; while frozen only what changed crosses")
		verdictPort := fs.Int("verdict", 0, "also take the verdict (die or thaw) over the network on this port, after -verdicttoken")
		verdictToken := fs.String("verdicttoken", "", "the token a network verdict must start with")
		boot := fs.String("boot", "", "a generic EnvMap receiver waiting at HOST:PORT: hand it this system's kernel and -bootinitrd first")
		bootToken := fs.String("boottoken", "", "the token the generic receiver expects")
		bootInitrd := fs.String("bootinitrd", "", "the receiver initramfs to hand over (with envmove in it as /envmove)")
		bootCmdline := fs.String("bootcmdline", "", "extra command line for the receiving kernel")
		via := fs.String("via", "", "carry the move over the network card with this address (a transfer card) instead of the card of the default route")
		after := fs.String("after", "", "MAC=IP/BITS[,GATEWAY]: the new machine's transfer card; once arrived, the system configures it for a moment and tells the copy it left behind (at the -via card's address, -verdict port) to power off")
		fs.Parse(os.Args[2:])
		// Tokens may come in the environment instead, so they are not on the
		// command line every user of the guest can read.
		if *bootToken == "" {
			*bootToken = os.Getenv("ENVMOVE_BOOTTOKEN")
		}
		if *verdictToken == "" {
			*verdictToken = os.Getenv("ENVMOVE_VERDICTTOKEN")
		}
		moveToken = *bootToken
		viaCard = strings.ToLower(*via)
		if *after != "" {
			if afterLine, err = parseAfter(*after); err != nil {
				break
			}
			if *verdictPort == 0 || viaCard == "" {
				err = errors.New("-after needs -via and -verdict: the old copy is told at its transfer address")
				break
			}
		}
		split := func(s string) []string {
			if s == "" || s == "none" {
				return nil
			}
			return strings.Split(s, ",")
		}
		if *boot != "" {
			if err = startReceiver(*boot, *bootToken, *bootInitrd, *bootCmdline, *to); err != nil {
				break
			}
		}
		if *verdictPort > 0 {
			if len(*verdictToken) < 16 {
				err = errors.New("-verdict needs -verdicttoken of at least 16 characters")
				break
			}
			verdictLine = fmt.Sprintf("verdict %d %s\n", *verdictPort, *verdictToken)
			verdictListen = *verdictPort
		}
		kept := split(*keep)
		if *keep == "auto" && *repoint {
			kept = nil // re-pointing: the controllers that change type are named, the rest go
		} else if *keep == "auto" {
			kept = autoKeep()
			fmt.Println("disk controllers kept attached (they hold mounted filesystems):", strings.Join(kept, ", "))
		}
		err = send(*to, kept, split(*fix), *clock, *repoint, *copyd, *ahead)
		if err == nil {
			afterArrival()
		}
	case "recv":
		fs := flag.NewFlagSet("recv", flag.ExitOnError)
		listen := fs.String("listen", ":7000", "address to wait on")
		addr := fs.String("addr", "", "give the first network card this address, IP/BITS")
		gw := fs.String("gw", "", "default gateway to set with -addr")
		force := fs.Bool("force", false, "accept a system the pre-flight would refuse")
		hold := fs.Bool("hold", false, "load the image but do not restore it (for testing the sender's undo)")
		fs.Parse(os.Args[2:])
		err = recv(*listen, *addr, *gw, *force, *hold)
	case "fits":
		fs := flag.NewFlagSet("fits", flag.ExitOnError)
		from := fs.String("from", "", "the sender's memory map, as printed by memmap")
		fs.Parse(os.Args[2:])
		err = fits(*from)
	case "imgfix":
		fs := flag.NewFlagSet("imgfix", flag.ExitOnError)
		dev := fs.String("dev", "", "block device that holds the hibernation image")
		from := fs.String("from", "", "the sender's memory map, as printed by memmap")
		force := fs.Bool("force", false, "adjust even if the sender's memory is not fully covered here")
		dry := fs.Bool("n", false, "report and stop")
		fs.Parse(os.Args[2:])
		err = imgFix(*dev, *from, *force, *dry)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err == errSaid || err == errDied {
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "envmove:", err)
		os.Exit(1)
	}
}

// parseAfter turns MAC=IP/BITS[,GATEWAY] into the plan's after line.
func parseAfter(s string) (string, error) {
	mac, rest, ok := strings.Cut(s, "=")
	addr, gw, _ := strings.Cut(rest, ",")
	if !ok || len(mac) != 17 {
		return "", fmt.Errorf("-after %q: want MAC=IP/BITS[,GATEWAY]", s)
	}
	a, n, err := net.ParseCIDR(addr)
	if err != nil || a.To4() == nil {
		return "", fmt.Errorf("-after %q: want MAC=IP/BITS[,GATEWAY]", s)
	}
	g := "0.0.0.0"
	if gw != "" {
		if net.ParseIP(gw).To4() == nil {
			return "", fmt.Errorf("-after %q: the gateway is not an IPv4 address", s)
		}
		g = gw
	}
	return fmt.Sprintf("after %s %s %s %s\n", strings.ToLower(mac), a.To4(), net.IP(n.Mask).To4(), g), nil
}

// rsdpArg is the address given as acpi_rsdp= on a command line, or 0.
func rsdpArg(cmdline string) uint64 {
	for _, f := range strings.Fields(cmdline) {
		if v, ok := strings.CutPrefix(f, "acpi_rsdp="); ok {
			n, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 64)
			if err == nil {
				return n
			}
		}
	}
	return 0
}
