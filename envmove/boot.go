//go:build linux

package main

// Becoming a receiver on a real hypervisor.
//
// A fresh target VM on ESXi or Proxmox can only start from a disk or a CD. So
// EnvMap gives it two CDs: the generic EnvMap receiver (one ISO for every move,
// see tools in lab/iso.py) and a small one with this move's settings. The
// generic receiver starts a small Linux with this program as its first
// process (envmove.role=boot). It brings up the transfer network card, waits
// for the moving system to hand over its own kernel and a receiver initramfs,
// and starts that kernel with kexec. That kernel starts this program again as
// its first process (envmove.role=rx), which is the receiver the lab proves.
//
// The moving system's own kernel is used for receiving because the restore
// code and the image header must match; any kernel would not do.

import (
	"bufio"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// cmdlineArgs is the kernel command line as key=value pairs.
func cmdlineArgs() map[string]string {
	b, _ := os.ReadFile("/proc/cmdline")
	out := map[string]string{}
	for _, f := range strings.Fields(string(b)) {
		k, v, _ := strings.Cut(f, "=")
		out[k] = v
	}
	return out
}

// earlyMounts gives a first process what it needs to look around.
func earlyMounts() {
	for _, m := range []struct{ dir, fs string }{{"/proc", "proc"}, {"/sys", "sysfs"}, {"/dev", "devtmpfs"}, {"/run", "tmpfs"}, {"/tmp", "tmpfs"}} {
		os.MkdirAll(m.dir, 0o755)
		syscall.Mount(m.fs, m.dir, m.fs, 0, "")
	}
}

func modprobe(names ...string) {
	for _, n := range names {
		modprobeCmd("-q", n).Run()
	}
}

// modprobeCmd runs the module loader with args. Where no program is called
// modprobe (a minimal initramfs carries only kmod), kmod is run under that
// name: kmod decides what to do by the name it is started with.
func modprobeCmd(args ...string) *exec.Cmd { return kmodCmd("modprobe", args...) }

// kmodCmd runs a module tool (modprobe, insmod) by its own program if there
// is one, else as kmod under that name, else as busybox under that name.
func kmodCmd(tool string, args ...string) *exec.Cmd {
	for _, d := range []string{"/usr/sbin/", "/sbin/", "/usr/bin/", "/bin/"} {
		if _, err := os.Stat(d + tool); err == nil {
			return exec.Command(d+tool, args...)
		}
	}
	for _, p := range []string{"/usr/bin/kmod", "/bin/kmod", "/usr/sbin/kmod", "/sbin/kmod", "/bin/busybox", "/usr/bin/busybox"} {
		if _, err := os.Stat(p); err == nil {
			return &exec.Cmd{Path: p, Args: append([]string{tool}, args...)}
		}
	}
	return exec.Command(tool, args...)
}

// loopAttach attaches a file to a free loop device and returns its path.
func loopAttach(file string) (string, error) {
	ctl, err := os.OpenFile("/dev/loop-control", os.O_RDWR, 0)
	if err != nil {
		return "", err
	}
	defer ctl.Close()
	n, _, e := syscall.Syscall(syscall.SYS_IOCTL, ctl.Fd(), 0x4C82, 0) // LOOP_CTL_GET_FREE
	if e != 0 {
		return "", e
	}
	dev := fmt.Sprintf("/dev/loop%d", n)
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var l *os.File
	for i := 0; i < 50; i++ { // the node shows up a moment after it is made
		if l, err = os.OpenFile(dev, os.O_RDWR, 0); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return "", err
	}
	defer l.Close()
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, l.Fd(), 0x4C00, f.Fd()); e != 0 { // LOOP_SET_FD
		return "", e
	}
	return dev, nil
}

type bootConfig struct {
	IP    string `json:"ip"`    // IP/BITS for the transfer network card
	GW    string `json:"gw"`    // default gateway, may be empty
	MAC   string `json:"mac"`   // the transfer card; empty: the first card
	Port  int    `json:"port"`  // where to wait for the moving system
	Token string `json:"token"` // what the moving system must say first
	// Where the moving system waits, frozen, for its verdict (IP:PORT), and
	// the token a verdict starts with. A receiver that starts while the system
	// waits there is a receiver that started again after the move failed on
	// this machine: it tells the system to carry on where it was.
	Verdict string `json:"verdict"`
	VToken  string `json:"vtoken"`
	// A helper of a powered-off move (cold_linux.go): its role ("give" on the
	// old host, "take" on the new one), where the taker waits (IP:PORT, for
	// the giver), and the place of each disk.
	Role  string     `json:"role"`
	To    string     `json:"to"`
	Disks []coldSlot `json:"disks"`
}

// bringBack watches for the moving system waiting for a verdict, and when it
// finds it, tells it to carry on where it was. On the first start the port is
// closed (the system has not left yet) until this receiver hands over to the
// moving system's own kernel, which ends this watch with everything else; it
// can only be found open by a receiver started afresh after a failed arrival.
func bringBack(addr, token string, say func(string, ...any)) {
	for {
		time.Sleep(3 * time.Second)
		c, err := net.DialTimeout("tcp4", addr, 2*time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(10 * time.Second))
		c.Write([]byte(token + " thaw\n"))
		ans := make([]byte, 16)
		n, _ := io.ReadAtLeast(c, ans, 1)
		c.Close()
		got := strings.TrimSpace(string(ans[:n]))
		if got == "TAKEN" {
			say("the moving system was still waiting at %s while this receiver started afresh: it did not arrive here, so it was told to carry on where it was", addr)
			halt()
		}
		say("asked the moving system at %s to carry on; it answered %q", addr, got)
		if got == "REFUSED" {
			return // another token: not this move's system
		}
	}
}

// bootInit is the generic receiver's first process.
func bootInit() {
	earlyMounts()
	say := func(f string, a ...any) { fmt.Printf("envboot: "+f+"\n", a...) }
	modprobe("cdrom", "sr_mod", "isofs", "ata_piix", "ahci", "virtio_pci", "virtio_scsi", "squashfs", "loop")
	time.Sleep(time.Second)
	// The CDs: the receiver itself (with the drivers bundle) and this move's settings.
	var cfg *bootConfig
	modloop := ""
	for i := 0; i < 8; i++ {
		dev := fmt.Sprintf("/dev/sr%d", i)
		if _, err := os.Stat(dev); err != nil {
			continue
		}
		dir := fmt.Sprintf("/media/cd%d", i)
		os.MkdirAll(dir, 0o755)
		if err := syscall.Mount(dev, dir, "iso9660", syscall.MS_RDONLY, ""); err != nil {
			continue
		}
		if b, err := os.ReadFile(dir + "/envmove.jsn"); err == nil {
			var c bootConfig
			if json.Unmarshal(b, &c) == nil {
				cfg = &c
			}
		}
		if _, err := os.Stat(dir + "/boot/modloop"); err == nil {
			modloop = dir + "/boot/modloop"
		}
	}
	if modloop != "" {
		if dev, err := loopAttach(modloop); err == nil {
			os.MkdirAll("/.modloop", 0o755)
			if err := syscall.Mount(dev, "/.modloop", "squashfs", syscall.MS_RDONLY, ""); err == nil {
				os.RemoveAll("/lib/modules")
				os.Symlink("/.modloop/modules", "/lib/modules")
				os.RemoveAll("/lib/firmware")
				os.Symlink("/.modloop/firmware", "/lib/firmware")
			} else {
				say("the drivers bundle does not mount: %v", err)
			}
		} else {
			say("the drivers bundle cannot be attached: %v", err)
		}
	}
	// Drivers carried on the CD itself (a slim receiver), in the order they depend on each other.
	if order, err := os.ReadFile("/envmove-mods/order"); err == nil {
		for _, m := range strings.Fields(string(order)) {
			kmodCmd("insmod", "/envmove-mods/"+m).Run()
		}
		time.Sleep(time.Second)
	}
	ownDrivers()
	if cfg == nil {
		say("no settings CD (envmove.jsn); nothing to do")
		halt()
	}
	if cfg.Role != "" {
		coldInit(cfg) // a helper of a powered-off move: it never returns
	}
	id, err := netFromConfig(cfg.IP, cfg.GW, cfg.MAC)
	if err != nil {
		say("network: %v", err)
		halt()
	}
	ln, err := net.Listen("tcp4", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		say("%v", err)
		halt()
	}
	say("waiting on %s port %d for the moving system", id, cfg.Port) // only once really listening
	if cfg.Verdict != "" && len(cfg.VToken) >= 16 {
		go bringBack(cfg.Verdict, cfg.VToken, say)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		kernel, initrd, cmdline, err := takeBoot(c, cfg.Token)
		if err != nil {
			c.Write([]byte("REFUSED\n"))
			c.Close()
			say("refused a hand-over: %v", err)
			continue
		}
		c.Write([]byte("TAKEN\n"))
		c.Close()
		// Every connection to the receiving kernel must carry this move's token.
		cmdline += " envmove.token=" + cfg.Token
		if !strings.Contains(cmdline, "envmove.ip=") {
			// The receiving kernel uses the same transfer card and address.
			cmdline += " envmove.ip=" + cfg.IP
			if cfg.GW != "" {
				cmdline += " envmove.gw=" + cfg.GW
			}
			if mac := cardMAC(cfg.MAC); mac != "" {
				cmdline += " envmove.mac=" + mac
			}
		}
		if rsdp := acpiRSDP(); rsdp != "" && !strings.Contains(cmdline, "acpi_rsdp=") {
			// A kernel started this way gets no firmware tables; on UEFI machines it
			// would not find ACPI by itself.
			cmdline += " acpi_rsdp=" + rsdp
		}
		here, _ := readMemmap()
		ln.Close()
		// Every device this kernel used is stopped and reset before the next
		// kernel takes over: a card still busy when kexec jumps can write into
		// memory the next kernel uses, and an older driver may not recover it.
		if err := letGo(nil); err != nil {
			say("letting go of the devices: %v", err)
		}
		say("starting the moving system's own kernel")
		if err := rekexec(formatMap(here), kernel, cmdline, []string{initrd}, false); err != nil {
			say("kexec: %v", err)
			for _, f := range []string{"/proc/sys/kernel/kexec_load_disabled", "/sys/kernel/security/lockdown", "/proc/sys/kernel/kexec_load_limit_reboot"} {
				b, _ := os.ReadFile(f)
				say("%s: %s", f, strings.TrimSpace(string(b)))
			}
			st, _ := os.ReadFile("/proc/self/status")
			for _, l := range strings.Split(string(st), "\n") {
				if strings.HasPrefix(l, "Cap") {
					say("%s", l)
				}
			}
			if k, err := readKmsg(); err == nil {
				lines := strings.Split(strings.TrimSpace(k), "\n")
				if len(lines) > 12 {
					lines = lines[len(lines)-12:]
				}
				for _, l := range lines {
					say("kernel: %s", l)
				}
			}
		}
		halt()
	}
}

// takeBoot reads a hand-over: ENVBOOT1, the token, then kernel, initramfs and
// command line, each with its length.
func takeBoot(c net.Conn, token string) (kernel, initrd, cmdline string, err error) {
	r := bufio.NewReaderSize(c, 1<<20)
	var magic [8]byte
	if _, err = io.ReadFull(r, magic[:]); err != nil || string(magic[:]) != "ENVBOOT1" {
		return "", "", "", errors.New("not a hand-over")
	}
	part := func(max uint64) ([]byte, error) {
		var n [8]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return nil, err
		}
		size := binary.LittleEndian.Uint64(n[:])
		if size > max {
			return nil, fmt.Errorf("a part of %d bytes is too large", size)
		}
		b := make([]byte, size)
		_, err := io.ReadFull(r, b)
		return b, err
	}
	fmt.Println("envboot: a hand-over is arriving")
	tok, err := part(256)
	if err != nil {
		return
	}
	if token == "" || subtle.ConstantTimeCompare(tok, []byte(token)) != 1 {
		return "", "", "", errors.New("wrong token")
	}
	k, err := part(256 << 20)
	if err != nil {
		return
	}
	fmt.Printf("envboot: kernel received (%d MiB)\n", len(k)>>20)
	i, err := part(2 << 30)
	if err != nil {
		return
	}
	fmt.Printf("envboot: initramfs received (%d MiB)\n", len(i)>>20)
	cl, err := part(4096)
	if err != nil {
		return
	}
	kernel, initrd = "/run/kernel", "/run/initrd"
	if err = os.WriteFile(kernel, k, 0o600); err != nil {
		return
	}
	if err = os.WriteFile(initrd, i, 0o600); err != nil {
		return
	}
	return kernel, initrd, string(cl), nil
}

// handOver sends this system's kernel and a receiver initramfs to a generic
// receiver, which starts them.
func handOver(to, token, kernel, initrd, cmdline string) error {
	c, err := net.DialTimeout("tcp", to, 10*time.Second)
	if err != nil {
		return fmt.Errorf("the generic receiver at %s does not answer: %w", to, err)
	}
	defer c.Close()
	w := bufio.NewWriterSize(c, 1<<20)
	w.WriteString("ENVBOOT1")
	put := func(b []byte) {
		var n [8]byte
		binary.LittleEndian.PutUint64(n[:], uint64(len(b)))
		w.Write(n[:])
		w.Write(b)
	}
	put([]byte(token))
	for _, f := range []string{kernel, initrd} {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		put(b)
	}
	put([]byte(cmdline))
	if err := w.Flush(); err != nil {
		return err
	}
	// The receiver answers once it has it all; a reset in between means it did not.
	c.(*net.TCPConn).CloseWrite()
	c.SetReadDeadline(time.Now().Add(60 * time.Second))
	ack, _ := bufio.NewReader(c).ReadString('\n')
	if ack != "TAKEN\n" {
		return fmt.Errorf("the generic receiver did not confirm the hand-over (%q)", strings.TrimSpace(ack))
	}
	return nil
}

func acpiRSDP() string {
	b, err := os.ReadFile("/sys/firmware/efi/systab")
	if err != nil {
		// No firmware table listing: the kernel's own log names the address.
		if k, err := readKmsg(); err == nil {
			for _, line := range strings.Split(k, "\n") {
				if i := strings.Index(line, "ACPI: RSDP 0x"); i >= 0 {
					return strings.Fields(line[i+len("ACPI: RSDP "):])[0]
				}
			}
		}
		return ""
	}
	for _, key := range []string{"ACPI20=", "ACPI="} {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, key) {
				return strings.TrimPrefix(line, key)
			}
		}
	}
	return ""
}

// netFromConfig gives the card with mac (or the first card) an address.
func netFromConfig(addr, gw, mac string) (string, error) {
	var id netID
	var err error
	if id.IP, id.Mask, err = parseCIDR(addr); err != nil {
		return "", err
	}
	if gw != "" {
		copy(id.GW[:], net.ParseIP(gw).To4())
	}
	ctl, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(ctl)
	name := ""
	for i := 0; i < 100 && name == ""; i++ {
		if mac != "" {
			name = ifByMAC(ctl, strings.ToLower(mac))
		} else {
			name = ifFirst(ctl)
		}
		if name == "" {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if name == "" {
		return "", errors.New("no network card found")
	}
	if err := ifConfigure(ctl, name, id); err != nil {
		return "", fmt.Errorf("configuring %s: %w", name, err)
	}
	return name + " " + addr, nil
}

// rxInit is the first process of the moving system's own kernel on the target:
// the receiver, set up from the command line.
func rxInit() {
	earlyMounts()
	a := cmdlineArgs()
	fmt.Println("envmove: receiver starting in the moving system's own kernel")
	ownDrivers()
	if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		var cards []string
		for _, e := range ents {
			cards = append(cards, e.Name())
		}
		fmt.Println("envmove: network cards here:", strings.Join(cards, " "))
	}
	// Drivers carried beside the initramfs's own (the lab packs network drivers
	// this way), loaded in the order they depend on each other.
	if _, err := os.Stat("/lab/mods"); err == nil {
		for _, m := range []string{"pps_core", "ptp", "failover", "net_failover", "virtio", "virtio_ring", "virtio_pci", "virtio_net", "vmxnet3", "e1000e", "e1000"} {
			fs, _ := filepath.Glob("/lab/mods/" + m + ".ko*")
			for _, f := range fs {
				kmodCmd("insmod", f).Run()
			}
		}
		time.Sleep(2 * time.Second)
	}
	port := a["envmove.port"]
	if port == "" {
		port = "8000"
	}
	rxToken = a["envmove.token"]
	if a["envmove.ip"] != "" {
		if id, err := netFromConfig(a["envmove.ip"], a["envmove.gw"], a["envmove.mac"]); err != nil {
			fmt.Println("envmove: network:", err)
		} else {
			fmt.Println("envmove: network:", id)
		}
	}
	err := recv(":"+port, "", "", false, a["envmove.hold"] == "1")
	if err != nil && err != errSaid {
		fmt.Println("envmove:", err)
	}
	halt()
}

// halt keeps a first process alive (its end would panic the kernel) and
// leaves the console readable.
func halt() {
	for {
		time.Sleep(time.Hour)
	}
}

// asInit runs a first-process role when the kernel started this program as its first process.
func asInit() bool {
	if os.Getpid() != 1 {
		return false
	}
	os.MkdirAll("/proc", 0o755)
	syscall.Mount("proc", "/proc", "proc", 0, "")
	switch cmdlineArgs()["envmove.role"] {
	case "boot":
		bootInit()
	case "rx":
		rxInit()
	default:
		fmt.Println("envmove: started as the first process without envmove.role=boot or rx")
		halt()
	}
	return true
}

// startReceiver hands this system's own kernel and a receiver initramfs to a
// generic receiver, then waits until the receiver they start answers at to.
func startReceiver(boot, token, initrd, extra, to string) error {
	kernel := "/boot/vmlinuz-" + release()
	if _, err := os.Stat(kernel); err != nil {
		return fmt.Errorf("this system's kernel is not at %s", kernel)
	}
	if initrd == "" {
		initrd = "/dev/shm/envmove-rx.img"
		if _, err := os.Stat("/dev/shm"); err != nil {
			initrd = "/tmp/envmove-rx.img"
		}
		fmt.Println("receiver: building a receiver initramfs for this kernel")
		t0 := time.Now()
		if err := mkrx(initrd); err != nil {
			return err
		}
		defer os.Remove(initrd)
		fi, _ := os.Stat(initrd)
		fmt.Printf("receiver: built (%d MiB) in %.0f s\n", fi.Size()>>20, time.Since(t0).Seconds())
	}
	host, port, err := net.SplitHostPort(to)
	if err != nil {
		return err
	}
	cmdline := "rdinit=/envmove envmove.role=rx envmove.port=" + port + " console=ttyS0,115200 console=tty0 " + extra
	_ = host
	fmt.Println("receiver: handing this system's kernel to the generic receiver at", boot)
	// The target may still be starting: try for a while before giving up.
	t1 := time.Now()
	for {
		err := handOver(boot, token, kernel, initrd, cmdline)
		if err == nil {
			break
		}
		if time.Since(t1) > 10*time.Minute {
			return err
		}
		time.Sleep(3 * time.Second)
	}
	t0 := time.Now()
	for time.Since(t0) < 10*time.Minute {
		// A connection alone proves nothing (address translation in between may
		// accept it on the receiver's behalf): the receiver must say it is ready.
		if c, err := net.DialTimeout("tcp", to, 3*time.Second); err == nil {
			c.SetDeadline(time.Now().Add(5 * time.Second))
			c.Write(kindAndToken("ENVMOVEQ"))
			line, _ := bufio.NewReader(c).ReadString('\n')
			c.Close()
			if line == "READY\n" {
				fmt.Printf("receiver: this system's kernel answers on the target after %.0f s\n", time.Since(t0).Seconds())
				return nil
			}
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("the receiver did not come up on the target within 10 minutes")
}

// cardMAC is the address of the card the settings name, or of the first card.
func cardMAC(mac string) string {
	if mac != "" {
		return strings.ToLower(mac)
	}
	ctl, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return ""
	}
	defer syscall.Close(ctl)
	if n := ifFirst(ctl); n != "" {
		return ifMAC(ctl, n)
	}
	return ""
}

// rxDrivers are the virtual disk controllers and network cards of ESXi and
// Proxmox (and a few more), so the receiving kernel can use whatever the
// target has.
var rxDrivers = []string{"vmw_pvscsi", "vmxnet3", "virtio_pci", "virtio_scsi", "virtio_blk", "virtio_net",
	"nvme", "ahci", "ata_piix", "sd_mod", "sr_mod", "e1000", "e1000e", "mptsas", "mptspi", "sym53c8xx", "megaraid_sas", "isofs"}

// mkrx builds a receiver initramfs for this very kernel, with this system's
// own tool for it, and puts envmove into it as /envmove.
func mkrx(out string) error {
	kver := release()
	base := out + ".base"
	defer os.Remove(base)
	var cmd *exec.Cmd
	if p, err := exec.LookPath("dracut"); err == nil {
		cmd = exec.Command(p, "--force", "--no-hostonly", "--no-hostonly-cmdline", "--no-early-microcode",
			"-m", "base kernel-modules", "--add-drivers", strings.Join(rxDrivers, " "), "--kver", kver, base)
	} else if p, err := exec.LookPath("mkinitramfs"); err == nil {
		cmd = exec.Command(p, "-o", base, kver) // Debian and Ubuntu keep MODULES=most: every common driver
	} else {
		return errors.New("neither dracut nor mkinitramfs is here to build a receiver initramfs")
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", cmd.Path, err, strings.TrimSpace(string(b))[max(0, len(b)-400):])
	}
	img, err := os.ReadFile(base)
	if err != nil {
		return err
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	// The kernel looks for the next archive only at a four-byte boundary, and
	// a compressed image ends wherever it ends: zeros in between are skipped.
	for len(img)%512 != 0 {
		img = append(img, 0)
	}
	img = append(img, cpioNewc("envmove", 0o100755, self)...)
	return os.WriteFile(out, img, 0o600)
}

// cpioNewc is a one-file cpio archive (newc), appended after an initramfs.
func cpioNewc(name string, mode uint32, data []byte) []byte {
	var b []byte
	pad := func() {
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
	}
	entry := func(ino uint32, name string, mode uint32, data []byte) {
		n := name + "\x00"
		b = append(b, fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
			ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(n), 0)...)
		b = append(b, n...)
		pad()
		b = append(b, data...)
		pad()
	}
	entry(1, name, mode, data)
	entry(2, "TRAILER!!!", 0, nil)
	return b
}
