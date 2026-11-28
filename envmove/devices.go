//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// A PCI device as the kernel remembers it and as the hardware answers now.
// After a move the two differ wherever the new hypervisor put something else
// (or nothing) at that address.
type pciDev struct {
	Addr       string
	Remembered string // vendor:device the kernel holds
	Live       string // vendor:device read from the device's configuration space now
	Driver     string
}

func (d pciDev) Stale() bool { return d.Remembered != d.Live }

const pciRoot = "/sys/bus/pci/devices"

func pciList() ([]pciDev, error) {
	dirs, err := filepath.Glob(pciRoot + "/*")
	if err != nil {
		return nil, err
	}
	sort.Strings(dirs)
	var out []pciDev
	for _, d := range dirs {
		rd := func(f string) string {
			b, _ := os.ReadFile(filepath.Join(d, f))
			return strings.TrimPrefix(strings.TrimSpace(string(b)), "0x")
		}
		dev := pciDev{Addr: filepath.Base(d), Remembered: rd("vendor") + ":" + rd("device"), Live: "none"}
		if f, err := os.Open(filepath.Join(d, "config")); err == nil {
			var id [4]byte
			if n, _ := f.Read(id[:]); n == 4 {
				dev.Live = fmt.Sprintf("%02x%02x:%02x%02x", id[1], id[0], id[3], id[2])
			}
			f.Close()
		}
		if l, err := os.Readlink(filepath.Join(d, "driver")); err == nil {
			dev.Driver = filepath.Base(l)
		}
		out = append(out, dev)
	}
	return out, nil
}

func pciPrint(devs []pciDev) {
	for _, d := range devs {
		mark := ""
		if d.Stale() {
			mark = "  <- changed"
		}
		fmt.Printf("%s %s %s %s%s\n", d.Addr, d.Remembered, d.Live, d.Driver, mark)
	}
}

func pciRemove(addr string) error {
	return os.WriteFile(filepath.Join(pciRoot, addr, "remove"), []byte("1"), 0)
}

// letGo detaches every device that has a driver, except the ones to keep. A
// device that is detached holds no driver state that could meet different
// hardware after the move.
func letGo(keep []string) error {
	devs, err := pciList()
	if err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, k := range keep {
		kept[k] = true
	}
	var gone []string
	for i := len(devs) - 1; i >= 0; i-- {
		d := devs[i]
		if d.Driver == "" || kept[d.Addr] {
			continue
		}
		if err := pciRemove(d.Addr); err != nil && !errors.Is(err, syscall.EAGAIN) { // EAGAIN: already on its way
			return fmt.Errorf("%s (%s): %w", d.Addr, d.Driver, err)
		}
		gone = append(gone, d.Addr+" "+d.Driver)
	}
	// Kernels before 3.14 remove a PCI device later, in a worker: wait until
	// every one is really gone, so nothing is half removed when the image is taken.
	for waited := 0; ; waited++ {
		left := 0
		for _, g := range gone {
			if _, err := os.Stat(filepath.Join(pciRoot, strings.Fields(g)[0])); err == nil {
				left++
			}
		}
		if left == 0 {
			break
		}
		if waited >= 200 {
			return fmt.Errorf("%d device(s) did not finish leaving in 20 s", left)
		}
		nap(100)
	}
	fmt.Println("let go of:", strings.Join(gone, ", "))
	return nil
}

// refresh drops every device that is no longer what the kernel remembers,
// then asks the kernel to look at the bus again.
func refresh() error {
	devs, err := pciList()
	if err != nil {
		return err
	}
	for i := len(devs) - 1; i >= 0; i-- {
		if d := devs[i]; d.Stale() {
			if c, err := os.ReadFile(pciRoot + "/" + d.Addr + "/config"); err == nil && len(c) > 0x0b && c[0x0b] == 1 &&
				((d.Driver == "nvme" && c[0x0a] == 8) || (d.Driver == "ahci" && c[0x0a] == 6)) {
				// NVMe and SATA drivers talk to a standard interface, whoever made
				// the controller. Another maker's controller of the same kind at
				// the same address is still theirs to drive.
				fmt.Printf("kept %s (%s, now %s): %s drives it by its standard interface\n", d.Addr, d.Remembered, d.Live, d.Driver)
				continue
			}
			if d.Driver != "" {
				// A driver still attached to hardware that changed under it may
				// never return from its own teardown. Say so instead of hanging.
				return fmt.Errorf("%s changed from %s to %s while %s is still attached; detach it before the move",
					d.Addr, d.Remembered, d.Live, d.Driver)
			}
			if err := pciRemove(d.Addr); err != nil {
				return fmt.Errorf("%s: %w", d.Addr, err)
			}
			fmt.Printf("forgot %s (%s, now %s)\n", d.Addr, d.Remembered, d.Live)
		}
	}
	if err := os.WriteFile("/sys/bus/pci/rescan", []byte("1"), 0); err != nil {
		return err
	}
	devs, err = pciList()
	if err == nil {
		pciPrint(devs)
	}
	return err
}

// pciOf returns the PCI address a sysfs device hangs off, for example
// /sys/class/net/eth0/device or /sys/block/sda/device.
func pciOf(sysfs string) (string, error) {
	p, err := filepath.EvalSymlinks(sysfs)
	if err != nil {
		return "", err
	}
	addr := ""
	for _, c := range strings.Split(p, "/") {
		if len(c) == 12 && c[4] == ':' && c[7] == ':' && c[10] == '.' {
			addr = c
		}
	}
	if addr == "" {
		return "", fmt.Errorf("%s is not on a PCI device", sysfs)
	}
	return addr, nil
}

// kick tells every disk controller that is still attached to reset itself and
// set its queues up again. A controller kept attached through a move is, on
// the new machine, a fresh device that knows nothing of the queues the driver
// believes it has. Without this the driver finds out only when a command times
// out (30 seconds by default) and error handling works its way up to a reset.
//
// Nothing here touches a filesystem: the tool is started from memory and talks
// to the kernel only, so it works while the root disk is still silent.
func kick() error {
	const sgScsiReset, resetHost = 0x2284, 3
	hosts, _ := filepath.Glob("/sys/class/scsi_host/host*")
	sort.Strings(hosts)
	n := 0
	for _, h := range hosts {
		disks, _ := filepath.Glob(filepath.Join(h, "device/target*/*/block/*"))
		if len(disks) == 0 {
			continue
		}
		name := filepath.Base(disks[0])
		drv, _ := os.ReadFile(filepath.Join(h, "proc_name"))
		fd, err := syscall.Open("/dev/"+name, syscall.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			fmt.Printf("%s (%s, %s): cannot open: %v\n", filepath.Base(h), strings.TrimSpace(string(drv)), name, err)
			continue
		}
		val := int32(resetHost)
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), sgScsiReset, uintptr(unsafe.Pointer(&val)))
		syscall.Close(fd)
		if e != 0 {
			fmt.Printf("%s (%s, %s): reset not done: %v\n", filepath.Base(h), strings.TrimSpace(string(drv)), name, e)
			continue
		}
		fmt.Printf("%s (%s, %s): controller reset and set up again\n", filepath.Base(h), strings.TrimSpace(string(drv)), name)
		n++
	}
	// NVMe controllers have their own switch for the same thing.
	ctrls, _ := filepath.Glob("/sys/class/nvme/nvme*")
	sort.Strings(ctrls)
	for _, c := range ctrls {
		if err := os.WriteFile(filepath.Join(c, "reset_controller"), []byte("1"), 0o200); err != nil {
			fmt.Printf("%s (nvme): reset not done: %v\n", filepath.Base(c), err)
			continue
		}
		fmt.Printf("%s (nvme): controller reset and set up again\n", filepath.Base(c))
		n++
	}
	if n == 0 {
		fmt.Println("no disk controller was reset")
	}
	return nil
}

// autoKeep is the PCI address of every disk controller that a mounted
// filesystem or swap space rests on, following device-mapper (LVM) down to the
// real disks. Those stay attached through the move: the same type of
// controller waits on the other side.
func autoKeep() []string {
	var devs []string
	if b, err := os.ReadFile("/proc/self/mounts"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 1 && strings.HasPrefix(f[0], "/dev/") {
				devs = append(devs, f[0])
			}
		}
	}
	if b, err := os.ReadFile("/proc/swaps"); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "/dev/") {
				devs = append(devs, f[0])
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	var walk func(name string, depth int)
	walk = func(name string, depth int) {
		if depth > 8 {
			return
		}
		dir := "/sys/class/block/" + name
		if slaves, _ := os.ReadDir(dir + "/slaves"); len(slaves) > 0 {
			for _, sl := range slaves {
				walk(sl.Name(), depth+1)
			}
			return
		}
		if _, err := os.Stat(dir + "/partition"); err == nil { // a partition: its disk
			if p, err := filepath.EvalSymlinks(dir); err == nil {
				name = filepath.Base(filepath.Dir(p))
			}
		}
		if a, err := pciOf("/sys/block/" + name + "/device"); err == nil && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, d := range devs {
		p, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue
		}
		walk(filepath.Base(p), 0)
	}
	sort.Strings(out)
	return out
}
