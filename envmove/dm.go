//go:build linux

package main

// Re-pointing storage: letting a mounted filesystem land on a different kind
// of disk controller.
//
// A filesystem that sits directly on a disk partition is tied to that disk's
// driver; if the controller changes type, the driver has nothing to talk to
// and the system freezes (RESULTS.md). A filesystem on LVM, or on any other
// device-mapper mapping, is tied only to the mapping, and a mapping can be
// told to rest on a different device while the filesystem stays mounted.
//
// So, with send -repoint:
//
//	before leaving   every mapping is suspended (its filesystem flushed and
//	                 held), and only then are the disk controllers let go. The
//	                 memory image is taken with no disk controller in it at all.
//	on arrival       the receiver's disks are discovered, each one is recognised
//	                 by its size and the contents of its first megabyte, the
//	                 mappings are loaded again pointing at the new devices, and
//	                 resumed. The filesystem never notices.
//	on undo          the same, back onto the disks that were let go.
//
// Filesystems mounted straight from a partition of those disks (typically
// /boot) are unmounted before and mounted again after. A root filesystem
// straight on a partition cannot be helped this way and is refused.
//
// This talks to the kernel's device-mapper directly (/dev/mapper/control), so
// it needs no helper program at a moment when no program can be loaded.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	dmHeader = 312 // struct dm_ioctl

	dmListDevices = 0xC138FD02
	dmDevSuspend  = 0xC138FD06
	dmTableLoad   = 0xC138FD09
	dmTableStatus = 0xC138FD0C

	dmSuspendFlag     = 1 << 1
	dmStatusTableFlag = 1 << 4
	dmBufferFullFlag  = 1 << 8
)

type dmTarget struct {
	Start, Length uint64
	Type, Params  string
}

func dmCall(fd int, cmd uintptr, name string, flags uint32, payload []byte, targets uint32) ([]byte, error) {
	for size := 16 << 10; ; size *= 4 {
		if size < dmHeader+len(payload)+8 {
			continue
		}
		b := make([]byte, size)
		le := binary.LittleEndian
		le.PutUint32(b[0:], 4) // interface version 4.0.0
		le.PutUint32(b[12:], uint32(size))
		le.PutUint32(b[16:], dmHeader)
		le.PutUint32(b[20:], targets)
		le.PutUint32(b[28:], flags)
		copy(b[48:48+127], name)
		copy(b[dmHeader:], payload)
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), cmd, uintptr(unsafe.Pointer(&b[0]))); e != 0 {
			return nil, e
		}
		if le.Uint32(b[28:])&dmBufferFullFlag != 0 && size < 4<<20 {
			continue
		}
		from, to := le.Uint32(b[16:]), le.Uint32(b[12:])
		if to <= from || int(to) > len(b) { // no data came back
			return nil, nil
		}
		return b[from:to], nil
	}
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func dmNames(fd int) ([]string, error) {
	d, err := dmCall(fd, dmListDevices, "", 0, nil, 0)
	if err != nil {
		return nil, err
	}
	var names []string
	for off := 0; off+12 < len(d); {
		if binary.LittleEndian.Uint64(d[off:]) == 0 {
			break
		}
		next := int(binary.LittleEndian.Uint32(d[off+8:]))
		names = append(names, cstr(d[off+12:]))
		if next == 0 {
			break
		}
		off += next
	}
	return names, nil
}

func dmTable(fd int, name string) ([]dmTarget, error) {
	d, err := dmCall(fd, dmTableStatus, name, dmStatusTableFlag, nil, 0)
	if err != nil {
		return nil, err
	}
	var t []dmTarget
	for off := 0; off+40 <= len(d); {
		le := binary.LittleEndian
		next := int(le.Uint32(d[off+20:]))
		t = append(t, dmTarget{le.Uint64(d[off:]), le.Uint64(d[off+8:]), cstr(d[off+24 : off+40]), cstr(d[off+40:])})
		if next <= off { // "next" counts from the start of the list here; no progress means the end
			break
		}
		off = next
	}
	return t, nil
}

func dmLoad(fd int, name string, t []dmTarget) error {
	var p []byte
	for _, x := range t {
		spec := make([]byte, 40)
		binary.LittleEndian.PutUint64(spec[0:], x.Start)
		binary.LittleEndian.PutUint64(spec[8:], x.Length)
		copy(spec[24:39], x.Type)
		body := append([]byte(x.Params), 0)
		for (len(spec)+len(body))%8 != 0 {
			body = append(body, 0)
		}
		binary.LittleEndian.PutUint32(spec[20:], uint32(len(spec)+len(body)))
		p = append(append(p, spec...), body...)
	}
	_, err := dmCall(fd, dmTableLoad, name, 0, p, uint32(len(t)))
	return err
}

func dmSuspend(fd int, name string, suspend bool) error {
	var f uint32
	if suspend {
		f = dmSuspendFlag
	}
	_, err := dmCall(fd, dmDevSuspend, name, f, nil, 0)
	return err
}

// leaf is a disk or partition that a mapping, or a plain mount, rests on.
type leaf struct {
	Was         string // "major:minor", as the tables name it
	Disk        string // the disk's kernel name when the plan was made
	DiskSectors uint64
	DiskHash    [32]byte // of the disk's first megabyte
	Part        int      // partition number; 0 is the whole disk
	Start, Size uint64
}

type plainMount struct {
	Was, Dir, Type string
	ReadOnly       bool
}

type storagePlan struct {
	ctl    int
	maps   []string // highest first: the order to suspend in
	tables map[string][]dmTarget
	leaves map[string]*leaf
	mounts []plainMount
}

var devToken = regexp.MustCompile(`\b\d+:\d+\b`)

func readU(path string) uint64 {
	b, _ := os.ReadFile(path)
	v, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return v
}

func hashDisk(name string) (h [32]byte, err error) {
	f, err := os.Open("/dev/" + name)
	if err != nil {
		return h, err
	}
	defer f.Close()
	b := make([]byte, 1<<20)
	n, _ := f.ReadAt(b, 0)
	if n < 4096 {
		return h, fmt.Errorf("cannot read the start of %s", name)
	}
	return sha256.Sum256(b[:n]), nil
}

// describe fills in what will identify a device after it has been rediscovered.
func describe(dev string) (*leaf, error) {
	p, err := filepath.EvalSymlinks("/sys/dev/block/" + dev)
	if err != nil {
		return nil, fmt.Errorf("device %s: %w", dev, err)
	}
	l := &leaf{Was: dev, Disk: filepath.Base(p)}
	if _, err := os.Stat(p + "/partition"); err == nil {
		l.Part, l.Start, l.Size = int(readU(p+"/partition")), readU(p+"/start"), readU(p+"/size")
		l.Disk = filepath.Base(filepath.Dir(p))
	}
	l.DiskSectors = readU("/sys/block/" + l.Disk + "/size")
	if l.DiskHash, err = hashDisk(l.Disk); err != nil {
		return nil, err
	}
	return l, nil
}

// planStorage looks at every mapping and plain mount and works out what will
// have to be pointed somewhere else. Disks on the controllers in keep stay as
// they are (the same controller type is there on the other side) and are left
// out. It changes nothing.
func planStorage(keep []string) (*storagePlan, error) {
	stays := func(l *leaf) bool {
		a, err := pciOf("/sys/block/" + l.Disk + "/device")
		if err != nil {
			return false
		}
		for _, k := range keep {
			if k == a {
				return true
			}
		}
		return false
	}
	ctl, err := syscall.Open("/dev/mapper/control", syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("device-mapper: %w", err)
	}
	p := &storagePlan{ctl: ctl, tables: map[string][]dmTarget{}, leaves: map[string]*leaf{}}
	names, err := dmNames(ctl)
	if err != nil {
		return nil, err
	}
	devOf := map[string]string{} // "major:minor" of a mapping -> its name
	for _, n := range names {
		var st syscall.Stat_t
		if syscall.Stat("/dev/mapper/"+n, &st) == nil {
			devOf[fmt.Sprintf("%d:%d", (st.Rdev>>8)&0xfff, (st.Rdev&0xff)|((st.Rdev>>12)&0xfff00))] = n
		}
	}
	above := map[string]int{} // how many mappings rest on this one
	for _, n := range names {
		t, err := dmTable(ctl, n)
		if err != nil {
			return nil, fmt.Errorf("mapping %s: %w", n, err)
		}
		p.tables[n] = t
		for _, x := range t {
			for _, d := range devToken.FindAllString(x.Params, -1) {
				if lower, isMap := devOf[d]; isMap {
					above[lower]++
				} else if _, seen := p.leaves[d]; !seen {
					if _, err := os.Stat("/sys/dev/block/" + d); err != nil {
						continue // a number pair that is not a device
					}
					l, err := describe(d)
					if err != nil {
						return nil, err
					}
					if !stays(l) {
						p.leaves[d] = l
					}
				}
			}
		}
	}
	// highest first: a mapping nothing rests on, then what it rests on, and so on
	for left := append([]string(nil), names...); len(left) > 0; {
		var rest []string
		for _, n := range left {
			if above[n] == 0 {
				p.maps = append(p.maps, n)
				for _, x := range p.tables[n] {
					for _, d := range devToken.FindAllString(x.Params, -1) {
						if lower, ok := devOf[d]; ok {
							above[lower]--
						}
					}
				}
			} else {
				rest = append(rest, n)
			}
		}
		if len(rest) == len(left) {
			return nil, errors.New("the mappings rest on each other in a circle")
		}
		left = rest
	}
	if len(p.leaves) == 0 {
		return nil, errors.New("no device-mapper mapping here rests on a disk that has to change: nothing to re-point")
	}
	b, _ := os.ReadFile("/proc/self/mounts")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasPrefix(f[0], "/dev/") {
			continue
		}
		var st syscall.Stat_t
		if syscall.Stat(f[0], &st) != nil {
			continue
		}
		d := fmt.Sprintf("%d:%d", (st.Rdev>>8)&0xfff, (st.Rdev&0xff)|((st.Rdev>>12)&0xfff00))
		if _, isMap := devOf[d]; isMap {
			continue
		}
		if _, ok := p.leaves[d]; !ok {
			l, err := describe(d)
			if err != nil {
				return nil, err
			}
			if stays(l) {
				continue
			}
			if f[1] == "/" {
				return nil, fmt.Errorf("the root filesystem sits straight on %s, not on a mapping: it cannot be re-pointed", f[0])
			}
			p.leaves[d] = l
		}
		p.mounts = append(p.mounts, plainMount{d, f[1], f[2], strings.HasPrefix(f[3], "ro,") || f[3] == "ro"})
	}
	if b, _ := os.ReadFile("/proc/swaps"); len(b) > 0 {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if f := strings.Fields(line); len(f) > 0 && strings.HasPrefix(f[0], "/dev/") && !strings.HasPrefix(f[0], "/dev/dm-") && !strings.HasPrefix(f[0], "/dev/mapper/") {
				return nil, fmt.Errorf("swap space %s sits straight on a disk partition; turn it off first", f[0])
			}
		}
	}
	return p, nil
}

// controllers returns the PCI addresses the plan's disks hang from.
func (p *storagePlan) controllers() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range p.leaves {
		if a, err := pciOf("/sys/block/" + l.Disk + "/device"); err == nil && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// unmountPlain takes the plain mounts off. Before the freeze.
func (p *storagePlan) unmountPlain() error {
	for i := len(p.mounts) - 1; i >= 0; i-- {
		if err := syscall.Unmount(p.mounts[i].Dir, 0); err != nil {
			return fmt.Errorf("cannot unmount %s: %w", p.mounts[i].Dir, err)
		}
	}
	return nil
}

// hold suspends every mapping, highest first, flushing its filesystem.
func (p *storagePlan) hold() error {
	for _, n := range p.maps {
		if err := dmSuspend(p.ctl, n, true); err != nil {
			return fmt.Errorf("cannot hold mapping %s: %w", n, err)
		}
	}
	return nil
}

// find looks for the device that is now what l was. Empty if it is not here yet.
func (l *leaf) find() string {
	disks, _ := os.ReadDir("/sys/block")
	for _, d := range disks {
		n := d.Name()
		if strings.HasPrefix(n, "dm-") || strings.HasPrefix(n, "loop") || strings.HasPrefix(n, "ram") || strings.HasPrefix(n, "sr") || strings.HasPrefix(n, "zram") {
			continue
		}
		if readU("/sys/block/"+n+"/size") != l.DiskSectors {
			continue
		}
		if h, err := hashDisk(n); err != nil || h != l.DiskHash {
			continue
		}
		dir := "/sys/block/" + n
		if l.Part > 0 {
			dir = ""
			parts, _ := os.ReadDir("/sys/block/" + n)
			for _, q := range parts {
				pd := "/sys/block/" + n + "/" + q.Name()
				if int(readU(pd+"/partition")) == l.Part && readU(pd+"/start") == l.Start && readU(pd+"/size") == l.Size {
					dir = pd
				}
			}
			if dir == "" {
				continue
			}
		}
		if b, err := os.ReadFile(dir + "/dev"); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// release points every mapping at where its disks are now, lets the
// filesystems go on, and puts the plain mounts back. Used on arrival and on undo.
func (p *storagePlan) release() error {
	now := map[string]string{}
	for tries := 0; ; tries++ {
		missing := ""
		for was, l := range p.leaves {
			if now[was] == "" {
				if now[was] = l.find(); now[was] == "" {
					missing = l.Disk
				}
			}
		}
		if missing == "" {
			break
		}
		if tries >= 300 {
			return fmt.Errorf("the disk that was %s has not appeared on this machine; the mappings stay held", missing)
		}
		nap(100)
	}
	swap := func(s string) string {
		return devToken.ReplaceAllStringFunc(s, func(d string) string {
			if n := now[d]; n != "" {
				return n
			}
			return d
		})
	}
	for i := len(p.maps) - 1; i >= 0; i-- { // lowest first
		n := p.maps[i]
		t := append([]dmTarget(nil), p.tables[n]...)
		moved := false
		for j := range t {
			if q := swap(t[j].Params); q != t[j].Params {
				t[j].Params, moved = q, true
			}
		}
		if moved {
			if err := dmLoad(p.ctl, n, t); err != nil {
				return fmt.Errorf("cannot re-point mapping %s: %w", n, err)
			}
		}
		if err := dmSuspend(p.ctl, n, false); err != nil {
			return fmt.Errorf("cannot release mapping %s: %w", n, err)
		}
		if moved {
			out("storage: " + n + " re-pointed and running\n")
		}
	}
	for _, m := range p.mounts {
		b, err := filepath.EvalSymlinks("/sys/dev/block/" + now[m.Was])
		if err != nil {
			return fmt.Errorf("mounting %s again: %w", m.Dir, err)
		}
		var fl uintptr
		if m.ReadOnly {
			fl = syscall.MS_RDONLY
		}
		if err := syscall.Mount("/dev/"+filepath.Base(b), m.Dir, m.Type, fl, ""); err == syscall.EBUSY {
			continue // it never left, or is already back
		} else if err != nil {
			return fmt.Errorf("mounting %s again from %s: %w", m.Dir, filepath.Base(b), err)
		}
		out("storage: " + m.Dir + " mounted again from " + filepath.Base(b) + "\n")
	}
	return nil
}
