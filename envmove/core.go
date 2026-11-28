//go:build linux

package main

// Starting the frozen part.
//
// From the freeze on, the work is done by envmove-core (core/core.c): a small
// program with one thread, no runtime and no C library, built into this one.
// This program prepares everything (what to correct in transit, which storage
// to hold and how to find it again, the network identity) and hands it over as
// a plan; envmove-core only carries it out.
//
// A Go program cannot do that part itself. It always has helper threads, the
// freeze stops them wherever they are, and one stopped while holding a lock of
// the runtime stops the working thread too, with the whole system waiting on
// it. A child forked from a Go program inherits those locks in whatever state
// they were at that instant. A separate program started with exec inherits
// nothing.

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

//go:embed coreimg/envmove-core
var coreImage []byte

// coreExecutable puts envmove-core somewhere it can be started from without
// touching a disk: an anonymous memory file where the kernel has them
// (Linux 3.17 on), otherwise a file in a memory filesystem.
func coreExecutable() (path string, cleanup func(), err error) {
	name := []byte("envmove-core\x00")
	fd, _, e := syscall.RawSyscall(319, uintptr(unsafe.Pointer(&name[0])), 0, 0) // memfd_create, no close-on-exec
	if e == 0 {
		f := os.NewFile(fd, "envmove-core")
		if _, err := f.Write(coreImage); err != nil {
			f.Close()
			return "", nil, err
		}
		// Keep the number clear of the ones the child is given (0 to 6).
		hi, _, e2 := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_DUPFD, 64)
		if e2 != 0 {
			f.Close()
			return "", nil, e2
		}
		f.Close()
		return fmt.Sprintf("/proc/self/fd/%d", hi), func() { syscall.Close(int(hi)) }, nil
	}
	for _, dir := range []string{"/dev/shm", "/run", "/tmp"} {
		f, err := os.CreateTemp(dir, "envmove-core-")
		if err != nil {
			continue
		}
		_, werr := f.Write(coreImage)
		f.Chmod(0o700)
		f.Close()
		if werr != nil {
			os.Remove(f.Name())
			continue
		}
		return f.Name(), func() { os.Remove(f.Name()) }, nil
	}
	return "", nil, errors.New("no memory filesystem to start the frozen part from")
}

// runCore starts envmove-core in mode with the snapshot device as its fd 3, the
// plan on fd 4, a gate on fd 5 and extra from fd 6 on, and waits for it. The
// snapshot device is closed here before the core is let through the gate, so
// the core is its only holder: if the core dies, for any reason, the kernel
// closes the device and thaws the system by itself.
func runCore(mode string, snap int, plan []byte, extra ...int) error {
	path, cleanup, err := coreExecutable()
	if err != nil {
		return err
	}
	defer cleanup()
	var pl, gate [2]int
	if err := syscall.Pipe2(pl[:], syscall.O_CLOEXEC); err != nil {
		return err
	}
	if err := syscall.Pipe2(gate[:], syscall.O_CLOEXEC); err != nil {
		return err
	}
	files := []uintptr{0, 1, 2, uintptr(snap), uintptr(pl[0]), uintptr(gate[0])}
	for _, f := range extra {
		files = append(files, uintptr(f))
	}
	pid, err := syscall.ForkExec(path, []string{"envmove-core", mode}, &syscall.ProcAttr{Env: os.Environ(), Files: files})
	syscall.Close(pl[0])
	syscall.Close(gate[0])
	if err != nil {
		syscall.Close(pl[1])
		syscall.Close(gate[1])
		return fmt.Errorf("cannot start the frozen part: %w", err)
	}
	for b := plan; len(b) > 0; {
		n, err := syscall.Write(pl[1], b)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			break // the core says what it missed
		}
		b = b[n:]
	}
	syscall.Close(pl[1])
	syscall.Close(snap)
	for _, f := range extra {
		syscall.Close(f)
	}
	syscall.Close(gate[1]) // the core goes on from here
	var ws syscall.WaitStatus
	for {
		_, err := syscall.Wait4(pid, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		break
	}
	if ws.Signaled() || ws.ExitStatus() > 1 {
		out(fmt.Sprintf("envmove: the frozen part of this program stopped unexpectedly (%v); the kernel thawed the system\n", ws))
		return errDied
	}
	if ws.ExitStatus() != 0 {
		return errSaid
	}
	return nil
}

// leavePlan is what envmove-core needs to leave this machine and arrive on the other.
func leavePlan(id netID, to string, port int, ps *fixSet, plan *storagePlan, stay []string) []byte {
	var b strings.Builder
	ip := func(a [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }
	fmt.Fprintf(&b, "to %s %d\n", to, port)
	fmt.Fprintf(&b, "net %s %s %s %s %s\n", id.Name, id.MAC, ip(id.IP), ip(id.Mask), ip(id.GW))
	for _, c := range cards() {
		if viaCard == "" || c.MAC != id.MAC { // the transfer card stays behind with the old copy
			fmt.Fprintf(&b, "nic %s %s\n", c.Name, c.MAC)
		}
	}
	b.WriteString(afterLine)
	if floppyToDrop() {
		b.WriteString("dropmod floppy\n")
	}
	for _, s := range stay {
		fmt.Fprintf(&b, "stay %s\n", s)
	}
	for pfn, edits := range ps.byPfn {
		for _, e := range edits {
			kind := 0
			if e.keepEndbr {
				kind = 1
			}
			fmt.Fprintf(&b, "patch %d %d %d %x\n", pfn, e.off, kind, e.data)
		}
	}
	for _, c := range ps.clocks {
		fmt.Fprintf(&b, "pvclock %d %d\n", c.pfn, c.off)
	}
	if plan != nil {
		for _, n := range plan.maps {
			fmt.Fprintf(&b, "map %s\n", n)
		}
		for _, n := range plan.maps {
			for _, t := range plan.tables[n] {
				fmt.Fprintf(&b, "target %s %d %d %s %s\n", n, t.Start, t.Length, t.Type, t.Params)
			}
		}
		for _, l := range plan.leaves {
			fmt.Fprintf(&b, "leaf %s %s %d %x %d %d %d\n", l.Was, l.Disk, l.DiskSectors, l.DiskHash, l.Part, l.Start, l.Size)
		}
		for _, m := range plan.mounts {
			ro := 0
			if m.ReadOnly {
				ro = 1
			}
			fmt.Fprintf(&b, "mount %s %s %d %s\n", m.Was, m.Type, ro, m.Dir)
		}
	}
	b.WriteString(verdictLine)
	if moveToken != "" {
		fmt.Fprintf(&b, "rxtoken %s\n", moveToken)
	}
	if os.Getenv("ENVMOVE_DEBUG") != "" {
		b.WriteString("flag debug\n")
	}
	switch os.Getenv("ENVMOVE_TEST") {
	case "crash":
		b.WriteString("flag crash\n")
	case "die":
		b.WriteString("flag die\n")
	}
	return []byte(b.String())
}

// verdictLine, when set, lets the frozen part take its verdict over the network,
// on verdictListen.
var verdictLine string
var verdictListen int
