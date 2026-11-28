//go:build linux

package main

// Corrections made to the system's memory while it travels.
//
// A kernel learns what machine it is on once, at boot, and keeps that in its
// own memory: where the firmware left its notes, which code to call for an
// interrupt, how to reach the firmware's services. After a move to different
// hardware some of that is wrong, and a few of the wrong parts hurt (see
// RESULTS.md). The kernel offers no way to correct them from outside while it
// runs. But during a move every page of its memory passes through this
// program, so the correction is made there: the system wakes up on the other
// side already holding the right value.
//
// Each fix names kernel symbols, never fixed addresses: the addresses come
// from the running kernel's own symbol table, so the same fix serves every
// kernel build that has the symbol, and is skipped (and said so) where it has
// not.
//
//	bootdata   forget the firmware's boot notes (their memory stayed behind;
//	           following them faults whenever a device is added, which leaves
//	           new devices without interrupts on UEFI guests)
//	noacpiirq  route device interrupts the plain way, not through the ACPI
//	           program (which belongs to the machine that was left; kernel
//	           3.10 crashes running it, newer ones log errors)
//	efioff     make every call into the firmware's runtime services fail
//	           politely instead of jumping into code that stayed behind
//	acpioff    stop the kernel running its ACPI program at all. That program was
//	           read from the old machine's firmware at boot; after a move its
//	           code is whatever the new firmware left at those addresses, and
//	           even an exact copy would be the old machine's instructions for
//	           the old machine's hardware. Every request to run it now gets
//	           "not found", which the kernel handles everywhere. The power-off
//	           codes it would have looked up there are set to the receiver's.
//	           Use together with acpiports
//	settle     after a disk controller is reset the kernel waits a fixed ten
//	           seconds ("settle time") before it lets disk requests through
//	           again: time real hardware once needed. A controller kept through a
//	           move has to be reset on arrival, and a virtual one is ready at once,
//	           so the wait becomes 50 ms in the reset path this tool uses
//	kvm        leaving KVM for another hypervisor: KVM's shortcuts off, its
//	           clock rewritten for the receiver (kvmfix.go)
//	acpiports  give the kernel the receiving machine's ACPI register addresses
//	           (power button, power-off, reset, the ACPI timer). The kernel keeps
//	           its own copy of that table from boot; without this, powering off
//	           from inside writes to a port that only existed on the old machine

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type edit struct {
	fix       string
	off       int
	data      []byte // bytes to put at off
	keepEndbr bool   // a function entry: if it starts with the branch-tracking mark, keep the mark and write after it
}

type fixSet struct {
	byPfn  map[uint64][]edit
	notes  []string
	clocks []pvEntry // KVM clock records the receiver rewrites (fix kvm)
}

// kernelSymbols returns the addresses of the named symbols.
func kernelSymbols(names ...string) (map[string]uint64, error) {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got := map[string]uint64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 3 || !want[p[2]] || len(p) > 3 { // a fourth field means a module's symbol
			continue
		}
		if _, dup := got[p[2]]; dup {
			continue
		}
		a, _ := strconv.ParseUint(p[0], 16, 64)
		got[p[2]] = a
	}
	if a, ok := got["_text"]; ok && a == 0 {
		return nil, errors.New("this kernel hides its symbol addresses (kernel.kptr_restrict); they are needed to make corrections in transit")
	}
	return got, nil
}

// kernelCodeAt is the physical address the kernel's code was loaded at.
func kernelCodeAt() (uint64, error) {
	b, err := os.ReadFile("/proc/iomem")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, "Kernel code") {
			a, err := strconv.ParseUint(strings.TrimSpace(strings.SplitN(line, "-", 2)[0]), 16, 64)
			if err == nil && a != 0 {
				return a, nil
			}
		}
	}
	return 0, errors.New("cannot tell where the kernel is loaded (/proc/iomem shows no address)")
}

// resolveFixes turns fix names into page edits for this running kernel.
func resolveFixes(names []string, fadt []byte, s5 []byte) (*fixSet, error) {
	fs := &fixSet{byPfn: map[uint64][]edit{}}
	if len(names) == 0 {
		return fs, nil
	}
	sym, err := kernelSymbols("_text", "boot_params", "pcibios_enable_irq", "pcibios_disable_irq",
		"pirq_enable_irq", "pirq_disable_irq", "__efi_call", "efi_call", "acpi_gbl_FADT",
		"acpi_gbl_xpm1a_status", "acpi_gbl_xpm1a_enable", "acpi_gbl_xpm1b_status", "acpi_gbl_xpm1b_enable", "pmtmr_ioport",
		"acpi_ns_evaluate", "acpi_gbl_sleep_type_a", "acpi_gbl_sleep_type_b")
	if err != nil {
		return nil, err
	}
	base, err := kernelCodeAt()
	if err != nil {
		return nil, err
	}
	text, ok := sym["_text"]
	if !ok {
		return nil, errors.New("the kernel's symbol table has no _text")
	}
	phys := func(v uint64) uint64 { return v - text + base }
	put := func(fix string, v uint64, data []byte) {
		for p := phys(v); len(data) > 0; {
			n := page - int(p%page)
			if n > len(data) {
				n = len(data)
			}
			fs.byPfn[p/page] = append(fs.byPfn[p/page], edit{fix: fix, off: int(p % page), data: data[:n]})
			p, data = p+uint64(n), data[n:]
		}
	}
	le64 := func(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }
	putPA := func(fix string, p uint64, data []byte) {
		for len(data) > 0 {
			n := page - int(p%page)
			if n > len(data) {
				n = len(data)
			}
			fs.byPfn[p/page] = append(fs.byPfn[p/page], edit{fix: fix, off: int(p % page), data: data[:n]})
			p, data = p+uint64(n), data[n:]
		}
	}
	for _, name := range names {
		switch name {
		case "bootdata":
			bp, ok := sym["boot_params"]
			if !ok {
				fs.notes = append(fs.notes, "bootdata: skipped, this kernel does not name boot_params")
				continue
			}
			put(name, bp+0x250, make([]byte, 8)) // setup_header.setup_data
			fs.notes = append(fs.notes, "bootdata: the pointer to the firmware's boot notes will be cleared")
		case "noacpiirq":
			en, d := sym["pcibios_enable_irq"], sym["pcibios_disable_irq"]
			pe, pd := sym["pirq_enable_irq"], sym["pirq_disable_irq"]
			if en == 0 || d == 0 || pe == 0 || pd == 0 {
				fs.notes = append(fs.notes, "noacpiirq: skipped, this kernel does not name the interrupt-routing hooks")
				continue
			}
			put(name, en, le64(pe))
			put(name, d, le64(pd))
			fs.notes = append(fs.notes, "noacpiirq: device interrupts will be routed without the ACPI program")
		case "efioff":
			at := sym["__efi_call"]
			if at == 0 {
				at = sym["efi_call"]
			}
			if at == 0 {
				fs.notes = append(fs.notes, "efioff: skipped, this kernel has no firmware runtime calls")
				continue
			}
			p := phys(at)
			if page-int(p%page) < 20 {
				fs.notes = append(fs.notes, "efioff: skipped, the call gate sits across a page boundary")
				continue
			}
			// mov $EFI_ABORTED, %rax ; ret
			stub := append(append([]byte{0x48, 0xb8}, le64(0x8000000000000015)...), 0xc3)
			fs.byPfn[p/page] = append(fs.byPfn[p/page], edit{fix: name, off: int(p % page), data: stub, keepEndbr: true})
			fs.notes = append(fs.notes, "efioff: calls into the firmware's runtime services will return an error instead of running")
		case "acpioff":
			at := sym["acpi_ns_evaluate"]
			if at == 0 {
				fs.notes = append(fs.notes, "acpioff: skipped, this kernel does not name its ACPI evaluator")
				continue
			}
			pa := phys(at)
			if page-int(pa%page) < 16 {
				fs.notes = append(fs.notes, "acpioff: skipped, the evaluator's entry sits across a page boundary")
				continue
			}
			stub := []byte{0xb8, 0x05, 0x00, 0x00, 0x00, 0xc3} // mov $AE_NOT_FOUND, %eax ; ret
			fs.byPfn[pa/page] = append(fs.byPfn[pa/page], edit{fix: name, off: int(pa % page), data: stub, keepEndbr: true})
			note := "acpioff: the kernel will no longer run the old machine's ACPI program"
			if a, b := sym["acpi_gbl_sleep_type_a"], sym["acpi_gbl_sleep_type_b"]; a != 0 && b != 0 && len(s5) == 2 {
				put(name, a, s5[0:1])
				put(name, b, s5[1:2])
				note += fmt.Sprintf("; power-off codes set to the receiver's (%d, %d)", s5[0], s5[1])
			} else {
				note += "; the receiver's power-off codes are not known, so power-off from inside may not work"
			}
			fs.notes = append(fs.notes, note)
		case "acpiports":
			at := sym["acpi_gbl_FADT"]
			if at == 0 || len(fadt) < 116 {
				fs.notes = append(fs.notes, "acpiports: skipped, the kernel does not name its ACPI table copy or the receiver sent none")
				continue
			}
			// One register block: the 64-bit description if the table has one, else built from the 32-bit field.
			block := func(xoff, off32, lenoff int) []byte {
				if len(fadt) >= xoff+12 && binary.LittleEndian.Uint64(fadt[xoff+4:]) != 0 {
					return fadt[xoff : xoff+12]
				}
				g := make([]byte, 12)
				if a := binary.LittleEndian.Uint32(fadt[off32:]); a != 0 {
					g[0], g[1] = 1, fadt[lenoff]*8 // I/O port space, width in bits
					binary.LittleEndian.PutUint64(g[4:], uint64(a))
				}
				return g
			}
			put(name, at+56, fadt[56:94]) // the 32-bit register addresses and their lengths
			if len(fadt) >= 129 {
				put(name, at+112, fadt[112:129]) // flags, reset register and value
			}
			for _, r := range [][3]int{{148, 56, 88}, {160, 60, 88}, {172, 64, 89}, {184, 68, 89}, {196, 72, 90}, {208, 76, 91}, {220, 80, 92}, {232, 84, 93}} {
				put(name, at+uint64(r[0]), block(r[0], r[1], r[2]))
			}
			// The event block is used as two halves: status, then enable.
			half := fadt[88] / 2
			for _, r := range []struct {
				x, off32 int
				st, en   string
			}{{148, 56, "acpi_gbl_xpm1a_status", "acpi_gbl_xpm1a_enable"}, {160, 60, "acpi_gbl_xpm1b_status", "acpi_gbl_xpm1b_enable"}} {
				b := block(r.x, r.off32, 88)
				addr := binary.LittleEndian.Uint64(b[4:])
				for i, s := range []string{r.st, r.en} {
					if sym[s] == 0 {
						continue
					}
					g := make([]byte, 12)
					if addr != 0 {
						g[0], g[1] = b[0], half*8
						binary.LittleEndian.PutUint64(g[4:], addr+uint64(i)*uint64(half))
					}
					put(name, sym[s], g)
				}
			}
			if t := sym["pmtmr_ioport"]; t != 0 {
				put(name, t, fadt[76:80])
			}
			fs.notes = append(fs.notes, fmt.Sprintf("acpiports: the kernel's ACPI register addresses will be the receiver's (power control at port %#x)",
				binary.LittleEndian.Uint32(fadt[64:])))
		case "settle":
			fs.notes = append(fs.notes, settleFix(putPA))
		case "kvm":
			n, c := kvmFix(putPA)
			fs.notes = append(fs.notes, n...)
			fs.clocks = c
		default:
			return nil, fmt.Errorf("unknown fix %q (bootdata, noacpiirq, efioff, acpioff, acpiports, settle, kvm)", name)
		}
	}
	return fs, nil
}

// settleFix finds the kernel's settle-time constant (ten seconds, as
// milliseconds, loaded for a call to msleep) in the reset path a user-space
// reset request takes, and has it replaced by 50 ms in transit. The reset
// handler of the user-space request is preferred: then only resets this tool
// asks for are shortened, and the kernel's own error handling keeps its waits.
// If the compiler kept the reset helpers separate, the wait is in them, and
// shortening it there shortens it for every reset of a SCSI host until the
// next restart; for virtual controllers that is harmless.
func settleFix(putPA func(string, uint64, []byte)) string {
	syms, addrs, err := allSymbols()
	if err != nil {
		return "settle: skipped, " + err.Error()
	}
	k, err := openKernel(syms)
	if err != nil {
		return "settle: skipped, " + err.Error()
	}
	defer k.close()
	find := func(fn string) []uint64 {
		s, ok := syms[fn]
		if !ok {
			return nil
		}
		end := symbolEnd(addrs, s.addr)
		if end <= s.addr || end-s.addr > 16384 {
			end = s.addr + 16384
		}
		code := make([]byte, end-s.addr)
		if k.read(s.addr, code) != nil {
			return nil
		}
		var at []uint64
		for i := 0; i+6 <= len(code); i++ {
			// mov $10000, %edi ; call ...
			if code[i] == 0xbf && code[i+1] == 0x10 && code[i+2] == 0x27 && code[i+3] == 0 && code[i+4] == 0 && code[i+5] == 0xe8 {
				at = append(at, s.addr+uint64(i)+1)
			}
		}
		return at
	}
	where, at := "the reset path user-space requests take", find("scsi_ioctl_reset")
	if len(at) == 0 {
		where = "the SCSI reset helpers (error handling included)"
		at = append(find("scsi_try_host_reset"), find("scsi_try_bus_reset")...)
	}
	if len(at) == 0 {
		return "settle: skipped, the settle time was not found in this kernel's SCSI code; the first disk access after the move may wait ten seconds"
	}
	pas := make([]uint64, len(at))
	for i, va := range at {
		pa, err := k.verified(va-1, 16) // the whole instruction and what follows, read both ways
		if err != nil {
			return "settle: skipped, " + err.Error()
		}
		pas[i] = pa + 1
	}
	for _, pa := range pas {
		putPA("settle", pa, []byte{50, 0, 0, 0})
	}
	mod := syms["scsi_try_host_reset"].module
	if s, ok := syms["scsi_ioctl_reset"]; ok {
		mod = s.module
	}
	if mod == "" {
		mod = "the kernel"
	}
	return fmt.Sprintf("settle: the ten-second wait after a controller reset becomes 50 ms (%d place(s) in %s, in %s)", len(at), where, mod)
}
