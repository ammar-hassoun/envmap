//go:build linux

package main

// Leaving KVM: corrections for a guest that started on KVM (Proxmox) and lands
// on another hypervisor (ESXi).
//
// A Linux guest that finds KVM at boot switches to KVM's shortcuts:
//
//   - hypercalls (an instruction only KVM answers) to wake a waiting processor,
//     to send interrupts between processors, and to yield; elsewhere that
//     instruction faults and the kernel crashes;
//   - writes to KVM-only processor registers, when a processor comes online
//     and on resume; elsewhere they fault (newer kernels survive the fault
//     with a warning, kernel 3.10 does not);
//   - KVM's clock: pages KVM keeps updated with how to turn the processor's
//     time-stamp counter into nanoseconds. Elsewhere nobody updates them, and
//     the new machine's counter means something else;
//   - flags KVM writes into the guest's memory (this processor was preempted,
//     skip this end-of-interrupt). A stale "preempted" makes the kernel skip
//     flushing that processor's address-translation cache: memory corruption.
//
// So, in transit: the hypercall and register-write routines return at once
// (a waiting processor spins instead of sleeping until kicked); the interrupt
// sender jumps to the kernel's own native one, and the wall-clock reader to
// the real-time clock; the flags are cleared; and KVM's clock pages are
// rewritten by the receiver, just before it restores, to describe its own
// time-stamp counter, continuing from where the clock stood. Every address is
// proved through kmem.verified before anything is written.

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// kvmGuest reports whether this kernel runs with KVM's clock, which it only
// registers when it found KVM at boot.
func kvmGuest() bool {
	b, _ := os.ReadFile("/sys/devices/system/clocksource/clocksource0/available_clocksource")
	return strings.Contains(string(b), "kvm-clock")
}

// symbolsAll is every address of every symbol name (some static functions
// share a name across files).
func symbolsAll() (map[string][]uint64, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string][]uint64{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		p := strings.Fields(sc.Text())
		if len(p) < 3 {
			continue
		}
		a, err := strconv.ParseUint(p[0], 16, 64)
		if err == nil {
			out[p[2]] = append(out[p[2]], a)
		}
	}
	return out, nil
}

func possibleCPUs() int {
	b, _ := os.ReadFile("/sys/devices/system/cpu/possible")
	s := strings.TrimSpace(string(b))
	if i := strings.LastIndexAny(s, "-,"); i >= 0 {
		s = s[i+1:]
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 1
	}
	return n + 1
}

// pvEntry is one processor's KVM clock record, by page frame and offset.
type pvEntry struct {
	pfn uint64
	off int
}

// kvmFix adds the corrections; it returns notes and the clock records for the core.
func kvmFix(putPA func(string, uint64, []byte)) (notes []string, clocks []pvEntry) {
	syms, _, err := allSymbols()
	if err != nil {
		return []string{"kvm: skipped, " + err.Error()}, nil
	}
	all, err := symbolsAll()
	if err != nil {
		return []string{"kvm: skipped, " + err.Error()}, nil
	}
	k, err := openKernel(syms)
	if err != nil {
		return []string{"kvm: skipped, " + err.Error()}, nil
	}
	defer k.close()
	le := binary.LittleEndian
	entry := func(va uint64) (uint64, error) { // a function's first instruction, after a branch-tracking mark
		var b [4]byte
		if err := k.read(va, b[:]); err != nil {
			return 0, err
		}
		if b == [4]byte{0xf3, 0x0f, 0x1e, 0xfa} {
			va += 4
		}
		return va, nil
	}
	var stubbed, jumped []string
	stub := func(name string) {
		s, ok := syms[name]
		if !ok || s.module != "" {
			return
		}
		va, err := entry(s.addr)
		if err != nil {
			return
		}
		pa, err := k.verified(va, 16)
		if err != nil {
			notes = append(notes, "kvm: "+name+": "+err.Error())
			return
		}
		putPA("kvm", pa, []byte{0x31, 0xc0, 0xc3}) // xor %eax,%eax ; ret
		stubbed = append(stubbed, name)
	}
	jump := func(name string, to uint64) {
		s, ok := syms[name]
		if !ok || s.module != "" || to == 0 {
			return
		}
		va, err := entry(s.addr)
		if err != nil {
			return
		}
		pa, err := k.verified(va, 16)
		if err != nil {
			notes = append(notes, "kvm: "+name+": "+err.Error())
			return
		}
		rel := int64(to) - int64(va+5)
		if rel < -(1<<31) || rel >= 1<<31 {
			return
		}
		b := []byte{0xe9, 0, 0, 0, 0} // jmp rel32
		le.PutUint32(b[1:], uint32(int32(rel)))
		putPA("kvm", pa, b)
		jumped = append(jumped, name)
	}

	// Hypercalls and KVM-only register writes: return at once.
	for _, n := range []string{"kvm_kick_cpu", "kvm_wait", "kvm_register_clock", "kvm_setup_secondary_clock",
		"kvm_guest_cpu_init", "kvm_guest_cpu_offline", "kvm_restore_sched_clock_state", "kvm_pv_disable_apf",
		"kvm_disable_steal_time", "kvm_pv_guest_cpu_reboot", "kvm_cpu_online", "kvm_cpu_down_prepare",
		"kvm_sched_yield", "__raw_callee_save___kvm_vcpu_is_preempted", "__kvm_vcpu_is_preempted"} {
		stub(n)
	}
	// The wall clock comes from the real-time clock chip, as on any machine.
	if a := syms["mach_get_cmos_time"].addr; a != 0 {
		jump("kvm_get_wallclock", a)
	}
	// Interrupts between processors: back to the kernel's own sender.
	if _, pv := syms["kvm_send_ipi_mask"]; pv {
		mask, allbut := nativeIPI(k, syms, all)
		if mask == 0 || allbut == 0 {
			notes = append(notes, "kvm: the kernel's own interrupt sender was not found; refusing to move a guest that sends interrupts through KVM")
			return notes, nil
		}
		jump("kvm_send_ipi_mask", mask)
		jump("kvm_send_ipi_mask_allbutself", allbut)
	}
	// Flags KVM writes into the guest's memory, per processor: cleared.
	cpus := possibleCPUs()
	if pco, ok := syms["__per_cpu_offset"]; ok {
		clear := func(name string, off, n int) {
			v, ok := syms[name]
			if !ok {
				return
			}
			for c := 0; c < cpus; c++ {
				base, err := k.u64(pco.addr + uint64(c)*8)
				if err != nil {
					return
				}
				pa, err := k.verified(base+v.addr+uint64(off), n)
				if err != nil {
					notes = append(notes, "kvm: "+name+": "+err.Error())
					return
				}
				putPA("kvm", pa, make([]byte, n))
			}
		}
		clear("steal_time", 16, 1)  // the "preempted" byte
		clear("kvm_apic_eoi", 0, 8) // "skip this end-of-interrupt"
		clear("apf_reason", 0, 8)   // async page fault flags and token
	}
	// KVM's clock records: found here, rewritten by the receiver.
	var recs []uint64
	if per, ok := syms["hv_clock_per_cpu"]; ok {
		if pco, ok := syms["__per_cpu_offset"]; ok {
			for c := 0; c < cpus; c++ {
				base, err := k.u64(pco.addr + uint64(c)*8)
				if err != nil {
					break
				}
				p, err := k.u64(base + per.addr)
				if err != nil || p == 0 {
					continue
				}
				recs = append(recs, p)
			}
		}
	} else if b, ok := syms["hv_clock_boot"]; ok {
		for c := 0; c < cpus && c < 64; c++ {
			recs = append(recs, b.addr+uint64(c)*64)
		}
	} else if h, ok := syms["hv_clock"]; ok { // 3.10: a pointer to the array
		if p, err := k.u64(h.addr); err == nil && p != 0 {
			for c := 0; c < cpus; c++ {
				recs = append(recs, p+uint64(c)*64)
			}
		}
	}
	for _, va := range recs {
		pa, err := k.verified(va, 32)
		if err != nil {
			notes = append(notes, "kvm: clock record: "+err.Error())
			continue
		}
		clocks = append(clocks, pvEntry{pa / page, int(pa % page)})
	}
	notes = append(notes, fmt.Sprintf("kvm: %d KVM-only routines return at once, %d sent to the kernel's own, per-processor KVM flags cleared, %d clock records to be set by the receiver",
		len(stubbed), len(jumped), len(clocks)))
	return notes, clocks
}

// nativeIPI finds the kernel's own interrupt senders for the processor
// interrupt controller in use, which KVM's shortcuts replaced at boot. Some
// carry the same name in several files; the one in the same file as the
// controller's single-processor sender, which KVM left alone, is the one.
func nativeIPI(k *kernelMem, syms map[string]ksym, all map[string][]uint64) (mask, allbut uint64) {
	ap, ok := syms["apic"]
	if !ok {
		return 0, 0
	}
	drv, err := k.u64(ap.addr)
	if err != nil || drv == 0 {
		return 0, 0
	}
	body := make([]byte, 1024)
	if k.read(drv, body) != nil {
		return 0, 0
	}
	ptrs := map[uint64]bool{}
	for i := 0; i+8 <= len(body); i += 8 {
		ptrs[binary.LittleEndian.Uint64(body[i:])] = true
	}
	near := func(name string, anchor uint64) uint64 {
		var best, dist uint64
		for _, a := range all[name] {
			d := a - anchor
			if a < anchor {
				d = anchor - a
			}
			if best == 0 || d < dist {
				best, dist = a, d
			}
		}
		return best
	}
	for _, kind := range []struct{ one, mask, allbut string }{
		{"x2apic_send_IPI", "x2apic_send_IPI_mask", "x2apic_send_IPI_mask_allbutself"},
		{"default_send_IPI_single_phys", "default_send_IPI_mask_sequence_phys", "default_send_IPI_mask_allbutself_phys"},
		{"default_send_IPI_single", "default_send_IPI_mask_logical", "default_send_IPI_mask_allbutself_logical"},
	} {
		for _, a := range all[kind.one] {
			if ptrs[a] {
				return near(kind.mask, a), near(kind.allbut, a)
			}
		}
	}
	return 0, 0
}

// timeScale is KVM's own way of turning a counter frequency into the
// multiplier and shift its clock records hold.
func timeScale(hz uint64) (mul uint32, shift int8) {
	scaled := uint64(1_000_000_000)
	tps := hz
	for tps > scaled*2 || tps&0xffffffff00000000 != 0 {
		tps >>= 1
		shift--
	}
	tps32 := uint32(tps)
	for uint64(tps32) <= scaled || scaled&0xffffffff00000000 != 0 {
		if scaled&0xffffffff00000000 != 0 || tps32&0x80000000 != 0 {
			scaled >>= 1
		} else {
			tps32 <<= 1
		}
		shift++
	}
	return uint32((scaled << 32) / uint64(tps32)), shift
}

// tscHz is this machine's time-stamp counter frequency, as its kernel measured it.
func tscHz() uint64 {
	best := uint64(0)
	if b, err := readKmsg(); err == nil {
		for _, line := range strings.Split(b, "\n") {
			for _, key := range []string{"Refined TSC clocksource calibration: ", "tsc: Detected "} {
				if i := strings.Index(line, key); i >= 0 {
					v := line[i+len(key):]
					if j := strings.Index(v, " MHz"); j > 0 {
						if mhz, err := strconv.ParseFloat(v[:j], 64); err == nil {
							best = uint64(mhz * 1e6)
						}
					}
				}
			}
		}
	}
	if best == 0 {
		b, _ := os.ReadFile("/proc/cpuinfo")
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "cpu MHz") {
				if mhz, err := strconv.ParseFloat(strings.TrimSpace(line[strings.Index(line, ":")+1:]), 64); err == nil {
					return uint64(mhz * 1e6)
				}
			}
		}
	}
	return best
}

// readKmsg reads the kernel's log without waiting for more. Plain system
// calls: Go's own files wait for more data on a non-blocking device instead
// of returning, and /dev/kmsg always has more to come (it hung the generic
// receiver once).
func readKmsg() (string, error) {
	fd, err := syscall.Open("/dev/kmsg", syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)
	var sb strings.Builder
	buf := make([]byte, 8192)
	for i := 0; i < 1<<16; i++ {
		n, err := syscall.Read(fd, buf)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EPIPE { // a record was overwritten while reading: carry on
			continue
		}
		if err != nil || n <= 0 {
			break
		}
		sb.Write(buf[:n])
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}
