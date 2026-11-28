/*
 * envmove-core: the part of EnvMap Move that runs while the system is frozen.
 *
 * Why it is separate, and why it is C with no C library:
 * after the freeze this program is the only thing running, and of its threads
 * only the one that asked for the freeze. A program with a runtime (Go, or a
 * C library with its own locks) has helper threads or shared locks; one of
 * them frozen, or a lock copied into a forked child while another thread held
 * it, can stop this program for good while the whole system waits on it. This
 * one has one thread, no locks, no allocator but a fixed arena, and talks to
 * the kernel with plain system calls. The Go program prepares everything
 * beforehand and hands it a plan; this program only carries it out.
 *
 *   envmove-core leave     fd 3 /dev/snapshot (read), fd 4 the plan, fd 5 a gate
 *   envmove-core restore   fd 3 /dev/snapshot (write), fd 4 the plan, fd 5 a gate,
 *                          fd 6 the connection the image arrives on
 *   envmove-core selftest  checks its own pieces and prints what it finds
 *
 * The gate: the parent holds its own copy of /dev/snapshot until this program
 * runs, then closes it and the gate. Only then does this program start, so it
 * is the only holder: if it dies for any reason, the kernel closes the device
 * and thaws the system by itself.
 */
#include <stdarg.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef long i64;

#define PAGE 4096

/* ---------------------------------------------------------------- system calls */

static inline long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long r10 __asm__("r10") = d;
	register long r8 __asm__("r8") = e;
	register long r9 __asm__("r9") = f;
	long ret;
	__asm__ volatile("syscall"
			 : "=a"(ret)
			 : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
			 : "rcx", "r11", "memory");
	return ret;
}
#define SYS(n, a, b, c) sys6(n, (long)(a), (long)(b), (long)(c), 0, 0, 0)

enum {
	NR_read = 0, NR_write = 1, NR_open = 2, NR_close = 3, NR_ioctl = 16, NR_pread = 17,
	NR_nanosleep = 35, NR_getpid = 39, NR_socket = 41, NR_connect = 42, NR_fork = 57,
	NR_execve = 59, NR_wait4 = 61, NR_kill = 62, NR_uname = 63, NR_chdir = 80,
	NR_readlink = 89, NR_mlockall = 151, NR_mount = 165, NR_umount2 = 166, NR_reboot = 169,
	NR_getdents64 = 217, NR_clock_gettime = 228, NR_exit_group = 231, NR_dup3 = 292,
};

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_NONBLOCK 0x800
#define O_DIRECTORY 0x10000
#define O_CLOEXEC 0x80000

#define EINTR 4
#define EBUSY 16
#define EEXIST 17

static long sread(int fd, void *b, u64 n) { return SYS(NR_read, fd, b, n); }
static long swrite(int fd, const void *b, u64 n) { return SYS(NR_write, fd, b, n); }
static long sopen(const char *p, int fl) { return SYS(NR_open, p, fl, 0); }
static long sclose(int fd) { return SYS(NR_close, fd, 0, 0); }
static long sioctl(int fd, u64 req, void *arg) { return SYS(NR_ioctl, fd, req, arg); }
static long spread(int fd, void *b, u64 n, u64 off) { return sys6(NR_pread, fd, (long)b, n, off, 0, 0); }

static __attribute__((noreturn)) void sexit(int code)
{
	for (;;)
		SYS(NR_exit_group, code, 0, 0);
}

static void nap(int ms)
{
	long ts[2] = {ms / 1000, (long)(ms % 1000) * 1000000};
	while (SYS(NR_nanosleep, ts, ts, 0) == -EINTR)
		;
}

static u64 now_ms(void)
{
	long ts[2];
	SYS(NR_clock_gettime, 1, ts, 0); /* CLOCK_MONOTONIC */
	return (u64)ts[0] * 1000 + (u64)ts[1] / 1000000;
}

/* --------------------------------------------- what the compiler may call itself */

void *memcpy(void *d, const void *s, u64 n)
{
	u8 *a = d;
	const u8 *b = s;
	while (n--)
		*a++ = *b++;
	return d;
}
void *memmove(void *d, const void *s, u64 n)
{
	u8 *a = d;
	const u8 *b = s;
	if (a < b) {
		while (n--)
			*a++ = *b++;
	} else {
		a += n;
		b += n;
		while (n--)
			*--a = *--b;
	}
	return d;
}
void *memset(void *d, int c, u64 n)
{
	u8 *a = d;
	while (n--)
		*a++ = (u8)c;
	return d;
}
int memcmp(const void *x, const void *y, u64 n)
{
	const u8 *a = x, *b = y;
	for (; n; n--, a++, b++)
		if (*a != *b)
			return *a - *b;
	return 0;
}

/* --------------------------------------------------------------------- strings */

static u64 slen(const char *s)
{
	u64 n = 0;
	while (s[n])
		n++;
	return n;
}
static int scmp(const char *a, const char *b)
{
	while (*a && *a == *b)
		a++, b++;
	return (u8)*a - (u8)*b;
}
static int seq(const char *a, const char *b) { return scmp(a, b) == 0; }
static int spre(const char *s, const char *p)
{
	while (*p)
		if (*s++ != *p++)
			return 0;
	return 1;
}
/* scpy copies at most n-1 bytes and always ends the string. */
static void scpy(char *d, const char *s, u64 n)
{
	u64 i = 0;
	for (; s[i] && i + 1 < n; i++)
		d[i] = s[i];
	d[i] = 0;
}
/* join builds a path from up to four pieces into d (size n). */
static char *join(char *d, u64 n, const char *a, const char *b, const char *c, const char *e)
{
	u64 o = 0;
	const char *p[4] = {a, b, c, e};
	for (int i = 0; i < 4; i++)
		for (const char *s = p[i]; s && *s && o + 1 < n; s++)
			d[o++] = *s;
	d[o] = 0;
	return d;
}
static const char *base(const char *p)
{
	const char *b = p;
	for (; *p; p++)
		if (*p == '/')
			b = p + 1;
	return b;
}
static void trim(char *s)
{
	u64 n = slen(s);
	while (n && (s[n - 1] == '\n' || s[n - 1] == ' ' || s[n - 1] == '\r' || s[n - 1] == '\t'))
		s[--n] = 0;
}
static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}
static u64 pnum(const char *s)
{
	u64 v = 0;
	if (s[0] == '0' && s[1] == 'x') {
		for (s += 2; hexval(*s) >= 0; s++)
			v = v * 16 + (u64)hexval(*s);
		return v;
	}
	for (; *s >= '0' && *s <= '9'; s++)
		v = v * 10 + (u64)(*s - '0');
	return v;
}
static long unhex(const char *s, u8 *out, u64 max)
{
	u64 n = 0;
	for (; s[0] && s[1] && n < max; s += 2) {
		int a = hexval(s[0]), b = hexval(s[1]);
		if (a < 0 || b < 0)
			return -1;
		out[n++] = (u8)(a * 16 + b);
	}
	return (long)n;
}

/* ---------------------------------------------------------------------- output */

static char obuf[8192];
static int olen;

static void oflush(void)
{
	int o = 0;
	while (o < olen) {
		long k = swrite(1, obuf + o, (u64)(olen - o));
		if (k == -EINTR)
			continue;
		if (k <= 0)
			break;
		o += (int)k;
	}
	olen = 0;
}
static void oc(char c)
{
	if (olen >= (int)sizeof obuf)
		oflush();
	obuf[olen++] = c;
}
static void os_(const char *s)
{
	while (*s)
		oc(*s++);
}
static void ou(u64 v)
{
	char b[24];
	int i = 0;
	do
		b[i++] = (char)('0' + v % 10);
	while (v /= 10);
	while (i)
		oc(b[--i]);
}
static void ox(u64 v, int w)
{
	char b[20];
	int i = 0;
	do
		b[i++] = "0123456789abcdef"[v & 15];
	while (v >>= 4);
	while (i < w)
		b[i++] = '0';
	while (i)
		oc(b[--i]);
}

static const char *errname(long e)
{
	switch (-e) {
	case 1: return "operation not permitted";
	case 2: return "no such file or directory";
	case 4: return "interrupted";
	case 5: return "input/output error";
	case 6: return "no such device or address";
	case 9: return "bad file descriptor";
	case 11: return "resource temporarily unavailable";
	case 12: return "cannot allocate memory";
	case 13: return "permission denied";
	case 16: return "device or resource busy";
	case 17: return "file exists";
	case 19: return "no such device";
	case 22: return "invalid argument";
	case 28: return "no space left on device";
	case 32: return "broken pipe";
	case 101: return "network is unreachable";
	case 104: return "connection reset by peer";
	case 110: return "connection timed out";
	case 111: return "connection refused";
	case 113: return "no route to host";
	}
	return "error";
}

/*
 * pr prints one message with one write, so it is never mixed with the
 * kernel's own lines. %s string, %u unsigned, %U 64-bit unsigned, %d int,
 * %x hex, %X 64-bit hex, %b a byte as two hex digits, %e an error number.
 */
static void pr(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	for (; *f; f++) {
		if (*f != '%') {
			oc(*f);
			continue;
		}
		switch (*++f) {
		case 's': os_(va_arg(ap, const char *)); break;
		case 'u': ou(va_arg(ap, unsigned)); break;
		case 'U': ou(va_arg(ap, u64)); break;
		case 'd': {
			int v = va_arg(ap, int);
			if (v < 0) {
				oc('-');
				v = -v;
			}
			ou((u64)v);
			break;
		}
		case 'x': ox(va_arg(ap, unsigned), 0); break;
		case 'X': ox(va_arg(ap, u64), 0); break;
		case 'b': ox(va_arg(ap, unsigned) & 0xff, 2); break;
		case 'e': os_(errname(va_arg(ap, long))); break;
		case '%': oc('%'); break;
		default: oc('?');
		}
	}
	va_end(ap);
	oflush();
}

/* ----------------------------------------------------------------------- arena */

static u8 arena[12 << 20] __attribute__((aligned(4096)));
static u64 atop;

static void *alloc(u64 n)
{
	n = (n + 15) & ~15UL;
	if (atop + n > sizeof arena) {
		pr("envmove: the frozen part ran out of its fixed memory\n");
		sexit(4); /* the kernel thaws the system when this process ends */
	}
	void *p = arena + atop;
	atop += n;
	return p;
}
static char *sdup(const char *s)
{
	u64 n = slen(s) + 1;
	char *d = alloc(n);
	memcpy(d, s, n);
	return d;
}

/* -------------------------------------------------------------- files and dirs */

static long rdall(int fd, u8 *b, u64 n)
{
	u64 got = 0;
	while (got < n) {
		long k = sread(fd, b + got, n - got);
		if (k == -EINTR)
			continue;
		if (k < 0)
			return k;
		if (k == 0)
			break;
		got += (u64)k;
	}
	return (long)got;
}
static long wrall(int fd, const u8 *b, u64 n)
{
	while (n) {
		long k = swrite(fd, b, n);
		if (k == -EINTR)
			continue;
		if (k < 0)
			return k;
		if (k == 0)
			return -5;
		b += k;
		n -= (u64)k;
	}
	return 0;
}
/* readfile reads a small file into b (size n), ends it, and trims the newline. */
static long readfile(const char *path, char *b, u64 n)
{
	long fd = sopen(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		b[0] = 0;
		return fd;
	}
	long k = rdall((int)fd, (u8 *)b, n - 1);
	sclose((int)fd);
	if (k < 0) {
		b[0] = 0;
		return k;
	}
	b[k] = 0;
	trim(b);
	return k;
}
static long writefile(const char *path, const char *s)
{
	long fd = sopen(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return fd;
	long r = wrall((int)fd, (const u8 *)s, slen(s));
	sclose((int)fd);
	return r;
}
static u64 readu(const char *path)
{
	char b[64];
	readfile(path, b, sizeof b);
	return pnum(b);
}
static int exists(const char *path)
{
	long fd = sopen(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return fd != -2;
	sclose((int)fd);
	return 1;
}
static long rlink(const char *path, char *b, u64 n)
{
	long k = SYS(NR_readlink, path, b, n - 1);
	if (k < 0) {
		b[0] = 0;
		return k;
	}
	b[k] = 0;
	return k;
}

/* dirlist returns the names in a directory, sorted, skipping "." and "..". */
static int dirlist(const char *path, char ***names)
{
	long fd = sopen(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	*names = 0;
	if (fd < 0)
		return 0;
	int cap = 64, n = 0;
	char **v = alloc(sizeof(char *) * (u64)cap);
	static u8 buf[16384];
	for (;;) {
		long k = SYS(NR_getdents64, fd, buf, sizeof buf);
		if (k <= 0)
			break;
		for (long o = 0; o < k;) {
			u16 reclen = *(u16 *)(buf + o + 16);
			const char *nm = (const char *)(buf + o + 19);
			if (!seq(nm, ".") && !seq(nm, "..")) {
				if (n == cap) {
					char **w = alloc(sizeof(char *) * (u64)cap * 2);
					memcpy(w, v, sizeof(char *) * (u64)cap);
					v = w;
					cap *= 2;
				}
				v[n++] = sdup(nm);
			}
			o += reclen;
		}
	}
	sclose((int)fd);
	for (int i = 1; i < n; i++)
		for (int j = i; j > 0 && scmp(v[j - 1], v[j]) > 0; j--) {
			char *t = v[j];
			v[j] = v[j - 1];
			v[j - 1] = t;
		}
	*names = v;
	return n;
}

/* ---------------------------------------------------------------------- SHA-256 */

static const u32 K256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(u32 h[8], const u8 *p)
{
	u32 w[64];
	for (int i = 0; i < 16; i++)
		w[i] = (u32)p[4 * i] << 24 | (u32)p[4 * i + 1] << 16 | (u32)p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		u32 s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		u32 s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	u32 a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
	for (int i = 0; i < 64; i++) {
		u32 t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
		u32 t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	h[0] += a, h[1] += b, h[2] += c, h[3] += d, h[4] += e, h[5] += f, h[6] += g, h[7] += hh;
}

static void sha256(const u8 *p, u64 n, u8 out[32])
{
	u32 h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	u64 i = 0;
	for (; i + 64 <= n; i += 64)
		sha256_block(h, p + i);
	u8 t[128];
	u64 r = n - i;
	memset(t, 0, sizeof t);
	memcpy(t, p + i, r);
	t[r] = 0x80;
	u64 blocks = r + 9 > 64 ? 2 : 1;
	u64 bits = n * 8;
	for (int k = 0; k < 8; k++)
		t[blocks * 64 - 1 - k] = (u8)(bits >> (8 * k));
	for (u64 k = 0; k < blocks; k++)
		sha256_block(h, t + 64 * k);
	for (int k = 0; k < 8; k++)
		out[4 * k] = (u8)(h[k] >> 24), out[4 * k + 1] = (u8)(h[k] >> 16), out[4 * k + 2] = (u8)(h[k] >> 8), out[4 * k + 3] = (u8)h[k];
}

/* ------------------------------------------------------------- fingerprints */

#define P1 0x9E3779B185EBCA87UL
#define P2 0xC2B2AE3D27D4EB4FUL
#define P3 0x165667B19E3779F9UL
#define P4 0x85EBCA77C2B2AE63UL
#define ROL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

static u64 xxround(u64 acc, u64 in) { return ROL64(acc + in * P2, 31) * P1; }
static u64 xxmerge(u64 acc, u64 v) { return (acc ^ xxround(0, v)) * P1 + P4; }

/* XXH64 of one page (the same as the Go part's). */
static u64 xxh64page(const u8 *b, u64 seed)
{
	u64 v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
	for (int i = 0; i < PAGE; i += 32) {
		v1 = xxround(v1, *(const u64 *)(b + i));
		v2 = xxround(v2, *(const u64 *)(b + i + 8));
		v3 = xxround(v3, *(const u64 *)(b + i + 16));
		v4 = xxround(v4, *(const u64 *)(b + i + 24));
	}
	u64 h = ROL64(v1, 1) + ROL64(v2, 7) + ROL64(v3, 12) + ROL64(v4, 18);
	h = xxmerge(h, v1);
	h = xxmerge(h, v2);
	h = xxmerge(h, v3);
	h = xxmerge(h, v4);
	h += PAGE;
	h ^= h >> 33;
	h *= P2;
	h ^= h >> 29;
	h *= P3;
	h ^= h >> 32;
	return h;
}

static void *smmap(int fd, u64 len, int write)
{
	long r = sys6(9, 0, (long)len, write ? 3 : 1, 1, fd, 0); /* MAP_SHARED */
	return r < 0 && r > -4096 ? 0 : (void *)r;
}

/* ------------------------------------------------------------------ PCI devices */

#define PCIROOT "/sys/bus/pci/devices"

struct pcidev {
	char addr[16];
	char rem[12]; /* vendor:device the kernel holds */
	char live[12]; /* vendor:device the hardware answers now */
	char drv[40];
};

static int pcilist(struct pcidev **out)
{
	char **names;
	int n = dirlist(PCIROOT, &names);
	struct pcidev *d = alloc(sizeof(struct pcidev) * (u64)(n ? n : 1));
	for (int i = 0; i < n; i++) {
		char p[256], v[32], dv[32];
		struct pcidev *x = &d[i];
		scpy(x->addr, names[i], sizeof x->addr);
		readfile(join(p, sizeof p, PCIROOT "/", names[i], "/vendor", 0), v, sizeof v);
		readfile(join(p, sizeof p, PCIROOT "/", names[i], "/device", 0), dv, sizeof dv);
		join(x->rem, sizeof x->rem, spre(v, "0x") ? v + 2 : v, ":", spre(dv, "0x") ? dv + 2 : dv, 0);
		scpy(x->live, "none", sizeof x->live);
		long fd = sopen(join(p, sizeof p, PCIROOT "/", names[i], "/config", 0), O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			u8 id[4];
			if (spread((int)fd, id, 4, 0) == 4) {
				const char *hx = "0123456789abcdef";
				char *l = x->live;
				l[0] = hx[id[1] >> 4], l[1] = hx[id[1] & 15], l[2] = hx[id[0] >> 4], l[3] = hx[id[0] & 15], l[4] = ':';
				l[5] = hx[id[3] >> 4], l[6] = hx[id[3] & 15], l[7] = hx[id[2] >> 4], l[8] = hx[id[2] & 15], l[9] = 0;
			}
			sclose((int)fd);
		}
		char lk[256];
		x->drv[0] = 0;
		if (rlink(join(p, sizeof p, PCIROOT "/", names[i], "/driver", 0), lk, sizeof lk) > 0)
			scpy(x->drv, base(lk), sizeof x->drv);
	}
	*out = d;
	return n;
}

static void pciprint(struct pcidev *d, int n)
{
	for (int i = 0; i < n; i++)
		pr("%s %s %s %s%s\n", d[i].addr, d[i].rem, d[i].live, d[i].drv, seq(d[i].rem, d[i].live) ? "" : "  <- changed");
}

static long pciremove(const char *addr)
{
	char p[256];
	return writefile(join(p, sizeof p, PCIROOT "/", addr, "/remove", 0), "1");
}

static int inlist(const char *s, char **v, int n)
{
	for (int i = 0; i < n; i++)
		if (seq(s, v[i]))
			return 1;
	return 0;
}

/* letgo detaches every device that has a driver, except the ones to keep, and
 * waits until they are really gone. Kernels before 3.14 remove a PCI device
 * later, in a worker, and answer "try again" to a second request for one whose
 * removal is already on its way; the memory image must not be taken with a
 * device half removed. */
static long letgo(char **keep, int nkeep)
{
	u64 mark = atop;
	struct pcidev *d;
	int n = pcilist(&d);
	char msg[2048];
	u64 m = 0;
	msg[0] = 0;
	char **gone = alloc(sizeof(char *) * (u64)(n ? n : 1));
	int ng = 0;
	for (int i = n - 1; i >= 0; i--) {
		if (!d[i].drv[0] || inlist(d[i].addr, keep, nkeep))
			continue;
		long r = pciremove(d[i].addr);
		if (r < 0 && r != -11) { /* EAGAIN: its removal is already on its way */
			pr("envmove: %s (%s): %e\n", d[i].addr, d[i].drv, r);
			atop = mark;
			return r;
		}
		gone[ng++] = d[i].addr;
		char item[96];
		join(item, sizeof item, m ? ", " : "", d[i].addr, " ", d[i].drv);
		for (const char *s = item; *s && m + 1 < sizeof msg; s++)
			msg[m++] = *s;
		msg[m] = 0;
	}
	for (int waited = 0;; waited++) {
		int left = 0;
		for (int i = 0; i < ng; i++) {
			char p[256];
			if (exists(join(p, sizeof p, PCIROOT "/", gone[i], 0, 0)))
				left++;
		}
		if (!left)
			break;
		if (waited >= 200) {
			pr("envmove: %d device(s) did not finish leaving in 20 s\n", left);
			atop = mark;
			return -16;
		}
		nap(100);
	}
	pr("let go of: %s\n", msg);
	atop = mark;
	return 0;
}

static void rescan(void) { writefile("/sys/bus/pci/rescan", "1"); }

/* refresh drops every device that is no longer what the kernel remembers,
 * then asks the kernel to look at the bus again. */
static long refresh(void)
{
	u64 mark = atop;
	struct pcidev *d;
	int n = pcilist(&d);
	for (int i = n - 1; i >= 0; i--) {
		if (seq(d[i].rem, d[i].live))
			continue;
		char p[256];
		u8 c[12];
		long fd = sopen(join(p, sizeof p, PCIROOT "/", d[i].addr, "/config", 0), O_RDONLY | O_CLOEXEC);
		int got = fd >= 0 && spread((int)fd, c, 12, 0) == 12;
		if (fd >= 0)
			sclose((int)fd);
		if (got && c[0x0b] == 1 && ((seq(d[i].drv, "nvme") && c[0x0a] == 8) || (seq(d[i].drv, "ahci") && c[0x0a] == 6))) {
			/* NVMe and SATA drivers talk to a standard interface, whoever made
			 * the controller: another maker's controller of the same kind at the
			 * same address is still theirs to drive. */
			pr("kept %s (%s, now %s): %s drives it by its standard interface\n", d[i].addr, d[i].rem, d[i].live, d[i].drv);
			continue;
		}
		if (d[i].drv[0]) {
			pr("refresh: %s changed from %s to %s while %s is still attached; detach it before the move\n",
			   d[i].addr, d[i].rem, d[i].live, d[i].drv);
			atop = mark;
			return -22;
		}
		long r = pciremove(d[i].addr);
		if (r < 0) {
			pr("refresh: %s: %e\n", d[i].addr, r);
			atop = mark;
			return r;
		}
		pr("forgot %s (%s, now %s)\n", d[i].addr, d[i].rem, d[i].live);
	}
	rescan();
	n = pcilist(&d);
	pciprint(d, n);
	atop = mark;
	return 0;
}

/* kick tells every disk controller still attached to reset itself and set its
 * queues up again (a controller kept through a move is, on the new machine, a
 * fresh device that knows nothing of the queues its driver believes in). */
static void kick(void)
{
	char **hosts;
	int nh = dirlist("/sys/class/scsi_host", &hosts), done = 0;
	for (int i = 0; i < nh; i++) {
		char p[256], disk[64] = "";
		char **tg;
		int nt = dirlist(join(p, sizeof p, "/sys/class/scsi_host/", hosts[i], "/device", 0), &tg);
		for (int t = 0; t < nt && !disk[0]; t++) {
			if (!spre(tg[t], "target"))
				continue;
			char tp[256];
			char **lu;
			int nl = dirlist(join(tp, sizeof tp, p, "/", tg[t], 0), &lu);
			for (int l = 0; l < nl && !disk[0]; l++) {
				char bp[320];
				char **bl;
				join(bp, sizeof bp, tp, "/", lu[l], "/block");
				if (dirlist(bp, &bl) > 0)
					scpy(disk, bl[0], sizeof disk);
			}
		}
		if (!disk[0])
			continue;
		char drv[64];
		readfile(join(p, sizeof p, "/sys/class/scsi_host/", hosts[i], "/proc_name", 0), drv, sizeof drv);
		long fd = sopen(join(p, sizeof p, "/dev/", disk, 0, 0), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (fd < 0) {
			pr("%s (%s, %s): cannot open: %e\n", hosts[i], drv, disk, fd);
			continue;
		}
		int val = 3; /* SG_SCSI_RESET_HOST */
		long r = sioctl((int)fd, 0x2284, &val);
		sclose((int)fd);
		if (r < 0) {
			pr("%s (%s, %s): reset not done: %e\n", hosts[i], drv, disk, r);
			continue;
		}
		pr("%s (%s, %s): controller reset and set up again\n", hosts[i], drv, disk);
		done++;
	}
	char **ctrl;
	int nc = dirlist("/sys/class/nvme", &ctrl);
	for (int i = 0; i < nc; i++) {
		char p[256];
		long r = writefile(join(p, sizeof p, "/sys/class/nvme/", ctrl[i], "/reset_controller", 0), "1");
		if (r < 0) {
			pr("%s (nvme): reset not done: %e\n", ctrl[i], r);
			continue;
		}
		pr("%s (nvme): controller reset and set up again\n", ctrl[i]);
		done++;
	}
	if (!done)
		pr("no disk controller was reset\n");
}

/* ------------------------------------------------------------- network cards */

struct netid {
	char name[16];
	u8 mac[6];
	u8 ip[4], mask[4], gw[4];
};

static int ctlsock(void) { return (int)SYS(NR_socket, 2, 2, 0); } /* AF_INET, SOCK_DGRAM */

static int ifnameat(int s, int idx, char *name)
{
	u8 r[40];
	memset(r, 0, sizeof r);
	*(int *)(r + 16) = idx;
	if (sioctl(s, 0x8910, r) < 0)
		return 0;
	scpy(name, (char *)r, 16);
	return 1;
}
static int ifmac(int s, const char *name, u8 mac[6])
{
	u8 r[40];
	memset(r, 0, sizeof r);
	scpy((char *)r, name, 16);
	if (sioctl(s, 0x8927, r) < 0)
		return 0;
	memcpy(mac, r + 18, 6);
	return 1;
}
static int ifbymac(int s, const u8 mac[6], char *name)
{
	for (int i = 1; i <= 256; i++) {
		char n[16];
		u8 m[6];
		if (ifnameat(s, i, n) && !seq(n, "lo") && ifmac(s, n, m) && memcmp(m, mac, 6) == 0) {
			scpy(name, n, 16);
			return 1;
		}
	}
	return 0;
}
static long ifflags_up(int s, const char *name)
{
	u8 r[40];
	memset(r, 0, sizeof r);
	scpy((char *)r, name, 16);
	long e = sioctl(s, 0x8913, r);
	if (e < 0)
		return e;
	*(u16 *)(r + 16) |= 1;
	return sioctl(s, 0x8914, r);
}
static long ifset(int s, const char *name, u64 req, const u8 a[4])
{
	u8 r[40];
	memset(r, 0, sizeof r);
	scpy((char *)r, name, 16);
	*(u16 *)(r + 16) = 2; /* AF_INET */
	memcpy(r + 20, a, 4);
	return sioctl(s, req, r);
}
static long ifrename(int s, const char *from, const char *to)
{
	u8 r[40];
	memset(r, 0, sizeof r);
	scpy((char *)r, from, 16);
	scpy((char *)r + 16, to, 16);
	return sioctl(s, 0x8923, r);
}
static long routedefault(int s, const u8 gw[4])
{
	u8 rt[120];
	memset(rt, 0, sizeof rt);
	*(u16 *)(rt + 8) = 2;
	*(u16 *)(rt + 24) = 2;
	memcpy(rt + 28, gw, 4);
	*(u16 *)(rt + 40) = 2;
	*(u16 *)(rt + 56) = 1 | 2;
	return sioctl(s, 0x890B, rt);
}
static long ifconfigure(int s, const char *name, const struct netid *id)
{
	long e;
	if ((e = ifset(s, name, 0x8916, id->ip)) < 0)
		return e;
	if ((e = ifset(s, name, 0x891c, id->mask)) < 0)
		return e;
	if ((e = ifflags_up(s, name)) < 0)
		return e;
	if (id->gw[0] | id->gw[1] | id->gw[2] | id->gw[3]) {
		e = routedefault(s, id->gw);
		if (e < 0 && e != -EEXIST)
			return e;
	}
	return 0;
}
static long routehost(int s, const u8 dst[4], const u8 gw[4], int add)
{
	u8 rt[120];
	memset(rt, 0, sizeof rt);
	*(u16 *)(rt + 8) = 2;
	memcpy(rt + 12, dst, 4);
	*(u16 *)(rt + 24) = 2;
	memcpy(rt + 28, gw, 4);
	*(u16 *)(rt + 40) = 2;
	memset(rt + 44, 0xff, 4);
	*(u16 *)(rt + 56) = 1 | 2 | 4; /* up, via a gateway, one host */
	return sioctl(s, add ? 0x890B : 0x890C, rt);
}
static long ifflags_down(int s, const char *name)
{
	u8 r[40];
	memset(r, 0, sizeof r);
	scpy((char *)r, name, 16);
	long e = sioctl(s, 0x8913, r);
	if (e < 0)
		return e;
	*(u16 *)(r + 16) &= (u16)~1;
	return sioctl(s, 0x8914, r);
}
static void parseip(const char *s, u8 a[4])
{
	for (int i = 0; i < 4; i++) {
		a[i] = (u8)pnum(s);
		while (*s >= '0' && *s <= '9')
			s++;
		if (*s == '.')
			s++;
	}
}
static void parsemac(const char *s, u8 m[6])
{
	for (int i = 0; i < 6 && s[0] && s[1]; i++, s += 3)
		m[i] = (u8)(hexval(s[0]) * 16 + hexval(s[1]));
}
static void fmtmac(const u8 m[6], char *b)
{
	const char *hx = "0123456789abcdef";
	for (int i = 0; i < 6; i++) {
		b[3 * i] = hx[m[i] >> 4];
		b[3 * i + 1] = hx[m[i] & 15];
		b[3 * i + 2] = i < 5 ? ':' : 0;
	}
}

/* -------------------------------------------------------------- device-mapper */

#define DMHDR 312

static long dmcall(int fd, u64 cmd, const char *name, u32 flags, const u8 *payload, u64 plen, u32 targets)
{
	u64 size = 16384;
	while (size < DMHDR + plen + 8)
		size *= 4;
	u64 mark = atop;
	u8 *b = alloc(size);
	memset(b, 0, size);
	*(u32 *)(b + 0) = 4;
	*(u32 *)(b + 12) = (u32)size;
	*(u32 *)(b + 16) = DMHDR;
	*(u32 *)(b + 20) = targets;
	*(u32 *)(b + 28) = flags;
	scpy((char *)b + 48, name, 128);
	memcpy(b + DMHDR, payload, plen);
	long r = sioctl(fd, cmd, b);
	atop = mark;
	return r;
}

struct dmtarget {
	u64 start, len;
	char type[16];
	char *params;
};

static long dmload(int fd, const char *name, struct dmtarget *t, int n)
{
	u64 mark = atop;
	u64 cap = 0;
	for (int i = 0; i < n; i++)
		cap += 40 + slen(t[i].params) + 16;
	u8 *p = alloc(cap + 16);
	u64 o = 0;
	for (int i = 0; i < n; i++) {
		u8 *spec = p + o;
		memset(spec, 0, 40);
		*(u64 *)(spec + 0) = t[i].start;
		*(u64 *)(spec + 8) = t[i].len;
		scpy((char *)spec + 24, t[i].type, 16);
		u64 pl = slen(t[i].params) + 1;
		memcpy(spec + 40, t[i].params, pl);
		u64 tot = 40 + pl;
		while (tot % 8)
			spec[tot++] = 0;
		*(u32 *)(spec + 20) = (u32)tot;
		o += tot;
	}
	long r = dmcall(fd, 0xC138FD09, name, 0, p, o, (u32)n);
	atop = mark;
	return r;
}
static long dmsuspend(int fd, const char *name, int suspend)
{
	return dmcall(fd, 0xC138FD06, name, suspend ? 2 : 0, 0, 0, 0);
}

/* a disk being copied: see "disk copy" below */
struct cdisk {
	int idx, devfd, nf;
	char name[40], dir[192], slot[16];
	u64 bytes, drops;
	int tf[128];
	u8 *tail[128];
	u32 tlen[128];
};
static struct cdisk cd[16];
static int ncd;

/* ---------------------------------------------------------------- the plan */

struct patch {
	u64 pfn;
	u32 off, kind, len;
	u8 *data;
};
struct leaf {
	char was[24], disk[40];
	u64 sectors, part, start, size;
	u8 hash[32];
	char now[24];
};
struct mapping {
	char name[128];
	struct dmtarget t[64];
	int nt;
};
struct mnt {
	char was[24], type[32], dir[256];
	int ro;
};

static struct {
	u8 to_ip[4];
	u16 to_port;
	struct netid id;
	struct netid nics[16]; /* every card the system had: found again by address on arrival */
	int nnics;
	struct netid after; /* the new machine's transfer card, used once on arrival to tell the old copy to go */
	char dropmod[4][32]; /* drivers of devices the new machine does not have, unloaded on arrival */
	int ndropmod;
	int hasafter;
	char *stay[64];
	int nstay;
	struct patch *patch;
	int npatch;
	struct mapping maps[32];
	int nmaps;
	struct leaf leaves[32];
	int nleaves;
	struct mnt mounts[32];
	int nmounts;
	int debug, crash, die;
	int letgo; /* the core lets go of the devices itself (all but the ones to stay) */
	int dconn; /* the disk copy's connection, or -1 */
	u32 vport; /* a verdict may also come over the network, here */
	char vtoken[96];
	int vfd;   /* the verdict listener, opened before the freeze by the Go side, or -1 */
	char rxtoken[96]; /* what every connection to the receiver starts with */
	int pre;   /* memory sent ahead: the fingerprints (sender) or the index (receiver), or -1 */
	int preslots; /* receiver: the pages sent ahead */
	u64 premax, seed_a, seed_b;
	int format; /* receiver: 2 when the image comes as fingerprints and changed pages */
	u64 pvpfn[256];
	u32 pvoff[256];
	int npv;
	u32 pvmul;
	int pvshift;
	u64 total;
	int hold;
	u8 *header;
} P;

/* plan lines are "word arg arg ..."; the last field of some runs to the end of the line. */
static char *field(char **s)
{
	while (**s == ' ')
		(*s)++;
	char *b = *s;
	while (**s && **s != ' ')
		(*s)++;
	if (**s)
		*(*s)++ = 0;
	return b;
}

static int readplan(int fd)
{
	u64 cap = 1 << 20, n = 0;
	char *b = alloc(cap);
	for (;;) {
		if (n + 1 >= cap) {
			char *c = alloc(cap * 2);
			memcpy(c, b, n);
			b = c;
			cap *= 2;
		}
		long k = sread(fd, b + n, cap - 1 - n);
		if (k == -EINTR)
			continue;
		if (k < 0)
			return (int)k;
		if (k == 0)
			break;
		n += (u64)k;
	}
	b[n] = 0;
	int maxp = 1;
	for (u64 i = 0; i < n; i++)
		if (b[i] == '\n')
			maxp++;
	P.patch = alloc(sizeof(struct patch) * (u64)maxp);
	for (char *line = b; *line;) {
		char *e = line;
		while (*e && *e != '\n')
			e++;
		char *next = *e ? e + 1 : e;
		*e = 0;
		char *s = line;
		char *w = field(&s);
		if (seq(w, "to")) {
			parseip(field(&s), P.to_ip);
			P.to_port = (u16)pnum(field(&s));
		} else if (seq(w, "net")) {
			scpy(P.id.name, field(&s), 16);
			parsemac(field(&s), P.id.mac);
			parseip(field(&s), P.id.ip);
			parseip(field(&s), P.id.mask);
			parseip(field(&s), P.id.gw);
		} else if (seq(w, "nic") && P.nnics < 16) {
			scpy(P.nics[P.nnics].name, field(&s), 16);
			parsemac(field(&s), P.nics[P.nnics].mac);
			P.nnics++;
		} else if (seq(w, "after")) {
			parsemac(field(&s), P.after.mac);
			parseip(field(&s), P.after.ip);
			parseip(field(&s), P.after.mask);
			parseip(field(&s), P.after.gw);
			P.hasafter = 1;
		} else if (seq(w, "dropmod") && P.ndropmod < 4) {
			scpy(P.dropmod[P.ndropmod++], field(&s), 32);
		} else if (seq(w, "stay") && P.nstay < 64) {
			P.stay[P.nstay++] = sdup(field(&s));
		} else if (seq(w, "patch")) {
			struct patch *p = &P.patch[P.npatch++];
			p->pfn = pnum(field(&s));
			p->off = (u32)pnum(field(&s));
			p->kind = (u32)pnum(field(&s));
			char *h = field(&s);
			p->data = alloc(slen(h) / 2 + 1);
			p->len = (u32)unhex(h, p->data, slen(h) / 2);
			if (p->off + p->len > PAGE)
				return -22;
		} else if (seq(w, "map") && P.nmaps < 32) {
			scpy(P.maps[P.nmaps++].name, field(&s), 128);
		} else if (seq(w, "target")) {
			char *mn = field(&s);
			struct mapping *m = 0;
			for (int i = 0; i < P.nmaps; i++)
				if (seq(P.maps[i].name, mn))
					m = &P.maps[i];
			if (!m || m->nt >= 64)
				return -22;
			struct dmtarget *t = &m->t[m->nt++];
			t->start = pnum(field(&s));
			t->len = pnum(field(&s));
			scpy(t->type, field(&s), 16);
			while (*s == ' ')
				s++;
			t->params = sdup(s);
		} else if (seq(w, "leaf") && P.nleaves < 32) {
			struct leaf *l = &P.leaves[P.nleaves++];
			scpy(l->was, field(&s), sizeof l->was);
			scpy(l->disk, field(&s), sizeof l->disk);
			l->sectors = pnum(field(&s));
			if (unhex(field(&s), l->hash, 32) != 32)
				return -22;
			l->part = pnum(field(&s));
			l->start = pnum(field(&s));
			l->size = pnum(field(&s));
		} else if (seq(w, "mount") && P.nmounts < 32) {
			struct mnt *m = &P.mounts[P.nmounts++];
			scpy(m->was, field(&s), sizeof m->was);
			scpy(m->type, field(&s), sizeof m->type);
			m->ro = (int)pnum(field(&s));
			while (*s == ' ')
				s++;
			scpy(m->dir, s, sizeof m->dir);
		} else if (seq(w, "flag")) {
			char *f = field(&s);
			if (seq(f, "debug"))
				P.debug = 1;
			if (seq(f, "crash"))
				P.crash = 1;
			if (seq(f, "die"))
				P.die = 1;
		} else if (seq(w, "verdict")) {
			P.vport = (u32)pnum(field(&s));
			scpy(P.vtoken, field(&s), sizeof P.vtoken);
		} else if (seq(w, "vfd")) {
			P.vfd = (int)pnum(field(&s));
		} else if (seq(w, "rxtoken")) {
			scpy(P.rxtoken, field(&s), sizeof P.rxtoken);
		} else if (seq(w, "letgo")) {
			P.letgo = 1;
		} else if (seq(w, "dcopy")) {
			P.dconn = (int)pnum(field(&s));
		} else if (seq(w, "disk") && ncd < 16) {
			struct cdisk *d = &cd[ncd++];
			d->idx = (int)pnum(field(&s));
			scpy(d->name, field(&s), sizeof d->name);
			d->bytes = pnum(field(&s));
			scpy(d->dir, field(&s), sizeof d->dir);
			d->drops = pnum(field(&s));
			scpy(d->slot, field(&s), sizeof d->slot);
		} else if (seq(w, "dtail")) {
			u64 di = pnum(field(&s)), cpu = pnum(field(&s));
			char *h = field(&s);
			for (int i = 0; i < ncd; i++)
				if ((u64)cd[i].idx == di && cpu < 128) {
					cd[i].tail[cpu] = alloc(slen(h) / 2 + 1);
					cd[i].tlen[cpu] = (u32)unhex(h, cd[i].tail[cpu], slen(h) / 2);
				}
		} else if (seq(w, "presend")) {
			P.pre = (int)pnum(field(&s));
			char *x = field(&s);
			if (seq(w, "presend") && *s && s[0] >= '0' && s[0] <= '9') {
				/* sender: presend <fd> <maxpfn> <seedA> <seedB> */
				P.premax = pnum(x);
				P.seed_a = pnum(field(&s));
				P.seed_b = pnum(field(&s));
			} else {
				P.premax = pnum(x);
			}
		} else if (seq(w, "pvclock") && P.npv < 256) {
			P.pvpfn[P.npv] = pnum(field(&s));
			P.pvoff[P.npv++] = (u32)pnum(field(&s));
		} else if (seq(w, "pvtime")) {
			P.pvmul = (u32)pnum(field(&s));
			P.pvshift = (int)pnum(field(&s)) - 128;
		} else if (seq(w, "preslots")) {
			P.preslots = (int)pnum(field(&s));
		} else if (seq(w, "format")) {
			P.format = (int)pnum(field(&s));
		} else if (seq(w, "total")) {
			P.total = pnum(field(&s));
		} else if (seq(w, "hold")) {
			P.hold = (int)pnum(field(&s));
		} else if (seq(w, "header")) {
			P.header = alloc(PAGE);
			if (unhex(field(&s), P.header, PAGE) != PAGE)
				return -22;
		}
		line = next;
	}
	/* patches sorted by page frame, so the stream can walk them in order */
	for (int i = 1; i < P.npatch; i++)
		for (int j = i; j > 0 && P.patch[j - 1].pfn > P.patch[j].pfn; j--) {
			struct patch t = P.patch[j];
			P.patch[j] = P.patch[j - 1];
			P.patch[j - 1] = t;
		}
	return 0;
}

static int wanted(u64 pfn)
{
	int lo = 0, hi = P.npatch;
	while (lo < hi) {
		int m = (lo + hi) / 2;
		if (P.patch[m].pfn < pfn)
			lo = m + 1;
		else
			hi = m;
	}
	return lo < P.npatch && P.patch[lo].pfn == pfn ? lo : -1;
}

static const u8 endbr64[4] = {0xf3, 0x0f, 0x1e, 0xfa};

static int apply(u64 pfn, u8 *pg)
{
	int n = 0;
	for (int i = wanted(pfn); i >= 0 && i < P.npatch && P.patch[i].pfn == pfn; i++) {
		struct patch *p = &P.patch[i];
		u32 off = p->off;
		if (p->kind == 1 && off + 4 + p->len <= PAGE && memcmp(pg + off, endbr64, 4) == 0)
			off += 4; /* a function entry marked for indirect branch tracking: keep the mark */
		memcpy(pg + off, p->data, p->len);
		n++;
	}
	return n;
}

/* ------------------------------------------------------------- storage plan */

/* hashdisk hashes the first megabyte of a disk. */
static int hashdisk(const char *name, u8 out[32])
{
	char p[128];
	long fd = sopen(join(p, sizeof p, "/dev/", name, 0, 0), O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	u64 mark = atop;
	u8 *b = alloc(1 << 20);
	long n = 0;
	while (n < (1 << 20)) {
		long k = spread((int)fd, b + n, (u64)((1 << 20) - n), (u64)n);
		if (k == -EINTR)
			continue;
		if (k <= 0)
			break;
		n += k;
	}
	sclose((int)fd);
	if (n >= 4096)
		sha256(b, (u64)n, out);
	atop = mark;
	return n >= 4096;
}

/* findleaf looks for the device that is now what l was. */
static int findleaf(struct leaf *l)
{
	u64 mark = atop;
	char **d;
	int n = dirlist("/sys/block", &d);
	for (int i = 0; i < n; i++) {
		const char *nm = d[i];
		if (spre(nm, "dm-") || spre(nm, "loop") || spre(nm, "ram") || spre(nm, "sr") || spre(nm, "zram"))
			continue;
		char p[256];
		if (readu(join(p, sizeof p, "/sys/block/", nm, "/size", 0)) != l->sectors)
			continue;
		u8 h[32];
		if (!hashdisk(nm, h) || memcmp(h, l->hash, 32) != 0)
			continue;
		char dir[256];
		join(dir, sizeof dir, "/sys/block/", nm, 0, 0);
		if (l->part > 0) {
			char **q;
			int nq = dirlist(dir, &q);
			int found = 0;
			for (int k = 0; k < nq && !found; k++) {
				char pd[320], f[360];
				join(pd, sizeof pd, dir, "/", q[k], 0);
				if (readu(join(f, sizeof f, pd, "/partition", 0, 0)) == l->part &&
				    readu(join(f, sizeof f, pd, "/start", 0, 0)) == l->start &&
				    readu(join(f, sizeof f, pd, "/size", 0, 0)) == l->size) {
					scpy(dir, pd, sizeof dir);
					found = 1;
				}
			}
			if (!found)
				continue;
		}
		char f[360], dev[32];
		if (readfile(join(f, sizeof f, dir, "/dev", 0, 0), dev, sizeof dev) > 0) {
			scpy(l->now, dev, sizeof l->now);
			atop = mark;
			return 1;
		}
	}
	atop = mark;
	return 0;
}

/* swapdev rewrites every "major:minor" in s that names a leaf to where it is now. */
static char *swapdev(const char *s, int *moved)
{
	char *o = alloc(slen(s) * 2 + 64);
	u64 n = 0;
	for (u64 i = 0; s[i];) {
		int edge = i == 0 || !((s[i - 1] >= '0' && s[i - 1] <= '9') || (s[i - 1] >= 'a' && s[i - 1] <= 'z') || (s[i - 1] >= 'A' && s[i - 1] <= 'Z') || s[i - 1] == '_');
		if (edge && s[i] >= '0' && s[i] <= '9') {
			u64 j = i;
			while (s[j] >= '0' && s[j] <= '9')
				j++;
			if (s[j] == ':' && s[j + 1] >= '0' && s[j + 1] <= '9') {
				u64 k = j + 1;
				while (s[k] >= '0' && s[k] <= '9')
					k++;
				int after = !((s[k] >= 'a' && s[k] <= 'z') || (s[k] >= 'A' && s[k] <= 'Z') || s[k] == '_');
				if (after) {
					char tok[32];
					u64 tl = k - i < sizeof tok ? k - i : sizeof tok - 1;
					memcpy(tok, s + i, tl);
					tok[tl] = 0;
					const char *rep = 0;
					for (int q = 0; q < P.nleaves; q++)
						if (seq(P.leaves[q].was, tok) && P.leaves[q].now[0])
							rep = P.leaves[q].now;
					if (rep && !seq(rep, tok))
						*moved = 1;
					for (const char *r = rep ? rep : tok; *r; r++)
						o[n++] = *r;
					i = k;
					continue;
				}
			}
			while (i < j)
				o[n++] = s[i++];
			continue;
		}
		o[n++] = s[i++];
	}
	o[n] = 0;
	return o;
}

static int dmctl = -1;

static long hold(void)
{
	for (int i = 0; i < P.nmaps; i++) {
		long r = dmsuspend(dmctl, P.maps[i].name, 1);
		if (r < 0) {
			pr("envmove: cannot hold mapping %s: %e\n", P.maps[i].name, r);
			return r;
		}
	}
	return 0;
}

static long unmountplain(void)
{
	for (int i = P.nmounts - 1; i >= 0; i--) {
		long r = SYS(NR_umount2, P.mounts[i].dir, 0, 0);
		if (r < 0) {
			pr("envmove: cannot unmount %s: %e\n", P.mounts[i].dir, r);
			return r;
		}
	}
	return 0;
}

/* release points every mapping at where its disks are now, lets the
 * filesystems go on, and puts the plain mounts back. On arrival and on undo. */
static long release(void)
{
	for (int i = 0; i < P.nleaves; i++)
		P.leaves[i].now[0] = 0;
	for (int tries = 0;; tries++) {
		const char *missing = 0;
		for (int i = 0; i < P.nleaves; i++)
			if (!P.leaves[i].now[0] && !findleaf(&P.leaves[i]))
				missing = P.leaves[i].disk;
		if (!missing)
			break;
		if (tries >= 300) {
			pr("storage: the disk that was %s has not appeared on this machine; the mappings stay held\n", missing);
			return -19;
		}
		nap(100);
	}
	for (int i = P.nmaps - 1; i >= 0; i--) { /* lowest first */
		struct mapping *m = &P.maps[i];
		u64 mark = atop;
		struct dmtarget t[64];
		int moved = 0;
		for (int k = 0; k < m->nt; k++) {
			t[k] = m->t[k];
			t[k].params = swapdev(m->t[k].params, &moved);
		}
		if (moved) {
			long r = dmload(dmctl, m->name, t, m->nt);
			if (r < 0) {
				pr("storage: cannot re-point mapping %s: %e\n", m->name, r);
				atop = mark;
				return r;
			}
		}
		long r = dmsuspend(dmctl, m->name, 0);
		atop = mark;
		if (r < 0) {
			pr("storage: cannot release mapping %s: %e\n", m->name, r);
			return r;
		}
		if (moved)
			pr("storage: %s re-pointed and running\n", m->name);
	}
	for (int i = 0; i < P.nmounts; i++) {
		struct mnt *m = &P.mounts[i];
		const char *now = 0;
		for (int q = 0; q < P.nleaves; q++)
			if (seq(P.leaves[q].was, m->was))
				now = P.leaves[q].now;
		if (!now || !now[0]) {
			pr("storage: mounting %s again: its disk is not known here\n", m->dir);
			return -2;
		}
		char p[128], lk[256], dev[128];
		if (rlink(join(p, sizeof p, "/sys/dev/block/", now, 0, 0), lk, sizeof lk) < 0) {
			pr("storage: mounting %s again: no device %s\n", m->dir, now);
			return -2;
		}
		join(dev, sizeof dev, "/dev/", base(lk), 0, 0);
		long r = sys6(NR_mount, (long)dev, (long)m->dir, (long)m->type, m->ro ? 1 : 0, 0, 0);
		if (r == -EBUSY)
			continue; /* it never left, or is already back */
		if (r < 0) {
			pr("storage: mounting %s again from %s: %e\n", m->dir, base(lk), r);
			return r;
		}
		pr("storage: %s mounted again from %s\n", m->dir, base(lk));
	}
	return 0;
}

/* ------------------------------------------------------------- disk copy */

/* The Go part copied the disks while the system ran and followed every write
 * with the kernel's block-I/O tracer. What was written since its last pass is
 * still in the tracer's buffers; it is read and sent from here, while nothing
 * but the kernel can write. */

static u64 dsent, dzero;

struct ext {
	u64 disk, start, end;
};

static int dopen(void)
{
	for (int i = 0; i < ncd; i++) {
		char p[256];
		long fd = sopen(join(p, sizeof p, "/dev/", cd[i].name, 0, 0), O_RDONLY | 0x4000 | O_CLOEXEC); /* O_DIRECT */
		if (fd < 0) {
			pr("envmove: disk copy: cannot open %s: %e\n", cd[i].name, fd);
			return -1;
		}
		cd[i].devfd = (int)fd;
		char **names;
		int n = dirlist(cd[i].dir, &names);
		for (int k = 0; k < n && cd[i].nf < 128; k++) {
			if (!spre(names[k], "trace"))
				continue;
			int cpu = (int)pnum(names[k] + 5);
			if (cpu < 0 || cpu >= 128)
				continue;
			long t = sopen(join(p, sizeof p, cd[i].dir, "/", names[k], 0), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
			if (t < 0) {
				pr("envmove: disk copy: cannot read the write tracer of %s: %e\n", cd[i].name, t);
				return -1;
			}
			cd[i].tf[cpu] = (int)t;
			if (cpu + 1 > cd[i].nf)
				cd[i].nf = cpu + 1;
		}
	}
	return 0;
}

/* ddrain collects the places written since the last look. */
static long ddrain(struct ext **out)
{
	static u8 rb[1 << 20];
	u64 cap = 4096, n = 0;
	struct ext *e = alloc(sizeof(struct ext) * cap);
	for (int i = 0; i < ncd; i++) {
		if (cd[i].devfd < 0)
			continue; /* let go: nothing can be written to it any more */
		for (int c = 0; c < cd[i].nf; c++) {
			if (cd[i].tf[c] <= 0)
				continue;
			for (;;) {
				long k = sread(cd[i].tf[c], rb, sizeof rb);
				if (k == -EINTR)
					continue;
				if (k <= 0)
					break;
				u8 *t = alloc(cd[i].tlen[c] + (u64)k);
				memcpy(t, cd[i].tail[c], cd[i].tlen[c]);
				memcpy(t + cd[i].tlen[c], rb, (u64)k);
				cd[i].tail[c] = t;
				cd[i].tlen[c] += (u32)k;
			}
			u8 *b = cd[i].tail[c];
			u32 len = cd[i].tlen[c], o = 0;
			while (len - o >= 48) {
				if ((*(u32 *)(b + o) & 0xffffff00) != 0x65617400) {
					pr("envmove: disk copy: the write tracer of %s returned something unreadable\n", cd[i].name);
					return -5;
				}
				u32 pdu = *(u16 *)(b + o + 46);
				if (len - o < 48 + pdu)
					break;
				u32 action = *(u32 *)(b + o + 28), bytes = *(u32 *)(b + o + 24);
				u32 cat = action >> 16;
				if ((cat & (1 << 1 | 1 << 13)) && !(cat & (1 << 10)) && bytes) {
					if (n == cap) {
						struct ext *w = alloc(sizeof(struct ext) * cap * 2);
						memcpy(w, e, sizeof(struct ext) * cap);
						e = w;
						cap *= 2;
					}
					u64 st = *(u64 *)(b + o + 16) * 512;
					e[n].disk = (u64)i;
					e[n].start = st & ~4095UL;
					e[n].end = (st + bytes + 4095) & ~4095UL;
					n++;
				}
				o += 48 + pdu;
			}
			cd[i].tail[c] = b + o;
			cd[i].tlen[c] = len - o;
		}
		char p[256], v[32];
		if (cd[i].devfd < 0)
			continue;
		readfile(join(p, sizeof p, cd[i].dir, "/dropped", 0, 0), v, sizeof v);
		if (pnum(v) != cd[i].drops) {
			pr("envmove: disk copy: the write tracer of %s lost track of writes\n", cd[i].name);
			return -5;
		}
	}
	/* sort by disk and place, then merge */
	for (u64 a = 1; a < n; a++)
		for (u64 j = a; j > 0 && (e[j - 1].disk > e[j].disk || (e[j - 1].disk == e[j].disk && e[j - 1].start > e[j].start)); j--) {
			struct ext t = e[j];
			e[j] = e[j - 1];
			e[j - 1] = t;
		}
	u64 m = 0;
	for (u64 a = 0; a < n; a++) {
		if (m && e[m - 1].disk == e[a].disk && e[a].start <= e[m - 1].end) {
			if (e[a].end > e[m - 1].end)
				e[m - 1].end = e[a].end;
			continue;
		}
		e[m++] = e[a];
	}
	*out = e;
	return (long)m;
}

static long dchunk(u32 kind, u32 disk, u64 off, u64 n, const u8 *data)
{
	u8 h[24];
	*(u32 *)(h + 0) = kind;
	*(u32 *)(h + 4) = disk;
	*(u64 *)(h + 8) = off;
	*(u64 *)(h + 16) = n;
	long r = wrall(P.dconn, h, 24);
	if (r < 0 || !data)
		return r;
	return wrall(P.dconn, data, n);
}

static long dsend(struct ext *e, long n)
{
	static u8 buf[1 << 20] __attribute__((aligned(4096)));
	for (long i = 0; i < n; i++) {
		struct cdisk *d = &cd[e[i].disk];
		for (u64 off = e[i].start; off < e[i].end && off < d->bytes;) {
			u64 len = e[i].end - off;
			if (len > sizeof buf)
				len = sizeof buf;
			if (off + len > d->bytes)
				len = d->bytes - off;
			long k = spread(d->devfd, buf, len, off);
			if (k < 0) {
				pr("envmove: disk copy: reading %s: %e\n", d->name, k);
				return k;
			}
			if (k == 0)
				break;
			int zero = 1;
			for (long z = 0; z < k && zero; z += 8)
				zero = *(u64 *)(buf + z) == 0;
			long r = zero ? dchunk(2, (u32)d->idx, off, (u64)k, 0) : dchunk(1, (u32)d->idx, off, (u64)k, buf);
			if (r < 0) {
				pr("envmove: disk copy: sending: %e\n", r);
				return r;
			}
			if (zero)
				dzero += (u64)k;
			else
				dsent += (u64)k;
			off += (u64)k;
		}
	}
	return 0;
}

/* dclose stops following and closes every disk whose controller is about to
 * be let go: nothing of ours may hold a disk open when its controller goes
 * (old kernels free the host a second time on the last close). Disks on
 * controllers that stay keep being followed until the image is taken. */
static void dclose(void)
{
	for (int i = 0; i < ncd; i++) {
		if (cd[i].devfd < 0 || (cd[i].slot[0] && inlist(cd[i].slot, P.stay, P.nstay)))
			continue;
		sioctl(cd[i].devfd, 0x1275, 0); /* BLKTRACESTOP */
		sioctl(cd[i].devfd, 0x1276, 0); /* BLKTRACETEARDOWN */
		for (int c = 0; c < cd[i].nf; c++)
			if (cd[i].tf[c] > 0) {
				sclose(cd[i].tf[c]);
				cd[i].tf[c] = 0;
			}
		cd[i].nf = 0;
		sclose(cd[i].devfd);
		cd[i].devfd = -1;
	}
}

/* dpass sends whatever was written, again and again, until nothing new shows. */
static long dpass(void)
{
	for (int round = 0; round < 50; round++) {
		u64 mark = atop;
		struct ext *e;
		long n = ddrain(&e);
		if (n < 0)
			return n;
		if (n == 0) {
			atop = mark;
			return 0;
		}
		long r = dsend(e, n);
		atop = mark;
		if (r < 0)
			return r;
		nap(20);
	}
	pr("envmove: disk copy: the disks kept changing while frozen\n");
	return -16;
}

/* dsync asks the receiver to put everything on its disks (final: and to take
 * no more), and waits until it has. */
static long dsync(int final)
{
	long r = dchunk(final ? 4 : 3, 0, 0, 0, 0);
	if (r < 0)
		return r;
	char line[16];
	int n = 0;
	while (n < 15) {
		long k = sread(P.dconn, line + n, 1);
		if (k == -EINTR)
			continue;
		if (k != 1)
			return -104;
		if (line[n++] == '\n')
			break;
	}
	line[n] = 0;
	return seq(line, "SYNCED\n") ? 0 : -5;
}

/* ------------------------------------------------------------- KVM clock */

static u64 rdtsc(void)
{
	u32 lo, hi;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
	return (u64)hi << 32 | lo;
}

/* A KVM clock record: version, pad, tsc_timestamp, system_time, mul, shift, flags. */
static u64 pvnow(const u8 *r, u64 tsc)
{
	u64 stamp = *(const u64 *)(r + 8), sys = *(const u64 *)(r + 16);
	u32 mul = *(const u32 *)(r + 24);
	int shift = (signed char)r[28];
	u64 d = tsc - stamp;
	if (shift < 0)
		d >>= -shift;
	else
		d <<= shift;
	return sys + (u64)(((unsigned __int128)d * mul) >> 32);
}

static int pvhas(u64 pfn)
{
	for (int i = 0; i < P.npv; i++)
		if (P.pvpfn[i] == pfn)
			return 1;
	return 0;
}

/* sender: the records in this page now hold the time it is by this machine's
 * clock, and wait for the receiver to give them its own counter. */
static int pvsend(u64 pfn, u8 *pg)
{
	u64 tsc = rdtsc(), s = 0;
	int n = 0;
	for (int i = 0; i < P.npv; i++)
		if (P.pvpfn[i] == pfn) {
			u64 v = pvnow(pg + P.pvoff[i], tsc);
			if (v > s)
				s = v;
		}
	for (int i = 0; i < P.npv; i++)
		if (P.pvpfn[i] == pfn) {
			u8 *r = pg + P.pvoff[i];
			*(u32 *)r &= ~1U; /* an even version: not being updated */
			*(u64 *)(r + 8) = 0;
			*(u64 *)(r + 16) = s;
			n++;
		}
	return n;
}

/* receiver: the records go on from that time, by this machine's counter. */
static void pvrecv(u64 pfn, u8 *pg)
{
	u64 tsc = rdtsc();
	for (int i = 0; i < P.npv; i++)
		if (P.pvpfn[i] == pfn) {
			u8 *r = pg + P.pvoff[i];
			*(u64 *)(r + 8) = tsc;
			*(u32 *)(r + 24) = P.pvmul;
			r[28] = (u8)(signed char)P.pvshift;
		}
}

/* ------------------------------------------------------------------ snapshot */

#define SNAP_FREEZE 0x3301
#define SNAP_UNFREEZE 0x3302
#define SNAP_ATOMIC_RESTORE 0x3304
#define SNAP_FREE 0x3305
#define SNAP_CREATE_IMAGE 0x40043311
#define SNAP_GET_IMAGE_SIZE 0x8008330E

#define OFF_IMAGE_PAGES 416
#define OFF_PAGES 424
#define ZERO_PAGE_FLAG (1UL << 63)
#define END_OF_LIST (~0UL)

static const int SNAP = 3, PLAN = 4, GATE = 5, CONN = 6;

/* back puts the storage where it was; used by every way out that stays here.
 * Letting go of the image memory first wakes the kernel's own worker threads,
 * which putting a filesystem back needs. */
static void back(void)
{
	sioctl(SNAP, SNAP_FREE, 0);
	/* Devices let go of before a failure come back too (a network card let go
	 * of while frozen would otherwise stay gone after the thaw). */
	rescan();
	if (!P.nleaves && !P.nmaps && !P.nmounts)
		return;
	release();
}

static int thawfail(const char *why, long e)
{
	back();
	sioctl(SNAP, SNAP_UNFREEZE, 0);
	if (e)
		pr("THAWED: %s: %e\n", why, e);
	else
		pr("THAWED: %s\n", why);
	return 1;
}

/* loaddrivers asks the module loader for a driver for every device without one. */
static void loaddrivers(char **envp)
{
	const char *mp = exists("/usr/sbin/modprobe") ? "/usr/sbin/modprobe" : "/sbin/modprobe";
	for (int pass = 0; pass < 2; pass++) {
		u64 mark = atop;
		int pids[256], np = 0;
		const char *buses[2] = {"pci", "virtio"};
		for (int b = 0; b < 2; b++) {
			char root[64], **d;
			join(root, sizeof root, "/sys/bus/", buses[b], "/devices", 0);
			int n = dirlist(root, &d);
			for (int i = 0; i < n && np < 256; i++) {
				char p[256], alias[256];
				if (exists(join(p, sizeof p, root, "/", d[i], "/driver")))
					continue;
				if (readfile(join(p, sizeof p, root, "/", d[i], "/modalias"), alias, sizeof alias) <= 1)
					continue;
				long pid = SYS(NR_fork, 0, 0, 0);
				if (pid == 0) {
					char *argv[] = {"modprobe", "-q", "-b", alias, 0};
					SYS(NR_execve, mp, argv, envp);
					sexit(127);
				}
				if (pid > 0)
					pids[np++] = (int)pid;
			}
		}
		/* wait, but not for ever: a driver stuck on hardware it cannot talk to
		 * must not keep the whole system frozen */
		for (int waited = 0; np > 0 && waited < 150; waited++) {
			int left = 0;
			for (int i = 0; i < np; i++) {
				int st;
				if (SYS(NR_wait4, pids[i], &st, 1) != pids[i]) /* WNOHANG */
					pids[left++] = pids[i];
			}
			np = left;
			if (np)
				nap(100);
		}
		atop = mark;
		if (np) {
			pr("a driver did not finish loading in 15 s; going on without waiting for it\n");
			return;
		}
		nap(300);
	}
}

/* kickaside resets the kept disk controllers from a side process and does not
 * wait for it: after a reset the kernel holds the caller for a fixed settle
 * time, and the whole system is still frozen. */
static long kickpid;

static void kickaside(void)
{
	long pid = SYS(NR_fork, 0, 0, 0);
	if (pid < 0) {
		pr("reset of kept disk controllers could not be started: %e\n", pid);
		return;
	}
	kickpid = pid;
	if (pid == 0) {
		sclose(SNAP); /* only the main process may hold the system frozen */
		long null = sopen("/dev/null", O_WRONLY);
		if (null >= 0) {
			SYS(NR_dup3, null, 1, 0);
			SYS(NR_dup3, null, 2, 0);
		}
		kick();
		sexit(0);
	}
	nap(300);
	pr("kept disk controllers told to reset\n");
}

/* arrive runs on the receiving machine, in the first moment of the restored
 * system, while everything else is still frozen. */
/* findcard gives the card with this address its old name. A card of this
 * machine that holds the name already (the kernel numbers cards in the order
 * they answer) steps aside first. */
static void findcard(int s, const struct netid *c)
{
	char name[16] = "", mac[18];
	fmtmac(c->mac, mac);
	for (int i = 0; i < 100 && !ifbymac(s, c->mac, name); i++)
		nap(100);
	if (!name[0]) {
		pr("network: no card with address %s on this machine\n", mac);
		return;
	}
	if (seq(name, c->name)) {
		pr("network: %s is %s, as before\n", mac, name);
		return;
	}
	long r = ifrename(s, name, c->name);
	if (r == -EEXIST) {
		char aside[16];
		u8 m[6];
		scpy(aside, "envmv0", 16);
		for (int k = 0; k < 10; k++) {
			aside[5] = (char)('0' + k);
			if (!ifmac(s, aside, m))
				break;
		}
		if (ifrename(s, c->name, aside) == 0)
			r = ifrename(s, name, c->name);
	}
	if (r < 0)
		pr("network: %s is %s here and could not be given its old name %s: %e\n", mac, name, c->name, r);
	else
		pr("network: %s came up as %s and was given its old name %s\n", mac, name, c->name);
}

/* tellold: the system runs here now, so the copy left behind, frozen and
 * waiting for its verdict, is told to power off. Over this machine's own
 * transfer card, configured for this alone and taken down again, while every
 * program is still frozen: nothing here can interfere, and the old copy is
 * gone before anything of the system runs again. */
static void tellold(int s)
{
	char name[16] = "", mac[18];
	fmtmac(P.after.mac, mac);
	for (int i = 0; i < 100 && !ifbymac(s, P.after.mac, name); i++)
		nap(100);
	if (!name[0]) {
		pr("OLD COPY: no transfer card %s on this machine; the old copy stays frozen until it is powered off from outside\n", mac);
		return;
	}
	struct netid c = P.after;
	u8 none[4] = {0, 0, 0, 0};
	memcpy(c.gw, none, 4); /* a route to the old copy alone, never a default route */
	long r = ifconfigure(s, name, &c);
	if (r < 0) {
		pr("OLD COPY: cannot configure the transfer card %s: %e\n", name, r);
		return;
	}
	if (P.after.gw[0] | P.after.gw[1] | P.after.gw[2] | P.after.gw[3])
		routehost(s, P.id.ip, P.after.gw, 1);
	char line[160];
	u64 tl = slen(P.vtoken);
	if (tl + 6 > sizeof line) {
		pr("OLD COPY: verdict token too long\n");
		return;
	}
	memcpy(line, P.vtoken, tl);
	memcpy(line + tl, " die\n", 5);
	int told = 0;
	u64 t0 = now_ms();
	while (!told && now_ms() - t0 < 30000) {
		long t = SYS(NR_socket, 2, 1, 0);
		u8 sa[16];
		memset(sa, 0, sizeof sa);
		*(u16 *)sa = 2;
		sa[2] = (u8)(P.vport >> 8), sa[3] = (u8)P.vport;
		memcpy(sa + 4, P.id.ip, 4);
		if (t >= 0 && SYS(NR_connect, t, sa, 16) == 0 && wrall((int)t, (const u8 *)line, tl + 5) >= 0) {
			char ans[16];
			int got = 0;
			struct {
				int fd;
				short events, revents;
			} pf = {(int)t, 1, 0};
			while (got < 15 && sys6(7, (long)&pf, 1, 5000, 0, 0, 0) > 0) {
				long k = sread((int)t, ans + got, 1);
				if (k != 1 || ans[got] == '\n')
					break;
				got++;
			}
			ans[got] = 0;
			told = got >= 5 && memcmp(ans, "TAKEN", 5) == 0;
			pr("OLD COPY: asked to power off; it answered %s\n", got ? ans : "nothing");
			if (!told && got)
				t0 = 0; /* refused: asking again will not change that */
		}
		if (t >= 0)
			sclose((int)t);
		if (!told && now_ms() - t0 < 30000)
			nap(500);
	}
	if (!told)
		pr("OLD COPY: not reached over the transfer network; it stays frozen until it is powered off from outside\n");
	if (P.after.gw[0] | P.after.gw[1] | P.after.gw[2] | P.after.gw[3])
		routehost(s, P.id.ip, P.after.gw, 0);
	ifset(s, name, 0x8916, none); /* an address of 0.0.0.0 removes the address */
	ifflags_down(s, name);
}

static int arrive(char **envp)
{
	pr("arrived on the other machine; everything else is still frozen\n");
	if (P.dconn >= 0)
		sclose(P.dconn); /* that connection lived on the machine that was left */
	kickaside();
	/* The kernel froze its own worker threads for the snapshot and they are
	 * still frozen. Mounting XFS and setting up new devices needs them. Letting
	 * go of the image memory is the kernel's own way to wake them while every
	 * program stays frozen. */
	sioctl(SNAP, SNAP_FREE, 0);
	refresh();
	if (P.nleaves || P.nmaps || P.nmounts)
		release();
	loaddrivers(envp);
	/* A device on no bus the kernel looks at again (a floppy controller) stays
	 * known after the move; its driver goes before anything can read it. */
	for (int i = 0; i < P.ndropmod; i++) {
		long r = SYS(176, P.dropmod[i], 04000, 0); /* delete_module, O_NONBLOCK */
		if (r < 0)
			pr("devices: the driver %s of a device this machine does not have could not be unloaded: %e\n", P.dropmod[i], r);
		else
			pr("devices: the old machine had a device this one has not; its driver %s was unloaded\n", P.dropmod[i]);
	}
	int s = ctlsock();
	if (P.nnics)
		for (int i = 0; i < P.nnics; i++)
			findcard(s, &P.nics[i]);
	else
		findcard(s, &P.id);
	if (P.hasafter && P.vport)
		tellold(s);
	sclose(s);
	/* The reset helper was forked while frozen and carries the freezer's mark;
	 * the kernel warns if it is still about at the thaw. With the settle time
	 * shortened it is long done; wait a little in case it is not. */
	for (int i = 0; kickpid > 0 && i < 30; i++) {
		int st;
		if (SYS(NR_wait4, kickpid, &st, 1) == kickpid) /* WNOHANG */
			break;
		nap(100);
	}
	long r = sioctl(SNAP, SNAP_UNFREEZE, 0);
	if (r < 0) {
		pr("envmove: thaw on arrival: %e\n", r);
		return 1;
	}
	sclose(SNAP);
	pr("ARRIVED: thawed and running here\n");
	return 0;
}

static int verdictwait(void);
static int undecided(int sock, long e);

static int leave(char **envp)
{
	if (SYS(NR_chdir, "/sys", 0, 0) < 0)
		SYS(NR_chdir, "/proc", 0, 0);
	long r = sioctl(SNAP, SNAP_FREEZE, 0);
	if (r < 0) {
		pr("envmove: freeze: %e\n", r);
		return 1;
	}
	int held = P.nleaves || P.nmaps || P.nmounts, final = 0;
	if (held) {
		if (unmountplain() < 0 || hold() < 0) {
			back();
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("envmove: thawed, nothing happened\n");
			return 1;
		}
	}
	if (P.dconn >= 0) {
		/* What was written since the last pass of the copy. With the storage
		 * held nothing can be written any more, so the copy is final now;
		 * otherwise the kernel may still write until the image is taken, and
		 * one more look follows then. */
		u64 t0 = now_ms();
		if (dpass() < 0 || dsync(held) < 0) {
			back();
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("envmove: the disk copy could not be finished; thawed, nothing happened\n");
			return 1;
		}
		final = held;
		pr("disks: %U KiB written since the last pass sent in %U ms while frozen%s\n", (dsent + dzero) >> 10, now_ms() - t0,
		   final ? "; the copy is final" : "");
	}
	if (held) {
		pr("storage: mappings held; letting go of the disk controllers\n");
		if (P.debug)
			for (int i = 0; i < P.nleaves; i++) {
				char p[128], a[64], st[64];
				readfile(join(p, sizeof p, "/sys/block/", P.leaves[i].disk, "/inflight", 0), a, sizeof a);
				readfile(join(p, sizeof p, "/sys/block/", P.leaves[i].disk, "/device/state", 0), st, sizeof st);
				pr("debug: %s in flight (read write): %s, state %s\n", P.leaves[i].disk, a, st);
			}
	}
	if (P.dconn >= 0)
		dclose();
	if (held || P.letgo) {
		if (letgo(P.stay, P.nstay) < 0) {
			back();
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("envmove: thawed, nothing happened\n");
			return 1;
		}
	}
	/* For tests of the safety net only: stop here, at the worst moment. */
	if (P.crash)
		*(volatile int *)0 = 1; /* a bug in this program */
	if (P.die)
		sexit(9); /* killed outright, no chance to clean up */

	int onsource = 0;
	r = sioctl(SNAP, SNAP_CREATE_IMAGE, &onsource);
	if (r < 0) {
		back();
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		pr("envmove: the kernel could not take the memory image: %e; thawed, nothing happened\n", r);
		return 1;
	}
	if (!onsource)
		return arrive(envp);

	/* Still on the source. The image exists; everything else here is frozen. */
	pr("image taken; bringing the network card back to carry it out\n");
	if ((r = writefile("/sys/bus/pci/rescan", "1")) < 0)
		return thawfail("cannot rediscover the network card", r);
	int s = ctlsock();
	char name[16] = "";
	for (int i = 0; i < 300 && !ifbymac(s, P.id.mac, name); i++)
		nap(100);
	if (!name[0])
		return thawfail("the network card did not come back", 0);
	if ((r = ifconfigure(s, name, &P.id)) < 0)
		return thawfail("cannot configure the network card", r);
	sclose(s);
	if (P.dconn >= 0 && !final) {
		/* Anything the kernel wrote after the last pass, before the image. */
		u64 before = dsent + dzero;
		if (dpass() < 0 || dsync(1) < 0)
			return thawfail("the disk copy could not be made final", 0);
		pr("disks: the copy is final (%U KiB more after the image was taken)\n", (dsent + dzero - before) >> 10);
	}
	int sock = -1;
	for (int i = 0; i < 60 && sock < 0; i++) {
		long t = SYS(NR_socket, 2, 1, 0); /* AF_INET, SOCK_STREAM */
		u8 sa[16];
		memset(sa, 0, sizeof sa);
		*(u16 *)sa = 2;
		sa[2] = (u8)(P.to_port >> 8), sa[3] = (u8)P.to_port;
		memcpy(sa + 4, P.to_ip, 4);
		if (t >= 0 && SYS(NR_connect, t, sa, 16) == 0)
			sock = (int)t;
		else {
			if (t >= 0)
				sclose((int)t);
			nap(500);
		}
	}
	if (sock < 0)
		return thawfail("cannot reach the receiver to send the image", 0);
	i64 size = 0;
	if ((r = sioctl(SNAP, SNAP_GET_IMAGE_SIZE, &size)) < 0)
		return thawfail("cannot size the image", r);
	u64 total = (u64)size / PAGE;
	u8 *ftab = 0; /* fingerprints of what the receiver holds, per page frame */
	if (P.pre >= 0) {
		ftab = smmap(P.pre, P.premax * 16, 0);
		if (!ftab)
			return thawfail("cannot map the fingerprints of the memory sent ahead", 0);
	}
	u8 head[16 + 1 + 96];
	u64 tl0 = slen(P.rxtoken), hl = 0;
	memcpy(head, ftab ? "ENVMOVE2" : "ENVMOVE1", 8);
	head[8] = (u8)tl0;
	memcpy(head + 9, P.rxtoken, tl0);
	hl = 9 + tl0;
	*(u64 *)(head + hl) = total;
	if ((r = wrall(sock, head, hl + 8)) < 0)
		return thawfail("sending", r);
	/* the KVM clock records, for the receiver to rewrite */
	u32 npv = (u32)P.npv;
	if ((r = wrall(sock, (const u8 *)&npv, 4)) < 0)
		return thawfail("sending", r);
	for (int i = 0; i < P.npv; i++) {
		u8 rec[16];
		memset(rec, 0, 16);
		*(u64 *)rec = P.pvpfn[i];
		*(u32 *)(rec + 8) = P.pvoff[i];
		if ((r = wrall(sock, rec, 16)) < 0)
			return thawfail("sending", r);
	}
	static u8 pg[PAGE] __attribute__((aligned(4096)));
	u64 lists = 0, data = 0, fixed = 0;
	/* data page number -> page frame, for the few pages to correct, in order */
	u64 *want_d = alloc(sizeof(u64) * (u64)(P.npatch + 1)), *want_f = alloc(sizeof(u64) * (u64)(P.npatch + 1));
	int nwant = 0, at = 0;
	/* With memory sent ahead, data pages go in groups of 64: a bit per page
	 * that the receiver already holds, then the pages it does not. */
	static u8 group[64 * PAGE] __attribute__((aligned(4096)));
	u64 gmask = 0, ndata = 0, same = 0;
	int gn = 0, gk = 0;
	u64 *datapfn = 0;
	for (u64 i = 0; i < total; i++) {
		long k = rdall(SNAP, pg, PAGE);
		if (k != PAGE)
			return thawfail("reading the image", k < 0 ? k : -5);
		if (i == 0) {
			lists = *(u64 *)(pg + OFF_PAGES) - *(u64 *)(pg + OFF_IMAGE_PAGES) - 1;
			ndata = total - 1 - lists;
			if (ftab || P.npv)
				datapfn = alloc(sizeof(u64) * (ndata + 1));
		} else if (i <= lists) { /* a list of the page frames whose contents follow */
			for (int o = 0; o < PAGE; o += 8) {
				u64 e = *(u64 *)(pg + o);
				if (e == END_OF_LIST)
					break;
				if (e & ZERO_PAGE_FLAG)
					continue;
				if (wanted(e) >= 0 && nwant <= P.npatch) {
					want_d[nwant] = data;
					want_f[nwant++] = e;
				}
				if (datapfn && data < ndata)
					datapfn[data] = e;
				data++;
			}
			if (i == lists)
				data = 0;
		} else {
			if (at < nwant && want_d[at] == data)
				fixed += (u64)apply(want_f[at++], pg);
			if (P.npv && pvhas(datapfn[data]))
				fixed += (u64)pvsend(datapfn[data], pg);
			if (ftab) {
				u64 pfn = datapfn[data];
				int known = 0;
				if (pfn < P.premax) {
					const u64 *t = (const u64 *)(ftab + pfn * 16);
					if (t[0] | t[1]) {
						u64 a = xxh64page(pg, P.seed_a), b = xxh64page(pg, P.seed_b);
						if (!a && !b)
							a = 1;
						known = a == t[0] && b == t[1];
					}
				}
				if (known) {
					gmask |= 1UL << gn;
					same++;
				} else
					memcpy(group + (u64)gk++ * PAGE, pg, PAGE);
				gn++;
				data++;
				if (gn == 64 || data == ndata) {
					if ((r = wrall(sock, (const u8 *)&gmask, 8)) < 0 || (r = wrall(sock, group, (u64)gk * PAGE)) < 0) {
						if (i == total - 1)
							return undecided(sock, r);
						return thawfail("sending the image", r);
					}
					gmask = 0;
					gn = gk = 0;
				}
				continue;
			}
			data++;
		}
		if ((r = wrall(sock, pg, PAGE)) < 0) {
			if (i == total - 1)
				return undecided(sock, r);
			return thawfail("sending the image", r);
		}
	}
	char ack[8];
	if (rdall(sock, (u8 *)ack, 7) != 7 || memcmp(ack, "LOADED\n", 7) != 0)
		return undecided(sock, 0);
	sclose(sock);
	if (ftab)
		pr("memory: %U of %U pages were already on the other side; %U MiB crossed while frozen\n", same, ndata, (total - same) * PAGE >> 20);
	pr("sent %U pages (%U MiB), %U corrections made in transit. The receiver has it all.\n", total, total * PAGE >> 20, fixed);
	return verdictwait();
}

/* undecided: the last of the image was sent but its receipt is not known.
 * The receiver may have it all and be restoring it: thawing here could make
 * two copies run. So only a verdict decides from here, as after LOADED. */
static int undecided(int sock, long e)
{
	sclose(sock);
	if (e)
		pr("envmove: the receiver's confirmation did not come (%e); this system stays frozen, and only a verdict decides now\n", e);
	else
		pr("envmove: the receiver's confirmation did not come; this system stays frozen, and only a verdict decides now\n");
	return verdictwait();
}

/* verdictwait: the system stays frozen until it is told "die" (it runs on
 * the other side) or "thaw" (it did not arrive), on the console or, with a
 * verdict port, over the network with the token first. Nothing else ever
 * thaws it: no lost console, no failed call, no failed power-off. */
static int verdictwait(void)
{
	pr("WAITING: this system stays frozen. Type die when it runs on the other side, or thaw to carry on here.\n");
	int lfd = P.vfd;
	if (lfd < 0 && P.vport) {
		lfd = (int)SYS(NR_socket, 2, 1, 0);
		int one = 1;
		sys6(54, lfd, 1, 2, (long)&one, 4, 0); /* SO_REUSEADDR */
		u8 sa[16];
		memset(sa, 0, sizeof sa);
		*(u16 *)sa = 2;
		sa[2] = (u8)(P.vport >> 8), sa[3] = (u8)P.vport;
		if (lfd < 0 || SYS(49, lfd, sa, 16) < 0 || SYS(50, lfd, 4, 0) < 0) { /* bind, listen */
			pr("envmove: cannot wait for a verdict on port %u; the console still works\n", (unsigned)P.vport);
			lfd = -1;
		}
	}
	if (lfd >= 0)
		pr("WAITING: a verdict is also taken on port %u\n", (unsigned)P.vport);
	char line[160];
	int ln = 0, console = 1;
	for (;;) {
		char vbuf[160];
		const char *verdict = 0;
		if (!console && lfd < 0) {
			/* nobody can tell this system anything any more: it stays frozen
			 * until its machine is powered off from outside */
			nap(1000);
			continue;
		}
		struct {
			int fd;
			short events, revents;
		} pf[2] = {{console ? 0 : -1, 1, 0}, {lfd, 1, 0}};
		long n = sys6(7, (long)pf, 2, -1, 0, 0, 0); /* poll */
		if (n < 0) {
			nap(200);
			continue;
		}
		if (console && pf[0].revents) {
			char c;
			long k = sread(0, &c, 1);
			if (k == -EINTR)
				continue;
			if (k != 1) {
				if (lfd < 0)
					pr("envmove: no console and no verdict port: this system stays frozen until it is powered off from its hypervisor\n");
				console = 0;
				continue;
			}
			if (c != '\n' && c != '\r') {
				if (ln < (int)sizeof line - 1)
					line[ln++] = c;
				continue;
			}
			line[ln] = 0;
			ln = 0;
			trim(line);
			verdict = line;
			while (*verdict == ' ')
				verdict++;
		} else if (lfd >= 0 && pf[1].revents) {
			long c = SYS(43, lfd, 0, 0); /* accept */
			if (c < 0)
				continue;
			long t0 = (long)now_ms(), got = 0;
			while (got < (long)sizeof vbuf - 1 && (long)now_ms() - t0 < 5000) {
				long k = sread((int)c, vbuf + got, 1);
				if (k != 1 || vbuf[got] == '\n')
					break;
				got++;
			}
			vbuf[got] = 0;
			trim(vbuf);
			if (seq(vbuf, "ENVMOVEV?")) {
				wrall((int)c, (const u8 *)"ENVMOVEV!\n", 10);
				sclose((int)c);
				continue;
			}
			u64 tl = slen(P.vtoken);
			int ok = tl > 0 && (u64)got > tl && memcmp(vbuf, P.vtoken, tl) == 0 && vbuf[tl] == ' ';
			wrall((int)c, (const u8 *)(ok ? "TAKEN\n" : "REFUSED\n"), ok ? 6 : 8);
			sclose((int)c);
			if (!ok)
				continue;
			verdict = vbuf + tl + 1;
		}
		if (!verdict)
			continue;
		if (seq(verdict, "die")) {
			pr("leaving: powering this machine off\n");
			for (;;) {
				sys6(NR_reboot, 0xfee1dead, 672274793, 0x4321fedc, 0, 0, 0);
				nap(1000); /* never thawed after "die": the other copy runs */
			}
		}
		if (seq(verdict, "thaw")) {
			if (lfd >= 0)
				sclose(lfd);
			back();
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("THAWED: carrying on here\n");
			return 1; /* the move did not happen: the program says so with its exit status */
		}
	}
}

static int restorefail(const char *what, long e)
{
	sioctl(SNAP, SNAP_UNFREEZE, 0);
	if (e)
		pr("envmove: %s: %e; nothing was restored\n", what, e);
	else
		pr("envmove: %s; nothing was restored\n", what);
	return 1;
}

static int finishrestore(void)
{
	wrall(CONN, (const u8 *)"LOADED\n", 7);
	sclose(CONN);
	if (P.hold) {
		pr("HOLDING: image loaded (%U pages) and deliberately not restored\n", P.total);
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		return 1;
	}
	pr("image loaded: %U pages (%U MiB); letting go of this machine's devices and restoring\n", P.total, P.total * PAGE >> 20);
	if (letgo(0, 0) < 0) {
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		return 1;
	}
	long r = sioctl(SNAP, SNAP_ATOMIC_RESTORE, 0); /* does not come back when it works */
	sioctl(SNAP, SNAP_UNFREEZE, 0);
	pr("envmove: the kernel did not restore the image: %e\n", r);
	return 1;
}

/* restore2 puts the image together from the pages sent ahead and the pages
 * that crossed during the freeze. */
static int restore2(u8 *pg)
{
	u32 *index = smmap(P.pre, P.premax * 4, 0);
	if (!index || P.preslots < 0)
		return restorefail("cannot map the pages sent ahead", 0);
	u64 lists = *(u64 *)(P.header + OFF_PAGES) - *(u64 *)(P.header + OFF_IMAGE_PAGES) - 1;
	u64 ndata = P.total - 1 - lists, data = 0, reused = 0;
	u64 *datapfn = alloc(sizeof(u64) * (ndata + 1));
	long r;
	for (u64 i = 1; i <= lists; i++) {
		if (rdall(CONN, pg, PAGE) != PAGE)
			return restorefail("the image stopped arriving in its page lists", 0);
		for (int o = 0; o < PAGE; o += 8) {
			u64 e = *(u64 *)(pg + o);
			if (e == END_OF_LIST)
				break;
			if (e & ZERO_PAGE_FLAG)
				continue;
			if (data < ndata)
				datapfn[data] = e;
			data++;
		}
		if ((r = wrall(SNAP, pg, PAGE)) < 0)
			return restorefail("the kernel refused a page list of the image", r);
	}
	if (data != ndata)
		return restorefail("the page lists do not match the image size", 0);
	for (data = 0; data < ndata;) {
		u64 mask;
		if (rdall(CONN, (u8 *)&mask, 8) != 8)
			return restorefail("the image stopped arriving", 0);
		for (int g = 0; g < 64 && data < ndata; g++, data++) {
			if (mask >> g & 1) {
				u64 pfn = datapfn[data];
				u32 slot = pfn < P.premax ? index[pfn] : 0;
				if (!slot)
					return restorefail("the sender believes a page is here that never arrived", 0);
				if (slot == 0xFFFFFFFFu) {
					memset(pg, 0, PAGE); /* known to be zeros: nothing was kept for it */
				} else {
					if (spread(P.preslots, pg, PAGE, (u64)(slot - 1) * PAGE) != PAGE)
						return restorefail("cannot read a page sent ahead", 0);
					/* the copy kept here is no longer needed: give its memory back */
					sys6(285, P.preslots, 3, (long)(slot - 1) * PAGE, PAGE, 0, 0); /* fallocate, punch hole */
				}
				reused++;
			} else if (rdall(CONN, pg, PAGE) != PAGE)
				return restorefail("the image stopped arriving", 0);
			if (P.npv && pvhas(datapfn[data]))
				pvrecv(datapfn[data], pg);
			if ((r = wrall(SNAP, pg, PAGE)) < 0)
				return restorefail("the kernel refused a page of the image", r);
		}
	}
	pr("memory: %U pages taken from what was sent ahead, %U crossed while frozen\n", reused, P.total - reused);
	return finishrestore();
}

/* restore runs on the receiver: the header page (already adjusted for this
 * machine by the Go part) and then the rest of the image are written to the
 * kernel, which then jumps into them. */
static int restore(void)
{
	/* The freeze comes first: old kernels (3.10) build, at this request, the
	 * tables they need to place an incoming image safely. */
	long r = sioctl(SNAP, SNAP_FREEZE, 0);
	if (r < 0) {
		pr("envmove: freeze before restore: %e\n", r);
		return 1;
	}
	if (!P.header || !P.total) {
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		pr("envmove: the plan has no image header\n");
		return 1;
	}
	if ((r = wrall(SNAP, P.header, PAGE)) < 0) {
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		pr("envmove: the kernel refused the image header: %e; nothing was restored\n", r);
		return 1;
	}
	static u8 pg[PAGE] __attribute__((aligned(4096)));
	if (P.format == 2)
		return restore2(pg);
	u64 lists = *(u64 *)(P.header + OFF_PAGES) - *(u64 *)(P.header + OFF_IMAGE_PAGES) - 1, data = 0, nd = P.total - 1 - lists;
	u64 *dpfn = P.npv ? alloc(sizeof(u64) * (nd + 1)) : 0;
	for (u64 i = 1; i < P.total; i++) {
		long k = rdall(CONN, pg, PAGE);
		if (k == PAGE && dpfn) {
			if (i <= lists) {
				for (int o = 0; o < PAGE; o += 8) {
					u64 e = *(u64 *)(pg + o);
					if (e == END_OF_LIST)
						break;
					if (!(e & ZERO_PAGE_FLAG) && data < nd)
						dpfn[data++] = e;
				}
				if (i == lists)
					data = 0;
			} else {
				if (data < nd && pvhas(dpfn[data]))
					pvrecv(dpfn[data], pg);
				data++;
			}
		}
		if (k != PAGE) {
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("envmove: the image stopped arriving at page %U of %U; nothing was restored\n", i, P.total);
			return 1;
		}
		if ((r = wrall(SNAP, pg, PAGE)) < 0) {
			sioctl(SNAP, SNAP_UNFREEZE, 0);
			pr("envmove: the kernel refused page %U of the image: %e; nothing was restored\n", i, r);
			return 1;
		}
	}
	wrall(CONN, (const u8 *)"LOADED\n", 7);
	sclose(CONN);
	if (P.hold) {
		pr("HOLDING: image loaded (%U pages) and deliberately not restored\n", P.total);
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		return 1;
	}
	pr("image loaded: %U pages (%U MiB); letting go of this machine's devices and restoring\n", P.total, P.total * PAGE >> 20);
	if (letgo(0, 0) < 0) {
		sioctl(SNAP, SNAP_UNFREEZE, 0);
		return 1;
	}
	r = sioctl(SNAP, SNAP_ATOMIC_RESTORE, 0); /* does not come back when it works */
	sioctl(SNAP, SNAP_UNFREEZE, 0);
	pr("envmove: the kernel did not restore the image: %e\n", r);
	return 1;
}

/* ------------------------------------------------------------------ self test */

static int selftest(void)
{
	u8 h[32];
	sha256((const u8 *)"abc", 3, h);
	const char *want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
	u8 w[32];
	unhex(want, w, 32);
	pr("sha256 abc: %s\n", memcmp(h, w, 32) == 0 ? "ok" : "WRONG");
	u8 *big = alloc(1000000);
	memset(big, 'a', 1000000);
	sha256(big, 1000000, h);
	unhex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", w, 32);
	pr("sha256 million a: %s\n", memcmp(h, w, 32) == 0 ? "ok" : "WRONG");
	int moved = 0;
	P.nleaves = 1;
	scpy(P.leaves[0].was, "8:2", sizeof P.leaves[0].was);
	scpy(P.leaves[0].now, "8:18", sizeof P.leaves[0].now);
	char *t = swapdev("0 11526144 linear 8:2 2048", &moved);
	pr("swapdev: %s (%s)\n", t, seq(t, "0 11526144 linear 8:18 2048") && moved ? "ok" : "WRONG");
	t = swapdev("2 1 8:20 128 254:8:2 x18:2", &moved);
	pr("swapdev boundaries: %s (%s)\n", t, seq(t, "2 1 8:20 128 254:8:2 x18:2") ? "ok" : "WRONG");
	P.nleaves = 0;
	struct pcidev *d;
	int n = pcilist(&d);
	pr("pci devices seen: %d\n", n);
	if (n)
		pciprint(d, n < 4 ? n : 4);
	char **ds;
	int nd = dirlist("/sys/block", &ds);
	pr("block devices: %d%s%s\n", nd, nd ? ", first " : "", nd ? ds[0] : "");
	int s = ctlsock();
	char nm[16];
	u8 mac[6];
	char ms[18];
	for (int i = 1; i <= 16; i++)
		if (ifnameat(s, i, nm)) {
			int ok = ifmac(s, nm, mac);
			fmtmac(mac, ms);
			pr("interface %d: %s %s\n", i, nm, ok ? ms : "-");
		}
	u8 *page = alloc(PAGE);
	for (int i = 0; i < PAGE; i++)
		page[i] = (u8)(i * 7 + 3);
	pr("xxh64 test page: %X %X\n", xxh64page(page, 12345), xxh64page(page, 0));
	pr("arena used: %U KiB, clock %U ms\n", atop >> 10, now_ms());
	return 0;
}

/* -------------------------------------------------------------------- start */

static int cmain(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		pr("usage: envmove-core leave|restore|selftest\n");
		return 2;
	}
	if (seq(argv[1], "selftest"))
		return selftest();
	/* Everything this program will ever touch stays in memory: nothing of it
	 * may need a disk that this move is holding still. */
	SYS(NR_mlockall, 3, 0, 0);
	P.dconn = -1;
	P.pre = -1;
	P.vfd = -1;
	P.preslots = -1;
	if (readplan(PLAN) < 0) {
		pr("envmove: the plan handed to the frozen part is malformed\n");
		return 1;
	}
	sclose(PLAN);
	/* Wait until the parent has given up its copy of the snapshot device. */
	char one;
	while (sread(GATE, &one, 1) == -EINTR)
		;
	sclose(GATE);
	if (seq(argv[1], "leave")) {
		if (P.nleaves || P.nmaps || P.nmounts) {
			long fd = sopen("/dev/mapper/control", O_RDWR | O_CLOEXEC);
			if (fd < 0) {
				pr("envmove: device-mapper: %e\n", fd);
				return 1;
			}
			dmctl = (int)fd;
		}
		if (P.dconn >= 0 && dopen() < 0)
			return 1;
		return leave(envp);
	}
	if (seq(argv[1], "restore"))
		return restore();
	pr("envmove-core: unknown mode %s\n", argv[1]);
	return 2;
}

__attribute__((used, noreturn)) void cstart(long *sp)
{
	int argc = (int)sp[0];
	char **argv = (char **)(sp + 1);
	char **envp = argv + argc + 1;
	sexit(cmain(argc, argv, envp));
}

__asm__(".text\n"
	".global _start\n"
	"_start:\n"
	"	xor %rbp, %rbp\n"
	"	mov %rsp, %rdi\n"
	"	and $-16, %rsp\n"
	"	call cstart\n"
	"	hlt\n");
