/* h7pin — create /sys/fs/bpf (needs a writable mountpoint on top of sysfs), mount
 * bpffs, and pin the trivial BPF socket filters netd expects.
 *
 * /sys is sysfs (read-only), so mkdir("/sys/fs/bpf") fails.  We put a tmpfs over
 * /sys/fs to get a writable directory, then mount bpffs inside it.  init mounts
 * selinuxfs under /sys/fs later, which works fine on top of our tmpfs.
 *
 * Runs in the background with retries so it also survives init re-mounting things.
 *
 * Build: aarch64-linux-gcc -O2 -static -nostdlib -ffreestanding -o h7pin tools/h7pin.c
 */
typedef unsigned long u64;
typedef unsigned int u32;

#define SYS_write 64
#define SYS_exit_group 94
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_close 57
#define SYS_nanosleep 101
#define SYS_bpf 280

#define BPF_PROG_LOAD 5
#define BPF_OBJ_PIN 6
#define BPF_PROG_TYPE_SOCKET_FILTER 1

#define AT_FDCWD -100
#define SZ_PROG_LOAD 40
#define SZ_OBJ_PIN 16

struct timespec {
	long tv_sec;
	long tv_nsec;
};

static inline long sc1(long n, long a)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
	return x0;
}

static inline long sc2(long n, long a, long b)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
	return x0;
}

static inline long sc3(long n, long a, long b, long c)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory");
	return x0;
}

static inline long sc4(long n, long a, long b, long c, long d)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory");
	return x0;
}

static long slen(const char *s)
{
	long n = 0;
	while (s[n])
		n++;
	return n;
}

static void say(const char *s)
{
	sc3(SYS_write, 1, (long)s, slen(s));
}

static void saynum(const char *prefix, long v)
{
	char buf[160];
	long i = 0, n = 0;
	while (prefix[n])
		n++;
	for (long k = 0; k < n; k++)
		buf[i++] = prefix[k];
	if (v < 0) {
		buf[i++] = '-';
		v = -v;
	}
	char tmp[24];
	int t = 0;
	if (v == 0)
		tmp[t++] = '0';
	while (v > 0) {
		tmp[t++] = '0' + (v % 10);
		v /= 10;
	}
	while (t > 0)
		buf[i++] = tmp[--t];
	buf[i++] = '\n';
	sc3(SYS_write, 1, (long)buf, i);
}

static void sleep_ms(long ms)
{
	struct timespec ts;
	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (ms % 1000) * 1000000L;
	sc2(SYS_nanosleep, (long)&ts, 0);
}

struct bpf_insn {
	unsigned char code;
	unsigned char dst_reg:4;
	unsigned char src_reg:4;
	signed short off;
	signed int imm;
};

union bpf_attr {
	struct {
		u32 map_type, key_size, value_size, max_entries, map_flags;
		u32 inner_map_fd, numa_node;
		char map_name[16];
	};
	struct {
		u32 prog_type, insn_cnt;
		u64 insns, license;
		u32 log_level, log_size;
		u64 log_buf;
		u32 kern_version;
	};
	struct {
		u64 pathname;
		u32 bpf_fd, file_flags;
	};
};

static const char *PATHS[] = {
	"/sys/fs/bpf/netd_shared/prog_netd_skfilter_allowlist_xtbpf",
	"/sys/fs/bpf/netd_shared/prog_netd_skfilter_denylist_xtbpf",
	"/sys/fs/bpf/netd_shared/prog_netd_skfilter_ingress_xtbpf",
	"/sys/fs/bpf/netd_shared/prog_netd_skfilter_egress_xtbpf",
	"/sys/fs/bpf/netd_shared/prog_netd_getsockopt_prog",
	"/sys/fs/bpf/netd_shared/prog_netd_setsockopt_prog",
};

static void setup_bpffs(void)
{
	long r;

	/* sysfs is read-only: put a tmpfs over /sys/fs so we can create the mountpoint */
	r = sc2(SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/bpf");
	if (r < 0) {
		r = sc4(SYS_mount, (long)"tmpfs", (long)"/sys/fs", (long)"tmpfs", 0);
		saynum("h7pin: tmpfs on /sys/fs -> ", r);
		sc2(SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/bpf");
	}
	/* mount bpffs (ignore EBUSY if init already did it) */
	r = sc4(SYS_mount, (long)"bpf", (long)"/sys/fs/bpf", (long)"bpf", 0);
	if (r < 0)
		saynum("h7pin: mount bpf -> ", r);
	else
		say("h7pin: mounted bpffs\n");
	sc2(SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/bpf/netd_shared");
}

static int try_pin_all(void)
{
	static struct bpf_insn insns[2];
	union bpf_attr attr;
	unsigned long i;
	int ok = 0;

	insns[0].code = 0xb7;	/* r0 = -1 ; exit  (accept everything) */
	insns[0].dst_reg = 0;
	insns[0].src_reg = 0;
	insns[0].off = 0;
	insns[0].imm = -1;
	insns[1].code = 0x95;
	insns[1].dst_reg = 0;
	insns[1].src_reg = 0;
	insns[1].off = 0;
	insns[1].imm = 0;

	for (i = 0; i < sizeof(PATHS) / sizeof(PATHS[0]); i++) {
		long fd, ret;

		for (unsigned long k = 0; k < sizeof(attr); k++)
			((char *)&attr)[k] = 0;
		attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
		attr.insn_cnt = 2;
		attr.insns = (u64)(unsigned long)insns;
		attr.license = (u64)(unsigned long)"GPL";
		fd = sc3(SYS_bpf, BPF_PROG_LOAD, (long)&attr, SZ_PROG_LOAD);
		if (fd < 0)
			continue;
		for (unsigned long k = 0; k < sizeof(attr); k++)
			((char *)&attr)[k] = 0;
		attr.pathname = (u64)(unsigned long)PATHS[i];
		attr.bpf_fd = (u32)fd;
		ret = sc3(SYS_bpf, BPF_OBJ_PIN, (long)&attr, SZ_OBJ_PIN);
		sc1(SYS_close, fd);
		if (ret == 0) {
			ok++;
			say("h7pin: pinned ");
			say(PATHS[i]);
			say("\n");
		}
	}
	return ok;
}

void _start(void)
{
	int attempt;

	say("h7pin: start\n");
	for (attempt = 0; attempt < 40; attempt++) {
		int ok;

		setup_bpffs();
		ok = try_pin_all();
		if (ok == (int)(sizeof(PATHS) / sizeof(PATHS[0]))) {
			say("h7pin: done (all pinned)\n");
			break;
		}
		saynum("h7pin: attempt pinned ", ok);
		sleep_ms(500);
	}
	sc1(SYS_exit_group, 0);
	for (;;)
		;
}
