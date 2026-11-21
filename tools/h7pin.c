/* h7pin — freestanding (no libc) helper that pins trivial BPF socket filters at the
 * paths netd expects (/sys/fs/bpf/netd_shared/prog_netd_skfilter_*) and creates the
 * netd stats maps minimally.
 *
 * Build:
 *   aarch64-linux-gcc -O2 -static -nostdlib -ffreestanding -o h7pin tools/h7pin.c
 */
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;

#define SYS_write 64
#define SYS_exit_group 94
#define SYS_mkdirat 34
#define SYS_mount 40
#define SYS_openat 56
#define SYS_close 57
#define SYS_bpf 280

#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD 5
#define BPF_OBJ_PIN 6
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_MAP_TYPE_ARRAY 2

#define AT_FDCWD -100
#define O_RDONLY 0

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
	char buf[128];
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

struct bpf_insn {
	unsigned char code;
	unsigned char dst_reg:4;
	unsigned char src_reg:4;
	signed short off;
	signed int imm;
};

struct bpf_attr {
	u32 map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u32 map_flags;
	u32 inner_map_fd;
	u32 numa_node;
	char map_name[16];
	u32 map_ifindex;
	u32 btf_fd;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	u64 map_extra;
	u32 prog_type;
	u32 insn_cnt;
	u64 insns;
	u64 license;
	u32 log_level;
	u32 log_size;
	u64 log_buf;
	u32 kern_version;
	u32 prog_flags;
	char prog_name[16];
	u32 prog_ifindex;
	u32 expected_attach_type;
	u64 pathname;
	u32 bpf_fd;
	u32 file_flags;
};

void _start(void)
{
	static const char *paths[] = {
		"/sys/fs/bpf/netd_shared/prog_netd_skfilter_allowlist_xtbpf",
		"/sys/fs/bpf/netd_shared/prog_netd_skfilter_denylist_xtbpf",
		"/sys/fs/bpf/netd_shared/prog_netd_skfilter_ingress_xtbpf",
		"/sys/fs/bpf/netd_shared/prog_netd_skfilter_egress_xtbpf",
		"/sys/fs/bpf/netd_shared/prog_netd_getsockopt_prog",
		"/sys/fs/bpf/netd_shared/prog_netd_setsockopt_prog",
	};
	static struct bpf_insn insns[2];
	struct bpf_attr attr;
	unsigned long i;

	say("h7pin: start\n");
	sc2(SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/bpf");
	sc4(SYS_mount, (long)"bpf", (long)"/sys/fs/bpf", (long)"bpf", 0);
	sc2(SYS_mkdirat, AT_FDCWD, (long)"/sys/fs/bpf/netd_shared");

	insns[0].code = 0xb7;	/* BPF_ALU64|BPF_MOV|BPF_K */
	insns[0].dst_reg = 0;
	insns[0].src_reg = 0;
	insns[0].off = 0;
	insns[0].imm = -1;
	insns[1].code = 0x95;	/* BPF_JMP|BPF_EXIT */
	insns[1].dst_reg = 0;
	insns[1].src_reg = 0;
	insns[1].off = 0;
	insns[1].imm = 0;

	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		long fd;

		for (unsigned long k = 0; k < sizeof(attr); k++)
			((char *)&attr)[k] = 0;
		attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
		attr.insn_cnt = 2;
		attr.insns = (u64)(unsigned long)insns;
		attr.license = (u64)(unsigned long)"GPL";
		fd = sc3(SYS_bpf, BPF_PROG_LOAD, (long)&attr, sizeof(attr));
		if (fd < 0) {
			saynum("h7pin: load failed errno ", -fd);
			continue;
		}
		for (unsigned long k = 0; k < sizeof(attr); k++)
			((char *)&attr)[k] = 0;
		attr.pathname = (u64)(unsigned long)paths[i];
		attr.bpf_fd = (u32)fd;
		long ret = sc3(SYS_bpf, BPF_OBJ_PIN, (long)&attr, sizeof(attr));
		if (ret < 0) {
			saynum("h7pin: pin failed errno ", -ret);
			say(paths[i]);
		} else {
			say("h7pin: pinned ");
			say(paths[i]);
			say("\n");
		}
		sc1(SYS_close, fd);
	}
	say("h7pin: done\n");
	sc1(SYS_exit_group, 0);
	for (;;)
		;
}
