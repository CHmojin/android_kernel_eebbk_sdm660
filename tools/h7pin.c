/* h7pin — create and pin the trivial BPF socket filters that netd expects.
 *
 * netd's BandwidthController runs:
 *   iptables -m bpf --object-pinned /sys/fs/bpf/netd_shared/prog_netd_skfilter_allowlist_xtbpf ...
 * and exits if those pins do not exist.  On this 4.4 kernel bpfloader can never
 * create them, so we create minimal SOCKET_FILTER programs ourselves (4.4 supports
 * that program type) and pin them.
 *
 * Build (aarch64, static):
 *   aarch64-linux-android-gcc -O2 -static -o h7pin h7pin.c
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_bpf
#define __NR_bpf 280
#endif

#define BPF_PROG_LOAD 5
#define BPF_OBJ_PIN   6
#define BPF_PROG_TYPE_SOCKET_FILTER 1

#define BPF_ALU64 0x07
#define BPF_MOV   0xb0
#define BPF_K     0x00
#define BPF_JMP   0x05
#define BPF_EXIT  0x90

struct bpf_insn {
	unsigned char code;
	unsigned char dst_reg:4;
	unsigned char src_reg:4;
	signed short off;
	signed int imm;
};

union bpf_attr_load {
	struct {
		unsigned int prog_type;
		unsigned int insn_cnt;
		unsigned long long insns;
		unsigned long long license;
		unsigned int log_level;
		unsigned int log_size;
		unsigned long long log_buf;
		unsigned int kern_version;
		unsigned int prog_flags;
	} __attribute__((aligned(8)));
	char pad[120];
};

union bpf_attr_pin {
	struct {
		unsigned long long pathname;
		int bpf_fd;
		unsigned int file_flags;
	} __attribute__((aligned(8)));
	char pad[120];
};

static int bpf(int cmd, void *attr)
{
	return syscall(__NR_bpf, cmd, attr, 120);
}

static const char *PIN_DIR = "/sys/fs/bpf/netd_shared";
static const char *NAMES[] = {
	"prog_netd_skfilter_allowlist_xtbpf",
	"prog_netd_skfilter_denylist_xtbpf",
	"prog_netd_skfilter_ingress_xtbpf",
	"prog_netd_skfilter_egress_xtbpf",
	"prog_netd_getsockopt_prog",
	"prog_netd_setsockopt_prog",
};

int main(void)
{
	struct bpf_insn insns[2];
	unsigned int i;

	/* bpffs may not be mounted yet when we run as a ramdisk helper */
	mkdir("/sys/fs", 0755);
	mkdir("/sys/fs/bpf", 0755);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	mkdir(PIN_DIR, 0755);

	/* r0 = -1 ; exit  (accept everything) */
	insns[0].code = BPF_ALU64 | BPF_MOV | BPF_K;
	insns[0].dst_reg = 0;
	insns[0].src_reg = 0;
	insns[0].off = 0;
	insns[0].imm = -1;
	insns[1].code = BPF_JMP | BPF_EXIT;
	insns[1].dst_reg = 0;
	insns[1].src_reg = 0;
	insns[1].off = 0;
	insns[1].imm = 0;

	for (i = 0; i < sizeof(NAMES) / sizeof(NAMES[0]); i++) {
		union bpf_attr_load la;
		union bpf_attr_pin pa;
		char path[128];
		int fd, ret;

		memset(&la, 0, sizeof(la));
		la.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
		la.insn_cnt = 2;
		la.insns = (unsigned long long)(unsigned long)insns;
		la.license = (unsigned long long)(unsigned long)"GPL";

		fd = bpf(BPF_PROG_LOAD, &la);
		if (fd < 0) {
			printf("h7pin: load %s failed: %s\n", NAMES[i], strerror(errno));
			continue;
		}

		snprintf(path, sizeof(path), "%s/%s", PIN_DIR, NAMES[i]);
		memset(&pa, 0, sizeof(pa));
		pa.pathname = (unsigned long long)(unsigned long)path;
		pa.bpf_fd = fd;

		ret = bpf(BPF_OBJ_PIN, &pa);
		if (ret < 0)
			printf("h7pin: pin %s failed: %s\n", path, strerror(errno));
		else
			printf("h7pin: pinned %s\n", path);
		close(fd);
	}
	printf("h7pin: done\n");
	return 0;
}
