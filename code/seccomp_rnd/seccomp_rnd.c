#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int main()
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl(NO_NEW_PRIVS)");
		return EXIT_FAILURE;
	}

    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RANDOM),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K,  0x1ff),
        BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
        BPF_STMT(BPF_RET | BPF_A, 0),

    };
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
		.filter = filter,
	};

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
		perror("prctl(SECCOMP)");
		return EXIT_FAILURE;
	}

    for (int i = 0; i < 4; i++) {
        printf("%6d %6d %6d %6d\n", getpid(), getpid(), getpid(), getpid());
    }
    return 0;
}
