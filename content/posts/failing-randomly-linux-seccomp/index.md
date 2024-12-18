+++
title = 'Failing Randomly: Linux Seccomp and Kernel Hacking'
date = 2024-12-17T14:47:00+01:00
+++

Seccomp filters system calls with cBPF code. One can blacklist certain system call numbers or even make a decision based on call arguments. Both Docker and Chromium use seccomp to protect host from malicious or misbehaving programs.

With seccomp we can make a syscall fail consistently. We can't make a syscall fail with a certain probability though. How hard could it be to extend seccomp for a complete kernel newbie?

<!--more-->

## Inspiration

Philip Kaludercic works as a TA for a systems-programming course. All assignments in this course are written in C with an emphasis on robustness. Certain edge cases are hard to test, therefore Philip developed a tool to perform error injection. He wrote an aptly named [Consistently Making Wrong Decisions Whilst Writing Recreational C][1] documenting his adventures.

[1]: https://amodernist.com/texts/fun-c.html

Most executables rely on dynamic linker to locate and load the libraries. On Linux, dynamic linker comes with code injection feature. It checks `LD_PRELOAD` variable in the environment and "preloads" the named libraries.

[2]: https://wiki.debian.org/FakeRoot.

Philip used `LD_PRELOAD` trick to inject some code into program under test. The code made certain libc calls fail. I was amused by Philip's write up and kept wondering if it was possible to do the same without injecting any code into a program under test, fully in the kernel. After all, `LD_PRELOAD` doesn't work with statically-linked executables.

I knew about [seccomp][3], a cBPF based filter that can make syscalls fail. Philip's tool had one feature that was hard to map though: failing with a probability. cBPF (or classic BPF) is rather restricted. Unlike eBPF, filter invocations don't share any state. Helper functions are not available either. So how do we generate a random number?

[3]: https://man7.org/linux/man-pages/man2/seccomp.2.html

## Seccomp primer

Classic BPF was made for filtering packets. When you invoke `tcpdump ip src or dst 1.1.1.1`,  filter expression is compiled into bytecode. Pass `-d` to tcpdump to inspect resulting program:
```c
(000) ldh      [12]
(001) jeq      #0x800           jt 2	jf 7
(002) ld       [26]
(003) jeq      #0x1010101       jt 6	jf 4
(004) ld       [30]
(005) jeq      #0x1010101       jt 6	jf 7
(006) ret      #262144
(007) ret      #0
```

Bytecode executes in kernel context. These days, cBPF JIT has been removed . Kernel converts cBPF code to eBPF internally.

The code is not exactly human-readable, but it is still possible to trace the logic. It starts with `ldh [12]`. `ldh` loads 16 bit value at offset `+12`. Assuming Ethernet packet, it tells us the payload type. Subsequent `jeq #0x800 jt 2 jf 7`  jumps to instruction `2` if the value was equal to `0x800` (IPv4), otherwise skips to instruction `7`.

Similarly, `ld [26]` obtains source IP address by loading a 32 bit value at offset `+26`, followed by `jeq #0x10101010 jt 6 jf 4` which checks if the value is equal to `1.1.1.1`.

A program terminates when it reaches `ret`. Exit code is written in `ret` instruction inline. `0` means "no match", while non-zero value tells the number of bytes to capture. It is clear that arbitrary filters can be made by combining loads and conditional jumps.

Seccomp reuses the same execution environment. It passes the following data structure instead of a network packet:


```c
struct seccomp_data {
    int   nr;                   /* System call number */
    __u32 arch;                 /* AUDIT_ARCH_* value */
    __u64 instruction_pointer;  /* CPU instruction pointer */
    __u64 args[6];              /* Up to 6 system call arguments */
};
```

Seccomp program responds with `SECCOMP_RET_ALLOW` to allow the syscall. `SECCOMP_RET_ERRNO` makes the syscall fail with the specified errno. There are further options such as `SECCOMP_RET_KILL_THREAD`. We could've used `SECCOMP_RET_USER_NOTIF` to defer decision to user space.

Remember, our goal was to build an error injection tool that makes syscalls fail with a certain probability? We still haven't figured out how to generate a random number with cBPF. We could've given up at this point and settled on `SECCOMP_RET_USER_NOTIF`, but I feel motivated to dig deeper. After all, if we don't involve user space, we can make syscalls fail faster!


## Basic seccomp program

Let's write a basic program in C to experiment with seccomp.

```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 42),
};
```

We can write cBPF inline in C. The program loads syscall number from `seccomp_data` and compares it to `__NR_getpid`. If equal, we skip one instruction and return `SECCOMP_RET_ERRNO | 42`. Otherwise, we respond with `SECCOMP_RET_ALLOW`. This program makes `getpid` syscall fail with `errno 42`, while other syscalls are not affected.

Please keep in mind: syscall numbers are architecture-dependent. `x86_64`, `i386` and `aarch64` assign different numbers to `getpid` syscall. Sometimes multiple syscall tables coexist such as in `x86_64` system capable of running `i386` code. Therefore a proper seccomp filter should check `arch` field in `seccomp_data`.

We install the filter defined above with `prctl` syscall:

```c
struct sock_fprog prog = {
    .len = sizeof(filter)/sizeof(filter[0]),
    .filter = filter,
};

prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
```

Even unprivileged processes can use seccomp. Child processes inherit seccomp filters. Imagine the following: a malicious program installs a seccomp filter and launches a privileged program such as `sudo`. Seccomp filter prevents certain syscalls from being executed, altering `sudo` in unexpected ways.

Due to security concerns, installing a seccomp filter fails, unless a `prctl` wtih `PR_SET_NO_NEW_PRIVS` was performed. As the name suggests, it prevents acquiring any new privileges by the current process and its descendants.


Once the filter is in effect, any `getpid` call will fail with `errno 42`. The statement below

```c
printf("%getpid: %d\n", getpid());
```

prints `getpid: -42`.

Complete source code can be found [here][seccomp_basic].

[seccomp_basic]: https://github.com/mejedi/blog/tree/master/code/seccomp_basic

## Random in cBPF

We've seen cBPF load instructions such as `ld [26]`. Technically, negative offsets are possible. Clearly, they fall outside packet boundaries. Linux [assigns meaning][5] to certain special offsets. For instance, `SKF_AD_OFFSET + SKF_AD_RXHASH` tells the packet hash while `SKF_AD_OFFSET + SKF_AD_RANDOM` generates TA-DA! a random value.

[5]: https://www.infradead.org/~mchehab/kernel_docs/networking/filter.html#bpf-engine-and-instruction-set

Let's write a seccomp filter that makes `getpid` fails with a *random* `errno`:

```c
struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SKF_AD_OFF + SKF_AD_RANDOM),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K,  0x1ff),
    BPF_STMT(BPF_ALU | BPF_OR | BPF_K, SECCOMP_RET_ERRNO),
    BPF_STMT(BPF_RET | BPF_A, 0),
};
```

Unfortunately, the kernel rejects it.

Even though this code is valid cBPF, seccomp presumably imposes additional restrictions. Let's dive into Linux kernel source code to find out.


## Code spelunking 101

Linux source code is vast. Navigating unfamiliar large code bases is an extremely valuable skill but surprisingly little is published on the topic of getting better at code spelunking.

Linux is exceptionally well structured and written in a "simple" language, therefore simple tools such as `git grep` work well. Navigating C++ code is much harder. I might write *Spelunking 202* some day using LLVM as the subject.

How do we locate a bit of seccomp code that rejects our cBPF programs?

We know that a filter is installed with `prctl(PR_SET_SECCOMP)`. Let's grep for `PR_SET_SECCOMP`. We get multiple hits. We are probably not interested in results from `samples/` and `tools/`, which leaves us with `kernel/sys.c`.

**Takeaway 1:** get familiar with the directory structure. When doing your own projects: settle on a reasonable directory structure. It will help strangers to get around in your code.

```c
SYSCALL_DEFINE5(prctl, int, option, unsigned long, arg2, unsigned long, arg3,
        unsigned long, arg4, unsigned long, arg5)
{
    ...

    switch (option) {
    
    ...

    case PR_SET_SECCOMP:
        error = prctl_set_seccomp(arg2, (char __user *)arg3);
        break;
```

This bit of code from `kernel/sys.c` implements `prctl` syscall. Let's follow the call chain starting from `prctl_set_seccomp`.

Going down the rabbit hole, we finally reach our target:

```c
prctl_set_seccomp
  do_seccomp
    seccomp_set_mode_filter
      seccomp_prepare_user_filter
        seccomp_prepare_filter
          bpf_prog_create_from_user
            seccomp_check_filter
```


**Takeaway 2:** optimism is key. You will have to read through the code and make decisions whether  certain calls look promissing to drill into. Getting a good understanding of the code at this point would be too time consuming. You will have to operate regardless. Trust your gut. Make and refine assumptions. You will make the right call quite often. Backtrack if needed.

Let's take a look at `seccomp_check_filter`:

```c
/**
 *  seccomp_check_filter - verify seccomp filter code
 *  @filter: filter to verify
 *  @flen: length of filter
 *
 * Takes a previously checked filter (by bpf_check_classic) and
 * redirects all filter code that loads struct sk_buff data
 * and related data through seccomp_bpf_load.  It also
 * enforces length and alignment checking of those loads.
 *
 * Returns 0 if the rule set is legal or -EINVAL if not.
 */
static int seccomp_check_filter(struct sock_filter *filter, unsigned int flen)
{
    int pc;
    for (pc = 0; pc < flen; pc++) {
        struct sock_filter *ftest = &filter[pc];
        u16 code = ftest->code;
        u32 k = ftest->k;

        switch (code) {
        case BPF_LD | BPF_W | BPF_ABS:
            ftest->code = BPF_LDX | BPF_W | BPF_ABS;
            /* 32-bit aligned and not out of bounds. */
            if (k >= sizeof(struct seccomp_data) || k & 3)
                return -EINVAL;
            continue;
```

The function examines filter instructions and applies minor rewrites. It rejects any loads that fall outside `struct seccomp_data`. Let's whitelist the magic `SKF_AD_OFF + SKF_AD_RANDOM` offset which otherwise fails this check.

```diff
                switch (code) {
                case BPF_LD | BPF_W | BPF_ABS:
+                       if (ftest->k == SKF_AD_OFF + SKF_AD_RANDOM) continue;
                        ftest->code = BPF_LDX | BPF_W | BPF_ABS;
                        /* 32-bit aligned and not out of bounds. */
                        if (k >= sizeof(struct seccomp_data) || k & 3)
```


## Testing our changes

So we patched Linux kernel and it might actually work! How do we test our change?

I totally didn't expect it but testing kernel changes was an unbelievably smooth experience.

`virtme-ng` (available from `apt` in Ubuntu) streamlines building and testing. While in kernel source tree root, invoke `virtme-ng -b` to configure and build the kernel. `virtme-ng` (without arguments) boots the newly built kernel in QEMU. VM shares filesystem with the host.

This is huge! Whatever is available in the host is available in VM as well. Assuming `./seccomp_rnd` is the path to the binary, we can run it in VM with `virtme-ng ./seccomp_rnd`. We get the following output which confirms that it works:

```
$ virtme-ng ./seccomp_rnd
  -505   -431   -181   -217
    -9    -69    -52   -189
  -419   -380   -130   -194
  -470   -375   -442   -400
```

`seccomp-rnd` arranges for `getpid` to fail with a random `errno`. It calls `getpid` 16 times and dumps results. Complete source code can be found [here][seccomp_rnd].

[seccomp_rnd]: https://github.com/mejedi/blog/tree/master/code/seccomp_rnd

## Conclusion

With a one line addition to the kernel, we made it possible to generate random numbers in seccomp programs. It is handy for error injection tools. While Linux kernel source code is vast, it turns out that without much prior knowledge, one can locate code responsible for features of interest, as demonstrated in *Code spelunking 101*.

Last but not least, testing Linux kernel changes is amazingly smooth with `virtme-ng`.