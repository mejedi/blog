+++
title = 'Ebpf: Dereference of Modified Ctx Ptr Disallowed'
date = 2023-12-17T21:41:12+01:00
draft = false
toc = true
tags = ['ebpf', 'compilers']
+++

Working with ebpf, the technology to *safely* execute custom code inside Linux kernel, can get interesting. Today we find out why `dereference of modified context pointer` makes verifier unhappy and how to fix it.

<!--more-->

We need a toy ebpf program to play with.
The program below discards all incoming IPv4 traffic:

```C
// drop_ipv4.c (uses libbpf headers)
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int drop_ipv4(struct xdp_md *ctx) {

    struct ethhdr *eth = (void *)(long)ctx->data;

    // Mandatory bounds check
    if ((void *)(eth + 1) > (void *)(long)ctx->data_end) return XDP_DROP;

    // Drop all IPv4
    if (eth->h_proto == __bpf_htons(ETH_P_IP)) return XDP_DROP;

    return XDP_PASS;
}
```

`drop_ipv4` is an *XDP* (express data path) program. It attaches to a particular network interface.
The program runs shortly after the device pushes in a network packet.
We didn't yet enter Linux network stack.
The network stack is highly flexible and feature-rich, but flexibility usually harms performance. XDP is an opportunity to create single-purpose, highly-optimized packet handlers.

Modern Linux kernels support many more ebpf program types beyond XDP.
But no matter a program type, the pattern remains the same.
The information a program might need is packed into a context structure, and the program receives a context pointer.
For XDP, the context includes pointers to a packet buffer (`data` and `data_end`).
The corresponding members are defined as `u32` for complicated reasons.
Please ignore ugly typecasts for now.

We assume that `drop_ipv4` will attach to an Ethernet interface.
Therefore, we can determine the protocol from link-layer header.
The program ensures that a packet is big enough before peeking inside.
Finally, we instruct the kernel to either drop the packet if it is IPv4 (by returning `XDP_DROP`) or proceed to the network stack otherwise (`XDP_PASS`).

We need to compile the program first, yielding `drop_ipv4.o` (please ensure that `libbpf` header files are installed).

```sh
clang -c -O2 -target bpf drop_ipv4.c
```

Then we load our program into the kernel.
```sh
bpftool prog load drop_ipv4.o /sys/fs/bpf/drop_ipv4
```
From now on, the program is *pinned* and known as `/sys/fs/bpf/drop_ipv4` (of course, we could've picked a different name at load time).

The program has been loaded into the kernel, but it is not attached to any interface yet.
We can enable it on say `eth0` with

```sh
bpftool net attach xdp pinned /sys/fs/bpf/drop_ipv4 dev eth0
```

Please proceed with caution, as it will prevent IPv4 communication over `eth0`!

## Modified context pointer

Every ebpf program receives a context pointer as the single argument.
Occasionally, when a program gets complex, the kernel complains about `dereference of modified ctx ptr`.
What does it mean to dereference a modified context pointer?
We need to peel off one layer and examine ebpf bytecode to answer this question.
The easiest option is to ask `clang` to emit assembly output, which will be ebpf for `-target bpf`.

```sh
clang -S -O2 -target bpf drop_ipv4.c
```

The command produces `drop_ipv4.s` with the following content (slightly edited for readability):

```c
    r0 = 1
    r2 = *(u32 *)(r1 + 4)
    r1 = *(u32 *)(r1 + 0)
    r3 = r1
    r3 += 14
    if r3 > r2 goto LBB0_3
    r1 = *(u16 *)(r1 + 12)
    if r1 == 8 goto LBB0_3
    r0 = 2
LBB0_3:
    exit
```

The bytecode is spelled in C-like syntax.
Still, it is essentially an assembly language.
This virtual machine has registers.
When a function is called, `r1` holds the first argument.
When a function returns, the result goes into `r0`.

The first instruction initializes function's result in `r0` to 1 (`XDP_DROP`).
Then `ctx->data_end`, a 32-bit value at offset `+4` relative to the context pointer (`r1`), is loaded into `r2`.
Similarly, `ctx->data` at offset `+0` overwrites `r1`.
Both instructions *dereference* the context pointer.

Initially, `r1` holds a context pointer. It is used unmodified by the two dereferences above.
But what if we replace
```c
r2 = *(u32 *)(r1 + 4)
```
with
```c
r2 = r1
r2 += 4
r2 = *(u32 *)(r2 + 0)
```
? We've artificially introduced a *modified context pointer*.
Let's manually make the change in `drop_ipv4.s`, compile, and attempt to load the program.
It fails with the following diagnostics:
```plain
0: (b7) r0 = 1
1: (bf) r2 = r1
2: (07) r2 += 4
3: (61) r2 = *(u32 *)(r2 +0)
dereference of modified ctx ptr R2 off=4 disallowed
```

Why does the kernel have issues with a modified context pointer?
Please keep in mind that effective read offset within the context defines semantics of the resulting value.
E.g., XDP context has `data` at `+0` and `data_end` at `+4`.
There's simply no way to support variable offsets.
It might be possible to prove that offset is fixed with a more elaborate analysis, but the added complexity needs to be justified.
After all, the verifier is probably the most complex code found in the kernel.
Any defects in this area could have severe security implications.
Presumably, the kernel deliberately [rejects](https://elixir.bootlin.com/linux/v6.5-rc5/source/kernel/bpf/verifier.c#L4942) modified context pointers to keep complexity in check.

## The need for a workaround

So far we've descended to bytecode level and understood the precise nature of the `modified ctx ptr disallowed` error.
We triggered this error on purpose by editing bytecode.
Unfortunately, compiler could ocasionally generate similar instruction sequences for a perfectly valid program. It happens more often when a program gets complex.

It is yet unclear what causes a compiler to emit such code and whether we can prevent it from happening.
Why does a compiler beleive that replacing
```c
r2 = *(u32 *)(r1 + 4)
```
with
```c
r2 = r1
r2 += 4
r2 = *(u32 *)(r2 + 0)
```
could be beneficial?

It typically happens when a memory load is the last expression involving a context pointer, hence the first copy `r2 = r1` becomes unnecessary.
Still, even with the copy eliminated, it is 2 instructions instead of 1.
An important thing to keep in mind is that fewer instructions is not necesserily better.
Modern CPUs have complex execution pipelines and sometimes extra computations could be taken in for free if the full bandwidth is underutilised.
Further, memory loads with zero offset (`r2 = *(u32 *)(r2 + 0)`) typically have lower latency, hence using an already *offset* pointer is beneficial.
Compiler makes reading a context field a tiny notch faster by producing a modified pointer many instructions beforehand for free.

Compiler elaborately models execution pipelines for native targets such as `x86_64` and `aarch64`.
It is unclear what kind of a model could it use for a *virtual* target, such as `ebpf`.
My educated guess is that there's still some model in use, intentional or not.

`Ebpf` target leverages much of the compiler framework built for native targets.
It inherits many powerful optimisiation passes, some of them with a potential to produce code that fails to validate.
Compilers will improve eventually. But as of today, we have to come up with a workaround.

How can we ensure that a problematic instruction sequence is not generated?
The challenge is that compiler doesn't optimise a line at a time, it considers whole function bodies.
Even if we find a code shape that doesn't trigger the issue today, it might resurface again due to unrelated code changes or compiler update.
It doesn't look good.
We need something more robust.

In this particular case, compiler is too smart for its own good.
It realises that reading a structure field involves address calculation and a memory load.
A single `load` instruction can handle both, or it could be 2 separate instructions.
We need a primitive for reading from context that compiler can't decompose into sub-ops and therefore won't generate 2 separate instructions.
A black box.

## Inline assembly to the resque

We can write [assembly inline](https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html) in C code, e.g. `asm("r1 = 42");`.
Interestingly, we can leave some gaps for compiler to fill in:

```c
static __always_inline void *xdp_data(const struct xdp_md *ctx) {
   void *data;

   asm("%[res] = *(u32 *)(%[base] + %[offset])",
       : [res]"=r"(data)
       : [base]"r"(ctx), [offset]"i"(offsetof(struct xdp_md, data)), "m"(*ctx)

   return data;
}
```

We ask compiler to pick up registers for `res` and `base`.
So `"%[res] = *(u32 *)(%[base] + %[offset])"` turns into e.g. `"r2 = *(u32 *)(r1 + 4)"`.
`Base` is initialised with a context pointer (`ctx`), and `res` is copied to `data`.
It might look as if some redundant copies are happening (`ctx` to `base`, `res` to `data`).
In fact, compiler will eliminate copies by picking up registers strategically.
For instance, both `ctx` and `base` will share the same register.

This way, we have *total* control over instructions used for loading context fields.
Libbpf itself employs this technique for static tail calls so that the instruction sequence is exactly as expected and can be [optimised](https://elixir.bootlin.com/linux/v6.5-rc5/source/tools/lib/bpf/bpf_helpers.h#L141) by ebpf JIT compiler.
Inline assembly is tightly integrated with the optimiser.
A function leveraging inline assembly inlines without issues.
But compiler is not allowed to alter the offset or to replace the load with a different instruction sequence.
Therefore, unlike straightforward `ctx->data`, we won't trigger `modified ctx ptr disallowed` error ever again no matter the surrounding code or optimisation settings.

## Common subexpression elimination

It is worth mentioning that compiler will eliminate redundant calls to `xdp_data()` (aka common subexpression elimination).
If the result is still lingering in a register somewhere, there's no need to recompute it.
It is quite handy when logic is split into smaler inlined functions.
There's no need to cache `data` pointer explicitly.
We can simply pass  `ctx` around and obtain  `data` pointer when needed without any performance impact.

It is important though that  `data` pointer is not cached across calls that potentially mutate `ctx` such as `bpf_xdp_adjust_head()`.
Luckily, we can declare that [result depends on the memory contents](https://stackoverflow.com/questions/56432259/how-can-i-indicate-that-the-memory-pointed-to-by-an-inline-asm-argument-may-be).
This is why we have a dummy memory input `"m"(*ctx)`.

## Wrapping up

Today we descended down to ebpf bytecode level to understand `dereference of modified ctx ptr disallowed` error.
The troublesome instruction sequence is ocasionally introduced by optimising compiler in complex ebpf programs.

We developed a robust workaround by leveraging inline assembly, a lesser known compiler feature.
We explored potential performance implications and concluded that there are none compared to  straightforward `ctx->data`.

Stay tuned for more ebpf content!
