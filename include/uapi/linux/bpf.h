/* Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UAPI__LINUX_BPF_H__
#define _UAPI__LINUX_BPF_H__

#include <linux/types.h>
#include <linux/bpf_common.h>

/* Extended instruction set based on top of classic BPF */

/* instruction classes */
#define BPF_JMP32	0x06	/* jmp mode in word width */
#define BPF_ALU64	0x07	/* alu mode in double word width */

/* ld/ldx fields */
#define BPF_DW		0x18	/* double word (64-bit) */
#define BPF_XADD	0xc0	/* exclusive add */

/* alu/jmp fields */
#define BPF_MOV		0xb0	/* mov reg to reg */
#define BPF_ARSH	0xc0	/* sign extending arithmetic shift right */

/* change endianness of a register */
#define BPF_END		0xd0	/* flags for endianness conversion: */
#define BPF_TO_LE	0x00	/* convert to little-endian */
#define BPF_TO_BE	0x08	/* convert to big-endian */
#define BPF_FROM_LE	BPF_TO_LE
#define BPF_FROM_BE	BPF_TO_BE

/* jmp encodings */
#define BPF_JNE		0x50	/* jump != */
#define BPF_JLT		0xa0	/* LT is unsigned, '<' */
#define BPF_JLE		0xb0	/* LE is unsigned, '<=' */
#define BPF_JSGT	0x60	/* SGT is signed '>', GT in x86 */
#define BPF_JSGE	0x70	/* SGE is signed '>=', GE in x86 */
#define BPF_JSLT	0xc0	/* SLT is signed, '<' */
#define BPF_JSLE	0xd0	/* SLE is signed, '<=' */
#define BPF_CALL	0x80	/* function call */
#define BPF_EXIT	0x90	/* function return */

/* Register numbers */
enum {
	BPF_REG_0 = 0,
	BPF_REG_1,
	BPF_REG_2,
	BPF_REG_3,
	BPF_REG_4,
	BPF_REG_5,
	BPF_REG_6,
	BPF_REG_7,
	BPF_REG_8,
	BPF_REG_9,
	BPF_REG_10,
	__MAX_BPF_REG,
};

/* BPF has 10 general purpose 64-bit registers and stack frame. */
#define MAX_BPF_REG	__MAX_BPF_REG

struct bpf_insn {
	__u8	code;		/* opcode */
	__u8	dst_reg:4;	/* dest register */
	__u8	src_reg:4;	/* source register */
	__s16	off;		/* signed offset */
	__s32	imm;		/* signed immediate constant */
};

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};

struct bpf_cgroup_storage_key {
	__u64	cgroup_inode_id;	/* cgroup inode id */
	__u32	attach_type;		/* program attach type */
};

/* BPF syscall commands, see bpf(2) man-page for details. */
enum bpf_cmd {
	BPF_MAP_CREATE,
	BPF_MAP_LOOKUP_ELEM,
	BPF_MAP_UPDATE_ELEM,
	BPF_MAP_DELETE_ELEM,
	BPF_MAP_GET_NEXT_KEY,
	BPF_PROG_LOAD,
	BPF_OBJ_PIN,
	BPF_OBJ_GET,
	BPF_PROG_ATTACH,
	BPF_PROG_DETACH,
	BPF_PROG_TEST_RUN,
	BPF_PROG_GET_NEXT_ID,
	BPF_MAP_GET_NEXT_ID,
	BPF_PROG_GET_FD_BY_ID,
	BPF_MAP_GET_FD_BY_ID,
	BPF_OBJ_GET_INFO_BY_FD,
	BPF_PROG_QUERY,
	BPF_RAW_TRACEPOINT_OPEN,
	BPF_BTF_LOAD = 18,
	BPF_BTF_GET_FD_BY_ID,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
	BPF_MAP_FREEZE,
	BPF_BTF_GET_NEXT_ID,
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC,
	BPF_MAP_TYPE_HASH,
	BPF_MAP_TYPE_ARRAY,
	BPF_MAP_TYPE_PROG_ARRAY,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	BPF_MAP_TYPE_PERCPU_HASH,
	BPF_MAP_TYPE_PERCPU_ARRAY,
	BPF_MAP_TYPE_STACK_TRACE,
	BPF_MAP_TYPE_CGROUP_ARRAY,
	BPF_MAP_TYPE_LRU_HASH,
	BPF_MAP_TYPE_LRU_PERCPU_HASH,
	BPF_MAP_TYPE_LPM_TRIE,
	BPF_MAP_TYPE_ARRAY_OF_MAPS,
	BPF_MAP_TYPE_HASH_OF_MAPS,
	BPF_MAP_TYPE_DEVMAP,
	BPF_MAP_TYPE_SOCKMAP,
	BPF_MAP_TYPE_CPUMAP,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE,
	BPF_MAP_TYPE_STACK,
	BPF_MAP_TYPE_SK_STORAGE,
	BPF_MAP_TYPE_DEVMAP_HASH,
	BPF_MAP_TYPE_RINGBUF = 27,
};

/* Note that tracing related programs such as
 * BPF_PROG_TYPE_{KPROBE,TRACEPOINT,PERF_EVENT,RAW_TRACEPOINT}
 * are not subject to a stable API since kernel internal data
 * structures can change from release to release and may
 * therefore break existing tracing BPF programs. Tracing BPF
 * programs correspond to /a/ specific kernel which is to be
 * analyzed, and not /a/ specific kernel /and/ all future ones.
 */
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS,
	BPF_CGROUP_INET_EGRESS,
	BPF_CGROUP_INET_SOCK_CREATE,
	BPF_CGROUP_SOCK_OPS,
	BPF_SK_SKB_STREAM_PARSER,
	BPF_SK_SKB_STREAM_VERDICT,
	BPF_CGROUP_DEVICE,
	BPF_SK_MSG_VERDICT,
	BPF_CGROUP_INET4_BIND,
	BPF_CGROUP_INET6_BIND,
	BPF_CGROUP_INET4_CONNECT,
	BPF_CGROUP_INET6_CONNECT,
	BPF_CGROUP_INET4_POST_BIND,
	BPF_CGROUP_INET6_POST_BIND,
	BPF_CGROUP_UDP4_SENDMSG,
	BPF_CGROUP_UDP6_SENDMSG,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG,
	BPF_CGROUP_UDP6_RECVMSG,
	BPF_CGROUP_GETSOCKOPT,
	BPF_CGROUP_SETSOCKOPT,
	BPF_TRACE_RAW_TP = 23,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	__MAX_BPF_ATTACH_TYPE
};

#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE

/* cgroup-bpf attach flags used in BPF_PROG_ATTACH command
 *
 * NONE(default): No further bpf programs allowed in the subtree.
 *
 * BPF_F_ALLOW_OVERRIDE: If a sub-cgroup installs some bpf program,
 * the program in this cgroup yields to sub-cgroup program.
 *
 * BPF_F_ALLOW_MULTI: If a sub-cgroup installs some bpf program,
 * that cgroup program gets run in addition to the program in this cgroup.
 *
 * Only one program is allowed to be attached to a cgroup with
 * NONE or BPF_F_ALLOW_OVERRIDE flag.
 * Attaching another program on top of NONE or BPF_F_ALLOW_OVERRIDE will
 * release old program and attach the new one. Attach flags has to match.
 *
 * Multiple programs are allowed to be attached to a cgroup with
 * BPF_F_ALLOW_MULTI flag. They are executed in FIFO order
 * (those that were attached first, run first)
 * The programs of sub-cgroup are executed first, then programs of
 * this cgroup and then programs of parent cgroup.
 * When children program makes decision (like picking TCP CA or sock bind)
 * parent program has a chance to override it.
 *
 * With BPF_F_ALLOW_MULTI a new program is added to the end of the list of
 * programs for a cgroup. Though it's possible to replace an old program at
 * any position by also specifying BPF_F_REPLACE flag and position itself in
 * replace_bpf_fd attribute. Old program at this position will be released.
 *
 * A cgroup with MULTI or OVERRIDE flag allows any attach flags in sub-cgroups.
 * A cgroup with NONE doesn't allow any programs in sub-cgroups.
 * Ex1:
 * cgrp1 (MULTI progs A, B) ->
 *    cgrp2 (OVERRIDE prog C) ->
 *      cgrp3 (MULTI prog D) ->
 *        cgrp4 (OVERRIDE prog E) ->
 *          cgrp5 (NONE prog F)
 * the event in cgrp5 triggers execution of F,D,A,B in that order.
 * if prog F is detached, the execution is E,D,A,B
 * if prog F and D are detached, the execution is E,A,B
 * if prog F, E and D are detached, the execution is C,A,B
 *
 * All eligible programs are executed regardless of return code from
 * earlier programs.
 */
#define BPF_F_ALLOW_OVERRIDE	(1U << 0)
#define BPF_F_ALLOW_MULTI	(1U << 1)
#define BPF_F_REPLACE		(1U << 2)

/* If BPF_F_STRICT_ALIGNMENT is used in BPF_PROG_LOAD command, the
 * verifier will perform strict alignment checking as if the kernel
 * has been built with CONFIG_EFFICIENT_UNALIGNED_ACCESS not set,
 * and NET_IP_ALIGN defined to 2.
 */
#define BPF_F_STRICT_ALIGNMENT	(1U << 0)

/* If BPF_F_ANY_ALIGNMENT is used in BPF_PROF_LOAD command, the
 * verifier will allow any alignment whatsoever.  On platforms
 * with strict alignment requirements for loads ands stores (such
 * as sparc and mips) the verifier validates that all loads and
 * stores provably follow this requirement.  This flag turns that
 * checking and enforcement off.
 *
 * It is mostly used for testing when we want to validate the
 * context and memory access aspects of the verifier, but because
 * of an unaligned access the alignment check would trigger before
 * the one we are interested in.
 */
#define BPF_F_ANY_ALIGNMENT	(1U << 1)

/* BPF_F_TEST_RND_HI32 is used in BPF_PROG_LOAD command for testing purpose.
 * Verifier does sub-register def/use analysis and identifies instructions whose
 * def only matters for low 32-bit, high 32-bit is never referenced later
 * through implicit zero extension. Therefore verifier notifies JIT back-ends
 * that it is safe to ignore clearing high 32-bit for these instructions. This
 * saves some back-ends a lot of code-gen. However such optimization is not
 * necessary on some arches, for example x86_64, arm64 etc, whose JIT back-ends
 * hence hasn't used verifier's analysis result. But, we really want to have a
 * way to be able to verify the correctness of the described optimization on
 * x86_64 on which testsuites are frequently exercised.
 *
 * So, this flag is introduced. Once it is set, verifier will randomize high
 * 32-bit for those instructions who has been identified as safe to ignore them.
 * Then, if verifier is not doing correct analysis, such randomization will
 * regress tests to expose bugs.
 */
#define BPF_F_TEST_RND_HI32	(1U << 2)

/* The verifier internal test flag. Behavior is undefined */
#define BPF_F_TEST_STATE_FREQ	(1U << 3)

/* When BPF ldimm64's insn[0].src_reg != 0 then this can have
 * two extensions:
 *
 * insn[0].src_reg:  BPF_PSEUDO_MAP_FD   BPF_PSEUDO_MAP_VALUE
 * insn[0].imm:      map fd              map fd
 * insn[1].imm:      0                   offset into value
 * insn[0].off:      0                   0
 * insn[1].off:      0                   0
 * ldimm64 rewrite:  address of map      address of map[0]+offset
 * verifier type:    CONST_PTR_TO_MAP    PTR_TO_MAP_VALUE
 */
#define BPF_PSEUDO_MAP_FD	1
#define BPF_PSEUDO_MAP_VALUE	2

/* when bpf_call->src_reg == BPF_PSEUDO_CALL, bpf_call->imm == pc-relative
 * offset to another bpf function
 */
#define BPF_PSEUDO_CALL		1

/* flags for BPF_MAP_UPDATE_ELEM command */
#define BPF_ANY		0 /* create new element or update existing */
#define BPF_NOEXIST	1 /* create new element if it didn't exist */
#define BPF_EXIST	2 /* update existing element */
#define BPF_F_LOCK	4 /* spin_lock-ed map_lookup/map_update */

/* flags for BPF_MAP_CREATE command */
#define BPF_F_NO_PREALLOC	(1U << 0)
/* Instead of having one common LRU list in the
 * BPF_MAP_TYPE_LRU_[PERCPU_]HASH map, use a percpu LRU list
 * which can scale and perform better.
 * Note, the LRU nodes (including free nodes) cannot be moved
 * across different LRU lists.
 */
#define BPF_F_NO_COMMON_LRU	(1U << 1)
/* Specify numa node during map creation */
#define BPF_F_NUMA_NODE		(1U << 2)

#define BPF_OBJ_NAME_LEN 16U

/* Flags for accessing BPF object */
#define BPF_F_RDONLY		(1U << 3)
#define BPF_F_WRONLY		(1U << 4)

/* Flag for stack_map, store build_id+offset instead of pointer */
#define BPF_F_STACK_BUILD_ID	(1U << 5)

/* Zero-initialize hash function seed. This should only be used for testing. */
#define BPF_F_ZERO_SEED		(1U << 6)

/* Flags for accessing BPF object from program side. */
#define BPF_F_RDONLY_PROG	(1U << 7)

/* Clone map from listener for newly accepted socket */
#define BPF_F_CLONE		(1U << 9)

/* Enable memory-mapping BPF map */
#define BPF_F_MMAPABLE		(1U << 10)

/* flags for BPF_PROG_QUERY */
#define BPF_F_QUERY_EFFECTIVE	(1U << 0)

enum bpf_stack_build_id_status {
	/* user space need an empty entry to identify end of a trace */
	BPF_STACK_BUILD_ID_EMPTY = 0,
	/* with valid build_id and offset */
	BPF_STACK_BUILD_ID_VALID = 1,
	/* couldn't get build_id, fallback to ip */
	BPF_STACK_BUILD_ID_IP = 2,
};

#define BPF_BUILD_ID_SIZE 20
struct bpf_stack_build_id {
	__s32		status;
	unsigned char	build_id[BPF_BUILD_ID_SIZE];
	union {
		__u64	offset;
		__u64	ip;
	};
};

union bpf_attr {
	struct { /* anonymous struct used by BPF_MAP_CREATE command */
		__u32	map_type;	/* one of enum bpf_map_type */
		__u32	key_size;	/* size of key in bytes */
		__u32	value_size;	/* size of value in bytes */
		__u32	max_entries;	/* max number of entries in a map */
		__u32	map_flags;	/* BPF_MAP_CREATE related
					 * flags defined above.
					 */
		__u32	inner_map_fd;	/* fd pointing to the inner map */
		__u32	numa_node;	/* numa node (effective only if
					 * BPF_F_NUMA_NODE is set).
					 */
		char	map_name[BPF_OBJ_NAME_LEN];
		__u32	map_ifindex;	/* ifindex of netdev to create on */
		__u32	btf_fd;		/* fd pointing to a BTF type data */
		__u32	btf_key_type_id;	/* BTF type_id of the key */
		__u32	btf_value_type_id;	/* BTF type_id of the value */
	};

	struct { /* anonymous struct used by BPF_MAP_*_ELEM commands */
		__u32		map_fd;
		__aligned_u64	key;
		union {
			__aligned_u64 value;
			__aligned_u64 next_key;
		};
		__u64		flags;
	};

	struct { /* anonymous struct used by BPF_PROG_LOAD command */
		__u32		prog_type;	/* one of enum bpf_prog_type */
		__u32		insn_cnt;
		__aligned_u64	insns;
		__aligned_u64	license;
		__u32		log_level;	/* verbosity level of verifier */
		__u32		log_size;	/* size of user buffer */
		__aligned_u64	log_buf;	/* user supplied buffer */
		__u32		kern_version;	/* not used */
		__u32		prog_flags;
		char		prog_name[BPF_OBJ_NAME_LEN];
		__u32		prog_ifindex;	/* ifindex of netdev to prep for */
		/* For some prog types expected attach type must be known at
		 * load time to verify attach type specific parts of prog
		 * (context accesses, allowed helpers, etc).
		 */
		__u32		expected_attach_type;
		__u32		prog_btf_fd;	/* fd pointing to BTF type data */
		__u32		func_info_rec_size;	/* userspace bpf_func_info size */
		__aligned_u64	func_info;	/* func info */
		__u32		func_info_cnt;	/* number of bpf_func_info records */
		__u32		line_info_rec_size;	/* userspace bpf_line_info size */
		__aligned_u64	line_info;	/* line info */
		__u32		line_info_cnt;	/* number of bpf_line_info records */
		__u32		attach_btf_id;	/* in-kernel BTF type id to attach to */
	};

	struct { /* anonymous struct used by BPF_OBJ_* commands */
		__aligned_u64	pathname;
		__u32		bpf_fd;
		__u32		file_flags;
	};

	struct { /* anonymous struct used by BPF_PROG_ATTACH/DETACH commands */
		__u32		target_fd;	/* container object to attach to */
		__u32		attach_bpf_fd;	/* eBPF program to attach */
		__u32		attach_type;
		__u32		attach_flags;
		__u32		replace_bpf_fd;	/* previously attached eBPF
						 * program to replace if
						 * BPF_F_REPLACE is used
						 */
	};

	struct { /* anonymous struct used by BPF_PROG_TEST_RUN command */
		__u32		prog_fd;
		__u32		retval;
		__u32		data_size_in;
		__u32		data_size_out;
		__aligned_u64	data_in;
		__aligned_u64	data_out;
		__u32		repeat;
		__u32		duration;
		__u32		ctx_size_in;	/* input: len of ctx_in */
		__u32		ctx_size_out;	/* input/output: len of ctx_out
						 *   returns ENOSPC if ctx_out
						 *   is too small.
						 */
		__aligned_u64	ctx_in;
		__aligned_u64	ctx_out;
	} test;

	struct { /* anonymous struct used by BPF_*_GET_*_ID */
		union {
			__u32		start_id;
			__u32		prog_id;
			__u32		map_id;
			__u32		btf_id;
		};
		__u32		next_id;
		__u32		open_flags;
	};

	struct { /* anonymous struct used by BPF_OBJ_GET_INFO_BY_FD */
		__u32		bpf_fd;
		__u32		info_len;
		__aligned_u64	info;
	} info;

	struct { /* anonymous struct used by BPF_PROG_QUERY command */
		__u32		target_fd;	/* container object to query */
		__u32		attach_type;
		__u32		query_flags;
		__u32		attach_flags;
		__aligned_u64	prog_ids;
		__u32		prog_cnt;
	} query;

	struct {
 		__u64 name;
 		__u32 prog_fd;
 	} raw_tracepoint;

	struct { /* anonymous struct for BPF_BTF_LOAD */
		__aligned_u64	btf;
		__aligned_u64	btf_log_buf;
		__u32		btf_size;
		__u32		btf_log_size;
		__u32		btf_log_level;
	};
} __attribute__((aligned(8)));

/* BPF helper function descriptions:
 *
 * void *bpf_map_lookup_elem(&map, &key)
 *     Return: Map value or NULL
 *
 * int bpf_map_update_elem(&map, &key, &value, flags)
 *     Return: 0 on success or negative error
 *
 * int bpf_map_delete_elem(&map, &key)
 *     Return: 0 on success or negative error
 *
 * int bpf_map_push_elem(struct bpf_map *map, const void *value, u64 flags)
 * 	Description
 * 		Push an element *value* in *map*. *flags* is one of:
 *
 * 		**BPF_EXIST**
 * 		If the queue/stack is full, the oldest element is removed to
 * 		make room for this.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		For tracing programs, safely attempt to read *size* bytes from
 * 		kernel space address *unsafe_ptr* and store the data in *dst*.
 *
 * 		Generally, use bpf_probe_read_user() or bpf_probe_read_kernel()
 * 		instead.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_ktime_get_ns(void)
 *     Return: current ktime
 *
 * int bpf_trace_printk(const char *fmt, int fmt_size, ...)
 *     Return: length of buffer written or negative error
 *
 * u32 bpf_prandom_u32(void)
 *     Return: random value
 *
 * u32 bpf_raw_smp_processor_id(void)
 *     Return: SMP processor ID
 *
 * int bpf_skb_store_bytes(skb, offset, from, len, flags)
 *     store bytes into packet
 *     @skb: pointer to skb
 *     @offset: offset within packet from skb->mac_header
 *     @from: pointer where to copy bytes from
 *     @len: number of bytes to store into packet
 *     @flags: bit 0 - if true, recompute skb->csum
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l3_csum_replace(skb, offset, from, to, flags)
 *     recompute IP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where IP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_l4_csum_replace(skb, offset, from, to, flags)
 *     recompute TCP/UDP checksum
 *     @skb: pointer to skb
 *     @offset: offset within packet where TCP/UDP checksum is located
 *     @from: old value of header field
 *     @to: new value of header field
 *     @flags: bits 0-3 - size of header field
 *             bit 4 - is pseudo header
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_tail_call(ctx, prog_array_map, index)
 *     jump into another BPF program
 *     @ctx: context pointer passed to next program
 *     @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
 *     @index: index inside array that selects specific program to run
 *     Return: 0 on success or negative error
 *
 * int bpf_clone_redirect(skb, ifindex, flags)
 *     redirect to another netdev
 *     @skb: pointer to skb
 *     @ifindex: ifindex of the net device
 *     @flags: bit 0 - if set, redirect to ingress instead of egress
 *             other bits - reserved
 *     Return: 0 on success or negative error
 *
 * u64 bpf_get_current_pid_tgid(void)
 *     Return: current->tgid << 32 | current->pid
 *
 * u64 bpf_get_current_uid_gid(void)
 *     Return: current_gid << 32 | current_uid
 *
 * int bpf_get_current_comm(char *buf, int size_of_buf)
 *     stores current->comm into buf
 *     Return: 0 on success or negative error
 *
 * u32 bpf_get_cgroup_classid(skb)
 *     retrieve a proc's classid
 *     @skb: pointer to skb
 *     Return: classid if != 0
 *
 * int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_vlan_pop(skb)
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_get_tunnel_key(skb, key, size, flags)
 * int bpf_skb_set_tunnel_key(skb, key, size, flags)
 *     retrieve or populate tunnel metadata
 *     @skb: pointer to skb
 *     @key: pointer to 'struct bpf_tunnel_key'
 *     @size: size of 'struct bpf_tunnel_key'
 *     @flags: room for future extensions
 *     Return: 0 on success or negative error
 *
 * u64 bpf_perf_event_read(&map, index)
 *     Return: Number events read or error code
 *
 * int bpf_redirect(ifindex, flags)
 *     redirect to another netdev
 *     @ifindex: ifindex of the net device
 *     @flags:
 *	  cls_bpf:
 *          bit 0 - if set, redirect to ingress instead of egress
 *          other bits - reserved
 *	  xdp_bpf:
 *	    all bits - reserved
 *     Return: cls_bpf: TC_ACT_REDIRECT on success or TC_ACT_SHOT on error
 *	       xdp_bfp: XDP_REDIRECT on success or XDP_ABORT on error
 * int bpf_redirect_map(map, key, flags)
 *     redirect to endpoint in map
 *     @map: pointer to dev map
 *     @key: index in map to lookup
 *     @flags: --
 *     Return: XDP_REDIRECT on success or XDP_ABORT on error
 *
 * u32 bpf_get_route_realm(skb)
 *     retrieve a dst's tclassid
 *     @skb: pointer to skb
 *     Return: realm if != 0
 *
 * int bpf_perf_event_output(ctx, map, index, data, size)
 *     output perf raw sample
 *     @ctx: struct pt_regs*
 *     @map: pointer to perf_event_array map
 *     @index: index of event in the map
 *     @data: data on stack to be output as raw data
 *     @size: size of data
 *     Return: 0 on success or negative error
 *
 * int bpf_get_stackid(ctx, map, flags)
 *     walk user or kernel stack and return id
 *     @ctx: struct pt_regs*
 *     @map: pointer to stack_trace map
 *     @flags: bits 0-7 - numer of stack frames to skip
 *             bit 8 - collect user stack instead of kernel
 *             bit 9 - compare stacks by hash only
 *             bit 10 - if two different stacks hash into the same stackid
 *                      discard old
 *             other bits - reserved
 *     Return: >= 0 stackid on success or negative error
 *
 * s64 bpf_csum_diff(from, from_size, to, to_size, seed)
 *     calculate csum diff
 *     @from: raw from buffer
 *     @from_size: length of from buffer
 *     @to: raw to buffer
 *     @to_size: length of to buffer
 *     @seed: optional seed
 *     Return: csum result or negative error code
 *
 * int bpf_skb_get_tunnel_opt(skb, opt, size)
 *     retrieve tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: option size
 *
 * int bpf_skb_set_tunnel_opt(skb, opt, size)
 *     populate tunnel options metadata
 *     @skb: pointer to skb
 *     @opt: pointer to raw tunnel option data
 *     @size: size of @opt
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_proto(skb, proto, flags)
 *     Change protocol of the skb. Currently supported is v4 -> v6,
 *     v6 -> v4 transitions. The helper will also resize the skb. eBPF
 *     program is expected to fill the new headers via skb_store_bytes
 *     and lX_csum_replace.
 *     @skb: pointer to skb
 *     @proto: new skb->protocol type
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_change_type(skb, type)
 *     Change packet type of skb.
 *     @skb: pointer to skb
 *     @type: new skb->pkt_type type
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_under_cgroup(skb, map, index)
 *     Check cgroup2 membership of skb
 *     @skb: pointer to skb
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 skb failed the cgroup2 descendant test
 *       == 1 skb succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * u32 bpf_get_hash_recalc(skb)
 *     Retrieve and possibly recalculate skb->hash.
 *     @skb: pointer to skb
 *     Return: hash
 *
 * u64 bpf_get_current_task(void)
 *     Returns current task_struct
 *     Return: current
 *
 * int bpf_probe_write_user(void *dst, void *src, int len)
 *     safely attempt to write to a location
 *     @dst: destination address in userspace
 *     @src: source address on stack
 *     @len: number of bytes to copy
 *     Return: 0 on success or negative error
 *
 * int bpf_current_task_under_cgroup(map, index)
 *     Check cgroup2 membership of current task
 *     @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
 *     @index: index of the cgroup in the bpf_map
 *     Return:
 *       == 0 current failed the cgroup2 descendant test
 *       == 1 current succeeded the cgroup2 descendant test
 *        < 0 error
 *
 * int bpf_skb_change_tail(skb, len, flags)
 *     The helper will resize the skb to the given new size, to be used f.e.
 *     with control messages.
 *     @skb: pointer to skb
 *     @len: new skb length
 *     @flags: reserved
 *     Return: 0 on success or negative error
 *
 * int bpf_skb_pull_data(skb, len)
 *     The helper will pull in non-linear data in case the skb is non-linear
 *     and not all of len are part of the linear section. Only needed for
 *     read/write with direct packet access.
 *     @skb: pointer to skb
 *     @len: len to make read/writeable
 *     Return: 0 on success or negative error
 *
 * s64 bpf_csum_update(skb, csum)
 *     Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
 *     @skb: pointer to skb
 *     @csum: csum to add
 *     Return: csum on success or negative error
 *
 * void bpf_set_hash_invalid(skb)
 *     Invalidate current skb->hash.
 *     @skb: pointer to skb
 *
 * int bpf_get_numa_node_id()
 *     Return: Id of current NUMA node.
 *
 * int bpf_skb_change_head()
 *     Grows headroom of skb and adjusts MAC header offset accordingly.
 *     Will extends/reallocae as required automatically.
 *     May change skb data pointer and will thus invalidate any check
 *     performed for direct packet access.
 *     @skb: pointer to skb
 *     @len: length of header to be pushed in front
 *     @flags: Flags (unused for now)
 *     Return: 0 on success or negative error
 *
 * int bpf_xdp_adjust_head(xdp_md, delta)
 *     Adjust the xdp_md.data by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data
 *     Return: 0 on success or negative on error
 *
 * int bpf_probe_read_str(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		Copy a NUL terminated string from an unsafe kernel address
 * 		*unsafe_ptr* to *dst*. See bpf_probe_read_kernel_str() for
 * 		more details.
 *
 * 		Generally, use bpf_probe_read_user_str() or bpf_probe_read_kernel_str()
 * 		instead.
 * 	Return
 * 		On success, the strictly positive length of the string,
 * 		including the trailing NUL character. On error, a negative
 * 		value.
 *
 * u64 bpf_get_socket_cookie(struct sk_buff *skb)
 * 	Description
 * 		If the **struct sk_buff** pointed by *skb* has a known socket,
 * 		retrieve the cookie (generated by the kernel) of this socket.
 * 		If no cookie has been set yet, generate a new cookie. Once
 * 		generated, the socket cookie remains stable for the life of the
 * 		socket. This helper can be useful for monitoring per socket
 * 		networking traffic statistics as it provides a unique socket
 * 		identifier per namespace.
 * 	Return
 * 		A 8-byte long non-decreasing number on success, or 0 if the
 * 		socket field is missing inside *skb*.
 *
 * u64 bpf_get_socket_cookie(struct bpf_sock_addr *ctx)
 * 	Description
 * 		Equivalent to bpf_get_socket_cookie() helper that accepts
 * 		*skb*, but gets socket from **struct bpf_sock_addr** contex.
 * 	Return
 * 		A 8-byte long non-decreasing number.
 *
 * u64 bpf_get_socket_cookie(struct bpf_sock_ops *ctx)
 * 	Description
 * 		Equivalent to bpf_get_socket_cookie() helper that accepts
 * 		*skb*, but gets socket from **struct bpf_sock_ops** contex.
 * 	Return
 * 		A 8-byte long non-decreasing number.
 *
 * u32 bpf_get_socket_uid(struct sk_buff *skb)
 * 	Return
 * 		The owner UID of the socket associated to *skb*. If the socket
 * 		is **NULL**, or if it is not a full socket (i.e. if it is a
 * 		time-wait or a request socket instead), **overflowuid** value
 * 		is returned (note that **overflowuid** might also be the actual
 * 		UID value for the socket).
 *
 * u32 bpf_set_hash(struct sk_buff *skb, u32 hash)
 * 	Description
 * 		Set the full hash for *skb* (set the field *skb*\ **->hash**)
 * 		to value *hash*.
 * 	Return
 * 		0
 *
 * int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls setsockopt. Not all opts are available, only those with
 *     integer optvals plus TCP_CONGESTION.
 *     Supported levels: SOL_SOCKET and IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: SOL_SOCKET or IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_getsockopt(bpf_socket, level, optname, optval, optlen)
 *     Calls getsockopt. Not all opts are available.
 *     Supported levels: IPPROTO_TCP
 *     @bpf_socket: pointer to bpf_socket
 *     @level: IPPROTO_TCP
 *     @optname: option name
 *     @optval: pointer to option value
 *     @optlen: length of optval in bytes
 *     Return: 0 or negative error
 *
 * int bpf_sock_ops_cb_flags_set(bpf_sock_ops, flags)
 *     Set callback flags for sock_ops
 *     @bpf_sock_ops: pointer to bpf_sock_ops_kern struct
 *     @flags: flags value
 *     Return: 0 for no error
 *             -EINVAL if there is no full tcp socket
 *             bits in flags that are not supported by current kernel
 *
 * int bpf_skb_adjust_room(skb, len_diff, mode, flags)
 *     Grow or shrink room in sk_buff.
 *     @skb: pointer to skb
 *     @len_diff: (signed) amount of room to grow/shrink
 *     @mode: operation mode (enum bpf_adj_room_mode)
 *     @flags: reserved for future use
 *     Return: 0 on success or negative error code
 *
 * int bpf_sk_redirect_map(map, key, flags)
 *     Redirect skb to a sock in map using key as a lookup key for the
 *     sock in map.
 *     @map: pointer to sockmap
 *     @key: key to lookup sock in map
 *     @flags: reserved for future use
 *     Return: SK_PASS
 *
 * int bpf_sock_map_update(skops, map, key, flags)
 *	@skops: pointer to bpf_sock_ops
 *	@map: pointer to sockmap to update
 *	@key: key to insert/update sock in map
 *	@flags: same flags as map update elem
 *
 * int bpf_xdp_adjust_meta(xdp_md, delta)
 *     Adjust the xdp_md.data_meta by delta
 *     @xdp_md: pointer to xdp_md
 *     @delta: An positive/negative integer to be added to xdp_md.data_meta
 *     Return: 0 on success or negative on error
 *
 * int bpf_perf_event_read_value(map, flags, buf, buf_size)
 *     read perf event counter value and perf event enabled/running time
 *     @map: pointer to perf_event_array map
 *     @flags: index of event in the map or bitmask flags
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return: 0 on success or negative error code
 *
 * int bpf_perf_prog_read_value(ctx, buf, buf_size)
 *     read perf prog attached perf event counter and enabled/running time
 *     @ctx: pointer to ctx
 *     @buf: buf to fill
 *     @buf_size: size of the buf
 *     Return : 0 on success or negative error code
 *
 * int bpf_msg_redirect_map(map, key, flags)
 *     Redirect msg to a sock in map using key as a lookup key for the
 *     sock in map.
 *     @map: pointer to sockmap
 *     @key: key to lookup sock in map
 *     @flags: reserved for future use
 *     Return: SK_PASS
 *
* int bpf_bind(ctx, addr, addr_len)
 *     Bind socket to address. Only binding to IP is supported, no port can be
 *     set in addr.
 *     @ctx: pointer to context of type bpf_sock_addr
 *     @addr: pointer to struct sockaddr to bind socket to
 *     @addr_len: length of sockaddr structure
 *     Return: 0 on success or negative error code
 *
 * int skb_load_bytes_relative(const struct sk_buff *skb, u32 offset, void *to, u32 len, u32 start_header)
 * 	Description
 * 		This helper is similar to **bpf_skb_load_bytes**\ () in that
 * 		it provides an easy way to load *len* bytes from *offset*
 * 		from the packet associated to *skb*, into the buffer pointed
 * 		by *to*. The difference to **bpf_skb_load_bytes**\ () is that
 * 		a fifth argument *start_header* exists in order to select a
 * 		base offset to start from. *start_header* can be one of:
 *
 * 		**BPF_HDR_START_MAC**
 * 			Base offset to load data from is *skb*'s mac header.
 * 		**BPF_HDR_START_NET**
 * 			Base offset to load data from is *skb*'s network header.
 *
 * 		In general, "direct packet access" is the preferred method to
 * 		access packet data, however, this helper is in particular useful
 * 		in socket filters where *skb*\ **->data** does not always point
 * 		to the start of the mac header and where "direct packet access"
 * 		is not available.
 *
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_sock_hash_update(struct bpf_sock_ops_kern *skops, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		Add an entry to, or update a sockhash *map* referencing sockets.
 *		The *skops* is used as a new value for the entry associated to
 *		*key*. *flags* is one of:
 *
 *		**BPF_NOEXIST**
 *			The entry for *key* must not exist in the map.
 *		**BPF_EXIST**
 *			The entry for *key* must already exist in the map.
 *		**BPF_ANY**
 *			No condition on the existence of the entry for *key*.
 *
 *		If the *map* has eBPF programs (parser and verdict), those will
 *		be inherited by the socket being added. If the socket is
 *		already attached to eBPF programs, this results in an error.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_msg_redirect_hash(struct sk_msg_buff *msg, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		This helper is used in programs implementing policies at the
 *		socket level. If the message *msg* is allowed to pass (i.e. if
 *		the verdict eBPF program returns **SK_PASS**), redirect it to
 *		the socket referenced by *map* (of type
 *		**BPF_MAP_TYPE_SOCKHASH**) using hash *key*. Both ingress and
 *		egress interfaces can be used for redirection. The
 *		**BPF_F_INGRESS** value in *flags* is used to make the
 *		distinction (ingress path is selected if the flag is present,
 *		egress path otherwise). This is the only flag supported for now.
 *	Return
 *		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * int bpf_sk_redirect_hash(struct sk_buff *skb, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		This helper is used in programs implementing policies at the
 *		skb socket level. If the sk_buff *skb* is allowed to pass (i.e.
 *		if the verdeict eBPF program returns **SK_PASS**), redirect it
 *		to the socket referenced by *map* (of type
 *		**BPF_MAP_TYPE_SOCKHASH**) using hash *key*. Both ingress and
 *		egress interfaces can be used for redirection. The
 *		**BPF_F_INGRESS** value in *flags* is used to make the
 *		distinction (ingress path is selected if the flag is present,
 *		egress otherwise). This is the only flag supported for now.
 *	Return
 *		**SK_PASS** on success, or **SK_DROP** on error.
 *
 * uint64_t bpf_skb_cgroup_id(struct sk_buff *skb)
 * 	Description
 * 		Return the cgroup v2 id of the socket associated with the *skb*.
 * 		This is roughly similar to the **bpf_get_cgroup_classid**\ ()
 * 		helper for cgroup v1 by providing a tag resp. identifier that
 * 		can be matched on or used for map lookups e.g. to implement
 * 		policy. The cgroup v2 id of a given path in the hierarchy is
 * 		exposed in user space through the f_handle API in order to get
 * 		to the same 64-bit id.
 *
 * 		This helper can be used on TC egress path, but not on ingress,
 * 		and is available only if the kernel was compiled with the
 * 		**CONFIG_SOCK_CGROUP_DATA** configuration option.
 * 	Return
 * 		The id is returned or 0 in case the id could not be retrieved.
 *
 * u64 bpf_get_current_cgroup_id(void)
 * 	Return
 * 		A 64-bit integer containing the current cgroup id based
 * 		on the cgroup within which the current task is running.
 * void* get_local_storage(void *map, u64 flags)
 *	Description
 *		Get the pointer to the local storage area.
 *		The type and the size of the local storage is defined
 *		by the *map* argument.
 *		The *flags* meaning is specific for each map type,
 *		and has to be 0 for cgroup local storage.
 *
 *		Depending on the BPF program type, a local storage area
 *		can be shared between multiple instances of the BPF program,
 *		running simultaneously.
 *
 *		A user should care about the synchronization by himself.
 *		For example, by using the **BPF_STX_XADD** instruction to alter
 *		the shared data.
 *	Return
 *		A pointer to the local storage area.
 *
 * int bpf_sk_select_reuseport(struct sk_reuseport_md *reuse, struct bpf_map *map, void *key, u64 flags)
 *	Description
 *		Select a **SO_REUSEPORT** socket from a
 *		**BPF_MAP_TYPE_REUSEPORT_SOCKARRAY** *map*.
 *		It checks the selected socket is matching the incoming
 *		request in the socket buffer.
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * struct bpf_sock *bpf_sk_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)
 *	Description
 *		Look for TCP socket matching *tuple*, optionally in a child
 *		network namespace *netns*. The return value must be checked,
 *		and if non-**NULL**, released via **bpf_sk_release**\ ().
 *
 *		The *ctx* should point to the context of the program, such as
 *		the skb or socket (depending on the hook in use). This is used
 *		to determine the base network namespace for the lookup.
 *
 *		*tuple_size* must be one of:
 *
 *		**sizeof**\ (*tuple*\ **->ipv4**)
 *			Look for an IPv4 socket.
 *		**sizeof**\ (*tuple*\ **->ipv6**)
 *			Look for an IPv6 socket.
 *
 *		If the *netns* is a negative signed 32-bit integer, then the
 *		socket lookup table in the netns associated with the *ctx* will
 *		will be used. For the TC hooks, this is the netns of the device
 *		in the skb. For socket hooks, this is the netns of the socket.
 *		If *netns* is any other signed 32-bit value greater than or
 *		equal to zero then it specifies the ID of the netns relative to
 *		the netns associated with the *ctx*. *netns* values beyond the
 *		range of 32-bit integers are reserved for future use.
 *
 *		All values for *flags* are reserved for future usage, and must
 *		be left at zero.
 *
 *		This helper is available only if the kernel was compiled with
 *		**CONFIG_NET** configuration option.
 *	Return
 *		A pointer to *struct bpf_sock*, or **NULL** in case of failure.
 *		For sockets with reuseport option, **struct bpf_sock**
 *		return is from **reuse->socks**\ [] using hash of the packet.
 *
 * struct bpf_sock *bpf_sk_lookup_udp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)
 *	Description
 *		Look for UDP socket matching *tuple*, optionally in a child
 *		network namespace *netns*. The return value must be checked,
 *		and if non-**NULL**, released via **bpf_sk_release**\ ().
 *
 *		The *ctx* should point to the context of the program, such as
 *		the skb or socket (depending on the hook in use). This is used
 *		to determine the base network namespace for the lookup.
 *
 *		*tuple_size* must be one of:
 *
 *		**sizeof**\ (*tuple*\ **->ipv4**)
 *			Look for an IPv4 socket.
 *		**sizeof**\ (*tuple*\ **->ipv6**)
 *			Look for an IPv6 socket.
 *
 *		If the *netns* is a negative signed 32-bit integer, then the
 *		socket lookup table in the netns associated with the *ctx* will
 *		will be used. For the TC hooks, this is the netns of the device
 *		in the skb. For socket hooks, this is the netns of the socket.
 *		If *netns* is any other signed 32-bit value greater than or
 *		equal to zero then it specifies the ID of the netns relative to
 *		the netns associated with the *ctx*. *netns* values beyond the
 *		range of 32-bit integers are reserved for future use.
 *
 *		All values for *flags* are reserved for future usage, and must
 *		be left at zero.
 *
 *		This helper is available only if the kernel was compiled with
 *		**CONFIG_NET** configuration option.
 *	Return
 *		A pointer to **struct bpf_sock**, or **NULL** in case of
 *		failure. For sockets with reuseport option, **struct bpf_sock**
 *		return is from **reuse->socks**\ [] using hash of the packet.
 *
 * int bpf_sk_release(struct bpf_sock *sock)
 *	Description
 *		Release the reference held by *sock*. *sock* must be a
 *		non-**NULL** pointer that was returned from
 *		**bpf_sk_lookup_xxx**\ ().
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_pop_elem(struct bpf_map *map, void *value)
 * 	Description
 * 		Pop an element from *map*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_map_peek_elem(struct bpf_map *map, void *value)
 * 	Description
 * 		Get an element from *map* without removing it.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * struct bpf_sock *bpf_sk_fullsock(struct bpf_sock *sk)
 *	Description
 *		This helper gets a **struct bpf_sock** pointer such
 *		that all the fields in bpf_sock can be accessed.
 *	Return
 *		A **struct bpf_sock** pointer on success, or NULL in
 *		case of failure.
 *
 * struct bpf_tcp_sock *bpf_tcp_sock(struct bpf_sock *sk)
 *	Description
 *		This helper gets a **struct bpf_tcp_sock** pointer from a
 *		**struct bpf_sock** pointer.
 *
 *	Return
 *		A **struct bpf_tcp_sock** pointer on success, or NULL in
 *		case of failure.
 *
 * struct bpf_sock *bpf_get_listener_sock(struct bpf_sock *sk)
 *	Description
 *		Return a **struct bpf_sock** pointer in TCP_LISTEN state.
 *		bpf_sk_release() is unnecessary and not allowed.
 *	Return
 *		A **struct bpf_sock** pointer on success, or NULL in
 *		case of failure.
 *
 * struct bpf_sock *bpf_skc_lookup_tcp(void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags)
 *	Description
 *		Look for TCP socket matching *tuple*, optionally in a child
 *		network namespace *netns*. The return value must be checked,
 *		and if non-**NULL**, released via **bpf_sk_release**\ ().
 *
 *		This function is identical to bpf_sk_lookup_tcp, except that it
 *		also returns timewait or request sockets. Use bpf_sk_fullsock
 *		or bpf_tcp_socket to access the full structure.
 *
 *		This helper is available only if the kernel was compiled with
 *		**CONFIG_NET** configuration option.
 *	Return
 *		Pointer to **struct bpf_sock**, or **NULL** in case of failure.
 *		For sockets with reuseport option, the **struct bpf_sock**
 *		result is from **reuse->socks**\ [] using the hash of the tuple.
 *
 * int bpf_sysctl_get_name(struct bpf_sysctl *ctx, char *buf, size_t buf_len, u64 flags)
 *	Description
 *		Get name of sysctl in /proc/sys/ and copy it into provided by
 *		program buffer *buf* of size *buf_len*.
 *
 *		The buffer is always NUL terminated, unless it's zero-sized.
 *
 *		If *flags* is zero, full name (e.g. "net/ipv4/tcp_mem") is
 *		copied. Use **BPF_F_SYSCTL_BASE_NAME** flag to copy base name
 *		only (e.g. "tcp_mem").
 *	Return
 *		Number of character copied (not including the trailing NUL).
 *
 *		**-E2BIG** if the buffer wasn't big enough (*buf* will contain
 *		truncated name in this case).
 *
 * int bpf_sysctl_get_current_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)
 *	Description
 *		Get current value of sysctl as it is presented in /proc/sys
 *		(incl. newline, etc), and copy it as a string into provided
 *		by program buffer *buf* of size *buf_len*.
 *
 *		The whole value is copied, no matter what file position user
 *		space issued e.g. sys_read at.
 *
 *		The buffer is always NUL terminated, unless it's zero-sized.
 *	Return
 *		Number of character copied (not including the trailing NUL).
 *
 *		**-E2BIG** if the buffer wasn't big enough (*buf* will contain
 *		truncated name in this case).
 *
 *		**-EINVAL** if current value was unavailable, e.g. because
 *		sysctl is uninitialized and read returns -EIO for it.
 *
 * int bpf_sysctl_get_new_value(struct bpf_sysctl *ctx, char *buf, size_t buf_len)
 *	Description
 *		Get new value being written by user space to sysctl (before
 *		the actual write happens) and copy it as a string into
 *		provided by program buffer *buf* of size *buf_len*.
 *
 *		User space may write new value at file position > 0.
 *
 *		The buffer is always NUL terminated, unless it's zero-sized.
 *	Return
 *		Number of character copied (not including the trailing NUL).
 *
 *		**-E2BIG** if the buffer wasn't big enough (*buf* will contain
 *		truncated name in this case).
 *
 *		**-EINVAL** if sysctl is being read.
 *
 * int bpf_sysctl_set_new_value(struct bpf_sysctl *ctx, const char *buf, size_t buf_len)
 *	Description
 *		Override new value being written by user space to sysctl with
 *		value provided by program in buffer *buf* of size *buf_len*.
 *
 *		*buf* should contain a string in same form as provided by user
 *		space on sysctl write.
 *
 *		User space may write new value at file position > 0. To override
 *		the whole sysctl value file position should be set to zero.
 *	Return
 *		0 on success.
 *
 *		**-E2BIG** if the *buf_len* is too big.
 *
 *		**-EINVAL** if sysctl is being read.
 *
 * int bpf_strtol(const char *buf, size_t buf_len, u64 flags, long *res)
 *	Description
 *		Convert the initial part of the string from buffer *buf* of
 *		size *buf_len* to a long integer according to the given base
 *		and save the result in *res*.
 *
 *		The string may begin with an arbitrary amount of white space
 *		(as determined by isspace(3)) followed by a single optional '-'
 *		sign.
 *
 *		Five least significant bits of *flags* encode base, other bits
 *		are currently unused.
 *
 *		Base must be either 8, 10, 16 or 0 to detect it automatically
 *		similar to user space strtol(3).
 *	Return
 *		Number of characters consumed on success. Must be positive but
 *		no more than buf_len.
 *
 *		**-EINVAL** if no valid digits were found or unsupported base
 *		was provided.
 *
 *		**-ERANGE** if resulting value was out of range.
 *
 * int bpf_strtoul(const char *buf, size_t buf_len, u64 flags, unsigned long *res)
 *	Description
 *		Convert the initial part of the string from buffer *buf* of
 *		size *buf_len* to an unsigned long integer according to the
 *		given base and save the result in *res*.
 *
 *		The string may begin with an arbitrary amount of white space
 *		(as determined by isspace(3)).
 *
 *		Five least significant bits of *flags* encode base, other bits
 *		are currently unused.
 *
 *		Base must be either 8, 10, 16 or 0 to detect it automatically
 *		similar to user space strtoul(3).
 *	Return
 *		Number of characters consumed on success. Must be positive but
 *		no more than buf_len.
 *
 *		**-EINVAL** if no valid digits were found or unsupported base
 *		was provided.
 *
 *		**-ERANGE** if resulting value was out of range.
 *
 * void *bpf_sk_storage_get(struct bpf_map *map, struct bpf_sock *sk, void *value, u64 flags)
 *	Description
 *		Get a bpf-local-storage from a sk.
 *
 *		Logically, it could be thought of getting the value from
 *		a *map* with *sk* as the **key**.  From this
 *		perspective,  the usage is not much different from
 *		**bpf_map_lookup_elem(map, &sk)** except this
 *		helper enforces the key must be a **bpf_fullsock()**
 *		and the map must be a BPF_MAP_TYPE_SK_STORAGE also.
 *
 *		Underneath, the value is stored locally at *sk* instead of
 *		the map.  The *map* is used as the bpf-local-storage **type**.
 *		The bpf-local-storage **type** (i.e. the *map*) is searched
 *		against all bpf-local-storages residing at sk.
 *
 *		An optional *flags* (BPF_SK_STORAGE_GET_F_CREATE) can be
 *		used such that a new bpf-local-storage will be
 *		created if one does not exist.  *value* can be used
 *		together with BPF_SK_STORAGE_GET_F_CREATE to specify
 *		the initial value of a bpf-local-storage.  If *value* is
 *		NULL, the new bpf-local-storage will be zero initialized.
 *	Return
 *		A bpf-local-storage pointer is returned on success.
 *
 *		**NULL** if not found or there was an error in adding
 *		a new bpf-local-storage.
 *
 * int bpf_sk_storage_delete(struct bpf_map *map, struct bpf_sock *sk)
 *	Description
 *		Delete a bpf-local-storage from a sk.
 *	Return
 *		0 on success.
 *
 *		**-ENOENT** if the bpf-local-storage cannot be found.
 *
 * int bpf_msg_push_data(struct sk_buff *skb, u32 start, u32 len, u64 flags)
 *	Description
 *		For socket policies, insert *len* bytes into msg at offset
 *		*start*.
 *
 *		If a program of type **BPF_PROG_TYPE_SK_MSG** is run on a
 *		*msg* it may want to insert metadata or options into the msg.
 *		This can later be read and used by any of the lower layer BPF
 *		hooks.
 *
 *		This helper may fail if under memory pressure (a malloc
 *		fails) in these cases BPF programs will get an appropriate
 *		error and BPF programs will need to handle them.
 *
 *	Return
 *		0 on success, or a negative error in case of failure.
 *
 * u64 bpf_get_netns_cookie(void *ctx)
 * 	Description
 * 		Retrieve the cookie (generated by the kernel) of the network
 * 		namespace the input *ctx* is associated with. The network
 * 		namespace cookie remains stable for its lifetime and provides
 * 		a global identifier that can be assumed unique. If *ctx* is
 * 		NULL, then the helper returns the cookie for the initial
 * 		network namespace. The cookie itself is very similar to that
 * 		of bpf_get_socket_cookie() helper, but for network namespaces
 * 		instead of sockets.
 * 	Return
 * 		A 8-byte long opaque number.
 *
 * u64 bpf_get_current_ancestor_cgroup_id(int ancestor_level)
 * 	Description
 * 		Return id of cgroup v2 that is ancestor of the cgroup associated
 * 		with the current task at the *ancestor_level*. The root cgroup
 * 		is at *ancestor_level* zero and each step down the hierarchy
 * 		increments the level. If *ancestor_level* == level of cgroup
 * 		associated with the current task, then return value will be the
 * 		same as that of **bpf_get_current_cgroup_id**\ ().
 *
 * 		The helper is useful to implement policies based on cgroups
 * 		that are upper in hierarchy than immediate cgroup associated
 * 		with the current task.
 *
 * 		The format of returned id and helper limitations are same as in
 * 		**bpf_get_current_cgroup_id**\ ().
 * 	Return
 * 		The id is returned or 0 in case the id could not be retrieved.
 *
 * int bpf_ringbuf_output(void *ringbuf, void *data, u64 size, u64 flags)
 * 	Description
 * 		Copy *size* bytes from *data* into a ring buffer *ringbuf*.
 * 		If BPF_RB_NO_WAKEUP is specified in *flags*, no notification of
 * 		new data availability is sent.
 * 		IF BPF_RB_FORCE_WAKEUP is specified in *flags*, notification of
 * 		new data availability is sent unconditionally.
 * 	Return
 * 		0, on success;
 * 		< 0, on error.
 *
 * void *bpf_ringbuf_reserve(void *ringbuf, u64 size, u64 flags)
 * 	Description
 * 		Reserve *size* bytes of payload in a ring buffer *ringbuf*.
 * 	Return
 * 		Valid pointer with *size* bytes of memory available; NULL,
 * 		otherwise.
 *
 * void bpf_ringbuf_submit(void *data, u64 flags)
 * 	Description
 * 		Submit reserved ring buffer sample, pointed to by *data*.
 * 		If BPF_RB_NO_WAKEUP is specified in *flags*, no notification of
 * 		new data availability is sent.
 * 		IF BPF_RB_FORCE_WAKEUP is specified in *flags*, notification of
 * 		new data availability is sent unconditionally.
 * 	Return
 * 		Nothing. Always succeeds.
 *
 * void bpf_ringbuf_discard(void *data, u64 flags)
 * 	Description
 * 		Discard reserved ring buffer sample, pointed to by *data*.
 * 		If BPF_RB_NO_WAKEUP is specified in *flags*, no notification of
 * 		new data availability is sent.
 * 		IF BPF_RB_FORCE_WAKEUP is specified in *flags*, notification of
 * 		new data availability is sent unconditionally.
 * 	Return
 * 		Nothing. Always succeeds.
 *
 * u64 bpf_ringbuf_query(void *ringbuf, u64 flags)
 *	Description
 *		Query various characteristics of provided ring buffer. What
 *		exactly is queries is determined by *flags*:
 *		  - BPF_RB_AVAIL_DATA - amount of data not yet consumed;
 *		  - BPF_RB_RING_SIZE - the size of ring buffer;
 *		  - BPF_RB_CONS_POS - consumer position (can wrap around);
 *		  - BPF_RB_PROD_POS - producer(s) position (can wrap around);
 *		Data returned is just a momentary snapshots of actual values
 *		and could be inaccurate, so this facility should be used to
 *		power heuristics and for reporting, not to make 100% correct
 *		calculation.
 *	Return
 *		Requested value, or 0, if flags are not recognized.
 *
 * int bpf_probe_read_user(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		Safely attempt to read *size* bytes from user space address
 * 		*unsafe_ptr* and store the data in *dst*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_probe_read_kernel(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		Safely attempt to read *size* bytes from kernel space address
 * 		*unsafe_ptr* and store the data in *dst*.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 *
 * int bpf_probe_read_user_str(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		Copy a NUL terminated string from an unsafe user address
 * 		*unsafe_ptr* to *dst*. The *size* should include the
 * 		terminating NUL byte. In case the string length is smaller than
 * 		*size*, the target is not padded with further NUL bytes. If the
 * 		string length is larger than *size*, just *size*-1 bytes are
 * 		copied and the last byte is set to NUL.
 *
 * 		On success, the length of the copied string is returned. This
 * 		makes this helper useful in tracing programs for reading
 * 		strings, and more importantly to get its length at runtime. See
 * 		the following snippet:
 *
 * 		::
 *
 * 			SEC("kprobe/sys_open")
 * 			void bpf_sys_open(struct pt_regs *ctx)
 * 			{
 * 			        char buf[PATHLEN]; // PATHLEN is defined to 256
 * 			        int res = bpf_probe_read_user_str(buf, sizeof(buf),
 * 				                                  ctx->di);
 *
 * 				// Consume buf, for example push it to
 * 				// userspace via bpf_perf_event_output(); we
 * 				// can use res (the string length) as event
 * 				// size, after checking its boundaries.
 * 			}
 *
 * 		In comparison, using **bpf_probe_read_user()** helper here
 * 		instead to read the string would require to estimate the length
 * 		at compile time, and would often result in copying more memory
 * 		than necessary.
 *
 * 		Another useful use case is when parsing individual process
 * 		arguments or individual environment variables navigating
 * 		*current*\ **->mm->arg_start** and *current*\
 * 		**->mm->env_start**: using this helper and the return value,
 * 		one can quickly iterate at the right offset of the memory area.
 * 	Return
 * 		On success, the strictly positive length of the string,
 * 		including the trailing NUL character. On error, a negative
 * 		value.
 *
 * int bpf_probe_read_kernel_str(void *dst, u32 size, const void *unsafe_ptr)
 * 	Description
 * 		Copy a NUL terminated string from an unsafe kernel address *unsafe_ptr*
 * 		to *dst*. Same semantics as with bpf_probe_read_user_str() apply.
 * 	Return
 * 		On success, the strictly positive length of the string,	including
 * 		the trailing NUL character. On error, a negative value.
 *
 * int bpf_skb_output(void *ctx, struct bpf_map *map, u64 flags, void *data, u64 size)
 * 	Description
 * 		Write raw *data* blob into a special BPF perf event held by
 * 		*map* of type **BPF_MAP_TYPE_PERF_EVENT_ARRAY**. This perf
 * 		event must have the following attributes: **PERF_SAMPLE_RAW**
 * 		as **sample_type**, **PERF_TYPE_SOFTWARE** as **type**, and
 * 		**PERF_COUNT_SW_BPF_OUTPUT** as **config**.
 *
 * 		The *flags* are used to indicate the index in *map* for which
 * 		the value must be put, masked with **BPF_F_INDEX_MASK**.
 * 		Alternatively, *flags* can be set to **BPF_F_CURRENT_CPU**
 * 		to indicate that the index of the current CPU core should be
 * 		used.
 *
 * 		The value to write, of *size*, is passed through eBPF stack and
 * 		pointed by *data*.
 *
 * 		*ctx* is a pointer to in-kernel struct sk_buff.
 *
 * 		This helper is similar to **bpf_perf_event_output**\ () but
 * 		restricted to raw_tracepoint bpf programs.
 * 	Return
 * 		0 on success, or a negative error in case of failure.
 */
#define __BPF_FUNC_MAPPER(FN)		\
	FN(unspec),			\
	FN(map_lookup_elem),		\
	FN(map_update_elem),		\
	FN(map_delete_elem),		\
	FN(probe_read),			\
	FN(ktime_get_ns),		\
	FN(trace_printk),		\
	FN(get_prandom_u32),		\
	FN(get_smp_processor_id),	\
	FN(skb_store_bytes),		\
	FN(l3_csum_replace),		\
	FN(l4_csum_replace),		\
	FN(tail_call),			\
	FN(clone_redirect),		\
	FN(get_current_pid_tgid),	\
	FN(get_current_uid_gid),	\
	FN(get_current_comm),		\
	FN(get_cgroup_classid),		\
	FN(skb_vlan_push),		\
	FN(skb_vlan_pop),		\
	FN(skb_get_tunnel_key),		\
	FN(skb_set_tunnel_key),		\
	FN(perf_event_read),		\
	FN(redirect),			\
	FN(get_route_realm),		\
	FN(perf_event_output),		\
	FN(skb_load_bytes),		\
	FN(get_stackid),		\
	FN(csum_diff),			\
	FN(skb_get_tunnel_opt),		\
	FN(skb_set_tunnel_opt),		\
	FN(skb_change_proto),		\
	FN(skb_change_type),		\
	FN(skb_under_cgroup),		\
	FN(get_hash_recalc),		\
	FN(get_current_task),		\
	FN(probe_write_user),		\
	FN(current_task_under_cgroup),	\
	FN(skb_change_tail),		\
	FN(skb_pull_data),		\
	FN(csum_update),		\
	FN(set_hash_invalid),		\
	FN(get_numa_node_id),		\
	FN(skb_change_head),		\
	FN(xdp_adjust_head),		\
	FN(probe_read_str),		\
	FN(get_socket_cookie),		\
	FN(get_socket_uid),		\
	FN(set_hash),			\
	FN(setsockopt),			\
	FN(skb_adjust_room),		\
	FN(redirect_map),		\
	FN(sk_redirect_map),		\
	FN(sock_map_update),		\
	FN(xdp_adjust_meta),		\
	FN(perf_event_read_value),	\
	FN(perf_prog_read_value),	\
	FN(getsockopt),			\
	FN(override_return),		\
	FN(sock_ops_cb_flags_set),	\
	FN(msg_redirect_map),		\
	FN(msg_apply_bytes),		\
	FN(msg_cork_bytes),		\
	FN(msg_pull_data),		\
	FN(bind),			\
	FN(xdp_adjust_tail),		\
	FN(skb_get_xfrm_state),		\
	FN(get_stack),			\
	FN(skb_load_bytes_relative),	\
	FN(fib_lookup),			\
	FN(sock_hash_update),		\
	FN(msg_redirect_hash),		\
	FN(sk_redirect_hash),		\
	FN(lwt_push_encap),		\
	FN(lwt_seg6_store_bytes),	\
	FN(lwt_seg6_adjust_srh),	\
	FN(lwt_seg6_action),		\
	FN(rc_repeat),			\
	FN(rc_keydown),			\
	FN(skb_cgroup_id),		\
	FN(get_current_cgroup_id),	\
	FN(get_local_storage),		\
	FN(sk_select_reuseport),	\
	FN(skb_ancestor_cgroup_id),	\
	FN(sk_lookup_tcp),		\
	FN(sk_lookup_udp),		\
	FN(sk_release),			\
	FN(map_push_elem),		\
	FN(map_pop_elem),		\
	FN(map_peek_elem),		\
	FN(msg_push_data),		\
	FN(msg_pop_data),		\
	FN(rc_pointer_rel),		\
	FN(spin_lock),			\
	FN(spin_unlock),		\
	FN(sk_fullsock),		\
	FN(tcp_sock),			\
	FN(skb_ecn_set_ce),		\
	FN(get_listener_sock),		\
	FN(skc_lookup_tcp),		\
	FN(tcp_check_syncookie),	\
	FN(sysctl_get_name),		\
	FN(sysctl_get_current_value),	\
	FN(sysctl_get_new_value),	\
	FN(sysctl_set_new_value),	\
	FN(strtol),			\
	FN(strtoul),			\
	FN(sk_storage_get),		\
	FN(sk_storage_delete),		\
	FN(send_signal),		\
	FN(tcp_gen_syncookie),		\
	FN(skb_output),			\
	FN(probe_read_user),		\
	FN(probe_read_kernel),		\
	FN(probe_read_user_str),	\
	FN(probe_read_kernel_str),	\
	FN(tcp_send_ack),		\
	FN(send_signal_thread),		\
	FN(jiffies64),			\
	FN(read_branch_records),	\
	FN(get_ns_current_pid_tgid),	\
	FN(xdp_output),			\
	FN(get_netns_cookie),		\
	FN(get_current_ancestor_cgroup_id),	\
	FN(sk_assign),			\
	FN(ktime_get_boot_ns),		\
	FN(ringbuf_output),		\
	FN(ringbuf_reserve),		\
	FN(ringbuf_submit),		\
	FN(ringbuf_discard),		\
	FN(ringbuf_query),

/* integer value in 'imm' field of BPF_CALL instruction selects which helper
 * function eBPF program intends to call
 */
#define __BPF_ENUM_FN(x) BPF_FUNC_ ## x
enum bpf_func_id {
	__BPF_FUNC_MAPPER(__BPF_ENUM_FN)
	__BPF_FUNC_MAX_ID,
};
#undef __BPF_ENUM_FN

/* All flags used by eBPF helper functions, placed here. */

/* BPF_FUNC_skb_store_bytes flags. */
#define BPF_F_RECOMPUTE_CSUM		(1ULL << 0)
#define BPF_F_INVALIDATE_HASH		(1ULL << 1)

/* BPF_FUNC_l3_csum_replace and BPF_FUNC_l4_csum_replace flags.
 * First 4 bits are for passing the header field size.
 */
#define BPF_F_HDR_FIELD_MASK		0xfULL

/* BPF_FUNC_l4_csum_replace flags. */
#define BPF_F_PSEUDO_HDR		(1ULL << 4)
#define BPF_F_MARK_MANGLED_0		(1ULL << 5)

/* BPF_FUNC_clone_redirect and BPF_FUNC_redirect flags. */
#define BPF_F_INGRESS			(1ULL << 0)

/* BPF_FUNC_skb_set_tunnel_key and BPF_FUNC_skb_get_tunnel_key flags. */
#define BPF_F_TUNINFO_IPV6		(1ULL << 0)

/* BPF_FUNC_skb_set_tunnel_key flags. */
#define BPF_F_ZERO_CSUM_TX              (1ULL << 1)
#define BPF_F_DONT_FRAGMENT             (1ULL << 2)

/* BPF_FUNC_get_stackid flags. */
#define BPF_F_SKIP_FIELD_MASK		0xffULL
#define BPF_F_USER_STACK		(1ULL << 8)
#define BPF_F_FAST_STACK_CMP		(1ULL << 9)
#define BPF_F_REUSE_STACKID		(1ULL << 10)

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
#define BPF_F_INDEX_MASK		0xffffffffULL
#define BPF_F_CURRENT_CPU		BPF_F_INDEX_MASK
/* BPF_FUNC_perf_event_output for sk_buff input context. */
#define BPF_F_CTXLEN_MASK		(0xfffffULL << 32)

/* Current network namespace */
#define BPF_F_CURRENT_NETNS		(-1L)

/* BPF_FUNC_sysctl_get_name flags. */
#define BPF_F_SYSCTL_BASE_NAME		(1ULL << 0)

/* BPF_FUNC_sk_storage_get flags */
#define BPF_SK_STORAGE_GET_F_CREATE	(1ULL << 0)

/* BPF_FUNC_bpf_ringbuf_commit, BPF_FUNC_bpf_ringbuf_discard, and
 * BPF_FUNC_bpf_ringbuf_output flags.
 */
enum {
	BPF_RB_NO_WAKEUP		= (1ULL << 0),
	BPF_RB_FORCE_WAKEUP		= (1ULL << 1),
};

/* BPF_FUNC_bpf_ringbuf_query flags */
enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

/* BPF ring buffer constants */
enum {
	BPF_RINGBUF_BUSY_BIT		= (1U << 31),
	BPF_RINGBUF_DISCARD_BIT		= (1U << 30),
	BPF_RINGBUF_HDR_SZ		= 8,
};

/* Mode for BPF_FUNC_skb_adjust_room helper. */
enum bpf_adj_room_mode {
	BPF_ADJ_ROOM_NET,
};

/* Mode for BPF_FUNC_skb_load_bytes_relative helper. */
enum bpf_hdr_start_off {
	BPF_HDR_START_MAC,
	BPF_HDR_START_NET,
};

#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))

/* user accessible mirror of in-kernel sk_buff.
 * new fields can only be added to the end of this structure
 */
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	/* ... here. */

	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
};

struct bpf_tunnel_key {
	__u32 tunnel_id;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
	__u8 tunnel_tos;
	__u8 tunnel_ttl;
	__u16 tunnel_ext;	/* Padding, future use. */
	__u32 tunnel_label;
};

/* Generic BPF return codes which all BPF program types may support.
 * The values are binary compatible with their TC_ACT_* counter-part to
 * provide backwards compatibility with existing SCHED_CLS and SCHED_ACT
 * programs.
 *
 * XDP is handled seprately, see XDP_*.
 */
enum bpf_ret_code {
	BPF_OK = 0,
	/* 1 reserved */
	BPF_DROP = 2,
	/* 3-6 reserved */
	BPF_REDIRECT = 7,
	/* >127 are reserved for prog type specific return codes */
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	/* IP address also allows 1 and 2 bytes access */
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;		/* host byte order */
	__u32 dst_port;		/* network byte order */
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
};

struct bpf_tcp_sock {
	__u32 snd_cwnd;		/* Sending congestion window		*/
	__u32 srtt_us;		/* smoothed round trip time << 3 in usecs */
	__u32 rtt_min;
	__u32 snd_ssthresh;	/* Slow start size threshold		*/
	__u32 rcv_nxt;		/* What we want to receive next		*/
	__u32 snd_nxt;		/* Next sequence we send		*/
	__u32 snd_una;		/* First byte we want an ack for	*/
	__u32 mss_cache;	/* Cached effective mss, not including SACKS */
	__u32 ecn_flags;	/* ECN status bits.			*/
	__u32 rate_delivered;	/* saved rate sample: packets delivered */
	__u32 rate_interval_us;	/* saved rate sample: time elapsed */
	__u32 packets_out;	/* Packets which are "in flight"	*/
	__u32 retrans_out;	/* Retransmitted packets out		*/
	__u32 total_retrans;	/* Total retransmits for entire connection */
	__u32 segs_in;		/* RFC4898 tcpEStatsPerfSegsIn
				 * total number of segments in.
				 */
	__u32 data_segs_in;	/* RFC4898 tcpEStatsPerfDataSegsIn
				 * total number of data segments in.
				 */
	__u32 segs_out;		/* RFC4898 tcpEStatsPerfSegsOut
				 * The total number of segments sent.
				 */
	__u32 data_segs_out;	/* RFC4898 tcpEStatsPerfDataSegsOut
				 * total number of data segments sent.
				 */
	__u32 lost_out;		/* Lost packets			*/
	__u32 sacked_out;	/* SACK'd packets			*/
	__u64 bytes_received;	/* RFC4898 tcpEStatsAppHCThruOctetsReceived
				 * sum(delta(rcv_nxt)), or how many bytes
				 * were acked.
				 */
	__u64 bytes_acked;	/* RFC4898 tcpEStatsAppHCThruOctetsAcked
				 * sum(delta(snd_una)), or how many bytes
				 * were acked.
				 */
};

struct bpf_sock_tuple {
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
			__be16 sport;
			__be16 dport;
		} ipv4;
		struct {
			__be32 saddr[4];
			__be32 daddr[4];
			__be16 sport;
			__be16 dport;
		} ipv6;
	};
};

#define XDP_PACKET_HEADROOM 256

/* User return codes for XDP prog type.
 * A valid XDP program must return one of these defined values. All other
 * return codes are reserved for future use. Unknown return codes will result
 * in packet drop.
 */
enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};

/* user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
 */
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	__u32 ingress_ifindex; /* rxq->dev->ifindex */
	__u32 rx_queue_index;  /* rxq->queue_index  */
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS,
};

/* user accessible metadata for SK_MSG packet hook, new fields must
 * be added to the end of this structure
 */
struct sk_msg_md {
	__bpf_md_ptr(void *, data);
	__bpf_md_ptr(void *, data_end);

	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */

	__bpf_md_ptr(struct bpf_sock *, sk); /* current socket */
};

struct sk_reuseport_md {
	/*
	 * Start of directly accessible data. It begins from
	 * the tcp/udp header.
	 */
	void *data;
	void *data_end;		/* End of directly accessible data */
	/*
	 * Total length of packet (starting from the tcp/udp header).
	 * Note that the directly accessible bytes (data_end - data)
	 * could be less than this "len".  Those bytes could be
	 * indirectly read by a helper "bpf_skb_load_bytes()".
	 */
	__u32 len;
	/*
	 * Eth protocol in the mac header (network byte order). e.g.
	 * ETH_P_IP(0x0800) and ETH_P_IPV6(0x86DD)
	 */
	__u32 eth_protocol;
	__u32 ip_protocol;	/* IP protocol. e.g. IPPROTO_TCP, IPPROTO_UDP */
	__u32 bind_inany;	/* Is sock bound to an INANY address? */
	__u32 hash;		/* A hash of the packet 4 tuples */
};

#define BPF_TAG_SIZE	8

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8  tag[BPF_TAG_SIZE];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__aligned_u64 jited_prog_insns;
	__aligned_u64 xlated_prog_insns;
	__u64 load_time;	/* ns since boottime */
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__aligned_u64 map_ids;
	char name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 :32;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__aligned_u64 jited_ksyms;
	__aligned_u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__aligned_u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__aligned_u64 line_info;
	__aligned_u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__aligned_u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
} __attribute__((aligned(8)));

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char  name[BPF_OBJ_NAME_LEN];
	__u32 ifindex;
	__u32 :32;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
} __attribute__((aligned(8)));

struct bpf_btf_info {
	__aligned_u64 btf;
	__u32 btf_size;
	__u32 id;
} __attribute__((aligned(8)));

/* User bpf_sock_addr struct to access socket fields and sockaddr struct passed
 * by user and intended to be used by socket (e.g. to bind to, depends on
 * attach attach type).
 */
struct bpf_sock_addr {
	__u32 user_family;	/* Allows 4-byte read, but no write. */
	__u32 user_ip4;		/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_ip6[4];	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_port;	/* Allows 4-byte read and write.
				 * Stored in network byte order
				 */
	__u32 family;		/* Allows 4-byte read, but no write */
	__u32 type;		/* Allows 4-byte read, but no write */
	__u32 protocol;		/* Allows 4-byte read, but no write */
	__u32 msg_src_ip4;	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 msg_src_ip6[4];	/* Allows 1,2,4-byte read an 4-byte write.
				 * Stored in network byte order.
				 */
};

/* User bpf_sock_ops struct to access socket values and specify request ops
 * and their replies.
 * Some of this fields are in network (bigendian) byte order and may need
 * to be converted before use (bpf_ntohl() defined in samples/bpf/bpf_endian.h).
 * New fields can only be added at the end of this structure
 */
struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];		/* Optionally passed to bpf program */
		__u32 reply;		/* Returned by bpf program	    */
		__u32 replylong[4];	/* Optionally returned by bpf prog  */
	};
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	__u32 is_fullsock;	/* Some TCP fields are only valid if
				 * there is a full socket. If not, the
				 * fields read as zero.
				 */
	__u32 snd_cwnd;
	__u32 srtt_us;		/* Averaged RTT << 3 in usecs */
	__u32 bpf_sock_ops_cb_flags; /* flags defined in uapi/linux/tcp.h */
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
};

/* Definitions for bpf_sock_ops_cb_flags */
#define BPF_SOCK_OPS_RTO_CB_FLAG	(1<<0)
#define BPF_SOCK_OPS_RETRANS_CB_FLAG	(1<<1)
#define BPF_SOCK_OPS_STATE_CB_FLAG	(1<<2)
#define BPF_SOCK_OPS_ALL_CB_FLAGS       0x7		/* Mask of all currently
							 * supported cb flags
							 */

/* List of known BPF sock_ops operators.
 * New entries can only be added at the end
 */
enum {
	BPF_SOCK_OPS_VOID,
	BPF_SOCK_OPS_TIMEOUT_INIT,	/* Should return SYN-RTO value to use or
					 * -1 if default value should be used
					 */
	BPF_SOCK_OPS_RWND_INIT,		/* Should return initial advertized
					 * window (in packets) or -1 if default
					 * value should be used
					 */
	BPF_SOCK_OPS_TCP_CONNECT_CB,	/* Calls BPF program right before an
					 * active connection is initialized
					 */
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,	/* Calls BPF program when an
						 * active connection is
						 * established
						 */
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,	/* Calls BPF program when a
						 * passive connection is
						 * established
						 */
	BPF_SOCK_OPS_NEEDS_ECN,		/* If connection's congestion control
					 * needs ECN
					 */
	BPF_SOCK_OPS_BASE_RTT,		/* Get base RTT. The correct value is
					 * based on the path and may be
					 * dependent on the congestion control
					 * algorithm. In general it indicates
					 * a congestion threshold. RTTs above
					 * this indicate congestion
					 */
	BPF_SOCK_OPS_RTO_CB,		/* Called when an RTO has triggered.
					 * Arg1: value of icsk_retransmits
					 * Arg2: value of icsk_rto
					 * Arg3: whether RTO has expired
					 */
	BPF_SOCK_OPS_RETRANS_CB,	/* Called when skb is retransmitted.
					 * Arg1: sequence number of 1st byte
					 * Arg2: # segments
					 * Arg3: return value of
					 *       tcp_transmit_skb (0 => success)
					 */
	BPF_SOCK_OPS_STATE_CB,		/* Called when TCP changes state.
					 * Arg1: old_state
					 * Arg2: new_state
					 */
};

/* List of TCP states. There is a build check in net/ipv4/tcp.c to detect
 * changes between the TCP and BPF versions. Ideally this should never happen.
 * If it does, we need to add code to convert them before calling
 * the BPF sock_ops function.
 */
enum {
	BPF_TCP_ESTABLISHED = 1,
	BPF_TCP_SYN_SENT,
	BPF_TCP_SYN_RECV,
	BPF_TCP_FIN_WAIT1,
	BPF_TCP_FIN_WAIT2,
	BPF_TCP_TIME_WAIT,
	BPF_TCP_CLOSE,
	BPF_TCP_CLOSE_WAIT,
	BPF_TCP_LAST_ACK,
	BPF_TCP_LISTEN,
	BPF_TCP_CLOSING,	/* Now a valid state */
	BPF_TCP_NEW_SYN_RECV,

	BPF_TCP_MAX_STATES	/* Leave at the end! */
};

#define TCP_BPF_IW		1001	/* Set TCP initial congestion window */
#define TCP_BPF_SNDCWND_CLAMP	1002	/* Set sndcwnd_clamp */

struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

#define BPF_DEVCG_ACC_MKNOD	(1ULL << 0)
#define BPF_DEVCG_ACC_READ	(1ULL << 1)
#define BPF_DEVCG_ACC_WRITE	(1ULL << 2)

#define BPF_DEVCG_DEV_BLOCK	(1ULL << 0)
#define BPF_DEVCG_DEV_CHAR	(1ULL << 1)

struct bpf_cgroup_dev_ctx {
	/* access_type encoded as (BPF_DEVCG_ACC_* << 16) | BPF_DEVCG_DEV_* */
	__u32 access_type;
	__u32 major;
	__u32 minor;
};

struct bpf_func_info {
	__u32	insn_off;
	__u32	type_id;
};

#define BPF_LINE_INFO_LINE_NUM(line_col)	((line_col) >> 10)
#define BPF_LINE_INFO_LINE_COL(line_col)	((line_col) & 0x3ff)

struct bpf_line_info {
	__u32	insn_off;
	__u32	file_name_off;
	__u32	line_off;
	__u32	line_col;
};

struct bpf_spin_lock {
	__u32	val;
};

struct bpf_sysctl {
	__u32	write;		/* Sysctl is being read (= 0) or written (= 1).
				 * Allows 1,2,4-byte read, but no write.
				 */
	__u32	file_pos;	/* Sysctl file position to read from, write to.
				 * Allows 1,2,4-byte read an 4-byte write.
				 */
};

struct bpf_sockopt {
	__bpf_md_ptr(struct bpf_sock *, sk);
	__bpf_md_ptr(void *, optval);
	__bpf_md_ptr(void *, optval_end);

	__s32	level;
	__s32	optname;
	__s32	optlen;
	__s32	retval;
};

struct bpf_raw_tracepoint_args {
 	__u64 args[0];
};

struct bpf_flow_keys {
 	__u16	nhoff;
 	__u16	thoff;
 	__u16	addr_proto;			/* ETH_P_* of valid addrs */
 	__u8	is_frag;
 	__u8	is_first_frag;
 	__u8	is_encap;
 	__u8	ip_proto;
 	__be16	n_proto;
 	__be16	sport;
 	__be16	dport;
 	union {
 		struct {
 			__be32	ipv4_src;
 			__be32	ipv4_dst;
 		};
 		struct {
 			__u32	ipv6_src[4];	/* in6_addr; network order */
 			__u32	ipv6_dst[4];	/* in6_addr; network order */
 		};
 	};
};

#endif /* _UAPI__LINUX_BPF_H__ */
