/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2019 Facebook */
#ifndef _BPF_SK_STORAGE_H
#define _BPF_SK_STORAGE_H

#include <linux/types.h>
#include <linux/spinlock.h>

struct sock;

void bpf_sk_storage_free(struct sock *sk);

extern const struct bpf_func_proto bpf_sk_storage_get_proto;
extern const struct bpf_func_proto bpf_sk_storage_delete_proto;

#define BPF_LOCAL_STORAGE_CACHE_SIZE	16

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	u64 idx_usage_counts[BPF_LOCAL_STORAGE_CACHE_SIZE];
};

#define DEFINE_BPF_STORAGE_CACHE(name)				\
static struct bpf_local_storage_cache name = {			\
	.idx_lock = __SPIN_LOCK_UNLOCKED(name.idx_lock),	\
}

u16 bpf_local_storage_cache_idx_get(struct bpf_local_storage_cache *cache);
void bpf_local_storage_cache_idx_free(struct bpf_local_storage_cache *cache,
				      u16 idx);

#ifdef CONFIG_BPF_SYSCALL
int bpf_sk_storage_clone(const struct sock *sk, struct sock *newsk);
#else
static inline int bpf_sk_storage_clone(const struct sock *sk,
				       struct sock *newsk)
{
	return 0;
}
#endif

#endif /* _BPF_SK_STORAGE_H */
