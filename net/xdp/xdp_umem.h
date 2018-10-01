/* SPDX-License-Identifier: GPL-2.0
 * XDP user-space packet buffer
 * Copyright(c) 2018 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef XDP_UMEM_H_
#define XDP_UMEM_H_

#include <net/xdp_sock.h>

int xdp_umem_assign_dev(struct xdp_umem *umem, struct net_device *dev,
			u16 queue_id, u16 flags);
bool xdp_umem_validate_queues(struct xdp_umem *umem);
void xdp_get_umem(struct xdp_umem *umem);
void xdp_put_umem(struct xdp_umem *umem);
void xdp_add_sk_umem(struct xdp_umem *umem, struct xdp_sock *xs);
void xdp_del_sk_umem(struct xdp_umem *umem, struct xdp_sock *xs);
struct xdp_umem *xdp_umem_create(struct xdp_umem_reg *mr);

#endif /* XDP_UMEM_H_ */
