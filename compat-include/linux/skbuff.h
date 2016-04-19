/* Copyright (C) 2007-2016  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * This file contains macros for maintaining compatibility with older versions
 * of the Linux kernel.
 */

#ifndef _NET_BATMAN_ADV_COMPAT_LINUX_SKBUFF_H_
#define _NET_BATMAN_ADV_COMPAT_LINUX_SKBUFF_H_

#include <linux/version.h>
#include_next <linux/skbuff.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)

/* hack for not correctly set mac_len. This may happen for some special
 * configurations like batman-adv on VLANs.
 *
 * This is pretty dirty, but we only use skb_share_check() in main.c right
 * before mac_len is checked, and the recomputation shouldn't hurt too much.
 */
#define skb_share_check(skb, b) \
	({ \
		struct sk_buff *_t_skb; \
		_t_skb = skb_share_check(skb, b); \
		if (_t_skb) \
			skb_reset_mac_len(_t_skb); \
		_t_skb; \
	})

#endif /* < KERNEL_VERSION(3, 8, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)

/* older kernels still need to call skb_abort_seq_read() */
#define skb_seq_read(consumed, data, st) \
	({ \
		int __len = skb_seq_read(consumed, data, st); \
		if (__len == 0) \
			skb_abort_seq_read(st); \
		__len; \
	})

#endif /* < KERNEL_VERSION(3, 11, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)

#define pskb_copy_for_clone pskb_copy

__sum16 skb_checksum_simple_validate(struct sk_buff *skb);

__sum16
skb_checksum_validate(struct sk_buff *skb, int proto,
		      __wsum (*compute_pseudo)(struct sk_buff *skb, int proto));

#endif /* < KERNEL_VERSION(3, 16, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)

struct sk_buff *skb_checksum_trimmed(struct sk_buff *skb,
				     unsigned int transport_len,
				     __sum16(*skb_chkf)(struct sk_buff *skb));

#endif /* < KERNEL_VERSION(4, 2, 0) */

#endif	/* _NET_BATMAN_ADV_COMPAT_LINUX_SKBUFF_H_ */
