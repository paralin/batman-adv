/* Copyright (C) 2007-2016 B.A.T.M.A.N. contributors:
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

#ifndef _NET_BATMAN_ADV_COMPAT_LINUX_NETLINK_H_
#define _NET_BATMAN_ADV_COMPAT_LINUX_NETLINK_H_

#include <linux/version.h>
#include_next <linux/netlink.h>

#include <net/scm.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)

struct batadv_netlink_skb_parms {
	struct ucred		creds;		/* Skb credentials	*/
	union {
		__u32		portid;
		__u32		pid;
	};
	__u32			dst_group;
};

#undef NETLINK_CB
#define NETLINK_CB(skb) (*(struct batadv_netlink_skb_parms*)&((skb)->cb))

#endif /* < KERNEL_VERSION(3, 7, 0) */

#endif /* _NET_BATMAN_ADV_COMPAT_LINUX_NETLINK_H_ */
