/* Copyright (C) 2016 B.A.T.M.A.N. contributors:
 *
 * Matthias Schiffer
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
 */

#ifndef _NET_BATMAN_ADV_NETLINK_H_
#define _NET_BATMAN_ADV_NETLINK_H_

#include <linux/compiler.h>
#include <linux/genetlink.h>
#include <net/genetlink.h>
#include <net/netlink.h>

struct nlmsghdr;

void batadv_netlink_register(void);
void batadv_netlink_unregister(void);

static inline int
batadv_netlink_get_ifindex(const struct nlmsghdr *nlh, int attrtype)
{
	struct nlattr *attr = nlmsg_find_attr(nlh, GENL_HDRLEN, attrtype);

	return attr ? nla_get_u32(attr) : 0;
}

extern struct genl_family batadv_netlink_family;

#endif /* _NET_BATMAN_ADV_NETLINK_H_ */
