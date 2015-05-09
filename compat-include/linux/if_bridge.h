#ifndef _NET_BATMAN_ADV_COMPAT_LINUX_IF_BRIDGE_H_
#define _NET_BATMAN_ADV_COMPAT_LINUX_IF_BRIDGE_H_

#include <linux/version.h>
#include_next <linux/if_bridge.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)

int br_multicast_list_adjacent(struct net_device *dev,
			       struct list_head *br_ip_list);
bool br_multicast_has_querier_adjacent(struct net_device *dev, int proto);

struct br_ip {
	union {
		__be32  ip4;
#if IS_ENABLED(CONFIG_IPV6)
		struct in6_addr ip6;
#endif
	} u;
	__be16          proto;
	__u16           vid;
};

struct br_ip_list {
	struct list_head list;
	struct br_ip addr;
};

#endif /* < KERNEL_VERSION(3, 16, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)

bool br_multicast_has_querier_anywhere(struct net_device *dev, int proto);

#endif /* < KERNEL_VERSION(3, 17, 0) */

#endif	/* _NET_BATMAN_ADV_COMPAT_LINUX_IF_BRIDGE_H_ */
