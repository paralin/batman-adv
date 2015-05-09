#include <linux/if_bridge.h>
#include <linux/printk.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0) || \
    LINUX_VERSION_CODE == KERNEL_VERSION(3, 16, 0) && \
	(!IS_ENABLED(CONFIG_BRIDGE) || \
	!IS_ENABLED(CONFIG_BRIDGE_IGMP_SNOOPING))

int br_multicast_list_adjacent(struct net_device *dev,
			       struct list_head *br_ip_list)
{
	return 0;
}

bool br_multicast_has_querier_adjacent(struct net_device *dev, int proto)
{
	return false;
}

#endif /* < KERNEL_VERSION(3, 16, 0) ||
	* !IS_ENABLED(CONFIG_BRIDGE) ||
	* !IS_ENABLED(CONFIG_BRIDGE_IGMP_SNOOPING) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)

bool br_multicast_has_querier_anywhere(struct net_device *dev, int proto)
{
	pr_warn_once("Old kernel detected (< 3.17) - multicast optimizations disabled\n");

	return false;
}

#endif /* < KERNEL_VERSION(3, 17, 0) */
