/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 *
 * This file contains macros for maintaining compatibility with older versions
 * of the Linux kernel.
 */

#include <linux/in.h>
#include <linux/version.h>
#include "main.h"
#include "multicast_flow.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)

void batadv_for_each_pmc_rcu_init(struct in_device *in_dev,
				  struct ip_mc_list **pmc)
{
	read_lock(&in_dev->mc_list_lock);
	*pmc = in_dev->mc_list;
}

bool batadv_for_each_pmc_rcu_check(struct in_device *in_dev,
				   struct ip_mc_list *pmc)
{
	if (pmc == NULL)
		read_unlock(&in_dev->mc_list_lock);

	return (pmc != NULL);
}

#endif /* < KERNEL_VERSION(2, 6, 38) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)

/* copy from multicast_forw.c */
struct batadv_mcast_forw_nexthop_entry {
	struct hlist_node list;
	uint8_t neigh_addr[ETH_ALEN];
	unsigned long timeout;	/* old jiffies value */
	struct rcu_head rcu;
};

/* copy from multicast_forw.c */
struct batadv_mcast_forw_if_entry {
	struct hlist_node list;
	int16_t if_num;
	int num_nexthops;
	struct hlist_head mcast_nexthop_list;
	struct rcu_head rcu;
};

/* copy from multicast_forw.c */
struct batadv_mcast_forw_orig_entry {
	struct hlist_node list;
	uint8_t orig[ETH_ALEN];
	struct hlist_head mcast_if_list;
	struct rcu_head rcu;
};

/* copy from multicast_forw.c */
struct batadv_mcast_forw_table_entry {
	struct hlist_node list;
	uint8_t mcast_addr[ETH_ALEN];
	struct hlist_head mcast_orig_list;
	struct rcu_head rcu;
};


void batadv_free_rcu_gw_node(struct rcu_head *rcu)
{
	struct batadv_gw_node *gw_node;

	gw_node = container_of(rcu, struct batadv_gw_node, rcu);
	kfree(gw_node);
}

void batadv_free_rcu_neigh_node(struct rcu_head *rcu)
{
	struct batadv_neigh_node *neigh_node;

	neigh_node = container_of(rcu, struct batadv_neigh_node, rcu);
	kfree(neigh_node);
}

void batadv_free_rcu_tt_local_entry(struct rcu_head *rcu)
{
	struct batadv_tt_common_entry *tt_common_entry;
	struct batadv_tt_local_entry *tt_local_entry;

	tt_common_entry = container_of(rcu, struct batadv_tt_common_entry, rcu);
	tt_local_entry = container_of(tt_common_entry,
				      struct batadv_tt_local_entry, common);
	kfree(tt_local_entry);
}

#ifdef CONFIG_BATMAN_ADV_BLA
void batadv_free_rcu_backbone_gw(struct rcu_head *rcu)
{
	struct batadv_backbone_gw *backbone_gw;

	backbone_gw = container_of(rcu, struct batadv_backbone_gw, rcu);
	kfree(backbone_gw);
}
#endif

#ifdef CONFIG_BATMAN_ADV_DAT
void batadv_free_rcu_dat_entry(struct rcu_head *rcu)
{
	struct batadv_dat_entry *dat_entry;

	dat_entry = container_of(rcu, struct batadv_dat_entry, rcu);
	kfree(dat_entry);
}
#endif

/**
 * batadv_free_rcu_flow_entry - Frees a multicast flow entry
 * @rcu:	The RCU context holding our flow entry
 *
 * This method should be scheduled via something like call_rcu().
 */
void batadv_free_rcu_flow_entry(struct rcu_head *rcu)
{
	struct batadv_mcast_flow_entry *flow_entry;

	flow_entry = container_of(rcu, struct batadv_mcast_flow_entry, rcu);
	kfree(flow_entry);
}

/**
 * batadv_free_rcu_nexthop_entry - Frees a multicast table nexthop entry
 * @rcu:	The RCU context of the nexthop entry to free
 *
 * Frees the nexthop entry which holds the specfied RCU structure.
 */
void batadv_free_rcu_nexthop_entry(struct rcu_head *rcu)
{
	struct batadv_mcast_forw_nexthop_entry *nexthop_entry;

	nexthop_entry = container_of(rcu,
				     struct batadv_mcast_forw_nexthop_entry,
				     rcu);
	kfree(nexthop_entry);
}

/**
 * batadv_free_rcu_if_entry - Frees a multicast table interface entry
 * @rcu:	The RCU context of the interface entry to free
 *
 * Frees the interface entry which holds the specfied RCU structure.
 */
void batadv_free_rcu_if_entry(struct rcu_head *rcu)
{
	struct batadv_mcast_forw_if_entry *if_entry;

	if_entry = container_of(rcu, struct batadv_mcast_forw_if_entry, rcu);
	kfree(if_entry);
}

/**
 * batadv_free_rcu_orig_entry - Frees a multicast table originator entry
 * @rcu:	The RCU context of the originator entry to free
 *
 * Frees the originator entry which holds the specfied RCU structure.
 */
void batadv_free_rcu_orig_entry(struct rcu_head *rcu)
{
	struct batadv_mcast_forw_orig_entry *orig_entry;

	orig_entry = container_of(rcu, struct batadv_mcast_forw_orig_entry,
				  rcu);
	kfree(orig_entry);
}

/**
 * batadv_free_rcu_table_entry - Frees a multicast table entry
 * @rcu:	The RCU context of the nexthop entry to free
 *
 * Frees the multicast table entry which holds the specfied RCU structure.
 */
void batadv_free_rcu_table_entry(struct rcu_head *rcu)
{
	struct batadv_mcast_forw_table_entry *table_entry;

	table_entry = container_of(rcu, struct batadv_mcast_forw_table_entry,
				   rcu);
	kfree(table_entry);
}

#endif /* < KERNEL_VERSION(3, 0, 0) */
