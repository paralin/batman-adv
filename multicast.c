/*
 * Copyright (C) 2010 B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing
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
 */

#include "main.h"
#include "hash.h"
#include "multicast.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 37)
#define for_each_pmc_rcu(in_dev, pmc)				\
	for (pmc = rcu_dereference(in_dev->mc_list);		\
	     pmc != NULL;					\
	     pmc = rcu_dereference(pmc->next_rcu))
#endif

#ifdef CONFIG_BATMAN_ADV_BR_MC_SNOOP
void br_mc_cpy(char *dst, struct br_ip *src)
{
	if (src->proto == htons(ETH_P_IP)) {
		/* RFC 1112 */
		memcpy(dst, "\x01\x00\x5e", 3);
		memcpy(dst + 3, ((char *)&src->u.ip4) + 1, ETH_ALEN - 3);
		dst[3] &= 0x7F;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (src->proto == htons(ETH_P_IPV6)) {
		/* RFC 2464 */
		memcpy(dst, "\x33\x33", 2);
		memcpy(dst + 2, &src->u.ip6.s6_addr32[3],
		       sizeof(src->u.ip6.s6_addr32[3]));
	}
#endif
	else
		memset(dst, 0, ETH_ALEN);
}
#endif

static int mcast_has_transient_ipv6(uint8_t *addr, struct net_device *dev)
{
	struct inet6_dev *idev;
	struct ifmcaddr6 *mc;
	uint8_t buf[ETH_ALEN];
	int ret = 0;

	rcu_read_lock();
	idev = __in6_dev_get(dev);
	if (!idev)
		goto unlock;

	read_lock_bh(&idev->lock);
	for (mc = idev->mc_list; mc; mc = mc->next) {
		ipv6_eth_mc_map(&mc->mca_addr, buf);
		if (memcmp(addr, buf, ETH_ALEN))
			continue;

		if (IPV6_ADDR_MC_FLAG_TRANSIENT(&mc->mca_addr)) {
			ret = 1;
			break;
		}
	}
	read_unlock_bh(&idev->lock);

unlock:
	rcu_read_unlock();
	return ret;
}

static int mcast_has_non_ll_ipv4(uint8_t *addr, struct net_device *dev)
{
	struct in_device *idev;
	struct ip_mc_list *im;
	uint8_t buf[ETH_ALEN];
	int ret = 0;

	rcu_read_lock();
	idev = __in_dev_get_rcu(dev);
	if (!idev)
		goto unlock;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
	read_lock(&idev->mc_list_lock);
	for (im = idev->mc_list; im; im = im->next) {
#else
	for_each_pmc_rcu(idev, im) {
#endif
		ip_eth_mc_map(im->multiaddr, buf);
		if (memcmp(addr, buf, ETH_ALEN))
			continue;

		if (ipv4_is_local_multicast(im->multiaddr))
			continue;

		ret = 1;
		break;
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
	read_unlock(&idev->mc_list_lock);
#endif

unlock:
	rcu_read_unlock();
	return ret;
}

/* Checks whether there is:
 * - a transient IPv6 address
 * - or a non-link-local IPv4 address
 * matching the specified addr and interface and if so
 * retruns true. These two categories of addresses are (and should
 * always be) the same ones as the bridge multicast snooping is
 * using.
 */
static int mcast_has_unspecial_addr(uint8_t *addr, struct net_device *dev)
{
	if (!memcmp(addr, "\x33\x33", 2))
		return mcast_has_transient_ipv6(addr, dev);
	else if (!memcmp(addr, "\x01\x00\x5E", 3))
		return mcast_has_non_ll_ipv4(addr, dev);
	else
		return 0;
}

/**
 * Attaches "unspecial" multicast addresses to OGM and sets batman_packet's
 * num_mca field accordingly.
 *
 * @batman_packet:	packet buffer to attach the MCAs to
 *			(caller takes care of enough reserved memory)
 * @num_mca:		number of multicast addresses found
 *			(_including_ "special" addresses)
 * @bridge_mc_list:	list of bridge-snooped mcast addresses to attach
 * @soft_iface:		virtual batman mesh interface, used for fetching
 *			own, local mcast addresses
 */
void mcast_add_own_MCA(struct batman_packet *batman_packet, int num_mca,
		       struct list_head *bridge_mc_list,
		       struct net_device *soft_iface)
{
	struct netdev_hw_addr *mc_list_entry;
#ifdef CONFIG_BATMAN_ADV_BR_MC_SNOOP
	struct br_ip_list *br_ip_entry, *tmp;
#endif
	int num_mca_done = 0;
	char *mca_entry = (char *)(batman_packet + 1);

	if (num_mca == 0)
		goto out;

	if (num_mca > UINT8_MAX) {
		pr_warning("Too many multicast announcements here, "
			   "just adding %i\n", UINT8_MAX);
		num_mca = UINT8_MAX;
	}

	mca_entry = mca_entry + batman_packet->num_hna * ETH_ALEN;

	netif_addr_lock_bh(soft_iface);
	netdev_for_each_mc_addr(mc_list_entry, soft_iface) {
		if (!mcast_has_unspecial_addr(mc_list_entry->addr, soft_iface))
			continue;

		memcpy(mca_entry, &mc_list_entry->addr, ETH_ALEN);
		mca_entry += ETH_ALEN;

		/* A multicast address might just have been added,
		 * avoid writing outside of buffer */
		if (++num_mca_done == num_mca)
			break;
	}
	netif_addr_unlock_bh(soft_iface);

#ifdef CONFIG_BATMAN_ADV_BR_MC_SNOOP
	list_for_each_entry_safe(br_ip_entry, tmp, bridge_mc_list, list) {
		if (num_mca_done < num_mca) {
			br_mc_cpy(mca_entry, &br_ip_entry->addr);
			num_mca_done++;
		}

		list_del(&br_ip_entry->list);
		kfree(br_ip_entry);
	}
#endif

out:
	batman_packet->num_mca = num_mca_done;
}

int mcast_mca_local_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct netdev_hw_addr *mc_list_entry;

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);

	netif_addr_lock_bh(net_dev);
	netdev_for_each_mc_addr(mc_list_entry, net_dev) {
		if (!mcast_has_unspecial_addr(mc_list_entry->addr, net_dev))
			continue;

		seq_printf(seq, "%pM\n", mc_list_entry->addr);
	}
	netif_addr_unlock_bh(net_dev);

	return 0;
}

#ifdef CONFIG_BATMAN_ADV_BR_MC_SNOOP
int mcast_mca_bridge_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct list_head bridge_mc_list;
	struct br_ip_list *br_ip_entry, *tmp;
	uint8_t buff[ETH_ALEN];

	INIT_LIST_HEAD(&bridge_mc_list);
	br_mc_snoop_list_adjacent(net_dev, &bridge_mc_list);

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);

	list_for_each_entry_safe(br_ip_entry, tmp, &bridge_mc_list, list) {
		br_mc_cpy(buff, &br_ip_entry->addr);

		seq_printf(seq, "%pM\n", buff);

		list_del(&br_ip_entry->list);
		kfree(br_ip_entry);
	}

	return 0;
}
#endif

int mcast_mca_global_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct orig_node *orig_node;
	struct hlist_node *walk;
	struct hlist_head *head;
	int i, j;

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, walk, head, hash_entry) {
			spin_lock_bh(&orig_node->mca_lock);
			if (!orig_node->num_mca) {
				spin_unlock_bh(&orig_node->mca_lock);
				continue;
			}

			seq_printf(seq, "Originator: %pM\n", orig_node->orig);
			for (j = 0; j < orig_node->num_mca; j++) {
				seq_printf(seq, "\t%pM",
					   &orig_node->mca_buff[j * ETH_ALEN]);
			}
			seq_printf(seq, "\n");
			spin_unlock_bh(&orig_node->mca_lock);
		}
		rcu_read_unlock();
	}

	return 0;
}
