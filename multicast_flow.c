/*
 * Copyright (C) 2011 B.A.T.M.A.N. contributors:
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
#include "multicast_flow.h"
#include "hash.h"

static void flow_entry_free_rcu(struct rcu_head *rcu)
{
	struct mcast_flow_entry *flow_entry;

	flow_entry = container_of(rcu, struct mcast_flow_entry, rcu);
	kfree(flow_entry);
}

void flow_entry_free_ref(struct mcast_flow_entry *flow_entry)
{
	if (atomic_dec_and_test(&flow_entry->refcount))
		call_rcu(&flow_entry->rcu, flow_entry_free_rcu);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static inline int ipv6_is_transient_multicast(const struct in6_addr *addr)
{
	if (ipv6_addr_is_multicast(addr) && IPV6_ADDR_MC_FLAG_TRANSIENT(addr))
		return 1;
	return 0;
}
#endif

static inline int mcast_ipv4_may_optimize(struct sk_buff *skb)
{
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(*iph)))
		return 0;

	iph = ip_hdr(skb);

	if (!iph || !ipv4_is_multicast(iph->daddr) ||
	    ipv4_is_local_multicast(iph->daddr))
		return 0;

	return 1;
}

static int mcast_ipv6_may_optimize(struct sk_buff *skb)
{
	struct ipv6hdr *ip6h;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		return 0;

	ip6h = ipv6_hdr(skb);

	if (!ip6h || !ipv6_addr_is_multicast(&ip6h->daddr) ||
	    !ipv6_is_transient_multicast(&ip6h->daddr))
		return 0;

	return 1;
}

static struct mcast_flow_entry *get_flow_entry(uint8_t *mcast_addr,
					       struct hlist_head *flow_table)
{
	struct mcast_flow_entry *entry = NULL;
	struct hlist_node *node;

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, node, flow_table, list)
		if (!memcmp(entry->mcast_addr, mcast_addr, ETH_ALEN))
			goto inc;

	entry = NULL;
	goto out;

inc:
	if (!atomic_inc_not_zero(&entry->refcount))
		entry = NULL;

out:
	rcu_read_unlock();
	return entry;
}

static struct mcast_flow_entry *create_flow_entry(uint8_t *mcast_addr,
						  struct bat_priv *bat_priv)
{
	struct mcast_flow_entry *entry;
	unsigned long threshold_segment;

	spin_lock_bh(&bat_priv->mcast_flow_table_lock);
	entry = get_flow_entry(mcast_addr, &bat_priv->mcast_flow_table);
	if (entry)
		goto out;

	entry = kzalloc(sizeof(struct mcast_flow_entry), GFP_ATOMIC);
	if (!entry)
		goto out;

	INIT_HLIST_NODE(&entry->list);
	spin_lock_init(&entry->update_lock);

	memcpy(entry->mcast_addr, mcast_addr, ETH_ALEN);
	threshold_segment = msecs_to_jiffies(
			atomic_read(&bat_priv->mcast_threshold_interval)) /
			THR_CNT_WIN_SIZE;
	entry->update_timeout = jiffies + threshold_segment;

	/* extra reference for return */
	atomic_set(&entry->refcount, 2);

	hlist_add_head_rcu(&entry->list, &bat_priv->mcast_flow_table);

out:
	spin_unlock_bh(&bat_priv->mcast_flow_table_lock);
	return entry;
}

/**
 * Returns:	1: threshold up (and therefore high)
 *		-1: threshold high, but not up
 *		0: threshold low
 *
 * @entry:	multicast tracker entry to update
 * @inc:	if set, also increment threshold count by one
 */
int update_flow_entry(struct mcast_flow_entry *entry,
		      struct bat_priv *bat_priv, int inc)
{
	unsigned long curr_time = jiffies, threshold_segment;
	int ret, threshold_high, threshold_count_old;

	threshold_high = atomic_read(&bat_priv->mcast_threshold_count);
	threshold_segment = msecs_to_jiffies(
			atomic_read(&bat_priv->mcast_threshold_interval)) /
			THR_CNT_WIN_SIZE;

	spin_lock_bh(&entry->update_lock);
	threshold_count_old = entry->threshold_count;

	if (!time_after(curr_time, entry->update_timeout))
		goto inc;

	if (time_after(curr_time, entry->update_timeout +
				  THR_CNT_WIN_SIZE * threshold_segment)) {
		memset(&entry->threshold_count_window[0], 0,
		       sizeof(entry->threshold_count_window[0]) *
		       THR_CNT_WIN_SIZE);
		entry->update_timeout = curr_time;
		goto inc;
	}

	do {
		entry->update_timeout += threshold_segment;
		entry->window_index = (entry->window_index + 1)
				      % THR_CNT_WIN_SIZE;
		entry->threshold_count -=
			    entry->threshold_count_window[entry->window_index];
		entry->threshold_count_window[entry->window_index] = 0;
	} while (time_after(curr_time, entry->update_timeout));

inc:
	if (!inc)
		goto skip;

	entry->threshold_count_window[entry->window_index]++;
	entry->threshold_count++;
	entry->last_seen = jiffies;
skip:

	if (entry->threshold_count < threshold_high)
		ret = 0;
	else if (threshold_count_old < threshold_high) {
		entry->grace_period_timeout = jiffies + msecs_to_jiffies(
				atomic_read(&bat_priv->mcast_grace_period));
		ret = 1;
	} else
		ret = -1;

	spin_unlock_bh(&entry->update_lock);
	return ret;
}

static int mcast_MCA_listener_exists(uint8_t *mcast_addr,
				     struct bat_priv *bat_priv)
{
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct orig_node *orig_node;
	struct hlist_node *walk;
	struct hlist_head *head;
	int i, j, ret = 0;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, walk, head, hash_entry) {
			spin_lock_bh(&orig_node->mca_lock);
			for (j = 0; j < orig_node->num_mca; j++) {
				if (!memcmp(&orig_node->mca_buff[j * ETH_ALEN],
					    mcast_addr, ETH_ALEN)) {
					spin_unlock_bh(&orig_node->mca_lock);
					rcu_read_unlock();
					ret = 1;
					goto out;
				}
			}
			spin_unlock_bh(&orig_node->mca_lock);
		}
		rcu_read_unlock();
	}

out:
	return ret;
}

/**
 * return:	1 -> multicast optimization
 *		0 -> broadcast, classic flooding
 *		-1 -> drop
 */
static int mcast_update_flow_table(uint8_t *mcast_addr,
				   struct bat_priv *bat_priv)
{
	struct mcast_flow_entry *entry = NULL;
	int ret = -1, threshold_state;

	entry = get_flow_entry(mcast_addr, &bat_priv->mcast_flow_table);
	if (entry)
		goto skip;

	entry = create_flow_entry(mcast_addr, bat_priv);
	if (!entry)
		goto out;

skip:
	threshold_state = update_flow_entry(entry, bat_priv, 1);
	if (threshold_state) {
		if (time_after(jiffies, entry->grace_period_timeout)) {
			ret = 1;
			goto out;
		}
	}

	if (mcast_MCA_listener_exists(mcast_addr, bat_priv))
		ret = 0;

out:
	if (entry)
		flow_entry_free_ref(entry);
	return ret;
}

/**
 * return:	1 -> multicast optimization
 *		0 -> broadcast, classic flooding
 *		-1 -> drop
 */
int mcast_may_optimize(struct sk_buff *skb, struct net_device *soft_iface)
{
	struct bat_priv *bat_priv = netdev_priv(soft_iface);
	struct ethhdr *ethhdr = (struct ethhdr *)skb->data;
	int ret;

	if (!atomic_read(&bat_priv->mcast_group_awareness))
		ret = 0;
	else if (ntohs(ethhdr->h_proto) == ETH_P_IP)
		ret = mcast_ipv4_may_optimize(skb);
	else if (ntohs(ethhdr->h_proto) == ETH_P_IPV6)
		ret = mcast_ipv6_may_optimize(skb);
	else
		ret = 0;

	if (!ret)
		goto out;

	ret = mcast_update_flow_table(ethhdr->h_dest, bat_priv);

out:
	return ret;
}

/**
 * Purges multicast flow entries either after PURGE_TIMEOUT seconds or after
 * 2x mcast_threshold_interval if that is higher.
 */
void mcast_flow_table_purge(struct bat_priv *bat_priv)
{
	struct mcast_flow_entry *entry;
	struct hlist_node *node;
	unsigned long timeout;

	timeout = atomic_read(&bat_priv->mcast_threshold_interval);
	timeout = 2 * timeout > PURGE_TIMEOUT * 1000 ?
		  2 * timeout : PURGE_TIMEOUT * 1000;
	timeout = msecs_to_jiffies(timeout);

	spin_lock_bh(&bat_priv->mcast_flow_table_lock);
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast_flow_table, list) {
		if (!time_after(jiffies, entry->last_seen + timeout))
			continue;

		hlist_del_rcu(&entry->list);
		flow_entry_free_ref(entry);
	}
	spin_unlock_bh(&bat_priv->mcast_flow_table_lock);
}

void mcast_flow_table_free(struct bat_priv *bat_priv)
{
	struct mcast_flow_entry *entry;
	struct hlist_node *node;

	spin_lock_bh(&bat_priv->mcast_flow_table_lock);
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast_flow_table, list) {
		hlist_del_rcu(&entry->list);
		flow_entry_free_ref(entry);
	}
	spin_unlock_bh(&bat_priv->mcast_flow_table_lock);
}

int mcast_flow_table_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct mcast_flow_entry *entry;
	struct hlist_node *node;
	int threshold_state, last_seen_secs, last_seen_msecs;
	int interval, threshold;
	long grace_period_left;
	char state;

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);
	seq_printf(seq, "%-11s %-13s %s %s %s\n",
			"state", "Mcast-Addr:", "last-seen",
			"pkts/ival (threshold)", "[grace-period-left]");

	interval = atomic_read(&bat_priv->mcast_threshold_interval);
	threshold = atomic_read(&bat_priv->mcast_threshold_count);

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast_flow_table, list) {
		last_seen_secs = jiffies_to_msecs(jiffies -
					entry->last_seen) / 1000;
		last_seen_msecs = jiffies_to_msecs(jiffies -
					entry->last_seen) % 1000;

		threshold_state = update_flow_entry(entry, bat_priv, 0);
		grace_period_left =
			jiffies_to_msecs(entry->grace_period_timeout) -
			jiffies_to_msecs(jiffies);

		if (!threshold_state)
			state = ' ';
		else if (grace_period_left <= 0) {
			state = '+';
			grace_period_left = 0;
		} else
			state = '~';

		if (state != ' ')
			seq_printf(seq,
				   "%4c %pM: %6i.%03is %8i/%ims (%i) %6lims\n",
				   state, entry->mcast_addr,
				   last_seen_secs, last_seen_msecs,
				   entry->threshold_count,
				   interval, threshold, grace_period_left);
		else
			seq_printf(seq,
				   "%4c %pM: %6i.%03is %8i/%ims (%i)\n",
				   state, entry->mcast_addr,
				   last_seen_secs, last_seen_msecs,
				   entry->threshold_count,
				   interval, threshold);
	}
	rcu_read_unlock();

	return 0;
}
