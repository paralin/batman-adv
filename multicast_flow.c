/*
 * Copyright (C) 2012 B.A.T.M.A.N. contributors:
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

/* multicast_flow.c - Reactive multicast flow table management
 *
 * These functions provide the capability to count and keep track of our own
 * multicast flow coming in from the soft interface. This allows us to only
 * build up the forwarding infrastructure if a certain threshold of
 * incoming multicast packets of a certain group is reached. */

#include "main.h"
#include "multicast_flow.h"
#include "multicast_tracker.h"
#include "hash.h"
#include "translation-table.h"
#include "originator.h"

/**
 * batadv_mcast_flow_entry_free_ref - Release reference to flow entry
 * @flow_entry: The flow entry to release a reference from
 *
 * Releases a reference from a multicast flow table entry. Schedules RCU safe
 * freeing if this was the last reference.
 */
void batadv_mcast_flow_entry_free_ref(
				struct batadv_mcast_flow_entry *flow_entry)
{
	if (atomic_dec_and_test(&flow_entry->refcount))
		kfree_rcu(flow_entry, rcu);
}

#if IS_ENABLED(CONFIG_IPV6)
/* FIXME: Move to net/addrconf.h */
static inline bool batadv_mcast_ipv6_is_transient_multicast(
						const struct in6_addr *addr)
{
	return ipv6_addr_is_multicast(addr) &&
	       IPV6_ADDR_MC_FLAG_TRANSIENT(addr);
}
#endif

/**
 * batadv_mcast_ipv4_may_optimize - Checks for non-link-local IPv4 multicast
 * @skb:	The frame to be checked
 *
 * Returns true if an IPv4 packet has a non-link-local IPv4 multicast
 * destination address. Otherwise returns false.
 */
static inline bool batadv_mcast_ipv4_may_optimize(struct sk_buff *skb)
{
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(*iph)))
		return false;

	iph = ip_hdr(skb);

	if (!iph || !ipv4_is_multicast(iph->daddr) ||
	    ipv4_is_local_multicast(iph->daddr))
		return false;

	return true;
}

/**
 * batadv_mcast_ipv6_may_optimize - Checks for transient IPv6 multicast
 * @skb:	The frame to be checked
 *
 * Returns true if an IPv6 packet has a transient IPv6 multicast
 * destination address. Otherwise returns false.
 *
 * Always returns false if we have no IPv6 support.
 */
static bool batadv_mcast_ipv6_may_optimize(struct sk_buff *skb)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct ipv6hdr *ip6h;

	if (!pskb_may_pull(skb, sizeof(*ip6h)))
		return false;

	ip6h = ipv6_hdr(skb);

	if (!ip6h || !batadv_mcast_ipv6_is_transient_multicast(&ip6h->daddr))
		return false;

	return true;
#else
	return false;
#endif
}

/**
 * batadv_mcast_flow_entry_get - Retrieves a multicast flow entry
 * @mcast_addr:	The multicast address of the flow table entry we want to fetch
 * @flow_table:	The multicast flow table we will search in
 *
 * This function will look up a multicast flow entry for the given
 * multicast address in the given flow table and if found returns it.
 * Otherwise returns NULL.
 */
static struct batadv_mcast_flow_entry *batadv_mcast_flow_entry_get(
						uint8_t *mcast_addr,
						struct hlist_head *flow_table)
{
	struct batadv_mcast_flow_entry *entry = NULL;
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

/**
 * batadv_mcast_flow_entry_create - Creates a new multicast flow entry
 * @mcast_addr:	The multicast address of the flow table entry we want to create
 * @bat_priv:	The bat priv with all the soft interface information
 *
 * If a multicast flow entry for the given mcast_addr already exists, then
 * we just return that one while increasing its reference counter.
 * Otherwise a new one with this multicast address gets created and returned.
 */
static struct batadv_mcast_flow_entry *batadv_mcast_flow_entry_create(
						uint8_t *mcast_addr,
						struct batadv_priv *bat_priv)
{
	struct batadv_mcast_flow_entry *entry;
	unsigned long threshold_segment;

	spin_lock_bh(&bat_priv->mcast.flow_table_lock);
	entry = batadv_mcast_flow_entry_get(mcast_addr,
					    &bat_priv->mcast.flow_table);
	if (entry)
		goto out;

	entry = kzalloc(sizeof(struct batadv_mcast_flow_entry), GFP_ATOMIC);
	if (!entry)
		goto out;

	INIT_HLIST_NODE(&entry->list);
	spin_lock_init(&entry->update_lock);

	memcpy(entry->mcast_addr, mcast_addr, ETH_ALEN);
	threshold_segment = msecs_to_jiffies(
			atomic_read(&bat_priv->mcast_threshold_interval)) /
			BATADV_MCAST_THR_CNT_WIN_SIZE;
	entry->update_timeout = jiffies + threshold_segment;

	/* extra reference for return */
	atomic_set(&entry->refcount, 2);

	hlist_add_head_rcu(&entry->list, &bat_priv->mcast.flow_table);

out:
	spin_unlock_bh(&bat_priv->mcast.flow_table_lock);
	return entry;
}

/**
 * batadv_mcast_flow_update_entry - Updates a multicast flow entry
 * @entry:	Multicast flow entry to update
 * @bat_priv:	The bat priv with all the soft interface information
 * @inc:	If set, also increment threshold count by one
 *
 * If the inc flag is set, then this increases the internal counter and
 * last seen value for the given multicast flow table entry.
 *
 * Returns:
 *  * BATADV_MCAST_THRESHOLD_UP: if the threshold is reached with this update
 *  * BATADV_MCAST_THRESHOLD_HIGH: if the threshold is still reached
 *  * BATADV_MCAST_THRESHOLD_LOW: if the threshold is not reached
 */
int batadv_mcast_flow_update_entry(struct batadv_mcast_flow_entry *entry,
				   struct batadv_priv *bat_priv, int inc)
{
	unsigned long curr_time = jiffies, threshold_segment;
	int ret, threshold_high, threshold_count_old;

	threshold_high = atomic_read(&bat_priv->mcast_threshold_count);
	threshold_segment = msecs_to_jiffies(
			atomic_read(&bat_priv->mcast_threshold_interval)) /
			BATADV_MCAST_THR_CNT_WIN_SIZE;

	spin_lock_bh(&entry->update_lock);
	threshold_count_old = entry->threshold_count;

	if (!time_after(curr_time, entry->update_timeout))
		goto inc;

	if (time_after(curr_time, entry->update_timeout +
				  BATADV_MCAST_THR_CNT_WIN_SIZE *
				  threshold_segment)) {
		memset(&entry->threshold_count_window[0], 0,
		       sizeof(entry->threshold_count_window[0]) *
		       BATADV_MCAST_THR_CNT_WIN_SIZE);
		entry->update_timeout = curr_time;
		goto inc;
	}

	do {
		entry->update_timeout += threshold_segment;
		entry->window_index = (entry->window_index + 1)
				      % BATADV_MCAST_THR_CNT_WIN_SIZE;
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

	if (entry->threshold_count < threshold_high) {
		ret = BATADV_MCAST_THRESHOLD_LOW;
	} else if (threshold_count_old < threshold_high) {
		entry->grace_period_timeout = jiffies + msecs_to_jiffies(
				atomic_read(&bat_priv->mcast_grace_period));
		ret = BATADV_MCAST_THRESHOLD_UP;
	} else {
		ret = BATADV_MCAST_THRESHOLD_HIGH;
	}

	spin_unlock_bh(&entry->update_lock);
	return ret;
}

/**
 * batadv_mcast_mla_listener_exists - Checks for a multicast listener
 * @mcast_addr:	The multicast address we want to check
 * @bat_priv:	The bat priv containing the MLA information
 *
 * This function checks whether there is a node which has signaled
 * an interest in the provided mcast_addr via a multicast listener
 * announcement.
 *
 * If so returns true, otherwise false.
 */
static bool batadv_mcast_mla_listener_exists(uint8_t *mcast_addr,
					     struct batadv_priv *bat_priv)
{
	struct batadv_orig_node *orig_node;

	orig_node = batadv_transtable_search(bat_priv, NULL, mcast_addr);
	if (!orig_node)
		return false;

	batadv_orig_node_free_ref(orig_node);

	return true;
}

static bool batadv_mcast_mla_listener_exists_compat(
						uint8_t *mcast_addr,
						struct batadv_priv *bat_priv)
{
	struct batadv_hashtable *hash = bat_priv->orig_hash;
	struct hlist_node *node;
	struct hlist_head *head;
	struct batadv_orig_node *orig_node;
	int i;
	bool ret = false;

	if (!hash)
		goto out;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, node, head, hash_entry) {
			if (orig_node->flags & BATADV_MCAST_OPTIMIZATIONS)
				continue;

			ret = true;
			break;
		}
		rcu_read_unlock();
	}

out:
	return ret;
}

/**
 * batadv_mcast_flow_table_update - Update a multicast flow table entry
 * @mcast_addr:	The multicast address (= flow table entry) we want to update
 * @bat_priv:	The bat priv with all the soft interface information
 *
 * This increases the internal counter for the specified multicast group
 * (more precisely, this multicast MAC address).
 *
 * If the configured threshold for this multicast MAC address is met with
 * this update then a burst of tracker packets will be send immediately.
 *
 * Further returns 1 if the configured threshold and grace period
 * for this multicast MAC address are met to indicate the availability of
 * a multicast forwarding tree.
 *
 * Returns -1 if this frame should be dropped (e.g. because either
 * we got an out-of-memory or because there is no other node
 * interested in this frame (= there is no matching MLA entry) ).
 *
 * Otherwise returns 0 to tell the caller to better use BATADV_BCAST
 * instead of BATADV_MCAST for now.
 */
static int batadv_mcast_flow_table_update(uint8_t *mcast_addr,
					  struct batadv_priv *bat_priv)
{
	struct batadv_mcast_flow_entry *entry = NULL;
	int ret = -1, threshold_state;

	/* if many multicast packets are coming in, then we want to avoid using
	 * the slower, spinlocked batadv_mcast_flow_entry_create() as much as
	 * possible */
	entry = batadv_mcast_flow_entry_get(mcast_addr,
					    &bat_priv->mcast.flow_table);
	if (entry)
		goto skip;

	entry = batadv_mcast_flow_entry_create(mcast_addr, bat_priv);
	if (!entry)
		goto out;

skip:
	threshold_state = batadv_mcast_flow_update_entry(entry, bat_priv, 1);
	switch (threshold_state) {
	case BATADV_MCAST_THRESHOLD_UP:
		batadv_mcast_tracker_burst(mcast_addr, bat_priv);
	case BATADV_MCAST_THRESHOLD_HIGH:
		if (time_after(jiffies, entry->grace_period_timeout)) {
			ret = 1;
			goto out;
		}
	}

	if (batadv_mcast_mla_listener_exists(mcast_addr, bat_priv) ||
	    batadv_mcast_mla_listener_exists_compat(mcast_addr, bat_priv))
		ret = 0;

out:
	if (entry)
		batadv_mcast_flow_entry_free_ref(entry);
	return ret;
}

/**
 * batadv_mcast_flow_may_optimize - Grants permission to use BATADV_MCAST
 * @skb:	The frame to be checked
 * @bat_priv:	The bat priv with all the soft interface information
 *
 * If multicast optimization is enabled and if the skb
 * contains either a valid transient IPv6 multicast address or
 * a valid non-link-local IPv4 multicast address then:
 *
 * This increases the internal counter for this multicast group
 * (more precisely, this multicast MAC address).
 *
 * Further returns 1 if the configured threshold and grace period
 * for this multicast MAC address are met to indicate the availability of
 * a multicast forwarding tree.
 *
 * Returns -1 if this frame should be dropped (e.g. because either
 * we got an out-of-memory or because there is no other node
 * interested in this frame (= there is no matching MLA entry) ).
 *
 * Otherwise returns 0 to tell the caller to better use BATADV_BCAST
 * instead of BATADV_MCAST for now.
 */
int batadv_mcast_flow_may_optimize(struct sk_buff *skb,
				   struct batadv_priv *bat_priv)
{
	struct ethhdr *ethhdr = (struct ethhdr *)skb->data;
	int ret;

	if (!atomic_read(&bat_priv->mcast_group_awareness))
		ret = 0;
	else if (ntohs(ethhdr->h_proto) == ETH_P_IP)
		ret = batadv_mcast_ipv4_may_optimize(skb);
	else if (ntohs(ethhdr->h_proto) == ETH_P_IPV6)
		ret = batadv_mcast_ipv6_may_optimize(skb);
	else
		ret = 0;

	if (!ret)
		goto out;

	ret = batadv_mcast_flow_table_update(ethhdr->h_dest, bat_priv);

out:
	return ret;
}

/**
 * batadv_mcast_flow_table_purge - Deletes outdated flow table entries
 * @bat_priv:	The bat priv with all the soft interface information
 *
 * Purges multicast flow entries either after BATADV_PURGE_TIMEOUT seconds or
 * after 2x mcast_threshold_interval if that is higher.
 */
void batadv_mcast_flow_table_purge(struct batadv_priv *bat_priv)
{
	struct batadv_mcast_flow_entry *entry;
	struct hlist_node *node;
	unsigned long timeout;

	timeout = atomic_read(&bat_priv->mcast_threshold_interval);
	timeout = 2 * timeout > BATADV_PURGE_TIMEOUT ?
		  2 * timeout : BATADV_PURGE_TIMEOUT;
	timeout = msecs_to_jiffies(timeout);

	spin_lock_bh(&bat_priv->mcast.flow_table_lock);
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast.flow_table, list) {
		if (!time_after(jiffies, entry->last_seen + timeout))
			continue;

		hlist_del_rcu(&entry->list);
		batadv_mcast_flow_entry_free_ref(entry);
	}
	spin_unlock_bh(&bat_priv->mcast.flow_table_lock);
}

/**
 * batadv_mcast_flow_table_free - Fully frees a multicast flow table
 * @bat_priv:	The bat priv with all the soft interface information
 *
 * This frees all data stored in mcast.flow_table of the provided bat_priv -
 * data which got previously, dynamically allocated upon new, own,
 * multicast data streams on our soft interface.
 */
void batadv_mcast_flow_table_free(struct batadv_priv *bat_priv)
{
	struct batadv_mcast_flow_entry *entry;
	struct hlist_node *node;

	spin_lock_bh(&bat_priv->mcast.flow_table_lock);
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast.flow_table, list) {
		hlist_del_rcu(&entry->list);
		batadv_mcast_flow_entry_free_ref(entry);
	}
	spin_unlock_bh(&bat_priv->mcast.flow_table_lock);
}

int batadv_mcast_flow_table_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct batadv_priv *bat_priv = netdev_priv(net_dev);
	struct batadv_mcast_flow_entry *entry;
	struct hlist_node *node;
	int threshold_state, last_seen_secs, last_seen_msecs;
	int interval, threshold;
	long grace_period_left;
	char state;

	seq_printf(seq, "Multicast flow table (from %s):\n",
		   net_dev->name);
	seq_printf(seq, "%-11s %-13s %s %s %s\n",
		   "state", "Mcast-Addr:", "last-seen",
		   "pkts/ival (threshold)", "[grace-period-left]");

	interval = atomic_read(&bat_priv->mcast_threshold_interval);
	threshold = atomic_read(&bat_priv->mcast_threshold_count);

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, node,
				 &bat_priv->mcast.flow_table, list) {
		last_seen_secs = jiffies_to_msecs(jiffies -
					entry->last_seen) / 1000;
		last_seen_msecs = jiffies_to_msecs(jiffies -
					entry->last_seen) % 1000;

		threshold_state = batadv_mcast_flow_update_entry(entry,
								 bat_priv, 0);
		grace_period_left =
			((long long)jiffies_to_msecs(entry->grace_period_timeout) -
			 (long long)jiffies_to_msecs(jiffies));

		if (threshold_state == BATADV_MCAST_THRESHOLD_LOW) {
			state = ' ';
		} else if (grace_period_left <= 0) {
			state = '+';
			grace_period_left = 0;
		} else {
			state = '~';
		}

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
