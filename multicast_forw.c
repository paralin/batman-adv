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

/* multicast_forw.c - Multicast routing table
 *
 * This part provides the functions for updating (e.g. when a multicast
 * tracker packet arrives) and storing our multicast routing table
 * (until entries time out).
 *
 * The routing table memorizes a tuple of a multicast group
 * (e.g. a multicast MAC address), an originator and a next hop
 * (+ its according interface) to be able to quickly determine the
 * next hop(s) for a specific multicast data packet and whether to
 * forward via unicast or broadcast packets.
 */

#include "main.h"

struct batadv_mcast_forw_nexthop_entry {
	struct hlist_node list;
	uint8_t neigh_addr[ETH_ALEN];
	unsigned long timeout;	/* old jiffies value */
	struct rcu_head rcu;
};

struct batadv_mcast_forw_if_entry {
	struct hlist_node list;
	int16_t if_num;
	int num_nexthops;
	struct hlist_head mcast_nexthop_list;
	struct rcu_head rcu;
};

struct batadv_mcast_forw_orig_entry {
	struct hlist_node list;
	uint8_t orig[ETH_ALEN];
	struct hlist_head mcast_if_list;
	struct rcu_head rcu;
};

struct batadv_mcast_forw_table_entry {
	struct hlist_node list;
	uint8_t mcast_addr[ETH_ALEN];
	struct hlist_head mcast_orig_list;
	struct rcu_head rcu;
};


/**
 * batadv_mcast_get_remaining_timeout - Timeout of a routing table element
 * @nexthop_entry:	The entry we want to return the remaining timeout of
 * @bat_priv:		The bat_priv holding the configured tracker timeout
 *
 * Either returns the remaining timeout of the specified nexthop_entry
 * in milliseconds or returns 0 if the timeout was exceeded.
 *
 * The remaining timeout will be generated on call of this function by
 * fetching the currently configured tracker timeout.
 */
static inline long batadv_mcast_get_remaining_timeout(
			struct batadv_mcast_forw_nexthop_entry *nexthop_entry,
			struct batadv_priv *bat_priv)
{
	long forw_timeout = atomic_read(&bat_priv->mcast_forw_timeout);

	forw_timeout = jiffies_to_msecs(nexthop_entry->timeout) -
			jiffies_to_msecs(jiffies) + forw_timeout;

	return (forw_timeout > 0 ? forw_timeout : 0);
}

/**
 * batadv_mcast_forw_if_entry_prep - Creates/adds an interface/neighbor entry
 * @forw_if_list:	The list the new entry will be added to
 * @if_num:		The interface index for the new interface entry
 * @neigh_addr:		The neighbor address for the new next-hop entry
 *
 * This method adds the interface number and neighbor address into the given
 * forw_if_list, using a format suitable for fast merging into our multicast
 * routing table.
 *
 * More specifically it prepares a multicast next-hop entry with the given
 * neighbor address. Then this entry plus the given interface index will be
 * used to generate a multicast interface entry which will finally be added to
 * the given multicast interface list.
 *
 * Duplicates are checked and omitted though (as there might be quite a lot of
 * them because several destination entries of a tracker packet can have the
 * same next hop which would lead to a lot of unnecessary memory allocations
 * otherwise).
 *
 * Will leave forw_if_list unmodified in case of out-of-memory errors.
 */
void batadv_mcast_forw_if_entry_prep(struct hlist_head *forw_if_list,
				     int16_t if_num,
				     uint8_t *neigh_addr)
{
	struct batadv_mcast_forw_if_entry *forw_if_entry;
	struct batadv_mcast_forw_nexthop_entry *forw_nexthop_entry;
	struct hlist_node *node;

	hlist_for_each_entry(forw_if_entry, node, forw_if_list, list)
		if (forw_if_entry->if_num == if_num)
			goto skip_create_if;

	forw_if_entry = kmalloc(sizeof(struct batadv_mcast_forw_if_entry),
				GFP_ATOMIC);
	if (!forw_if_entry)
		return;

	forw_if_entry->if_num = if_num;
	forw_if_entry->num_nexthops = 0;
	INIT_HLIST_HEAD(&forw_if_entry->mcast_nexthop_list);
	hlist_add_head(&forw_if_entry->list, forw_if_list);

skip_create_if:
	hlist_for_each_entry(forw_nexthop_entry, node,
			     &forw_if_entry->mcast_nexthop_list, list) {
		if (!memcmp(forw_nexthop_entry->neigh_addr,
			    neigh_addr, ETH_ALEN))
			return;
	}

	forw_nexthop_entry = kmalloc(
				sizeof(struct batadv_mcast_forw_nexthop_entry),
				GFP_ATOMIC);
	if (!forw_nexthop_entry && forw_if_entry->num_nexthops)
		return;
	else if (!forw_nexthop_entry)
		goto free;

	memcpy(forw_nexthop_entry->neigh_addr, neigh_addr, ETH_ALEN);
	forw_nexthop_entry->timeout = jiffies;
	forw_if_entry->num_nexthops++;
	if (forw_if_entry->num_nexthops < 0) {
		kfree(forw_nexthop_entry);
		goto free;
	}

	hlist_add_head(&forw_nexthop_entry->list,
		       &forw_if_entry->mcast_nexthop_list);
	return;
free:
	hlist_del(&forw_if_entry->list);
	kfree(forw_if_entry);
}

/**
 * batadv_mcast_forw_table_entry_prep - Adds a multicast/originator entry
 * @forw_table:	The list the new entry will be added to
 * @mcast_addr: The multicast address of the new multicast entry
 * @orig:
 *
 * This method adds the multicast and originator address into the given
 * forw_table, using a format suitable for fast merging into our multicast
 * routing table.
 *
 * More specifically it prepares a multicast originator entry with the given
 * originator address. Then this entry plus the given multicast address will be
 * used to generate a multicast entry which will finally be added to the
 * specified multicast routing table.
 *
 * Will leave forw_table unmodified in case of out-of-memory errors.
 */
struct hlist_head *batadv_mcast_forw_table_entry_prep(
				struct hlist_head *forw_table,
				uint8_t *mcast_addr, uint8_t *orig)
{
	struct batadv_mcast_forw_table_entry *forw_table_entry;
	struct batadv_mcast_forw_orig_entry *orig_entry;

	forw_table_entry = kmalloc(
				sizeof(struct batadv_mcast_forw_table_entry),
				GFP_ATOMIC);
	if (!forw_table_entry)
		return NULL;

	memcpy(forw_table_entry->mcast_addr, mcast_addr, ETH_ALEN);
	/* Don't do any duplicate checks here: A sane tracker packet will
	 * not have any - and the syncing will be able to handle such rare,
	 * broken packets */
	hlist_add_head(&forw_table_entry->list, forw_table);

	INIT_HLIST_HEAD(&forw_table_entry->mcast_orig_list);
	orig_entry = kmalloc(sizeof(struct batadv_mcast_forw_orig_entry),
			     GFP_ATOMIC);
	if (!orig_entry)
		goto free;

	memcpy(orig_entry->orig, orig, ETH_ALEN);
	INIT_HLIST_HEAD(&orig_entry->mcast_if_list);
	hlist_add_head(&orig_entry->list, &forw_table_entry->mcast_orig_list);

	return &orig_entry->mcast_if_list;

free:
	hlist_del(&forw_table_entry->list);
	kfree(forw_table_entry);
	return NULL;
}

/**
 * batadv_mcast_sync_nexthop - Adds a multicast next-hop entry into a list
 * @sync_if_entry:	The multicast nexthop entry we want to merge
 * @if_list:		The multicast nexthop list we want to merge into
 *
 * This method merges a specific multicast nexthop entry (sync_nexthop_entry),
 * that is an entry of a specific multicast address, originator, interface
 * and next-hop, into the provided multicast interface
 * list (if_list).
 *
 * If such a four tuple already exists in the provided nexthop list, then
 * the timeout of that one will just get reset.
 *
 * This method consumes the provided sync_nexthop_entry.
 */
static int batadv_mcast_sync_nexthop(
		struct batadv_mcast_forw_nexthop_entry *sync_nexthop_entry,
		struct hlist_head *nexthop_list)
{
	struct batadv_mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node;
	int synced = 0;

	hlist_for_each_entry(nexthop_entry, node, nexthop_list, list) {
		if (memcmp(sync_nexthop_entry->neigh_addr,
			   nexthop_entry->neigh_addr, ETH_ALEN))
			continue;

		nexthop_entry->timeout = jiffies;
		hlist_del(&sync_nexthop_entry->list);
		kfree(sync_nexthop_entry);

		synced = 1;
		break;
	}

	if (!synced) {
		hlist_add_head(&sync_nexthop_entry->list, nexthop_list);
		return 1;
	}

	return 0;
}

/**
 * batadv_mcast_sync_if - Adds a multicast interface entry into a list
 * @sync_if_entry:	The multicast interface entry we want to merge
 * @if_list:		The multicast interface list we want to merge into
 *
 * This method merges a specific multicast interface entry (sync_if_entry),
 * that is an entry of a specific multicast address, originator and interface
 * with its list of next-hops, into the provided multicast interface
 * list (if_list).
 *
 * This method consumes the provided sync_if_entry.
 */
static void batadv_mcast_sync_if(
			struct batadv_mcast_forw_if_entry *sync_if_entry,
			struct hlist_head *if_list)
{
	struct batadv_mcast_forw_if_entry *if_entry;
	struct batadv_mcast_forw_nexthop_entry *sync_nexthop_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(if_entry, node, if_list, list) {
		if (sync_if_entry->if_num != if_entry->if_num)
			continue;

		hlist_for_each_entry_safe(sync_nexthop_entry, node2, node_tmp,
					  &sync_if_entry->mcast_nexthop_list,
					  list)
			if (batadv_mcast_sync_nexthop(
						sync_nexthop_entry,
						&if_entry->mcast_nexthop_list))
				if_entry->num_nexthops++;

		hlist_del(&sync_if_entry->list);
		kfree(sync_if_entry);

		synced = 1;
		break;
	}

	if (!synced)
		hlist_add_head(&sync_if_entry->list, if_list);
}

/**
 * batadv_mcast_sync_orig - Adds a multicast originator entry into a list
 * @sync_orig_entry:	The multicast originator entry we want to merge
 * @orig_list:		The multicast originator list we want to merge into
 *
 * This method merges a specific multicast originator entry (sync_orig_entry),
 * that is an entry of a specific multicast address and originator with its
 * tuple of interfaces and next-hops, into the provided multicast originator
 * list (orig_list).
 *
 * This method consumes the provided sync_orig_entry.
 */
static void batadv_mcast_sync_orig(
			struct batadv_mcast_forw_orig_entry *sync_orig_entry,
			struct hlist_head *orig_list)
{
	struct batadv_mcast_forw_orig_entry *orig_entry;
	struct batadv_mcast_forw_if_entry *sync_if_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(orig_entry, node, orig_list, list) {
		if (memcmp(sync_orig_entry->orig,
			   orig_entry->orig, ETH_ALEN))
			continue;

		hlist_for_each_entry_safe(sync_if_entry, node2, node_tmp,
					  &sync_orig_entry->mcast_if_list,
					  list)
			batadv_mcast_sync_if(sync_if_entry,
					     &orig_entry->mcast_if_list);

		hlist_del(&sync_orig_entry->list);
		kfree(sync_orig_entry);

		synced = 1;
		break;
	}

	if (!synced)
		hlist_add_head(&sync_orig_entry->list, orig_list);
}

/**
 * batadv_mcast_sync_table - Adds a multicast table entry into a table
 * @sync_table_entry:	The multicast routing table we want to merge
 * @forw_table:		The multicast routing table we want to merge into
 *
 * This method merges a specific multicast table entry (sync_table_entry),
 * that is an entry of a specific multicast address with its tuple of
 * originators, interfaces and next-hops, into the provided
 * multicast routing table (forw_table).
 *
 * This method consumes the provided sync_table_entry.
 */
static void batadv_mcast_sync_table(
		struct batadv_mcast_forw_table_entry *sync_table_entry,
		struct hlist_head *forw_table)
{
	struct batadv_mcast_forw_table_entry *table_entry;
	struct batadv_mcast_forw_orig_entry *sync_orig_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(table_entry, node, forw_table, list) {
		if (memcmp(sync_table_entry->mcast_addr,
			   table_entry->mcast_addr, ETH_ALEN))
			continue;

		hlist_for_each_entry_safe(sync_orig_entry, node2, node_tmp,
					  &sync_table_entry->mcast_orig_list,
					  list)
			batadv_mcast_sync_orig(sync_orig_entry,
					       &table_entry->mcast_orig_list);

		hlist_del(&sync_table_entry->list);
		kfree(sync_table_entry);

		synced = 1;
		break;
	}

	if (!synced)
		hlist_add_head(&sync_table_entry->list, forw_table);
}

/**
 * batadv_mcast_forw_table_update - Updates the multicast routing table
 * @forw_table:	A new multicast routing table we want to merge
 * @bat_priv:	The bat_priv holding the table we want to merge into
 *
 * This method merges a new multicast routing table - usually a partial
 * one generated/received from a single tracker packet - provided by forw_table
 * into our main multicast routing table stored in bat_priv.
 *
 * This method consumes the provided forw_table.
 */
void batadv_mcast_forw_table_update(struct hlist_head *forw_table,
				    struct batadv_priv *bat_priv)
{
	struct batadv_mcast_forw_table_entry *sync_table_entry;
	struct hlist_node *node, *node_tmp;

	spin_lock_bh(&bat_priv->mcast.forw_table_lock);
	hlist_for_each_entry_safe(sync_table_entry, node, node_tmp, forw_table,
				  list)
		batadv_mcast_sync_table(sync_table_entry,
					&bat_priv->mcast.forw_table);
	spin_unlock_bh(&bat_priv->mcast.forw_table_lock);
}

/**
 * batadv_mcast_nexthop_list_purge - Purges timeouted nexthop entries
 * @bat_priv:		bat_priv of our mesh network
 * @mcast_nexthop_list:	The next-hop list for a specific interface
 *
 * For a next-hop list of a specific multicast address, originator and
 * (batman hard) interface:
 *
 * This method purges multicast routing table entries which have
 * expired, that is entries which have not been updated with a new,
 * matching tracker packet during the configured mcast_forw_timeout.
 *
 * It also updates the nexthop entry counter in the given nexthop list.
 */
static void batadv_mcast_nexthop_list_purge(
					struct hlist_head *mcast_nexthop_list,
					int *num_nexthops,
					struct batadv_priv *bat_priv)
{
	struct batadv_mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(nexthop_entry, node, node_tmp,
				  mcast_nexthop_list, list) {
		if (batadv_mcast_get_remaining_timeout(nexthop_entry,
						       bat_priv))
			continue;

		hlist_del_rcu(&nexthop_entry->list);
		kfree_rcu(nexthop_entry, rcu);
		*num_nexthops = *num_nexthops - 1;
	}
}

/**
 * batadv_mcast_if_list_purge - Purges timeouted mcast routing table entries
 * @bat_priv:		bat_priv of our mesh network
 * @mcast_orig_list:	The interface list of a specific originator
 *
 * For an interface list of a specific multicast address and originator:
 *
 * This method purges multicast routing table entries which have
 * expired, that is entries which have not been updated with a new,
 * matching tracker packet during the configured mcast_forw_timeout,
 */
static void batadv_mcast_if_list_purge(struct hlist_head *mcast_if_list,
				       struct batadv_priv *bat_priv)
{
	struct batadv_mcast_forw_if_entry *if_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(if_entry, node, node_tmp, mcast_if_list,
				  list) {
		batadv_mcast_nexthop_list_purge(&if_entry->mcast_nexthop_list,
						&if_entry->num_nexthops,
						bat_priv);

		if (!hlist_empty(&if_entry->mcast_nexthop_list))
				continue;

		hlist_del_rcu(&if_entry->list);
		kfree_rcu(if_entry, rcu);
	}
}

/**
 * batadv_mcast_orig_list_purge - Purges timeouted mcast routing table entries
 * @bat_priv:		bat_priv of our mesh network
 * @mcast_orig_list:	The originator list for a specific multicast address
 *
 * For an originator list of a specific multicast address:
 *
 * This method purges multicast routing table entries which have
 * expired, that is entries which have not been updated with a new,
 * matching tracker packet during the configured mcast_forw_timeout.
 */
static void batadv_mcast_orig_list_purge(struct hlist_head *mcast_orig_list,
					 struct batadv_priv *bat_priv)
{
	struct batadv_mcast_forw_orig_entry *orig_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(orig_entry, node, node_tmp, mcast_orig_list,
				  list) {
		batadv_mcast_if_list_purge(&orig_entry->mcast_if_list,
					   bat_priv);

		if (!hlist_empty(&orig_entry->mcast_if_list))
			continue;

		hlist_del_rcu(&orig_entry->list);
		kfree_rcu(orig_entry, rcu);
	}
}

/**
 * batadv_mcast_forw_table_purge - Purges timeouted mcast routing table entries
 * @bat_priv:	bat_priv of our mesh network
 *
 * This method purges multicast routing table entries which have
 * expired, that is entries which have not been updated with a new,
 * matching tracker packet during the configured mcast_forw_timeout.
 */
void batadv_mcast_forw_table_purge(struct batadv_priv *bat_priv)
{
	struct batadv_mcast_forw_table_entry *table_entry;
	struct hlist_node *node, *node_tmp;

	spin_lock_bh(&bat_priv->mcast.forw_table_lock);
	hlist_for_each_entry_safe(table_entry, node, node_tmp,
				  &bat_priv->mcast.forw_table, list) {
		batadv_mcast_orig_list_purge(&table_entry->mcast_orig_list,
					     bat_priv);

		if (!hlist_empty(&table_entry->mcast_orig_list))
			continue;

		hlist_del_rcu(&table_entry->list);
		kfree_rcu(table_entry, rcu);
	}
	spin_unlock_bh(&bat_priv->mcast.forw_table_lock);
}

/**
 * batadv_mcast_if_num_to_hard_if - Converts an interface number to a hard-if
 * @if_num:	Index of an interface
 *
 * This function converts an interface index to a batman hard interface
 * pointer.
 *
 * Might return NULL if no interface is present for the specified number.
 *
 * Caller needs to aquire an RCU read lock first.
 */
static inline struct batadv_hard_iface *batadv_mcast_if_num_to_hard_if(
								int16_t if_num)
{
	struct batadv_hard_iface *hard_iface;

	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list)
		if (hard_iface->if_num == if_num)
			return hard_iface;

	return NULL;
}

static void batadv_mcast_seq_print_if_entry(
				struct batadv_mcast_forw_if_entry *if_entry,
				struct batadv_priv *bat_priv,
				struct seq_file *seq)
{
	struct batadv_mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node;
	struct batadv_hard_iface *hard_iface;

	hard_iface = batadv_mcast_if_num_to_hard_if(if_entry->if_num);
	if (!hard_iface)
		return;

	seq_printf(seq, "\t\t%s\n", hard_iface->net_dev->name);

	hlist_for_each_entry_rcu(nexthop_entry, node,
				 &if_entry->mcast_nexthop_list, list)
		seq_printf(seq, "\t\t\t%pM - %li\n", nexthop_entry->neigh_addr,
			   batadv_mcast_get_remaining_timeout(nexthop_entry,
							      bat_priv));
}

static void batadv_mcast_seq_print_orig_entry(
			struct batadv_mcast_forw_orig_entry *orig_entry,
			struct batadv_priv *bat_priv,
			struct seq_file *seq)
{
	struct batadv_mcast_forw_if_entry *if_entry;
	struct hlist_node *node;

	seq_printf(seq, "\t%pM\n", orig_entry->orig);
	hlist_for_each_entry_rcu(if_entry, node, &orig_entry->mcast_if_list,
				 list)
		batadv_mcast_seq_print_if_entry(if_entry, bat_priv, seq);
}

static void batadv_mcast_seq_print_table_entry(
			struct batadv_mcast_forw_table_entry *table_entry,
			struct batadv_priv *bat_priv,
			struct seq_file *seq)
{
	struct batadv_mcast_forw_orig_entry *orig_entry;
	struct hlist_node *node;

	seq_printf(seq, "%pM\n", table_entry->mcast_addr);
	hlist_for_each_entry_rcu(orig_entry, node,
				 &table_entry->mcast_orig_list, list)
		batadv_mcast_seq_print_orig_entry(orig_entry, bat_priv, seq);
}

int batadv_mcast_forw_table_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct batadv_priv *bat_priv = netdev_priv(net_dev);
	struct batadv_mcast_forw_table_entry *table_entry;
	struct hlist_node *node;

	seq_printf(seq, "Multicast forwarding table (from %s):\n",
		   net_dev->name);
	seq_printf(seq,
		   "Multicast group MAC\tOriginator\tOutgoing interface\tNexthop - timeout in msecs\n");

	rcu_read_lock();
	hlist_for_each_entry_rcu(table_entry, node,
				 &bat_priv->mcast.forw_table, list)
		batadv_mcast_seq_print_table_entry(table_entry, bat_priv, seq);
	rcu_read_unlock();

	return 0;
}
