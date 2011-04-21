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
#include "multicast_flow.h"
#include "send.h"
#include "soft-interface.h"
#include "hard-interface.h"
#include "originator.h"

/* If auto mode for tracker timeout has been selected,
 * how many times of tracker_interval to wait */
#define TRACKER_TIMEOUT_AUTO_X 5
#define TRACKER_BURST_EXTRA 2

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 37)
#define for_each_pmc_rcu(in_dev, pmc)				\
	for (pmc = rcu_dereference(in_dev->mc_list);		\
	     pmc != NULL;					\
	     pmc = rcu_dereference(pmc->next_rcu))
#endif

struct tracker_packet_state {
	int mcast_num, dest_num;
	struct mcast_entry *mcast_entry;
	uint8_t *dest_entry;
	int break_flag;
};

static void init_state_mcast_entry(struct tracker_packet_state *state,
				   struct mcast_tracker_packet *tracker_packet)
{
	state->mcast_num = 0;
	state->mcast_entry = (struct mcast_entry *)(tracker_packet + 1);
	state->dest_entry = (uint8_t *)(state->mcast_entry + 1);
	state->break_flag = 0;
}

static int check_state_mcast_entry(struct tracker_packet_state *state,
				   struct mcast_tracker_packet *tracker_packet)
{
	if (state->mcast_num < tracker_packet->num_mcast_entries &&
	    !state->break_flag)
		return 1;

	return 0;
}

static void inc_state_mcast_entry(struct tracker_packet_state *state)
{
	if (state->break_flag)
		return;

	state->mcast_num++;
	state->mcast_entry = (struct mcast_entry *)state->dest_entry;
	state->dest_entry = (uint8_t *)(state->mcast_entry + 1);
}

static void init_state_dest_entry(struct tracker_packet_state *state)
{
	state->dest_num = 0;
	state->break_flag = 1;
}

static int check_state_dest_entry(struct tracker_packet_state *state)
{
	if (state->dest_num < state->mcast_entry->num_dest)
		return 1;

	state->break_flag = 0;
	return 0;
}

static void inc_state_dest_entry(struct tracker_packet_state *state)
{
	state->dest_num++;
	state->dest_entry += ETH_ALEN;
}

#define tracker_packet_for_each_dest(state, tracker_packet)		 \
	for (init_state_mcast_entry(state, tracker_packet);		 \
	     check_state_mcast_entry(state, tracker_packet);		 \
	     inc_state_mcast_entry(state))				 \
		for (init_state_dest_entry(state);			 \
		     check_state_dest_entry(state);			 \
		     inc_state_dest_entry(state))

struct dest_entries_list {
	struct list_head list;
	uint8_t dest[6];
	struct hard_iface *hard_iface;
};

struct mcast_entries_list {
	struct list_head list;
	uint8_t mcast_addr[6];
	struct list_head dest_entries;
};

struct mcast_forw_nexthop_entry {
	struct hlist_node list;
	uint8_t neigh_addr[6];
	unsigned long timeout;	/* old jiffies value */
	struct rcu_head rcu;
};

struct mcast_forw_if_entry {
	struct hlist_node list;
	int16_t if_num;
	int num_nexthops;
	struct hlist_head mcast_nexthop_list;
	struct rcu_head rcu;
};

struct mcast_forw_orig_entry {
	struct hlist_node list;
	uint8_t orig[6];
	uint32_t last_mcast_seqno;
	unsigned long mcast_bits[NUM_WORDS];
	struct hlist_head mcast_if_list;
	struct rcu_head rcu;
};

struct mcast_forw_table_entry {
	struct hlist_node list;
	uint8_t mcast_addr[6];
	struct hlist_head mcast_orig_list;
	struct rcu_head rcu;
};

/* how long to wait until sending a multicast tracker packet */
static int tracker_send_delay(struct bat_priv *bat_priv)
{
	int tracker_interval = atomic_read(&bat_priv->mcast_tracker_interval);

	/* auto mode, set to 1/2 ogm interval */
	if (!tracker_interval)
		tracker_interval = atomic_read(&bat_priv->orig_interval) / 2;

	/* multicast tracker packets get half as much jitter as ogms as they're
	 * limited down to JITTER and not JITTER*2 */
	return msecs_to_jiffies(tracker_interval -
		   JITTER/2 + (random32() % JITTER));
}

static void mcast_tracker_start(struct bat_priv *bat_priv)
{
	/* adding some jitter */
	unsigned long tracker_interval = tracker_send_delay(bat_priv);
	queue_delayed_work(bat_event_workqueue, &bat_priv->mcast_tracker_work,
			   tracker_interval);
}

static void mcast_tracker_stop(struct bat_priv *bat_priv)
{
	cancel_delayed_work_sync(&bat_priv->mcast_tracker_work);
}

void mcast_tracker_reset(struct bat_priv *bat_priv)
{
	mcast_tracker_stop(bat_priv);
	mcast_tracker_start(bat_priv);
}

static inline long get_remaining_timeout(
				struct mcast_forw_nexthop_entry *nexthop_entry,
				struct bat_priv *bat_priv)
{
	long tracker_timeout = atomic_read(&bat_priv->mcast_tracker_timeout);
	if (!tracker_timeout)
		tracker_timeout = atomic_read(&bat_priv->mcast_tracker_interval)
				  * TRACKER_TIMEOUT_AUTO_X;
	if (!tracker_timeout)
		tracker_timeout = atomic_read(&bat_priv->orig_interval)
				  * TRACKER_TIMEOUT_AUTO_X / 2;

	tracker_timeout = jiffies_to_msecs(nexthop_entry->timeout) -
			jiffies_to_msecs(jiffies) + tracker_timeout;

	return (tracker_timeout > 0 ? tracker_timeout : 0);
}

static void prepare_forw_if_entry(struct hlist_head *forw_if_list,
				  int16_t if_num, uint8_t *neigh_addr)
{
	struct mcast_forw_if_entry *forw_if_entry;
	struct mcast_forw_nexthop_entry *forw_nexthop_entry;
	struct hlist_node *node;

	hlist_for_each_entry(forw_if_entry, node, forw_if_list, list)
		if (forw_if_entry->if_num == if_num)
			goto skip_create_if;

	forw_if_entry = kmalloc(sizeof(struct mcast_forw_if_entry),
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

	forw_nexthop_entry = kmalloc(sizeof(struct mcast_forw_nexthop_entry),
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

static struct hlist_head *prepare_forw_table_entry(
				struct hlist_head *forw_table,
				uint8_t *mcast_addr, uint8_t *orig)
{
	struct mcast_forw_table_entry *forw_table_entry;
	struct mcast_forw_orig_entry *orig_entry;

	forw_table_entry = kmalloc(sizeof(struct mcast_forw_table_entry),
				   GFP_ATOMIC);
	if (!forw_table_entry)
		return NULL;

	memcpy(forw_table_entry->mcast_addr, mcast_addr, ETH_ALEN);
	hlist_add_head(&forw_table_entry->list, forw_table);

	INIT_HLIST_HEAD(&forw_table_entry->mcast_orig_list);
	orig_entry = kmalloc(sizeof(struct mcast_forw_orig_entry), GFP_ATOMIC);
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

static int sync_nexthop(struct mcast_forw_nexthop_entry *sync_nexthop_entry,
			 struct hlist_head *nexthop_list)
{
	struct mcast_forw_nexthop_entry *nexthop_entry;
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

static void sync_if(struct mcast_forw_if_entry *sync_if_entry,
		    struct hlist_head *if_list)
{
	struct mcast_forw_if_entry *if_entry;
	struct mcast_forw_nexthop_entry *sync_nexthop_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(if_entry, node, if_list, list) {
		if (sync_if_entry->if_num != if_entry->if_num)
			continue;

		hlist_for_each_entry_safe(sync_nexthop_entry, node2, node_tmp,
				&sync_if_entry->mcast_nexthop_list, list)
			if (sync_nexthop(sync_nexthop_entry,
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

static void sync_orig(struct mcast_forw_orig_entry *sync_orig_entry,
		      struct hlist_head *orig_list)
{
	struct mcast_forw_orig_entry *orig_entry;
	struct mcast_forw_if_entry *sync_if_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(orig_entry, node, orig_list, list) {
		if (memcmp(sync_orig_entry->orig,
			    orig_entry->orig, ETH_ALEN))
			continue;

		hlist_for_each_entry_safe(sync_if_entry, node2, node_tmp,
				&sync_orig_entry->mcast_if_list, list)
			sync_if(sync_if_entry, &orig_entry->mcast_if_list);

		hlist_del(&sync_orig_entry->list);
		kfree(sync_orig_entry);

		synced = 1;
		break;
	}

	if (!synced)
		hlist_add_head(&sync_orig_entry->list, orig_list);
}


/* syncs all multicast entries of sync_table_entry to forw_table */
static void sync_table(struct mcast_forw_table_entry *sync_table_entry,
		       struct hlist_head *forw_table)
{
	struct mcast_forw_table_entry *table_entry;
	struct mcast_forw_orig_entry *sync_orig_entry;
	struct hlist_node *node, *node2, *node_tmp;
	int synced = 0;

	hlist_for_each_entry(table_entry, node, forw_table, list) {
		if (memcmp(sync_table_entry->mcast_addr,
			   table_entry->mcast_addr, ETH_ALEN))
			continue;

		hlist_for_each_entry_safe(sync_orig_entry, node2, node_tmp,
				&sync_table_entry->mcast_orig_list, list)
			sync_orig(sync_orig_entry,
				  &table_entry->mcast_orig_list);

		hlist_del(&sync_table_entry->list);
		kfree(sync_table_entry);

		synced = 1;
		break;
	}

	if (!synced)
		hlist_add_head(&sync_table_entry->list, forw_table);
}

/* Updates the old multicast forwarding table with the information gained
 * from the generated/received tracker packet. It also frees the generated
 * table for syncing (*forw_table). */
static void update_mcast_forw_table(struct hlist_head *forw_table,
				    struct bat_priv *bat_priv)
{
	struct mcast_forw_table_entry *sync_table_entry;
	struct hlist_node *node, *node_tmp;

	spin_lock_bh(&bat_priv->mcast_forw_table_lock);
	hlist_for_each_entry_safe(sync_table_entry, node, node_tmp, forw_table,
				  list)
		sync_table(sync_table_entry, &bat_priv->mcast_forw_table);
	spin_unlock_bh(&bat_priv->mcast_forw_table_lock);
}

/**
 * Searches if a certain multicast address of another originator is also
 * one of ours.
 *
 * Returns -1 if no match could be found. Otherwise returns the number of
 * the element in our mc_addr_list which matches.
 *
 * Caller needs to hold orig_node->mca_lock outside.
 *
 * @orig_node:		the originator we are refering to
 * @mca_pos:		refers to the specific multicast address in orig_node's
 *			mca buffer which we are trying to find a match for
 * @mc_addr_list:	a list of our own multicast addresses
 * @num_mcast_entries:	the number of our own multicast addresses
 */
static inline int find_mca_match(struct orig_node *orig_node,
		int mca_pos, uint8_t *mc_addr_list, int num_mcast_entries)
{
	int pos;

	for (pos = 0; pos < num_mcast_entries; pos++)
		if (!memcmp(&mc_addr_list[pos*ETH_ALEN],
			    &orig_node->mca_buff[ETH_ALEN*mca_pos], ETH_ALEN))
			return pos;
	return -1;
}

static struct sk_buff *build_tracker_packet_skb(int tracker_packet_len,
						struct bat_priv *bat_priv)
{
	struct sk_buff *skb;
	struct mcast_tracker_packet *tracker_packet;

	skb = dev_alloc_skb(tracker_packet_len + sizeof(struct ethhdr));
	if (!skb)
		return NULL;

	skb_reserve(skb, sizeof(struct ethhdr));
	tracker_packet = (struct mcast_tracker_packet *)
			 skb_put(skb, tracker_packet_len);

	tracker_packet->packet_type = BAT_MCAST_TRACKER;
	tracker_packet->version = COMPAT_VERSION;
	memcpy(tracker_packet->orig, bat_priv->primary_if->net_dev->dev_addr,
		ETH_ALEN);
	tracker_packet->ttl = TTL;
	tracker_packet->num_mcast_entries = 0;
	memset(tracker_packet->align, 0, sizeof(tracker_packet->align));

	return skb;
}

static void mcast_tracker_dests_free(struct list_head *dest_entries)
{
	struct dest_entries_list *dest_entry, *tmp;

	list_for_each_entry_safe(dest_entry, tmp, dest_entries, list) {
		list_del(&dest_entry->list);
		kfree(dest_entry);
	}
}

static int mcast_tracker_collect_dests(struct bat_priv *bat_priv,
				       struct mcast_entries_list *mcast_entry)
{
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct orig_node *orig_node;
	struct hlist_node *walk;
	struct hlist_head *head;
	struct dest_entries_list *dest_entry;
	int i, j, num_dests = 0;

	if (!hash)
		goto out;

	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(orig_node, walk, head, hash_entry) {
			if (!atomic_inc_not_zero(&orig_node->refcount))
				continue;

			spin_lock_bh(&orig_node->mca_lock);
			for (j = 0; j < orig_node->num_mca; j++) {
				if (memcmp(&orig_node->mca_buff[ETH_ALEN * j],
					   mcast_entry->mcast_addr, ETH_ALEN))
					continue;

				dest_entry = kmalloc(sizeof(
						struct dest_entries_list),
						GFP_ATOMIC);
				if (!dest_entry)
					goto free;

				memcpy(dest_entry->dest, orig_node->orig,
				       ETH_ALEN);
				list_add(&dest_entry->list,
					 &mcast_entry->dest_entries);
				num_dests++;
				break;
			}
			spin_unlock_bh(&orig_node->mca_lock);
			orig_node_free_ref(orig_node);
		}
		rcu_read_unlock();
	}

	goto out;

free:
	spin_unlock_bh(&orig_node->mca_lock);
	rcu_read_unlock();
	orig_node_free_ref(orig_node);

	mcast_tracker_dests_free(&mcast_entry->dest_entries);
	num_dests = 0;

out:
	return num_dests;
	return 0;
}

static void mcast_tracker_collect_free(struct list_head *mcast_dest_list)
{
	struct mcast_entries_list *mcast_entry, *tmp;

	list_for_each_entry_safe(mcast_entry, tmp, mcast_dest_list, list) {
		mcast_tracker_dests_free(&mcast_entry->dest_entries);
		list_del(&mcast_entry->list);
		kfree(mcast_entry);
	}
}

static int mcast_addr_add_collect_mcast(uint8_t *mcast_addr,
					struct list_head *mcast_dest_list)
{
	struct mcast_entries_list *mcast_entry;

	mcast_entry = kmalloc(sizeof(struct mcast_entries_list),
			      GFP_ATOMIC);
	if (!mcast_entry)
		return -1;

	memcpy(mcast_entry->mcast_addr, mcast_addr, ETH_ALEN);
	INIT_LIST_HEAD(&mcast_entry->dest_entries);
	list_add(&mcast_entry->list, mcast_dest_list);

	return 0;
}

static void mcast_tracker_collect_mcasts(struct bat_priv *bat_priv,
					 struct list_head *mcast_dest_list)
{
	struct mcast_flow_entry *flow_entry;
	struct hlist_node *node;
	int threshold_state;

	rcu_read_lock();
	hlist_for_each_entry_rcu(flow_entry, node,
				 &bat_priv->mcast_flow_table, list) {
		if (!atomic_inc_not_zero(&flow_entry->refcount))
			continue;

		threshold_state = update_flow_entry(flow_entry, bat_priv, 0);
		if (!threshold_state) {
			flow_entry_free_ref(flow_entry);
			continue;
		}

		if (mcast_addr_add_collect_mcast(flow_entry->mcast_addr,
						 mcast_dest_list) < 0)
			goto free;

		flow_entry_free_ref(flow_entry);
	}
	rcu_read_unlock();
	return;

free:
	/* Out-of-memory, free all */
	flow_entry_free_ref(flow_entry);
	mcast_tracker_collect_free(mcast_dest_list);
}

static int mcast_tracker_collect(struct bat_priv *bat_priv,
				 struct list_head *mcast_dest_list)
{
	struct mcast_entries_list *mcast_entry, *tmp;
	struct dest_entries_list *dest_entry;
	int tracker_packet_len = sizeof(struct mcast_tracker_packet);
	int used_mcast_entries = 0, reduced = 0;

	list_for_each_entry_safe(mcast_entry, tmp, mcast_dest_list, list) {
		tracker_packet_len += sizeof(struct mcast_entry);
		if (used_mcast_entries == UINT8_MAX ||
		    tracker_packet_len + ETH_ALEN > ETH_DATA_LEN) {
			reduced = 1;
			goto del;
		}

		tracker_packet_len += ETH_ALEN *
			mcast_tracker_collect_dests(bat_priv, mcast_entry);

		if (list_empty(&mcast_entry->dest_entries)) {
del:
			tracker_packet_len -= sizeof(struct mcast_entry);
			list_del(&mcast_entry->list);
			kfree(mcast_entry);
			continue;
		}

		while (tracker_packet_len > ETH_DATA_LEN) {
			/* list won't get empty here due to the
			 * previous checks */
			reduced = 1;
			dest_entry = list_first_entry(
					       &mcast_entry->dest_entries,
					       struct dest_entries_list, list);
			list_del(&dest_entry->list);
			kfree(dest_entry);
			tracker_packet_len -= ETH_ALEN;
		}

		used_mcast_entries++;
	}

	if (!used_mcast_entries)
		tracker_packet_len = 0;
	else if (reduced)
		pr_warning("mcast tracker packet got too large, "
			   "forcing reduced size of %i Bytes\n",
			   tracker_packet_len);

	return tracker_packet_len;
}

void mcast_tracker_skb_attach(struct sk_buff *skb,
			      struct list_head *mcast_dest_list)
{
	struct mcast_tracker_packet *tracker_packet;
	struct mcast_entry *mcast_entry;
	struct mcast_entries_list *mcast;
	struct dest_entries_list *dest;
	uint8_t *dest_entry;

	tracker_packet = (struct mcast_tracker_packet *)skb->data;
	mcast_entry = (struct mcast_entry *)(tracker_packet + 1);

	list_for_each_entry(mcast, mcast_dest_list, list) {
		tracker_packet->num_mcast_entries++;
		mcast_entry->num_dest = 0;
		mcast_entry->align = 0;
		memcpy(mcast_entry->mcast_addr, mcast->mcast_addr, ETH_ALEN);
		dest_entry = (uint8_t *)(mcast_entry + 1);

		list_for_each_entry(dest, &mcast->dest_entries, list) {
			mcast_entry->num_dest++;
			memcpy(dest_entry, dest->dest, ETH_ALEN);

			dest_entry += ETH_ALEN;
		}
		mcast_entry = (struct mcast_entry *)dest_entry;
	}
}

/**
 * Prepares a multicast tracker packet on a multicast member with all its
 * groups and their members attached. Note, that the proactive tracking
 * mode does not differentiate between multicast senders and receivers,
 * resulting in tracker packets between each node.
 *
 * Returns NULL if this node is not a member of any group or if there are
 * no other members in its groups.
 *
 * @bat_priv:		bat_priv for the mesh we are preparing this packet
 */
static struct sk_buff *mcast_tracker_prepare(struct bat_priv *bat_priv,
					     struct list_head *mcast_dest_list)
{
	struct sk_buff *skb = NULL;
	int tracker_packet_len;

	tracker_packet_len = mcast_tracker_collect(bat_priv, mcast_dest_list);
	if (!tracker_packet_len)
		goto out;

	/* prepare tracker packet */
	skb = build_tracker_packet_skb(tracker_packet_len, bat_priv);
	if (!skb)
		goto free;

	/* append all collected entries */
	mcast_tracker_skb_attach(skb, mcast_dest_list);

	/* outstanding cleanup */
free:
	mcast_tracker_collect_free(mcast_dest_list);
out:

	return skb;
}

static struct sk_buff *mcast_periodic_tracker_prepare(
						struct bat_priv *bat_priv)
{
	struct list_head mcast_dest_list;

	INIT_LIST_HEAD(&mcast_dest_list);
	mcast_tracker_collect_mcasts(bat_priv, &mcast_dest_list);

	return mcast_tracker_prepare(bat_priv, &mcast_dest_list);
}

static struct sk_buff *mcast_reactive_tracker_prepare(uint8_t *mcast_addr,
						     struct bat_priv *bat_priv)
{
	struct list_head mcast_dest_list;

	INIT_LIST_HEAD(&mcast_dest_list);
	mcast_addr_add_collect_mcast(mcast_addr, &mcast_dest_list);

	return mcast_tracker_prepare(bat_priv, &mcast_dest_list);
}

/* Adds the router for the destination address to the next_hop list and its
 * interface to the forw_if_list - but only if this router has not been
 * added yet */
static int add_router_of_dest(struct dest_entries_list *next_hops,
			      uint8_t *dest,
			      struct hlist_head *forw_if_list,
			      struct bat_priv *bat_priv)
{
	struct dest_entries_list *next_hop_tmp, *next_hop_entry;
	int16_t if_num;
	struct orig_node *orig_node = NULL;
	struct neigh_node *router = NULL;
	int ret = 1;


	next_hop_entry = kmalloc(sizeof(struct dest_entries_list), GFP_ATOMIC);
	if (!next_hop_entry)
		goto out;

	orig_node = orig_hash_find(bat_priv, dest);
	if (!orig_node)
		goto free;

	router = orig_node_get_router(orig_node);
	if (!router)
		goto free;

	rcu_read_lock();
	if (!router->if_incoming ||
	    !atomic_inc_not_zero(&router->if_incoming->refcount)) {
		rcu_read_unlock();
		goto free;
	}
	next_hop_entry->hard_iface = router->if_incoming;
	if_num = next_hop_entry->hard_iface->if_num;
	rcu_read_unlock();

	memcpy(next_hop_entry->dest, router->addr, ETH_ALEN);

	if (forw_if_list)
		prepare_forw_if_entry(forw_if_list, if_num,
				      next_hop_entry->dest);

	list_for_each_entry(next_hop_tmp, &next_hops->list, list)
		if (!memcmp(next_hop_tmp->dest, next_hop_entry->dest,
								ETH_ALEN))
			goto kref_free;

	list_add(&next_hop_entry->list, &next_hops->list);

	ret = 0;
	goto out;

kref_free:
	hardif_free_ref(next_hop_entry->hard_iface);
free:
	kfree(next_hop_entry);
	if (router)
		neigh_node_free_ref(router);
	if (orig_node)
		orig_node_free_ref(orig_node);
out:
	return ret;
}

/* Collect nexthops for all dest entries specified in this tracker packet.
 * It also reduces the number of elements in the tracker packet if they exceed
 * the buffers length (e.g. because of a received, broken tracker packet) to
 * avoid writing in unallocated memory. */
static int tracker_next_hops(struct mcast_tracker_packet *tracker_packet,
			     int tracker_packet_len,
			     struct dest_entries_list *next_hops,
			     struct hlist_head *forw_table,
			     struct bat_priv *bat_priv)
{
	int num_next_hops = 0, ret;
	struct tracker_packet_state state;
	uint8_t *tail = (uint8_t *)tracker_packet + tracker_packet_len;
	struct hlist_head *forw_table_if = NULL;

	INIT_LIST_HEAD(&next_hops->list);
	INIT_HLIST_HEAD(forw_table);

	tracker_packet_for_each_dest(&state, tracker_packet) {
		/* avoid writing outside of unallocated memory later */
		if (state.dest_entry + ETH_ALEN > tail) {
			bat_dbg(DBG_BATMAN, bat_priv,
				"mcast tracker packet is broken, too many "
				"entries claimed for its length, repairing");

			tracker_packet->num_mcast_entries = state.mcast_num;

			if (state.dest_num) {
				tracker_packet->num_mcast_entries++;
				state.mcast_entry->num_dest = state.dest_num;
			}

			break;
		}

		if (state.dest_num)
			goto skip;

		forw_table_if = prepare_forw_table_entry(forw_table,
						 state.mcast_entry->mcast_addr,
						 tracker_packet->orig);
skip:
		ret = add_router_of_dest(next_hops, state.dest_entry,
					 forw_table_if, bat_priv);
		if (!ret)
			num_next_hops++;
	}

	return num_next_hops;
}

/* Zero destination entries not destined for the specified next hop in the
 * tracker packet */
static void zero_tracker_packet(struct mcast_tracker_packet *tracker_packet,
				uint8_t *next_hop, struct bat_priv *bat_priv)
{
	struct tracker_packet_state state;
	struct orig_node *orig_node;
	struct neigh_node *router;

	tracker_packet_for_each_dest(&state, tracker_packet) {
		router = NULL;
		orig_node = orig_hash_find(bat_priv, state.dest_entry);
		/* we don't know this destination */
		if (!orig_node)
			goto erase;

		/* is the next hop already our destination? */
		if (!memcmp(orig_node->orig, next_hop, ETH_ALEN))
			goto erase;

		router = orig_node_get_router(orig_node);
		if (!router)
			goto erase;

		if (!memcmp(router->orig_node->primary_addr,
			    orig_node->orig, ETH_ALEN) ||
		    /* is this the wrong next hop for our
		     * destination? */
		    memcmp(router->addr, next_hop, ETH_ALEN))
			goto erase;

		goto free;
erase:
		memset(state.dest_entry, '\0', ETH_ALEN);
free:
		if (orig_node)
			orig_node_free_ref(orig_node);
		if (router)
			neigh_node_free_ref(router);
	}
}

/* Remove zeroed destination entries and empty multicast entries in tracker
 * packet */
static void shrink_tracker_packet(struct sk_buff *skb)
{
	struct mcast_tracker_packet *tracker_packet =
				(struct mcast_tracker_packet *)skb->data;
	struct tracker_packet_state state;
	unsigned char *tail = skb_tail_pointer(skb);
	int new_tracker_packet_len = sizeof(struct mcast_tracker_packet);

	tracker_packet_for_each_dest(&state, tracker_packet) {
		if (memcmp(state.dest_entry, "\0\0\0\0\0\0", ETH_ALEN)) {
			new_tracker_packet_len += ETH_ALEN;
			continue;
		}

		memmove(state.dest_entry, state.dest_entry + ETH_ALEN,
			tail - state.dest_entry - ETH_ALEN);

		state.mcast_entry->num_dest--;
		tail -= ETH_ALEN;

		if (state.mcast_entry->num_dest) {
			state.dest_num--;
			state.dest_entry -= ETH_ALEN;
			continue;
		}

		/* = mcast_entry */
		state.dest_entry -= sizeof(struct mcast_entry);

		memmove(state.dest_entry, state.dest_entry +
			sizeof(struct mcast_entry),
			tail - state.dest_entry - sizeof(struct mcast_entry));

		tracker_packet->num_mcast_entries--;
		tail -= sizeof(struct mcast_entry);

		state.mcast_num--;

		/* Avoid mcast_entry check of tracker_packet_for_each_dest's
		 * inner loop */
		state.break_flag = 0;
		break;
	}

	new_tracker_packet_len += sizeof(struct mcast_entry) *
				  tracker_packet->num_mcast_entries;

	skb_trim(skb, new_tracker_packet_len);
}

static int mcast_tracker_dec_ttl(struct mcast_tracker_packet *packet)
{
	if (packet->ttl - 1 <= 0)
		return 0;

	packet->ttl--;
	return 1;
}

/**
 * Sends (splitted parts of) a multicast tracker packet on the according
 * interfaces.
 *
 * @tracker_packet:	A compact multicast tracker packet with all groups and
 *			destinations attached.
 */
void route_mcast_tracker_packet(struct sk_buff *skb,
				struct bat_priv *bat_priv,
				int num_redundancy)
{
	struct dest_entries_list next_hops, *tmp;
	struct dest_entries_list *next_hop;
	struct hlist_head forw_table;
	struct sk_buff *skb_tmp, *skb_cloned;
	int i, num_next_hops;

	num_next_hops = tracker_next_hops((struct mcast_tracker_packet *)
					  skb->data, skb->len, &next_hops,
					  &forw_table, bat_priv);
	if (!num_next_hops)
		return;

	update_mcast_forw_table(&forw_table, bat_priv);

	if (!mcast_tracker_dec_ttl((struct mcast_tracker_packet *)skb->data))
		return;

	list_for_each_entry(next_hop, &next_hops.list, list) {
		skb_tmp = skb_copy(skb, GFP_ATOMIC);
		if (!skb_tmp)
			goto free;

		/* cut the tracker packets for the according destinations */
		zero_tracker_packet((struct mcast_tracker_packet *)
				skb_tmp->data, next_hop->dest, bat_priv);
		shrink_tracker_packet(skb_tmp);
		if (skb_tmp->len == sizeof(struct mcast_tracker_packet)) {
			dev_kfree_skb(skb_tmp);
			continue;
		}

		for (i = 0; i < num_redundancy; i++) {
			skb_cloned = skb_clone(skb_tmp, GFP_ATOMIC);
			if (!skb_cloned)
				break;

			send_skb_packet(skb_cloned, next_hop->hard_iface,
					next_hop->dest);
		}

		/* Send 'em! */
		send_skb_packet(skb_tmp, next_hop->hard_iface, next_hop->dest);
	}

free:
	list_for_each_entry_safe(next_hop, tmp, &next_hops.list, list) {
		hardif_free_ref(next_hop->hard_iface);
		list_del(&next_hop->list);
		kfree(next_hop);
	}
}

static void nexthop_entry_free(struct rcu_head *rcu)
{
	struct mcast_forw_nexthop_entry *nexthop_entry;

	nexthop_entry = container_of(rcu, struct mcast_forw_nexthop_entry,
				     rcu);
	kfree(nexthop_entry);
}

static void if_entry_free(struct rcu_head *rcu)
{
	struct mcast_forw_if_entry *if_entry;

	if_entry = container_of(rcu, struct mcast_forw_if_entry, rcu);
	kfree(if_entry);
}

static void orig_entry_free(struct rcu_head *rcu)
{
	struct mcast_forw_orig_entry *orig_entry;

	orig_entry = container_of(rcu, struct mcast_forw_orig_entry, rcu);
	kfree(orig_entry);
}

static void table_entry_free(struct rcu_head *rcu)
{
	struct mcast_forw_table_entry *table_entry;

	table_entry = container_of(rcu, struct mcast_forw_table_entry, rcu);
	kfree(table_entry);
}

static void purge_mcast_nexthop_list(struct hlist_head *mcast_nexthop_list,
				     int *num_nexthops,
				     struct bat_priv *bat_priv)
{
	struct mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(nexthop_entry, node, node_tmp,
				 mcast_nexthop_list, list) {
		if (get_remaining_timeout(nexthop_entry, bat_priv))
			continue;

		hlist_del_rcu(&nexthop_entry->list);
		call_rcu(&nexthop_entry->rcu, nexthop_entry_free);
		*num_nexthops = *num_nexthops - 1;
	}
}

static void purge_mcast_if_list(struct hlist_head *mcast_if_list,
				struct bat_priv *bat_priv)
{
	struct mcast_forw_if_entry *if_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(if_entry, node, node_tmp, mcast_if_list,
				  list) {
		purge_mcast_nexthop_list(&if_entry->mcast_nexthop_list,
					 &if_entry->num_nexthops,
					 bat_priv);

		if (!hlist_empty(&if_entry->mcast_nexthop_list))
				continue;

		hlist_del_rcu(&if_entry->list);
		call_rcu(&if_entry->rcu, if_entry_free);
	}
}

static void purge_mcast_orig_list(struct hlist_head *mcast_orig_list,
				  struct bat_priv *bat_priv)
{
	struct mcast_forw_orig_entry *orig_entry;
	struct hlist_node *node, *node_tmp;

	hlist_for_each_entry_safe(orig_entry, node, node_tmp, mcast_orig_list,
				  list) {
		purge_mcast_if_list(&orig_entry->mcast_if_list, bat_priv);

		if (!hlist_empty(&orig_entry->mcast_if_list))
			continue;

		hlist_del_rcu(&orig_entry->list);
		call_rcu(&orig_entry->rcu, orig_entry_free);
	}
}

void purge_mcast_forw_table(struct bat_priv *bat_priv)
{
	struct mcast_forw_table_entry *table_entry;
	struct hlist_node *node, *node_tmp;

	spin_lock_bh(&bat_priv->mcast_forw_table_lock);
	hlist_for_each_entry_safe(table_entry, node, node_tmp,
				  &bat_priv->mcast_forw_table, list) {
		purge_mcast_orig_list(&table_entry->mcast_orig_list, bat_priv);

		if (!hlist_empty(&table_entry->mcast_orig_list))
			continue;

		hlist_del_rcu(&table_entry->list);
		call_rcu(&table_entry->rcu, table_entry_free);
	}
	spin_unlock_bh(&bat_priv->mcast_forw_table_lock);
}

static void mcast_tracker_timer(struct work_struct *work)
{
	struct bat_priv *bat_priv = container_of(work, struct bat_priv,
						 mcast_tracker_work.work);
	struct sk_buff *tracker_packet = NULL;

	if (atomic_read(&bat_priv->mcast_group_awareness))
		tracker_packet = mcast_periodic_tracker_prepare(bat_priv);

	if (!tracker_packet)
		goto out;

	route_mcast_tracker_packet(tracker_packet, bat_priv, 0);
	dev_kfree_skb(tracker_packet);

out:
	mcast_tracker_start(bat_priv);
}

void mcast_tracker_burst(uint8_t *mcast_addr, struct bat_priv *bat_priv)
{
	struct sk_buff *tracker_packet;

	tracker_packet = mcast_reactive_tracker_prepare(mcast_addr, bat_priv);
	if (!tracker_packet)
		return;

	route_mcast_tracker_packet(tracker_packet, bat_priv,
				   TRACKER_BURST_EXTRA);
	dev_kfree_skb(tracker_packet);
}

int mcast_tracker_interval_set(struct net_device *net_dev, char *buff,
			       size_t count)
{
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	unsigned long new_tracker_interval;
	int cur_tracker_interval;
	int ret;

	ret = strict_strtoul(buff, 10, &new_tracker_interval);

	if (ret && !strncmp(buff, "auto", 4)) {
		new_tracker_interval = 0;
		goto ok;
	}

	else if (ret) {
		bat_info(net_dev, "Invalid parameter for "
			 "'mcast_tracker_interval' setting received: %s\n",
			 buff);
		return -EINVAL;
	}

	if (new_tracker_interval < JITTER) {
		bat_info(net_dev, "New mcast tracker interval too small: %li "
			 "(min: %i or auto)\n", new_tracker_interval, JITTER);
		return -EINVAL;
	}

ok:
	cur_tracker_interval = atomic_read(&bat_priv->mcast_tracker_interval);

	if (cur_tracker_interval == new_tracker_interval)
		return count;

	if (!cur_tracker_interval && new_tracker_interval)
		bat_info(net_dev, "Tracker interval change from: %s to: %li\n",
			 "auto", new_tracker_interval);
	else if (cur_tracker_interval && !new_tracker_interval)
		bat_info(net_dev, "Tracker interval change from: %i to: %s\n",
			 cur_tracker_interval, "auto");
	else
		bat_info(net_dev, "Tracker interval change from: %i to: %li\n",
			 cur_tracker_interval, new_tracker_interval);

	atomic_set(&bat_priv->mcast_tracker_interval, new_tracker_interval);

	mcast_tracker_reset(bat_priv);

	return count;
}

int mcast_tracker_timeout_set(struct net_device *net_dev, char *buff,
			       size_t count)
{
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	unsigned long new_tracker_timeout;
	int cur_tracker_timeout;
	int ret;

	ret = strict_strtoul(buff, 10, &new_tracker_timeout);

	if (ret && !strncmp(buff, "auto", 4)) {
		new_tracker_timeout = 0;
		goto ok;
	}

	else if (ret) {
		bat_info(net_dev, "Invalid parameter for "
			 "'mcast_tracker_timeout' setting received: %s\n",
			 buff);
		return -EINVAL;
	}

	if (new_tracker_timeout < JITTER) {
		bat_info(net_dev, "New mcast tracker timeout too small: %li "
			 "(min: %i or auto)\n", new_tracker_timeout, JITTER);
		return -EINVAL;
	}

ok:
	cur_tracker_timeout = atomic_read(&bat_priv->mcast_tracker_timeout);

	if (cur_tracker_timeout == new_tracker_timeout)
		return count;

	if (!cur_tracker_timeout && new_tracker_timeout)
		bat_info(net_dev, "Tracker timeout change from: %s to: %li\n",
			 "auto", new_tracker_timeout);
	else if (cur_tracker_timeout && !new_tracker_timeout)
		bat_info(net_dev, "Tracker timeout change from: %i to: %s\n",
			 cur_tracker_timeout, "auto");
	else
		bat_info(net_dev, "Tracker timeout change from: %i to: %li\n",
			 cur_tracker_timeout, new_tracker_timeout);

	atomic_set(&bat_priv->mcast_tracker_timeout, new_tracker_timeout);

	return count;
}

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
static inline struct hard_iface *if_num_to_hard_iface(int16_t if_num)
{
	struct hard_iface *hard_iface;

	list_for_each_entry_rcu(hard_iface, &hardif_list, list)
		if (hard_iface->if_num == if_num)
			return hard_iface;

	return NULL;
}

static void seq_print_if_entry(struct mcast_forw_if_entry *if_entry,
			       struct bat_priv *bat_priv, struct seq_file *seq)
{
	struct mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node;
	struct hard_iface *hard_iface;

	hard_iface = if_num_to_hard_iface(if_entry->if_num);
	if (!hard_iface)
		return;

	seq_printf(seq, "\t\t%s\n", hard_iface->net_dev->name);

	hlist_for_each_entry_rcu(nexthop_entry, node,
				 &if_entry->mcast_nexthop_list, list)
		seq_printf(seq, "\t\t\t%pM - %li\n", nexthop_entry->neigh_addr,
			   get_remaining_timeout(nexthop_entry, bat_priv));
}

static void seq_print_orig_entry(struct mcast_forw_orig_entry *orig_entry,
				 struct bat_priv *bat_priv,
				 struct seq_file *seq)
{
	struct mcast_forw_if_entry *if_entry;
	struct hlist_node *node;

	seq_printf(seq, "\t%pM\n", orig_entry->orig);
	hlist_for_each_entry_rcu(if_entry, node, &orig_entry->mcast_if_list,
				 list)
		seq_print_if_entry(if_entry, bat_priv, seq);
}

static void seq_print_table_entry(struct mcast_forw_table_entry *table_entry,
				  struct bat_priv *bat_priv,
				  struct seq_file *seq)
{
	struct mcast_forw_orig_entry *orig_entry;
	struct hlist_node *node;

	seq_printf(seq, "%pM\n", table_entry->mcast_addr);
	hlist_for_each_entry_rcu(orig_entry, node,
				 &table_entry->mcast_orig_list, list)
		seq_print_orig_entry(orig_entry, bat_priv, seq);
}

int mcast_forw_table_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct mcast_forw_table_entry *table_entry;
	struct hlist_node *node;

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);
	seq_printf(seq, "Multicast group MAC\tOriginator\t"
			"Outgoing interface\tNexthop - timeout in msecs\n");

	rcu_read_lock();
	hlist_for_each_entry_rcu(table_entry, node,
				 &bat_priv->mcast_forw_table, list)
		seq_print_table_entry(table_entry, bat_priv, seq);
	rcu_read_unlock();

	return 0;
}

static inline void nexthops_from_if_list(struct hlist_head *mcast_if_list,
					 struct list_head *nexthop_list,
					 struct bat_priv *bat_priv)
{
	struct hard_iface *hard_iface;
	struct mcast_forw_if_entry *if_entry;
	struct mcast_forw_nexthop_entry *nexthop_entry;
	struct hlist_node *node, *node2;
	struct dest_entries_list *dest_entry;
	int mcast_fanout = atomic_read(&bat_priv->mcast_fanout);

	hlist_for_each_entry_rcu(if_entry, node, mcast_if_list, list) {
		hard_iface = if_num_to_hard_iface(if_entry->if_num);
		if (!hard_iface || !atomic_inc_not_zero(&hard_iface->refcount))
			continue;

		/* send via broadcast */
		if (if_entry->num_nexthops > mcast_fanout) {
			dest_entry = kmalloc(sizeof(struct dest_entries_list),
					     GFP_ATOMIC);
			memcpy(dest_entry->dest, broadcast_addr, ETH_ALEN);
			dest_entry->hard_iface = hard_iface;
			list_add(&dest_entry->list, nexthop_list);
			continue;
		}

		/* send separate unicast packets */
		hlist_for_each_entry_rcu(nexthop_entry, node2,
					 &if_entry->mcast_nexthop_list, list) {
			if (!get_remaining_timeout(nexthop_entry, bat_priv))
				continue;

			dest_entry = kmalloc(sizeof(struct dest_entries_list),
					     GFP_ATOMIC);
			memcpy(dest_entry->dest, nexthop_entry->neigh_addr,
			       ETH_ALEN);

			if (!atomic_inc_not_zero(&hard_iface->refcount)) {
				kfree(dest_entry);
				continue;
			}

			dest_entry->hard_iface = hard_iface;
			list_add(&dest_entry->list, nexthop_list);
		}
		hardif_free_ref(hard_iface);
	}
}

static inline void nexthops_from_orig_list(uint8_t *orig,
					   struct hlist_head *mcast_orig_list,
					   struct list_head *nexthop_list,
					   struct bat_priv *bat_priv)
{
	struct mcast_forw_orig_entry *orig_entry;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(orig_entry, node, mcast_orig_list, list) {
		if (memcmp(orig, orig_entry->orig, ETH_ALEN))
			continue;

		nexthops_from_if_list(&orig_entry->mcast_if_list, nexthop_list,
				      bat_priv);
		break;
	}
}

static inline void nexthops_from_table(uint8_t *dest, uint8_t *orig,
				       struct hlist_head *mcast_forw_table,
				       struct list_head *nexthop_list,
				       struct bat_priv *bat_priv)
{
	struct mcast_forw_table_entry *table_entry;
	struct hlist_node *node;

	hlist_for_each_entry_rcu(table_entry, node, mcast_forw_table, list) {
		if (memcmp(dest, table_entry->mcast_addr, ETH_ALEN))
			continue;

		nexthops_from_orig_list(orig, &table_entry->mcast_orig_list,
					nexthop_list, bat_priv);
		break;
	}
}

static void route_mcast_packet(struct sk_buff *skb, struct bat_priv *bat_priv)
{
	struct sk_buff *skb1;
	struct mcast_packet *mcast_packet;
	struct ethhdr *ethhdr;
	int num_bcasts, i;
	struct list_head nexthop_list;
	struct dest_entries_list *dest_entry, *tmp;

	num_bcasts = atomic_read(&bat_priv->num_bcasts);
	mcast_packet = (struct mcast_packet *)skb->data;
	ethhdr = (struct ethhdr *)(mcast_packet + 1);

	INIT_LIST_HEAD(&nexthop_list);

	mcast_packet->ttl--;

	rcu_read_lock();
	nexthops_from_table(ethhdr->h_dest, mcast_packet->orig,
			    &bat_priv->mcast_forw_table, &nexthop_list,
			    bat_priv);
	rcu_read_unlock();

	list_for_each_entry_safe(dest_entry, tmp, &nexthop_list, list) {
		if (is_broadcast_ether_addr(dest_entry->dest)) {
			for (i = 0; i < num_bcasts; i++) {
				skb1 = skb_clone(skb, GFP_ATOMIC);
				send_skb_packet(skb1, dest_entry->hard_iface,
						dest_entry->dest);
			}
		} else {
			skb1 = skb_clone(skb, GFP_ATOMIC);
			send_skb_packet(skb1, dest_entry->hard_iface,
					dest_entry->dest);
		}
		hardif_free_ref(dest_entry->hard_iface);
		list_del(&dest_entry->list);
		kfree(dest_entry);
	}
}

int mcast_send_skb(struct sk_buff *skb, struct bat_priv *bat_priv)
{
	struct mcast_packet *mcast_packet;

	if (!bat_priv->primary_if)
		goto dropped;

	if (my_skb_head_push(skb, sizeof(struct mcast_packet)) < 0)
		goto dropped;

	mcast_packet = (struct mcast_packet *)skb->data;
	mcast_packet->version = COMPAT_VERSION;
	mcast_packet->ttl = TTL;

	/* batman packet type: broadcast */
	mcast_packet->packet_type = BAT_MCAST;

	/* hw address of first interface is the orig mac because only
	 * this mac is known throughout the mesh */
	memcpy(mcast_packet->orig,
	       bat_priv->primary_if->net_dev->dev_addr, ETH_ALEN);

	/* set broadcast sequence number */
	mcast_packet->seqno =
		htonl(atomic_inc_return(&bat_priv->mcast_seqno));

	route_mcast_packet(skb, bat_priv);

	kfree_skb(skb);
	return 0;

dropped:
	kfree_skb(skb);
	return 1;
}

int mcast_init(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->mcast_tracker_work, mcast_tracker_timer);

	mcast_tracker_start(bat_priv);

	return 1;
}

void mcast_free(struct bat_priv *bat_priv)
{
	mcast_flow_table_free(bat_priv);
	mcast_tracker_stop(bat_priv);
}
