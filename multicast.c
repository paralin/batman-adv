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
#include "multicast.h"
#include "hash.h"
#include "send.h"
#include "compat.h"

/* If auto mode for tracker timeout has been selected,
 * how many times of tracker_interval to wait */
#define TRACKER_TIMEOUT_AUTO_X 5

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

	return 0;
}

static void inc_state_dest_entry(struct tracker_packet_state *state)
{
	state->dest_num++;
	state->dest_entry += ETH_ALEN;
	state->break_flag = 0;
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
	struct batman_if *batman_if;
};


struct mcast_forw_nexthop_entry {
	struct list_head list;
	uint8_t neigh_addr[6];
	unsigned long timeout;	/* old jiffies value */
};

struct mcast_forw_if_entry {
	struct list_head list;
	int16_t if_num;
	int num_nexthops;
	struct list_head mcast_nexthop_list;
};

struct mcast_forw_orig_entry {
	struct list_head list;
	uint8_t orig[6];
	uint32_t last_mcast_seqno;
	unsigned long mcast_bits[NUM_WORDS];
	struct list_head mcast_if_list;
};

struct mcast_forw_table_entry {
	struct list_head list;
	uint8_t mcast_addr[6];
	struct list_head mcast_orig_list;
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

static void start_mcast_tracker(struct bat_priv *bat_priv)
{
	/* adding some jitter */
	unsigned long tracker_interval = tracker_send_delay(bat_priv);
	queue_delayed_work(bat_event_workqueue, &bat_priv->mcast_tracker_work,
			   tracker_interval);
}

static void stop_mcast_tracker(struct bat_priv *bat_priv)
{
	cancel_delayed_work_sync(&bat_priv->mcast_tracker_work);
}

void mcast_tracker_reset(struct bat_priv *bat_priv)
{
	stop_mcast_tracker(bat_priv);
	start_mcast_tracker(bat_priv);
}

static inline int get_remaining_timeout(
				struct mcast_forw_nexthop_entry *nexthop_entry,
				struct bat_priv *bat_priv)
{
	int tracker_timeout = atomic_read(&bat_priv->mcast_tracker_timeout);
	if (!tracker_timeout)
		tracker_timeout = atomic_read(&bat_priv->mcast_tracker_interval)
				  * TRACKER_TIMEOUT_AUTO_X;
	if (!tracker_timeout)
		tracker_timeout = atomic_read(&bat_priv->orig_interval)
				  * TRACKER_TIMEOUT_AUTO_X / 2;

	tracker_timeout = jiffies_to_msecs(nexthop_entry->timeout) +
			tracker_timeout - jiffies_to_msecs(jiffies);

	return (tracker_timeout > 0 ? tracker_timeout : 0);
}

static void prepare_forw_if_entry(struct list_head *forw_if_list,
				  int16_t if_num, uint8_t *neigh_addr)
{
	struct mcast_forw_if_entry *forw_if_entry;
	struct mcast_forw_nexthop_entry *forw_nexthop_entry;

	list_for_each_entry(forw_if_entry, forw_if_list, list)
		if (forw_if_entry->if_num == if_num)
			goto skip_create_if;

	forw_if_entry = kmalloc(sizeof(struct mcast_forw_if_entry),
				GFP_ATOMIC);
	if (!forw_if_entry)
		return;

	forw_if_entry->if_num = if_num;
	forw_if_entry->num_nexthops = 0;
	INIT_LIST_HEAD(&forw_if_entry->mcast_nexthop_list);
	list_add(&forw_if_entry->list, forw_if_list);

skip_create_if:
	list_for_each_entry(forw_nexthop_entry,
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
	forw_if_entry->num_nexthops++;
	if (forw_if_entry->num_nexthops < 0) {
		kfree(forw_nexthop_entry);
		goto free;
	}

	list_add(&forw_nexthop_entry->list,
		 &forw_if_entry->mcast_nexthop_list);
	return;
free:
	list_del(&forw_if_entry->list);
	kfree(forw_if_entry);
}

static struct list_head *prepare_forw_table_entry(
				struct mcast_forw_table_entry *forw_table,
				uint8_t *mcast_addr, uint8_t *orig)
{
	struct mcast_forw_table_entry *forw_table_entry;
	struct mcast_forw_orig_entry *orig_entry;

	forw_table_entry = kmalloc(sizeof(struct mcast_forw_table_entry),
				   GFP_ATOMIC);
	if (!forw_table_entry)
		return NULL;

	memcpy(forw_table_entry->mcast_addr, mcast_addr, ETH_ALEN);
	list_add(&forw_table_entry->list, &forw_table->list);

	INIT_LIST_HEAD(&forw_table_entry->mcast_orig_list);
	orig_entry = kmalloc(sizeof(struct mcast_forw_orig_entry), GFP_ATOMIC);
	if (!orig_entry)
		goto free;

	memcpy(orig_entry->orig, orig, ETH_ALEN);
	INIT_LIST_HEAD(&orig_entry->mcast_if_list);
	list_add(&orig_entry->list, &forw_table_entry->mcast_orig_list);

	return &orig_entry->mcast_if_list;

free:
	list_del(&forw_table_entry->list);
	kfree(forw_table_entry);
	return NULL;
}

static int sync_nexthop(struct mcast_forw_nexthop_entry *sync_nexthop_entry,
			 struct list_head *nexthop_list)
{
	struct mcast_forw_nexthop_entry *nexthop_entry;
	int synced = 0;

	list_for_each_entry(nexthop_entry, nexthop_list, list) {
		if (memcmp(sync_nexthop_entry->neigh_addr,
			   nexthop_entry->neigh_addr, ETH_ALEN))
			continue;

		nexthop_entry->timeout = jiffies;
		list_del(&sync_nexthop_entry->list);
		kfree(sync_nexthop_entry);

		synced = 1;
		break;
	}

	if (!synced) {
		sync_nexthop_entry->timeout = jiffies;
		list_move(&sync_nexthop_entry->list, nexthop_list);
		return 1;
	}

	return 0;
}

static void sync_if(struct mcast_forw_if_entry *sync_if_entry,
		    struct list_head *if_list)
{
	struct mcast_forw_if_entry *if_entry;
	struct mcast_forw_nexthop_entry *sync_nexthop_entry, *tmp;
	int synced = 0;

	list_for_each_entry(if_entry, if_list, list) {
		if (sync_if_entry->if_num != if_entry->if_num)
			continue;

		list_for_each_entry_safe(sync_nexthop_entry, tmp,
				&sync_if_entry->mcast_nexthop_list, list)
			if (sync_nexthop(sync_nexthop_entry,
					 &if_entry->mcast_nexthop_list))
				if_entry->num_nexthops++;

		list_del(&sync_if_entry->list);
		kfree(sync_if_entry);

		synced = 1;
		break;
	}

	if (!synced)
		list_move(&sync_if_entry->list, if_list);
}

/* syncs all multicast entries of sync_table_entry to forw_table */
static void sync_orig(struct mcast_forw_orig_entry *sync_orig_entry,
		      struct list_head *orig_list)
{
	struct mcast_forw_orig_entry *orig_entry;
	struct mcast_forw_if_entry *sync_if_entry, *tmp;
	int synced = 0;

	list_for_each_entry(orig_entry, orig_list, list) {
		if (memcmp(sync_orig_entry->orig,
			    orig_entry->orig, ETH_ALEN))
			continue;

		list_for_each_entry_safe(sync_if_entry, tmp,
				&sync_orig_entry->mcast_if_list, list)
			sync_if(sync_if_entry, &orig_entry->mcast_if_list);

		list_del(&sync_orig_entry->list);
		kfree(sync_orig_entry);

		synced = 1;
		break;
	}

	if (!synced)
		list_move(&sync_orig_entry->list, orig_list);
}


/* syncs all multicast entries of sync_table_entry to forw_table */
static void sync_table(struct mcast_forw_table_entry *sync_table_entry,
		       struct list_head *forw_table)
{
	struct mcast_forw_table_entry *table_entry;
	struct mcast_forw_orig_entry *sync_orig_entry, *tmp;
	int synced = 0;

	list_for_each_entry(table_entry, forw_table, list) {
		if (memcmp(sync_table_entry->mcast_addr,
			   table_entry->mcast_addr, ETH_ALEN))
			continue;

		list_for_each_entry_safe(sync_orig_entry, tmp,
				&sync_table_entry->mcast_orig_list, list)
			sync_orig(sync_orig_entry,
				  &table_entry->mcast_orig_list);

		list_del(&sync_table_entry->list);
		kfree(sync_table_entry);

		synced = 1;
		break;
	}

	if (!synced)
		list_move(&sync_table_entry->list, forw_table);
}

/* Updates the old multicast forwarding table with the information gained
 * from the generated/received tracker packet. It also frees the generated
 * table for syncing (*forw_table). */
static void update_mcast_forw_table(struct mcast_forw_table_entry *forw_table,
				    struct bat_priv *bat_priv)
{
	struct mcast_forw_table_entry *sync_table_entry, *tmp;

	spin_lock_bh(&bat_priv->mcast_forw_table_lock);
	list_for_each_entry_safe(sync_table_entry, tmp, &forw_table->list,
				 list)
		sync_table(sync_table_entry, &bat_priv->mcast_forw_table);
	spin_unlock_bh(&bat_priv->mcast_forw_table_lock);
}

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
static struct mcast_tracker_packet *mcast_proact_tracker_prepare(
			struct bat_priv *bat_priv, int *tracker_packet_len)
{
	struct net_device *soft_iface = bat_priv->primary_if->soft_iface;
	uint8_t *mc_addr_list;
	MC_LIST *mc_entry;
	struct element_t *bucket;
	struct orig_node *orig_node;
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct hlist_node *walk;
	struct hlist_head *head;
	int i;

	/* one dest_entries_list per multicast group,
	 * they'll collect dest_entries[x] */
	int num_mcast_entries, used_mcast_entries = 0;
	struct list_head *dest_entries_list;
	struct dest_entries_list dest_entries[UINT8_MAX], *dest, *tmp;
	int num_dest_entries, dest_entries_total = 0;

	uint8_t *dest_entry;
	int pos, mca_pos;
	struct mcast_tracker_packet *tracker_packet = NULL;
	struct mcast_entry *mcast_entry;

	if (!hash)
		goto out;

	/* Make a copy so we don't have to rush because of locking */
	netif_addr_lock_bh(soft_iface);
	num_mcast_entries = netdev_mc_count(soft_iface);
	mc_addr_list = kmalloc(ETH_ALEN * num_mcast_entries, GFP_ATOMIC);
	if (!mc_addr_list) {
		netif_addr_unlock_bh(soft_iface);
		goto out;
	}
	pos = 0;
	netdev_for_each_mc_addr(mc_entry, soft_iface) {
		memcpy(&mc_addr_list[pos * ETH_ALEN], mc_entry->MC_LIST_ADDR,
		       ETH_ALEN);
		pos++;
	}
	netif_addr_unlock_bh(soft_iface);

	if (num_mcast_entries > UINT8_MAX)
		num_mcast_entries = UINT8_MAX;
	dest_entries_list = kmalloc(num_mcast_entries *
					sizeof(struct list_head), GFP_ATOMIC);
	if (!dest_entries_list)
		goto free;

	for (pos = 0; pos < num_mcast_entries; pos++)
		INIT_LIST_HEAD(&dest_entries_list[pos]);

	/* fill the lists and buffers */
	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(bucket, walk, head, hlist) {
			orig_node = bucket->data;
			if (!orig_node->num_mca)
				continue;

			num_dest_entries = 0;
			for (mca_pos = 0; mca_pos < orig_node->num_mca &&
			     dest_entries_total != UINT8_MAX; mca_pos++) {
				pos = find_mca_match(orig_node, mca_pos,
					mc_addr_list, num_mcast_entries);
				if (pos > UINT8_MAX || pos < 0)
					continue;
				memcpy(dest_entries[dest_entries_total].dest,
				       orig_node->orig, ETH_ALEN);
				list_add(
					&dest_entries[dest_entries_total].list,
					&dest_entries_list[pos]);

				num_dest_entries++;
				dest_entries_total++;
			}
		}
		rcu_read_unlock();
	}

	/* Any list left empty? */
	for (pos = 0; pos < num_mcast_entries; pos++)
		if (!list_empty(&dest_entries_list[pos]))
			used_mcast_entries++;

	if (!used_mcast_entries)
		goto free_all;

	/* prepare tracker packet, finally! */
	*tracker_packet_len = sizeof(struct mcast_tracker_packet) +
			     used_mcast_entries * sizeof(struct mcast_entry) +
			     ETH_ALEN * dest_entries_total;
	if (*tracker_packet_len > ETH_DATA_LEN) {
		pr_warning("mcast tracker packet got too large (%i Bytes), "
			   "forcing reduced size of %i Bytes\n",
			   *tracker_packet_len, ETH_DATA_LEN);
		*tracker_packet_len = ETH_DATA_LEN;
	}
	tracker_packet = kmalloc(*tracker_packet_len, GFP_ATOMIC);

	tracker_packet->packet_type = BAT_MCAST_TRACKER;
	tracker_packet->version = COMPAT_VERSION;
	memcpy(tracker_packet->orig, bat_priv->primary_if->net_dev->dev_addr,
		ETH_ALEN);
	tracker_packet->ttl = TTL;
	tracker_packet->num_mcast_entries = (used_mcast_entries > UINT8_MAX) ?
						UINT8_MAX : used_mcast_entries;
	memset(tracker_packet->align, 0, sizeof(tracker_packet->align));

	/* append all collected entries */
	mcast_entry = (struct mcast_entry *)(tracker_packet + 1);
	for (pos = 0; pos < num_mcast_entries; pos++) {
		if (list_empty(&dest_entries_list[pos]))
			continue;

		if ((char *)(mcast_entry + 1) <=
		    (char *)tracker_packet + ETH_DATA_LEN) {
			memcpy(mcast_entry->mcast_addr,
			       &mc_addr_list[pos*ETH_ALEN], ETH_ALEN);
			mcast_entry->num_dest = 0;
		}

		dest_entry = (uint8_t *)(mcast_entry + 1);
		list_for_each_entry_safe(dest, tmp, &dest_entries_list[pos],
					 list) {
			/* still place for a dest_entry left?
			 * watch out for overflow here, stop at UINT8_MAX */
			if ((char *)dest_entry + ETH_ALEN <=
			    (char *)tracker_packet + ETH_DATA_LEN &&
			    mcast_entry->num_dest != UINT8_MAX) {
				mcast_entry->num_dest++;
				memcpy(dest_entry, dest->dest, ETH_ALEN);
				dest_entry += ETH_ALEN;
			}
			list_del(&dest->list);
		}
		/* still space for another mcast_entry left? */
		if ((char *)(mcast_entry + 1) <=
		    (char *)tracker_packet + ETH_DATA_LEN)
			mcast_entry = (struct mcast_entry *)dest_entry;
	}


	/* outstanding cleanup */
free_all:
	kfree(dest_entries_list);
free:
	kfree(mc_addr_list);
out:

	return tracker_packet;
}

/* Adds the router for the destination address to the next_hop list and its
 * interface to the forw_if_list - but only if this router has not been
 * added yet */
static int add_router_of_dest(struct dest_entries_list *next_hops,
			      uint8_t *dest,
			      struct list_head *forw_if_list,
			      struct bat_priv *bat_priv)
{
	struct dest_entries_list *next_hop_tmp, *next_hop_entry;
	int16_t if_num;
	struct element_t *bucket;
	struct orig_node *orig_node;
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct hlist_node *walk;
	struct hlist_head *head;
	int i;

	next_hop_entry = kmalloc(sizeof(struct dest_entries_list), GFP_ATOMIC);
	if (!next_hop_entry)
		return 1;

	next_hop_entry->batman_if = NULL;
	for (i = 0; i < hash->size; i++) {
		head = &hash->table[i];

		rcu_read_lock();
		hlist_for_each_entry_rcu(bucket, walk, head, hlist) {
			orig_node = bucket->data;

			if (memcmp(orig_node->orig, dest, ETH_ALEN))
				continue;

			if (!orig_node->router) {
				i = hash->size;
				break;
			}

			memcpy(next_hop_entry->dest, orig_node->router->addr,
			       ETH_ALEN);
			next_hop_entry->batman_if =
						orig_node->router->if_incoming;
			if_num = next_hop_entry->batman_if->if_num;
			i = hash->size;
			break;
		}
		rcu_read_unlock();
	}
	if (!next_hop_entry->batman_if)
		goto free;

	if (forw_if_list)
		prepare_forw_if_entry(forw_if_list, if_num,
				      next_hop_entry->dest);

	list_for_each_entry(next_hop_tmp, &next_hops->list, list)
		if (!memcmp(next_hop_tmp->dest, next_hop_entry->dest,
								ETH_ALEN))
			goto free;

	list_add(&next_hop_entry->list, &next_hops->list);

	return 0;

free:
	kfree(next_hop_entry);
	return 1;
}

/* Collect nexthops for all dest entries specified in this tracker packet.
 * It also reduces the number of elements in the tracker packet if they exceed
 * the buffers length (e.g. because of a received, broken tracker packet) to
 * avoid writing in unallocated memory. */
static int tracker_next_hops(struct mcast_tracker_packet *tracker_packet,
			     int tracker_packet_len,
			     struct dest_entries_list *next_hops,
			     struct mcast_forw_table_entry *forw_table,
			     struct bat_priv *bat_priv)
{
	int num_next_hops = 0, ret;
	struct tracker_packet_state state;
	uint8_t *tail = (uint8_t *)tracker_packet + tracker_packet_len;
	struct list_head *forw_table_if = NULL;

	INIT_LIST_HEAD(&next_hops->list);
	INIT_LIST_HEAD(&forw_table->list);

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

	struct element_t *bucket;
	struct orig_node *orig_node;
	struct hashtable_t *hash = bat_priv->orig_hash;
	struct hlist_node *walk;
	struct hlist_head *head;
	int i;

	tracker_packet_for_each_dest(&state, tracker_packet) {
		for (i = 0; i < hash->size; i++) {
			head = &hash->table[i];

			rcu_read_lock();
			hlist_for_each_entry_rcu(bucket, walk, head, hlist) {
				orig_node = bucket->data;

				if (memcmp(orig_node->orig, state.dest_entry,
					   ETH_ALEN))
					continue;

				/* is the next hop already our destination? */
				if (!memcmp(orig_node->orig, next_hop,
					    ETH_ALEN))
					memset(state.dest_entry, '\0',
					       ETH_ALEN);
				else if (!orig_node->router)
					memset(state.dest_entry, '\0',
					       ETH_ALEN);
				else if (!memcmp(orig_node->orig,
						 orig_node->router->orig_node->
						 primary_addr, ETH_ALEN))
					memset(state.dest_entry, '\0',
					       ETH_ALEN);
				/* is this the wrong next hop for our
				 * destination? */
				else if (memcmp(orig_node->router->addr,
						next_hop, ETH_ALEN))
					memset(state.dest_entry, '\0',
					       ETH_ALEN);

				i = hash->size;
				break;
			}
			rcu_read_unlock();
		}
	}
}

/* Remove zeroed destination entries and empty multicast entries in tracker
 * packet */
static int shrink_tracker_packet(struct mcast_tracker_packet *tracker_packet,
				  int tracker_packet_len)
{
	struct tracker_packet_state state;
	uint8_t *tail = (uint8_t *)tracker_packet + tracker_packet_len;
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

	return new_tracker_packet_len;
}

static struct sk_buff *build_tracker_packet_skb(
		struct mcast_tracker_packet *tracker_packet,
		int tracker_packet_len, uint8_t *dest)
{
	struct sk_buff *skb;
	struct mcast_tracker_packet *skb_tracker_data;

	skb = dev_alloc_skb(tracker_packet_len + sizeof(struct ethhdr));
	if (!skb)
		return NULL;

	skb_reserve(skb, sizeof(struct ethhdr));
	skb_tracker_data = (struct mcast_tracker_packet *)
				skb_put(skb, tracker_packet_len);

	memcpy(skb_tracker_data, tracker_packet, tracker_packet_len);

	return skb;
}


/**
 * Sends (splitted parts of) a multicast tracker packet on the according
 * interfaces.
 *
 * @tracker_packet:	A compact multicast tracker packet with all groups and
 *			destinations attached.
 */
void route_mcast_tracker_packet(
			struct mcast_tracker_packet *tracker_packet,
			int tracker_packet_len, struct bat_priv *bat_priv)
{
	struct dest_entries_list next_hops, *tmp;
	struct mcast_tracker_packet *next_hop_tracker_packets,
				    *next_hop_tracker_packet;
	struct dest_entries_list *next_hop;
	struct mcast_forw_table_entry forw_table;
	struct sk_buff *skb;
	int num_next_hops, i;
	int *tracker_packet_lengths;

	rcu_read_lock();
	num_next_hops = tracker_next_hops(tracker_packet, tracker_packet_len,
					  &next_hops, &forw_table, bat_priv);
	if (!num_next_hops)
		goto out;

	update_mcast_forw_table(&forw_table, bat_priv);

	next_hop_tracker_packets = kmalloc(tracker_packet_len * num_next_hops,
					   GFP_ATOMIC);
	if (!next_hop_tracker_packets)
		goto free;

	tracker_packet_lengths = kmalloc(num_next_hops * sizeof(int),
					  GFP_ATOMIC);
	if (!tracker_packet_lengths)
		goto free2;

	i = 0;
	list_for_each_entry_safe(next_hop, tmp, &next_hops.list, list) {
		next_hop_tracker_packet = (struct mcast_tracker_packet *)
					  ((char *)next_hop_tracker_packets +
					   i * tracker_packet_len);
		memcpy(next_hop_tracker_packet, tracker_packet,
		       tracker_packet_len);
		zero_tracker_packet(next_hop_tracker_packet, next_hop->dest,
				    bat_priv);
		tracker_packet_lengths[i] = shrink_tracker_packet(
				next_hop_tracker_packet, tracker_packet_len);
		i++;
	}

	i = 0;
	/* Add ethernet header, send 'em! */
	list_for_each_entry_safe(next_hop, tmp, &next_hops.list, list) {
		if (tracker_packet_lengths[i] ==
		    sizeof(struct mcast_tracker_packet))
			goto skip_send;

		skb = build_tracker_packet_skb(&next_hop_tracker_packets[i],
					       tracker_packet_lengths[i],
					       next_hop->dest);
		if (skb)
			send_skb_packet(skb, next_hop->batman_if,
					next_hop->dest);
skip_send:
		list_del(&next_hop->list);
		kfree(next_hop);
		i++;
	}

	kfree(tracker_packet_lengths);
	kfree(next_hop_tracker_packets);
	return;

free2:
	kfree(next_hop_tracker_packets);
free:
	list_for_each_entry_safe(next_hop, tmp, &next_hops.list, list) {
		list_del(&next_hop->list);
		kfree(next_hop);
	}
out:
	rcu_read_unlock();
}

static void mcast_tracker_timer(struct work_struct *work)
{
	struct bat_priv *bat_priv = container_of(work, struct bat_priv,
						 mcast_tracker_work.work);
	struct mcast_tracker_packet *tracker_packet = NULL;
	int tracker_packet_len = 0;

	if (atomic_read(&bat_priv->mcast_mode) == MCAST_MODE_PROACT_TRACKING)
		tracker_packet = mcast_proact_tracker_prepare(bat_priv,
							&tracker_packet_len);

	if (!tracker_packet)
		goto out;

	route_mcast_tracker_packet(tracker_packet, tracker_packet_len,
				   bat_priv);
	kfree(tracker_packet);

out:
	start_mcast_tracker(bat_priv);
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

static inline struct batman_if *if_num_to_batman_if(int16_t if_num)
{
	struct batman_if *batman_if;

	list_for_each_entry_rcu(batman_if, &if_list, list)
		if (batman_if->if_num == if_num)
			return batman_if;

	return NULL;
}

int mcast_forw_table_seq_print_text(struct seq_file *seq, void *offset)
{
	struct net_device *net_dev = (struct net_device *)seq->private;
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	struct batman_if *batman_if;
	struct mcast_forw_table_entry *table_entry;
	struct mcast_forw_orig_entry *orig_entry;
	struct mcast_forw_if_entry *if_entry;
	struct mcast_forw_nexthop_entry *nexthop_entry;

	seq_printf(seq, "[B.A.T.M.A.N. adv %s%s, MainIF/MAC: %s/%pM (%s)]\n",
		   SOURCE_VERSION, REVISION_VERSION_STR,
		   bat_priv->primary_if->net_dev->name,
		   bat_priv->primary_if->net_dev->dev_addr, net_dev->name);
	seq_printf(seq, "Multicast group MAC\tOriginator\t"
			"Outgoing interface\tNexthop - timeout in msecs\n");

	rcu_read_lock();
	spin_lock_bh(&bat_priv->mcast_forw_table_lock);
	list_for_each_entry(table_entry, &bat_priv->mcast_forw_table, list) {
		seq_printf(seq, "%pM\n", table_entry->mcast_addr);

		list_for_each_entry(orig_entry, &table_entry->mcast_orig_list,
				    list) {
			seq_printf(seq, "\t%pM\n", orig_entry->orig);

			list_for_each_entry(if_entry,
					    &orig_entry->mcast_if_list, list) {
				batman_if =
					if_num_to_batman_if(if_entry->if_num);
				if (!batman_if)
					continue;

				seq_printf(seq, "\t\t%s\n",
					   batman_if->net_dev->name);

				list_for_each_entry(nexthop_entry,
						&if_entry->mcast_nexthop_list,
						list) {
					seq_printf(seq, "\t\t\t%pM - %i\n",
						   nexthop_entry->neigh_addr,
						   get_remaining_timeout(
						     nexthop_entry, bat_priv));
				}
			}
		}
	}
	spin_unlock_bh(&bat_priv->mcast_forw_table_lock);
	rcu_read_unlock();

	return 0;
}

int mcast_init(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->mcast_tracker_work, mcast_tracker_timer);
	INIT_LIST_HEAD(&bat_priv->mcast_forw_table);

	start_mcast_tracker(bat_priv);

	return 1;
}

void mcast_free(struct bat_priv *bat_priv)
{
	stop_mcast_tracker(bat_priv);
}
