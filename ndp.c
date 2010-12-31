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
#include "send.h"
#include "ndp.h"
#include "originator.h"

/* when do we schedule our own neighbor discovery packet to be sent */
static unsigned long own_ndp_send_time(struct batman_if *batman_if)
{
	return jiffies + msecs_to_jiffies(
		   atomic_read(&batman_if->ndp_interval) -
		   JITTER + (random32() % 2*JITTER));
}

void ndp_start_timer(struct batman_if *batman_if)
{
	/* adding some jitter */
	unsigned long ndp_interval = own_ndp_send_time(batman_if);
	queue_delayed_work(bat_event_workqueue, &batman_if->ndp_wq,
			   ndp_interval - jiffies);
}

void ndp_stop_timer(struct batman_if *batman_if)
{
	cancel_delayed_work_sync(&batman_if->ndp_wq);
}

static void ndp_send(struct work_struct *work)
{
	struct batman_if *batman_if = container_of(work, struct batman_if,
							ndp_wq.work);
	struct bat_priv *bat_priv = netdev_priv(batman_if->soft_iface);
	struct batman_packet_ndp *ndp_packet;
	struct neigh_entry *neigh_entry;
	struct neigh_node *neigh_node;
	struct hlist_node *node;
	int entries_len = 0;
	struct sk_buff *skb;

	skb = skb_copy(batman_if->ndp_skb, GFP_ATOMIC);
	ndp_packet = (struct batman_packet_ndp *)skb->data;
	ndp_packet->seqno = htonl(atomic_read(&batman_if->ndp_seqno));
	ndp_packet->num_neighbors = 0;
	memcpy(ndp_packet->orig, bat_priv->primary_if->net_dev->dev_addr,
	       ETH_ALEN);

	neigh_entry = (struct neigh_entry *)(ndp_packet + 1);
	spin_lock_bh(&batman_if->neigh_list_lock);
	hlist_for_each_entry(neigh_node, node, &batman_if->neigh_list, list) {
		if (entries_len + sizeof(struct neigh_entry) >
		    skb_tailroom(skb))
			break;

		memcpy(neigh_entry->addr, neigh_node->addr, ETH_ALEN);
		neigh_entry->rq = neigh_node->rq;
		ndp_packet->num_neighbors++;
		neigh_entry++;
		entries_len += sizeof(struct neigh_entry);
	}
	spin_unlock_bh(&batman_if->neigh_list_lock);
	skb_put(skb, entries_len);

	bat_dbg(DBG_BATMAN, bat_priv,
		"batman-adv:Sending ndp packet on interface %s, seqno %d\n",
		batman_if->net_dev, ntohl(ndp_packet->seqno));

	send_skb_packet(skb, batman_if, broadcast_addr);

	atomic_inc(&batman_if->ndp_seqno);
	ndp_start_timer(batman_if);
}

int ndp_init(struct batman_if *batman_if)
{
	struct batman_packet_ndp *ndp_packet;

	batman_if->ndp_skb =
		dev_alloc_skb(ETH_DATA_LEN + sizeof(struct ethhdr));
	if (!batman_if->ndp_skb) {
		printk(KERN_ERR "batman-adv: Can't add "
			"local interface packet (%s): out of memory\n",
			batman_if->net_dev->name);
		goto err;
	}
	skb_reserve(batman_if->ndp_skb, sizeof(struct ethhdr) +
					sizeof(struct batman_packet_ndp));
	ndp_packet = (struct batman_packet_ndp *)
		skb_push(batman_if->ndp_skb, sizeof(struct batman_packet_ndp));
	memset(ndp_packet, 0, sizeof(struct batman_packet_ndp));

	ndp_packet->packet_type = BAT_PACKET_NDP;
	ndp_packet->version = COMPAT_VERSION;

	INIT_HLIST_HEAD(&batman_if->neigh_list);
	spin_lock_init(&batman_if->neigh_list_lock);

	INIT_DELAYED_WORK(&batman_if->ndp_wq, ndp_send);

	return 0;
err:
	return 1;
}

void ndp_free(struct batman_if *batman_if)
{
	ndp_stop_timer(batman_if);
	dev_kfree_skb(batman_if->ndp_skb);
}

/* extract my own tq to neighbor from the ndp packet */
uint8_t ndp_fetch_tq(struct batman_packet_ndp *packet,
			 uint8_t *my_if_addr)
{
	struct neigh_entry *neigh_entry = (struct neigh_entry *)(packet + 1);
	uint8_t tq = 0;
	int i;

	for (i = 0; i < packet->num_neighbors; i++) {
		if (compare_orig(my_if_addr, neigh_entry->addr)) {
			tq = neigh_entry->rq;
			break;
		}
		neigh_entry++;
	}
	return tq;
}

static void ndp_update_neighbor_lq(uint8_t tq, uint32_t seqno,
				   struct neigh_node *neigh_node,
				   struct bat_priv *bat_priv)
{
	char is_duplicate = 0;
	int32_t seq_diff;
	int need_update = 0;

	seq_diff = seqno - neigh_node->last_rq_seqno;

	is_duplicate |= get_bit_status(neigh_node->ndp_rq_window,
				       neigh_node->last_rq_seqno,
				       seqno);

	/* if the window moved, set the update flag. */
	need_update |= bit_get_packet(bat_priv, neigh_node->ndp_rq_window,
				      seq_diff, 1);
	/* TODO: rename TQ_LOCAL_WINDOW_SIZE to RQ_LOCAL... */
	neigh_node->rq =
		(bit_packet_count(neigh_node->ndp_rq_window) * TQ_MAX_VALUE)
			/ TQ_LOCAL_WINDOW_SIZE;

	if (need_update) {
		bat_dbg(DBG_BATMAN, bat_priv, "batman-adv: ndp: "
			"updating last_seqno of neighbor %pM: old %d, new %d\n",
			neigh_node->addr, neigh_node->last_rq_seqno, seqno);
		/* TODO: this is not really an average here,
		   need to change the variable name later */
		neigh_node->tq_avg = tq;
		neigh_node->last_valid = jiffies;
		neigh_node->last_rq_seqno = seqno;
	}

	if (is_duplicate)
		bat_dbg(DBG_BATMAN, bat_priv,
			"seqno %d of neighbor %pM was a duplicate!\n",
			seqno, neigh_node->addr);

	bat_dbg(DBG_BATMAN, bat_priv, "batman-adv: ndp: "
		"new rq/tq of neighbor %pM: rq %d, tq %d\n",
		neigh_node->addr, neigh_node->rq, neigh_node->tq_avg);
}

static struct neigh_node *ndp_create_neighbor(uint8_t my_tq, uint32_t seqno,
					      uint8_t *neigh_addr,
					      struct bat_priv *bat_priv)
{
	struct neigh_node *neigh_node;

	bat_dbg(DBG_BATMAN, bat_priv,
		"batman-adv: ndp: Creating new neighbor %pM, "
		"initial tq %d, initial seqno %d\n",
		neigh_addr, my_tq, seqno);

	neigh_node = kzalloc(sizeof(struct neigh_node), GFP_ATOMIC);
	if (!neigh_node)
		return NULL;

	INIT_HLIST_NODE(&neigh_node->list);
	memcpy(neigh_node->addr, neigh_addr, ETH_ALEN);
	neigh_node->last_rq_seqno = seqno - 1;

	return neigh_node;
}

int ndp_update_neighbor(uint8_t my_tq, uint32_t seqno,
			struct batman_if *batman_if, uint8_t *neigh_addr)
{
	struct bat_priv *bat_priv = netdev_priv(batman_if->soft_iface);
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node;
	struct hlist_node *node;
	int ret = 1;

	spin_lock_bh(&batman_if->neigh_list_lock);
	/* old neighbor? */
	hlist_for_each_entry(tmp_neigh_node, node, &batman_if->neigh_list,
			     list) {
		if (!compare_orig(tmp_neigh_node->addr, neigh_addr))
			continue;

		neigh_node = tmp_neigh_node;
		break;
	}

	/* new neighbor? */
	if (!neigh_node) {
		neigh_node = ndp_create_neighbor(my_tq, seqno, neigh_addr,
						 bat_priv);
		if (!neigh_node)
			goto ret;

		hlist_add_head(&neigh_node->list, &batman_if->neigh_list);
	}

	ndp_update_neighbor_lq(my_tq, seqno, neigh_node, bat_priv);

	ret = 0;

ret:
	spin_unlock_bh(&batman_if->neigh_list_lock);
	return ret;
}
