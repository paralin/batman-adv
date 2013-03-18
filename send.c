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
 */

#include "main.h"
#include "distributed-arp-table.h"
#include "send.h"
#include "routing.h"
#include "translation-table.h"
#include "soft-interface.h"
#include "hard-interface.h"
#include "vis.h"
#include "gateway_common.h"
#include "originator.h"
#include "network-coding.h"

#include <linux/if_ether.h>

static void batadv_send_outstanding_bcast_packet(struct work_struct *work);

/* send out an already prepared packet to the given address via the
 * specified batman interface
 */
int batadv_send_skb_packet(struct sk_buff *skb,
			   struct batadv_hard_iface *hard_iface,
			   const uint8_t *dst_addr)
{
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct ethhdr *ethhdr;

	if (hard_iface->if_status != BATADV_IF_ACTIVE)
		goto send_skb_err;

	if (unlikely(!hard_iface->net_dev))
		goto send_skb_err;

	if (!(hard_iface->net_dev->flags & IFF_UP)) {
		pr_warn("Interface %s is not up - can't send packet via that interface!\n",
			hard_iface->net_dev->name);
		goto send_skb_err;
	}

	/* push to the ethernet header. */
	if (batadv_skb_head_push(skb, ETH_HLEN) < 0)
		goto send_skb_err;

	skb_reset_mac_header(skb);

	ethhdr = eth_hdr(skb);
	memcpy(ethhdr->h_source, hard_iface->net_dev->dev_addr, ETH_ALEN);
	memcpy(ethhdr->h_dest, dst_addr, ETH_ALEN);
	ethhdr->h_proto = __constant_htons(ETH_P_BATMAN);

	skb_set_network_header(skb, ETH_HLEN);
	skb->priority = TC_PRIO_CONTROL;
	skb->protocol = __constant_htons(ETH_P_BATMAN);

	skb->dev = hard_iface->net_dev;

	/* Save a clone of the skb to use when decoding coded packets */
	batadv_nc_skb_store_for_decoding(bat_priv, skb);

	/* dev_queue_xmit() returns a negative result on error.	 However on
	 * congestion and traffic shaping, it drops and returns NET_XMIT_DROP
	 * (which is > 0). This will not be treated as an error.
	 */
	return dev_queue_xmit(skb);
send_skb_err:
	kfree_skb(skb);
	return NET_XMIT_DROP;
}

/**
 * batadv_send_skb_to_orig - Lookup next-hop and transmit skb.
 * @skb: Packet to be transmitted.
 * @orig_node: Final destination of the packet.
 * @recv_if: Interface used when receiving the packet (can be NULL).
 *
 * Looks up the best next-hop towards the passed originator and passes the
 * skb on for preparation of MAC header. If the packet originated from this
 * host, NULL can be passed as recv_if and no interface alternating is
 * attempted.
 *
 * Returns TRUE on success; FALSE otherwise.
 */
bool batadv_send_skb_to_orig(struct sk_buff *skb,
			     struct batadv_orig_node *orig_node,
			     struct batadv_hard_iface *recv_if)
{
	struct batadv_priv *bat_priv = orig_node->bat_priv;
	struct batadv_neigh_node *neigh_node;

	/* batadv_find_router() increases neigh_nodes refcount if found. */
	neigh_node = batadv_find_router(bat_priv, orig_node, recv_if);
	if (!neigh_node)
		return false;

	/* route it */
	batadv_send_skb_packet(skb, neigh_node->if_incoming, neigh_node->addr);

	batadv_neigh_node_free_ref(neigh_node);

	return true;
}

void batadv_schedule_bat_ogm(struct batadv_hard_iface *hard_iface)
{
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	if ((hard_iface->if_status == BATADV_IF_NOT_IN_USE) ||
	    (hard_iface->if_status == BATADV_IF_TO_BE_REMOVED))
		return;

	/* the interface gets activated here to avoid race conditions between
	 * the moment of activating the interface in
	 * hardif_activate_interface() where the originator mac is set and
	 * outdated packets (especially uninitialized mac addresses) in the
	 * packet queue
	 */
	if (hard_iface->if_status == BATADV_IF_TO_BE_ACTIVATED)
		hard_iface->if_status = BATADV_IF_ACTIVE;

	bat_priv->bat_algo_ops->bat_ogm_schedule(hard_iface);
}

/**
 * batadv_forw_packet_alloc - Allocates a forwarding packet
 * @if_incoming: The (optional) if_incoming to be grabbed
 * @queue_left: The (optional) queue counter to decrease
 * @bat_priv: The bat_priv for the mesh of this forw_packet
 *
 * Allocates a forwarding packet and tries to get a reference to the
 * (optional) if_incoming and queue_left. If queue_left is NULL then
 * bat_priv is optional, too.
 *
 * On success, returns the allocated forwarding packet. Otherwise returns
 * NULL.
 */
struct batadv_forw_packet *batadv_forw_packet_alloc(
					struct batadv_hard_iface *if_incoming,
					atomic_t *queue_left,
					struct batadv_priv *bat_priv)
{
	struct batadv_forw_packet *forw_packet = NULL;

	if (if_incoming && !atomic_inc_not_zero(&if_incoming->refcount))
		goto out;

	if (queue_left && !batadv_atomic_dec_not_zero(queue_left)) {
		if (queue_left == &bat_priv->bcast_queue_left)
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "bcast queue full\n");
		else if (queue_left == &bat_priv->batman_queue_left)
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "batman queue full\n");
		else
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "a mysterious queue is full\n");
		goto err;
	}

	forw_packet = kmalloc(sizeof(struct batadv_forw_packet), GFP_ATOMIC);
	if (!forw_packet)
		goto err2;

	forw_packet->skb = NULL;
	forw_packet->if_incoming = if_incoming;
	forw_packet->queue_left = queue_left;

	goto out;

err2:
	if (queue_left)
		atomic_inc(queue_left);
err:
	if (if_incoming)
		batadv_hardif_free_ref(if_incoming);
out:
	return forw_packet;
}

/**
 * batadv_forw_packet_free - Frees a forwarding packet
 * @forw_packet: The packet to free
 *
 * This frees a forwarding packet and releases any ressources it might
 * have claimed.
 */
void batadv_forw_packet_free(struct batadv_forw_packet *forw_packet)
{
	if (forw_packet->skb)
		kfree_skb(forw_packet->skb);
	if (forw_packet->if_incoming)
		batadv_hardif_free_ref(forw_packet->if_incoming);
	if (forw_packet->queue_left)
		atomic_inc(forw_packet->queue_left);
	kfree(forw_packet);
}

static void
_batadv_add_bcast_packet_to_list(struct batadv_priv *bat_priv,
				 struct batadv_forw_packet *forw_packet,
				 unsigned long send_time)
{
	hlist_add_head(&forw_packet->list, &bat_priv->forw_bcast_list);
	queue_delayed_work(batadv_event_workqueue, &forw_packet->delayed_work,
			   send_time);
}

/* add a broadcast packet to the queue and setup timers. broadcast packets
 * are sent multiple times to increase probability for being received.
 *
 * This function returns NETDEV_TX_OK on success and NETDEV_TX_BUSY on
 * errors.
 *
 * The skb is not consumed, so the caller should make sure that the
 * skb is freed.
 */
int batadv_add_bcast_packet_to_list(struct batadv_priv *bat_priv,
				    const struct sk_buff *skb,
				    unsigned long delay)
{
	struct batadv_hard_iface *primary_if;
	struct batadv_forw_packet *forw_packet;
	struct batadv_bcast_packet *bcast_packet;
	struct sk_buff *newskb;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		goto out;

	forw_packet = batadv_forw_packet_alloc(primary_if,
					       &bat_priv->bcast_queue_left,
					       bat_priv);
	batadv_hardif_free_ref(primary_if);
	if (!forw_packet)
		goto out;

	newskb = skb_copy(skb, GFP_ATOMIC);
	if (!newskb)
		goto packet_free;

	/* as we have a copy now, it is safe to decrease the TTL */
	bcast_packet = (struct batadv_bcast_packet *)newskb->data;
	bcast_packet->header.ttl--;

	skb_reset_mac_header(newskb);

	forw_packet->skb = newskb;

	/* how often did we send the bcast packet ? */
	forw_packet->num_packets = 0;

	INIT_DELAYED_WORK(&forw_packet->delayed_work,
			  batadv_send_outstanding_bcast_packet);

	spin_lock_bh(&bat_priv->forw_bcast_list_lock);
	_batadv_add_bcast_packet_to_list(bat_priv, forw_packet, delay);
	spin_unlock_bh(&bat_priv->forw_bcast_list_lock);

	return NETDEV_TX_OK;

packet_free:
	batadv_forw_packet_free(forw_packet);
out:
	return NETDEV_TX_BUSY;
}

static void batadv_send_outstanding_bcast_packet(struct work_struct *work)
{
	struct batadv_hard_iface *hard_iface;
	struct delayed_work *delayed_work;
	struct batadv_forw_packet *forw_packet;
	struct sk_buff *skb1;
	struct net_device *soft_iface;
	struct batadv_priv *bat_priv;

	delayed_work = container_of(work, struct delayed_work, work);
	forw_packet = container_of(delayed_work, struct batadv_forw_packet,
				   delayed_work);
	soft_iface = forw_packet->if_incoming->soft_iface;
	bat_priv = netdev_priv(soft_iface);

	if (atomic_read(&bat_priv->mesh_state) == BATADV_MESH_DEACTIVATING)
		goto out;

	if (batadv_dat_drop_broadcast_packet(bat_priv, forw_packet))
		goto out;

	/* rebroadcast packet */
	rcu_read_lock();
	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != soft_iface)
			continue;

		if (forw_packet->num_packets >= hard_iface->num_bcasts)
			continue;

		/* send a copy of the saved skb */
		skb1 = skb_clone(forw_packet->skb, GFP_ATOMIC);
		if (skb1)
			batadv_send_skb_packet(skb1, hard_iface,
					       batadv_broadcast_addr);
	}
	rcu_read_unlock();

	forw_packet->num_packets++;

	/* if we still have some more bcasts to send */
	if (forw_packet->num_packets < BATADV_NUM_BCASTS_MAX) {
		spin_lock_bh(&bat_priv->forw_bcast_list_lock);
		if (hlist_unhashed(&forw_packet->list)) {
			spin_unlock_bh(&bat_priv->forw_bcast_list_lock);
			return;
		}
		hlist_del(&forw_packet->list);

		_batadv_add_bcast_packet_to_list(bat_priv, forw_packet,
						 msecs_to_jiffies(5));
		spin_unlock_bh(&bat_priv->forw_bcast_list_lock);

		return;
	}

out:
	spin_lock_bh(&bat_priv->forw_bcast_list_lock);
	if (hlist_unhashed(&forw_packet->list)) {
		spin_unlock_bh(&bat_priv->forw_bcast_list_lock);
		return;
	}
	hlist_del(&forw_packet->list);
	spin_unlock_bh(&bat_priv->forw_bcast_list_lock);

	batadv_forw_packet_free(forw_packet);
}

void batadv_send_outstanding_bat_ogm_packet(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_forw_packet *forw_packet;
	struct batadv_priv *bat_priv;

	delayed_work = container_of(work, struct delayed_work, work);
	forw_packet = container_of(delayed_work, struct batadv_forw_packet,
				   delayed_work);
	bat_priv = netdev_priv(forw_packet->if_incoming->soft_iface);
	spin_lock_bh(&bat_priv->forw_bat_list_lock);
	if (hlist_unhashed(&forw_packet->list)) {
		spin_unlock_bh(&bat_priv->forw_bat_list_lock);
		return;
	}
	hlist_del(&forw_packet->list);
	spin_unlock_bh(&bat_priv->forw_bat_list_lock);

	if (atomic_read(&bat_priv->mesh_state) == BATADV_MESH_DEACTIVATING)
		goto out;

	bat_priv->bat_algo_ops->bat_ogm_emit(forw_packet);

	/* we have to have at least one packet in the queue
	 * to determine the queues wake up time unless we are
	 * shutting down
	 */
	if (forw_packet->own)
		batadv_schedule_bat_ogm(forw_packet->if_incoming);

out:
	batadv_forw_packet_free(forw_packet);
}

/**
 * batadv_cancel_packets - Cancels a list of forward packets
 * @forw_list:		The to be canceled forward packets
 * @canceled_list:	The backup list
 * @hard_iface:		The interface to cancel forward packets for
 *
 * This cancels any scheduled forwarding packet tasks in the provided
 * forw_list for the given hard_iface. If hard_iface is NULL forwarding packets
 * on all hard interfaces will be canceled.
 *
 * The packets are being moved from the forw_list to the canceled_list
 * and the forward packet list pointer will be unhashed, allowing any already
 * running task to notice the cancelation.
 */
static void batadv_cancel_packets(struct hlist_head *forw_list,
				  struct hlist_head *canceled_list,
				  const struct batadv_hard_iface *hard_iface)
{
	struct batadv_forw_packet *forw_packet;
	struct hlist_node *safe_tmp_node;

	hlist_for_each_entry_safe(forw_packet, safe_tmp_node,
				  forw_list, list) {
		/* if purge_outstanding_packets() was called with an argument
		 * we delete only packets belonging to the given interface
		 */
		if ((hard_iface) &&
		    (forw_packet->if_incoming != hard_iface))
			continue;

		hlist_del_init(&forw_packet->list);
		hlist_add_head(&forw_packet->canceled_list, canceled_list);
	}
}

/**
 * batadv_canceled_packets_free - Frees canceled forward packets
 * @head:	A list of to be freed forw_packets
 *
 * This function canceles the scheduling of any packet in the provided list,
 * waits for any possibly running packet forwarding thread to finish and
 * finally, safely frees this forward packet.
 *
 * This function might sleep.
 */
static void batadv_canceled_packets_free(struct hlist_head *head)
{
	struct batadv_forw_packet *forw_packet;
	struct hlist_node *safe_tmp_node;

	hlist_for_each_entry_safe(forw_packet, safe_tmp_node, head,
				  canceled_list) {
		cancel_delayed_work_sync(&forw_packet->delayed_work);

		hlist_del(&forw_packet->canceled_list);
		batadv_forw_packet_free(forw_packet);
	}
}

/**
 * batadv_purge_outstanding_packets - Stops/purges scheduled bcast/ogm packets
 * @bat_priv:	The mesh to cancel and purge bcast/ogm packets for
 * @hard_iface:	The hard interface to cancel and purge bcast_ogm packets on
 *
 * This method cancels and purges any broadcast and ogm packet on the given
 * hard_iface. If hard_iface is NULL, broadcast and ogm packets on all hard
 * interfaces will be canceled and purged.
 *
 * Note that after this method bcast/ogm callbacks might still be running for
 * a few instructions (use a flush_workqueue(batadv_event_workqueue) to
 * wait for them to finish).
 *
 * This function might sleep.
 */
void
batadv_purge_outstanding_packets(struct batadv_priv *bat_priv,
				 const struct batadv_hard_iface *hard_iface)
{
	struct hlist_head head;

	INIT_HLIST_HEAD(&head);

	if (hard_iface)
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "purge_outstanding_packets(): %s\n",
			   hard_iface->net_dev->name);
	else
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "purge_outstanding_packets()\n");

	/* free bcast list */
	spin_lock_bh(&bat_priv->forw_bcast_list_lock);
	batadv_cancel_packets(&bat_priv->forw_bcast_list, &head, hard_iface);
	spin_unlock_bh(&bat_priv->forw_bcast_list_lock);

	/* free batman packet list */
	spin_lock_bh(&bat_priv->forw_bat_list_lock);
	batadv_cancel_packets(&bat_priv->forw_bat_list, &head, hard_iface);
	spin_unlock_bh(&bat_priv->forw_bat_list_lock);

	batadv_canceled_packets_free(&head);
}
