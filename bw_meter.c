#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"

void start_bw_meter(struct bat_priv *bat_priv, 
		    struct icmp_packet_bw *icmp_packet_bw)
{
	struct hard_iface *primary_if = NULL;
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_to_send;
	struct orig_node *orig_node = NULL;
	struct neigh_node *neigh_node = NULL;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter started...\n");
	primary_if = batadv_primary_if_get_selected(bat_priv);

	if (!primary_if) {
		goto out;
	}

	skb = dev_alloc_skb(sizeof (struct icmp_packet_bw) + ETH_HLEN);
	if (!skb) {
		goto out;
	}

	skb_reserve(skb, ETH_HLEN);
	icmp_to_send = (struct icmp_packet_bw *)
		skb_put(skb, 1000); //TODO fill the packet!
	
	/*fill the icmp header*/
	memcpy (icmp_to_send, icmp_packet_bw, sizeof (struct icmp_packet_bw));
	icmp_to_send->offset = 1;

	/*icmp_to_send->uid = socket_client->index;*/ //TODO see if needed

	if (atomic_read(&bat_priv->mesh_state) != MESH_ACTIVE)
		goto dst_unreach;

	orig_node = batadv_orig_hash_find(bat_priv, icmp_packet_bw->dst);
	if (!orig_node)
		goto dst_unreach;

	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node)
		goto dst_unreach;

	if (!neigh_node->if_incoming)
		goto dst_unreach;

	if (neigh_node->if_incoming->if_status != IF_ACTIVE)
		goto dst_unreach;

	memcpy(icmp_to_send->orig, primary_if->net_dev->dev_addr, ETH_ALEN);

	batadv_send_skb_packet(skb, neigh_node->if_incoming, neigh_node->addr);
	goto out;

dst_unreach:
	/*
	icmp_to_send->msg_type = DESTINATION_UNREACHABLE;
	batadv_socket_add_packet(socket_client, icmp_to_send, packet_len); //not in .h
	*/
out:
	if (primary_if)
		batadv_hardif_free_ref(primary_if);
	if (neigh_node)
		batadv_neigh_node_free_ref(neigh_node);
	if (orig_node)
		batadv_orig_node_free_ref(orig_node);
}

void batadv_bw_meter_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	batadv_dbg(DBG_BATMAN, bat_priv, "Bandwidth meter packet received\n");	
}
