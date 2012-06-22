#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"

#define BW_PACKET_LEN 1000
#define BW_WINDOW_SIZE 5000

static void resend_window(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bat_priv *bat_priv =
		container_of(delayed_work, struct bat_priv, bw_work);

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: Ack not received!!\n");
}

void send_icmp_packet(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct hard_iface *primary_if = NULL;
	struct orig_node *orig_node = NULL;
	struct neigh_node *neigh_node = NULL;
	struct icmp_packet *icmp_packet= (struct icmp_packet*)skb->data;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: send_icmp_packet called\n");
	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		goto out;
	if (atomic_read(&bat_priv->mesh_state) != MESH_ACTIVE)
		goto dst_unreach;

	orig_node = batadv_orig_hash_find(bat_priv, 
					  icmp_packet->dst);
	if (!orig_node)
		goto dst_unreach;

	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node)
		goto dst_unreach;

	if (!neigh_node->if_incoming)
		goto dst_unreach;

	if (neigh_node->if_incoming->if_status != IF_ACTIVE)
		goto dst_unreach;

	memcpy(icmp_packet->orig, 
	       primary_if->net_dev->dev_addr, ETH_ALEN);

	batadv_send_skb_packet(skb, neigh_node->if_incoming, 
			       neigh_node->addr);
	goto out;

dst_unreach:
	/*
	icmp_to_send->msg_type = DESTINATION_UNREACHABLE;
	batadv_socket_add_packet(socket_client, icmp_to_send, packet_len); //TODO not in .h
	*/

out:
	if (primary_if)
		batadv_hardif_free_ref(primary_if);
	if (neigh_node)
		batadv_neigh_node_free_ref(neigh_node);
	if (orig_node)
		batadv_orig_node_free_ref(orig_node);
}


void batadv_bw_ack_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	//struct icmp_packet_bw *icmp_packet;
	//struct bw_meter_vars *bw_meter_vars = bat_priv->bw_meter_vars;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: received an ack\n");
/*
	icmp_packet = (struct icmp_packet_bw *)skb->data;

	if (icmp_packet->offset != bw_meter_vars->first + BW_WINDOW_SIZE)
		goto out;
out:
	return;
*/
}

void send_whole_window(struct bat_priv *bat_priv)
{
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_packet_bw, *icmp_to_send;
	int sent_bytes = 0;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: send_whole_window called\n");

	icmp_packet_bw = bat_priv->bw_meter_vars->icmp_packet_bw;

	while (sent_bytes < BW_WINDOW_SIZE){
		skb = dev_alloc_skb(BW_PACKET_LEN + ETH_HLEN);
		if (!skb) {
			goto out;
		}

		skb_reserve(skb, ETH_HLEN);
		icmp_to_send = (struct icmp_packet_bw *)
				skb_put(skb, BW_PACKET_LEN); //TODO redefine BW_PACKET_LEN
		
		/*fill the icmp header*/
		memcpy (icmp_to_send, icmp_packet_bw, 
			sizeof (struct icmp_packet_bw));
		icmp_to_send->offset = 0; //TODO update offset
		icmp_to_send->wsize = BW_WINDOW_SIZE;

		/*icmp_to_send->uid = socket_client->index;*/ //TODO see if needed
		send_icmp_packet(bat_priv, skb);
		sent_bytes += BW_PACKET_LEN;
	}

	/*start the timer*/
	INIT_DELAYED_WORK(&bat_priv->bw_work, resend_window);
	queue_delayed_work(batadv_event_workqueue, &bat_priv->bw_work,
			   msecs_to_jiffies(5000));

out:
	return;
}

void start_bw_meter(struct bat_priv *bat_priv, 
		    struct icmp_packet_bw *icmp_packet_bw)
{
	batadv_dbg(DBG_BATMAN, bat_priv, "Meter started...\n");

	/*TODO should I check the parameters?*/
	/*TODO bw_meter_vars->other end is ignored*/
	/*check bw_meter_vars*/
	if (!bat_priv->bw_meter_vars){
		bat_priv->bw_meter_vars = kmalloc(sizeof(struct bw_meter_vars),
						  GFP_ATOMIC); /*TODO GFP kernel?*/
		if (!bat_priv->bw_meter_vars)
			goto out;

		bat_priv->bw_meter_vars->status = INACTIVE;
	}

	if (bat_priv->bw_meter_vars->status != INACTIVE)
		goto out;
	
	bat_priv->bw_meter_vars->icmp_packet_bw = icmp_packet_bw;
	bat_priv->bw_meter_vars->to_send = 10000;
	bat_priv->bw_meter_vars->first = 0;

	send_whole_window(bat_priv);
	goto out;
	
out:
	return;
}

void batadv_bw_meter_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{

	struct icmp_packet_bw *icmp_packet, *icmp_ack;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: BW_METER received\n");

	icmp_packet = (struct icmp_packet_bw *)skb->data;
	if (!bat_priv->bw_meter_vars){
		if (icmp_packet->offset != 0)
			goto out;
		bat_priv->bw_meter_vars = 
			kmalloc(sizeof(struct bw_meter_vars), GFP_ATOMIC);
		if (!bat_priv->bw_meter_vars)
			goto out;
		bat_priv->bw_meter_vars->status = INACTIVE;
	}

	if (bat_priv->bw_meter_vars->status == INACTIVE){
		if (icmp_packet->offset != 0)
			goto out;
		bat_priv->bw_meter_vars->status = RECEIVER;
		bat_priv->bw_meter_vars->first = 0; 
		bat_priv->bw_meter_vars->to_send = 0;
	}

	/*check if packet expected*/
	if (icmp_packet->offset < bat_priv->bw_meter_vars->first){
		batadv_dbg(DBG_BATMAN, bat_priv, "Meter: I should send the hack again:)\n");
		goto out; //TODO send an ack!
	}
	
	if (icmp_packet->offset > 
	    bat_priv->bw_meter_vars->first + icmp_packet->wsize)
	    	goto out; //TODO ??

	bat_priv->bw_meter_vars->to_send += skb->len;

	/*window full*/
	if (bat_priv->bw_meter_vars->to_send >=
	    bat_priv->bw_meter_vars->first + icmp_packet->wsize){
	    	bat_priv->bw_meter_vars->first += icmp_packet->wsize;
		bat_priv->bw_meter_vars->to_send = 0;

		/*fill the ACK*/
		batadv_dbg(DBG_BATMAN, bat_priv, "Meter: sending the ack!\n");
		skb = dev_alloc_skb(sizeof(struct icmp_packet_bw) + ETH_HLEN);
		if (!skb)
			goto out;
		
		skb_reserve(skb, ETH_HLEN);
		icmp_ack = (struct icmp_packet_bw *) 
			   skb_put(skb, sizeof(struct icmp_packet_bw));
		icmp_ack->header.packet_type = BAT_ICMP;
		icmp_ack->header.version = COMPAT_VERSION;
		icmp_ack->header.ttl = 50;
		icmp_ack->seqno = 0;
		icmp_ack->offset = bat_priv->bw_meter_vars->first;
		icmp_ack->msg_type = BW_ACK;
		memcpy(icmp_ack->dst, icmp_packet->orig, ETH_ALEN);
		/*icmp_ack->uid = socket_client->index;*/ //TODO see if needed

		/*send the ack*/
		send_icmp_packet(bat_priv, skb);
       }
       goto out;

out:
	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: going out\n");
	return;
}
