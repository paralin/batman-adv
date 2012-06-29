#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"

#define BW_PACKET_LEN 1000
#define BW_WINDOW_SIZE 5

static void resend_window(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bat_priv *bat_priv =
		container_of(delayed_work, struct bat_priv, bw_work);

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: Ack not received!!\n");
}

int send_icmp_packet(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct hard_iface *primary_if = NULL;
	struct orig_node *orig_node = NULL;
	struct neigh_node *neigh_node = NULL;
	struct icmp_packet *icmp_packet= (struct icmp_packet*)skb->data;
	int ret = -1;

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
	ret = 0;
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
	return ret;
}


void batadv_bw_ack_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct icmp_packet_bw *icmp_packet;
	struct bw_meter_vars *bw_meter_vars = bat_priv->bw_meter_vars;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: received an ack\n");
	//cancel_delayed_work_sync(&bat_priv->bw_work); //TODO kernel panic
	icmp_packet = (struct icmp_packet_bw *)skb->data;

out:
	return;
}

int batadv_send_whole_window(struct bat_priv *bat_priv, int send_offset)
{
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_packet_bw, *icmp_to_send;
	int last, ret = -1;
	struct socket_client *socket_client = 
		container_of(&bat_priv, struct socket_client, bat_priv);

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: send_whole_window called\n");
	icmp_packet_bw = bat_priv->bw_meter_vars->icmp_packet_bw;
	last = bat_priv->bw_meter_vars->first + BW_WINDOW_SIZE;

	while (send_offset < last){
		skb = dev_alloc_skb(BW_PACKET_LEN + ETH_HLEN);
		if (!skb) {
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: send_whole_window() cannot allocate skb\n");
			goto out;
		}

		skb_reserve(skb, ETH_HLEN);
		icmp_to_send = (struct icmp_packet_bw *)skb_put(skb, 
								BW_PACKET_LEN);//TODO redefine BW_PACKET_LEN
		
		/*fill the icmp header*/
		memcpy (icmp_to_send, icmp_packet_bw, 
			sizeof (struct icmp_packet_bw));
		icmp_to_send->seqno = send_offset++;
		icmp_to_send->wsize = BW_WINDOW_SIZE;

		icmp_to_send->uid = socket_client->index;
		if (send_icmp_packet(bat_priv, skb) < 0 ){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: send_whole_window cannot send_icmp_packet\n");
			goto out;
		}
	}

	/*start the timer*/
	INIT_DELAYED_WORK(&bat_priv->bw_work, resend_window);
	queue_delayed_work(batadv_event_workqueue, &bat_priv->bw_work,
			   msecs_to_jiffies(5000));
	ret = 0;

out:
	return ret;
}

void start_bw_meter(struct bat_priv *bat_priv, 
		    struct icmp_packet_bw *icmp_packet_bw)
{
	batadv_dbg(DBG_BATMAN, bat_priv, "Meter started...\n");

	/*TODO should I check the parameters?*/
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
	bat_priv->bw_meter_vars->to_send = 10;
	bat_priv->bw_meter_vars->first = 0;

	batadv_send_whole_window(bat_priv, 0);
	goto out;
	
out:
	return;
}

int batadv_send_bw_ack(struct socket_client *socket_client, 
		       struct icmp_packet *icmp_packet,  int seq)
{
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_ack;
	struct bat_priv *bat_priv = socket_client->bat_priv;
	int ret = -1;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: batadv_send_bw_ack called\n");
	bat_priv = socket_client->bat_priv;
	skb = dev_alloc_skb(sizeof(struct icmp_packet_bw) + ETH_HLEN);
	if (!skb){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: batadv_send_bw_ack cannot allocate skb\n");
		goto out;
	}
	
	skb_reserve(skb, ETH_HLEN);
	icmp_ack = (struct icmp_packet_bw *) 
		   skb_put(skb, sizeof(struct icmp_packet_bw));
	icmp_ack->header.packet_type = BAT_ICMP;
	icmp_ack->header.version = COMPAT_VERSION;
	icmp_ack->header.ttl = 50;
	icmp_ack->seqno = seq;
	icmp_ack->msg_type = BW_ACK;
	memcpy(icmp_ack->dst, icmp_packet->orig, ETH_ALEN);
	icmp_ack->uid = socket_client->index;

	/*send the ack*/
	if (send_icmp_packet(bat_priv, skb) < 0){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: batadv_send_bw_ack cannot send_icmp_packet\n");
		goto out;
	}
	ret = 0;
out:
	return ret;
}

void batadv_bw_meter_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct icmp_packet_bw *icmp_packet;
	struct socket_client *socket_client;
	socket_client = container_of(&bat_priv, struct socket_client, bat_priv);

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: BW_METER received\n");
	icmp_packet = (struct icmp_packet_bw *)skb->data;

	/*setup RECEIVER data structure*/
	if (!bat_priv->bw_meter_vars){
		if (icmp_packet->seqno != 0){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: seq != 0 cannot initiate connection\n");
			goto out;
		}
		bat_priv->bw_meter_vars = 
			kmalloc(sizeof(struct bw_meter_vars), GFP_ATOMIC);
		if (!bat_priv->bw_meter_vars){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: meter_received cannot allocate bw_meter_vars\n");
			goto out;
		}
		bat_priv->bw_meter_vars->status = INACTIVE;
	}

	if (bat_priv->bw_meter_vars->status == INACTIVE){
		if (icmp_packet->seqno != 0)
			goto out;
		bat_priv->bw_meter_vars->status = RECEIVER;
		bat_priv->bw_meter_vars->first = 0; 
		bat_priv->bw_meter_vars->to_send = 0;
	}

	if (bat_priv->bw_meter_vars->status != RECEIVER){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: cannot be sender and receiver\n");
		goto out;
	}

	/*check if packet belongs to window*/
	if (icmp_packet->seqno < bat_priv->bw_meter_vars->first){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: I should send the hack again:)\n");
		goto out; //TODO send an ack!
	}
	
	if (icmp_packet->seqno > 
	    bat_priv->bw_meter_vars->first + icmp_packet->wsize){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: unexpected packet received\n");
	    	goto out; //TODO ??
	}

	if (icmp_packet->seqno == bat_priv->bw_meter_vars->first){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: sending ack\n");
		bat_priv->bw_meter_vars->first++;
		batadv_send_bw_ack(socket_client, 
				   (struct icmp_packet *) icmp_packet,
				   icmp_packet->seqno);
	}

	goto out;
out:
	batadv_dbg(DBG_BATMAN, bat_priv, "Meter: going out\n");
	return;
}
