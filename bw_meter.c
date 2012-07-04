#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"
#include "bw_meter.h"

#define BW_PACKET_LEN 1500
#define BW_WINDOW_SIZE 300
#define BW_CLEAN_RECEIVER_TIMEOUT 2000
#define BW_TIMEOUT 800
#define BW_WORKER_TIMEOUT BW_TIMEOUT/10

int send_icmp_packet(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct hard_iface *primary_if = NULL;
	struct orig_node *orig_node = NULL;
	struct neigh_node *neigh_node = NULL;
	struct icmp_packet *icmp_packet= (struct icmp_packet*)skb->data;
	int ret = -1;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: no primary if\n");
		goto out;
	}
	if (atomic_read(&bat_priv->mesh_state) != MESH_ACTIVE){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: mesh inactive\n");
		goto dst_unreach;
		}

	orig_node = batadv_orig_hash_find(bat_priv, 
					  icmp_packet->dst);
	if (!orig_node){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: no orig node\n");
		goto dst_unreach;
	}

	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: no neigh node\n");
		goto dst_unreach;
	}

	if (!neigh_node->if_incoming){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: no if incoming\n");
		goto dst_unreach;
	}

	if (neigh_node->if_incoming->if_status != IF_ACTIVE){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter:send_icmp_packet: status not IF_ACTIVE\n");
		goto dst_unreach;
	}

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

int batadv_send_bw_ack(struct socket_client *socket_client, 
		       struct icmp_packet *icmp_packet,  int seq)
{
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_ack;
	struct bat_priv *bat_priv = socket_client->bat_priv;
	int ret = -1;

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

void batadv_bw_receiver_clean(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bw_vars *bw_vars =
		container_of(delayed_work, struct bw_vars, bw_work);

	//TODO deallocate struct
	printk("test finished\n");
	spin_lock_bh(&bw_vars->bw_vars_lock);
	bw_vars->status = INACTIVE;
	spin_unlock_bh(&bw_vars->bw_vars_lock);
}

void batadv_bw_meter_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct icmp_packet_bw *icmp_packet;
	struct socket_client *socket_client;
	socket_client = container_of(&bat_priv, struct socket_client, bat_priv);

	icmp_packet = (struct icmp_packet_bw *)skb->data;

	/*setup RECEIVER data structure*/
	if (!bat_priv->bw_vars){
		if (icmp_packet->seqno != 0){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: seq != 0 cannot initiate connection\n");
			goto out;
		}
		bat_priv->bw_vars = 
			kmalloc(sizeof(struct bw_vars), GFP_ATOMIC);
		if (!bat_priv->bw_vars){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: meter_received cannot allocate bw_vars\n");
			goto out;
		}
		bat_priv->bw_vars->status = INACTIVE;
	}

	if (bat_priv->bw_vars->status == INACTIVE){
		if (icmp_packet->seqno != 0)
			goto out;
		bat_priv->bw_vars->status = RECEIVER;
		bat_priv->bw_vars->window_first = 0; 
		bat_priv->bw_vars->total_to_send = 0;
	}

	if (bat_priv->bw_vars->status != RECEIVER){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: cannot be sender and receiver\n");
		goto out;
	}

	/*check if packet belongs to window*/
	if (icmp_packet->seqno < bat_priv->bw_vars->window_first){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: %d < window_first\n", icmp_packet->seqno);
		goto out; //TODO send an ack!
	}
	
	if (icmp_packet->seqno > 
	    bat_priv->bw_vars->window_first + BW_WINDOW_SIZE){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: unexpected packet received\n");
	    	goto out; //TODO ??
	}

	if (icmp_packet->seqno == bat_priv->bw_vars->window_first){
		printk("Meter: correctely received %d - %d\n", icmp_packet->seqno, skb->len);
		bat_priv->bw_vars->window_first++;
		batadv_send_bw_ack(socket_client, 
				   (struct icmp_packet *) icmp_packet,
				   icmp_packet->seqno);
		
		/*check for last packet*/
		if (skb->len < BW_PACKET_LEN){
			//TODO use work for different tests??
			INIT_DELAYED_WORK(&bat_priv->bw_work, batadv_bw_receiver_clean);
			queue_delayed_work(batadv_event_workqueue, &bat_priv->bw_work, 
				   msecs_to_jiffies(BW_CLEAN_RECEIVER_TIMEOUT));
		}
	}

	goto out;
out:
	return;
}

static void batadv_bw_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct bw_vars * =
		container_of(delayed_work, struct bw_vars, bw_work);
	struct bat_priv *bat_priv = bw_vars->bat_priv;
	unsigned long int test_time;

	spin_lock_bh(&bw_vars->bw_vars_lock);
	/*if timedout, resend whole window*/
	if(batadv_has_timed_out(bw_vars->last_sent_time, BW_TIMEOUT)){
		bw_vars->next_to_send = bw_vars->window_first;
		spin_unlock_bh(&bw_vars->bw_vars_lock);
	   	batadv_send_remaining_window(bat_priv, bw_vars);
		spin_lock_bh(&bw_vars->bw_vars_lock);
	}

	/*if not finished, re-enqueue worker*/
	if (bw_vars->window_first < bw_vars->total_to_send){
		queue_delayed_work(batadv_event_workqueue, &bw_vars->bw_work,
				   msecs_to_jiffies(BW_WORKER_TIMEOUT));
	}else{
		test_time = (long)jiffies - (long)bat_priv->bw_vars->start_time;
		printk("Meter: test over in %u s. Throughput %u B/s\n", 
		       test_time/HZ,
		       bw_vars->total_to_send * 
		       BW_PACKET_LEN / (test_time/HZ));
	}
	spin_unlock_bh(&bw_vars->bw_vars_lock);
}

/*sends packets from next_to_send to (window_first+BW_WINDOW_SIZE) */
int batadv_send_remaining_window(struct bat_priv *bat_priv, 
				 struct bw_vars *bw_vars)
{
	struct sk_buff *skb;
	struct icmp_packet_bw *icmp_to_send;
	int send_until, ret = -1, bw_packet_len = BW_PACKET_LEN, next_to_send;
	struct socket_client *socket_client = 
		container_of(&bat_priv, struct socket_client, bat_priv);

	while (1){
		spin_lock_bh(&bw_vars->bw_vars_lock);
		if (bw_vars->next_to_send <
		    min(bat_priv->bw_vars->window_first + BW_WINDOW_SIZE, 
		   	bat_priv->bw_vars->total_to_send + 1)){
			spin_unlock_bh(&bw_vars->bw_vars_lock);
			break;
		}
		next_to_send = bw_vars->next_to_send++;
		spin_unlock_bh(&bw_vars->bw_vars_lock);
			
		if (bw_vars->next_to_send == bw_vars->total_to_send)
			bw_packet_len -= 1;

		skb = dev_alloc_skb(bw_packet_len + ETH_HLEN);
		if (!skb) {
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: send_remaining_window() cannot allocate skb\n");
			goto out;
		}

		skb_reserve(skb, ETH_HLEN);
		icmp_to_send = (struct icmp_packet_bw *)skb_put(skb, 
								bw_packet_len);//TODO redefine BW_PACKET_LEN
		
		/*fill the icmp header*/
		memcpy (&icmp_to_send->dst, &bat_priv->bw_vars->other_end, ETH_ALEN);
		icmp_to_send->header.version = COMPAT_VERSION;
		icmp_to_send->header.packet_type = BAT_ICMP;
		icmp_to_send->msg_type = BW_METER;
		icmp_to_send->seqno = next_to_send;
		icmp_to_send->uid = socket_client->index;

		if (send_icmp_packet(bat_priv, skb) < 0 ){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: send_remaining_window cannot send_icmp_packet\n"); goto out;
		}

		spin_lock_bh(&bw_vars->bw_vars_lock);
		bw_vars->last_sent_time = jiffies;
		spin_unlock_bh(&bw_vars->bw_vars_lock);
	}
	ret = 0;
out:
	return ret;
}

void batadv_bw_ack_received(struct bat_priv *bat_priv, struct sk_buff *skb)
{
	struct icmp_packet_bw *icmp_packet = (struct icmp_packet_bw *)skb->data;
	struct bw_vars *bw_vars;

	/*find the bw_vars*/
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->dst);
	spin_unlock_bh(&bat_priv->bw_list_lock);

	if (!bw_vars){
		batadv_dbg(DBG_BATMAN, bat_priv,
			   "Meter: received an ack not related to an open connection\n");
		goto out;
	}

	spin_lock_bh(&bw_vars->bw_vars_lock);

	/*check if seqno in window*/
	if (icmp_packet->seqno < bw_vars->window_first){
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: received ack %d < window_first\n", 
			   icmp_packet->seqno);
		spin_unlock_bh(&bw_vars->bw_vars_lock);
		goto out;
	}
	if (icmp_packet->seqno > bat_priv->bw_vars->next_to_send){
		/*after a timeout next_to_send=first*/
		/*or maybe I can keep it*/
		batadv_dbg(DBG_BATMAN, bat_priv, 
			   "Meter: received ack %d > next_to_send\n", 
			   icmp_packet->seqno);
		spin_unlock_bh(&bw_vars->bw_vars_lock);
		goto out;
	}

	/*slide and send fresh packets*/
	if (bw_vars->window_first <= icmp_packet->seqno)
		bw_vars->window_first = icmp_packet->seqno + 1;
	spin_unlock_bh(&bw_vars->bw_vars_lock);

	batadv_send_remaining_window(bw_vars);
out:
	return;
}

struct bw_vars *batadv_bw_list_find(struct bat_priv *bat_priv, void *dst)
{
	struct bw_vars *pos = NULL, *tmp;

	list_for_each_entry_safe(pos, tmp, &bat_priv->bw_list, list){
		if (memcmp (&pos->other_end, dst, ETH_ALEN) == 0)
			break;
	}

	return pos;
}

void batadv_bw_start(struct bat_priv *bat_priv, 
		    struct icmp_packet_bw *icmp_packet_bw)
{
	struct bw_vars *bw_vars;

	batadv_dbg(DBG_BATMAN, bat_priv, "Meter started...\n");
	
	/*find/initialize bw_vars*/
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet_bw->dst);
		
	if (!bw_vars){
		bw_vars = kmalloc(sizeof(struct bw_vars), GFP_ATOMIC);
		if (!bw_vars){
			batadv_dbg(DBG_BATMAN, bat_priv, 
				   "Meter: batadv_bw_start cannot allocate list elements\n");
			spin_unlock_bh(&bat_priv->bw_list_lock);
			goto out;
		}

		bw_vars->status = INACTIVE;
		spin_lock_init(&bw_vars->bw_vars_lock);
		list_add(&bw_vars->list, &bat_priv->bw_list);
	}

	if (bw_vars->status != INACTIVE){
		spin_unlock_bh(&bat_priv->bw_list_lock);
		goto out;
	}
	spin_unlock_bh(&bat_priv->bw_list_lock);
	
	/*initialize bw_vars*/
	spin_lock_bh(&bw_vars->bw_vars_lock);
	memcpy(&bw_vars->other_end, &icmp_packet_bw->dst, ETH_ALEN);
	bw_vars->total_to_send = 3000;
	bw_vars->next_to_send = 0;
	bw_vars->window_first = 0;
	bw_vars->bat_priv = bat_priv;
	bw_vars->last_sent_time = jiffies;
	bw_vars->start_time = jiffies;

	/*start worker*/
	INIT_DELAYED_WORK(&bw_vars->bw_work, batadv_bw_worker);
	queue_delayed_work(batadv_event_workqueue, &bw_vars->bw_work, 
			   msecs_to_jiffies(BW_TIMEOUT));
	spin_unlock_bh(&bw_vars->bw_vars_lock);
	batadv_send_remaining_window(bat_priv, bw_vars);
out:
	return;
}
