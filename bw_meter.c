#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"
#include "bw_meter.h"

#define BW_PACKET_LEN 1000
#define BW_WINDOW_SIZE 1005
#define BW_CLEAN_RECEIVER_TIMEOUT 2000
#define BATADV_BW_TIMEOUT 400
#define BATADV_BW_WORKER_TIMEOUT (BATADV_BW_TIMEOUT/10)
#define BATADV_BW_BUFFER 65536
#define BATADV_BW_TOTAL_TO_SEND 1000

static int batadv_bw_queue_delayed_work(struct batadv_bw_vars *bw_vars);

static void batadv_bw_vars_free(struct batadv_bw_vars *bw_vars)
{
	//spin_lock_bh(&bw_vars->bat_priv->bw_list_lock);
	list_del(&bw_vars->list);
	//spin_unlock_bh(&bw_vars->bat_priv->bw_list_lock);
	kfree(bw_vars);
}


static int batadv_bw_icmp_send(struct batadv_priv *bat_priv, struct sk_buff *skb)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	struct batadv_icmp_packet *icmp_packet =
		(struct batadv_icmp_packet *)skb->data;
	int ret = -1;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: no primary if\n");
		goto out;
	}
	if (atomic_read(&bat_priv->mesh_state) != BATADV_MESH_ACTIVE) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: mesh inactive\n");
		goto dst_unreach;
	}

	orig_node = batadv_orig_hash_find(bat_priv,
					  icmp_packet->dst);
	if (!orig_node) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: no orig node\n");
		goto dst_unreach;
	}

	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: no neigh node\n");
		goto dst_unreach;
	}

	if (!neigh_node->if_incoming) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: no if incoming\n");
		goto dst_unreach;
	}

	if (neigh_node->if_incoming->if_status != BATADV_IF_ACTIVE) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter:batadv_bw_icmp_send: status not IF_ACTIVE\n");
		goto dst_unreach;
	}

	memcpy(icmp_packet->orig,
	       primary_if->net_dev->dev_addr, ETH_ALEN);

	batadv_send_skb_packet(skb, neigh_node->if_incoming,
			       neigh_node->addr);
	ret = 0;
	goto out;

dst_unreach:
	/* TODO not in .h
	icmp_to_send->msg_type = DESTINATION_UNREACHABLE;
	batadv_socket_add_packet(socket_client, icmp_to_send, packet_len);
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

static struct batadv_bw_vars *batadv_bw_list_find(struct batadv_priv *bat_priv,
						  void *dst)
{
	struct batadv_bw_vars *pos = NULL, *tmp;

	list_for_each_entry_safe(pos, tmp, &bat_priv->bw_list, list) {
		if (memcmp(&pos->other_end, dst, ETH_ALEN) == 0)
			return pos;
	}

	return NULL;
}

static int batadv_bw_ack_send(struct batadv_socket_client *socket_client,
			      struct batadv_icmp_packet *icmp_packet,  int seq)
{
	struct sk_buff *skb;
	struct batadv_icmp_packet_bw *icmp_ack;
	struct batadv_priv *bat_priv = socket_client->bat_priv;
	int ret = -1;

	bat_priv = socket_client->bat_priv;
	skb = dev_alloc_skb(sizeof(*skb) + ETH_HLEN);
	if (!skb) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_send_bw_ack cannot allocate skb\n");
		goto out;
	}

	skb_reserve(skb, ETH_HLEN);
	icmp_ack = (struct batadv_icmp_packet_bw *)
		   skb_put(skb, sizeof(struct batadv_icmp_packet_bw));
	icmp_ack->header.packet_type = BATADV_ICMP;
	icmp_ack->header.version = BATADV_COMPAT_VERSION;
	icmp_ack->header.ttl = 50;
	icmp_ack->seqno = seq;
	icmp_ack->msg_type = BATADV_BW_ACK;
	memcpy(icmp_ack->dst, icmp_packet->orig, ETH_ALEN);
	icmp_ack->uid = socket_client->index;

	/* send the ack */
	if (batadv_bw_icmp_send(bat_priv, skb) < 0) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_send_bw_ack cannot send_icmp_packet\n");
		goto out;
	}
	ret = 0;
out:
	return ret;
}

static void batadv_bw_receiver_clean(struct work_struct *work)
{
	struct delayed_work *delayed_work =
		container_of(work, struct delayed_work, work);
	struct batadv_bw_vars *bw_vars =
		container_of(delayed_work, struct batadv_bw_vars, bw_work);

	pr_info("test finished\n");
	batadv_bw_vars_free(bw_vars);
}

void batadv_bw_meter_received(struct batadv_priv *bat_priv, struct sk_buff *skb)
{
	struct batadv_bw_vars *bw_vars;
	struct batadv_icmp_packet_bw *icmp_packet;
	struct batadv_socket_client *socket_client;
	unsigned int timeout = BW_CLEAN_RECEIVER_TIMEOUT;
	socket_client = container_of(&bat_priv,
				     struct batadv_socket_client, bat_priv);

	icmp_packet = (struct batadv_icmp_packet_bw *)skb->data;
	printk("RECEIVED: %d\n", icmp_packet->seqno);

	/* search/initialize bw_vars struct */
	//spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->dst);
	if (!bw_vars) {
		if (icmp_packet->seqno != 0) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: seq != 0 cannot initiate connection\n");
			//spin_unlock_bh(&bat_priv->bw_list_lock);
			goto out;
		}
		bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
		if (!bw_vars) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: meter_received cannot allocate bw_vars\n");
			//spin_unlock_bh(&bat_priv->bw_list_lock);
			goto out;
		}
		memcpy(&bw_vars->other_end, &icmp_packet->dst, ETH_ALEN);
		bw_vars->status = RECEIVER;
		bw_vars->window_first = 0;
		bw_vars->bat_priv = bat_priv;
		//spin_lock_init(&bw_vars->bw_vars_lock);
		list_add(&bw_vars->list, &bat_priv->bw_list);
	}

	if (bw_vars->status != RECEIVER) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: cannot be sender and receiver\n");
		//spin_unlock_bh(&bat_priv->bw_list_lock);
		goto out;
	}
	//spin_unlock_bh(&bat_priv->bw_list_lock);

	/* check if the packet belongs to window */
	//spin_lock_bh(&bw_vars->bw_vars_lock);
	if (icmp_packet->seqno < bw_vars->window_first) {
		//spin_unlock_bh(&bw_vars->bw_vars_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: %d < window_first\n", icmp_packet->seqno);
		goto out; /* TODO send an ack! */
	}

	if (icmp_packet->seqno > bw_vars->window_first + BW_WINDOW_SIZE) {
		//spin_unlock_bh(&bw_vars->bw_vars_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: unexpected packet received\n");
		goto out; /* TODO ?? */
	}

	/* packet does belong to the window */
	if (icmp_packet->seqno == bw_vars->window_first) {
		bw_vars->window_first++;
		//spin_unlock_bh(&bw_vars->bw_vars_lock);

		batadv_bw_ack_send(socket_client,
				   (struct batadv_icmp_packet *)icmp_packet,
				   icmp_packet->seqno);

		/* check for the last packet */
		if (skb->len < BW_PACKET_LEN) {
			printk("last packet received %u\n", icmp_packet->seqno);
			INIT_DELAYED_WORK(&bw_vars->bw_work,
					  batadv_bw_receiver_clean);
			queue_delayed_work(batadv_event_workqueue,
					   &bw_vars->bw_work,
					   msecs_to_jiffies(timeout));
		}
	} else {
		//spin_unlock_bh(&bw_vars->bw_vars_lock);
	}
out:
	return;
}

/* Sends all packets that belongs to the window and have not been sent yet
 * according to next_to_send and (window_first + BW_WINDOW_SIZE)
 */
static int batadv_bw_multiple_send(struct batadv_priv *bat_priv,
				   struct batadv_bw_vars *bw_vars)
{
	struct sk_buff *skb;
	struct batadv_icmp_packet_bw *icmp_to_send;
	int ret = -1, bw_packet_len = BW_PACKET_LEN, next_to_send;
	struct batadv_socket_client *socket_client;
	uint16_t window_end;

	printk("entering\n");

	socket_client = container_of(&bat_priv, struct batadv_socket_client,
				     bat_priv);
	//if (!spin_trylock(&bw_vars->bw_send_lock))
	//	goto out;

	while (1) {
		//spin_lock_bh(&bw_vars->bw_ack_lock);
		window_end = min( (uint16_t) (bw_vars->window_first + BW_WINDOW_SIZE),
				 bw_vars->total_to_send);
		if (!batadv_seq_before(bw_vars->next_to_send, window_end)) {
			//spin_unlock(&bw_vars->bw_send_lock);
			//spin_unlock_bh(&bw_vars->bw_ack_lock);
			printk ("\nExiting: window_first: %d, last_sent_time:%lu\n",
				bw_vars->window_first, bw_vars->last_sent_time);
			break;
		}
		//spin_unlock_bh(&bw_vars->bw_ack_lock);
		next_to_send = bw_vars->next_to_send++;

		if (bw_vars->next_to_send == bw_vars->total_to_send){
			bw_packet_len -= 1;
		}

		skb = dev_alloc_skb(bw_packet_len + ETH_HLEN);
		if (!skb) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_multiple_send() cannot allocate skb\n");
			//spin_unlock(&bw_vars->bw_send_lock);
			goto out;
		}

		/* TODO redefine BW_PACKET_LEN */
		skb_reserve(skb, ETH_HLEN);
		icmp_to_send = (struct batadv_icmp_packet_bw *)
					skb_put(skb, bw_packet_len);

		/* fill the icmp header */
		memcpy(&icmp_to_send->dst, &bw_vars->other_end, ETH_ALEN);
		icmp_to_send->header.version = BATADV_COMPAT_VERSION;
		icmp_to_send->header.packet_type = BATADV_ICMP;
		icmp_to_send->msg_type = BATADV_BW_METER;
		icmp_to_send->seqno = next_to_send;
		icmp_to_send->uid = socket_client->index;

		if (batadv_bw_icmp_send(bat_priv, skb) < 0) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_multiple_send() cannot send_icmp_packet\n");
			//spin_unlock(&bw_vars->bw_send_lock);
			goto out;
		}

		bw_vars->last_sent_time = jiffies;
	}
	ret = 0;
out:
	return ret;
}

void batadv_bw_ack_received(struct batadv_priv *bat_priv,
			    struct sk_buff *skb)
{
	struct batadv_icmp_packet_bw *icmp_packet;
	struct batadv_bw_vars *bw_vars;
	uint16_t window_end;

	icmp_packet = (struct batadv_icmp_packet_bw *)skb->data;
	printk("ack %d\n", icmp_packet->seqno);
	/* find the bw_vars */
	//spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->orig);
	//spin_unlock_bh(&bat_priv->bw_list_lock);
	if (!bw_vars) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: received an ack not related to an open connection\n");
		goto out;
	}

	/* slide and send fresh packets */
	//spin_lock_bh(&bw_vars->bw_ack_lock);
	window_end = bw_vars->window_first + BW_WINDOW_SIZE;
	if (!batadv_seq_after(bw_vars->window_first, icmp_packet->seqno) &&
	    batadv_seq_before(icmp_packet->seqno, window_end)) {
		bw_vars->window_first = icmp_packet->seqno + 1;
	} else {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: received unespected ack\n");
	}

	//spin_unlock_bh(&bw_vars->bw_ack_lock);
	//batadv_bw_multiple_send(bat_priv, bw_vars);
out:
	return;
}

static void fake_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars, bw_work);
	bat_priv = bw_vars->bat_priv;

	printk("Fake worker called!\n");
	if (bw_vars->window_first <= BATADV_BW_TOTAL_TO_SEND -1){
		if (batadv_bw_queue_delayed_work(bw_vars) == 0){
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_start work already enqueued\n");
		}
	}
}
static void batadv_bw_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;
	unsigned long int test_time, total_bytes, throughput;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars, bw_work);
	bat_priv = bw_vars->bat_priv;

	/* if timedout, resend whole window */
	if (batadv_has_timed_out(bw_vars->last_sent_time, BATADV_BW_TIMEOUT)) {
		pr_info("WORKER RESENDING WHOLE WINDOW %d\n", bw_vars->window_first);
		printk("%lu, %lu\n", bw_vars->last_sent_time, jiffies);
		bw_vars->next_to_send = bw_vars->window_first;
		batadv_bw_multiple_send(bat_priv, bw_vars);
	}

	/* if not finished, re-enqueue worker */
	if (bw_vars->window_first < bw_vars->total_to_send -1 ) {
		if (batadv_bw_queue_delayed_work(bw_vars) == 0){
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_start work already enqueued\n");
		}
	} else {
		test_time = ((long)jiffies - (long)bw_vars->start_time) *
			    (1000/HZ);
		total_bytes = bw_vars->total_to_send * BW_PACKET_LEN;
		throughput = total_bytes / test_time * 1000;

		pr_info("Meter: test over in %lu ms.\nMeter: sent %lu bytes.\nThroughput %lu B/s\n",
			test_time, total_bytes, throughput);
		batadv_bw_vars_free(bw_vars);
	}
	printk("WORKER called, not resending. FIRST: %d", bw_vars->window_first);
}

void batadv_bw_start(struct batadv_priv *bat_priv,
		     struct batadv_icmp_packet_bw *icmp_packet_bw)
{
	struct batadv_bw_vars *bw_vars;

	/* find bw_vars */
	//spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet_bw->dst);
	if (bw_vars){
		/* TODO notify batctl */
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: test to or from the same node already ongoing, aborting\n");
		//spin_unlock_bh(&bat_priv->bw_list_lock);
		goto out;
	}

	bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
	if (!bw_vars) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_bw_start cannot allocate list elements\n");
		//spin_unlock_bh(&bat_priv->bw_list_lock);
		goto out;
	}

	/* initialize bw_vars */
	memcpy(&bw_vars->other_end, &icmp_packet_bw->dst, ETH_ALEN);
	bw_vars->total_to_send = BATADV_BW_TOTAL_TO_SEND;
	bw_vars->next_to_send = 0;
	bw_vars->window_first = 0;
	bw_vars->bat_priv = bat_priv;
	bw_vars->last_sent_time = jiffies;
	bw_vars->start_time = jiffies;
	//spin_lock_init(&bw_vars->bw_ack_lock);
	//spin_lock_init(&bw_vars->bw_send_lock);
	list_add(&bw_vars->list, &bat_priv->bw_list);
	//spin_unlock_bh(&bat_priv->bw_list_lock);

	printk ("starting worker. bw_vars->last_sent_time = %lu\n", bw_vars->last_sent_time);
	/*
	if (batadv_bw_queue_delayed_work(bw_vars) == 0){
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_bw_start work already enqueued\n");
	}
	*/

	/* start worker */
	batadv_bw_multiple_send(bat_priv, bw_vars);
out:
	return;
}

static int batadv_bw_queue_delayed_work(struct batadv_bw_vars *bw_vars)
{
	int ret;
	INIT_DELAYED_WORK(&bw_vars->bw_work, fake_worker);
	ret = queue_delayed_work(batadv_event_workqueue, &bw_vars->bw_work,
				 msecs_to_jiffies(BATADV_BW_WORKER_TIMEOUT));
	return ret;
}
