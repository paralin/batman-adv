#include "main.h"
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"
#include "bw_meter.h"

#define BATADV_BW_PACKET_LEN 1400
#define BATADV_BW_WINDOW_SIZE 30
#define BATADV_BW_CLEAN_RECEIVER_TIMEOUT 2000
#define BATADV_BW_TIMEOUT 60
#define BATADV_BW_WORKER_TIMEOUT 30
#define BATADV_BW_RECV_TIMEOUT 1000
#define BATADV_BW_TOTAL_TO_SEND 5000
#define BATADV_BW_MAX_RETRY 3
#define BATADV_BW_FIRST_SEQ 65530

static int batadv_bw_queue_sender_worker(struct batadv_bw_vars *bw_vars);
static int batadv_bw_queue_receiver_worker(struct batadv_bw_vars *bw_vars);

static void batadv_bw_vars_free(struct batadv_bw_vars *bw_vars)
{
	spin_lock_bh(&bw_vars->bat_priv->bw_list_lock);
	list_del(&bw_vars->list);
	spin_unlock_bh(&bw_vars->bat_priv->bw_list_lock);
	kfree(bw_vars);
}

static int batadv_bw_icmp_send(struct batadv_priv *bat_priv,
			       struct sk_buff *skb)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	struct batadv_icmp_packet *icmp_packet;
	int ret = -1;

	icmp_packet = (struct batadv_icmp_packet *)skb->data;
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
			      struct batadv_icmp_packet *icmp_packet,
			      uint16_t seq)
{
	struct sk_buff *skb;
	struct batadv_icmp_packet *icmp_ack;
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
	icmp_ack = (struct batadv_icmp_packet *)
		   skb_put(skb, sizeof(*icmp_ack));
	icmp_ack->header.packet_type = BATADV_ICMP;
	icmp_ack->header.version = BATADV_COMPAT_VERSION;
	icmp_ack->header.ttl = 50;
	icmp_ack->seqno = htons(seq);
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

void batadv_bw_meter_received(struct batadv_priv *bat_priv, struct sk_buff *skb)
{
	struct batadv_bw_vars *bw_vars;
	struct batadv_icmp_packet *icmp_packet;
	struct batadv_socket_client *socket_client;
	uint16_t seqno, window_first_16;
	socket_client = container_of(&bat_priv,
				     struct batadv_socket_client, bat_priv);

	icmp_packet = (struct batadv_icmp_packet *)skb->data;

	/* search/initialize bw_vars struct */
	spin_lock_bh(&bat_priv->bw_list_lock);
	seqno = ntohs(icmp_packet->seqno);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->dst);
	if (!bw_vars) {
		if (seqno != BATADV_BW_FIRST_SEQ) {
			spin_unlock_bh(&bat_priv->bw_list_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: seq != 0 cannot initiate connection\n");
			goto out;
		}
		bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
		if (!bw_vars) {
			spin_unlock_bh(&bat_priv->bw_list_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: meter_received cannot allocate bw_vars\n");
			goto out;
		}
		memcpy(&bw_vars->other_end, &icmp_packet->dst, ETH_ALEN);
		bw_vars->status = RECEIVER;
		bw_vars->window_first = BATADV_BW_FIRST_SEQ;
		bw_vars->bat_priv = bat_priv;
		spin_lock_init(&bw_vars->bw_vars_lock);
		list_add(&bw_vars->list, &bat_priv->bw_list);

		batadv_bw_queue_receiver_worker(bw_vars);

	}

	if (bw_vars->status != RECEIVER) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: dropping packet: connection is not expecting any\n");
		goto out;
	}
	window_first_16 = (uint16_t) bw_vars->window_first;
	spin_unlock_bh(&bat_priv->bw_list_lock);

	/* check if the packet belongs to window */
	spin_lock_bh(&bw_vars->bw_vars_lock);
	if (batadv_seq_before(seqno, window_first_16)) {
		spin_unlock_bh(&bw_vars->bw_vars_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: %d < window_first\n", icmp_packet->seqno);
		goto out; /* TODO send an ack! */
	}

	if (batadv_seq_after(seqno, (uint16_t) (window_first_16 +
						BATADV_BW_WINDOW_SIZE))) {
		spin_unlock_bh(&bw_vars->bw_vars_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: unexpected packet received\n");
		goto out; /* TODO ?? */
	}

	/* packet does belong to the window */
	if (seqno == window_first_16) {
		bw_vars->window_first++;
		bw_vars->last_sent_time = jiffies;
		spin_unlock_bh(&bw_vars->bw_vars_lock);

		batadv_bw_ack_send(socket_client,
				   (struct batadv_icmp_packet *)icmp_packet,
				   seqno);

		/* check for the last packet */
		if (skb->len < BATADV_BW_PACKET_LEN) {
			bw_vars->status = COMPLETED;
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: succesfully completed test with node %02x:%02x:%02x:%02x:%02x:%02x\n",
				   icmp_packet->orig[0], icmp_packet->orig[1],
				   icmp_packet->orig[2], icmp_packet->orig[3],
				   icmp_packet->orig[4], icmp_packet->orig[5]);
		}
	} else {
		spin_unlock_bh(&bw_vars->bw_vars_lock);
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
	struct batadv_icmp_packet *icmp_to_send;
	struct batadv_socket_client *socket_client;
	int ret, bw_packet_len;
	uint16_t window_end, next_to_send;

	ret = -1;
	bw_packet_len = BATADV_BW_PACKET_LEN;
	socket_client = container_of(&bat_priv, struct batadv_socket_client,
				     bat_priv);

	if (!spin_trylock_bh(&bw_vars->bw_send_lock))
		goto out;

	while (1) {
		spin_lock_bh(&bw_vars->bw_window_first_lock);
		window_end = min(bw_vars->window_first + BATADV_BW_WINDOW_SIZE,
				 bw_vars->total_to_send);

		if (!batadv_seq_before(bw_vars->next_to_send, window_end)) {
			spin_unlock_bh(&bw_vars->bw_send_lock);
			spin_unlock_bh(&bw_vars->bw_window_first_lock);
			break;
		}

		bw_vars->last_sent_time = jiffies;
		next_to_send = bw_vars->next_to_send++;
		spin_unlock_bh(&bw_vars->bw_window_first_lock);

		if ((bw_vars->window_first + BATADV_BW_WINDOW_SIZE >=
		     bw_vars->total_to_send) &&
		    bw_vars->next_to_send == (uint16_t)bw_vars->total_to_send) {
			bw_packet_len -= 1;
		}

		skb = dev_alloc_skb(bw_packet_len + ETH_HLEN);
		if (!skb) {
			spin_unlock_bh(&bw_vars->bw_send_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_multiple_send() cannot allocate skb\n");
			goto out;
		}

		/* TODO redefine BW_PACKET_LEN */
		skb_reserve(skb, ETH_HLEN);
		icmp_to_send = (struct batadv_icmp_packet *)
					skb_put(skb, bw_packet_len);

		/* fill the icmp header */
		memcpy(&icmp_to_send->dst, &bw_vars->other_end, ETH_ALEN);
		icmp_to_send->header.version = BATADV_COMPAT_VERSION;
		icmp_to_send->header.packet_type = BATADV_ICMP;
		icmp_to_send->msg_type = BATADV_BW_START;
		icmp_to_send->seqno = htons(next_to_send);
		icmp_to_send->uid = socket_client->index;

		if (batadv_bw_icmp_send(bat_priv, skb) < 0) {
			spin_unlock_bh(&bw_vars->bw_send_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_multiple_send() cannot send_icmp_packet\n");
			goto out;
		}
	}
	ret = 0;
out:
	return ret;
}

void batadv_bw_ack_received(struct batadv_priv *bat_priv,
			    struct sk_buff *skb)
{
	struct batadv_icmp_packet *icmp_packet;
	struct batadv_bw_vars *bw_vars;
	uint16_t seqno, window_end, window_first_16;

	icmp_packet = (struct batadv_icmp_packet *)skb->data;

	/* find the bw_vars */
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->orig);
	spin_unlock_bh(&bat_priv->bw_list_lock);

	if (!bw_vars) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: received an ack not related to an open connection\n");
		goto out;
	}

	/* slide and send fresh packets */
	spin_lock_bh(&bw_vars->bw_window_first_lock);
	seqno = ntohs(icmp_packet->seqno);
	window_first_16 = (uint16_t) bw_vars->window_first;
	window_end = window_first_16 + BATADV_BW_WINDOW_SIZE;
	if (!batadv_seq_after(window_first_16, seqno) &&
	    batadv_seq_before(seqno, bw_vars->next_to_send)) {
		bw_vars->window_first += seqno + 1 - window_first_16;
	} else if (bw_vars->status != ABORTING) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: received unespected ack\n");
	}

	spin_unlock_bh(&bw_vars->bw_window_first_lock);
	batadv_bw_multiple_send(bat_priv, bw_vars);
out:
	return;
}

static void batadv_bw_receiver_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars, bw_work);
	bat_priv = bw_vars->bat_priv;

	if (batadv_has_timed_out(bw_vars->last_sent_time,
				 BATADV_BW_RECV_TIMEOUT)) {
		if (bw_vars->status != COMPLETED) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: more than %dms of inactivity: test will be aborted!\n",
				   BATADV_BW_RECV_TIMEOUT);
		}
		batadv_bw_vars_free(bw_vars);
	} else {
		batadv_bw_queue_receiver_worker(bw_vars);
	}
}
static void batadv_bw_sender_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;
	struct batadv_bw_result *result;
	struct batadv_icmp_packet_rr *icmp_packet_rr;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars, bw_work);
	bat_priv = bw_vars->bat_priv;

	/* if timedout, resend whole window */
	if (batadv_has_timed_out(bw_vars->last_sent_time, BATADV_BW_TIMEOUT)) {
		/* increase resend counters */
		if (bw_vars->window_first == bw_vars->last_resent_window) {
			bw_vars->retry_number += 1;
			if (bw_vars->retry_number > BATADV_BW_MAX_RETRY) {
				bw_vars->window_first = bw_vars->total_to_send;
				bw_vars->status = ABORTING;
			}
		} else {
			bw_vars->retry_number = 0;
		}

		pr_info("RESENDING WHOLE WINDOW %d\n",
			(uint16_t)bw_vars->window_first);
		bw_vars->last_resent_window = bw_vars->window_first;
		bw_vars->next_to_send = bw_vars->window_first;
		batadv_bw_multiple_send(bat_priv, bw_vars);
	}

	/* if not finished, re-enqueue worker */
	if (bw_vars->window_first < bw_vars->total_to_send) {
		if (batadv_bw_queue_sender_worker(bw_vars) == 0) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_start work already enqueued\n");
		}
	/* send the answer to batctl */
	} else {
		icmp_packet_rr = kmalloc(sizeof(*icmp_packet_rr), GFP_ATOMIC);
		icmp_packet_rr->uid = bw_vars->socket_client->index;
		result = (struct batadv_bw_result *)icmp_packet_rr;
		if (bw_vars->status == ABORTING) {
			result->test_time = 0;
			result->total_bytes = 0;
		} else {
			result->test_time = ((long)jiffies -
					     (long)bw_vars->start_time);
			result->total_bytes = BATADV_BW_TOTAL_TO_SEND *
					      BATADV_BW_PACKET_LEN;
		}
		batadv_socket_receive_packet(icmp_packet_rr,
					     sizeof(*icmp_packet_rr));
		batadv_bw_vars_free(bw_vars);
	}
}

static int batadv_bw_queue_sender_worker(struct batadv_bw_vars *bw_vars)
{
	int ret;
	INIT_DELAYED_WORK(&bw_vars->bw_work, batadv_bw_sender_worker);
	ret = queue_delayed_work(batadv_event_workqueue, &bw_vars->bw_work,
				 msecs_to_jiffies(BATADV_BW_WORKER_TIMEOUT));

	return ret;
}

static int batadv_bw_queue_receiver_worker(struct batadv_bw_vars *bw_vars)
{
	int ret;
	INIT_DELAYED_WORK(&bw_vars->bw_work, batadv_bw_receiver_worker);
	ret = queue_delayed_work(batadv_event_workqueue, &bw_vars->bw_work,
				 msecs_to_jiffies(BATADV_BW_RECV_TIMEOUT));

	return ret;
}

void batadv_bw_stop(struct batadv_priv *bat_priv,
		    struct batadv_icmp_packet *icmp_packet)
{
	struct batadv_bw_vars *bw_vars;
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->dst);
	if (!bw_vars) {
		/* TODO notify batctl */
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: trying to interrupt an already over connection\n");
		return;
	}
	spin_unlock_bh(&bat_priv->bw_list_lock);
	spin_lock_bh(&bw_vars->bw_window_first_lock);
	bw_vars->window_first = bw_vars->total_to_send;
	bw_vars->status = ABORTING;
	spin_unlock_bh(&bw_vars->bw_window_first_lock);
}

void batadv_bw_start(struct batadv_socket_client *socket_client,
		     struct batadv_icmp_packet *icmp_packet)
{
	struct batadv_priv *bat_priv = socket_client->bat_priv;
	struct batadv_bw_vars *bw_vars;

	/* find bw_vars */
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->dst);
	if (bw_vars) {
		/* TODO notify batctl */
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: test to or from the same node already ongoing, aborting\n");
		goto out;
	}

	bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
	if (!bw_vars) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_bw_start cannot allocate list elements\n");
		goto out;
	}

	/* initialize bw_vars */
	memcpy(&bw_vars->other_end, &icmp_packet->dst, ETH_ALEN);
	bw_vars->total_to_send = BATADV_BW_TOTAL_TO_SEND + BATADV_BW_FIRST_SEQ;
	bw_vars->window_first = BATADV_BW_FIRST_SEQ;
	bw_vars->next_to_send = BATADV_BW_FIRST_SEQ;
	bw_vars->last_resent_window = 0;
	bw_vars->bat_priv = bat_priv;
	bw_vars->socket_client = socket_client;
	bw_vars->last_sent_time = jiffies;
	bw_vars->start_time = jiffies;
	spin_lock_init(&bw_vars->bw_window_first_lock);
	spin_lock_init(&bw_vars->bw_send_lock);
	list_add(&bw_vars->list, &bat_priv->bw_list);
	spin_unlock_bh(&bat_priv->bw_list_lock);

	/* start worker */
	if (batadv_bw_queue_sender_worker(bw_vars) == 0) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_bw_start work already enqueued\n");
	}

	batadv_bw_multiple_send(bat_priv, bw_vars);
out:
	return;
}
