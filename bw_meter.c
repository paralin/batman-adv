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
#define BATADV_BW_TOTAL_TO_SEND 10000
#define BATADV_BW_MAX_RETRY 3
#define BATADV_BW_FIRST_SEQ 65530

#define batadv_bw_batctl_error_notify(status, uid) \
	batadv_bw_batctl_notify(status, uid, 0)

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
	batadv_bw_stop(bat_priv, icmp_packet->dst, BATADV_BW_DST_UNREACHABLE);

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

/* Returns the next zero position, starting from bit_first. If the end of the
 * bitmap is reached, another find_next is performed starting from the
 * beginning of the bitmap
 */
static int batadv_bw_modular_next_zero_find(struct batadv_bw_vars *bw_vars)
{
	int ret;

	ret = find_next_zero_bit(bw_vars->bw_bits,
				 BATADV_BW_WINDOW_SIZE,
				 (bw_vars->bit_first + 1) %
				 BATADV_BW_WINDOW_SIZE);
	if (ret != BATADV_BW_WINDOW_SIZE)
		return ret;

	ret = find_next_zero_bit(bw_vars->bw_bits,
				 BATADV_BW_WINDOW_SIZE, 0);
	return ret;
}

static void batadv_bw_bit_first_move(struct batadv_bw_vars *bw_vars,
				     uint16_t new_pos)
{
	if (new_pos > BATADV_BW_WINDOW_SIZE) {
		batadv_dbg(BATADV_DBG_BATMAN, bw_vars->bat_priv,
			   "Meter: can't move bit first to inconsistent position\n");
		return;
	}

	do {
		bw_vars->bit_first = (bw_vars->bit_first + 1) %
				     BATADV_BW_WINDOW_SIZE;
		clear_bit(bw_vars->bit_first, bw_vars->bw_bits);
	} while (bw_vars->bit_first != new_pos);
}

static void batadv_bw_window_slide(struct batadv_bw_vars *bw_vars,
				   uint16_t seqno, uint16_t len)
{
	uint16_t window_first_16, diff, bit_seqno, new_position;

	/* check if the packet belongs to window */
	spin_lock_bh(&bw_vars->bw_vars_lock);
	window_first_16 = (uint16_t) bw_vars->window_first;
	diff = seqno - window_first_16;
	bw_vars->last_sent_time = jiffies;

	if (diff >= BATADV_BW_WINDOW_SIZE) {
		spin_unlock_bh(&bw_vars->bw_vars_lock);
		goto out;
	}

	/* check for the last packet */
	if (len < BATADV_BW_PACKET_LEN &&
	    bw_vars->status == BATADV_BW_RECEIVER) {
		bit_seqno = (bw_vars->bit_first + diff) % BATADV_BW_WINDOW_SIZE;
		bw_vars->total_to_send = (bit_seqno + 1) %
					 BATADV_BW_WINDOW_SIZE;
		bw_vars->status = BATADV_BW_LAST_WINDOW;
	}

	/* packet is in order */
	if (diff == 0) {
		new_position = batadv_bw_modular_next_zero_find(bw_vars);

		/* update bw_vars->window_first */
		if (new_position > bw_vars->bit_first)
			bw_vars->window_first += new_position -
						 bw_vars->bit_first;
		else
			bw_vars->window_first += new_position +
						 BATADV_BW_WINDOW_SIZE -
						 bw_vars->bit_first;

		batadv_bw_bit_first_move(bw_vars, new_position);
	}
	/* hole in the window */
	else {
		bit_seqno = (bw_vars->bit_first + diff) % BATADV_BW_WINDOW_SIZE;
		set_bit(bit_seqno, bw_vars->bw_bits);
	}

	if (bw_vars->status == BATADV_BW_LAST_WINDOW &&
	    bw_vars->bit_first == bw_vars->total_to_send) {
		bw_vars->status = BATADV_BW_COMPLETE;
	}

	spin_unlock_bh(&bw_vars->bw_vars_lock);
out:
	return;
}


void batadv_bw_meter_received(struct batadv_priv *bat_priv, struct sk_buff *skb)
{
	struct batadv_bw_vars *bw_vars;
	struct batadv_icmp_packet *icmp_packet;
	struct batadv_socket_client *socket_client;
	uint16_t seqno;

	socket_client = container_of(&bat_priv,
				     struct batadv_socket_client, bat_priv);
	icmp_packet = (struct batadv_icmp_packet *)skb->data;

	/* search/initialize bw_vars struct */
	spin_lock_bh(&bat_priv->bw_list_lock);
	seqno = ntohs(icmp_packet->seqno);
	bw_vars = batadv_bw_list_find(bat_priv, &icmp_packet->orig);
	if (!bw_vars) {
		if (seqno != BATADV_BW_FIRST_SEQ) {
			spin_unlock_bh(&bat_priv->bw_list_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: seqno != BATADV_BW_FIRST_SEQ cannot initiate connection\n");
			goto out;
		}

		bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
		if (!bw_vars) {
			spin_unlock_bh(&bat_priv->bw_list_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: meter_received cannot allocate bw_vars\n");
			goto out;
		}

		memcpy(&bw_vars->other_end, &icmp_packet->orig, ETH_ALEN);
		bw_vars->status = BATADV_BW_RECEIVER;
		bw_vars->window_first = BATADV_BW_FIRST_SEQ;
		bw_vars->bat_priv = bat_priv;
		bw_vars->bw_bits = kmalloc(BITS_TO_LONGS(BATADV_BW_WINDOW_SIZE),
					   GFP_ATOMIC);
		if (!bw_vars->bw_bits) {
			spin_unlock_bh(&bat_priv->bw_list_lock);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: meter_received cannot allocate window_bitmap\n");
			goto out;
		}

		bw_vars->bit_first = 0;
		bitmap_zero(bw_vars->bw_bits, BATADV_BW_WINDOW_SIZE);

		spin_lock_init(&bw_vars->bw_vars_lock);
		list_add(&bw_vars->list, &bat_priv->bw_list);

		batadv_bw_queue_receiver_worker(bw_vars);
	}

	if (bw_vars->status != BATADV_BW_RECEIVER &&
	    bw_vars->status != BATADV_BW_LAST_WINDOW) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: dropping packet: connection is not expecting any\n");
		goto out;
	}

	spin_unlock_bh(&bat_priv->bw_list_lock);
	batadv_bw_window_slide(bw_vars, seqno, skb->len);
	batadv_bw_ack_send(socket_client,
			   (struct batadv_icmp_packet *)icmp_packet,
			   bw_vars->window_first - 1);
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
	char *icmp_to_send_char;
	int ret, bw_packet_len;
	uint16_t window_end, next_to_send;

	ret = -1;
	socket_client = container_of(&bat_priv, struct batadv_socket_client,
				     bat_priv);

	if (!atomic_add_unless(&bw_vars->sending, 1, 1))
		goto out;

	while (1) {
		spin_lock_bh(&bw_vars->bw_vars_lock);
		window_end = min(bw_vars->window_first + BATADV_BW_WINDOW_SIZE,
				 bw_vars->total_to_send);

		if (!batadv_seq_before(bw_vars->next_to_send, window_end)) {
			atomic_dec(&bw_vars->sending);
			spin_unlock_bh(&bw_vars->bw_vars_lock);
			break;
		}

		bw_packet_len = BATADV_BW_PACKET_LEN;
		bw_vars->last_sent_time = jiffies;
		next_to_send = bw_vars->next_to_send++;
		spin_unlock_bh(&bw_vars->bw_vars_lock);

		if ((bw_vars->window_first + BATADV_BW_WINDOW_SIZE >=
		     bw_vars->total_to_send) &&
		    bw_vars->next_to_send == (uint16_t)bw_vars->total_to_send) {
			bw_packet_len -= 1;
		}

		skb = dev_alloc_skb(bw_packet_len + ETH_HLEN);
		if (!skb) {
			atomic_dec(&bw_vars->sending);
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: batadv_bw_multiple_send() cannot allocate skb\n");
			goto out;
		}

		/* TODO redefine BW_PACKET_LEN */
		skb_reserve(skb, ETH_HLEN);
		icmp_to_send_char = skb_put(skb, bw_packet_len);
		icmp_to_send = (struct batadv_icmp_packet *)icmp_to_send_char;

		/* fill the icmp header */
		memcpy(&icmp_to_send->dst, &bw_vars->other_end, ETH_ALEN);
		icmp_to_send->header.version = BATADV_COMPAT_VERSION;
		icmp_to_send->header.packet_type = BATADV_ICMP;
		icmp_to_send->msg_type = BATADV_BW_START;
		icmp_to_send->seqno = htons(next_to_send);
		icmp_to_send->uid = socket_client->index;

		if (batadv_bw_icmp_send(bat_priv, skb) < 0) {
			atomic_dec(&bw_vars->sending);
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
	spin_lock_bh(&bw_vars->bw_vars_lock);
	seqno = ntohs(icmp_packet->seqno);
	window_first_16 = (uint16_t) bw_vars->window_first;
	window_end = window_first_16 + BATADV_BW_WINDOW_SIZE;
	if (!batadv_seq_after(window_first_16, seqno) &&
	    batadv_seq_before(seqno, bw_vars->next_to_send)) {
		bw_vars->window_first += (uint16_t) (seqno + 1 -
						     window_first_16);
	} else if (!batadv_bw_is_error(bw_vars->status)) {
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: received unespected ack\n");
	}

	spin_unlock_bh(&bw_vars->bw_vars_lock);
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
		if (bw_vars->status != BATADV_BW_COMPLETE) {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: more than %dms of inactivity: test will be aborted!\n",
				   BATADV_BW_RECV_TIMEOUT);
		} else {
			batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
				   "Meter: succesfully completed test with node %02x:%02x:%02x:%02x:%02x:%02x\n",
				   bw_vars->other_end[0], bw_vars->other_end[1],
				   bw_vars->other_end[2], bw_vars->other_end[3],
				   bw_vars->other_end[4],
				   bw_vars->other_end[5]);
		}

		batadv_bw_vars_free(bw_vars);
	} else {
		batadv_bw_queue_receiver_worker(bw_vars);
	}
}

static void batadv_bw_batctl_notify(uint8_t status, uint8_t uid,
				    unsigned long int start_time)
{
	struct batadv_bw_result result;

	result.icmp_packet.uid = uid;

	if (!batadv_bw_is_error(status)) {
		result.return_value = BATADV_BW_COMPLETE;
		result.test_time = ((long)jiffies -
				    (long)start_time);
		result.total_bytes = BATADV_BW_TOTAL_TO_SEND *
				      BATADV_BW_PACKET_LEN;
	} else {
		result.return_value = status;
	}

	batadv_socket_receive_packet((struct batadv_icmp_packet_rr *)&result,
				     sizeof(result));
}

static void batadv_bw_sender_worker(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars, bw_work);
	bat_priv = bw_vars->bat_priv;

	/* if timedout, resend whole window */
	if (bw_vars->status == BATADV_BW_SENDER &&
	    batadv_has_timed_out(bw_vars->last_sent_time, BATADV_BW_TIMEOUT)) {
		/* increase resend counters */
		if (bw_vars->window_first == bw_vars->last_resent_window) {
			bw_vars->retry_number += 1;
			if (bw_vars->retry_number > BATADV_BW_MAX_RETRY) {
				bw_vars->window_first = bw_vars->total_to_send;
				bw_vars->status = BATADV_BW_RESEND_LIMIT;
			}
		} else {
			bw_vars->retry_number = 0;
		}

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
	} else {
		batadv_bw_batctl_notify(bw_vars->status,
					bw_vars->socket_client->index,
					bw_vars->start_time);
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
		    uint8_t dst[], uint8_t error_status)
{
	struct batadv_bw_vars *bw_vars;
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, dst);
	if (!bw_vars) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: trying to interrupt an already over connection\n");
		return;
	}
	spin_unlock_bh(&bat_priv->bw_list_lock);
	spin_lock_bh(&bw_vars->bw_vars_lock);
	bw_vars->window_first = bw_vars->total_to_send;
	bw_vars->status = error_status;
	spin_unlock_bh(&bw_vars->bw_vars_lock);
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
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: test to or from the same node already ongoing, aborting\n");
		batadv_bw_batctl_error_notify(BATADV_BW_ALREADY_ONGOING,
					      socket_client->index);
		goto out;
	}

	bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
	if (!bw_vars) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BATMAN, bat_priv,
			   "Meter: batadv_bw_start cannot allocate list elements\n");
		batadv_bw_batctl_error_notify(BATADV_BW_MEMORY_ERROR,
					      socket_client->index);
		goto out;
	}

	/* initialize bw_vars */
	memcpy(&bw_vars->other_end, &icmp_packet->dst, ETH_ALEN);
	bw_vars->total_to_send = BATADV_BW_TOTAL_TO_SEND + BATADV_BW_FIRST_SEQ;
	bw_vars->window_first = BATADV_BW_FIRST_SEQ;
	bw_vars->next_to_send = BATADV_BW_FIRST_SEQ;
	bw_vars->status = BATADV_BW_SENDER;
	bw_vars->last_resent_window = 0;
	bw_vars->bat_priv = bat_priv;
	bw_vars->socket_client = socket_client;
	bw_vars->last_sent_time = jiffies;
	bw_vars->start_time = jiffies;
	atomic_set(&bw_vars->sending, 0);
	spin_lock_init(&bw_vars->bw_vars_lock);
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
