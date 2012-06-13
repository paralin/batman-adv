/* Copyright (C) 2012-2013 B.A.T.M.A.N. contributors:
 *
 * Edo Monticelli, Antonio Quartulli
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
#include "send.h"
#include "hash.h"
#include "originator.h"
#include "hard-interface.h"
#include "bw_meter.h"
#include "icmp_socket.h"
#include "types.h"

/**
 * BATADV_BW_DEF_TEST_LENGTH - Default test length if not specified by the user
 *  in milliseconds
 */
#define BATADV_BW_DEF_TEST_LENGTH 10000
/**
 * BATADV_BW_AWND - Advertised window by the receiver (in bytes)
 */
#define BATADV_BW_AWND (1U << 29)
/**
 * BATADV_BW_RECV_TIMEOUT - Receiver activity timeout. If the receiver does not
 *  get anything for such amount of milliseconds, the connection is killed
 */
#define BATADV_BW_RECV_TIMEOUT 1000
/**
 * BATADV_BW_MAX_RTO - Maximum sender timeout. If the sender RTO gets beyond
 * such amound of milliseconds, the receiver is considered unreachable and the
 * connection is killed
 */
#define BATADV_BW_MAX_RTO 30000
/**
 * BATADV_BW_FIRST_SEQ - First seqno of each session. The number is rather high
 *  in order to immediately trigger a wrap around (test purposes)
 */
#define BATADV_BW_FIRST_SEQ ((uint32_t)-1 - 2000)

/**
 * batadv_bw_cwnd - compute the new cwnd size
 * @base: base cwnd size value
 * @increment: the value to add to base to get the new size
 * @min: minumim cwnd value (usually MSS)
 *
 * Return the new cwnd size and ensures it does not exceed the Advertised
 * Receiver Window size. It is wrap around safe.
 * For details refer to Section 3.1 of RFC5681
 */
static uint32_t batadv_bw_cwnd(uint32_t base, uint32_t increment, uint32_t min)
{
	uint32_t new_size = base + increment;

	/* check for wrap-around */
	if (new_size < base)
		new_size = (uint32_t)ULONG_MAX;

	new_size = min_t(uint32_t, new_size, BATADV_BW_AWND);

	return max_t(uint32_t, new_size, min);
}

static void batadv_bw_batctl_notify(uint8_t status, uint8_t uid,
				    unsigned long start_time,
				    uint32_t total_sent)
{
	struct batadv_icmp_bw_result_packet result;

	result.uid = uid;

	if (!batadv_bw_is_error(status)) {
		result.return_value = BATADV_BW_COMPLETE;
		result.test_time = jiffies_to_msecs(jiffies - start_time);
		result.total_bytes = total_sent;
	} else {
		result.return_value = status;
	}

	batadv_socket_receive_packet(&result, sizeof(result));
}

static void batadv_bw_batctl_error_notify(uint8_t status, uint8_t uid) {
	batadv_bw_batctl_notify(status, uid, 0, 0);
}

/**
 * batadv_bw_vars_free_rcu - clean up and free a bw_vars object
 * @rcu: pointer to the RCU object of the bw_vars structure
 *
 * Clean up the unacked packet list and free the bw_vars object
 */
static void batadv_bw_vars_free_rcu(struct rcu_head *rcu)
{
	struct batadv_bw_vars *bw_vars;
	struct batadv_bw_unacked *un, *safe;

	bw_vars = container_of(rcu, struct batadv_bw_vars, rcu);

	/* lock should not be needed because this object is now out of any
	 * context!
	 */
	spin_lock_bh(&bw_vars->unacked_lock);
	list_for_each_entry_safe(un, safe, &bw_vars->unacked_list, list) {
		list_del(&un->list);
		kfree(un);
	}
	spin_unlock_bh(&bw_vars->unacked_lock);

	kfree(bw_vars);
}

/**
 * batadv_bw_vars_free_ref - decrement the refcount and possibly free the
 *  bw_vars object
 * @bw_vars: the object for which the counter has to be decremented
 */
static void batadv_bw_vars_free_ref(struct batadv_bw_vars *bw_vars)
{
	if (unlikely(atomic_dec_and_test(&bw_vars->refcount)))
		call_rcu(&bw_vars->rcu, batadv_bw_vars_free_rcu);
}

static void batadv_bw_update_rto(struct batadv_bw_vars *bw_vars,
				 uint32_t new_rtt)
{
	long m = new_rtt;

	/* RTT update
	 * Details in Section 2.2 and 2.3 of RFC6298
	 *
	 * It's tricky to understand. Don't lose hair please.
	 * Inspired by tcp_rtt_estimator() tcp_input.c
	 */
	if (bw_vars->srtt != 0) {
		m -= (bw_vars->srtt >> 3); /* m is now error in rtt est */
		bw_vars->srtt += m; /* rtt = 7/8 srtt + 1/8 new */
		if (m < 0)
			m = -m;

		m -= (bw_vars->rttvar >> 2);
		bw_vars->rttvar += m; /* mdev ~= 3/4 rttvar + 1/4 new */
	} else {
		/* first measure getting in */
		bw_vars->srtt = m << 3;	/* take the measured time to be srtt */
		bw_vars->rttvar = m << 1; /* new_rtt / 2 */
	}

	/* rto = srtt + 4 * rttvar.
	 * rttvar is scaled by 4, therefore doesn't need to be multiplied */
	bw_vars->rto = (bw_vars->srtt >> 3) + bw_vars->rttvar;
}

static void batadv_bw_cleanup(struct batadv_priv *bat_priv,
			      struct batadv_bw_vars *bw_vars)
{
	cancel_delayed_work(&bw_vars->finish_work);

	spin_lock_bh(&bw_vars->bat_priv->bw_list_lock);
	hlist_del_rcu(&bw_vars->list);
	spin_unlock_bh(&bw_vars->bat_priv->bw_list_lock);

	atomic_dec(&bw_vars->bat_priv->bw_num);

	/* kill the timer and remove its reference */
	del_timer_sync(&bw_vars->timer);
	/* the worker might have rearmed itself therefore we kill it again. Note
	 * that if the worker should run again before invoking the following
	 * del_timer(), it would not re-arm itself once aain because the status
	 * is OFF now
	 */
	del_timer(&bw_vars->timer);

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Test towards %pM finished..shutting down (reason=%d)\n",
		   bw_vars->other_end, bw_vars->reason);

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Last timing stats: SRTT=%ums RTTVAR=%ums RTO=%ums\n",
		   bw_vars->srtt >> 3, bw_vars->rttvar >> 2, bw_vars->rto);

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Final values: cwnd=%u ss_threshold=%u\n",
		   bw_vars->cwnd, bw_vars->ss_threshold);

	batadv_bw_batctl_notify(bw_vars->reason,
				bw_vars->socket_client->index,
				bw_vars->start_time,
				atomic_read(&bw_vars->tot_sent));

	batadv_bw_vars_free_ref(bw_vars);
}

static void batadv_bw_shutdown(struct batadv_bw_vars *bw_vars, int reason)
{
	if (!atomic_dec_and_test(&bw_vars->sending))
		return;

	bw_vars->reason = reason;
}

/**
 * batadv_bw_reset_receiver_timer - reset the receiver shutdown timer
 * @bw_vars: the private data of the current BW meter session
 *
 * start the receiver shutdown timer or reset it if already started
 */
static void batadv_bw_reset_receiver_timer(struct batadv_bw_vars *bw_vars)
{
	mod_timer(&bw_vars->timer,
		  jiffies + msecs_to_jiffies(BATADV_BW_RECV_TIMEOUT));
}

/**
 * batadv_bw_reset_sender_timer - reschedule the sender timer
 * @bw_vars: the private BW meter data for this session
 *
 * Reschedule the timer using bw_vars->rto as delay
 */
static void batadv_bw_reset_sender_timer(struct batadv_bw_vars *bw_vars)
{
	/* most of the time this function is invoked while normal packet
	 * reception...
	 */
	if (unlikely(atomic_read(&bw_vars->sending) == 0))
		return;

	mod_timer(&bw_vars->timer, jiffies + msecs_to_jiffies(bw_vars->rto));
}

/**
 * batadv_bw_list_find - find a bw_vars object in the global list
 * @bat_priv: the bat priv with all the soft interface information
 * @dst: the other endpoint address to look for
 *
 * Look for a bw_vars object matching dst as end_point and return it after
 * having incremented the refcounter. Return NULL is not found
 */
static struct batadv_bw_vars *batadv_bw_list_find(struct batadv_priv *bat_priv,
						  uint8_t *dst)
{
	struct batadv_bw_vars *pos, *bw_vars = NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(pos, &bat_priv->bw_list, list) {
		/* most of the time this function is invoked during the normal
		 * process..it makes sens to pay more when the session is
		 * finished and to speed the process up during the measurement
		 */
		if (unlikely(!atomic_inc_not_zero(&pos->refcount)))
			continue;

		if (!batadv_compare_eth(pos->other_end, dst))
			continue;

		bw_vars = pos;
		break;
	}
	rcu_read_unlock();

	return bw_vars;
}

/**
 * batadv_bw_send_ack - send an ACK packet
 * @bat_priv: the bat priv with all the soft interface information
 * @dst: the mac address of the destination originator
 * @seq: the sequence number to ACK
 * @timestamp: the timestamp to echo back in the ACK
 *
 * Return 0 on success, a positive integer representing the reason of the
 * failure otherwise
 */
static int batadv_bw_send_ack(struct batadv_priv *bat_priv, uint8_t *dst,
			      uint32_t seq, uint32_t timestamp,
			      int socket_index)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node;
	struct batadv_icmp_bw_packet *icmp;
	struct sk_buff *skb;
	int r, ret;

	orig_node = batadv_orig_hash_find(bat_priv, dst);
	if (unlikely(!orig_node)) {
		ret = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (unlikely(!primary_if)) {
		ret = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}

	skb = netdev_alloc_skb_ip_align(NULL, sizeof(*icmp) + ETH_HLEN);
	if (unlikely(!skb)) {
		ret = BATADV_BW_MEMORY_ERROR;
		goto out;
	}

	skb_reserve(skb, ETH_HLEN);
	icmp = (struct batadv_icmp_bw_packet *)skb_put(skb, sizeof(*icmp));
	icmp->packet_type = BATADV_ICMP;
	icmp->version = BATADV_COMPAT_VERSION;
	icmp->ttl = BATADV_TTL;
	icmp->msg_type = BATADV_BW;
	memcpy(icmp->dst, orig_node->orig, ETH_ALEN);
	memcpy(icmp->orig, primary_if->net_dev->dev_addr, ETH_ALEN);
	icmp->uid = socket_index;

	icmp->subtype = BATADV_BW_ACK;
	icmp->seqno = htonl(seq);
	icmp->timestamp = timestamp;

	/* send the ack */
	r = batadv_send_skb_to_orig(skb, orig_node, NULL);
	if (unlikely(r < 0) || (r == NET_XMIT_DROP)) {
		ret = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}
	ret = 0;

out:
	if (likely(orig_node))
		batadv_orig_node_free_ref(orig_node);
	if (likely(primary_if))
		batadv_hardif_free_ref(primary_if);

	return ret;
}

/**
 * batadv_bw_handle_out_of_order - store an out of order packet
 * @bw_vars: the private data of the current BW meter session
 * @skb: the buffer containing the received packet
 *
 * Store the out of order packet in the unacked list for late processing. This
 * packets are kept in this list so that they can be ACKed at once as soon as
 * all the previous packets have been received
 *
 * Return true if the packed has been successfully processed, false otherwise
 */
static bool batadv_bw_handle_out_of_order(struct batadv_bw_vars *bw_vars,
					  struct sk_buff *skb)
{

	struct batadv_icmp_bw_packet *icmp;
	struct batadv_bw_unacked *un, *new;
	uint32_t payload_len;

	new = kmalloc(sizeof(*new), GFP_ATOMIC);
	if (unlikely(!new))
		return false;

	icmp = (struct batadv_icmp_bw_packet *)skb->data;

	new->seqno = ntohl(icmp->seqno);
	payload_len = skb->len - sizeof(struct batadv_unicast_packet);
	new->len = payload_len;

	spin_lock_bh(&bw_vars->unacked_lock);
	/* if the list is empty immediately attach this new object */
	if (list_empty(&bw_vars->unacked_list)) {
		list_add(&new->list, &bw_vars->unacked_list);
		goto out;
	}

	/* otherwise loop over the list and either drop the packet because this
	 * is a duplicate or store it at the right position.
	 *
	 * The iteration is done in the reverse way because it is likely that
	 * the last received packet (the one being processed now) has a bigger
	 * seqno than all the others already stored.
	 */
	list_for_each_entry_reverse(un, &bw_vars->unacked_list, list) {
		/* check for duplicates */
		if (new->seqno == un->seqno) {
			if (new->len > un->len)
				un->len = new->len;
			kfree(new);
			break;
		}

		/* look for the right position */
		if (batadv_seq_before(new->seqno, un->seqno))
			continue;

		/* as soon as an entry having a bigger seqno is found, the new
		 * one is attached _after_ it. In this way the list is kept in
		 * ascending order
		 */
		list_add_tail(&new->list, &un->list);
		break;
	}
out:
	spin_unlock_bh(&bw_vars->unacked_lock);

	return true;
}

static void batadv_bw_receiver_shutdown(unsigned long arg)
{
	struct batadv_bw_vars *bw_vars = (struct batadv_bw_vars *)arg;
	struct batadv_bw_unacked *un, *safe;
	struct batadv_priv *bat_priv;

	bat_priv = bw_vars->bat_priv;

	/* if there is recent activity rearm the timer */
	if (!batadv_has_timed_out(bw_vars->last_recv_time,
				  BATADV_BW_RECV_TIMEOUT)) {
		/* reset the receiver shutdown timer */
		batadv_bw_reset_receiver_timer(bw_vars);
		return;
	}

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Shutting down for inactivity (more than %dms) from %pM\n",
		   BATADV_BW_RECV_TIMEOUT, bw_vars->other_end);

	spin_lock_bh(&bw_vars->bat_priv->bw_list_lock);
	hlist_del_rcu(&bw_vars->list);
	spin_unlock_bh(&bw_vars->bat_priv->bw_list_lock);

	atomic_dec(&bat_priv->bw_num);

	spin_lock_bh(&bw_vars->unacked_lock);
	list_for_each_entry_safe(un, safe, &bw_vars->unacked_list, list) {
		list_del(&un->list);
		kfree(un);
	}
	spin_unlock_bh(&bw_vars->unacked_lock);

	batadv_bw_vars_free_ref(bw_vars);
}

static struct batadv_bw_vars *
batadv_bw_init_recv(struct batadv_priv *bat_priv,
		    struct batadv_icmp_bw_packet *icmp)
{
	struct batadv_bw_vars *bw_vars;

	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, icmp->orig);
	if (bw_vars)
		goto out_unlock;

	if (!atomic_add_unless(&bat_priv->bw_num, 1, BATADV_BW_MAX_NUM)) {
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: too many ongoing sessions, aborting (RECV)\n");
		goto out_unlock;
	}

	bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
	if (!bw_vars) {
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: meter_received cannot allocate bw_vars\n");
		goto out_unlock;
	}

	memcpy(bw_vars->other_end, icmp->orig, ETH_ALEN);
	bw_vars->status = BATADV_BW_RECEIVER;
	bw_vars->last_recv = BATADV_BW_FIRST_SEQ;
	bw_vars->bat_priv = bat_priv;
	atomic_set(&bw_vars->refcount, 2);

	spin_lock_init(&bw_vars->unacked_lock);
	INIT_LIST_HEAD(&bw_vars->unacked_list);

	hlist_add_head_rcu(&bw_vars->list, &bat_priv->bw_list);

	setup_timer(&bw_vars->timer, batadv_bw_receiver_shutdown,
		    (unsigned long)bw_vars);

	batadv_bw_reset_receiver_timer(bw_vars);

out_unlock:
	spin_unlock_bh(&bat_priv->bw_list_lock);

	return bw_vars;
}

static void batadv_bw_ack_unordered(struct batadv_bw_vars *bw_vars)
{
	struct batadv_bw_unacked *un, *safe;
	uint32_t to_ack;

	if (list_empty(&bw_vars->unacked_list))
		return;

	/* go through the unacked packet list and possibly ACK them as
	 * well
	 */
	spin_lock_bh(&bw_vars->unacked_lock);
	list_for_each_entry_safe(un, safe, &bw_vars->unacked_list, list) {
		/* the list is ordered, therefore it is possible to stop as soon
		 * there is a gap between the last acked seqno and the seqno of
		 * the packet under inspection
		 */
		if (batadv_seq_before(bw_vars->last_recv, un->seqno))
			break;

		to_ack = un->seqno + un->len - bw_vars->last_recv;

		if (batadv_seq_before(bw_vars->last_recv, un->seqno + un->len))
			bw_vars->last_recv += to_ack;

		list_del(&un->list);
		kfree(un);
	}
	spin_unlock_bh(&bw_vars->unacked_lock);
}

/**
 * batadv_bw_recv_msg - process a single data message
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the buffer containing the received packet
 *
 * Process a received BW MSG packet
 */
static void batadv_bw_recv_msg(struct batadv_priv *bat_priv,
			       struct sk_buff *skb)
{
	struct batadv_icmp_bw_packet *icmp;
	struct batadv_bw_vars *bw_vars;
	size_t packet_size;
	uint32_t seqno;

	icmp = (struct batadv_icmp_bw_packet *)skb->data;

	seqno = ntohl(icmp->seqno);
	/* check if this is the first seqno. This means that if the
	 * first packet is lost, the bw meter does not work anymore!
	 */
	if (seqno == BATADV_BW_FIRST_SEQ) {
		bw_vars = batadv_bw_init_recv(bat_priv, icmp);
		if (!bw_vars) {
			batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
				   "Meter: seqno != BATADV_BW_FIRST_SEQ cannot initiate connection\n");
			goto out;
		}
	} else {
		bw_vars = batadv_bw_list_find(bat_priv, icmp->orig);
		if (!bw_vars) {
			batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
				   "Unexpected packet from %pM!\n",
				   icmp->orig);
			goto out;
		}
	}

	if (unlikely(bw_vars->status != BATADV_BW_RECEIVER)) {
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: dropping packet: not expected (status=%u)\n",
			   bw_vars->status);
		goto out;
	}

	bw_vars->last_recv_time = jiffies;

	/* if the packet is a duplicate, it may be the case that an ACK has been
	 * lost. Resend the ACK
	 */
	if (batadv_seq_before(seqno, bw_vars->last_recv))
		goto send_ack;

	/* if the packet is out of order enqueue it */
	if (ntohl(icmp->seqno) != bw_vars->last_recv) {
		/* exit immediately (and do not send any ACK) if the packet has
		 * not been enqueued correctly
		 */
		if (!batadv_bw_handle_out_of_order(bw_vars, skb))
			goto out;

		/* send a duplicate ACK */
		goto send_ack;
	}

	/* if everything was fine count the ACKed bytes */
	packet_size = skb->len - sizeof(struct batadv_unicast_packet);
	bw_vars->last_recv += packet_size;

	/* check if this ordered message filled a gap.... */
	batadv_bw_ack_unordered(bw_vars);

send_ack:
	/* send the ACK. If the received packet was out of order, the ACK that
	 * is going to be sent is a duplicate (the sender will count them and
	 * possibly enter Fast Retransmit as soon as it has reached 3)
	 */
	batadv_bw_send_ack(bat_priv, icmp->orig, bw_vars->last_recv,
			   icmp->timestamp, icmp->uid);
out:
	if (likely(bw_vars))
		batadv_bw_vars_free_ref(bw_vars);

	return;
}

/**
 * batadv_bw_send_msg - send a single message
 * @src: source mac address
 * @dst: destination mac address
 * @seqno: sequence number of this packet
 * @len: length of the entire packet
 *
 * Create and send a single BW Meter message.
 * Return 0 on success, BATADV_BW_DST_UNREACHABLE if the destination is not
 * reachable, BATADV_BW_MEMORY_ERROR if the packet couldn't be allocated
 */
static int batadv_bw_send_msg(uint8_t *src, struct batadv_orig_node *orig_node,
			      uint32_t seqno, size_t len, int socket_index,
			      uint32_t timestamp)
{
	struct batadv_icmp_bw_packet *icmp;
	struct sk_buff *skb;
	int r;

	skb = netdev_alloc_skb_ip_align(NULL, len + ETH_HLEN);
	if (unlikely(!skb))
		return BATADV_BW_MEMORY_ERROR;

	skb_reserve(skb, ETH_HLEN);
	icmp = (struct batadv_icmp_bw_packet *)skb_put(skb, len);

	/* fill the icmp header */
	memcpy(icmp->dst, orig_node->orig, ETH_ALEN);
	memcpy(icmp->orig, src, ETH_ALEN);
	icmp->version = BATADV_COMPAT_VERSION;
	icmp->packet_type = BATADV_ICMP;
	icmp->ttl = BATADV_TTL;
	icmp->msg_type = BATADV_BW;
	icmp->uid = socket_index;

	icmp->subtype = BATADV_BW_MSG;
	icmp->seqno = htonl(seqno);
	icmp->timestamp = timestamp;

	r = batadv_send_skb_to_orig(skb, orig_node, NULL);
	if (r < 0)
		kfree_skb(skb);

	if (r == NET_XMIT_SUCCESS)
		return 0;

	return BATADV_BW_CANT_SEND;
}

static void batadv_bw_sender_finish(struct work_struct *work)
{
	struct delayed_work *delayed_work;
	struct batadv_bw_vars *bw_vars;

	delayed_work = container_of(work, struct delayed_work, work);
	bw_vars = container_of(delayed_work, struct batadv_bw_vars,
			       finish_work);

	batadv_bw_shutdown(bw_vars, BATADV_BW_COMPLETE);
}

static bool batadv_bw_avail(struct batadv_bw_vars *bw_vars,
			    size_t payload_len)
{
	uint32_t win_left, win_limit;

	win_limit = atomic_read(&bw_vars->last_acked) + bw_vars->cwnd;
	win_left = win_limit - bw_vars->last_sent;

	return win_left >= payload_len;
}

static int batadv_bw_send(void *arg)
{
	struct batadv_bw_vars *bw_vars = arg;
	struct batadv_priv *bat_priv = bw_vars->bat_priv;
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node = NULL;
	size_t payload_len, packet_len;
	int err = 0;

	if (unlikely(bw_vars->status != BATADV_BW_SENDER)) {
		err = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}

	orig_node = batadv_orig_hash_find(bat_priv, bw_vars->other_end);
	if (unlikely(!orig_node)) {
		err = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (unlikely(!primary_if)) {
		err = BATADV_BW_DST_UNREACHABLE;
		goto out;
	}

	/* assume that all the hard_interfaces have a correctly
	 * configured MTU, so use the soft_iface MTU as MSS.
	 * This might not be true and in that case the fragmentation
	 * should be used.
	 * Now, try to send the packet as it is
	 */
	payload_len = bat_priv->soft_iface->mtu;
	if (bat_priv->soft_iface->mtu < sizeof(struct batadv_icmp_bw_packet)) {
		err = BATADV_PARAMETER_PROBLEM;
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: batadv_bw_send() MTU too small! Minimum=%zu\n",
			   sizeof(struct batadv_icmp_bw_packet));
		goto out;
	}

	batadv_bw_reset_sender_timer(bw_vars);

	/* init and queue the worker in charge of terminating the test */
	INIT_DELAYED_WORK(&bw_vars->finish_work, batadv_bw_sender_finish);
	queue_delayed_work(batadv_event_workqueue, &bw_vars->finish_work,
			   msecs_to_jiffies(bw_vars->test_length));

	set_current_state(TASK_INTERRUPTIBLE);

	while (atomic_read(&bw_vars->sending) != 0) {
		if (unlikely(!batadv_bw_avail(bw_vars, payload_len))) {
			wait_event_interruptible_timeout(bw_vars->more_bytes,
				 batadv_bw_avail(bw_vars, payload_len),
				 HZ / 10);
			continue;
		}

		__set_current_state(TASK_RUNNING);

		/* to emulate normal unicast traffic, add to the payload len
		 * the size of the unicast header
		 */
		packet_len = payload_len + sizeof(struct batadv_unicast_packet);

		err = batadv_bw_send_msg(primary_if->net_dev->dev_addr,
					 orig_node, bw_vars->last_sent, packet_len,
					 bw_vars->socket_client->index,
					 jiffies_to_msecs(jiffies));

		/* something went wrong during the preparation/transmission */
		if (unlikely(err && err != BATADV_BW_CANT_SEND)) {
			batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
				   "Meter: batadv_bw_send() cannot send packets (%d)\n",
				   err);
			/* ensure nobody else tries to stop the thread now */
			if (atomic_dec_and_test(&bw_vars->sending))
				bw_vars->reason = err;
			break;
		}

		/* right-shift the TWND */
		if (!err)
			bw_vars->last_sent += payload_len;

		if (need_resched())
			schedule();
		else
			cpu_relax();

		set_current_state(TASK_INTERRUPTIBLE);
	}

out:
	if (likely(primary_if))
		batadv_hardif_free_ref(primary_if);
	if (likely(orig_node))
		batadv_orig_node_free_ref(orig_node);

	batadv_bw_cleanup(bat_priv, bw_vars);

	batadv_bw_vars_free_ref(bw_vars);

	do_exit(0);
}

/**
 * batadv_bw_updated_cwnd - update the Congestion Windows
 * @bw_vars: the private data of the current BW meter session
 *
 * 1) if the session is in Slow Start, the CWND has to be increased by 1
 * MSS every unique received ACK
 * 2) if the session is in Congestion Avoidance, the CWND has to be
 * increased by MSS * MSS / CWND for every unique received ACK
 */
static void batadv_bw_update_cwnd(struct batadv_bw_vars *bw_vars, uint32_t mss)
{
	spin_lock_bh(&bw_vars->cwnd_lock);

	/* slow start... */
	if (bw_vars->cwnd <= bw_vars->ss_threshold) {
		bw_vars->dec_cwnd = 0;
		bw_vars->cwnd = batadv_bw_cwnd(bw_vars->cwnd, mss, mss);
		spin_unlock_bh(&bw_vars->cwnd_lock);
		return;
	}

	/* increment CWND at least of 1 (section 3.1 of RFC5681) */
	bw_vars->dec_cwnd += max_t(uint32_t, 1U << 3,
				   ((mss * mss) << 6) / (bw_vars->cwnd << 3));
	if (bw_vars->dec_cwnd < (mss << 3)) {
		spin_unlock_bh(&bw_vars->cwnd_lock);
		return;
	}

	bw_vars->cwnd = batadv_bw_cwnd(bw_vars->cwnd, mss, mss);
	bw_vars->dec_cwnd = 0;

	spin_unlock_bh(&bw_vars->cwnd_lock);
}

/**
 * batadv_bw_recv_ack - ACK receiving function
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the buffer containing the received packet
 *
 * Process a recived BW ACK packet
 */
static void batadv_bw_recv_ack(struct batadv_priv *bat_priv,
			       struct sk_buff *skb)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_icmp_bw_packet *icmp;
	struct batadv_bw_vars *bw_vars;
	size_t packet_len, mss;
	uint32_t rtt, recv_ack, cwnd;

	packet_len = mss = bat_priv->soft_iface->mtu;
	packet_len += sizeof(struct batadv_unicast_packet);

	icmp = (struct batadv_icmp_bw_packet *)skb->data;

	/* find the bw_vars */
	bw_vars = batadv_bw_list_find(bat_priv, icmp->orig);
	if (unlikely(!bw_vars))
		return;

	if (unlikely(atomic_read(&bw_vars->sending) == 0))
		goto out;

	/* old ACK? silently drop it.. */
	if (batadv_seq_before(ntohl(icmp->seqno),
			      (uint32_t)atomic_read(&bw_vars->last_acked)))
		goto out;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (unlikely(!primary_if))
		goto out;

	orig_node = batadv_orig_hash_find(bat_priv, icmp->orig);
	if (unlikely(!orig_node))
		goto out;

	/* update RTO with the new sampled RTT, if any */
	rtt = jiffies_to_msecs(jiffies) - icmp->timestamp;
	if (icmp->timestamp && rtt)
		batadv_bw_update_rto(bw_vars, rtt);

	/* ACK for new data... reset the timer */
	batadv_bw_reset_sender_timer(bw_vars);

	recv_ack = ntohl(icmp->seqno);

	/* check if this ACK is a duplicate */
	if (atomic_read(&bw_vars->last_acked) == recv_ack) {
		atomic_inc(&bw_vars->dup_acks);
		if (atomic_read(&bw_vars->dup_acks) != 3)
			goto out;

		if (recv_ack >= bw_vars->recover)
			goto out;

		/* if this is the third duplicate ACK do Fast Retransmit */
		batadv_bw_send_msg(primary_if->net_dev->dev_addr,
				   orig_node, recv_ack, packet_len,
				   icmp->uid, jiffies_to_msecs(jiffies));

		spin_lock_bh(&bw_vars->cwnd_lock);

		/* Fast Recovery */
		bw_vars->fast_recovery = true;
		/* Set recover to the last outstanding seqno when Fast Recovery
		 * is entered. RFC6582, Section 3.2, step 1
		 */
		bw_vars->recover = bw_vars->last_sent;
		bw_vars->ss_threshold = bw_vars->cwnd >> 1;
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: Fast Recovery, (cur cwnd=%u) ss_thr=%u last_sent=%u recv_ack=%u\n",
			   bw_vars->cwnd, bw_vars->ss_threshold,
			   bw_vars->last_sent, recv_ack);
		bw_vars->cwnd = batadv_bw_cwnd(bw_vars->ss_threshold, 3 * mss,
					       mss);
		bw_vars->dec_cwnd = 0;
		bw_vars->last_sent = recv_ack;

		spin_unlock_bh(&bw_vars->cwnd_lock);
	} else {
		/* count the acked data */
		atomic_add(recv_ack - atomic_read(&bw_vars->last_acked),
			   &bw_vars->tot_sent);
		/* reset the duplicate ACKs counter */
		atomic_set(&bw_vars->dup_acks, 0);

		if (bw_vars->fast_recovery) {
			/* partial ACK */
			if (batadv_seq_before(recv_ack, bw_vars->recover)) {
				/* this is another hole in the window. React
				 * immediately as specified by NewReno (see
				 * Section 3.2 of RFC6582 for details)
				 */
				batadv_bw_send_msg(primary_if->net_dev->dev_addr,
						   orig_node, recv_ack,
						   packet_len, icmp->uid,
						   jiffies_to_msecs(jiffies));
				bw_vars->cwnd = batadv_bw_cwnd(bw_vars->cwnd,
							       mss, mss);
			} else {
				bw_vars->fast_recovery = false;
				/* set cwnd to the value of ss_threshold at the
				 * moment that Fast Recovery was entered.
				 * RFC6582, Section 3.2, step 3
				 */
				cwnd = batadv_bw_cwnd(bw_vars->ss_threshold, 0,
						      mss);
				bw_vars->cwnd = cwnd;
			}
			goto move_twnd;
		}

		if (recv_ack - atomic_read(&bw_vars->last_acked) >= mss)
			batadv_bw_update_cwnd(bw_vars, mss);
move_twnd:
		/* move the Transmit Window */
		atomic_set(&bw_vars->last_acked, recv_ack);
	}

	wake_up(&bw_vars->more_bytes);
out:
	if (likely(primary_if))
		batadv_hardif_free_ref(primary_if);
	if (likely(orig_node))
		batadv_orig_node_free_ref(orig_node);
	if (likely(bw_vars))
		batadv_bw_vars_free_ref(bw_vars);

	return;
}

/**
 * batadv_bw_sender_timeout - timer that fires in case of packet loss
 * @arg: address of the related bw_vars
 *
 * If fired it means that there was packet loss.
 * Switch to Slow Start, set the ss_threshold to half of the current cwnd and
 * reset the cwnd to 3*MSS
 */
static void batadv_bw_sender_timeout(unsigned long arg)
{
	struct batadv_bw_vars *bw_vars = (struct batadv_bw_vars *)arg;
	struct batadv_priv *bat_priv = bw_vars->bat_priv;

	if (atomic_read(&bw_vars->sending) == 0)
		return;

	/* if the user waited long enough...shutdown the test */
	if (unlikely(bw_vars->rto >= BATADV_BW_MAX_RTO)) {
		batadv_bw_shutdown(bw_vars, BATADV_BW_DST_UNREACHABLE);
		return;
	}

	/* RTO exponential backoff
	 * Details in Section 5.5 of RFC6298
	 */
	bw_vars->rto <<= 1;

	spin_lock_bh(&bw_vars->cwnd_lock);

	bw_vars->ss_threshold = bw_vars->cwnd >> 1;
	if (bw_vars->ss_threshold < bat_priv->soft_iface->mtu * 2)
		bw_vars->ss_threshold = bat_priv->soft_iface->mtu * 2;

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Meter: RTO fired during test towards %pM! cwnd=%u new ss_thr=%u, resetting last_sent to %u\n",
		   bw_vars->other_end, bw_vars->cwnd, bw_vars->ss_threshold,
		   atomic_read(&bw_vars->last_acked));

	bw_vars->cwnd = bat_priv->soft_iface->mtu * 3;

	spin_unlock_bh(&bw_vars->cwnd_lock);

	/* resend the non-ACKed packets.. */
	bw_vars->last_sent = atomic_read(&bw_vars->last_acked);
	wake_up(&bw_vars->more_bytes);

	batadv_bw_reset_sender_timer(bw_vars);
}

void batadv_bw_stop(struct batadv_priv *bat_priv, uint8_t *dst,
		    uint8_t error_status)
{
	struct batadv_orig_node *orig_node;
	struct batadv_bw_vars *bw_vars;

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Meter: stopping test towards %pM\n", dst);

	orig_node = batadv_orig_hash_find(bat_priv, dst);
	if (!orig_node)
		return;

	bw_vars = batadv_bw_list_find(bat_priv, orig_node->orig);
	if (!bw_vars) {
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: trying to interrupt an already over connection\n");
		goto out;
	}

	batadv_bw_shutdown(bw_vars, error_status);
	batadv_bw_vars_free_ref(bw_vars);
out:
	batadv_orig_node_free_ref(orig_node);
}

static void batadv_bw_start_worker(struct work_struct *work)
{
	struct batadv_bw_vars *bw_vars;
	struct batadv_priv *bat_priv;
	struct task_struct *kthread;

	bw_vars = container_of(work, struct batadv_bw_vars, start_work);
	bat_priv = bw_vars->bat_priv;

	kthread = kthread_create(batadv_bw_send, bw_vars, "kbatadv_tp_meter");
	if (IS_ERR(kthread)) {
		pr_err("batadv: cannot create tp meter kthread\n");
		batadv_bw_batctl_error_notify(BATADV_BW_MEMORY_ERROR,
					      bw_vars->socket_client->index);
		batadv_bw_vars_free_ref(bw_vars);
		batadv_bw_vars_free_ref(bw_vars);
		return;
	}

	wake_up_process(kthread);
}

void batadv_bw_start(struct batadv_socket_client *socket_client, uint8_t *dst,
		     uint32_t test_length)
{
	struct batadv_priv *bat_priv = socket_client->bat_priv;
	struct batadv_bw_vars *bw_vars;

	/* look for an already existing test towards this node */
	spin_lock_bh(&bat_priv->bw_list_lock);
	bw_vars = batadv_bw_list_find(bat_priv, dst);
	if (bw_vars) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_bw_vars_free_ref(bw_vars);
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: test to or from the same node already ongoing, aborting\n");
		batadv_bw_batctl_error_notify(BATADV_BW_ALREADY_ONGOING,
					      socket_client->index);
		return;
	}

	if (!atomic_add_unless(&bat_priv->bw_num, 1, BATADV_BW_MAX_NUM)) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: too many ongoing sessions, aborting (SEND)\n");
		batadv_bw_batctl_error_notify(BATADV_BW_TOO_MANY,
					      socket_client->index);
		return;
	}

	bw_vars = kmalloc(sizeof(*bw_vars), GFP_ATOMIC);
	if (!bw_vars) {
		spin_unlock_bh(&bat_priv->bw_list_lock);
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Meter: batadv_bw_start cannot allocate list elements\n");
		batadv_bw_batctl_error_notify(BATADV_BW_MEMORY_ERROR,
					      socket_client->index);
		return;
	}

	/* initialize bw_vars */
	memcpy(bw_vars->other_end, dst, ETH_ALEN);
	atomic_set(&bw_vars->refcount, 2);
	bw_vars->status = BATADV_BW_SENDER;
	atomic_set(&bw_vars->sending, 1);

	bw_vars->last_sent = BATADV_BW_FIRST_SEQ;
	atomic_set(&bw_vars->last_acked, BATADV_BW_FIRST_SEQ);
	bw_vars->fast_recovery = false;
	bw_vars->recover = BATADV_BW_FIRST_SEQ;

	/* initialise the CWND to 3*MSS (Section 3.1 in RFC5681).
	 * For batman-adv the MSS is the size of the payload received by the
	 * soft_interface, hence its MTU
	 */
	bw_vars->cwnd = bat_priv->soft_iface->mtu * 3;
	/* at the beginning initialise the SS threshold to the biggest possible
	 * window size, hence the AWND size
	 */
	bw_vars->ss_threshold = BATADV_BW_AWND;

	/* RTO initial value is 3 seconds.
	 * Details in Section 2.1 of RFC6298
	 */
	bw_vars->rto = 1000;
	bw_vars->srtt = 0;
	bw_vars->rttvar = 0;

	atomic_set(&bw_vars->tot_sent, 0);

	setup_timer(&bw_vars->timer, batadv_bw_sender_timeout,
		    (unsigned long)bw_vars);

	bw_vars->bat_priv = bat_priv;
	bw_vars->socket_client = socket_client;
	bw_vars->start_time = jiffies;

	init_waitqueue_head(&bw_vars->more_bytes);
	init_completion(&bw_vars->done);

	spin_lock_init(&bw_vars->unacked_lock);
	INIT_LIST_HEAD(&bw_vars->unacked_list);

	spin_lock_init(&bw_vars->cwnd_lock);

	hlist_add_head_rcu(&bw_vars->list, &bat_priv->bw_list);
	spin_unlock_bh(&bat_priv->bw_list_lock);

	bw_vars->test_length = test_length;
	if (!bw_vars->test_length)
		bw_vars->test_length = BATADV_BW_DEF_TEST_LENGTH;

	batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
		   "Meter: starting bandwidth meter towards %pM (length=%ums)\n",
		   dst, test_length);

	/* initialize and queue deferred work. This way the write() call issued
	 * from userspace can happily return and avoid to block
	 */
	INIT_WORK(&bw_vars->start_work, batadv_bw_start_worker);
	queue_work(batadv_event_workqueue, &bw_vars->start_work);
}

/**
 * batadv_bw_meter_recv - main BW Meter receiving function
 * @bat_priv: the bat priv with all the soft interface information
 * @skb: the received packet
 */
void batadv_bw_meter_recv(struct batadv_priv *bat_priv, struct sk_buff *skb)
{
	struct batadv_icmp_bw_packet *icmp;

	icmp = (struct batadv_icmp_bw_packet *)skb->data;

	switch (icmp->subtype) {
	case BATADV_BW_MSG:
		batadv_bw_recv_msg(bat_priv, skb);
		break;
	case BATADV_BW_ACK:
		batadv_bw_recv_ack(bat_priv, skb);
		break;
	default:
		batadv_dbg(BATADV_DBG_BW_METER, bat_priv,
			   "Received unknown BW Metric packet type %u\n",
			   icmp->subtype);
	}
	consume_skb(skb);
}
