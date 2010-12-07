#include "main.h"
#include "send.h"
#include "ndp.h"
#include "soft-interface.h"
#include "originator.h"

void start_ndp_timer(struct batman_if *batman_if)
{
	// adding some jitter
	unsigned long ndp_interval = own_ndp_send_time(batman_if);
	queue_delayed_work(bat_event_workqueue, &batman_if->ndp_wq,
			   ndp_interval - jiffies);
}

void stop_ndp_timer(struct batman_if *batman_if)
{
	cancel_delayed_work_sync(&batman_if->ndp_wq);
}

static void ndp_send(struct work_struct *work)
{
	struct batman_if *batman_if = container_of(work, struct batman_if,
							ndp_wq.work);
	struct bat_priv *bat_priv = netdev_priv(batman_if->soft_iface);
	struct batman_packet_ndp *ndp_packet = (struct batman_packet_ndp*)
						batman_if->ndp_packet_buff;
	int packet_len = sizeof(struct batman_packet_ndp);
	struct neigh_entry *neigh_entry = (struct neigh_entry*)
						(ndp_packet + 1);
	struct neigh_node *neigh_node = NULL;
	struct sk_buff *skb;

	ndp_packet->num_neighbors = 0;

	spin_lock_bh(&batman_if->neigh_list_lock);
	list_for_each_entry(neigh_node, &batman_if->neigh_list, list) {
		if (packet_len + sizeof(struct neigh_entry) > ETH_DATA_LEN)
			break;

		memcpy(neigh_entry->addr, neigh_node->addr, ETH_ALEN);
		neigh_entry->rq = neigh_node->rq;
		ndp_packet->num_neighbors++;
		neigh_entry++;
		packet_len += sizeof(struct neigh_entry);
	}
	spin_unlock_bh(&batman_if->neigh_list_lock);

	ndp_packet->seqno = htonl(atomic_read(&batman_if->ndp_seqno));
	memcpy(ndp_packet->orig, bat_priv->primary_if->net_dev->dev_addr,
	       ETH_ALEN);

	bat_dbg(DBG_BATMAN, bat_priv,
		"batman-adv:Sending ndp packet on interface %s, seqno %d\n",
		batman_if->net_dev, ntohl(ndp_packet->seqno));

	skb = dev_alloc_skb(packet_len + sizeof(struct ethhdr));
	skb_reserve(skb, sizeof(struct ethhdr));

	memcpy(skb_put(skb, packet_len), batman_if->ndp_packet_buff,
	       packet_len);

	send_skb_packet(skb, batman_if, broadcast_addr);

	atomic_inc(&batman_if->ndp_seqno);
	start_ndp_timer(batman_if);
}

int ndp_init(struct batman_if *batman_if)
{
	struct batman_packet_ndp *ndp_packet;

	atomic_set(&batman_if->ndp_interval, 500);
	atomic_set(&batman_if->ndp_seqno, 0);

	batman_if->ndp_packet_buff =
		kmalloc(ETH_DATA_LEN, GFP_ATOMIC);
	if (!batman_if->ndp_packet_buff) {
		printk(KERN_ERR "batman-adv: Can't add "
			"local interface packet (%s): out of memory\n",
			batman_if->net_dev->name);
		goto err;
	}
	memset(batman_if->ndp_packet_buff, 0, batman_if->packet_len);
	ndp_packet = (struct batman_packet_ndp*)
			batman_if->ndp_packet_buff;

	ndp_packet->packet_type = BAT_PACKET_NDP;
	ndp_packet->version = COMPAT_VERSION;

	INIT_LIST_HEAD(&batman_if->neigh_list);
	spin_lock_init(&batman_if->neigh_list_lock);

	INIT_DELAYED_WORK(&batman_if->ndp_wq, ndp_send);

	return 0;
err:
	return 1;
}

void ndp_free(struct batman_if *batman_if)
{
	stop_ndp_timer(batman_if);
	kfree(batman_if->ndp_packet_buff);
}

/* extract my own tq to neighbor from the ndp packet */
uint8_t ndp_fetch_tq(struct batman_packet_ndp *packet,
			 uint8_t *my_if_addr)
{
	struct neigh_entry *neigh_entry = (struct neigh_entry*)(packet + 1);
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

	is_duplicate |= get_bit_status(neigh_node->rq_real_bits,
				       neigh_node->last_rq_seqno,
				       seqno);

	/* if the window moved, set the update flag. */
	need_update |= bit_get_packet(bat_priv, neigh_node->rq_real_bits,
				      seq_diff, 1);
	// TODO: rename TQ_LOCAL_WINDOW_SIZE to RQ_LOCAL...
	neigh_node->rq =
		(bit_packet_count(neigh_node->rq_real_bits) * TQ_MAX_VALUE)
			/ TQ_LOCAL_WINDOW_SIZE;

	if (need_update) {
		bat_dbg(DBG_BATMAN, bat_priv, "batman-adv: ndp: "
			"updating last_seqno of neighbor %pM: old %d, new %d\n",
			neigh_node->addr, neigh_node->last_rq_seqno, seqno);
		neigh_node->last_rq_seqno = seqno;
		// TODO: this is not really an average here,
		// need to change the variable name later
		neigh_node->tq_avg = tq;
		neigh_node->last_valid = jiffies;
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

	INIT_LIST_HEAD(&neigh_node->list);
	memcpy(neigh_node->addr, neigh_addr, ETH_ALEN);
	neigh_node->tq_avg = my_tq;
	neigh_node->last_valid = jiffies;

	// TODO: need to initialise rq-window with seqno here

	return neigh_node;
}

int ndp_update_neighbor(uint8_t my_tq, uint32_t seqno,
			struct batman_if *batman_if, uint8_t *neigh_addr)
{
	struct bat_priv *bat_priv = netdev_priv(batman_if->soft_iface);
	struct neigh_node *neigh_node = NULL, *tmp_neigh_node = NULL;
	int ret = 1;

	spin_lock_bh(&batman_if->neigh_list_lock);
	// old neighbor?
	list_for_each_entry(tmp_neigh_node, &batman_if->neigh_list, list) {
		if (compare_orig(tmp_neigh_node->addr, neigh_addr)) {
			neigh_node = tmp_neigh_node;
			ndp_update_neighbor_lq(my_tq, seqno, neigh_node,
					       bat_priv);
			break;
		}
	}

	// new neighbor?
	if (!neigh_node) {
		neigh_node = ndp_create_neighbor(my_tq, seqno, neigh_addr,
						 bat_priv);
		if (!neigh_node)
			goto ret;

		list_add_tail(&neigh_node->list, &batman_if->neigh_list);
	}

	ret = 0;

ret:
	spin_unlock_bh(&batman_if->neigh_list_lock);
	return ret;
}
