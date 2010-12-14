#include "main.h"
#include "send.h"
#include "ndp.h"

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
	struct batman_packet_ndp *ndp_packet;
	struct sk_buff *skb;

	skb = skb_clone(batman_if->ndp_skb, GFP_ATOMIC);
	ndp_packet = (struct batman_packet_ndp*)skb->data;
	ndp_packet->seqno = htonl(atomic_read(&batman_if->ndp_seqno));
	ndp_packet->num_neighbors = 0;
	memcpy(ndp_packet->orig, bat_priv->primary_if->net_dev->dev_addr,
	       ETH_ALEN);

	bat_dbg(DBG_BATMAN, bat_priv,
		"batman-adv:Sending ndp packet on interface %s, seqno %d\n",
		batman_if->net_dev, ntohl(ndp_packet->seqno));

	send_skb_packet(skb, batman_if, broadcast_addr);

	atomic_inc(&batman_if->ndp_seqno);
	start_ndp_timer(batman_if);
}

int ndp_init(struct batman_if *batman_if)
{
	struct batman_packet_ndp *ndp_packet;

	atomic_set(&batman_if->ndp_interval, 500);
	atomic_set(&batman_if->ndp_seqno, 0);

	batman_if->ndp_skb =
		dev_alloc_skb(ETH_DATA_LEN + sizeof(struct ethhdr));
	if (!batman_if->ndp_skb) {
		printk(KERN_ERR "batman-adv: Can't add "
			"local interface packet (%s): out of memory\n",
			batman_if->net_dev->name);
		goto err;
	}
	skb_reserve(batman_if->ndp_skb, sizeof(struct ethhdr) +
					sizeof(struct batman_packet_ndp));
	ndp_packet = (struct batman_packet_ndp*)
		skb_push(batman_if->ndp_skb, sizeof(struct batman_packet_ndp));
	memset(ndp_packet, 0, sizeof(struct batman_packet_ndp));

	ndp_packet->packet_type = BAT_PACKET_NDP;
	ndp_packet->version = COMPAT_VERSION;

	INIT_DELAYED_WORK(&batman_if->ndp_wq, ndp_send);

	return 0;
err:
	return 1;
}

void ndp_free(struct batman_if *batman_if)
{
	stop_ndp_timer(batman_if);
	dev_kfree_skb(batman_if->ndp_skb);
}
