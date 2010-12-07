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

	bat_dbg(DBG_BATMAN, bat_priv,
		"batman-adv:Sending ndp packet on interface %s, seqno %d\n",
		batman_if->net_dev, atomic_read(&batman_if->ndp_seqno));

	atomic_inc(&batman_if->ndp_seqno);
	start_ndp_timer(batman_if);
}

int ndp_init(struct batman_if *batman_if)
{
	atomic_set(&batman_if->ndp_interval, 500);
	atomic_set(&batman_if->ndp_seqno, 0);
	INIT_DELAYED_WORK(&batman_if->ndp_wq, ndp_send);

	return 0;
}

void ndp_free(struct batman_if *batman_if)
{
	stop_ndp_timer(batman_if);
}
