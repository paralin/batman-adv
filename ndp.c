/*
 * Copyright (C) 2010 B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing
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
 *
 */

#include "main.h"
#include "send.h"
#include "ndp.h"

/* when do we schedule our own neighbor discovery packet to be sent */
static unsigned long own_ndp_send_time(struct batman_if *batman_if)
{
	return jiffies + msecs_to_jiffies(
		   atomic_read(&batman_if->ndp_interval) -
		   JITTER + (random32() % 2*JITTER));
}

void ndp_start_timer(struct batman_if *batman_if)
{
	/* adding some jitter */
	unsigned long ndp_interval = own_ndp_send_time(batman_if);
	queue_delayed_work(bat_event_workqueue, &batman_if->ndp_wq,
			   ndp_interval - jiffies);
}

void ndp_stop_timer(struct batman_if *batman_if)
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
	ndp_start_timer(batman_if);
}

int ndp_init(struct batman_if *batman_if)
{
	INIT_DELAYED_WORK(&batman_if->ndp_wq, ndp_send);

	return 0;
}

void ndp_free(struct batman_if *batman_if)
{
	ndp_stop_timer(batman_if);
}
