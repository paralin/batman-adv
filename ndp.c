/*
 * Copyright (C) 2011 B.A.T.M.A.N. contributors:
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
static unsigned long ndp_own_send_time(struct hard_iface *hard_iface)
{
	return jiffies + msecs_to_jiffies(
		   atomic_read(&hard_iface->ndp_interval) -
		   JITTER + (random32() % 2*JITTER));
}

void ndp_start_timer(struct hard_iface *hard_iface)
{
	/* adding some jitter */
	unsigned long ndp_interval = ndp_own_send_time(hard_iface);
	queue_delayed_work(bat_event_workqueue, &hard_iface->ndp_wq,
			   ndp_interval - jiffies);
}

void ndp_stop_timer(struct hard_iface *hard_iface)
{
	cancel_delayed_work_sync(&hard_iface->ndp_wq);
}

static void ndp_send(struct work_struct *work)
{
	struct hard_iface *hard_iface = container_of(work, struct hard_iface,
							ndp_wq.work);
	struct bat_priv *bat_priv = netdev_priv(hard_iface->soft_iface);

	bat_dbg(DBG_BATMAN, bat_priv,
		"Sending ndp packet on interface %s, seqno %d\n",
		hard_iface->net_dev->name,
		atomic_read(&hard_iface->ndp_seqno));

	atomic_inc(&hard_iface->ndp_seqno);
	ndp_start_timer(hard_iface);
}

int ndp_init(struct hard_iface *hard_iface)
{
	INIT_DELAYED_WORK(&hard_iface->ndp_wq, ndp_send);

	return 0;
}

void ndp_free(struct hard_iface *hard_iface)
{
	ndp_stop_timer(hard_iface);
}
