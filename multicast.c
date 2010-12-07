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
#include "multicast.h"

/* how long to wait until sending a multicast tracker packet */
static int tracker_send_delay(struct bat_priv *bat_priv)
{
	int tracker_interval = atomic_read(&bat_priv->mcast_tracker_interval);

	/* auto mode, set to 1/2 ogm interval */
	if (!tracker_interval)
		tracker_interval = atomic_read(&bat_priv->orig_interval) / 2;

	/* multicast tracker packets get half as much jitter as ogms as they're
	 * limited down to JITTER and not JITTER*2 */
	return msecs_to_jiffies(tracker_interval -
		   JITTER/2 + (random32() % JITTER));
}

static void start_mcast_tracker(struct bat_priv *bat_priv)
{
        // adding some jitter
        unsigned long tracker_interval = tracker_send_delay(bat_priv);
        queue_delayed_work(bat_event_workqueue, &bat_priv->mcast_tracker_work,
                                tracker_interval);
}

static void stop_mcast_tracker(struct bat_priv *bat_priv)
{
        cancel_delayed_work_sync(&bat_priv->mcast_tracker_work);
}

void mcast_tracker_reset(struct bat_priv *bat_priv)
{
	stop_mcast_tracker(bat_priv);
	start_mcast_tracker(bat_priv);
}

static void mcast_tracker_timer(struct work_struct *work)
{
	struct bat_priv *bat_priv = container_of(work, struct bat_priv,
						 mcast_tracker_work.work);

	start_mcast_tracker(bat_priv);
}

int mcast_tracker_interval_set(struct net_device *net_dev, char *buff,
			       size_t count)
{
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	unsigned long new_tracker_interval;
	int cur_tracker_interval;
	int ret;

	ret = strict_strtoul(buff, 10, &new_tracker_interval);

	if (ret && !strncmp(buff, "auto", 4)) {
		new_tracker_interval = 0;
		goto ok;
	}

	else if (ret) {
		bat_info(net_dev, "Invalid parameter for "
			 "'mcast_tracker_interval' setting received: %s\n",
			 buff);
		return -EINVAL;
	}

	if (new_tracker_interval < JITTER) {
		bat_info(net_dev, "New mcast tracker interval too small: %li "
			 "(min: %i or auto)\n", new_tracker_interval, JITTER);
		return -EINVAL;
	}

ok:
	cur_tracker_interval = atomic_read(&bat_priv->mcast_tracker_interval);

	if (cur_tracker_interval == new_tracker_interval)
		return count;

	if (!cur_tracker_interval && new_tracker_interval)
		bat_info(net_dev, "Tracker interval change from: %s to: %li\n",
			 "auto", new_tracker_interval);
	else if (cur_tracker_interval && !new_tracker_interval)
		bat_info(net_dev, "Tracker interval change from: %i to: %s\n",
			 cur_tracker_interval, "auto");
	else
		bat_info(net_dev, "Tracker interval change from: %i to: %li\n",
			 cur_tracker_interval, new_tracker_interval);

	atomic_set(&bat_priv->mcast_tracker_interval, new_tracker_interval);

	mcast_tracker_reset(bat_priv);

	return count;
}

int mcast_tracker_timeout_set(struct net_device *net_dev, char *buff,
			       size_t count)
{
	struct bat_priv *bat_priv = netdev_priv(net_dev);
	unsigned long new_tracker_timeout;
	int cur_tracker_timeout;
	int ret;

	ret = strict_strtoul(buff, 10, &new_tracker_timeout);

	if (ret && !strncmp(buff, "auto", 4)) {
		new_tracker_timeout = 0;
		goto ok;
	}

	else if (ret) {
		bat_info(net_dev, "Invalid parameter for "
			 "'mcast_tracker_timeout' setting received: %s\n",
			 buff);
		return -EINVAL;
	}

	if (new_tracker_timeout < JITTER) {
		bat_info(net_dev, "New mcast tracker timeout too small: %li "
			 "(min: %i or auto)\n", new_tracker_timeout, JITTER);
		return -EINVAL;
	}

ok:
	cur_tracker_timeout = atomic_read(&bat_priv->mcast_tracker_timeout);

	if (cur_tracker_timeout == new_tracker_timeout)
		return count;

	if (!cur_tracker_timeout && new_tracker_timeout)
		bat_info(net_dev, "Tracker timeout change from: %s to: %li\n",
			 "auto", new_tracker_timeout);
	else if (cur_tracker_timeout && !new_tracker_timeout)
		bat_info(net_dev, "Tracker timeout change from: %i to: %s\n",
			 cur_tracker_timeout, "auto");
	else
		bat_info(net_dev, "Tracker timeout change from: %i to: %li\n",
			 cur_tracker_timeout, new_tracker_timeout);

	atomic_set(&bat_priv->mcast_tracker_timeout, new_tracker_timeout);

	return count;
}

int mcast_init(struct bat_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->mcast_tracker_work, mcast_tracker_timer);
	start_mcast_tracker(bat_priv);

	return 1;
}

void mcast_free(struct bat_priv *bat_priv)
{
	stop_mcast_tracker(bat_priv);
}
