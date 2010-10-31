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
