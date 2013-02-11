/*
 * Copyright (C) 2012 B.A.T.M.A.N. contributors:
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
#include "multicast_flow.h"
#include "multicast_tracker.h"
#include "multicast_mla.h"

int batadv_mcast_init(struct batadv_priv *bat_priv)
{
	INIT_DELAYED_WORK(&bat_priv->mcast.tracker_work,
			  batadv_mcast_tracker_timer);

	batadv_mcast_tracker_start(bat_priv);

	return 0;
}

void batadv_mcast_free(struct batadv_priv *bat_priv)
{
	batadv_mcast_flow_table_free(bat_priv);
	batadv_mcast_tracker_stop(bat_priv);
	batadv_mcast_mla_collect_free(&bat_priv->mcast.mla_list);
}
