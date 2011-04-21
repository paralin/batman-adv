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

#ifndef _NET_BATMAN_ADV_MULTICAST_TRACKER_H_
#define _NET_BATMAN_ADV_MULTICAST_TRACKER_H_

struct batadv_dest_entries_list {
	struct list_head list;
	uint8_t dest[6];
	struct batadv_hard_iface *hard_iface;
};

void batadv_mcast_tracker_timer(struct work_struct *work);
void batadv_mcast_tracker_start(struct batadv_priv *bat_priv);
void batadv_mcast_tracker_stop(struct batadv_priv *bat_priv);
void batadv_mcast_tracker_burst(uint8_t *mcast_addr,
				struct batadv_priv *bat_priv);

#endif /* _NET_BATMAN_ADV_MULTICAST_H_ */
