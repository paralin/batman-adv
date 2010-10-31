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

#ifndef _NET_BATMAN_ADV_MULTICAST_FORW_H_
#define _NET_BATMAN_ADV_MULTICAST_FORW_H_

void batadv_mcast_forw_if_entry_prep(struct hlist_head *forw_if_list,
				     int16_t if_num,
				     uint8_t *neigh_addr);
struct hlist_head *batadv_mcast_forw_table_entry_prep(
				struct hlist_head *forw_table,
				uint8_t *mcast_addr, uint8_t *orig);
void batadv_mcast_forw_table_update(struct hlist_head *forw_table,
				    struct batadv_priv *bat_priv);

#endif /* _NET_BATMAN_ADV_MULTICAST_FORW_H_ */
