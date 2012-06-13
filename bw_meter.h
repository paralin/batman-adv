/* Copyright (C) 2012-2013 B.A.T.M.A.N. contributors:
 *
 * Edo Monticelli, Antonio Quartulli
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
 */

#ifndef _NET_BATMAN_ADV_BW_METER_H_
#define _NET_BATMAN_ADV_BW_METER_H_

void batadv_bw_start(struct batadv_socket_client *socket_client, uint8_t *dst,
		     uint32_t test_length);
void batadv_bw_stop(struct batadv_priv *bat_priv, uint8_t *dst,
		    uint8_t return_value);
void batadv_bw_meter_recv(struct batadv_priv *bat_priv, struct sk_buff *skb);

#endif /* _NET_BATMAN_ADV_BW_METER_H_ */
