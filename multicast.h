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

#ifndef _NET_BATMAN_ADV_MULTICAST_H_
#define _NET_BATMAN_ADV_MULTICAST_H_

int mcast_tracker_interval_set(struct net_device *net_dev, char *buff,
			       size_t count);
int mcast_tracker_timeout_set(struct net_device *net_dev, char *buff,
			       size_t count);
void mcast_tracker_reset(struct bat_priv *bat_priv);
int mcast_may_optimize(uint8_t *dest, struct net_device *soft_iface);
void route_mcast_tracker_packet(
			struct mcast_tracker_packet *tracker_packet,
			int tracker_packet_len, struct bat_priv *bat_priv);
void purge_mcast_forw_table(struct bat_priv *bat_priv);
int mcast_forw_table_seq_print_text(struct seq_file *seq, void *offset);
void route_mcast_packet(struct sk_buff *skb, struct bat_priv *bat_priv);
int mcast_send_skb(struct sk_buff *skb, struct bat_priv *bat_priv);
int mcast_init(struct bat_priv *bat_priv);
void mcast_free(struct bat_priv *bat_priv);

#endif /* _NET_BATMAN_ADV_MULTICAST_H_ */
