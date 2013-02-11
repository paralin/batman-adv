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

#ifndef _NET_BATMAN_ADV_MULTICAST_H_
#define _NET_BATMAN_ADV_MULTICAST_H_

int batadv_mcast_init(struct batadv_priv *bat_priv);
void batadv_mcast_free(struct batadv_priv *bat_priv);

/* from multicast_mla.c */

int batadv_mcast_mla_len(int changes_num);
void batadv_mcast_mla_tt_update(struct batadv_priv *bat_priv);
int batadv_mcast_mla_local_seq_print_text(struct seq_file *seq, void *offset);
#ifdef CONFIG_BATMAN_ADV_MCAST_BRIDGE_SNOOP
int batadv_mcast_mla_bridge_seq_print_text(struct seq_file *seq, void *offset);
#endif

/* from multicast_flow.c */
int batadv_mcast_flow_may_optimize(struct sk_buff *skb,
			      struct batadv_priv *bat_priv);
void batadv_mcast_flow_table_purge(struct batadv_priv *bat_priv);
int batadv_mcast_flow_table_seq_print_text(struct seq_file *seq, void *offset);

/* from multicast_tracker.c */
void batadv_mcast_tracker_reset(struct net_device *net_dev);
int batadv_mcast_tracker_interval_set(struct net_device *net_dev, char *buff,
				      size_t count);
void batadv_mcast_tracker_packet_route(struct sk_buff *skb,
				       struct batadv_priv *bat_priv,
				       int num_redundancy);

/* from multicast_forw.c */
void batadv_mcast_forw_table_purge(struct batadv_priv *bat_priv);
int batadv_mcast_forw_table_timeout_set(struct net_device *net_dev, char *buff,
					size_t count);
int batadv_mcast_forw_send_skb(struct sk_buff *skb,
			       struct batadv_priv *bat_priv);
void batadv_mcast_forw_packet_route(struct sk_buff *skb,
				    struct batadv_priv *bat_priv);
int batadv_mcast_forw_table_seq_print_text(struct seq_file *seq, void *offset);

#endif /* _NET_BATMAN_ADV_MULTICAST_H_ */
