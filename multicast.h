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

/* from multicast_mla.c */

int batadv_mcast_mla_len(int changes_num);
int batadv_mcast_mla_append(struct net_device *soft_iface,
			    unsigned char **packet_buff, int *packet_buff_len,
			    int packet_min_len);
int batadv_mcast_mla_local_seq_print_text(struct seq_file *seq, void *offset);
#ifdef CONFIG_BATMAN_ADV_MCAST_BRIDGE_SNOOP
int batadv_mcast_mla_bridge_seq_print_text(struct seq_file *seq, void *offset);
#endif

#endif /* _NET_BATMAN_ADV_MULTICAST_H_ */
