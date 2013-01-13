/* Copyright (C) 2013 B.A.T.M.A.N. contributors:
 *
 * Martin Hundeboll <martin@hundeboll.net>
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

#ifndef _NET_BATMAN_ADV_HELPER_H_
#define _NET_BATMAN_ADV_HELPER_H_

#ifdef CONFIG_BATMAN_ADV_HELPER

int batadv_hlp_init(struct batadv_priv *bat_priv);
void batadv_hlp_free(struct batadv_priv *bat_priv);
void batadv_hlp_update_orig(struct batadv_priv *bat_priv,
			    struct batadv_orig_node *orig_node,
			    struct batadv_neigh_node *neigh_node,
			    struct batadv_ogm_packet *ogm_packet);
bool batadv_hlp_check_one_hop(struct batadv_one_hop *one_hop);
void batadv_hlp_free_orig(struct batadv_orig_node *orig_node,
			  bool (*cb)(struct batadv_one_hop *));
bool batadv_hlp_is_one_hop(struct batadv_priv *bat_priv,
			   const struct ethhdr *ethhdr);
int batadv_hlp_write_ogm_helpers(struct sk_buff *skb,
				 struct batadv_priv *bat_priv,
				 const uint8_t *buff,
				 int packet_len);

static inline int batadv_hlp_len(uint8_t helper_num) {
	return helper_num * sizeof(struct batadv_helper_info);
}

#else /* CONFIG_BATMAN_ADV_HELPER */

static inline int batadv_hlp_init(struct batadv_priv *bat_priv)
{
	return 0;
}

static inline void batadv_hlp_free(struct batadv_priv *bat_priv)
{
	return;
}

static inline void batadv_hlp_update_orig(struct batadv_priv *bat_priv,
					  struct batadv_orig_node *orig_node,
					  struct batadv_neigh_node *neigh_node,
					  struct batadv_ogm_packet *ogm_packet)
{
	return;
}

bool batadv_hlp_check_one_hop(struct batadv_one_hop *one_hop)
{
	return false;
}

void batadv_hlp_free_orig(struct batadv_orig_node *orig_node,
			  int (*cb)(struct batadv_one_hop *))
{
	return;
}

static inline bool batadv_hlp_is_one_hop(struct batadv_priv *bat_priv,
					 const struct ethhdr *ethhdr)
{
	return false;
}

static inline int batadv_iv_ogm_add_helpers(struct sk_buff *skb,
					    struct batadv_priv *bat_priv,
					    const uint8_t *buff,
					    int packet_len)
{
	return packet_len;
}

static inline int batadv_hlp_len(uint8_t helper_num)
{
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_HELPER */

#endif /* _NET_BATMAN_ADV_HELPER_H_ */
