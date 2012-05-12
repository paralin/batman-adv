/* Copyright (C) 2007-2012 B.A.T.M.A.N. contributors:
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

#ifndef _NET_BATMAN_ADV_RLNC_H_
#define _NET_BATMAN_ADV_RLNC_H_

#ifdef CONFIG_BATMAN_ADV_RLNC

#define BATADV_RLNC_FILE "rlnc"
#define BATADV_RLNC_PACKET_LEN 1600
#define BATADV_RLNC_MIN_PACKET_LEN 100

int batadv_rlnc_setup(struct batadv_priv *bat_priv);
void batadv_rlnc_cleanup(struct batadv_priv *bat_priv);
int batadv_rlnc_skb_add_plain(struct sk_buff *skb,
			       struct batadv_orig_node *orig_node);
bool batadv_rlnc_skb_add_enc(struct sk_buff *skb,
			     struct batadv_priv *bat_priv,
			     enum batadv_rlnc_types type);
bool batadv_rlnc_skb_add_req(struct batadv_priv *bat_priv,
			     struct sk_buff *skb);
bool batadv_rlnc_skb_add_ack(struct batadv_priv *bat_priv,
			     struct sk_buff *skb);
int batadv_rlnc_genl_frame(struct sk_buff *skb, struct genl_info *info);
int batadv_rlnc_genl_block(struct sk_buff *skb, struct genl_info *info);

#else /* CONFIG_BATMAN_ADV_RLNC */

static inline int batadv_rlnc_setup(struct batadv_priv *bat_priv)
{
	return 0;
}

static inline void batadv_rlnc_cleanup(struct batadv_priv *bat_priv)
{
	return;
}

static inline int batadv_rlnc_skb_add_plain(struct sk_buff *skb,
					     struct batadv_orig_node *orig)
{
	return false;
}

static inline bool batadv_rlnc_skb_add_enc(struct sk_buff *skb,
					   struct batadv_priv *bat_priv,
					   enum batadv_rlnc_types type)
{
	return false;
}

static inline bool batadv_rlnc_skb_add_req(struct batadv_priv *bat_priv,
					   struct sk_buff *skb)
{
	return false;
}

static inline int batadv_rlnc_genl_frame(struct sk_buff *skb,
					 struct genl_info *info)
{
	return 0;
}

static inline int batadv_rlnc_genl_block(struct sk_buff *skb,
					 struct genl_info *info)
{
	return 0;
}

#endif /* CONFIG_BATMAN_ADV_RLNC */

#endif /* _NET_BATMAN_ADV_RLNC_H_ */
