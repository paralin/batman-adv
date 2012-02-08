/*
 * Copyright (C) 2007-2012 B.A.T.M.A.N. contributors:
 *
 * Martin Hundebøll <martin@hundeboll.net>
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

#ifndef _NET_BATMAN_ADV_NETWORK_BLOCK_OGM_H
#define _NET_BATMAN_ADV_NETWORK_BLOCK_OGM_H

enum {
	BLOCK_ACTION_NONE,
	BLOCK_ACTION_DEL,
	BLOCK_ACTION_DROP,
	BLOCK_ACTION_ALLOW,
};

#define BLOCK_ACTION_DEL_NAME	"del"
#define BLOCK_ACTION_DROP_NAME	"drop"
#define BLOCK_ACTION_ALLOW_NAME	"allow"

#define MAC_ADDR_LEN 17
#define BLOCK_ACTION_MAX_LEN 10

#ifdef CONFIG_BATMAN_ADV_BLOCK_OGM

int batadv_block_file_setup(struct batadv_priv *bat_priv);
int batadv_block_file_cleanup(struct batadv_priv *bat_priv);
bool batadv_block_ogm(struct batadv_hard_iface *hard_iface,
		      const uint8_t *addr);
void batadv_block_check_orig_entry(struct batadv_priv *bat_priv,
				   struct batadv_orig_node *orig_node);

#else /* ifdef CONFIG_BATMAN_ADV_BLOCK_OGM */

#define batadv_block_file_setup(...)		do {} while (0)
#define batadv_block_file_cleanup(...)		do {} while (0)
#define batadv_block_check_orig_entry(...)	{}

static inline bool batadv_block_ogm(struct batadv_hard_iface *hard_iface,
				    const uint8_t *addr)
{
	return false;
}

#endif /* ifdef CONFIG_BATMAN_ADV_BLOCK_OGM */

#endif /* _NET_BATMAN_ADV_NETWORK_BLOCK_OGM_H */
