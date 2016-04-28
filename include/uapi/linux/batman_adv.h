/* Copyright (C) 2016 B.A.T.M.A.N. contributors:
 *
 * Matthias Schiffer
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _UAPI_LINUX_BATMAN_ADV_H_
#define _UAPI_LINUX_BATMAN_ADV_H_

#define BATADV_NL_NAME "batadv"

/**
 * enum batadv_tt_client_flags - TT client specific flags
 * @BATADV_TT_CLIENT_DEL: the client has to be deleted from the table
 * @BATADV_TT_CLIENT_ROAM: the client roamed to/from another node and the new
 *  update telling its new real location has not been received/sent yet
 * @BATADV_TT_CLIENT_WIFI: this client is connected through a wifi interface.
 *  This information is used by the "AP Isolation" feature
 * @BATADV_TT_CLIENT_ISOLA: this client is considered "isolated". This
 *  information is used by the Extended Isolation feature
 * @BATADV_TT_CLIENT_NOPURGE: this client should never be removed from the table
 * @BATADV_TT_CLIENT_NEW: this client has been added to the local table but has
 *  not been announced yet
 * @BATADV_TT_CLIENT_PENDING: this client is marked for removal but it is kept
 *  in the table for one more originator interval for consistency purposes
 * @BATADV_TT_CLIENT_TEMP: this global client has been detected to be part of
 *  the network but no nnode has already announced it
 *
 * Bits from 0 to 7 are called _remote flags_ because they are sent on the wire.
 * Bits from 8 to 15 are called _local flags_ because they are used for local
 * computations only.
 *
 * Bits from 4 to 7 - a subset of remote flags - are ensured to be in sync with
 * the other nodes in the network. To achieve this goal these flags are included
 * in the TT CRC computation.
 */
enum batadv_tt_client_flags {
	BATADV_TT_CLIENT_DEL     = (1 << 0),
	BATADV_TT_CLIENT_ROAM    = (1 << 1),
	BATADV_TT_CLIENT_WIFI    = (1 << 4),
	BATADV_TT_CLIENT_ISOLA	 = (1 << 5),
	BATADV_TT_CLIENT_NOPURGE = (1 << 8),
	BATADV_TT_CLIENT_NEW     = (1 << 9),
	BATADV_TT_CLIENT_PENDING = (1 << 10),
	BATADV_TT_CLIENT_TEMP	 = (1 << 11),
};

enum {
	BATADV_ATTR_UNSPEC,
	BATADV_ATTR_VERSION,
	BATADV_ATTR_ALGO_NAME,
	BATADV_ATTR_MESH_IFINDEX,
	BATADV_ATTR_MESH_IFNAME,
	BATADV_ATTR_MESH_ADDRESS,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_HARD_IFNAME,
	BATADV_ATTR_HARD_ADDRESS,
	BATADV_ATTR_ACTIVE,
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_TT_TTVN,
	BATADV_ATTR_TT_LAST_TTVN,
	BATADV_ATTR_TT_CRC32,
	BATADV_ATTR_TT_VID,
	BATADV_ATTR_TT_FLAGS,
	BATADV_ATTR_FLAG_BEST,
	BATADV_ATTR_LAST_SEEN_MSECS,
	__BATADV_ATTR_MAX,
};

#define BATADV_ATTR_MAX (__BATADV_ATTR_MAX - 1)

enum {
	BATADV_CMD_UNSPEC,
	BATADV_CMD_GET_ROUTING_ALGOS,
	BATADV_CMD_GET_MESH_INFO,
	BATADV_CMD_GET_HARDIFS,
	BATADV_CMD_GET_TRANSTABLE_LOCAL,
	BATADV_CMD_GET_TRANSTABLE_GLOBAL,
	__BATADV_CMD_MAX,
};

#define BATADV_CMD_MAX (__BATADV_CMD_MAX - 1)

#endif /* _UAPI_LINUX_BATMAN_ADV_H_ */
