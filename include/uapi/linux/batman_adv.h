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
	__BATADV_ATTR_MAX,
};

#define BATADV_ATTR_MAX (__BATADV_ATTR_MAX - 1)

enum {
	BATADV_CMD_UNSPEC,
	BATADV_CMD_GET_ROUTING_ALGOS,
	BATADV_CMD_GET_MESH_INFO,
	BATADV_CMD_GET_HARDIFS,
	__BATADV_CMD_MAX,
};

#define BATADV_CMD_MAX (__BATADV_CMD_MAX - 1)

#endif /* _UAPI_LINUX_BATMAN_ADV_H_ */
