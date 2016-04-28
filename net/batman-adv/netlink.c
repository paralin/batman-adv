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

#include "main.h"
#include "netlink.h"

#include <linux/netdevice.h>
#include <net/sock.h>
#include <uapi/linux/batman_adv.h>

#include "hard-interface.h"
#include "originator.h"
#include "soft-interface.h"
#include "translation-table.h"

struct genl_family batadv_netlink_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = BATADV_NL_NAME,
	.version = 1,
	.maxattr = BATADV_ATTR_MAX,
};

static int
batadv_netlink_mesh_info_put(struct sk_buff *msg, struct net_device *soft_iface)
{
	int ret = -ENOBUFS;
	struct batadv_priv *bat_priv = netdev_priv(soft_iface);
	struct batadv_hard_iface *primary_if = NULL;
	struct net_device *hard_iface;

	if (nla_put_string(msg, BATADV_ATTR_VERSION, BATADV_SOURCE_VERSION) ||
	    nla_put_string(msg, BATADV_ATTR_ALGO_NAME,
			   bat_priv->bat_algo_ops->name) ||
	    nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, soft_iface->ifindex) ||
	    nla_put_string(msg, BATADV_ATTR_MESH_IFNAME, soft_iface->name) ||
	    nla_put(msg, BATADV_ATTR_MESH_ADDRESS, ETH_ALEN,
		    soft_iface->dev_addr))
		goto out;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (primary_if && primary_if->if_status == BATADV_IF_ACTIVE) {
		hard_iface = primary_if->net_dev;

		if (nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
				hard_iface->ifindex) ||
		    nla_put_string(msg, BATADV_ATTR_HARD_IFNAME,
				   hard_iface->name) ||
		    nla_put(msg, BATADV_ATTR_HARD_ADDRESS, ETH_ALEN,
			    hard_iface->dev_addr))
			goto out;
	}

	ret = 0;

 out:
	if (primary_if)
		batadv_hardif_put(primary_if);

	return ret;
}

static int
batadv_netlink_get_mesh_info(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	int ret;
	struct sk_buff *msg = NULL;
	void *msg_head;
	int ifindex;
	struct net_device *soft_iface;

	if (!info->attrs[BATADV_ATTR_MESH_IFINDEX])
		return -EINVAL;

	ifindex = nla_get_u32(info->attrs[BATADV_ATTR_MESH_IFINDEX]);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface || !batadv_softif_is_valid(soft_iface)) {
		ret = -ENODEV;
		goto out;
	}

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg) {
		ret = -ENOMEM;
		goto out;
	}

	msg_head = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			       &batadv_netlink_family, 0,
			       BATADV_CMD_GET_MESH_INFO);
	if (!msg_head) {
		ret = -ENOBUFS;
		goto out;
	}

	ret = batadv_netlink_mesh_info_put(msg, soft_iface);

 out:
	if (soft_iface)
		dev_put(soft_iface);

	if (ret) {
		if (msg)
			nlmsg_free(msg);
		return ret;
	}

	genlmsg_end(msg, msg_head);
	return genlmsg_reply(msg, info);
}

static int
batadv_netlink_dump_hardif_entry(struct sk_buff *msg, u32 portid, u32 seq,
				 struct batadv_hard_iface *hard_iface)
{
	struct net_device *net_dev = hard_iface->net_dev;
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &batadv_netlink_family, NLM_F_MULTI,
			  BATADV_CMD_GET_HARDIFS);
	if (!hdr)
		return -EMSGSIZE;

	if (nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX,
			net_dev->ifindex) ||
	    nla_put_string(msg, BATADV_ATTR_HARD_IFNAME,
			   net_dev->name) ||
	    nla_put(msg, BATADV_ATTR_HARD_ADDRESS, ETH_ALEN,
		    net_dev->dev_addr))
		goto nla_put_failure;

	if (hard_iface->if_status == BATADV_IF_ACTIVE) {
		if (nla_put_flag(msg, BATADV_ATTR_ACTIVE))
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);
	return 0;

 nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int
batadv_netlink_dump_hardifs(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct net *net = sock_net(cb->skb->sk);
	struct net_device *soft_iface;
	struct batadv_hard_iface *hard_iface;
	int ifindex;
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	int skip = cb->args[0];
	int i = 0;

	ifindex = batadv_netlink_get_ifindex(cb->nlh, BATADV_ATTR_MESH_IFINDEX);
	if (!ifindex)
		return -EINVAL;

	soft_iface = dev_get_by_index(net, ifindex);
	if (!soft_iface)
		return -ENODEV;

	if (!batadv_softif_is_valid(soft_iface)) {
		dev_put(soft_iface);
		return -ENODEV;
	}

	rcu_read_lock();

	list_for_each_entry_rcu(hard_iface, &batadv_hardif_list, list) {
		if (hard_iface->soft_iface != soft_iface)
			continue;

		if (i++ < skip)
			continue;

		if (batadv_netlink_dump_hardif_entry(msg, portid, seq,
						     hard_iface)) {
			i--;
			break;
		}
	}

	rcu_read_unlock();

	dev_put(soft_iface);

	cb->args[0] = i;

	return msg->len;
}

static struct nla_policy batadv_netlink_policy[BATADV_ATTR_MAX + 1] = {
	[BATADV_ATTR_MESH_IFINDEX]	= { .type = NLA_U32 },
};

static struct genl_ops batadv_netlink_ops[] = {
	{
		.cmd = BATADV_CMD_GET_ROUTING_ALGOS,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.dumpit = batadv_algo_dump,
	},
	{
		.cmd = BATADV_CMD_GET_MESH_INFO,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.doit = batadv_netlink_get_mesh_info,
	},
	{
		.cmd = BATADV_CMD_GET_HARDIFS,
		.flags = GENL_ADMIN_PERM,
		.policy = batadv_netlink_policy,
		.dumpit = batadv_netlink_dump_hardifs,
	},
};

void __init batadv_netlink_register(void)
{
	int ret;

	ret = genl_register_family_with_ops(&batadv_netlink_family,
					    batadv_netlink_ops);
	if (ret)
		pr_warn("unable to register netlink family");
}

void batadv_netlink_unregister(void)
{
	genl_unregister_family(&batadv_netlink_family);
}
