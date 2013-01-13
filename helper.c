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

#include "linux/netlink.h"
#include "net/netlink.h"
#include <net/genetlink.h>
#include "main.h"
#include "hard-interface.h"
#include "soft-interface.h"
#include "originator.h"
#include "send.h"
#include "routing.h"
#include "translation-table.h"
#include "helper.h"

static HLIST_HEAD(batadv_genl_portid_head);

struct batadv_genl_portid {
	struct hlist_node node;
	struct batadv_priv *bat_priv;
	int portid;
};

static bool batadv_hlp_genl_add_portid(struct hlist_head *head,
				struct batadv_priv *bat_priv, int portid)
{
	struct batadv_genl_portid *genl_portid_entry;
	bool ret = false;

	hlist_for_each_entry(genl_portid_entry, head, node) {
		if (genl_portid_entry->portid == portid)
			goto out;
	}

	genl_portid_entry = kmalloc(sizeof(*genl_portid_entry), GFP_KERNEL);
	if (!genl_portid_entry)
		goto out;

	genl_portid_entry->bat_priv = bat_priv;
	genl_portid_entry->portid = portid;
	hlist_add_head(&genl_portid_entry->node, head);
	ret = true;

out:
	return ret;
}

static void batadv_hlp_genl_del_portid(struct hlist_head *head, int portid)
{
	struct batadv_genl_portid *genl_portid_entry;

	hlist_for_each_entry(genl_portid_entry, head, node) {
		if (genl_portid_entry->portid != portid)
			continue;

		hlist_del(&genl_portid_entry->node);
		break;
	}
}

static struct batadv_priv *batadv_hlp_genl_get_priv(struct hlist_head *head,
						    int portid)
{
	struct batadv_priv *bat_priv = NULL;
	struct batadv_genl_portid *genl_portid_entry;

	hlist_for_each_entry(genl_portid_entry, head, node) {
		if (genl_portid_entry->portid != portid)
			continue;

		bat_priv = genl_portid_entry->bat_priv;
		break;
	}

	return bat_priv;
}

static void batadv_hlp_tvlv_container_update(struct batadv_priv *bat_priv,
					     bool enable)
{
	if (enable)
		batadv_tvlv_container_register(bat_priv, BATADV_TVLV_HLP, 1,
					       NULL, 0);
	else
		batadv_tvlv_container_unregister(bat_priv, BATADV_TVLV_HLP, 1);
}

static void batadv_hlp_tvlv_ogm_handler_v1(struct batadv_priv *bat_priv,
					   struct batadv_orig_node *orig,
					   uint8_t flags,
					   void *tvlv_value,
					   uint16_t tvlv_value_len)
{
	if (flags & BATADV_TVLV_HANDLER_OGM_CIFNOTFND)
		orig->capabilities &= ~BATADV_ORIG_CAPA_CAN_HLP;
	else
		orig->capabilities |= BATADV_ORIG_CAPA_CAN_HLP;
}

bool batadv_hlp_check_one_hop(struct batadv_one_hop *one_hop)
{
	return batadv_has_timed_out(one_hop->timestamp, 10000);
}

static void batadv_hlp_one_hop_free_rcu(struct rcu_head *rcu)
{
	struct batadv_one_hop *one_hop;
	struct batadv_helper_entry *helper_entry;
	struct hlist_node *node;

	one_hop = container_of(rcu, struct batadv_one_hop, rcu);

	spin_lock_bh(&one_hop->helpers_lock);
	hlist_for_each_entry_safe(helper_entry, node, &one_hop->helpers, node) {
		hlist_del_rcu(&helper_entry->node);
		kfree_rcu(helper_entry, rcu);
	}
	spin_unlock_bh(&one_hop->helpers_lock);

	kfree(one_hop);
}

static void batadv_hlp_one_hop_free_ref(struct batadv_orig_node *orig_node,
					struct batadv_one_hop *one_hop)
{
	if (atomic_dec_and_test(&one_hop->refcount))
		call_rcu(&one_hop->rcu, batadv_hlp_one_hop_free_rcu);
}

void batadv_hlp_free_orig(struct batadv_orig_node *orig_node,
			  bool (*cb)(struct batadv_one_hop *))
{
	struct batadv_one_hop *one_hop;
	struct hlist_node *node;

	spin_lock_bh(&orig_node->one_hops_lock);
	hlist_for_each_entry_safe(one_hop, node, &orig_node->one_hops, node) {
		if (cb && !cb(one_hop))
			continue;

		hlist_del_rcu(&one_hop->node);
		orig_node->one_hops_count--;
		batadv_hlp_one_hop_free_ref(orig_node, one_hop);
	}
	spin_unlock_bh(&orig_node->one_hops_lock);
}

static struct batadv_one_hop *
batadv_hlp_orig_find_one_hop(struct batadv_orig_node *orig_node,
			     const uint8_t *neigh_addr)
{
	struct batadv_one_hop *one_hop_tmp, *one_hop_out = NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(one_hop_tmp, &orig_node->one_hops, node) {
		if (!batadv_compare_eth(one_hop_tmp->info.addr, neigh_addr))
			continue;

		if (!atomic_inc_not_zero(&one_hop_tmp->refcount))
			break;

		one_hop_out = one_hop_tmp;
		break;
	}
	rcu_read_unlock();

	return one_hop_out;
}

static struct batadv_one_hop *
batadv_hlp_orig_get_one_hop(struct batadv_orig_node *orig_node,
			    struct batadv_neigh_node *neigh_node)
{
	struct batadv_one_hop *one_hop;

	one_hop = batadv_hlp_orig_find_one_hop(orig_node, neigh_node->addr);
	if (one_hop) {
		one_hop->timestamp = jiffies;
		return one_hop;
	}

	one_hop = kmalloc(sizeof(*one_hop), GFP_ATOMIC);
	if (!one_hop)
		goto out;

	if (!atomic_inc_not_zero(&neigh_node->refcount))
		goto out_free;

	memcpy(one_hop->info.addr, neigh_node->addr, ETH_ALEN);
	INIT_HLIST_HEAD(&one_hop->helpers);
	INIT_HLIST_NODE(&one_hop->node);
	spin_lock_init(&one_hop->helpers_lock);
	atomic_set(&one_hop->refcount, 2);
	one_hop->timestamp = jiffies;
	one_hop->helper_count = 0;

	spin_lock_bh(&orig_node->one_hops_lock);
	hlist_add_head(&one_hop->node, &orig_node->one_hops);
	orig_node->one_hops_count++;
	spin_unlock_bh(&orig_node->one_hops_lock);

	goto out;

out_free:
	kfree(one_hop);
	one_hop = NULL;

out:
	return one_hop;
}

static struct batadv_helper_entry *
batadv_hlp_find_helper(struct batadv_one_hop *one_hop, uint8_t *addr)
{
	struct batadv_helper_entry *helper_tmp, *helper_out = NULL;

	rcu_read_lock();
	hlist_for_each_entry_rcu(helper_tmp, &one_hop->helpers, node) {
		if (!batadv_compare_eth(helper_tmp->info.addr, addr))
			continue;

		helper_out = helper_tmp;
		break;
	}
	rcu_read_unlock();

	return helper_out;
}

static void batadv_hlp_add_helper(struct batadv_orig_node *orig_node,
				  struct batadv_one_hop *one_hop,
				  struct batadv_helper_info *helper)
{
	struct batadv_helper_entry *helper_entry;

	helper_entry = batadv_hlp_find_helper(one_hop, helper->addr);
	if (helper_entry) {
		helper_entry->info.tq_total = helper->tq_total;
		helper_entry->timestamp = jiffies;
		return;
	}

	helper_entry = kmalloc(sizeof(*helper_entry), GFP_ATOMIC);
	if (!helper_entry)
		return;

	memcpy(&helper_entry->info, helper, sizeof(helper_entry->info));
	INIT_HLIST_NODE(&helper_entry->node);
	helper_entry->timestamp = jiffies;

	spin_lock_bh(&one_hop->helpers_lock);
	hlist_add_head(&helper_entry->node, &one_hop->helpers);
	one_hop->helper_count++;
	spin_unlock_bh(&one_hop->helpers_lock);

	printk("%hhu (%hhu) is a helper from %hhu to %hhu\n",
	       helper->addr[4], helper->tq_total, one_hop->info.addr[4],
	       orig_node->orig[4]);
}

static void batadv_hlp_read_ogm_helpers(struct batadv_orig_node *orig_node,
					struct batadv_one_hop *one_hop,
					struct batadv_ogm_packet *ogm_packet)
{
	uint8_t i, *buff = (uint8_t *)ogm_packet;
	struct batadv_helper_info *helper;

	buff += BATADV_OGM_HLEN + ntohs(ogm_packet->tvlv_len);
	helper = (struct batadv_helper_info *)buff;

	for (i = 0; i < ogm_packet->helper_num; i++) {
		batadv_hlp_add_helper(orig_node, one_hop, helper);
		helper++;
	}

	ogm_packet->helper_num = 0;
}

int batadv_hlp_write_ogm_helpers(struct sk_buff *skb,
				 struct batadv_priv *bat_priv,
				 const uint8_t *buff,
				 int packet_len)
{
	struct batadv_ogm_packet *ogm_packet;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node;
	struct batadv_one_hop *one_hop;
	struct batadv_helper_info *helper_pos;
	int helper_size;

	ogm_packet = (struct batadv_ogm_packet *)buff;
	orig_node = batadv_orig_hash_find(bat_priv, ogm_packet->orig);

	if (!orig_node) {
		ogm_packet->helper_num = 0;
		goto out;
	}

	/* add the information for the direct link with no helper */
	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node)
		return packet_len;

	/* increment one_hops_count by one to add space for the direct link */
	helper_size = batadv_hlp_len(orig_node->one_hops_count + 1);
	helper_pos = (struct batadv_helper_info *)(buff + packet_len);

	skb_put(skb, helper_size);
	packet_len += helper_size;

	/* add link quality from this node to orig */
	memset(helper_pos->addr, 0, ETH_ALEN);
	helper_pos->tq_total = neigh_node->tq_avg;
	helper_pos->tq_second_hop = 0;
	helper_pos++;
	batadv_neigh_node_free_ref(neigh_node);

	rcu_read_lock();
	hlist_for_each_entry_rcu(one_hop, &orig_node->one_hops, node) {
		memcpy(helper_pos, &one_hop->info, sizeof(*helper_pos));
		helper_pos++;
	}
	rcu_read_unlock();

	ogm_packet->helper_num = orig_node->one_hops_count + 1;

out:
	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	return packet_len;
}

void batadv_hlp_update_orig(struct batadv_priv *bat_priv,
			    struct batadv_orig_node *orig_node,
			    struct batadv_neigh_node *neigh_node,
			    struct batadv_ogm_packet *ogm_packet)
{
	struct batadv_one_hop *one_hop;
	struct batadv_neigh_node *router = NULL;

	if (!(neigh_node->orig_node->capabilities & BATADV_ORIG_CAPA_CAN_HLP))
		goto out;
	if (orig_node->last_real_seqno != ntohl(ogm_packet->seqno))
		goto out;
	if (orig_node->last_ttl != ogm_packet->header.ttl + 1)
		goto out;
	if (!batadv_compare_eth(ogm_packet->orig, ogm_packet->prev_sender))
		goto out;
	router = batadv_orig_node_get_router(orig_node);
	if (!router)
		goto out;
	if (!batadv_compare_eth(orig_node->orig, router->addr))
		goto out;
	if (batadv_compare_eth(orig_node->orig, neigh_node->addr))
		goto out;

	one_hop = batadv_hlp_orig_get_one_hop(orig_node, neigh_node);
	if (!one_hop)
		goto out;

	one_hop->info.tq_total = neigh_node->tq_avg;
	one_hop->info.tq_second_hop = ogm_packet->tq;
	batadv_hlp_read_ogm_helpers(orig_node, one_hop, ogm_packet);
	batadv_hlp_one_hop_free_ref(orig_node, one_hop);

out:
	if (router)
		batadv_neigh_node_free_ref(router);
}

bool batadv_hlp_is_one_hop(struct batadv_priv *bat_priv,
			   const struct ethhdr *ethhdr)
{
	struct batadv_orig_node *orig_node_src = NULL;
	struct batadv_one_hop *one_hop_dst = NULL;
	bool ret = false;

	orig_node_src = batadv_orig_hash_find(bat_priv, ethhdr->h_source);
	if (!orig_node_src)
		goto out;

	one_hop_dst = batadv_hlp_orig_find_one_hop(orig_node_src,
						   ethhdr->h_dest);
	if (!one_hop_dst)
		goto out;

	ret = true;

out:
	if (one_hop_dst)
		batadv_hlp_one_hop_free_ref(orig_node_src, one_hop_dst);

	if (orig_node_src)
		batadv_orig_node_free_ref(orig_node_src);

	return ret;
}

int batadv_hlp_genl_register(struct sk_buff *skb, struct genl_info *info)
{
	struct batadv_priv *bat_priv;
	struct net_device *soft_iface = NULL;
	struct sk_buff *skb_out = NULL;
	void *msg_head = NULL;
	char *ifname;
	int ret = 0;

	if (!info->attrs[BATADV_HLP_A_IFNAME]) {
		ret = -ENOENT;
		goto out;
	}

	ifname = nla_data(info->attrs[BATADV_HLP_A_IFNAME]);
	soft_iface = dev_get_by_name(&init_net, ifname);
	if (!soft_iface) {
		ret = -ENOENT;
		goto out;
	}

	bat_priv = netdev_priv(soft_iface);

	if (bat_priv->genl_portid != 0) {
		ret = -EACCES;
		goto out;
	}

	bat_priv->genl_portid = info->snd_portid;
	batadv_hlp_tvlv_container_update(bat_priv, true);
	batadv_hlp_genl_add_portid(&batadv_genl_portid_head, bat_priv,
				   info->snd_portid);

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_out) {
		ret = -ENOMEM;
		goto out;
	}

	msg_head = genlmsg_put_reply(skb_out, info, &bat_priv->hlp_genl_family, 0,
				     BATADV_HLP_C_REGISTER);
	if (!msg_head) {
		ret = -ENOMEM;
		goto out;
	}

	if (nla_put_u32(skb_out, BATADV_HLP_A_IFINDEX, soft_iface->ifindex)) {
		ret = -ENOMEM;
		goto out;
	}

	genlmsg_end(skb_out, msg_head);
	genlmsg_reply(skb_out, info);
	skb_out = NULL;

out:
	if (soft_iface)
		dev_put(soft_iface);

	if (skb_out)
		kfree_skb(skb_out);

	return 0;
}

int batadv_hlp_genl_get_relays(struct sk_buff *skb, struct genl_info *info)
{
	struct batadv_priv *bat_priv;
	struct net_device *soft_iface = NULL;
	struct batadv_orig_node *orig_node_src = NULL, *orig_node_dst = NULL;
	struct batadv_neigh_node *neigh_node_src = NULL, *neigh_node_dst = NULL;
	struct batadv_one_hop *one_hop = NULL;
	struct sk_buff *skb_out = NULL;
	struct batadv_helper_entry *helper_tmp;
	struct nlattr *rly_list;
	int info_len = sizeof(struct batadv_helper_info), ifindex, ret = ENOENT;
	void *msg_head = NULL;
	char *src, *dst;

	if (!info->attrs[BATADV_HLP_A_IFINDEX])
		goto out;

	ifindex = nla_get_u32(info->attrs[BATADV_HLP_A_IFINDEX]);
	soft_iface = dev_get_by_index(&init_net, ifindex);
	if (!soft_iface)
		goto out;

	bat_priv = netdev_priv(soft_iface);

	src = nla_data(info->attrs[BATADV_HLP_A_SRC]);
	dst = nla_data(info->attrs[BATADV_HLP_A_DST]);

	orig_node_src = batadv_orig_hash_find(bat_priv, src);
	if (!orig_node_src)
		goto out;

	orig_node_dst = batadv_orig_hash_find(bat_priv, dst);
	if (!orig_node_dst)
		goto out;

	neigh_node_src = batadv_orig_node_get_router(orig_node_src);
	if (!neigh_node_src)
		goto out;

	neigh_node_dst = batadv_orig_node_get_router(orig_node_dst);
	if (!neigh_node_dst)
		goto out;

	one_hop = batadv_hlp_orig_find_one_hop(neigh_node_src->orig_node,
					       neigh_node_dst->addr);
	if (!one_hop)
		goto out;

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_out)
		goto out;

	msg_head = genlmsg_put_reply(skb_out, info,
			       &bat_priv->hlp_genl_family, 0,
			       BATADV_HLP_C_GET_RELAYS);
	if (!msg_head)
		goto out;

	if (nla_put(skb_out, BATADV_HLP_A_SRC, ETH_ALEN, src))
		goto out;

	if (nla_put(skb_out, BATADV_HLP_A_DST, ETH_ALEN, dst))
		goto out;

	rly_list = nla_nest_start(skb_out, BATADV_HLP_A_RLY_LIST);
	if (!rly_list)
		goto out;

	rcu_read_lock();
	hlist_for_each_entry_rcu(helper_tmp, &one_hop->helpers, node) {
		if (nla_put(skb_out, BATADV_HLP_RLY_A_INFO, info_len,
			    &helper_tmp->info))
			break;
	}
	rcu_read_unlock();

	nla_nest_end(skb_out, rly_list);
	genlmsg_end(skb_out, msg_head);
	genlmsg_reply(skb_out, info);

	ret = 0;

out:
	if (soft_iface)
		dev_put(soft_iface);

	if (one_hop)
		batadv_hlp_one_hop_free_ref(orig_node_src, one_hop);

	if (orig_node_src)
		batadv_orig_node_free_ref(orig_node_src);

	if (orig_node_dst)
		batadv_orig_node_free_ref(orig_node_dst);

	if (neigh_node_src)
		batadv_neigh_node_free_ref(neigh_node_src);

	if (neigh_node_dst)
		batadv_neigh_node_free_ref(neigh_node_dst);

	return -ret;
}

int batadv_hlp_genl_get_link(struct sk_buff *skb, struct genl_info *info)
{
	struct batadv_priv *bat_priv;
	struct net_device *soft_iface = NULL;
	struct sk_buff *skb_out = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	void *msg_head = NULL;
	int ifindex, ret = ENOENT;
	u8 *addr = nla_data(info->attrs[BATADV_HLP_A_ADDR]);

	if (!info->attrs[BATADV_HLP_A_IFINDEX])
		goto out;

	ifindex = nla_get_u32(info->attrs[BATADV_HLP_A_IFINDEX]);
	soft_iface = dev_get_by_index(&init_net, ifindex);
	if (!soft_iface)
		goto out;

	bat_priv = netdev_priv(soft_iface);

	orig_node = batadv_orig_hash_find(bat_priv, addr);
	if (!orig_node)
		goto out;

	neigh_node = batadv_orig_node_get_router(orig_node);
	if (!neigh_node)
		goto out;

	skb_out = nlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_out)
		goto out;

	msg_head = genlmsg_put_reply(skb_out, info, &bat_priv->hlp_genl_family,
				     0, BATADV_HLP_C_GET_LINK);
	if (!msg_head)
		goto out;

	if (nla_put(skb_out, BATADV_HLP_A_ADDR, ETH_ALEN, addr))
		goto out;

	if (nla_put_u8(skb_out, BATADV_HLP_A_TQ, neigh_node->tq_avg))
		goto out;

	genlmsg_end(skb_out, msg_head);
	genlmsg_reply(skb_out, info);

	ret = 0;

out:
	if (soft_iface)
		dev_put(soft_iface);

	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	if (neigh_node)
		batadv_neigh_node_free_ref(neigh_node);

	return -ret;
}

int batadv_hlp_genl_get_one_hop(struct sk_buff *skb, struct genl_info *info)
{
	struct batadv_priv *bat_priv;
	struct net_device *soft_iface = NULL;
	struct sk_buff *skb_out = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	struct batadv_one_hop *one_hop;
	struct nlattr *hop_list;
	void *msg_head = NULL;
	int info_len = sizeof(struct batadv_helper_info), ifindex, ret = ENOENT;
	u8 *addr = nla_data(info->attrs[BATADV_HLP_A_ADDR]);

	if (!info->attrs[BATADV_HLP_A_IFINDEX])
		goto out;

	ifindex = nla_get_u32(info->attrs[BATADV_HLP_A_IFINDEX]);
	soft_iface = dev_get_by_index(&init_net, ifindex);
	if (!soft_iface)
		goto out;

	bat_priv = netdev_priv(soft_iface);

	orig_node = batadv_orig_hash_find(bat_priv, addr);
	if (!orig_node)
		goto out;

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb_out)
		goto out;

	msg_head = genlmsg_put_reply(skb_out, info,
				     &bat_priv->hlp_genl_family, 0,
				     BATADV_HLP_C_GET_ONE_HOP);
	if (!msg_head)
		goto out;

	if (nla_put(skb_out, BATADV_HLP_A_ADDR, ETH_ALEN, addr))
		goto out;

	hop_list = nla_nest_start(skb_out, BATADV_HLP_A_HOP_LIST);

	rcu_read_lock();
	hlist_for_each_entry_rcu(one_hop, &orig_node->one_hops, node) {
		if (nla_put(skb_out, BATADV_HLP_HOP_A_INFO, info_len,
			    &one_hop->info)) {
			break;
		}
	}
	rcu_read_unlock();

	nla_nest_end(skb_out, hop_list);
	genlmsg_end(skb_out, msg_head);
	genlmsg_reply(skb_out, info);

out:
	if (soft_iface)
		dev_put(soft_iface);

	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	if (neigh_node)
		batadv_neigh_node_free_ref(neigh_node);

	return -ret;
}

#if 0
static struct nla_policy batadv_hlp_genl_hop_policy[BATADV_HLP_HOP_A_NUM] = {
	[BATADV_HLP_HOP_A_UNSPEC] = {
		.type = NLA_UNSPEC,
	},
	[BATADV_HLP_HOP_A_INFO] = {
		.type = NLA_UNSPEC,
		.len = sizeof(struct batadv_helper_info),
	},
};

static struct nla_policy batadv_hlp_genl_rly_policy[BATADV_HLP_RLY_A_NUM] = {
	[BATADV_HLP_RLY_A_UNSPEC] = {
		.type = NLA_UNSPEC,
	},
	[BATADV_HLP_RLY_A_INFO] = {
		.type = NLA_UNSPEC,
		.len = sizeof(struct batadv_helper_info),
	},
};
#endif

static struct nla_policy batadv_hlp_genl_policy[BATADV_HLP_A_NUM] = {
	[BATADV_HLP_A_IFNAME] = {
		.type = NLA_NUL_STRING,
	},
	[BATADV_HLP_A_IFINDEX] = {
		.type = NLA_U32,
	},
	[BATADV_HLP_A_SRC] = {
		.type = NLA_UNSPEC,
		.len = ETH_ALEN,
	},
	[BATADV_HLP_A_DST] = {
		.type = NLA_UNSPEC,
		.len = ETH_ALEN,
	},
	[BATADV_HLP_A_ADDR] = {
		.type = NLA_UNSPEC,
		.len = ETH_ALEN,
	},
	[BATADV_HLP_A_TQ] = {
		.type = NLA_U8,
	},
	[BATADV_HLP_A_HOP_LIST] = {
		.type = NLA_NESTED,
	},
	[BATADV_HLP_A_RLY_LIST] = {
		.type = NLA_NESTED,
	},
};

static struct genl_ops batadv_hlp_genl_ops[] = {
	[BATADV_HLP_C_REGISTER - 1] = {
		.cmd = BATADV_HLP_C_REGISTER,
		.policy = batadv_hlp_genl_policy,
		.doit = batadv_hlp_genl_register,
	},
	[BATADV_HLP_C_GET_RELAYS - 1] = {
		.cmd = BATADV_HLP_C_GET_RELAYS,
		.policy = batadv_hlp_genl_policy,
		.doit = batadv_hlp_genl_get_relays,
	},
	[BATADV_HLP_C_GET_LINK - 1] = {
		.cmd = BATADV_HLP_C_GET_LINK,
		.policy = batadv_hlp_genl_policy,
		.doit = batadv_hlp_genl_get_link,
	},
	[BATADV_HLP_C_GET_ONE_HOP - 1] = {
		.cmd = BATADV_HLP_C_GET_ONE_HOP,
		.policy = batadv_hlp_genl_policy,
		.doit = batadv_hlp_genl_get_one_hop,
	},
};

static int batadv_hlp_netlink_notify(struct notifier_block *nb,
				     unsigned long state, void *_notify)
{
        struct netlink_notify *notify = _notify;
	struct batadv_priv *bat_priv;

        if (state != NETLINK_URELEASE)
                return NOTIFY_DONE;

	bat_priv = batadv_hlp_genl_get_priv(&batadv_genl_portid_head,
					    notify->portid);
	if (!bat_priv)
		return NOTIFY_DONE;

	bat_priv->genl_portid = 0;
	batadv_hlp_tvlv_container_update(bat_priv, false);
	batadv_hlp_genl_del_portid(&batadv_genl_portid_head, notify->portid);

	batadv_info(bat_priv->soft_iface, "userspace released netlink"
	       " socket; switching to sending plain packets\n");

        return NOTIFY_DONE;
}

static struct notifier_block batadv_hlp_netlink_notifier = {
        .notifier_call = batadv_hlp_netlink_notify,
};

int batadv_hlp_init(struct batadv_priv *bat_priv)
{
	struct genl_family *family = &bat_priv->hlp_genl_family;
	char genl_name[] = "batman_adv";

	if (family->id != GENL_ID_GENERATE)
		return 0;

	family->id = GENL_ID_GENERATE;
	memcpy(family->name, genl_name, sizeof(genl_name));
	family->version = 1;
	family->maxattr = BATADV_HLP_A_MAX;

	genl_register_family_with_ops(family, batadv_hlp_genl_ops,
				      ARRAY_SIZE(batadv_hlp_genl_ops));

	netlink_register_notifier(&batadv_hlp_netlink_notifier);
	batadv_tvlv_handler_register(bat_priv, batadv_hlp_tvlv_ogm_handler_v1,
				     NULL, BATADV_TVLV_HLP, 1,
				     BATADV_TVLV_HANDLER_OGM_CIFNOTFND);

	return 0;
}

void batadv_hlp_free(struct batadv_priv *bat_priv)
{
	if (bat_priv->hlp_genl_family.id == GENL_ID_GENERATE)
		return;

	batadv_hlp_genl_del_portid(&batadv_genl_portid_head,
				   bat_priv->genl_portid);
	genl_unregister_family(&bat_priv->hlp_genl_family);
	netlink_unregister_notifier(&batadv_hlp_netlink_notifier);
	bat_priv->hlp_genl_family.id = GENL_ID_GENERATE;
}
