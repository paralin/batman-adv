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

#include <linux/debugfs.h>
#include "main.h"
#include "hard-interface.h"
#include "soft-interface.h"
#include "originator.h"
#include "send.h"
#include "routing.h"
#include "rlnc.h"
#include "helper.h"

int batadv_rlnc_setup(struct batadv_priv *bat_priv)
{
	batadv_recv_handler_register(BATADV_RLNC, batadv_rlnc_recv_skb);
	atomic_set(&bat_priv->hlp_block, 0);

	return 0;
}


void batadv_rlnc_cleanup(struct batadv_priv *bat_priv)
{
}

static bool batadv_rlnc_skb_send_enc(struct batadv_priv *bat_priv,
				     struct sk_buff *skb,
				     struct genl_info *info)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_rlnc_packet *pkt;
	struct sk_buff *skb_out = NULL;
	int hdr_len = sizeof(*pkt), subtype, block_id, len;
	bool ret = false;
	u8 *src, *dst, *data;

	if (!info->attrs[BATADV_HLP_A_SRC])
		goto err;

	if (!info->attrs[BATADV_HLP_A_DST])
		goto err;

	if (!info->attrs[BATADV_HLP_A_BLOCK])
		goto err;

	if (!info->attrs[BATADV_HLP_A_FRAME])
		goto err;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		goto err;

	len = nla_len(info->attrs[BATADV_HLP_A_FRAME]);
	skb_out= dev_alloc_skb(ETH_HLEN + hdr_len + len);
	if (!skb_out)
		goto err;
	skb_reserve(skb_out, ETH_HLEN);

	subtype = nla_get_u8(info->attrs[BATADV_HLP_A_TYPE]);
	block_id = nla_get_u16(info->attrs[BATADV_HLP_A_BLOCK]);
	src = nla_data(info->attrs[BATADV_HLP_A_SRC]);
	dst = nla_data(info->attrs[BATADV_HLP_A_DST]);
	data = nla_data(info->attrs[BATADV_HLP_A_FRAME]);

	pkt = (struct batadv_rlnc_packet *)skb_put(skb_out, hdr_len);
	pkt->header.packet_type = BATADV_RLNC;
	pkt->header.version = BATADV_COMPAT_VERSION;
	pkt->header.ttl = BATADV_TTL;
	pkt->subtype = subtype;
	pkt->block_id = block_id;
	memcpy(pkt->src, src, ETH_ALEN);
	memcpy(pkt->dst, dst, ETH_ALEN);
	memcpy(skb_put(skb_out, len), data, len);

	if (atomic_read(&bat_priv->mesh_state) != BATADV_MESH_ACTIVE)
		goto err;

	orig_node = batadv_orig_hash_find(bat_priv, pkt->dst);
	if (!orig_node) {
		goto err;
	}

	switch (subtype) {
	case BATADV_RLNC_RED:
		skb_out->priority = TC_PRIO_INTERACTIVE + 256;
		//pkt->subtype = BATADV_RLNC_ENC;
	case BATADV_RLNC_ENC:
		batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_ENC_TX);
		break;

	case BATADV_RLNC_REC:
		batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_REC_TX);
		break;

	case BATADV_RLNC_HLP:
		batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_HLP_TX);
		break;
	}

	batadv_send_skb_to_orig(skb_out, orig_node, NULL);

	ret = true;

err:
	if (primary_if)
		batadv_hardif_free_ref(primary_if);

	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	return ret;
}

static bool batadv_rlnc_skb_recv_dec(struct batadv_priv *bat_priv,
				     struct sk_buff *skb,
				     struct genl_info *info)
{
	struct batadv_hard_iface *primary_if = NULL;
	struct sk_buff *skb_out = NULL;
	int len = nla_len(info->attrs[BATADV_HLP_A_FRAME]);
	u8 *data = (u8 *)nla_data(info->attrs[BATADV_HLP_A_FRAME]);

	if (!info->attrs[BATADV_HLP_A_FRAME])
		return false;

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		return false;

	skb_out = dev_alloc_skb(len);
	if (!skb_out)
		return false;

	memcpy(skb_put(skb_out, len), data, len);

	batadv_interface_rx(primary_if->soft_iface, skb_out, primary_if, 0,
			    NULL);
	batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_DEC_RX);

	if (primary_if)
		batadv_hardif_free_ref(primary_if);

	return true;
}

static bool batadv_rlnc_skb_send_feedback(struct batadv_priv *bat_priv,
					  struct sk_buff *skb,
					  struct genl_info *info)
{
	struct batadv_orig_node *orig_node = NULL;
	struct sk_buff *skb_out;
	struct batadv_rlnc_packet *rlnc;
	struct batadv_rlnc_req_packet *req;
	struct batadv_rlnc_ack_packet *ack;
	int hdr_len = sizeof(*req), block_id, rank = 0, seq = 0, intvl = 0;
	bool ret = false;
	u8 *src, *dst, subtype;

	if (!info->attrs[BATADV_HLP_A_SRC])
		goto err;

	if (!info->attrs[BATADV_HLP_A_DST])
		goto err;

	if (!info->attrs[BATADV_HLP_A_BLOCK])
		goto err;


	subtype = nla_get_u8(info->attrs[BATADV_HLP_A_TYPE]);
	switch (subtype) {
	case BATADV_RLNC_ACK:
		hdr_len = sizeof(*ack);
		intvl = nla_get_u16(info->attrs[BATADV_HLP_A_INT]);
		batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_ACK_TX);
		break;

	case BATADV_RLNC_REQ:
		hdr_len = sizeof(*req);
		rank = nla_get_u16(info->attrs[BATADV_HLP_A_RANK]);
		seq = nla_get_u16(info->attrs[BATADV_HLP_A_SEQ]);
		batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_REQ_TX);
		break;
	}

	skb_out = dev_alloc_skb(ETH_HLEN + hdr_len);
	if (!skb_out)
		goto err;

	skb_reserve(skb_out, ETH_HLEN);

	src = nla_data(info->attrs[BATADV_HLP_A_SRC]);
	dst = nla_data(info->attrs[BATADV_HLP_A_DST]);
	block_id = nla_get_u16(info->attrs[BATADV_HLP_A_BLOCK]);

	rlnc = (struct batadv_rlnc_packet *)skb_put(skb_out, hdr_len);
	rlnc->header.packet_type = BATADV_RLNC;
	rlnc->header.version = BATADV_COMPAT_VERSION;
	rlnc->header.ttl = BATADV_TTL;
	rlnc->subtype = subtype;
	rlnc->block_id = block_id;
	memcpy(rlnc->src, src, ETH_ALEN);
	memcpy(rlnc->dst, dst, ETH_ALEN);

	switch (subtype) {
	case BATADV_RLNC_ACK:
		ack = (struct batadv_rlnc_ack_packet *)rlnc;
		ack->interval = intvl;
		break;

	case BATADV_RLNC_REQ:
		req = (struct batadv_rlnc_req_packet *)rlnc;
		req->rank = rank;
		req->seq = seq;
		break;
	}

	orig_node = batadv_orig_hash_find(bat_priv, rlnc->src);
	if (!orig_node) {
		goto err;
	}

	if (atomic_read(&bat_priv->mesh_state) != BATADV_MESH_ACTIVE)
		goto err;

	skb_out->priority = TC_PRIO_CONTROL + 256;

	batadv_send_skb_to_orig(skb_out, orig_node, NULL);
	batadv_inc_counter(bat_priv, BATADV_CNT_RLNC_ACK_TX);

	ret = true;

err:
	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	return ret;
}

static bool batadv_rlnc_skb_send_plain(struct batadv_priv *bat_priv,
				       struct sk_buff *skb,
				       struct genl_info *info)
{
	struct sk_buff *skb_out = NULL;
	int len = nla_len(info->attrs[BATADV_HLP_A_FRAME]);
	u8 *data = nla_data(info->attrs[BATADV_HLP_A_FRAME]);
	bool ret = false;

	skb_out= dev_alloc_skb(ETH_HLEN + len);
	if (!skb_out)
		goto err;
	skb_reserve(skb_out, ETH_HLEN + sizeof(struct batadv_unicast_packet));

	memcpy(skb_put(skb_out, len), data, len);
	BATADV_SKB_CB(skb_out)->plain = true;
	batadv_send_skb_unicast(bat_priv, skb_out);
	skb_out = NULL;
	ret = false;

err:
	if (skb_out)
		kfree_skb(skb_out);

	return ret;
}

static void *batadv_rlnc_skb_prepare(struct batadv_priv *bat_priv,
				     struct sk_buff *skb,
				     struct sk_buff *skb_out,
				     struct batadv_rlnc_packet *pkt)
{
	void *msg_head = genlmsg_put(skb_out, 0, 0, &bat_priv->hlp_genl_family,
				     0, BATADV_HLP_C_FRAME);
	if (!msg_head)
		goto err;

	if (nla_put_u8(skb_out, BATADV_HLP_A_TYPE, pkt->subtype))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_SRC, ETH_ALEN, pkt->src))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_DST, ETH_ALEN, pkt->dst))
		goto err;

	if (nla_put_u16(skb_out, BATADV_HLP_A_BLOCK, pkt->block_id))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_FRAME, skb->len, skb->data))
		goto err;

	return msg_head;

err:
	return NULL;
}

static bool batadv_rlnc_skb_add(struct batadv_priv *bat_priv,
				struct sk_buff *skb, int type, u8 *src, u8 *dst,
				int block_id)
{
	struct sk_buff *skb_out = NULL;
	void *msg_head;
	int portid = ACCESS_ONCE(bat_priv->genl_portid), ret = false;

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	msg_head = genlmsg_put(skb_out, 0, 0, &bat_priv->hlp_genl_family, 0,
			       BATADV_HLP_C_FRAME);
	if (!msg_head)
		goto err;

	if (nla_put_u8(skb_out, BATADV_HLP_A_TYPE, type))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_SRC, ETH_ALEN, src))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_DST, ETH_ALEN, dst))
		goto err;

	if (nla_put_u16(skb_out, BATADV_HLP_A_BLOCK, block_id))
		goto err;

	if (nla_put(skb_out, BATADV_HLP_A_FRAME, skb->len, skb->data))
		goto err;

	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(&init_net, skb_out, portid);
	kfree_skb(skb);
	skb_out = NULL;
	ret = true;

err:
	if (skb_out)
		kfree_skb(skb_out);

	return ret;
}

int batadv_rlnc_skb_add_plain(struct sk_buff *skb,
			       struct batadv_orig_node *orig_node)
{
	struct batadv_priv *bat_priv = orig_node->bat_priv;
	struct batadv_hard_iface *primary_if = NULL;
	u8 *src, *dst;
	bool ret = NET_XMIT_DROP;

	if (skb->len < BATADV_RLNC_MIN_PACKET_LEN)
		goto err;

	if (BATADV_SKB_CB(skb)->plain)
		goto err;

	if (!ACCESS_ONCE(bat_priv->genl_portid))
		goto err;

	if (!(orig_node->capabilities & BATADV_ORIG_CAPA_CAN_HLP))
		goto err;

	if (atomic_read(&bat_priv->hlp_block)) {
		ret = NET_XMIT_CN;
		kfree_skb(skb);
		ret = NET_XMIT_SUCCESS;
		goto err;
	}

	primary_if = batadv_primary_if_get_selected(bat_priv);
	if (!primary_if)
		goto err;

	src = primary_if->net_dev->dev_addr;
	dst = orig_node->orig;

	if (batadv_rlnc_skb_add(bat_priv, skb, BATADV_RLNC_PLAIN, src, dst, 0))
		ret = NET_XMIT_SUCCESS;

err:
	if (primary_if)
		batadv_hardif_free_ref(primary_if);

	return ret;
}

static bool batadv_rlnc_filter_ctrl(struct batadv_priv *bat_priv,
				    const uint8_t *sender,
				    const uint8_t *final_dst)
{
	struct batadv_orig_node *orig_node = NULL;
	struct batadv_neigh_node *neigh_node = NULL;
	bool ret = true;

	orig_node = batadv_orig_hash_find(bat_priv, final_dst);
	if (!orig_node)
		goto out;

	neigh_node = batadv_find_router(bat_priv, orig_node, NULL);
	if (!neigh_node)
		goto out;

	if (batadv_compare_eth(neigh_node->addr, sender))
		ret = false;

out:
	if (orig_node)
		batadv_orig_node_free_ref(orig_node);

	if (neigh_node)
		batadv_neigh_node_free_ref(neigh_node);

	return ret;
}

bool batadv_rlnc_skb_add_req(struct batadv_priv *bat_priv,
			     struct sk_buff *skb)
{
	struct batadv_rlnc_req_packet *req_pkt;
	struct sk_buff *skb_out = NULL;
	struct ethhdr *ethhdr;
	int portid = ACCESS_ONCE(bat_priv->genl_portid);
	void *msg_head;
	bool ret = false;

	if (!portid)
		goto out;

	ethhdr = eth_hdr(skb);
	req_pkt = (struct batadv_rlnc_req_packet *)skb->data;
	skb_pull(skb, sizeof(*req_pkt));

	/*
	if (batadv_rlnc_filter_ctrl(bat_priv, ethhdr->h_source,
				    req_pkt->rlnc.dst))
		goto out;
	*/

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb_out)
		goto out;

	msg_head = batadv_rlnc_skb_prepare(bat_priv, skb, skb_out,
					   &req_pkt->rlnc);
	if (!msg_head)
		goto out;

	nla_put_u16(skb_out, BATADV_HLP_A_RANK, req_pkt->rank);
	nla_put_u16(skb_out, BATADV_HLP_A_SEQ, req_pkt->seq);
	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(&init_net, skb_out, portid);
	skb_out = NULL;
	ret = true;

out:
	kfree_skb(skb);
	if (skb_out)
		kfree_skb(skb_out);

	return ret;
}

bool batadv_rlnc_skb_add_ack(struct batadv_priv *bat_priv,
			     struct sk_buff *skb)
{
	struct batadv_rlnc_ack_packet *ack_pkt;
	struct sk_buff *skb_out = NULL;
	struct ethhdr *ethhdr;
	int portid = ACCESS_ONCE(bat_priv->genl_portid);
	void *msg_head;
	bool ret = false;

	if (!portid)
		goto out;

	ethhdr = eth_hdr(skb);
	ack_pkt = (struct batadv_rlnc_ack_packet *)skb->data;
	skb_pull(skb, sizeof(*ack_pkt));

	/*
	if (batadv_rlnc_filter_ctrl(bat_priv, ethhdr->h_source,
				    ack_pkt->rlnc.dst))
		goto out;
	*/

	skb_out = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb_out)
		goto out;

	msg_head = batadv_rlnc_skb_prepare(bat_priv, skb, skb_out,
					   &ack_pkt->rlnc);
	if (!msg_head)
		goto out;

	nla_put_u16(skb_out, BATADV_HLP_A_INT, ack_pkt->interval);
	genlmsg_end(skb_out, msg_head);
	genlmsg_unicast(&init_net, skb_out, portid);
	skb_out = NULL;
	ret = true;

out:
	kfree_skb(skb);
	if (skb_out)
		kfree_skb(skb_out);

	return ret;
}

bool batadv_rlnc_skb_add_enc(struct sk_buff *skb,
			     struct batadv_priv *bat_priv,
			     enum batadv_rlnc_types type)
{
	struct batadv_rlnc_packet *rlnc_pkt;
	struct ethhdr *ethhdr;
	int hdr_size = sizeof(*rlnc_pkt);

	if (!ACCESS_ONCE(bat_priv->genl_portid))
		goto err;

	ethhdr = eth_hdr(skb);
	rlnc_pkt = (struct batadv_rlnc_packet *)skb->data;
	/*
	if (type == BATADV_RLNC_ACK &&
	    batadv_rlnc_filter_ctrl(bat_priv, ethhdr->h_source, rlnc_pkt->dst))
		goto err;
	*/

	rlnc_pkt = (struct batadv_rlnc_packet *)skb->data;
	skb_pull(skb, hdr_size);

	if (batadv_rlnc_skb_add(bat_priv, skb, type, rlnc_pkt->src,
				rlnc_pkt->dst, rlnc_pkt->block_id))
		return true;

	skb_push(skb, hdr_size);

err:
	return false;
}

int batadv_rlnc_genl_frame(struct sk_buff *skb, struct genl_info *info)
{
	struct batadv_priv *bat_priv;
	struct net_device *soft_iface = NULL;
	int ret = ENODATA, ifindex, type;

	if (!info->attrs[BATADV_HLP_A_IFINDEX])
		goto out;

	if (!info->attrs[BATADV_HLP_A_TYPE])
		goto out;

	ifindex = nla_get_u32(info->attrs[BATADV_HLP_A_IFINDEX]);
	soft_iface = dev_get_by_index(&init_net, ifindex);
	if (!soft_iface)
		goto out;

	bat_priv = netdev_priv(soft_iface);

	type = nla_get_u8(info->attrs[BATADV_HLP_A_TYPE]);
	switch (type) {
	case BATADV_RLNC_RED:
	case BATADV_RLNC_HLP:
	case BATADV_RLNC_REC:
	case BATADV_RLNC_ENC:
		batadv_rlnc_skb_send_enc(bat_priv, skb, info);
		break;

	case BATADV_RLNC_DEC:
		batadv_rlnc_skb_recv_dec(bat_priv, skb, info);
		break;

	case BATADV_RLNC_REQ:
	case BATADV_RLNC_ACK:
		batadv_rlnc_skb_send_feedback(bat_priv, skb, info);
		break;

	case BATADV_RLNC_PLAIN:
		batadv_rlnc_skb_send_plain(bat_priv, skb, info);
		break;
	}

	ret = 0;

out:
	if (soft_iface)
		dev_put(soft_iface);

	return -ret;
}

int batadv_rlnc_genl_block(struct sk_buff *skb, struct genl_info *info)
{
	struct net_device *soft_iface = NULL;
	struct batadv_priv *bat_priv;
	int ifindex;

	if (!info->attrs[BATADV_HLP_A_IFINDEX])
		goto out;
	ifindex = nla_get_u32(info->attrs[BATADV_HLP_A_IFINDEX]);
	soft_iface = dev_get_by_index(&init_net, ifindex);
	if (!soft_iface)
		goto out;

	bat_priv = netdev_priv(soft_iface);

	switch (info->genlhdr->cmd) {
	case BATADV_HLP_C_BLOCK:
		atomic_set(&bat_priv->hlp_block, 1);
		break;

	case BATADV_HLP_C_UNBLOCK:
		atomic_set(&bat_priv->hlp_block, 0);
		break;
	}

out:
	if (soft_iface)
		dev_put(soft_iface);

	return 0;
}
