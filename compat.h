/* Copyright (C) 2007-2013 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner, Simon Wunderlich
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
 *
 * This file contains macros for maintaining compatibility with older versions
 * of the Linux kernel.
 */

#ifndef _NET_BATMAN_ADV_COMPAT_H_
#define _NET_BATMAN_ADV_COMPAT_H_

#include <linux/version.h>	/* LINUX_VERSION_CODE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)

/*
 * net_device - multicast list handling
 *	locking
 */
#define netif_addr_lock_bh(soft_iface) \
		netif_tx_lock_bh(soft_iface)
#define netif_addr_unlock_bh(soft_iface) \
		netif_tx_unlock_bh(soft_iface)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)

#undef __alloc_percpu
#define __alloc_percpu(size, align) \
	percpu_alloc_mask((size), GFP_KERNEL, cpu_possible_map)

#endif /* < KERNEL_VERSION(2, 6, 30) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)

#define __compat__module_param_call(p1, p2, p3, p4, p5, p6, p7) \
	__module_param_call(p1, p2, p3, p4, p5, p7)

#else

#define __compat__module_param_call(p1, p2, p3, p4, p5, p6, p7) \
	__module_param_call(p1, p2, p3, p4, p5, p6, p7)

#endif /* < KERNEL_VERSION(2, 6, 31) */


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33))
#include <linux/autoconf.h>
#else
#include <generated/autoconf.h>
#endif
#include "compat-autoconf.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#define __always_unused			__attribute__((unused))
#define __percpu

#define skb_iif iif

#endif /* < KERNEL_VERSION(2, 6, 33) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)

#define rcu_dereference_protected(p, c) (p)

#endif /* < KERNEL_VERSION(2, 6, 34) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)

#define pr_warn pr_warning

#define netdev_mc_count(dev) ((dev)->mc_count)
#undef  netdev_for_each_mc_addr
#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = (struct bat_dev_addr_list *)dev->mc_list; mclist; \
	     mclist = (struct bat_dev_addr_list *)mclist->next)

/* Note, that this breaks the usage of the normal 'struct netdev_hw_addr'
 * for kernels < 2.6.35 in batman-adv! */
#define netdev_hw_addr bat_dev_addr_list
struct bat_dev_addr_list {
	struct dev_addr_list *next;
	u8  addr[MAX_ADDR_LEN];
	u8  da_addrlen;
	u8  da_synced;
	int da_users;
	int da_gusers;
};

#endif /* < KERNEL_VERSION(2, 6, 35) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

#define __rcu
#define IFF_BRIDGE_PORT  0 || (hard_iface->net_dev->br_port ? 1 : 0)

struct kernel_param_ops {
	/* Returns 0, or -errno.  arg is in kp->arg. */
	int (*set)(const char *val, const struct kernel_param *kp);
	/* Returns length written or -errno.  Buffer is 4k (ie. be short!) */
	int (*get)(char *buffer, struct kernel_param *kp);
	/* Optional function to free kp->arg when module unloaded. */
	void (*free)(void *arg);
};

#define module_param_cb(name, ops, arg, perm)				\
	static int __compat_set_param_##name(const char *val,		\
					     struct kernel_param *kp)	\
				{ return (ops)->set(val, kp); }		\
	static int __compat_get_param_##name(char *buffer,		\
					     struct kernel_param *kp)	\
				{ return (ops)->get(buffer, kp); }	\
	__compat__module_param_call(MODULE_PARAM_PREFIX, name,		\
				    __compat_set_param_##name,		\
				    __compat_get_param_##name, arg,	\
				    __same_type((arg), bool *), perm)

static inline int batadv_param_set_copystring(const char *val,
					      const struct kernel_param *kp)
{
	return param_set_copystring(val, (struct kernel_param *)kp);
}
#define param_set_copystring batadv_param_set_copystring

/* hack for dev->addr_assign_type &= ~NET_ADDR_RANDOM; */
#define addr_assign_type ifindex
#define NET_ADDR_RANDOM 0

#endif /* < KERNEL_VERSION(2, 6, 36) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)

#define IPV6_ADDR_MC_FLAG_TRANSIENT(a)  \
	((a)->s6_addr[1] & 0x10)

void batadv_for_each_pmc_rcu_init(struct in_device *in_dev,
				  struct ip_mc_list **pmc);
bool batadv_for_each_pmc_rcu_check(struct in_device *in_dev,
				   struct ip_mc_list *pmc);

#undef for_each_pmc_rcu
#define for_each_pmc_rcu(in_dev, pmc)				\
	for (batadv_for_each_pmc_rcu_init(in_dev, &pmc);	\
	     batadv_for_each_pmc_rcu_check(in_dev, pmc);	\
	     pmc = NULL)					\
		for (; pmc != NULL; pmc = pmc->next)

#endif /* < KERNEL_VERSION(2, 6, 38) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39)

#define kstrtoul strict_strtoul
#define kstrtol  strict_strtol

#endif /* < KERNEL_VERSION(2, 6, 39) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0)

#define kfree_rcu(ptr, rcu_head) call_rcu(&ptr->rcu_head, batadv_free_rcu_##ptr)
#define vlan_insert_tag(skb, vid) __vlan_put_tag(skb, vid)

void batadv_free_rcu_gw_node(struct rcu_head *rcu);
void batadv_free_rcu_neigh_node(struct rcu_head *rcu);
void batadv_free_rcu_tt_local_entry(struct rcu_head *rcu);
void batadv_free_rcu_backbone_gw(struct rcu_head *rcu);
void batadv_free_rcu_dat_entry(struct rcu_head *rcu);
void batadv_free_rcu_flow_entry(struct rcu_head *rcu);

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->network_header - skb->mac_header;
}

#endif /* < KERNEL_VERSION(3, 0, 0) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 1, 0)

#define __ARG_PLACEHOLDER_1 0,
#define config_enabled(cfg) _config_enabled(cfg)
#define _config_enabled(value) __config_enabled(__ARG_PLACEHOLDER_##value)
#define __config_enabled(arg1_or_junk) ___config_enabled(arg1_or_junk 1, 0)
#define ___config_enabled(__ignored, val, ...) val

#define IS_ENABLED(module) \
	(config_enabled(module) || config_enabled(option##_MODULE))

#endif /* < KERNEL_VERSION(3, 1, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)

static inline void eth_hw_addr_random(struct net_device *dev)
{
	random_ether_addr(dev->dev_addr);
}

#endif /* < KERNEL_VERSION(3, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)

#define net_ratelimited_function(func, ...) \
	do { \
		if (net_ratelimit()) \
			func(__VA_ARGS__); \
	} while (0)

#endif /* < KERNEL_VERSION(3, 5, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)

#define ETH_P_BATMAN	0x4305

/* hack for not correctly set mac_len. This may happen for some special
 * configurations like batman-adv on VLANs.
 *
 * This is pretty dirty, but we only use skb_share_check() in main.c right
 * before mac_len is checked, and the recomputation shouldn't hurt too much.
 */
#define skb_share_check(skb, b) \
	({ \
		struct sk_buff *_t_skb; \
		_t_skb = skb_share_check(skb, b); \
		if (_t_skb) \
			skb_reset_mac_len(_t_skb); \
		_t_skb; \
	})

#endif /* < KERNEL_VERSION(3, 8, 0) */

#endif /* _NET_BATMAN_ADV_COMPAT_H_ */
