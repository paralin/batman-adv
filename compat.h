/* Copyright (C) 2007-2012 B.A.T.M.A.N. contributors:
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)

#define skb_set_network_header(_skb, _offset) \
	do { (_skb)->nh.raw = (_skb)->data + (_offset); } while (0)

#define skb_reset_mac_header(_skb) \
	do { (_skb)->mac.raw = (_skb)->data; } while (0)

#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)

#define skb_mac_header(_skb) \
    ((_skb)->mac.raw)

#include <linux/etherdevice.h>
static inline __be16 bat_eth_type_trans(struct sk_buff *skb,
					struct net_device *dev)
{
	skb->dev = dev;
	return eth_type_trans(skb, dev);
}

#define eth_type_trans(_skb, _dev) \
	bat_eth_type_trans(_skb, _dev);

#ifndef __maybe_unused
# define __maybe_unused		/* unimplemented */
#endif

static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->nh.raw - skb->mac.raw;
}

#endif /* < KERNEL_VERSION(2,6,22) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)

static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom)
{
	return skb_cow(skb, headroom);
}

#define cancel_delayed_work_sync(wq) cancel_delayed_work(wq)

#endif /* < KERNEL_VERSION(2, 6, 23) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)

#ifndef pr_fmt
#define pr_fmt(fmt) fmt
#endif

#define pr_err(fmt, ...) \
       printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warning(fmt, ...) \
       printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)

#if defined(DEBUG)
#define pr_debug(fmt, ...) \
	printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#else
#define pr_debug(fmt, ...) \
	({ if (0) printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__); 0; })
#endif

#define dev_get_by_name(x, y) dev_get_by_name(y)
#define dev_get_by_index(x, y) dev_get_by_index(y)

#define get_sset_count get_stats_count

#define BIT(nr)		(1UL << (nr))

#endif /* < KERNEL_VERSION(2, 6, 24) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 25)

#define strict_strtoul(cp, base, res) \
	({ \
	int ret = 0; \
	char *endp; \
	*res = simple_strtoul(cp, &endp, base); \
	if (cp == endp) \
		ret = -EINVAL; \
	ret; \
})

#define strict_strtol(cp, base, res) \
	({ \
	int ret = 0; \
	char *endp; \
	*res = simple_strtol(cp, &endp, base); \
	if (cp == endp) \
		ret = -EINVAL; \
	ret; \
})

#define to_battr(a) container_of(a, struct batadv_attribute, attr)

ssize_t bat_wrapper_show(struct kobject *kobj, struct attribute *attr,
			 char *buf);

ssize_t bat_wrapper_store(struct kobject *kobj, struct attribute *attr,
			  const char *buf, size_t count);

static struct sysfs_ops bat_wrapper_ops = {
	.show   = bat_wrapper_show,
	.store  = bat_wrapper_store,
};

static struct kobj_type ktype_bat_wrapper = {
	.sysfs_ops      = &bat_wrapper_ops,
};

static inline struct kobject *kobject_create_and_add(const char *name,
						     struct kobject *parent)
{
	struct kobject *kobj;
	int err;

	kobj = kzalloc(sizeof(*kobj), GFP_KERNEL);
	if (!kobj)
		return NULL;

	kobject_set_name(kobj, "%s", name);
	kobj->ktype = &ktype_bat_wrapper;
	kobj->kset = NULL;
	kobj->parent = parent;

	err = kobject_register(kobj);
	if (err) {
		kobject_put(kobj);
		return NULL;
	}

	return kobj;
}

#define kobject_put(kobj) kobject_unregister(kobj)

#endif /* < KERNEL_VERSION(2, 6, 25) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)

/* time_is_before_jiffies(a) return true if a is before jiffies */
#define time_is_before_jiffies(a) time_after(jiffies, a)

#include <linux/if_arp.h>
static inline int arp_hdr_len(struct net_device *dev)
{
	/* ARP header, plus 2 device addresses, plus 2 IP addresses. */
	return sizeof(struct arphdr) + (dev->addr_len + sizeof(u32)) * 2;
}

static const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]
static inline char *pack_hex_byte(char *buf, u8 byte)
{
    *buf++ = hex_asc_hi(byte);
    *buf++ = hex_asc_lo(byte);
    return buf;
}

#endif /* < KERNEL_VERSION(2, 6, 26) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 27)

#define ethtool_cmd_speed_set(_ep, _speed) \
	do { (_ep)->speed = (_speed); } while (0)

#ifndef dereference_function_descriptor
#define dereference_function_descriptor(p) (p)
#endif

#include <linux/debugfs.h>

static inline void debugfs_remove_recursive(struct dentry *dentry)
{
	struct dentry *child;
	struct dentry *parent;

	if (!dentry)
		return;

	parent = dentry->d_parent;
	if (!parent || !parent->d_inode)
		return;

	parent = dentry;

	while (1) {
		/*
		 * When all dentries under "parent" has been removed,
		 * walk up the tree until we reach our starting point.
		 */
		if (list_empty(&parent->d_subdirs)) {
			if (parent == dentry)
				break;
			parent = parent->d_parent;
		}
		child = list_entry(parent->d_subdirs.next, struct dentry,
				d_u.d_child);
next_sibling:

		/*
		 * If "child" isn't empty, walk down the tree and
		 * remove all its descendants first.
		 */
		if (!list_empty(&child->d_subdirs)) {
			parent = child;
			continue;
		}
		debugfs_remove(child);
		if (parent->d_subdirs.next == &child->d_u.d_child) {
			/*
			 * Try the next sibling.
			 */
			if (child->d_u.d_child.next != &parent->d_subdirs) {
				child = list_entry(child->d_u.d_child.next,
						   struct dentry,
						   d_u.d_child);
				goto next_sibling;
			}
			break;
		}
	}

	debugfs_remove(dentry);
}

#endif /* < KERNEL_VERSION(2, 6, 27) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)

#include <linux/netdevice.h>

struct net_device_ops {
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	int			(*ndo_start_xmit) (struct sk_buff *skb,
						   struct net_device *dev);
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
	int			(*ndo_validate_addr)(struct net_device *dev);
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
};

int eth_validate_addr(struct net_device *dev);

int bat_vscnprintf(char *buf, size_t size, const char *fmt, va_list args);
#define vscnprintf bat_vscnprintf

asmlinkage int bat_printk(const char *fmt, ...);
#define printk bat_printk

int bat_sprintf(char *buf, const char *fmt, ...);
#define sprintf bat_sprintf

int bat_snprintf(char *buf, size_t size, const char *fmt, ...);
#define snprintf bat_snprintf

int bat_seq_printf(struct seq_file *m, const char *f, ...);
#define seq_printf bat_seq_printf

#endif /* < KERNEL_VERSION(2, 6, 29) */

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

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)

#define __always_unused			__attribute__((unused))
#define __percpu

#define skb_iif iif

#endif /* < KERNEL_VERSION(2, 6, 33) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 34)

#define hlist_first_rcu(head) (*((struct hlist_node **)(&(head)->first)))
#define hlist_next_rcu(node) (*((struct hlist_node **)(&(node)->next)))

#define __hlist_for_each_rcu(pos, head) \
	for (pos = rcu_dereference(hlist_first_rcu(head)); \
	     pos && ({ prefetch(pos->next); 1; }); \
	     pos = rcu_dereference(hlist_next_rcu(pos)))

#define rcu_dereference_protected(p, c) (p)

#endif /* < KERNEL_VERSION(2, 6, 34) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)

#define pr_warn pr_warning

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

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 21)
static inline void skb_reset_mac_len(struct sk_buff *skb)
{
	skb->mac_len = skb->network_header - skb->mac_header;
}
#endif

#endif /* < KERNEL_VERSION(3, 0, 0) */


#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0)

static inline void eth_hw_addr_random(struct net_device *dev)
{
	random_ether_addr(dev->dev_addr);
}

#endif /* < KERNEL_VERSION(3, 4, 0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)

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
