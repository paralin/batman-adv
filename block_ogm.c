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

#include <linux/debugfs.h>
#include "main.h"
#include "block_ogm.h"
#include "originator.h"

/* Called when receiving OGM packets to check if it should be dropped.
 * Returns true if the packets should be dropped. False if not. */
bool batadv_block_ogm(struct batadv_hard_iface *hard_iface, const uint8_t *addr)
{
	struct batadv_priv *bat_priv = netdev_priv(hard_iface->soft_iface);
	struct batadv_orig_node *orig_node;
	uint8_t action;

	orig_node = batadv_orig_hash_find(bat_priv, addr);
	if (!orig_node)
		return false;

	action = atomic_read(&orig_node->block_action);

	/* Check if address is blocked */
	if (action == BLOCK_ACTION_DROP)
		goto out_true;

	/* Check if address is not allowed */
	if (atomic_read(&bat_priv->block_ogm_allow_cnt) &&
	    action != BLOCK_ACTION_ALLOW)
		goto out_true;

	batadv_orig_node_free_ref(orig_node);
	return false;

out_true:
	batadv_orig_node_free_ref(orig_node);
	return true;
}

/* Decrement reference count of the block entry and free it, if it becomes
 * zero. */
static void batadv_block_entry_free_ref(struct batadv_block_entry *block_entry)
{
	if (atomic_dec_and_test(&block_entry->refcount))
		kfree_rcu(block_entry, rcu);
}

/* Search the list of block-entries for an address. Returns the found entry
 * and NULL if none is found. */
static struct batadv_block_entry *
batadv_block_find_entry(struct batadv_priv *bat_priv,
			const uint8_t *addr)
{
	struct batadv_block_entry *block_entry_tmp, *block_entry = NULL;

	/* Search for existing entry */
	rcu_read_lock();
	list_for_each_entry_rcu(block_entry_tmp, &bat_priv->block_list, list) {
		if (batadv_compare_eth(block_entry_tmp->addr, addr)) {
			/* Found a match */
			block_entry = block_entry_tmp;
			atomic_inc_not_zero(&block_entry->refcount);
			break;
		}
	}
	rcu_read_unlock();

	return block_entry;
}

/* Searches the list of block-entries and creates one, if none is found. */
static struct batadv_block_entry *
batadv_block_get_entry(struct batadv_priv *bat_priv,
		       const uint8_t *addr)
{
	struct batadv_block_entry *block_entry;
	
	block_entry = batadv_block_find_entry(bat_priv, addr);
	if (block_entry)
		return block_entry;

	/* Create and insert entry if needed */
	block_entry = kmalloc(sizeof(*block_entry), GFP_ATOMIC);
	if (!block_entry)
		return NULL;

	memcpy(block_entry->addr, addr, ETH_ALEN);
	atomic_set(&block_entry->refcount, 2);
	block_entry->action = BLOCK_ACTION_NONE;

	spin_lock_bh(&bat_priv->block_lock);
	list_add(&block_entry->list, &bat_priv->block_list);
	spin_unlock_bh(&bat_priv->block_lock);

	return block_entry;
}

/* Deletes an entry from the list */
static void batadv_block_del_addr(struct batadv_priv *bat_priv,
				  struct batadv_block_entry *block_entry)
{
	if (!block_entry)
		return;

	spin_lock_bh(&bat_priv->block_lock);
	list_del(&block_entry->list);
	spin_unlock_bh(&bat_priv->block_lock);

	batadv_block_entry_free_ref(block_entry);
}

/* When new entries are added to the list, existing originators are
 * searched and if one exists, its block_action member is set accordingly. */
static void batadv_block_set_orig_action(struct batadv_priv *bat_priv,
					 struct batadv_block_entry *block_entry,
					 uint8_t action)
{
	struct batadv_orig_node *orig_node;
	
	orig_node = batadv_orig_hash_find(bat_priv, block_entry->addr);
	if (!orig_node)
		return;

	atomic_set(&orig_node->block_action, action);
	batadv_orig_node_free_ref(orig_node);
}

/* Set the action of an entry and update the allow counter in bat_priv
 * if necessary. Also, update existing originators. */
static void batadv_block_add_action(struct batadv_priv *bat_priv,
				    struct batadv_block_entry *block_entry,
				    uint8_t action)
{
	uint8_t old_action;

	if (!block_entry)
		return;

	old_action = block_entry->action;

	/* Check if the allow counter should be adjusted. */
	if (action == old_action)
		return;
	else if (old_action == BLOCK_ACTION_ALLOW)
		batadv_atomic_dec_not_zero(&bat_priv->block_ogm_allow_cnt);
	else if (action == BLOCK_ACTION_ALLOW)
		atomic_inc(&bat_priv->block_ogm_allow_cnt);

	block_entry->action = action;
	batadv_block_set_orig_action(bat_priv, block_entry, action);
}

/* Adjust allow counter if needed and set action of originator, if one
 * exists. */
static void batadv_block_del_action(struct batadv_priv *bat_priv,
				    struct batadv_block_entry *block_entry)
{
	if (!block_entry)
		return;

	if (block_entry->action == BLOCK_ACTION_ALLOW)
		 batadv_atomic_dec_not_zero(&bat_priv->block_ogm_allow_cnt);

	batadv_block_set_orig_action(bat_priv, block_entry, BLOCK_ACTION_NONE);
}

/* Called upon creation of an originator. Checks if the address of the new
 * originator is listed in the list of block entries and sets the action of
 * the originator accordingly. */
void batadv_block_check_orig_entry(struct batadv_priv *bat_priv,
				   struct batadv_orig_node *orig_node)
{
	struct batadv_block_entry *block_entry;

	block_entry = batadv_block_find_entry(bat_priv, orig_node->orig);

	if (block_entry) {
		atomic_set(&orig_node->block_action, block_entry->action);
		batadv_block_entry_free_ref(block_entry);
	} else {
		atomic_set(&orig_node->block_action, BLOCK_ACTION_NONE);
	}
}

/* Convert a human-readable MAC address into byte values. */
static int batadv_block_parse_pretty_mac(const char *str, char *addr)
{
	int i;

	if (str[MAC_ADDR_LEN] != ' ')
		return -EINVAL;

	/* Validate if string has valid format */
	for (i = 1; i <= ETH_ALEN - 1; i++) {
		if (str[i*3-1] != ':')
			return -EINVAL;
	}

	/* Convert string to bytes */
	for (i = 0; i < ETH_ALEN; i++) {
		unsigned long l;

		l = simple_strtoul(&str[i*3], (char **)NULL, 16);
		addr[i] = (char)l;
	}

	return 0;
}

/* Convert the human readable action to a decimal value. */
static int batadv_block_parse_action(const char *str, int *action)
{
	if (strncmp(str, BLOCK_ACTION_DEL_NAME,
		    strlen(BLOCK_ACTION_DEL_NAME)) == 0)
		*action = BLOCK_ACTION_DEL;
	else if (strncmp(str, BLOCK_ACTION_DROP_NAME,
			 strlen(BLOCK_ACTION_DROP_NAME)) == 0)
		*action = BLOCK_ACTION_DROP;
	else if (strncmp(str, BLOCK_ACTION_ALLOW_NAME,
			 strlen(BLOCK_ACTION_ALLOW_NAME)) == 0)
		*action = BLOCK_ACTION_ALLOW;
	else
		return -EINVAL;

	return 0;
}

/* Called by debugfs when our file is opened. */
static int batadv_block_file_open(struct inode *inode, struct file *file)
{
	nonseekable_open(inode, file);
	file->private_data = inode->i_private;
	if (!try_module_get(THIS_MODULE))
		return -EBUSY;
	return 0;
}

/* Called by debugfs when our file is closed. */
static int batadv_block_file_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return 0;
}

/* Called by debugfs when data is requested from our file. The function
 * copies the address and action from each entry in the block list into
 * the user buffer. */
static ssize_t batadv_block_file_read(struct file *file, char __user *buff,
				      size_t count, loff_t *ppos)
{
	struct batadv_priv *bat_priv = file->private_data;
	struct batadv_block_entry *block_entry;
	char mac[MAC_ADDR_LEN + BLOCK_ACTION_MAX_LEN + 2];
	ssize_t c, i = 0;

	/* If private_data is cleared, our work is done. */
	if (!bat_priv)
		return 0;

	if (!access_ok(VERIFY_WRITE, buff, count))
		return -EFAULT;

	/* For each block entry. */
	rcu_read_lock();
	list_for_each_entry_rcu(block_entry, &bat_priv->block_list,
				list) {
		/* Copy address and action into temp buffer. */
		c = scnprintf(mac, MAC_ADDR_LEN + BLOCK_ACTION_MAX_LEN + 2,
			      "%pM %hhu\n",
			      block_entry->addr,
			      block_entry->action);
		/* Copy formatted string to user space. */
		c = c > count ? count : c;
		if (copy_to_user(buff, mac, c)) {
			i = 0;
			goto out;
		}

		/* Update counters before next copy. */
		buff += c;
		i += c;
	}

out:
	rcu_read_unlock();

	/* Clear private_data to skip further reads */
	file->private_data = NULL;

	return i;
}

/* Called by debugfs when data is written to our file. Copies the written data
 * into a local buffer and reads out the MAC address and action from this and
 * calls the according functions. */
static ssize_t batadv_block_file_write(struct file *file,
				       const char __user *buff,
				       size_t count, loff_t *ppos)
{
	struct batadv_priv *bat_priv = file->private_data;
	struct batadv_block_entry *block_entry = NULL;
	char *str;
	char addr[MAC_ADDR_LEN];
	int error = 0;
	int action = 0;

	/* Make sure buffer is long enough to hold at least a MAC address. */
	if (!buff || count < MAC_ADDR_LEN + 1)
		return -EINVAL;

	if (!access_ok(VERIFY_READ, buff, count))
		return -EFAULT;

	/* Copy data from user space buffer. */
	str = kmalloc(count, GFP_ATOMIC);
	if (!str)
		return -ENOMEM;
	if (copy_from_user(str, buff, count))
		goto out;
	str[count - 1] = '\0';

	/* Read out MAC address. */
	error = batadv_block_parse_pretty_mac(str, addr);
	if (error)
		goto out;

	/* Read out action. */
	error = batadv_block_parse_action(str + MAC_ADDR_LEN + 1, &action);
	if (error < 0)
		goto out;

	switch (action) {
		/* Find and delete requested address. */
	case BLOCK_ACTION_DEL:
		block_entry = batadv_block_find_entry(bat_priv, addr);
		batadv_block_del_action(bat_priv, block_entry);
		batadv_block_del_addr(bat_priv, block_entry);
		break;

		/* Create or update requested address. */
	case BLOCK_ACTION_DROP:
	case BLOCK_ACTION_ALLOW:
		block_entry = batadv_block_get_entry(bat_priv, addr);
		batadv_block_add_action(bat_priv, block_entry, action);
		break;
	}

	if (block_entry)
		batadv_block_entry_free_ref(block_entry);

out:
	kfree(str);
	return count;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = batadv_block_file_open,
	.release = batadv_block_file_release,
	.read = batadv_block_file_read,
	.write = batadv_block_file_write,
	.llseek = no_llseek,
};

/* Register/create our file in debugfs and initialize bat_priv members. */
int batadv_block_file_setup(struct batadv_priv *bat_priv)
{
	struct dentry *d;

	if (!bat_priv->debug_dir)
		goto err;

	d = debugfs_create_file("block_ogm", S_IFREG | S_IWUSR | S_IRUSR,
				bat_priv->debug_dir, bat_priv, &fops);
	if (d)
		goto err;

	return 0;

err:
	return 1;
}

/* Remove all entries from the block list. */
int batadv_block_file_cleanup(struct batadv_priv *bat_priv)
{
	struct batadv_block_entry *block_entry, *block_entry_tmp;

	spin_lock_bh(&bat_priv->block_lock);
	list_for_each_entry_safe(block_entry, block_entry_tmp,
				 &bat_priv->block_list, list) {
		list_del(&block_entry->list);
		kfree(block_entry);
	}
	spin_unlock_bh(&bat_priv->block_lock);
	return 0;
}
