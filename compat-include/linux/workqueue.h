/* Copyright (C) 2007-2016 B.A.T.M.A.N. contributors:
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
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * This file contains macros for maintaining compatibility with older versions
 * of the Linux kernel.
 */

#ifndef _NET_BATMAN_ADV_COMPAT_LINUX_WORKQUEUE_H_
#define _NET_BATMAN_ADV_COMPAT_LINUX_WORKQUEUE_H_

#include <linux/version.h>
#include_next <linux/workqueue.h>

#include <linux/kernel.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)

/* some stable versions like Linux 3.2.44 also introduced this function
 * and would therefore break the build because they trigger a redefinition
 * of this function. Instead rename this function to be in the batadv_*
 * namespace
 */
#define to_delayed_work(__work) batadv_to_delayed_work(__work)

static inline struct delayed_work *
batadv_to_delayed_work(struct work_struct *work)
{
	return container_of(work, struct delayed_work, work);
}

#endif /* < KERNEL_VERSION(2, 6, 30) */

#endif /* _NET_BATMAN_ADV_COMPAT_LINUX_WORKQUEUE_H_ */
