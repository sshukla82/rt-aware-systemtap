/* main header file
 * Copyright (C) 2005-2008 Red Hat Inc.
 * Copyright (C) 2005, 2006 Intel Corporation.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _RUNTIME_H_
#define _RUNTIME_H_

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/string.h>
#include <linux/kprobes.h>
#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/time.h>
#include <linux/spinlock.h>
#include <linux/hardirq.h>
#include <asm/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/compat.h>
#include <linux/mm.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,15)
#if !defined (CONFIG_DEBUG_FS)  && !defined (CONFIG_DEBUG_FS_MODULE)
#error "DebugFS is required and was not found in the kernel."
#endif
#else
/* older kernels have no debugfs and older version of relayfs. */
#define STP_OLD_TRANSPORT
#endif

#ifndef for_each_cpu
#define for_each_cpu(cpu)  for_each_cpu_mask((cpu), cpu_possible_map)
#endif

static void _stp_dbug (const char *func, int line, const char *fmt, ...);
void _stp_error (const char *fmt, ...);

#include "debug.h"

/* atomic globals */
static atomic_t _stp_transport_failures = ATOMIC_INIT (0);

static struct
{
	atomic_t ____cacheline_aligned_in_smp seq;
} _stp_seq = { ATOMIC_INIT (0) };

#define _stp_seq_inc() (atomic_inc_return(&_stp_seq.seq))

/* TEST_MODE is always defined by systemtap */
#ifdef TEST_MODE
#define SYSTEMTAP 1
#else
#define MAXTRYLOCK 1000
#define TRYLOCKDELAY 100
#endif

#ifndef MAXSTRINGLEN
#define MAXSTRINGLEN 128
#endif

#include "alloc.c"
#include "print.c"
#include "string.c"
#include "io.c"
#include "arith.c"
#include "copy.c"
#include "sym.h"
#include "sym.c"
#ifdef STP_PERFMON
#include "perf.c"
#endif

/* Support functions for int64_t module parameters. */
int param_set_int64_t(const char *val, struct kernel_param *kp)
{
  char *endp;
  long long ll;

  if (!val)
    return -EINVAL;

  /* simple_strtoll isn't exported... */
  if (*val == '-')
    ll = -simple_strtoull(val+1, &endp, 0);
  else
    ll = simple_strtoull(val, &endp, 0);

  if ((endp == val) || ((int64_t)ll != ll))
    return -EINVAL;

  *((int64_t *)kp->arg) = ll;
  return 0;
}

int param_get_int64_t(char *buffer, struct kernel_param *kp)
{
  return sprintf(buffer, "%lli", (long long)*((int64_t *)kp->arg));
}

#define param_check_int64_t(name, p) __param_check(name, p, int64_t)


/************* Module Stuff ********************/

int init_module (void)
{
  return _stp_transport_init();
}

int probe_start(void);

void cleanup_module(void)
{
  _stp_transport_close();
}

MODULE_LICENSE("GPL");

#endif /* _RUNTIME_H_ */
