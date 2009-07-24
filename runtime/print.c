/* -*- linux-c -*-
 * Print Functions
 * Copyright (C) 2007-2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _PRINT_C_
#define _PRINT_C_


#include "string.h"
#include "vsprintf.c"
#include "print.h"
#include "transport/transport.c"
#include "vsprintf.c"

/** @file print.c
 * Printing Functions.
 */

/** @addtogroup print Print Functions
 * The print buffer is for collecting output to send to the user daemon.
 * This is a per-cpu static buffer.  The buffer is sent when
 * _stp_print_flush() is called.
 *
 * The reason to do this is to allow multiple small prints to be combined then
 * timestamped and sent together to staprun. This is more efficient than sending
 * numerous small packets.
 *
 * This function is called automatically when the print buffer is full.
 * It MUST also be called at the end of every probe that prints something.
 * @{
 */

typedef struct __stp_pbuf {
	uint32_t len;			/* bytes used in the buffer */
	char buf[STP_BUFFER_SIZE];
} _stp_pbuf;

static void *Stp_pbuf = NULL;

/** private buffer for _stp_vlog() */
#define STP_LOG_BUF_LEN 256

typedef char _stp_lbuf[STP_LOG_BUF_LEN];
static void *Stp_lbuf = NULL;

/* create percpu print and io buffers */
static int _stp_print_init (void)
{
	Stp_pbuf = _stp_alloc_percpu(sizeof(_stp_pbuf));
	if (unlikely(Stp_pbuf == 0))
		return -1;

	/* now initialize IO buffer used in io.c */
	Stp_lbuf = _stp_alloc_percpu(sizeof(_stp_lbuf));
	if (unlikely(Stp_lbuf == 0)) {
		_stp_free_percpu(Stp_pbuf);
		return -1;
	}
	return 0;
}

static void _stp_print_cleanup (void)
{
	if (Stp_pbuf)
		_stp_free_percpu(Stp_pbuf);
	if (Stp_lbuf)
		_stp_free_percpu(Stp_lbuf);
}

#define __DEF_EXPORT_FN(fn, postfix) fn ## _ ## postfix
#define DEF_EXPORT_FN(fn, postfix) __DEF_EXPORT_FN(fn, postfix)

#if defined(RELAY_GUEST)
#if defined(RELAY_HOST)
        #error "Cannot specify both RELAY_HOST and RELAY_GUEST"
#endif
#define EXPORT_FN(fn) DEF_EXPORT_FN(fn, RELAY_GUEST)
#elif defined(RELAY_HOST)
#define EXPORT_FN(fn) DEF_EXPORT_FN(fn, RELAY_HOST)
#else /* defined(RELAY_GUEST) || defined(RELAY_HOST) */
#define EXPORT_FN(fn) fn
#endif

#if !defined(RELAY_GUEST)

#include "print_flush.c"
#if defined(RELAY_HOST)
EXPORT_SYMBOL_GPL(EXPORT_FN(stp_print_flush));
#endif

#endif /*!RELAY_GUEST*/

#if defined(RELAY_GUEST) || defined(RELAY_HOST)
/* Prohibit irqs to avoid racing on a relayfs */
extern void EXPORT_FN(stp_print_flush) (_stp_pbuf *);
static inline void _stp_print_flush(void)
{
	unsigned long flags;
	local_irq_save(flags);
	EXPORT_FN(stp_print_flush) (per_cpu_ptr(Stp_pbuf, smp_processor_id()));
	local_irq_restore(flags);
}
#else
#define _stp_print_flush() \
	EXPORT_FN(stp_print_flush)(per_cpu_ptr(Stp_pbuf, smp_processor_id()))
#endif

#ifndef STP_MAXBINARYARGS
#define STP_MAXBINARYARGS 127
#endif

/** Write 64-bit args directly into the output stream.
 * This function takes a variable number of 64-bit arguments
 * and writes them directly into the output stream.  Marginally faster
 * than doing the same in _stp_vsnprintf().
 * @sa _stp_vsnprintf()
 */
static void _stp_print_binary (int num, ...)
{
	unsigned long flags;
	va_list vargs;
	int i, len;
	int64_t *buf, *end;
	void *entry = NULL;
	size_t bytes_reserved;

	if (unlikely(num > STP_MAXBINARYARGS))
		num = STP_MAXBINARYARGS;

	va_start(vargs, num);
	len = num * sizeof(int64_t);

	spin_lock_irqsave(&_stp_print_lock, flags);
	while (len > 0) {
		bytes_reserved = _stp_data_write_reserve(len, &entry);
		buf = (int64_t *) _stp_data_entry_data(entry);
		if (likely(buf != NULL)) {
			end = buf + bytes_reserved * sizeof(int64_t);
			while (buf <= end) {
				*buf = va_arg(vargs, int64_t);
				buf++;
			}
			_stp_data_write_commit(entry);
			len -= bytes_reserved;
		}
	}
	spin_unlock_irqrestore(&_stp_print_lock, flags);
	va_end(vargs);
}

/** Print into the print buffer.
 * Like C printf.
 *
 * @sa _stp_print_flush()
 */
static void _stp_printf (const char *fmt, ...)
{
	unsigned long flags;
	va_list args;
	va_start(args, fmt);
	spin_lock_irqsave(&_stp_print_lock, flags);
	_stp_vsnprintf(NULL, 0, fmt, args);
	spin_unlock_irqrestore(&_stp_print_lock, flags);
	va_end(args);
}

/** Write a string into the print buffer.
 * @param str A C string (char *)
 */

static void _stp_print (const char *str)
{
	size_t len = strnlen(str, STP_BUFFER_SIZE);
	_stp_print_transport(str, len);
}

static void _stp_print_char (const char c)
{
	_stp_print_transport(&c, 1);
}

static void _stp_print_kernel_info(char *vstr, int ctx, int num_probes)
{
#ifdef DEBUG_MEM
	printk(KERN_DEBUG "%s: systemtap: %s, base: %p, memory: %lu+%lu+%u+%u+%u data+text+ctx+net+alloc, probes: %d\n",
	       THIS_MODULE->name,
	       vstr,
	       THIS_MODULE->module_core,
	       (unsigned long) (THIS_MODULE->core_size - THIS_MODULE->core_text_size),
               (unsigned long) THIS_MODULE->core_text_size,
	       ctx,
	       _stp_allocated_net_memory,
	       _stp_allocated_memory - _stp_allocated_net_memory,
		num_probes);
#else
	printk(KERN_DEBUG "%s: systemtap: %s, base: %p, memory: %lu+%lu+%u+%u data+text+ctx+net, probes: %d\n",
	       THIS_MODULE->name,
	       vstr,
	       THIS_MODULE->module_core,
	       (unsigned long) (THIS_MODULE->core_size - THIS_MODULE->core_text_size),
               (unsigned long) THIS_MODULE->core_text_size,
	       ctx,
	       _stp_allocated_net_memory,
	       num_probes);
#endif
}

/** @} */
#endif /* _PRINT_C_ */
