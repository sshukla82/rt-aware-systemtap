/* -*- linux-c -*-
 *
 * ctl.c - staprun control channel
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2007 Red Hat Inc.
 */

#include "staprun.h"

/* This is only used in the old relayfs code */
static void read_buffer_info(void)
{
	char buf[PATH_MAX];
	struct statfs st;
	int fd, len, ret;

	if (!use_old_transport)
		return;

 	if (statfs("/sys/kernel/debug", &st) == 0 && (int) st.f_type == (int) DEBUGFS_MAGIC)
		return;

	sprintf (buf, "/proc/systemtap/%s/bufsize", modname);	
	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return;

	len = read(fd, buf, sizeof(buf));
	if (len <= 0) {
		fprintf (stderr, "ERROR: couldn't read bufsize: %s.\n",
			 strerror(errno));
		close(fd);
		return;
	}
	ret = sscanf(buf, "%u,%u", &n_subbufs, &subbuf_size);
	if (ret != 2)
		fprintf (stderr, "ERROR: couldn't read bufsize.\n");

	dbug(2, "n_subbufs= %u, size=%u\n", n_subbufs, subbuf_size);
	close(fd);
	return;
}


int init_ctl_channel(void)
{
	char buf[PATH_MAX];
	struct statfs st;

 	if (statfs("/sys/kernel/debug", &st) == 0 && (int) st.f_type == (int) DEBUGFS_MAGIC)
 		sprintf (buf, "/sys/kernel/debug/systemtap/%s/cmd", modname);
	else
		sprintf (buf, "/proc/systemtap/%s/cmd", modname);

	dbug(2, "Opening %s\n", buf); 
	control_channel = open(buf, O_RDWR);
	if (control_channel < 0) {
		fprintf (stderr,
			 "ERROR: couldn't open control channel '%s': %s\n",
			 buf, strerror(errno));
		return -1;
	}

	read_buffer_info();
	return 0;
}

void close_ctl_channel(void)
{
	if (control_channel > 0) {
		close(control_channel);
		control_channel = 0;
	}
}
