/* -*- linux-c -*-
 *
 * common.h - include file for common.c
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2007 Red Hat Inc.
 */

extern int verbose;
extern int target_pid;
extern unsigned int buffer_size;

extern char *target_cmd;
extern char *outfile_name;

extern int attach_mod;
extern int load_only;

extern void parse_args(int argc, char **argv);
extern void usage(char *prog);

extern void fatal_handler (int signum);
extern void setup_signals(void);

extern int using_old_transport(void);

extern int check_permissions(void);
