/* -*- linux-c -*-
 *
 * common.c - staprun suid/user common code
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2007 Red Hat Inc.
 */

#include "staprun.h"
#include "common.h"
#include <sys/types.h>
#include <unistd.h>

extern char *optarg;
extern int optopt;
extern int optind;

/* variables needed by parse_args() */
int verbose;
int target_pid;
unsigned int buffer_size;
char *target_cmd;
char *outfile_name;
int attach_mod;
int load_only;

void parse_args(int argc, char **argv)
{
	int c;

	/* Initialize option variables. */
	verbose = 0;
	target_pid = 0;
	buffer_size = 0;
	target_cmd = NULL;
	outfile_name = NULL;
	attach_mod = 0;
	load_only = 0;

	while ((c = getopt(argc, argv, "ALvb:t:d:c:o:x:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'b':
		{
			int size = (unsigned)atoi(optarg);
			if (!size)
				usage(argv[0]);
			if (size > 64) {
				fprintf(stderr, "Maximum buffer size is 64 (MB)\n");
				exit(1);
			}
			buffer_size = size;
			break;
		}
		case 't':
		case 'x':
			target_pid = atoi(optarg);
			break;
		case 'd':
			/* obsolete internal option used by stap */
			break;
		case 'c':
			target_cmd = optarg;
			break;
		case 'o':
			outfile_name = optarg;
			break;
		case 'A':
			attach_mod = 1;
			break;
		case 'L':
			load_only = 1;
			break;
		default:
			usage(argv[0]);
		}
	}
}

void usage(char *prog)
{
	fprintf(stderr, "\n%s [-v]  [-c cmd ] [-x pid] [-u user]\n"
                "\t[-A modname]] [-L] [-b bufsize] [-o FILE] kmod-name [kmod-options]\n", prog);
	fprintf(stderr, "-v              Increase verbosity.\n");
	fprintf(stderr, "-c cmd          Command \'cmd\' will be run and staprun will\n");
	fprintf(stderr, "                exit when it does.  The '_stp_target' variable\n");
	fprintf(stderr, "                will contain the pid for the command.\n");
	fprintf(stderr, "-x pid          Sets the '_stp_target' variable to pid.\n");
	fprintf(stderr, "-o FILE         Send output to FILE.\n");
	fprintf(stderr, "-b buffer size  The systemtap module specifies a buffer size.\n");
	fprintf(stderr, "                Setting one here will override that value.  The\n");
	fprintf(stderr, "                value should be an integer between 1 and 64\n");
	fprintf(stderr, "                which be assumed to be the buffer size in MB.\n");
	fprintf(stderr, "                That value will be per-cpu in bulk mode.\n");
	fprintf(stderr, "-L              Load module and start probes, then detach.\n");
	fprintf(stderr, "-A modname      Attach to systemtap module modname.\n");
	exit(1);
}

void path_parse_modname (char *path)
{
	char *mptr = rindex (path, '/');
	if (mptr == NULL) 
		mptr = path;
	else
		mptr++;

	if (strlen(mptr) >= sizeof(modname)) {
		err("Module name larger than modname buffer.\n");
		exit (-1);
	}
	strcpy(modname, mptr);			
	
	mptr = rindex(modname, '.');
	if (mptr)
		*mptr = '\0';
}

#define ERR_MSG "\nUNEXPECTED FATAL ERROR in staprun. Please file a bug report.\n"
static void fatal_handler (int signum)
{
        int rc;
        char *str = strsignal(signum);
        rc = write (STDERR_FILENO, ERR_MSG, sizeof(ERR_MSG));
        rc = write (STDERR_FILENO, str, strlen(str));
        rc = write (STDERR_FILENO, "\n", 1);
        _exit(-1);
}

void setup_signals(void)
{
	sigset_t s;
	struct sigaction a;

	/* blocking all signals while we set things up */
	sigfillset(&s);
#ifdef SINGLE_THREADED
	sigprocmask(SIG_SETMASK, &s, NULL);
#else
	pthread_sigmask(SIG_SETMASK, &s, NULL);
#endif
	/* set some of them to be ignored */
	memset(&a, 0, sizeof(a));
	sigfillset(&a.sa_mask);
	a.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &a, NULL);
	sigaction(SIGUSR2, &a, NULL);

	/* for serious errors, handle them in fatal_handler */
	a.sa_handler = fatal_handler;
	sigaction(SIGBUS, &a, NULL);
	sigaction(SIGFPE, &a, NULL);
	sigaction(SIGILL, &a, NULL);
	sigaction(SIGSEGV, &a, NULL);
	sigaction(SIGXCPU, &a, NULL);
	sigaction(SIGXFSZ, &a, NULL);

	/* unblock all signals */
	sigemptyset(&s);

#ifdef SINGLE_THREADED
	sigprocmask(SIG_SETMASK, &s, NULL);
#else
	pthread_sigmask(SIG_SETMASK, &s, NULL);
#endif
}
