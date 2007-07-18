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
#include <grp.h>
#include <unistd.h>
#include <sys/utsname.h>

extern char *optarg;
extern int optopt;
extern int optind;

void
parse_args(int argc, char **argv)
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

#define ERR_MSG "\nUNEXPECTED FATAL ERROR in staprun. Please file a bug report.\n"
void fatal_handler (int signum)
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

int
using_old_transport(void)
{
	struct utsname utsbuf;
	int i;
	long int kver[3];
	char *start, *end;

	if (uname(&utsbuf) != 0) {
		fprintf(stderr,
			"ERROR: Unable to determine kernel version, uname failed: %s\n",
			strerror(errno));
		return -1;
	}

	start = utsbuf.release;
	for (i = 0; i < 3; i++) {
		errno = 0;
		kver[i] = strtol(start, &end, 10);
		if (errno != 0) {
			fprintf(stderr,
				"ERROR: Unable to parse kernel version, strtol failed: %s\n",
				strerror(errno));
			return -1;
		}
		start = end;
		start++;
	}

	if (KERNEL_VERSION(kver[0], kver[1], kver[2])
	    <= KERNEL_VERSION(2, 6, 15)) {
		dbug(2, "Using OLD TRANSPORT\n");
		return 1;
	}
	return 0;
}

/*
 * Members of the 'stapusr' group can only use "blessed" modules -
 * ones in the '/lib/modules/KVER/systemtap' directory.  Make sure the
 * module path is in that directory.
 *
 * Returns: -1 on errors, 0 on failure, 1 on success.
 */
static int
check_path(void)
{
	struct utsname utsbuf;
	char staplib_dir_path[PATH_MAX];
	char staplib_dir_realpath[PATH_MAX];
	char module_realpath[PATH_MAX];

	/* First, we need to figure out what the kernel
	 * version is and build the '/lib/modules/KVER/systemtap' path. */
	if (uname(&utsbuf) != 0) {
		fprintf(stderr,
			"ERROR: Unable to determine kernel version, uname failed: %s\n",
			strerror(errno));
		return -1;
	}
	sprintf(staplib_dir_path, "/lib/modules/%s/systemtap",
		utsbuf.release);

	/* Use realpath() to canonicalize the module directory
	 * path. */
	if (realpath(staplib_dir_path, staplib_dir_realpath) == NULL) {
		fprintf(stderr,
			"ERROR: Unable to canonicalize path \"%s\": %s\n",
			staplib_dir_path, strerror(errno));
		return -1;
	}

	/* Use realpath() to canonicalize the module path. */
	if (realpath(modpath, module_realpath) == NULL) {
		fprintf(stderr,
			"ERROR: Unable to canonicalize path \"%s\": %s\n",
			modpath, strerror(errno));
		return -1;
	}

	/* Now we've got two canonicalized paths.  Make sure
	 * module_realpath starts with staplib_dir_realpath. */
	if (strncmp(staplib_dir_realpath, module_realpath,
		    strlen(staplib_dir_realpath)) != 0) {
		fprintf(stderr,
			"ERROR: Members of the \"stapusr\" group can only use modules within\n"
			"  the \"%s\" directory.\n"
			"  Module \"%s\" does not exist within that directory.\n",
			staplib_dir_path, modpath);
		return 0;
	}
	return 1;
}

/*
 * Check the user's permissions.  Is he allowed to run staprun (or is
 * he limited to "blessed" modules)?
 *
 * Returns: -1 on errors, 0 on failure, 1 on success.
 */
int
check_permissions(void)
{
	gid_t gid, gidlist[NGROUPS_MAX];
	gid_t stapdev_gid, stapusr_gid;
	int i, ngids;
	struct group *stgr;
	int path_check = 0;

	/* If we're root, we can do anything. */
	if (geteuid() == 0)
		return 1;

	/* Lookup the gid for group "stapdev" */
	errno = 0;
	stgr = getgrnam("stapdev");
	/* If we couldn't find the group, just set the gid to an
	 * invalid number.  Just because this group doesn't exist
	 * doesn't mean the other group doesn't exist. */
	if (stgr == NULL)
		stapdev_gid = (gid_t)-1;
	else
		stapdev_gid = stgr->gr_gid;

	/* Lookup the gid for group "stapusr" */
	errno = 0;
	stgr = getgrnam("stapusr");
	/* If we couldn't find the group, just set the gid to an
	 * invalid number.  Just because this group doesn't exist
	 * doesn't mean the other group doesn't exist. */
	if (stgr == NULL)
		stapusr_gid = (gid_t)-1;
	else
		stapusr_gid = stgr->gr_gid;

	/* If neither group was found, just return an error. */
	if (stapdev_gid == (gid_t)-1 && stapusr_gid == (gid_t)-1) {
		fprintf(stderr, "ERROR: unable to find either group \"stapdev\" or group \"stapusr\"\n");
		return -1;
	}

	/* According to the getgroups() man page, getgroups() may not
	 * return the effective gid, so try to match it first. */
	gid = getegid();
	if (gid == stapdev_gid)
		return 1;
	else if (gid == stapusr_gid)
		path_check = 1;

	/* Get the list of the user's groups. */
	ngids = getgroups(NGROUPS_MAX, gidlist);
	if (ngids < 0) {
		fprintf(stderr, "ERROR: Unable to retrieve group list: %s\n",
			strerror(errno));
		return -1;
	}

	for (i = 0; i < ngids; i++) {
		/* If the user is a member of 'stapdev', then we're
		 *  done, since he can use staprun without any
		 *  restrictions. */
		if (gidlist[i] == stapdev_gid)
			return 1;

		/* If the user is a member of 'stapusr', then we'll
		 * need to check the module path.  However, we'll keep
		 * checking groups since it is possible the user is a
		 * member of both groups and we haven't seen the
		 * 'stapdev' group yet. */
		if (gidlist[i] == stapusr_gid)
			path_check = 1;
	}

	/* If path_check is 0, then the user isn't a member of either
	 * group.  Error out. */
	if (path_check == 0) {
		fprintf(stderr, "ERROR: you must be a member of either group \"stapdev\" or group \"stapusr\"\n");
		return 0;
	}

	/* At this point the user is only a member of the 'stapusr'
	 * group.  Members of the 'stapusr' group can only use modules
	 * in /lib/modules/KVER/systemtap.  Make sure the module path
	 * is in that directory. */
	return check_path();
}
