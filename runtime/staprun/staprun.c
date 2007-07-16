/* -*- linux-c -*-
 *
 * staprun.c - SystemTap module loader 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2007 Red Hat, Inc.
 *
 */

#include "staprun.h"
#include "common.h"
#include <pwd.h>

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

char modname[128];
char *modpath = NULL;
#define MAXMODOPTIONS 64
char *modoptions[MAXMODOPTIONS];
uid_t cmd_uid;
gid_t cmd_gid;

/* globals */
int control_channel = 0;
int ncpus;
int use_old_transport = 0;

static void
path_parse_modname (char *path)
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

static void
setup_main_signals()
{
	struct sigaction a;
	memset(&a, 0, sizeof(a));
	sigfillset(&a.sa_mask);
	a.sa_handler = SIG_IGN;

	sigaction(SIGINT, &a, NULL);
	sigaction(SIGTERM, &a, NULL);
	sigaction(SIGHUP, &a, NULL);
	sigaction(SIGQUIT, &a, NULL);
}

static int
run_as(uid_t uid, gid_t gid, const char *path, char *const argv[])
{
	pid_t pid;
	int rstatus;

	if ((pid = fork()) < 0) {
		return -1;
	}
	else if (pid == 0) {
		/* Make sure we run as the full user.  If we're
		 * switching to a non-root user, this won't allow
		 * that process to switch back to root (since the
		 * original process is setuid). */
		if (setresgid(gid, gid, gid) < 0)
			perror("setresgid");
		if (setresuid(uid, uid, uid) < 0)
			perror("setresuid");

		/* Actually run the command. */
		if (execv(path, argv) < 0)
			perror(path);
		_exit(-1);
	}

	if (waitpid(pid, &rstatus, 0) < 0)
		return -1;

	if (WIFEXITED(rstatus))
		return WEXITSTATUS(rstatus);
	return -1;
}

/* stp_check script */
#ifdef PKGLIBDIR
char *stp_check=PKGLIBDIR "/stp_check";
#else
char *stp_check="stp_check";
#endif

static int
run_stp_check (void)
{
	int ret ;
	char *argv[] = { stp_check, NULL };

	/* run the _stp_check script */
	dbug(2, "executing %s\n", stp_check);
	ret = run_as(0, 0, stp_check, argv);
	return ret;
}

static int
run_stapio(char **argv)
{
	dbug (2, "execing stapio\n");
	return run_as(cmd_uid, cmd_gid, PKGLIBDIR "/stapio", argv);
}

static int
setup_ctl_channel(int setup)
{
	char buf[PATH_MAX];
	struct statfs st;
	uid_t uid = 0;
	gid_t gid = 0;

	if (setup) {
		uid = cmd_uid;
		gid = cmd_gid;
	}

 	if (statfs("/sys/kernel/debug", &st) == 0
	    && (int) st.f_type == (int) DEBUGFS_MAGIC)
 		sprintf (buf, "/sys/kernel/debug/systemtap/%s/cmd", modname);
	else
		sprintf (buf, "/proc/systemtap/%s/cmd", modname);
	dbug(2, "attempting to chown %s\n", buf);
	if (chown(buf, uid, gid) < 0) {
		perror("chown");
		return -1;
	}
	return 0;
}

static int
setup_relayfs(int setup)
{
	int i;
	struct statfs st;
	char buf[PATH_MAX], relay_filebase[PATH_MAX];
	uid_t uid = 0;
	gid_t gid = 0;

	if (setup) {
		uid = cmd_uid;
		gid = cmd_gid;
	}

	dbug(1, "setting up relayfs\n");
 	if (statfs("/sys/kernel/debug", &st) == 0
	    && (int) st.f_type == (int) DEBUGFS_MAGIC)
		sprintf(relay_filebase, "/sys/kernel/debug/systemtap/%s",
			modname);
 	else {
		fprintf(stderr,"Cannot find relayfs or debugfs mount point.\n");
		return -1;
	}

	for (i = 0; i < NR_CPUS; i++) {
		sprintf(buf, "%s/trace%d", relay_filebase, i);
		dbug(2, "attempting to chown %s\n", buf);
		if (chown(buf, uid, gid) < 0)
			break;
	}
	return 0;
}

static int
setup_oldrelayfs(int setup)
{
	int i;
	struct statfs st;
	char buf[PATH_MAX], relay_filebase[PATH_MAX], proc_filebase[PATH_MAX];
	uid_t uid = 0;
	gid_t gid = 0;

	if (setup) {
		uid = cmd_uid;
		gid = cmd_gid;
	}

	dbug(1, "setting up relayfs\n");
 	if (statfs("/sys/kernel/debug", &st) == 0
	    && (int) st.f_type == (int) DEBUGFS_MAGIC) {
 		sprintf(relay_filebase,
			"/sys/kernel/debug/systemtap/%s/trace", modname);
 		sprintf(proc_filebase,
			"/sys/kernel/debug/systemtap/%s/", modname);
	}
	else if (statfs("/mnt/relay", &st) == 0
		 && (int) st.f_type == (int) RELAYFS_MAGIC) {
 		sprintf(relay_filebase,
			"/mnt/relay/systemtap/%s/trace", modname);
 		sprintf(proc_filebase, "/proc/systemtap/%s/", modname);
 	}
	else {
		fprintf(stderr,"Cannot find relayfs or debugfs mount point.\n");
		return -1;
	}

	for (i = 0; i < NR_CPUS; i++) {
		sprintf(buf, "%s%d", relay_filebase, i);
		dbug(2, "attempting to chown %s\n", buf);
		if (chown(buf, uid, gid) < 0)
			break;
		sprintf(buf, "%s%d", proc_filebase, i);
		dbug(2, "attempting to chown %s\n", buf);
		if (chown(buf, uid, gid) < 0)
			break;
	}
	return 0;
}

int
init_staprun(void)
{
	char bufcmd[128];

	dbug(2, "init_staprun\n");
	if (run_stp_check() < 0)
		return -1;

	/* insert module */
	if (! attach_mod) {
		dbug(2, "inserting module\n");
		sprintf(bufcmd, "_stp_bufsize=%d", buffer_size);
		modoptions[0] = "insmod";
		modoptions[1] = modpath;
		modoptions[2] = bufcmd;
		/* modoptions[3...N] set by command line parser. */

		if (run_as(0, 0, "/sbin/insmod", modoptions) != 0) {
			fprintf(stderr,
				"ERROR, couldn't insmod probe module %s\n",
				modpath);
			return -1;
		}
	}

	if (setup_ctl_channel(1) < 0)
		return -1;

	use_old_transport = using_old_transport();
	if (use_old_transport) {
		if (setup_oldrelayfs(1) < 0)
			return -1;
	}
	else {
		if (setup_relayfs(1) < 0)
			return -1;
	}
	return 0;
}
	
static void
cleanup(int rc)
{
	char *argv[] = { "rmmod", "-w", modname, NULL };

	if (rc != 2)
	{
		dbug(2, "removing module %s...\n", modname);
		if (run_as(0, 0, "/sbin/rmmod", argv) != 0) {
			fprintf(stderr,
				"ERROR: couldn't rmmod probe module %s.\n",
				modname);
			exit(1);
		}
	}
	else {
		setup_ctl_channel(0);

		use_old_transport = using_old_transport();
		if (use_old_transport)
			setup_oldrelayfs(0);
		else
			setup_relayfs(0);
	}
}

int
main(int argc, char **argv)
{
	int rc;

	/* Get rid of a few standard environment variables (which
	 * might cause us to do unintended things). */
	rc = unsetenv("IFS") || unsetenv("CDPATH") || unsetenv("ENV")
		|| unsetenv("BASH_ENV");
	if (rc)
		fprintf(stderr, "unsetenv failed: %s\n", strerror(errno));

	setup_signals();

	parse_args(argc, argv);

	if (verbose) {
		if (buffer_size)
			printf ("Using a buffer of %u bytes.\n", buffer_size);
	}

	if (optind < argc) {
		modpath = argv[optind++];
		path_parse_modname(modpath);
		dbug(2, "modpath=\"%s\", modname=\"%s\"\n", modpath, modname);
	}

        if (optind < argc) {
		if (attach_mod) {
			fprintf(stderr, "Cannot have module options with attach (-A).\n");
			usage(argv[0]);
		} else {
			unsigned start_idx = 3; /* reserve three slots in modoptions[] */
			while (optind < argc && start_idx+1 < MAXMODOPTIONS)
				modoptions[start_idx++] = argv[optind++];
			modoptions[start_idx] = NULL;
		}
	}

	if (!modpath) {
		fprintf (stderr, "Need a module to load.\n");
		usage(argv[0]);
	}

	cmd_uid = getuid();
	cmd_gid = getgid();

	if (check_permissions() != 1)
		usage(argv[0]);

	/* now bump the priority */
	setpriority (PRIO_PROCESS, 0, -10);

	if (init_staprun())
		exit(1);

	setup_main_signals();

	rc = run_stapio(argv);
	cleanup(rc);

	return 0;
}
