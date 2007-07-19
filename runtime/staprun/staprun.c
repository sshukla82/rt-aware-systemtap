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

extern char *optarg;
extern int optopt;
extern int optind;

char modname[128];
char *modpath = NULL;
#define MAXMODOPTIONS 64
char *modoptions[MAXMODOPTIONS];

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

		add_cap(CAP_SETUID); add_cap(CAP_SETGID);
		if (setresgid(gid, gid, gid) < 0)
			perror("setresgid");
		if (setresuid(uid, uid, uid) < 0)
			perror("setresuid");
		del_cap(CAP_SETUID); del_cap(CAP_SETGID);

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


static int
run_stapio(char **argv)
{
	dbug (2, "execing stapio\n");
	return run_as(getuid(), getgid(), PKGLIBDIR "/stapio", argv);
}


int
init_staprun(void)
{
	dbug(2, "init_staprun\n");

	if (mountfs() < 0)
		return -1;

	if (insert_module() < 0)
		return -1;

	return 0;
}
	
extern long delete_module(const char *, unsigned int);

static void
cleanup(int rc)
{
	/* rc == 2 means disconnected */
	if (rc != 2) {
		long ret;
		dbug(2, "removing module %s...\n", modname);
		add_cap(CAP_SYS_MODULE);
		ret = delete_module(modname, 0);
		del_cap(CAP_SYS_MODULE);
		if (ret)
			printf("delete_module returned %ld\n", ret);
	}
}

int
main(int argc, char **argv)
{
	int rc;

	if (!init_cap())
		exit(-1);

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

	if (check_permissions() != 1)
		usage(argv[0]);

	/* now bump the priority */
	rc = do_cap(CAP_SYS_NICE, setpriority, PRIO_PROCESS, 0, -10);
	/* failure is not fatal in this case*/
	if (rc < 0)
		perror("setpriority");

	if (init_staprun())
		exit(1);

	setup_staprun_signals();

	rc = run_stapio(argv);
	cleanup(rc);

	return 0;
}
