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

int inserted_module = 0;

extern long delete_module(const char *, unsigned int);

static int
run_as(uid_t uid, gid_t gid, const char *path, char *const argv[])
{
	pid_t pid;
	int rstatus;

	if ((pid = fork()) < 0) {
		fprintf(stderr, "ERROR: fork failed: %s\n", strerror(errno));
		return -1;
	}
	else if (pid == 0) {
		/* Make sure we run as the full user.  If we're
		 * switching to a non-root user, this won't allow
		 * that process to switch back to root (since the
		 * original process is setuid). */
		if (uid != getuid()) {
			if (do_cap(CAP_SETGID, setresgid, gid, gid, gid) < 0)
				ferror("setresgid");
			if (do_cap(CAP_SETUID, setresuid, uid, uid, uid) < 0)
				ferror("setresuid");
		}

		/* Actually run the command. */
		if (execv(path, argv) < 0)
			perror(path);
		_exit(1);
	}

	if (waitpid(pid, &rstatus, 0) < 0)
		return -1;

	if (WIFEXITED(rstatus))
		return WEXITSTATUS(rstatus);
	return -1;
}

/* Keep the uid and gid settings because we will likely */
/* conditionally restore "-u" */
static int run_stapio(char **argv)
{
	uid_t uid = getuid();
	gid_t gid = getgid();
	argv[0] = PKGLIBDIR "/stapio";

	if (verbose >= 2) {
		int i = 0;
		fprintf(stderr, "execing: ");
		while (argv[i]) {
			fprintf(stderr, "%s ", argv[i]);
			i++;
		}
		fprintf(stderr, "\n");		
	}
	return run_as(uid, gid, argv[0], argv);
}


int init_staprun(void)
{
	dbug(2, "init_staprun\n");

	if (mountfs() < 0)
		return -1;

	if (!attach_mod) {
		if (insert_module() < 0)
			return -1;
		else
			inserted_module = 1;
	}
	
	return 0;
}
	
static void cleanup(int rc)
{
	/* Only cleanup once. */
	static int done = 0;
	if (done == 0)
		done = 1;
	else
		return;

	dbug(2, "rc=%d, inserted_module=%d\n", rc, inserted_module);

	/* rc == 2 means disconnected */
	if (rc == 2)
		return;

	/* If we inserted the module and did not get rc==2, then */
	/* we really want to remove it. */
	if (inserted_module || rc == 3) {
		long ret;
		dbug(2, "removing module %s\n", modname);
		ret = do_cap(CAP_SYS_MODULE, delete_module, modname, 0);
		if (ret != 0) {
			fprintf(stderr, "ERROR: Error removing module '%s': %s\n",
				modname, moderror(errno));
		}
	}
}

static void exit_cleanup(void)
{
	dbug(2, "something exited...\n");
	cleanup(1);
}

int main(int argc, char **argv)
{
	int rc;

	if (atexit(exit_cleanup))
		ferror("cannot set exit function\n");

	if (!init_cap())
		return 1;

	/* Get rid of a few standard environment variables (which */
	/* might cause us to do unintended things). */
	rc = unsetenv("IFS") || unsetenv("CDPATH") || unsetenv("ENV")
		|| unsetenv("BASH_ENV");
	if (rc) {
		fprintf(stderr, "ERROR: unsetenv failed: %s\n",
			strerror(errno));
		exit(-1);
	}
	
	setup_signals();

	parse_args(argc, argv);

	if (buffer_size)
		dbug(1, "Using a buffer of %u bytes.\n", buffer_size);

	if (optind < argc) {
		if (strlen(argv[optind]) > sizeof(modpath)) {
			fprintf(stderr,
				"ERROR: Module path '%s' is larger than buffer.\n",
				argv[optind]);
			exit(-1);
		}
		/* No need to check for overflow because of check
		 * above. */
		strcpy(modpath, argv[optind++]);
		parse_modpath();
		dbug(2, "modpath=\"%s\", modname=\"%s\"\n", modpath, modname);
	}

        if (optind < argc) {
		if (attach_mod) {
			fprintf(stderr, "ERROR: Cannot have module options with attach (-A).\n");
			usage(argv[0]);
		} else {
			unsigned start_idx = 0;
			while (optind < argc && start_idx+1 < MAXMODOPTIONS)
				modoptions[start_idx++] = argv[optind++];
			modoptions[start_idx] = NULL;
		}
	}

	if (*modpath == '\0') {
		fprintf(stderr, "ERROR: Need a module name or path to load.\n");
		usage(argv[0]);
	}

	if (check_permissions() != 1)
		usage(argv[0]);

	/* now bump the priority */
	rc = do_cap(CAP_SYS_NICE, setpriority, PRIO_PROCESS, 0, -10);
	/* failure is not fatal in this case */
	if (rc < 0)
		perror("setpriority");

	if (init_staprun())
		exit(1);

	setup_staprun_signals();

	rc = run_stapio(argv);
	cleanup(rc);

	return 0;
}
