/* -*- linux-c -*-
 *
 * staprun_funcs.c - staprun functions
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2007 Red Hat Inc.
 */

#include "staprun.h"
#include <sys/mount.h>
#include <sys/utsname.h>
#include <grp.h>
#include <pwd.h>

void setup_staprun_signals(void)
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

extern long init_module(void *, unsigned long, const char *);

/* Module errors get translated. */
const char *moderror(int err)
{
	switch (err) {
	case ENOEXEC:
		return "Invalid module format";
	case ENOENT:
		return "Unknown symbol in module";
	case ESRCH:
		return "Module has wrong symbol version";
	case EINVAL:
		return "Invalid parameters";
	default:
		return strerror(err);
	}
}

int insert_module(void)
{
	int i;
	long ret;
	void *file;
	char *opts;
	int fd, saved_errno;
	struct stat sbuf;
		
	if (attach_mod)
		return 0;

	dbug(2, "inserting module\n");

	opts = malloc(128);
	if (opts == NULL) {
		fprintf(stderr, "ERROR: allocating memory failed: %s\n",
			strerror(errno));
		return -1;
	}
	sprintf(opts, "_stp_bufsize=%d", buffer_size);
	for (i = 0; modoptions[i] != NULL; i++) {
		opts = realloc(opts, strlen(opts) + strlen(modoptions[i]) + 2);
		if (opts == NULL) {
			fprintf(stderr,
				"ERROR: reallocating memory failed: %s\n",
				strerror(errno));
			return -1;
		}
		strcat(opts, " ");
		strcat(opts, modoptions[i]);
	}
	dbug(2, "module options: %s\n", opts);

	/* Open the module file. */
	fd = open(modpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "ERROR: Error opening '%s': %s\n",
			modpath, strerror(errno));
		return -1;
	}
	
	/* Now that the file is open, figure out how big it is. */
	if (fstat(fd, &sbuf) < 0) {
		close(fd);
		fprintf(stderr, "ERROR: Error stat'ing '%s': %s\n",
			modpath, strerror(errno));
		return -1;
	}

	/* mmap in the entire module. */
	file = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		close(fd);
		free(opts);
		fprintf(stderr, "ERROR: Error mapping '%s': %s\n",
			modpath, strerror(errno));
		return -1;
	}
	    
	/* Actually insert the module */
	ret = do_cap(CAP_SYS_MODULE, init_module, file, sbuf.st_size, opts);
	saved_errno = errno;

	/* Cleanup. */
	free(opts);
	munmap(file, sbuf.st_size);
	close(fd);

	if (ret != 0) {
		fprintf(stderr, "ERROR: Error inserting module '%s': %s\n",
			modpath, moderror(saved_errno));
		return -1; 
	}
	return 0;
}

int mountfs(void)
{
	struct stat sb;
	struct statfs st;
	int rc;

	/* If the debugfs dir is already mounted correctly, we're done. */
 	if (statfs(DEBUGFSDIR, &st) == 0
	    && (int) st.f_type == (int) DEBUGFS_MAGIC)
		return 0;

	/* If DEBUGFSDIR exists (and is a directory), try to mount
	 * DEBUGFSDIR. */
	rc = stat(DEBUGFSDIR, &sb);
	if (rc == 0 && S_ISDIR(sb.st_mode)) {
		/* If we can mount the debugfs dir correctly, we're done. */
		rc = do_cap(CAP_SYS_ADMIN, mount, "debugfs", DEBUGFSDIR,
			    "debugfs", 0, NULL); 
		if (rc == 0)
			return 0;
		/* If we got ENODEV, that means that debugfs isn't
		 * supported, so we'll need try try relayfs.  If we
		 * didn't get ENODEV, we got a real error. */
		else if (errno != ENODEV) {
			fprintf(stderr, "ERROR: Couldn't mount %s: %s\n",
				DEBUGFSDIR, strerror(errno));
			return -1;
		}
	}
	
	/* DEBUGFSDIR couldn't be mounted.  So, try RELAYFSDIR. */

	/* If the relayfs dir is already mounted correctly, we're done. */
	if (statfs(RELAYFSDIR, &st) == 0
	    && (int)st.f_type == (int)RELAYFS_MAGIC)
		return 0;

	/* Ensure that RELAYFSDIR exists and is a directory. */
	rc = stat(RELAYFSDIR, &sb);
	if (rc == 0 && ! S_ISDIR(sb.st_mode)) {
		fprintf(stderr, "ERROR: %s exists but isn't a directory.\n",
			RELAYFSDIR);
		return -1;
	}
	else if (rc < 0) {
		mode_t old_umask;
		int saved_errno;
		gid_t gid = getgid();
		uid_t uid = getuid();

		/* To ensure the directory gets created with the proper
		 * permissions, set umask to a known value. */
		old_umask = umask(0002);

		/* To ensure the directory gets created with the
		 * proper group, we'll have to temporarily switch to
		 * root. */
		if (do_cap(CAP_SETUID, setuid, 0) < 0) {
			fprintf(stderr,
				"ERROR: Couldn't change user while creating %s: %s\n",
				RELAYFSDIR, strerror(errno));
			return -1;
		}
		if (do_cap(CAP_SETGID, setgid, 0) < 0) {
			fprintf(stderr,
				"ERROR: Couldn't change group while creating %s: %s\n",
				RELAYFSDIR, strerror(errno));
			return -1;
		}

		/* Try to create the directory, saving the return
		 * status and errno value. */
		rc = mkdir(RELAYFSDIR, 0755);
		saved_errno = errno;

		/* Restore everything we changed. */
		if (do_cap(CAP_SETGID, setgid, gid) < 0) {
			fprintf(stderr,
				"ERROR: Couldn't restore group while creating %s: %s\n",
				RELAYFSDIR, strerror(errno));
			return -1;
		}
		if (do_cap(CAP_SETUID, setuid, uid) < 0) {
			fprintf(stderr,
				"ERROR: Couldn't restore user while creating %s: %s\n",
				RELAYFSDIR, strerror(errno));
			return -1;
		}
		umask(old_umask);

		/* If creating the directory failed, error out. */
		if (rc < 0) {
			fprintf(stderr, "ERROR: Couldn't create %s: %s\n",
				RELAYFSDIR, strerror(saved_errno));
			return -1;
		}
	}

	/* Now that we're sure the directory exists, try mounting
	 * RELAYFSDIR. */
	if (do_cap(CAP_SYS_ADMIN, mount, "relayfs", RELAYFSDIR,
		   "relayfs", 0, NULL) < 0) {
		fprintf(stderr, "ERROR: Couldn't mount %s: %s\n",
			RELAYFSDIR, strerror(errno));
		return -1;
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
		if (errno == ENOENT)
			fprintf(stderr, 
				"ERROR: Members of the \"stapusr\" group can only use modules within\n"
				"  the \"%s\" directory.\n"
				"  That directory does not exist.\n",
				staplib_dir_path);
		else
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
int check_permissions(void)
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
