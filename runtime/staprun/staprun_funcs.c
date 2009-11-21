/* -*- linux-c -*-
 *
 * staprun_funcs.c - staprun functions
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2007-2009 Red Hat Inc.
 */

#include "config.h"
#include "staprun.h"
#if HAVE_NSS
#include "modverify.h"
#endif

#include <sys/mount.h>
#include <sys/utsname.h>
#include <grp.h>
#include <pwd.h>
#include <assert.h>

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

int insert_module(
  const char *path,
  const char *special_options,
  char **options,
  assert_permissions_func assert_permissions
) {
	int i;
	long ret;
	void *file;
	char *opts;
	int fd, saved_errno;
	char module_realpath[PATH_MAX];
	struct stat sbuf;

	dbug(2, "inserting module\n");

	if (special_options)
		opts = strdup(special_options);
	else
		opts = strdup("");
	if (opts == NULL) {
		_perr("allocating memory failed");
		return -1;
	}
	for (i = 0; options[i] != NULL; i++) {
		opts = realloc(opts, strlen(opts) + strlen(options[i]) + 2);
		if (opts == NULL) {
			_perr("[re]allocating memory failed");
			return -1;
		}
		strcat(opts, " ");
		strcat(opts, options[i]);
	}
	dbug(2, "module options: %s\n", opts);

	/* Use realpath() to canonicalize the module path. */
	if (realpath(path, module_realpath) == NULL) {
		perr("Unable to canonicalize path \"%s\"", path);
		return -1;
	}

        /* Use module_realpath from this point on. "Poison" 'path'
	   by setting it to NULL so that it doesn't get used again by
	   mistake.  */
        path = NULL;

	/* Open the module file. Work with the open file descriptor from this
	   point on to avoid TOCTOU problems. */
	fd = open(module_realpath, O_RDONLY);
	if (fd < 0) {
		perr("Error opening '%s'", module_realpath);
		return -1;
	}

	/* Now that the file is open, figure out how big it is. */
	if (fstat(fd, &sbuf) < 0) {
		_perr("Error stat'ing '%s'", module_realpath);
		close(fd);
		return -1;
	}

	/* mmap in the entire module. Work with the memory mapped data from this
	   point on to avoid a TOCTOU race between path and signature checking
	   below and module loading.  */
	file = mmap(NULL, sbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		_perr("Error mapping '%s'", module_realpath);
		close(fd);
		free(opts);
		return -1;
	}

	/* Check whether this module can be loaded by the current user.
	 * check_permissions will exit(-1) if permissions are insufficient*/
	assert_permissions (module_realpath, file, sbuf.st_size);

	STAP_PROBE1(staprun, insert__module, (char*)module_realpath);
	/* Actually insert the module */
	ret = init_module(file, sbuf.st_size, opts);
	saved_errno = errno;

	/* Cleanup. */
	free(opts);
	munmap(file, sbuf.st_size);
	close(fd);

	if (ret != 0) {
		err("Error inserting module '%s': %s\n", module_realpath, moderror(saved_errno));
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
          	rc = mount ("debugfs", DEBUGFSDIR, "debugfs", 0, NULL);
		if (rc == 0)
			return 0;
		/* If we got ENODEV, that means that debugfs isn't
		 * supported, so we'll need try try relayfs.  If we
		 * didn't get ENODEV, we got a real error. */
		else if (errno != ENODEV) {
			perr("Couldn't mount %s", DEBUGFSDIR);
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
		err("%s exists but isn't a directory.\n", RELAYFSDIR);
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
                /* XXX: Why not just chown() the thing? */
		if (setuid (0) < 0) {
			_perr("Couldn't change user while creating %s", RELAYFSDIR);
			return -1;
		}
		if (setgid (0) < 0) {
			_perr("Couldn't change group while creating %s", RELAYFSDIR);
			return -1;
		}

		/* Try to create the directory, saving the return
		 * status and errno value. */
		rc = mkdir(RELAYFSDIR, 0755);
		saved_errno = errno;

		/* Restore everything we changed. */
		if (setgid (gid) < 0) {
			_perr("Couldn't restore group while creating %s", RELAYFSDIR);
			return -1;
		}
		if (setuid (uid) < 0) {
			_perr("Couldn't restore user while creating %s", RELAYFSDIR);
			return -1;
		}
		umask(old_umask);

		/* If creating the directory failed, error out. */
		if (rc < 0) {
			err("Couldn't create %s: %s\n", RELAYFSDIR, strerror(saved_errno));
			return -1;
		}
	}

	/* Now that we're sure the directory exists, try mounting RELAYFSDIR. */
	if (mount ("relayfs", RELAYFSDIR, "relayfs", 0, NULL) < 0) {
		perr("Couldn't mount %s", RELAYFSDIR);
		return -1;
	}
	return 0;
}

#if HAVE_NSS
/*
 * Modules which have been signed using a certificate and private key
 * corresponding to a certificate and public key in the database in
 * the '$sysconfdir/systemtap/staprun' directory may be loaded by
 * anyone.
 *
 * Returns: -1 on errors, 0 on failure, 1 on success.
 */
static int
check_signature(const char *path, const void *module_data, off_t module_size)
{
  char signature_realpath[PATH_MAX];
  int rc;

  dbug(2, "checking signature for %s\n", path);

  /* Add the .sgn suffix to the canonicalized module path to get the signature
     file path.  */
  if (strlen (path) >= PATH_MAX - 4) {
    err("Path \"%s.sgn\" is too long.", path);
    return -1;
  }
  sprintf (signature_realpath, "%s.sgn", path);

  rc = verify_module (signature_realpath, path, module_data, module_size);

  dbug(2, "verify_module returns %d\n", rc);

  return rc;
}
#endif /* HAVE_NSS */

/*
 * Members of the 'stapusr' group can only use "blessed" modules -
 * ones in the '/lib/modules/KVER/systemtap' directory.  Make sure the
 * module path is in that directory.
 *
 * Returns: -1 on errors, 0 on failure, 1 on success.
 */
static int
check_path(const char *module_path)
{
	char staplib_dir_path[PATH_MAX];
	char staplib_dir_realpath[PATH_MAX];
	struct utsname utsbuf;
	struct stat sb;

	/* First, we need to figure out what the kernel
	 * version is and build the '/lib/modules/KVER/systemtap' path. */
	if (uname(&utsbuf) != 0) {
		_perr("ERROR: Unable to determine kernel version, uname failed");
		return -1;
	}
	if (sprintf_chk(staplib_dir_path, "/lib/modules/%s/systemtap", utsbuf.release))
		return -1;

	/* Validate /lib/modules/KVER/systemtap. */
	if (stat(staplib_dir_path, &sb) < 0) {
		perr("Members of the \"stapusr\" group can only use modules within\n"
		     "  the \"%s\" directory.\n"
		     "  Error getting information on that directory", staplib_dir_path);
		return -1;
	}
	/* Make sure it is a directory. */
	if (! S_ISDIR(sb.st_mode)) {
		err("ERROR: Members of the \"stapusr\" group can only use modules within\n"
		    "  the \"%s\" directory.\n"
		    "  That path must refer to a directory.\n", staplib_dir_path);
		return -1;
	}
	/* Make sure it is owned by root. */
	if (sb.st_uid != 0) {
		err("ERROR: Members of the \"stapusr\" group can only use modules within\n"
		    "  the \"%s\" directory.\n"
		    "  That directory should be owned by root.\n", staplib_dir_path);
		return -1;
	}
	/* Make sure it isn't world writable. */
	if (sb.st_mode & S_IWOTH) {
		err("ERROR: Members of the \"stapusr\" group can only use modules within\n"
		    "  the \"%s\" directory.\n"
		    "  That directory should not be world writable.\n", staplib_dir_path);
		return -1;
	}

	/* Use realpath() to canonicalize the module directory
	 * path. */
	if (realpath(staplib_dir_path, staplib_dir_realpath) == NULL) {
		perr("Members of the \"stapusr\" group can only use modules within\n"
		     "  the \"%s\" directory.\n"
		     "  Unable to canonicalize that directory",	staplib_dir_path);
		return -1;
	}

	/* To make sure the user can't specify something like
	 * /lib/modules/`uname -r`/systemtapmod.ko, put a '/' on the
	 * end of staplib_dir_realpath. */
	if (strlen(staplib_dir_realpath) < (PATH_MAX - 1))
		strcat(staplib_dir_realpath, "/");
	else {
		err("Path \"%s\" is too long.", staplib_dir_realpath);
		return -1;
	}

	/* Now we've got two canonicalized paths.  Make sure
	 * path starts with staplib_dir_realpath. */
	if (strncmp(staplib_dir_realpath, module_path,
		    strlen(staplib_dir_realpath)) != 0) {
		err("ERROR: Members of the \"stapusr\" group can only use modules within\n"
		    "  the \"%s\" directory.\n"
		    "  Module \"%s\" does not exist within that directory.\n",
		    staplib_dir_path, module_path);
		return 0;
	}
	return 1;
}

/*
 * Check the user's group membership.
 *
 * o members of stapdev can do anything
 * o members of stapusr can load modules from /lib/modules/KVER/systemtap
 *
 * Returns: -2 if neither group exists
 *          -1 for other errors
 *           0 on failure
 *           1 on success
 */
static int
check_groups (const char *module_path)
{
	gid_t gid, gidlist[NGROUPS_MAX];
	gid_t stapdev_gid, stapusr_gid;
	int i, ngids;
	struct group *stgr;

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

	/* If neither group was found, then return -2.  */
	if (stapdev_gid == (gid_t)-1 && stapusr_gid == (gid_t)-1)
	  return -2;

	/* According to the getgroups() man page, getgroups() may not
	 * return the effective gid, so try to match it first. */
	gid = getegid();
	if (gid == stapdev_gid)
		return 1;

	if (gid != stapusr_gid) {
		/* Get the list of the user's groups. */
		ngids = getgroups(NGROUPS_MAX, gidlist);
		if (ngids < 0) {
			perr("Unable to retrieve group list");
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
				gid = stapusr_gid;
		}
		if (gid != stapusr_gid) {
			unprivileged_user = 1;
			return 0;
		}
	}

	/* At this point the user is only a member of the 'stapusr'
	 * group.  Members of the 'stapusr' group can only use modules
	 * in /lib/modules/KVER/systemtap.  Make sure the module path
	 * is in that directory. */
	return check_path (module_path);
}

/*
 * Check the user's permissions.  Is he allowed to run staprun, or is
 * he limited to "blessed" modules?
 *
 * There are several levels of possible permission:
 *
 * 1) root can do anything
 * 2) members of stapdev can do anything
 * 3) members of stapusr can load modules from /lib/modules/KVER/systemtap
 * 4) anyone can load a module which has been signed by a trusted signer
 *
 * It is only an error if all 4 levels of checking fail
 */
void assert_stap_module_permissions(
  const char *module_path __attribute__ ((unused)),
  const void *module_data __attribute__ ((unused)),
  off_t module_size __attribute__ ((unused))
) {
	int check_groups_rc;

#if HAVE_NSS
	/* Attempt to verify the module against its signature. Return failure
	   if the module has been tampered with (altered).  */
	int check_signature_rc = check_signature (module_path, module_data, module_size);
	if (check_signature_rc == MODULE_ALTERED)
		exit(-1);
#endif

	/* If we're root, we can do anything. */
	if (getuid() == 0) {
		/* ... like overriding the real UID */
		const char *env_id = getenv("SYSTEMTAP_REAL_UID");
		if (env_id && setreuid(atoi(env_id), -1))
			err("WARNING: couldn't set staprun UID to '%s': %s",
					env_id, strerror(errno));

		/* ... or overriding the real GID */
		env_id = getenv("SYSTEMTAP_REAL_GID");
		if (env_id && setregid(atoi(env_id), -1))
			err("WARNING: couldn't set staprun GID to '%s': %s",
					env_id, strerror(errno));

		return;
	}

	/* Check permissions for group membership.  */
	check_groups_rc = check_groups (module_path);
	if (check_groups_rc == 1)
		return;

	/* The user is an ordinary user. If the module has been signed with
	 * an authorized certificate and private key, then we will load it for
	 * anyone.  */
#if HAVE_NSS
	if (check_signature_rc == MODULE_OK)
		return;
	assert (check_signature_rc == MODULE_UNTRUSTED || check_signature_rc == MODULE_CHECK_ERROR);
#endif

	/* We are an ordinary user and the module was not signed by a trusted
	   signer.  */
	err("ERROR: You are trying to run stap as a normal user.\n"
	    "You should either be root, or be part of either "
	    "group \"stapdev\" or group \"stapusr\".\n");
	if (check_groups_rc == -2) {
		err("Your system doesn't seem to have either group.\n");
		check_groups_rc = -1;
	}
#if HAVE_NSS
	err("Alternatively, your module must be compiled using the --unprivileged option and signed by a trusted signer.\n"
	    "For more information, please consult the \"SAFETY AND SECURITY\" section of the \"stap(1)\" manpage\n");
#endif

	exit(-1);
}

/*
 * For the uprobes.ko module, if we have NSS, then
 * check the signature. Otherwise go ahead and load it.
 */
void assert_uprobes_module_permissions(
  const char *module_path __attribute__ ((unused)),
  const void *module_data __attribute__ ((unused)),
  off_t module_size __attribute__ ((unused))
) {
#if HAVE_NSS
	/* Attempt to verify the module against its signature. Return failure
	   if the module has been tampered with (altered).  */
	int rc = check_signature (module_path, module_data, module_size);
	if (rc == MODULE_ALTERED)
		exit(-1);
	if (rc == MODULE_OK)
		return;
	assert (rc == MODULE_UNTRUSTED || rc == MODULE_CHECK_ERROR);
	err("Signature verification failed for module %s.\n", module_path);
	if (rc == MODULE_UNTRUSTED) {
		err("Run '" BINDIR "/stap-sign-module %s' as root and/or\n", module_path);
		err("run '" BINDIR "/stap-authorize-signing-cert %s' as root\n",
		    SYSCONFDIR "/systemtap/ssl/server/stap.cert");
	}
	exit(-1);
#endif
}
