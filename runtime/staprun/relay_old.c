/* -*- linux-c -*-
 *
 * relay_old.c - staprun relayfs functions for kernels with
 * old relayfs implementations.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 *
 * Copyright (C) 2005-2007 Red Hat Inc.
 */

#include "staprun.h"

/* temporary per-cpu output written here for relayfs, filebase0...N */
static int relay_fd[NR_CPUS];
static int proc_fd[NR_CPUS];
static FILE *percpu_tmpfile[NR_CPUS];
static char *relay_buffer[NR_CPUS];
static pthread_t reader[NR_CPUS];
static int bulkmode = 0;
unsigned subbuf_size = 0;
unsigned n_subbufs = 0;

/* per-cpu buffer info */
static struct buf_status
{
	struct _stp_buf_info info;
	unsigned max_backlog; /* max # sub-buffers ready at one time */
} status[NR_CPUS];


/**
 *	close_relayfs_files - close and munmap buffer and open output file
 */
static void close_relayfs_files(int cpu)
{
	size_t total_bufsize = subbuf_size * n_subbufs;
	if (relay_fd[cpu]) {
		munmap(relay_buffer[cpu], total_bufsize);
		close(relay_fd[cpu]);
		close(proc_fd[cpu]);
		relay_fd[cpu] = 0;
		fclose(percpu_tmpfile[cpu]);
	}
}

/**
 *	close_all_relayfs_files - close and munmap buffers and output files
 */
void close_oldrelayfs(int detach)
{
	int i;

	if (!bulkmode)
		return;
	
	dbug(2, "detach=%d, ncpus=%d\n", detach, ncpus);
	
	if (detach) {
		for (i = 0; i < ncpus; i++)
			if (reader[i]) pthread_cancel(reader[i]);
	} else {
		for (i = 0; i < ncpus; i++)
			if (reader[i]) pthread_join(reader[i], NULL);
	}
	
	for (i = 0; i < ncpus; i++)
		close_relayfs_files(i);
}

/**
 *	open_relayfs_files - open and mmap buffer and open output file.
 *	Returns -1 on unexpected failure, 0 if file not found, 1 on success.
 */
static int open_relayfs_files(int cpu, const char *relay_filebase, const char *proc_filebase)
{
	size_t total_bufsize;
	char tmp[PATH_MAX];

	memset(&status[cpu], 0, sizeof(struct buf_status));
	status[cpu].info.cpu = cpu;

	if (sprintf_chk(tmp, "%s%d", relay_filebase, cpu))
		return -1;
	dbug(2, "Opening %s.\n", tmp); 
	relay_fd[cpu] = open(tmp, O_RDONLY | O_NONBLOCK);
	if (relay_fd[cpu] < 0) {
		relay_fd[cpu] = 0;
		return 0;
	}

	if (sprintf_chk(tmp, "%s%d", proc_filebase, cpu))
		goto err1;
	dbug(2, "Opening %s.\n", tmp); 
	proc_fd[cpu] = open(tmp, O_RDWR | O_NONBLOCK);
	if (proc_fd[cpu] < 0) {
		perr("Couldn't open proc file %s", tmp);
		goto err1;
	}

	if (outfile_name) {
		/* special case: for testing we sometimes want to
		 * write to /dev/null */
		if (strcmp(outfile_name, "/dev/null") == 0) {
			strcpy(tmp, "/dev/null");
		} else {
			if (sprintf_chk(tmp, "%s_%d", outfile_name, cpu))
				goto err1;
		}
	} else {
		if (sprintf_chk(tmp, "stpd_cpu%d", cpu))
			goto err1;
	}

	if((percpu_tmpfile[cpu] = fopen(tmp, "w+")) == NULL) {
		perr("Couldn't open output file %s", tmp);
		goto err2;
	}

	total_bufsize = subbuf_size * n_subbufs;
	relay_buffer[cpu] = mmap(NULL, total_bufsize, PROT_READ,
				 MAP_PRIVATE | MAP_POPULATE, relay_fd[cpu],
				 0);
	if(relay_buffer[cpu] == MAP_FAILED)
	{
		_perr("Couldn't mmap relay file, total_bufsize (%d)"	\
		     "= subbuf_size (%d) * n_subbufs(%d)",
		     (int)total_bufsize, (int)subbuf_size, (int)n_subbufs);
		goto err3;
	}
	
	return 1;
	
err3:
	fclose(percpu_tmpfile[cpu]);
err2:
	close (proc_fd[cpu]);
err1:
	close (relay_fd[cpu]);
	relay_fd[cpu] = 0;
	return -1;

}

/**
 *	process_subbufs - write ready subbufs to disk
 */
static int process_subbufs(struct _stp_buf_info *info)
{
	unsigned subbufs_ready, start_subbuf, end_subbuf, subbuf_idx, i;
	int len, cpu = info->cpu;
	char *subbuf_ptr;
	int subbufs_consumed = 0;
	unsigned padding;

	subbufs_ready = info->produced - info->consumed;
	start_subbuf = info->consumed % n_subbufs;
	end_subbuf = start_subbuf + subbufs_ready;

	for (i = start_subbuf; i < end_subbuf; i++) {
		subbuf_idx = i % n_subbufs;
		subbuf_ptr = relay_buffer[cpu] + subbuf_idx * subbuf_size;
		padding = *((unsigned *)subbuf_ptr);
		subbuf_ptr += sizeof(padding);
		len = (subbuf_size - sizeof(padding)) - padding;
		if (len) {
			if (fwrite_unlocked (subbuf_ptr, len, 1, percpu_tmpfile[cpu]) != 1) {
				_perr("Couldn't write to output file for cpu %d, exiting:", cpu);
				exit(1);
			}
		}
		subbufs_consumed++;
	}

	return subbufs_consumed;
}

/**
 *	reader_thread - per-cpu channel buffer reader
 */
static void *reader_thread(void *data)
{
	int rc;
	int cpu = (long)data;
	struct pollfd pollfd;
	struct _stp_consumed_info consumed_info;
	unsigned subbufs_consumed;
	cpu_set_t cpu_mask;

	CPU_ZERO(&cpu_mask);
	CPU_SET(cpu, &cpu_mask);
	if( sched_setaffinity( 0, sizeof(cpu_mask), &cpu_mask ) < 0 )
		_perr("sched_setaffinity");

	pollfd.fd = relay_fd[cpu];
	pollfd.events = POLLIN;

	do {
		rc = poll(&pollfd, 1, -1);
		if (rc < 0) {
			if (errno != EINTR) {
				_perr("poll error");
				exit(1);
			}
			err("WARNING: poll warning: %s\n", strerror(errno));
			rc = 0;
		}

		rc = read(proc_fd[cpu], &status[cpu].info, sizeof(struct _stp_buf_info));
		subbufs_consumed = process_subbufs(&status[cpu].info);
		if (subbufs_consumed) {
			if (subbufs_consumed > status[cpu].max_backlog)
				status[cpu].max_backlog = subbufs_consumed;
			status[cpu].info.consumed += subbufs_consumed;
			consumed_info.cpu = cpu;
			consumed_info.consumed = subbufs_consumed;
			if (write (proc_fd[cpu], &consumed_info, sizeof(struct _stp_consumed_info)) < 0)
				perr("writing consumed info failed");
		}
		if (status[cpu].info.flushing)
			pthread_exit(NULL);
	} while (1);
}

/**
 *	init_relayfs - create files and threads for relayfs processing
 *
 *	Returns 0 if successful, negative otherwise
 */
int init_oldrelayfs(void)
{
	int i, j;
	struct statfs st;
	char relay_filebase[PATH_MAX], proc_filebase[PATH_MAX];

	dbug(2, "initializing relayfs.n_subbufs=%d subbuf_size=%d\n", n_subbufs, subbuf_size);

	if (n_subbufs)
		bulkmode = 1;
 
	if (!bulkmode) {
		if (outfile_name) {
			out_fd[0] = open (outfile_name, O_CREAT|O_TRUNC|O_WRONLY, 0666);
			if (out_fd[0] < 0) {
				perr("Couldn't open output file '%s'", outfile_name);
				return -1;
			}
		} else
			out_fd[0] = STDOUT_FILENO;
	  return 0;
	}

 	if (statfs("/sys/kernel/debug", &st) == 0
	    && (int) st.f_type == (int) DEBUGFS_MAGIC) {
		if (sprintf_chk(relay_filebase,
				"/sys/kernel/debug/systemtap/%s/trace",
				modname))
			return -1;
 		if (sprintf_chk(proc_filebase, 
				"/sys/kernel/debug/systemtap/%s/", modname))
			return -1;
	} else if (statfs("/mnt/relay", &st) == 0
		   && (int) st.f_type == (int) RELAYFS_MAGIC) {
		if (sprintf_chk(relay_filebase, "/mnt/relay/systemtap/%s/trace", modname))
			return -1;
		if (sprintf_chk(proc_filebase, "/proc/systemtap/%s/", modname))
			return -1;
 	} else {
		err("Cannot find relayfs or debugfs mount point.\n");
		return -1;
	}


	reader[0] = (pthread_t)0;
	relay_fd[0] = 0;
	out_fd[0] = 0;

	for (i = 0; i < NR_CPUS; i++) {
		int ret = open_relayfs_files(i, relay_filebase, proc_filebase);
		if (ret == 0)
			break;
		if (ret < 0) {
			err("ERROR: couldn't open relayfs files, cpu = %d\n", i);
			goto err;
		}
	}

	ncpus = i;
	dbug(2, "ncpus=%d\n", ncpus);

	if (ncpus == 0) {
		err("couldn't open relayfs files.\n");
		return -1;
	}

	for (i = 0; i < ncpus; i++) {
		/* create a thread for each per-cpu buffer */
		if (pthread_create(&reader[i], NULL, reader_thread, (void *)(long)i) < 0) {
			int saved_errno = errno;
			close_relayfs_files(i);
			err("ERROR: Couldn't create reader thread, cpu = %d: %s\n",
				i, strerror(saved_errno));
			goto err;
		}
	}
	return 0;
err:
	for (j = 0; j < i; j++)
		close_relayfs_files(j);

	for (j = 0; j < i; j++)
		if (reader[j]) pthread_cancel(reader[j]);
	
	return -1;
}

