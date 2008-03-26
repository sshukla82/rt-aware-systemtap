#include <linux/list.h>

static LIST_HEAD(_stp_task_finder_list);

struct stap_task_finder_target;

typedef void (*stap_utrace_callback)(struct task_struct *tsk, int register_p,
				     struct stap_task_finder_target *tgt);

struct stap_task_finder_target {
	struct list_head list;		/* _stp_task_finder_list linkage */
	struct list_head callback_list_head;
	struct list_head callback_list;
    	const char *pathname;
	size_t pathlen;
	stap_utrace_callback callback;
};

static int
stap_register_task_finder_target(struct stap_task_finder_target *new_tgt)
{
	// Since this _stp_task_finder_list is (currently) only
        // written to in one big setup operation before the task
        // finder process is started, we don't need to lock it.
	struct list_head *node;
	struct stap_task_finder_target *tgt = NULL;
	int found_node = 0;

	// Search the list for an existing entry for pathname.
	list_for_each(node, &_stp_task_finder_list) {
		tgt = list_entry(node, struct stap_task_finder_target, list);
		if (tgt != NULL && tgt->pathlen == new_tgt->pathlen
		    && strcmp(tgt->pathname, new_tgt->pathname) == 0) {
			found_node = 1;
			break;
		}
	}

	// If we didn't find a matching existing entry, add the new
	// target to the task list.
	if (! found_node) {
		INIT_LIST_HEAD(&new_tgt->callback_list_head);
		list_add(&new_tgt->list, &_stp_task_finder_list);
		tgt = new_tgt;
	}

	// Add this target to the callback list for this task.
	list_add_tail(&new_tgt->callback_list, &tgt->callback_list_head);
	return 0;
}

static void
stap_notify_cleanup(void)
{
	struct list_head *tgt_node, *tgt_next;
	struct list_head *cb_node, *cb_next;
	struct stap_task_finder_target *tgt;

	// Walk the main list, cleaning up as we go.
	list_for_each_safe(tgt_node, tgt_next, &_stp_task_finder_list) {
		tgt = list_entry(tgt_node, struct stap_task_finder_target,
				 list);
		if (tgt == NULL)
			continue;

		_stp_dbug(__FUNCTION__, __LINE__, "cleaning up '%s' entry",
			  tgt->pathname);
		list_for_each_safe(cb_node, cb_next,
				   &tgt->callback_list_head) {
			struct stap_task_finder_target *cb_tgt;
			cb_tgt = list_entry(cb_node,
					    struct stap_task_finder_target,
					    callback_list);
			if (cb_tgt == NULL)
				continue;

			if (cb_tgt->callback != NULL)
				cb_tgt->callback(NULL, 0, cb_tgt);

			list_del(&cb_tgt->callback_list);
		}
		list_del(&tgt->list);
	}
}

void stap_utrace_detach_ops (struct utrace_engine_ops *ops)
{
	struct task_struct *tsk;
	struct utrace_attached_engine *engine;
	long error = 0;
	pid_t pid = 0;

	_stp_dbug(__FUNCTION__, __LINE__, "enter");
	rcu_read_lock();
	for_each_process(tsk) {
		struct mm_struct *mm;
		mm = get_task_mm(tsk);
		if (mm) {
			mmput(mm);
			engine = utrace_attach(tsk, UTRACE_ATTACH_MATCH_OPS,
					       ops, 0);
			if (IS_ERR(engine)) {
				error = -PTR_ERR(engine);
				if (error != ENOENT) {
					pid = tsk->pid;
					break;
				}
				error = 0;
			}
			else if (engine != NULL) {
				utrace_detach(tsk, engine);
			}
		}
	}
	rcu_read_unlock();
	_stp_dbug(__FUNCTION__, __LINE__, "exit");

	if (error != 0) {
		_stp_error("utrace_attach returned error %d on pid %d",
			   error, pid);
	}
}

static char *
stap_utrace_get_mm_path(struct mm_struct *mm, char *buf, int buflen)
{
	struct vm_area_struct *vma;
	char *rc = NULL;

	down_read(&mm->mmap_sem);
	vma = mm->mmap;
	while (vma) {
		if ((vma->vm_flags & VM_EXECUTABLE) && vma->vm_file)
			break;
		vma = vma->vm_next;
	}
	if (vma) {
		struct vfsmount *mnt = mntget(vma->vm_file->f_path.mnt);
		struct dentry *dentry = dget(vma->vm_file->f_path.dentry);
		rc = d_path(dentry, mnt, buf, buflen);
		dput(dentry);
		mntput(mnt);
	}
	else {
		*buf = '\0';
		rc = ERR_PTR(ENOENT);
	}
	up_read(&mm->mmap_sem);
	return rc;
}

#define STAP_UTRACE_TASK_FINDER_EVENTS (UTRACE_EVENT(CLONE) \
					| UTRACE_EVENT(EXEC))

static u32
stap_utrace_task_finder_clone(struct utrace_attached_engine *engine,
			      struct task_struct *parent,
			      unsigned long clone_flags,
			      struct task_struct *child)
{
	struct utrace_attached_engine *child_engine;
	struct mm_struct *mm;

	// On clone, attach to the child.  Ignore threads with no mm
	// (which are kernel threads).
	_stp_dbug(__FUNCTION__, __LINE__, "current pid is %d", child->pid);
	mm = get_task_mm(child);
	if (mm) {
		mmput(mm);
		child_engine = utrace_attach(child, UTRACE_ATTACH_CREATE,
					     engine->ops, 0);
		if (IS_ERR(child_engine))
			_stp_error("attach to clone child %d (%lx) from 0x%p failed: %ld", (int)child->pid, clone_flags, engine, PTR_ERR(child_engine));
		else {
			utrace_set_flags(child, child_engine,
					 STAP_UTRACE_TASK_FINDER_EVENTS);
			_stp_dbug(__FUNCTION__, __LINE__,
				  "attach to clone child %d (%lx) from 0x%p",
				  (int)child->pid, clone_flags, engine);
		}
	}
	return UTRACE_ACTION_RESUME;
}

static u32
stap_utrace_task_finder_exec(struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     const struct linux_binprm *bprm,
			     struct pt_regs *regs)
{
	// On exec, check bprm
	_stp_dbug(__FUNCTION__, __LINE__, "pid %d is exec'ing '%s' ('%s')",
		  (int)tsk->pid,
		  (bprm->filename == NULL) ? "(none)" : bprm->filename,
		  (bprm->interp == NULL) ? "(none)" : bprm->interp);
	if (bprm->filename != NULL) {
		size_t filelen = strlen(bprm->filename);
		struct list_head *tgt_node;
		struct stap_task_finder_target *tgt;
		int found_node = 0;
		list_for_each(tgt_node, &_stp_task_finder_list) {
			tgt = list_entry(tgt_node,
					 struct stap_task_finder_target, list);
			if (tgt->pathlen == filelen
			    && strcmp(tgt->pathname, bprm->filename) == 0) {
				_stp_dbug(__FUNCTION__, __LINE__,
					  "found a match!");
				found_node = 1;
				break;
			}
		}
		if (found_node) {
			struct list_head *cb_node;
			list_for_each(cb_node, &tgt->callback_list_head) {
				struct stap_task_finder_target *cb_tgt;
				cb_tgt = list_entry(cb_node,
						    struct stap_task_finder_target,
						    callback_list);
				if (cb_tgt == NULL || cb_tgt->callback == NULL)
					continue;
				cb_tgt->callback(tsk, 1, cb_tgt);
			}
		}
	}
	return UTRACE_ACTION_RESUME;
}

struct utrace_engine_ops stap_utrace_task_finder_ops = {
	.report_clone = stap_utrace_task_finder_clone,
	.report_exec = stap_utrace_task_finder_exec,
};

int
stap_utrace_start_task_finder(void)
{
	int rc = 0;
	struct task_struct *tsk;
	char *error_fmt;
	char *mmpath_buf;

	mmpath_buf = _stp_kmalloc(PATH_MAX);
	if (mmpath_buf == NULL) {
		_stp_error("Unable to allocate space for path");
		return ENOMEM;
	}

	rcu_read_lock();
	for_each_process(tsk) {
		struct utrace_attached_engine *engine;
		struct mm_struct *mm;
		char *mmpath;

		mm = get_task_mm(tsk);
		if (! mm) {
		    /* If the thread doesn't have a mm_struct, it is
		     * a kernel thread which we need to skip. */
		    continue;
		}

		/* Attach to the thread */
		engine = utrace_attach(tsk, UTRACE_ATTACH_CREATE,
				       &stap_utrace_task_finder_ops, 0);
		if (IS_ERR(engine)) {
			int error = -PTR_ERR(engine);
			if (error != ENOENT) {
				mmput(mm);
				error_fmt = "utrace_attach returned error %d on pid %d";
				rc = error;
				break;
			}
		}
		else if (unlikely(engine == NULL)) {
			mmput(mm);
			error_fmt = "utrace_attach returned NULL (%d) on pid %d";
			rc = EFAULT;
			break;
		}
		utrace_set_flags(tsk, engine, STAP_UTRACE_TASK_FINDER_EVENTS);
		_stp_dbug(__FUNCTION__, __LINE__, "attach to pid %d",
			  (int)tsk->pid);

		/* Check the thread's exe's path against our list. */
		mmpath = stap_utrace_get_mm_path(mm, mmpath_buf, PATH_MAX);
		mmput(mm);		/* We're done with mm */
		if (IS_ERR(mmpath)) {
			rc = -PTR_ERR(mmpath);
			error_fmt = "Unable to get path (error %d) for pid %d";
			break;
		}
		else {
			size_t mmpathlen = strlen(mmpath);
			struct list_head *tgt_node;
			struct stap_task_finder_target *tgt;
			int found_node = 0;

			_stp_dbug(__FUNCTION__, __LINE__,
				  "pid %d path: \"%s\"", (int)tsk->pid, mmpath);
			list_for_each(tgt_node, &_stp_task_finder_list) {
				tgt = list_entry(tgt_node,
						 struct stap_task_finder_target,
						 list);
				if (tgt != NULL && tgt->pathlen == mmpathlen
				    && strcmp(tgt->pathname, mmpath) == 0) {
					_stp_dbug(__FUNCTION__, __LINE__,
						  "found a match!");
					found_node = 1;
					break;
				}
			}
			if (found_node) {
				struct list_head *cb_node;
				list_for_each(cb_node, &tgt->callback_list_head) {
					struct stap_task_finder_target *cb_tgt;
					cb_tgt = list_entry(cb_node,
							    struct stap_task_finder_target,
							    callback_list);
					if (cb_tgt == NULL
					    || cb_tgt->callback == NULL)
						continue;
					
					cb_tgt->callback(tsk, 1, cb_tgt);
				}
			}
		}
		if (rc != 0) {
			break;
		}
	}
	rcu_read_unlock();
	_stp_kfree(mmpath_buf);

	if (rc != 0) {
		_stp_error(error_fmt, rc, (int)tsk->pid);
	}
	return rc;
}
