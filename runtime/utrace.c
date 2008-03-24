#include <linux/list.h>

static LIST_HEAD(_stp_task_finder_list);

typedef struct _stp_utrace_task_finder_target_t {
	struct list_head list;		/* _stp_task_finder_list linkage */
    	const char *pathname;
	size_t pathlen;
	struct list_head callback_list;
} _stp_utrace_task_finder_target;

typedef void (*stap_utrace_callback)(const char *pathname, size_t pathlen,
				     struct task_struct *tsk, int entry_p,
				     void *data);

typedef struct _stp_utrace_task_finder_callback_t {
	struct list_head list;		/* callback_list linkage */
	stap_utrace_callback callback;
	void *data;    
} _stp_utrace_task_finder_callback;


static int
stap_notify_process(const char *pathname, size_t pathlen,
		    stap_utrace_callback callback, void *data)
{
	// Since this _stp_task_finder_list is (currently) only
        // written to in one big setup operation before the task
        // finder process is started, we don't need to lock it.
	struct list_head *node;
	_stp_utrace_task_finder_target *tgt;
	_stp_utrace_task_finder_callback *cb;
	int found_node = 0;

	// Search the list for an existing entry for pathname.
	list_for_each(node, &_stp_task_finder_list) {
		tgt = list_entry(node, _stp_utrace_task_finder_target, list);
		if (tgt != NULL && tgt->pathlen == pathlen
		    && strcmp(tgt->pathname, pathname) == 0) {
			found_node = 1;
			break;
		}
	}

	// If we didn't find a matching existing entry, allocate a new
	// _stp_utrace_task_finder_target and add it to the list.
	if (! found_node) {
		tgt = (_stp_utrace_task_finder_target *)
			_stp_kzalloc(sizeof(_stp_utrace_task_finder_target));
		if (tgt == NULL)
			return(-ENOMEM);
		tgt->pathname = pathname;
		tgt->pathlen = pathlen;
		INIT_LIST_HEAD(&tgt->callback_list);
		list_add(&tgt->list, &_stp_task_finder_list);
	}

	// Allocate a new _stp_utrace_task_finder_callback and add it
	// to the _stp_utrace_task_finder_target list of callbacks.
	cb = (_stp_utrace_task_finder_callback *)
		_stp_kzalloc(sizeof(_stp_utrace_task_finder_callback));
	if (cb == NULL)
		return(-ENOMEM);
	cb->callback = callback;
	cb->data = data;
	list_add(&cb->list, &tgt->callback_list);
	return 0;
}

static void
stap_notify_cleanup(void)
{
	struct list_head *tgt_node, *tgt_next;
	struct list_head *cb_node, *cb_next;
	_stp_utrace_task_finder_target *tgt;
	_stp_utrace_task_finder_callback *cb;

	// Walk the main list, deleting as we go.
	list_for_each_safe(tgt_node, tgt_next, &_stp_task_finder_list) {
		tgt = list_entry(tgt_node, _stp_utrace_task_finder_target,
				 list);
		if (tgt == NULL)
			continue;

		_stp_dbug(__FUNCTION__, __LINE__, "cleaning up '%s' entry",
			  tgt->pathname);
		list_for_each_safe(cb_node, cb_next, &tgt->callback_list) {
			cb = list_entry(cb_node,
					_stp_utrace_task_finder_callback,
					list);
			if (cb == NULL)
				continue;

			if (cb->callback != NULL)
				cb->callback(tgt->pathname, tgt->pathlen, NULL,
					     0, cb->data);

			list_del(&cb->list);
			_stp_kfree(cb);
		}

		list_del(&tgt->list);
		_stp_kfree(tgt);
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
