/*
 * user space instruction tracing
 * Copyright (C) 2005, 2006, 2007, 2008, 2009 IBM Corp.
 * Copyright (C) 2009 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/rcupdate.h>
#include <linux/utrace.h>
#include "ptrace_compatibility.h"

/* PR10171: To avoid ia64 lockups, disable itrace on ia64. */
#if defined(__ia64__)
#error "Unsupported itrace architecture"
#endif

/* PR9974: Adapt to struct renaming. */
#ifdef UTRACE_API_VERSION
#define utrace_attached_engine utrace_engine
#endif

#include <asm/string.h>
#include "uprobes/uprobes.h"
#include "utrace_compatibility.h"

#ifndef put_task_struct
#define put_task_struct(t) BUG_ON(atomic_dec_and_test(&(t)->usage))
#endif

#ifdef CONFIG_PPC
struct bpt_info {
        unsigned long addr;
        unsigned int instr;
};

struct atomic_ss_info {
        int step_over_atomic;
        struct bpt_info end_bpt;
        struct bpt_info br_bpt;
};

static int handle_ppc_atomic_seq(struct task_struct *tsk, struct pt_regs *regs,
	struct atomic_ss_info *ss_info);
static void remove_atomic_ss_breakpoint (struct task_struct *tsk, 
	struct bpt_info *bpt);
#endif

struct itrace_info {
	pid_t tid;
	u32 step_flag;
	struct stap_itrace_probe *itrace_probe;
#ifdef CONFIG_PPC
	struct atomic_ss_info ppc_atomic_ss;
#endif
	struct task_struct *tsk;
	struct utrace_attached_engine *engine;
	struct list_head link;
};

static LIST_HEAD(usr_itrace_info);
static DEFINE_MUTEX(itrace_lock);
static struct itrace_info *create_itrace_info(
	struct task_struct *tsk, u32 step_flag,
	struct stap_itrace_probe *itrace_probe);
void static remove_itrace_info(struct itrace_info *ui);

/* Note: __access_process_vm moved to access_process_vm.h */


#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_quiesce(struct utrace_attached_engine *engine,
					struct task_struct *tsk)
#else
static u32 usr_itrace_report_quiesce(enum utrace_resume_action action,
				struct utrace_attached_engine *engine,
				struct task_struct *tsk,
				unsigned long event)
#endif
{
	int status;
	struct itrace_info *ui;

	ui = rcu_dereference(engine->data);

        /* Already detached/deallocated from another callback? */
        if (ui == NULL) return UTRACE_DETACH;

#ifdef DEBUG_ITRACE
        _stp_dbug (__FUNCTION__,__LINE__,"pid %d step %d\n", ui->tsk->pid, ui->step_flag);
#endif

        /* We've been asked to detach; shutdown must be under way.  */
        if (ui->step_flag == UTRACE_DETACH)
          {
            mutex_lock(&itrace_lock);
            list_del(&ui->link);
            put_task_struct(tsk);
            kfree(ui);
            engine->data = NULL;
            mutex_unlock(&itrace_lock);
            return UTRACE_DETACH;
          }


#ifdef UTRACE_ORIG_VERSION
	return (ui->step_flag | UTRACE_ACTION_NEWSTATE);
#else
	return (event == 0 ? ui->step_flag : UTRACE_RESUME);
#endif
}


#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_death(struct utrace_attached_engine *e,
                                   struct task_struct *tsk)
#else
static u32 usr_itrace_report_death(struct utrace_attached_engine *e,
                                   struct task_struct *tsk, bool group_dead, int signal)
#endif
{
  struct itrace_info *ui = rcu_dereference(e->data);

  /* Already detached/deallocated from another callback? */
  if (ui == NULL) return UTRACE_DETACH;

#ifdef DEBUG_ITRACE
        _stp_dbug (__FUNCTION__,__LINE__,"pid %d step %d\n", ui->tsk->pid, ui->step_flag);
#endif

  /* even if not (ui->step_flag == UTRACE_DETACH) */
  mutex_lock(&itrace_lock);
  list_del(&ui->link);
  put_task_struct(tsk);
  kfree(ui);
  e->data = NULL;
  mutex_unlock(&itrace_lock);

  return UTRACE_DETACH;
}


#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_exec(struct utrace_attached_engine *e,
                                  struct task_struct *tsk,
                                  const struct linux_binprm *bprm,
                                  struct pt_regs *regs)
#else
static u32 usr_itrace_report_exec(enum utrace_resume_action action,
                                  struct utrace_attached_engine *e,
                                  struct task_struct *tsk,
                                  const struct linux_binfmt *fmt,
                                  const struct linux_binprm *bprm,
                                  struct pt_regs *regs)
#endif
{
  struct itrace_info *ui = rcu_dereference(e->data);

  /* Already detached/deallocated from another callback? */
  if (ui == NULL) return UTRACE_DETACH;

#ifdef DEBUG_ITRACE
        _stp_dbug (__FUNCTION__,__LINE__,"pid %d step %d\n", ui->tsk->pid, ui->step_flag);
#endif

  /* even if not (ui->step_flag == UTRACE_DETACH) */
  mutex_lock(&itrace_lock);
  list_del(&ui->link);
  put_task_struct(ui->tsk);
  kfree(ui);
  e->data = NULL;
  mutex_unlock(&itrace_lock);

  return UTRACE_DETACH;
}



#ifdef UTRACE_ORIG_VERSION
static u32 usr_itrace_report_signal(
			     struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
                             u32 action, siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka)
#else
static u32 usr_itrace_report_signal(u32 action,
			     struct utrace_attached_engine *engine,
			     struct task_struct *tsk,
			     struct pt_regs *regs,
			     siginfo_t *info,
			     const struct k_sigaction *orig_ka,
			     struct k_sigaction *return_ka)
#endif
{
	struct itrace_info *ui;
	u32 return_flags;
	unsigned long data = 0;

#ifdef CONFIG_PPC
	data = mfspr(SPRN_SDAR);
#endif

	ui = rcu_dereference(engine->data);

        /* Already detached/deallocated from another callback? */
        if (ui == NULL) return UTRACE_DETACH;

#ifdef DEBUG_ITRACE
        _stp_dbug (__FUNCTION__,__LINE__,"pid %d step %d\n", ui->tsk->pid, ui->step_flag);
#endif

	if (info->si_signo != SIGTRAP) 
          return UTRACE_RESUME;

        /* shutdown in progress: get out of single-stepping state,
           await quiesce to really shut down */
        if (ui->step_flag == UTRACE_DETACH) 
          return UTRACE_RESUME | UTRACE_SIGNAL_IGN;

#if defined(UTRACE_ORIG_VERSION) && defined(CONFIG_PPC)
	/* Because of a ppc utrace bug, we need to stop the task here.
	   usr_itrace_report_quiesce() will continue stepping the task. */
	return_flags = UTRACE_SIGNAL_IGN | UTRACE_STOP | UTRACE_ACTION_NEWSTATE;
#else
	/* normal case: continue stepping */
	return_flags =  ui->step_flag | UTRACE_SIGNAL_IGN;
#endif
#ifdef CONFIG_PPC
	if (ui->ppc_atomic_ss.step_over_atomic) {
		remove_atomic_ss_breakpoint(tsk, &ui->ppc_atomic_ss.end_bpt);
		if (ui->ppc_atomic_ss.br_bpt.addr)
			remove_atomic_ss_breakpoint(tsk,
				&ui->ppc_atomic_ss.br_bpt);
		ui->ppc_atomic_ss.step_over_atomic = 0;
	}
	
	if (handle_ppc_atomic_seq(tsk, regs, &ui->ppc_atomic_ss))
		return_flags = UTRACE_RESUME | UTRACE_SIGNAL_IGN;
#endif

	enter_itrace_probe(ui->itrace_probe, regs, (void *)&data);

	return return_flags;
}


static const struct utrace_engine_ops utrace_ops =
{
	.report_quiesce = usr_itrace_report_quiesce,
	.report_signal = usr_itrace_report_signal,
	.report_death = usr_itrace_report_death,
	.report_exec = usr_itrace_report_exec,
};


static int usr_itrace_init(int single_step, struct task_struct *tsk, struct stap_itrace_probe *p)
{
  struct itrace_info *ui;
  int rc = 0;
  struct utrace_attached_engine *e = NULL;

  BUG_ON(!tsk);

  rcu_read_lock();
  mutex_lock(&itrace_lock);
  get_task_struct(tsk);

  /* initialize ui */
  ui = kzalloc(sizeof(struct itrace_info), GFP_USER);
  ui->tsk = tsk;
  ui->tid = tsk->pid;
  ui->step_flag = single_step ? UTRACE_SINGLESTEP : UTRACE_BLOCKSTEP;
  ui->itrace_probe = p;
#ifdef CONFIG_PPC
  ui->ppc_atomic_ss.step_over_atomic = 0;
#endif
  INIT_LIST_HEAD(&ui->link);

  /* attach a single stepping engine */
  e = utrace_attach_task(ui->tsk, UTRACE_ATTACH_CREATE, &utrace_ops, ui);
  if (IS_ERR(e)) {
    rc = -PTR_ERR(e);
    kfree (ui);
    put_task_struct(tsk);
    goto out;
  }
  ui->engine = e;

  rc = utrace_set_events(tsk, ui->engine, 
                         UTRACE_EVENT(QUIESCE) |
                         UTRACE_EVENT_SIGNAL_ALL |
                         UTRACE_EVENT(EXEC) |
                         UTRACE_EVENT(DEATH));
  if (rc < 0) {
    int rc2 = utrace_control(tsk, ui->engine, UTRACE_DETACH);
    if (rc2 == -EINPROGRESS) rc2 = utrace_barrier (tsk, ui->engine);
    put_task_struct(tsk);
    kfree(ui);
    e->data = NULL;
    goto out;
  }

  rc = utrace_control(tsk, ui->engine, UTRACE_STOP); /* XXX: or _INTERRUPT? */
  if (rc < 0) {
    if (rc != -EINPROGRESS) /* other than expected "will stop real soon now" */
      printk(KERN_ERR "utrace_control(STOP) returns %d\n", rc);
    rc = 0;
    /* FALLTHROUGH; expect quiesce callback soon */
  }

  /* Add this to the list, to ensure shutdown paths remember to clean it up. */
  list_add(&ui->link, &usr_itrace_info);

 out:
  mutex_unlock(&itrace_lock);
  rcu_read_unlock();

#ifdef DEBUG_ITRACE
  _stp_dbug (__FUNCTION__,__LINE__,"create_itrace_init completed %d rc %d\n", tsk->pid, rc);
#endif

  return rc;
}


static void usr_itrace_dtor_all (void)
{
  struct itrace_info *tmp;
  struct itrace_info *ui;
  int rc = 0;
  unsigned loops = 0;

  
  while(1)
    {
      mutex_lock(&itrace_lock);
      if (list_empty (&usr_itrace_info))
        {
          mutex_unlock(&itrace_lock);
          break; // all done!
        }

      loops ++;

      list_for_each_entry_safe(ui, tmp, &usr_itrace_info, link) 
        {
          struct task_struct *tsk = ui->tsk;
#ifdef DEBUG_ITRACE
          _stp_dbug (__FUNCTION__,__LINE__,"detach/interrupt: pid %d\n", ui->tsk->pid);
#endif
          ui->step_flag = UTRACE_DETACH;

#ifdef UTRACE_ORIG_VERSION
          // no UTRACE_INTERRUPT
          send_sig (SIGTRAP, tsk, 1);
#else
          // XXX: ui->step_flag should be atomic; guaranteed set by the time 
          rc = utrace_control(tsk, ui->engine, UTRACE_INTERRUPT);
          if (rc == -EINPROGRESS) /* signal etc. in progress */
            rc = utrace_barrier(tsk, ui->engine);
          if (rc)
            _stp_error("utrace interrupt returned error %d on pid %d", rc, tsk->pid);
#endif
        }
      mutex_unlock(&itrace_lock);

      synchronize_sched();
      // sleep a random small amount, to make it more likely that
      // the utraced task gets around to being interrupted -> quiesced -> detached
      msleep (10);
      WARN_ON ((loops % 100) == 0); // a second has gone by
    }

#ifdef DEBUG_ITRACE
  _stp_dbug (__FUNCTION__,__LINE__,"completed, #loops: %d\n", loops);
#endif
}


#ifdef CONFIG_PPC
#define PPC_INSTR_SIZE 4
#define TEXT_SEGMENT_BASE 1

/* Instruction masks used during single-stepping of atomic sequences.  */
#define LWARX_MASK 0xfc0007fe
#define LWARX_INSTR 0x7c000028
#define LDARX_INSTR 0x7c0000A8
#define STWCX_MASK 0xfc0007ff
#define STWCX_INSTR 0x7c00012d
#define STDCX_INSTR 0x7c0001ad
#define BC_MASK 0xfc000000
#define BC_INSTR 0x40000000
#define ATOMIC_SEQ_LENGTH 16
#define BPT_TRAP 0x7fe00008
#define INSTR_SZ sizeof(int)

static int get_instr(unsigned long addr, char *msg)
{
	unsigned int instr;

	if (copy_from_user(&instr, (const void __user *) addr,
			sizeof(instr))) {
		printk(KERN_ERR "get_instr failed: %s\n", msg);
		WARN_ON(1);
	}
	return instr;

}

static void insert_atomic_ss_breakpoint (struct task_struct *tsk,
	struct bpt_info *bpt)
{
	unsigned int bp_instr = BPT_TRAP;
	unsigned int cur_instr;

	cur_instr = get_instr(bpt->addr, "insert_atomic_ss_breakpoint");
	if (cur_instr != BPT_TRAP) {
		bpt->instr = cur_instr;
		WARN_ON(__access_process_vm(tsk, bpt->addr, &bp_instr, INSTR_SZ, 1) !=
			INSTR_SZ);
	}
}

static void remove_atomic_ss_breakpoint (struct task_struct *tsk,
	struct bpt_info *bpt)
{
	WARN_ON(__access_process_vm(tsk, bpt->addr, &bpt->instr, INSTR_SZ, 1) !=
		INSTR_SZ);
}

/* locate the branch destination.  Return -1 if not a branch.  */
static unsigned long
branch_dest (int opcode, int instr, struct pt_regs *regs, unsigned long pc)
{
	unsigned long dest;
	int immediate;
	int absolute;
	int ext_op;

	absolute = (int) ((instr >> 1) & 1);

	switch (opcode) {
	case 18:
		immediate = ((instr & ~3) << 6) >> 6;	/* br unconditional */
		if (absolute)
			dest = immediate;
		else
			dest = pc + immediate;
		break;

	case 16:
		immediate = ((instr & ~3) << 16) >> 16;	/* br conditional */
		if (absolute)
			dest = immediate;
		else
			dest = pc + immediate;
		break;

	case 19:
		ext_op = (instr >> 1) & 0x3ff;

		if (ext_op == 16) {
			/* br conditional register */
			dest = regs->link & ~3;
			/* FIX: we might be in a signal handler */
			WARN_ON(dest > 0);
		} else if (ext_op == 528) {
			/* br cond to ctr reg */
			dest = regs->ctr & ~3;

			/* for system call dest < TEXT_SEGMENT_BASE */
			if (dest < TEXT_SEGMENT_BASE)
				dest = regs->link & ~3;
		} else
			return -1;
		break;

	default:
		return -1;
	}
	return dest;
}

/* Checks for an atomic sequence of instructions beginning with a LWARX/LDARX
   instruction and ending with a STWCX/STDCX instruction.  If such a sequence
   is found, attempt to step through it.  A breakpoint is placed at the end of 
   the sequence.  */

static int handle_ppc_atomic_seq(struct task_struct *tsk, struct pt_regs *regs,
	struct atomic_ss_info *ss_info)
{
	unsigned long ip = regs->nip;
	unsigned long start_addr;
	unsigned int instr;
	int got_stx = 0;
	int i;
	int ret;

	unsigned long br_dest; /* bpt at branch instr's destination */
	int bc_instr_count = 0; /* conditional branch instr count  */

	instr = get_instr(regs->nip, "handle_ppc_atomic_seq:1");
	/* Beginning of atomic sequence starts with lwarx/ldarx instr */
	if ((instr & LWARX_MASK) != LWARX_INSTR
		&& (instr & LWARX_MASK) != LDARX_INSTR)
		return 0;

	start_addr = regs->nip;
	for (i = 0; i < ATOMIC_SEQ_LENGTH; ++i) {
		ip += INSTR_SZ;
		instr = get_instr(ip, "handle_ppc_atomic_seq:2");

		/* look for at most one conditional branch in the sequence
		 * and put a bpt at it's destination address
		 */
		if ((instr & BC_MASK) == BC_INSTR) {
			if (bc_instr_count >= 1)
				return 0; /* only handle a single branch */

			br_dest = branch_dest (BC_INSTR >> 26, instr, regs, ip);

			if (br_dest != -1 &&
				br_dest >= TEXT_SEGMENT_BASE) {
				ss_info->br_bpt.addr = br_dest;
				bc_instr_count++;
			}
		}

		if ((instr & STWCX_MASK) == STWCX_INSTR
			|| (instr & STWCX_MASK) == STDCX_INSTR) {
			got_stx = 1;
			break;
		}
	}

	/* Atomic sequence ends with a stwcx/stdcx instr */
	if (!got_stx)
		return 0;

	ip += INSTR_SZ;
	instr = get_instr(ip, "handle_ppc_atomic_seq:3");
	if ((instr & BC_MASK) == BC_INSTR) {
		ip += INSTR_SZ;
		instr = get_instr(ip, "handle_ppc_atomic_seq:4");
	}

	/* Insert a breakpoint right after the end of the atomic sequence.  */
	ss_info->end_bpt.addr = ip;

	/* Check for duplicate bpts */
	if (bc_instr_count && (ss_info->br_bpt.addr >= start_addr &&
		ss_info->br_bpt.addr <= ss_info->end_bpt.addr))
		ss_info->br_bpt.addr = 0;

	insert_atomic_ss_breakpoint (tsk, &ss_info->end_bpt);
	if (ss_info->br_bpt.addr)
		insert_atomic_ss_breakpoint (tsk, &ss_info->br_bpt);

	ss_info->step_over_atomic = 1;
	return 1;
}
#endif
