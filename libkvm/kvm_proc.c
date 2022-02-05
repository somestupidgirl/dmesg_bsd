/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*-
 * Copyright (c) 1989, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software developed by the Computer Systems
 * Engineering group at Lawrence Berkeley Laboratory under DARPA contract
 * BG 91-66 and contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#if defined(LIBC_SCCS) && !defined(lint)
static char sccsid[] = "@(#)kvm_proc.c	8.4 (Berkeley) 8/20/94";
#endif /* LIBC_SCCS and not lint */

/*
 * Proc traversal interface for kvm.  ps and w are (probably) the exclusive
 * users of this code, so we've factored it out into a separate module.
 * Thus, we keep this grunge out of the other kvm applications (i.e.,
 * most other applications are interested only in open/close/read/nlist).
 */

#include <db.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <paths.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <machine/vmparam.h>
#include <mach/machine/vm_param.h>
#include <mach/mach_types.h>

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/tty.h>
#include <sys/vm.h>
#include <sys/user.h>

#include "kvm_private.h"

#include <stdio.h>

#define	KERN_PROC_ARGS 7
#define	KERN_PROC_ENV  35

static char *
kvm_readswap(kvm_t *kd, const struct proc *p, u_long va, u_long *cnt)
{
    fprintf(stderr, "kvm_readswap: not supported\n");
    return NULL;
}

#define KREAD(kd, addr, obj) \
	(kvm_read(kd, addr, (char *)(obj), sizeof(*obj)) != sizeof(*obj))

/*
 * Read proc's from memory file into buffer bp, which has space to hold
 * at most maxcnt procs.
 */
static int
kvm_proclist(kvm_t *kd, int what, arg, struct proc *p, struct kinfo_proc *bp, int maxcnt)
{
	fprintf(stderr, "kvm_proclist: not supported\n");
	return (-1);
#if 0
	int cnt = 0;
	struct kinfo_proc kinfo_proc, *kp;
	struct pgrp pgrp;
	struct session sess;
	struct cdev t_cdev;
	struct tty tty;
	struct vmspace vmspace;
	struct sigacts sigacts;
#if 0
	struct pstats pstats;
#endif
	struct ucred ucred;
	struct prison pr;
	struct thread mtd;
	struct proc proc;
	struct proc pproc;
	struct sysentvec sysent;
	char svname[KI_EMULNAMELEN];
	struct thread *td = NULL;
	bool first_thread;

	kp = &kinfo_proc;
	kp->ki_structsize = sizeof(kinfo_proc);
	/*
	 * Loop on the processes, then threads within the process if requested.
	 */
	if (what == KERN_PROC_ALL)
		what |= KERN_PROC_INC_THREAD;
	for (; cnt < maxcnt && p != NULL; p = LIST_NEXT(&proc, p_list)) {
		memset(kp, 0, sizeof *kp);
		if (KREAD(kd, (u_long)p, &proc)) {
			_kvm_err(kd, kd->program, "can't read proc at %p", p);
			return (-1);
		}
		if (proc.p_state == PRS_NEW)
			continue;
		if (KREAD(kd, (u_long)proc.p_ucred, &ucred) == 0) {
			kp->ki_ruid = ucred.cr_ruid;
			kp->ki_svuid = ucred.cr_svuid;
			kp->ki_rgid = ucred.cr_rgid;
			kp->ki_svgid = ucred.cr_svgid;
			kp->ki_cr_flags = ucred.cr_flags;
			if (ucred.cr_ngroups > KI_NGROUPS) {
				kp->ki_ngroups = KI_NGROUPS;
				kp->ki_cr_flags |= KI_CRF_GRP_OVERFLOW;
			} else
				kp->ki_ngroups = ucred.cr_ngroups;
			kvm_read(kd, (u_long)ucred.cr_groups, kp->ki_groups,
			    kp->ki_ngroups * sizeof(gid_t));
			kp->ki_uid = ucred.cr_uid;
			if (ucred.cr_prison != NULL) {
				if (KREAD(kd, (u_long)ucred.cr_prison, &pr)) {
					_kvm_err(kd, kd->program,
					    "can't read prison at %p",
					    ucred.cr_prison);
					return (-1);
				}
				kp->ki_jid = pr.pr_id;
			}
		}

		switch(what & ~KERN_PROC_INC_THREAD) {

		case KERN_PROC_GID:
			if (kp->ki_groups[0] != (gid_t)arg)
				continue;
			break;

		case KERN_PROC_PID:
			if (proc.p_pid != (pid_t)arg)
				continue;
			break;

		case KERN_PROC_RGID:
			if (kp->ki_rgid != (gid_t)arg)
				continue;
			break;

		case KERN_PROC_UID:
			if (kp->ki_uid != (uid_t)arg)
				continue;
			break;

		case KERN_PROC_RUID:
			if (kp->ki_ruid != (uid_t)arg)
				continue;
			break;
		}
		/*
		 * We're going to add another proc to the set.  If this
		 * will overflow the buffer, assume the reason is because
		 * nprocs (or the proc list) is corrupt and declare an error.
		 */
		if (cnt >= maxcnt) {
			_kvm_err(kd, kd->program, "nprocs corrupt");
			return (-1);
		}
		/*
		 * gather kinfo_proc
		 */
		kp->ki_paddr = p;
		kp->ki_addr = 0;	/* XXX uarea */
		/* kp->ki_kstack = proc.p_thread.td_kstack; XXXKSE */
		kp->ki_args = proc.p_args;
		kp->ki_numthreads = proc.p_numthreads;
		kp->ki_tracep = NULL;	/* XXXKIB do not expose ktr_io_params */
		kp->ki_textvp = proc.p_textvp;
		kp->ki_fd = proc.p_fd;
		kp->ki_pd = proc.p_pd;
		kp->ki_vmspace = proc.p_vmspace;
		if (proc.p_sigacts != NULL) {
			if (KREAD(kd, (u_long)proc.p_sigacts, &sigacts)) {
				_kvm_err(kd, kd->program,
				    "can't read sigacts at %p", proc.p_sigacts);
				return (-1);
			}
			kp->ki_sigignore = sigacts.ps_sigignore;
			kp->ki_sigcatch = sigacts.ps_sigcatch;
		}
#if 0
		if ((proc.p_flag & P_INMEM) && proc.p_stats != NULL) {
			if (KREAD(kd, (u_long)proc.p_stats, &pstats)) {
				_kvm_err(kd, kd->program,
				    "can't read stats at %x", proc.p_stats);
				return (-1);
			}
			kp->ki_start = pstats.p_start;

			/*
			 * XXX: The times here are probably zero and need
			 * to be calculated from the raw data in p_rux and
			 * p_crux.
			 */
			kp->ki_rusage = pstats.p_ru;
			kp->ki_childstime = pstats.p_cru.ru_stime;
			kp->ki_childutime = pstats.p_cru.ru_utime;
			/* Some callers want child-times in a single value */
			timeradd(&kp->ki_childstime, &kp->ki_childutime,
			    &kp->ki_childtime);
		}
#endif
		if (proc.p_oppid)
			kp->ki_ppid = proc.p_oppid;
		else if (proc.p_pptr) {
			if (KREAD(kd, (u_long)proc.p_pptr, &pproc)) {
				_kvm_err(kd, kd->program,
				    "can't read pproc at %p", proc.p_pptr);
				return (-1);
			}
			kp->ki_ppid = pproc.p_pid;
		} else
			kp->ki_ppid = 0;
		if (proc.p_pgrp == NULL)
			goto nopgrp;
		if (KREAD(kd, (u_long)proc.p_pgrp, &pgrp)) {
			_kvm_err(kd, kd->program, "can't read pgrp at %p",
				 proc.p_pgrp);
			return (-1);
		}
		kp->ki_pgid = pgrp.pg_id;
		kp->ki_jobc = -1;	/* Or calculate?  Arguably not. */
		if (KREAD(kd, (u_long)pgrp.pg_session, &sess)) {
			_kvm_err(kd, kd->program, "can't read session at %p",
				pgrp.pg_session);
			return (-1);
		}
		kp->ki_sid = sess.s_sid;
		(void)memcpy(kp->ki_login, sess.s_login,
						sizeof(kp->ki_login));
		if ((proc.p_flag & P_CONTROLT) && sess.s_ttyp != NULL) {
			if (KREAD(kd, (u_long)sess.s_ttyp, &tty)) {
				_kvm_err(kd, kd->program,
					 "can't read tty at %p", sess.s_ttyp);
				return (-1);
			}
			if (tty.t_dev != NULL) {
				if (KREAD(kd, (u_long)tty.t_dev, &t_cdev)) {
					_kvm_err(kd, kd->program,
						 "can't read cdev at %p",
						tty.t_dev);
					return (-1);
				}
#if 0
				kp->ki_tdev = t_cdev.si_udev;
#else
				kp->ki_tdev = NODEV;
#endif
			}
			if (tty.t_pgrp != NULL) {
				if (KREAD(kd, (u_long)tty.t_pgrp, &pgrp)) {
					_kvm_err(kd, kd->program,
						 "can't read tpgrp at %p",
						tty.t_pgrp);
					return (-1);
				}
				kp->ki_tpgid = pgrp.pg_id;
			} else
				kp->ki_tpgid = -1;
			if (tty.t_session != NULL) {
				if (KREAD(kd, (u_long)tty.t_session, &sess)) {
					_kvm_err(kd, kd->program,
					    "can't read session at %p",
					    tty.t_session);
					return (-1);
				}
				kp->ki_tsid = sess.s_sid;
			}
		} else {
nopgrp:
			kp->ki_tdev = NODEV;
		}

		(void)kvm_read(kd, (u_long)proc.p_vmspace,
		    (char *)&vmspace, sizeof(vmspace));
		kp->ki_size = vmspace.vm_map.size;
		/*
		 * Approximate the kernel's method of calculating
		 * this field.
		 */
#define		pmap_resident_count(pm) ((pm)->pm_stats.resident_count)
		kp->ki_rssize = pmap_resident_count(&vmspace.vm_pmap);
		kp->ki_swrss = vmspace.vm_swrss;
		kp->ki_tsize = vmspace.vm_tsize;
		kp->ki_dsize = vmspace.vm_dsize;
		kp->ki_ssize = vmspace.vm_ssize;

		switch (what & ~KERN_PROC_INC_THREAD) {

		case KERN_PROC_PGRP:
			if (kp->ki_pgid != (pid_t)arg)
				continue;
			break;

		case KERN_PROC_SESSION:
			if (kp->ki_sid != (pid_t)arg)
				continue;
			break;

		case KERN_PROC_TTY:
			if ((proc.p_flag & P_CONTROLT) == 0 ||
			     kp->ki_tdev != (dev_t)arg)
				continue;
			break;
		}
		if (proc.p_comm[0] != 0)
			strlcpy(kp->ki_comm, proc.p_comm, MAXCOMLEN);
		(void)kvm_read(kd, (u_long)proc.p_sysent, (char *)&sysent,
		    sizeof(sysent));
		(void)kvm_read(kd, (u_long)sysent.sv_name, (char *)&svname,
		    sizeof(svname));
		if (svname[0] != 0)
			strlcpy(kp->ki_emul, svname, KI_EMULNAMELEN);
		kp->ki_runtime = cputick2usec(proc.p_rux.rux_runtime);
		kp->ki_pid = proc.p_pid;
		kp->ki_xstat = KW_EXITCODE(proc.p_xexit, proc.p_xsig);
		kp->ki_acflag = proc.p_acflag;
		kp->ki_lock = proc.p_lock;
		kp->ki_tdev_freebsd11 = kp->ki_tdev; /* truncate */

		/* Per-thread items; iterate as appropriate. */
		td = TAILQ_FIRST(&proc.p_threads);
		for (first_thread = true; cnt < maxcnt && td != NULL &&
		    (first_thread || (what & KERN_PROC_INC_THREAD));
		    first_thread = false) {
			if (proc.p_state != PRS_ZOMBIE) {
				if (KREAD(kd, (u_long)td, &mtd)) {
					_kvm_err(kd, kd->program,
					    "can't read thread at %p", td);
					return (-1);
				}
				if (what & KERN_PROC_INC_THREAD)
					td = TAILQ_NEXT(&mtd, td_plist);
			} else
				td = NULL;
			if ((proc.p_state != PRS_ZOMBIE) && mtd.td_wmesg)
				(void)kvm_read(kd, (u_long)mtd.td_wmesg,
				    kp->ki_wmesg, WMESGLEN);
			else
				memset(kp->ki_wmesg, 0, WMESGLEN);
			if (proc.p_pgrp == NULL) {
				kp->ki_kiflag = 0;
			} else {
				kp->ki_kiflag = sess.s_ttyvp ? KI_CTTY : 0;
				if (sess.s_leader == p)
					kp->ki_kiflag |= KI_SLEADER;
			}
			if ((proc.p_state != PRS_ZOMBIE) &&
			    (mtd.td_blocked != 0)) {
				kp->ki_kiflag |= KI_LOCKBLOCK;
				if (mtd.td_lockname)
					(void)kvm_read(kd,
					    (u_long)mtd.td_lockname,
					    kp->ki_lockname, LOCKNAMELEN);
				else
					memset(kp->ki_lockname, 0,
					    LOCKNAMELEN);
				kp->ki_lockname[LOCKNAMELEN] = 0;
			} else
				kp->ki_kiflag &= ~KI_LOCKBLOCK;
			kp->ki_siglist = proc.p_siglist;
			if (proc.p_state != PRS_ZOMBIE) {
				SIGSETOR(kp->ki_siglist, mtd.td_siglist);
				kp->ki_sigmask = mtd.td_sigmask;
				kp->ki_swtime = (ticks - proc.p_swtick) / hz;
				kp->ki_flag = proc.p_flag;
				kp->ki_sflag = 0;
				kp->ki_nice = proc.p_nice;
				kp->ki_traceflag = proc.p_traceflag;
				if (proc.p_state == PRS_NORMAL) {
					if (TD_ON_RUNQ(&mtd) ||
					    TD_CAN_RUN(&mtd) ||
					    TD_IS_RUNNING(&mtd)) {
						kp->ki_stat = SRUN;
					} else if (TD_GET_STATE(&mtd) ==
					    TDS_INHIBITED) {
						if (P_SHOULDSTOP(&proc)) {
							kp->ki_stat = SSTOP;
						} else if (
						    TD_IS_SLEEPING(&mtd)) {
							kp->ki_stat = SSLEEP;
						} else if (TD_ON_LOCK(&mtd)) {
							kp->ki_stat = SLOCK;
						} else {
							kp->ki_stat = SWAIT;
						}
					}
				} else {
					kp->ki_stat = SIDL;
				}
				/* Stuff from the thread */
				kp->ki_pri.pri_level = mtd.td_priority;
				kp->ki_pri.pri_native = mtd.td_base_pri;
				kp->ki_lastcpu = mtd.td_lastcpu;
				kp->ki_wchan = mtd.td_wchan;
				kp->ki_oncpu = mtd.td_oncpu;
				if (mtd.td_name[0] != '\0')
					strlcpy(kp->ki_tdname, mtd.td_name,
					    sizeof(kp->ki_tdname));
				else
					memset(kp->ki_tdname, 0,
					    sizeof(kp->ki_tdname));
				kp->ki_pctcpu = 0;
				kp->ki_rqindex = 0;

				/*
				 * Note: legacy fields; wraps at NO_CPU_OLD
				 * or the old max CPU value as appropriate
				 */
				if (mtd.td_lastcpu == NOCPU)
					kp->ki_lastcpu_old = NOCPU_OLD;
				else if (mtd.td_lastcpu > MAXCPU_OLD)
					kp->ki_lastcpu_old = MAXCPU_OLD;
				else
					kp->ki_lastcpu_old = mtd.td_lastcpu;

				if (mtd.td_oncpu == NOCPU)
					kp->ki_oncpu_old = NOCPU_OLD;
				else if (mtd.td_oncpu > MAXCPU_OLD)
					kp->ki_oncpu_old = MAXCPU_OLD;
				else
					kp->ki_oncpu_old = mtd.td_oncpu;
				kp->ki_tid = mtd.td_tid;
			} else {
				memset(&kp->ki_sigmask, 0,
				    sizeof(kp->ki_sigmask));
				kp->ki_stat = SZOMB;
				kp->ki_tid = 0;
			}

			bcopy(&kinfo_proc, bp, sizeof(kinfo_proc));
			++bp;
			++cnt;
		}
	}
	return (cnt);
#endif
}

/*
 * Build proc info array by reading in proc list from a crash dump.
 * Return number of procs read.  maxcnt is the max we will read.
 */
static int
kvm_deadprocs(kvm_t *kd, int what, arg, u_long a_allproc, u_long a_zombproc, int maxcnt)
{
	fprintf(stderr, "kvm_deadprocs: not supported\n");
	return (-1);
#if 0
	struct kinfo_proc *bp = kd->procbase;
	int acnt, zcnt = 0;
	struct proc *p;

	if (KREAD(kd, a_allproc, &p)) {
		_kvm_err(kd, kd->program, "cannot read allproc");
		return (-1);
	}
	acnt = kvm_proclist(kd, what, arg, p, bp, maxcnt);
	if (acnt < 0)
		return (acnt);

	if (a_zombproc != 0) {
		if (KREAD(kd, a_zombproc, &p)) {
			_kvm_err(kd, kd->program, "cannot read zombproc");
			return (-1);
		}
		zcnt = kvm_proclist(kd, what, arg, p, bp + acnt, maxcnt - acnt);
		if (zcnt < 0)
			zcnt = 0;
	}

	return (acnt + zcnt);
#endif
}

struct kinfo_proc *
kvm_getprocs(kvm_t *kd, int op, int arg, int *cnt)
{
	int mib[4], st, nprocs;
	size_t size;

	if (kd->procbase != 0) {
		free((void *)kd->procbase);
		/* 
		 * Clear this pointer in case this call fails.  Otherwise,
		 * kvm_close() will free it again.
		 */
		kd->procbase = 0;
	}
	if (ISALIVE(kd)) {
		size = 0;
		mib[0] = CTL_KERN;
		mib[1] = KERN_PROC;
		mib[2] = op;
		mib[3] = arg;
		st = sysctl(mib, 4, NULL, &size, NULL, 0);
		if (st == -1) {
			_kvm_syserr(kd, kd->program, "kvm_getprocs");
			return (0);
		}
		kd->procbase = (struct kinfo_proc *)_kvm_malloc(kd, size);
		if (kd->procbase == 0)
			return (0);
		st = sysctl(mib, 4, kd->procbase, &size, NULL, 0);
		if (st == -1) {
			_kvm_syserr(kd, kd->program, "kvm_getprocs");
			return (0);
		}
		if (size % sizeof(struct kinfo_proc) != 0) {
			_kvm_err(kd, kd->program,
				"proc size mismatch (%d total, %d chunks)",
				size, sizeof(struct kinfo_proc));
			return (0);
		}
		nprocs = size / sizeof(struct kinfo_proc);
	} else {
		struct nlist nl[4], *p;

		nl[0].n_name = "_nprocs";
		nl[1].n_name = "_allproc";
		nl[2].n_name = "_zombproc";
		nl[3].n_name = 0;

		if (kvm_nlist(kd, nl) != 0) {
			for (p = nl; p->n_type != 0; ++p)
				;
			_kvm_err(kd, kd->program,
				 "%s: no such symbol", p->n_name);
			return (0);
		}
		if (KREAD(kd, nl[0].n_value, &nprocs)) {
			_kvm_err(kd, kd->program, "can't read nprocs");
			return (0);
		}
		size = nprocs * sizeof(struct kinfo_proc);
		kd->procbase = (struct kinfo_proc *)_kvm_malloc(kd, size);
		if (kd->procbase == 0)
			return (0);

		nprocs = kvm_deadprocs(kd, op, arg, nl[1].n_value,
				      nl[2].n_value, nprocs);
#ifdef notdef
		size = nprocs * sizeof(struct kinfo_proc);
		(void)realloc(kd->procbase, size);
#endif
	}
	*cnt = nprocs;
	return (kd->procbase);
}

void
_kvm_freeprocs(kvm_t *kd)
{

	free(kd->procbase);
	kd->procbase = NULL;
}

void *
_kvm_realloc(kvm_t *kd, void *p, size_t n)
{
	void *np;

	np = reallocf(p, n);
	if (np == NULL)
		_kvm_err(kd, kd->program, "out of memory");
	return (np);
}

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

/*
 * Read in an argument vector from the user address space of process p.
 * addr if the user-space base address of narg null-terminated contiguous 
 * strings.  This is used to read in both the command arguments and
 * environment strings.  Read at most maxcnt characters of strings.
 */
static char **
kvm_argv(kvm_t *kd, const struct kinfo_proc *kp, int env, int nchr)
{
	int oid[4];
	int i;
	size_t bufsz;
	static int buflen;
	static char *buf, *p;
	static char **bufp;
	static int argc;
	char **nbufp;

	if (!ISALIVE(kd)) {
		_kvm_err(kd, kd->program,
		    "cannot read user space from dead kernel");
		return (NULL);
	}

	if (nchr == 0 || nchr > ARG_MAX)
		nchr = ARG_MAX;
	if (buflen == 0) {
		buf = malloc(nchr);
		if (buf == NULL) {
			_kvm_err(kd, kd->program, "cannot allocate memory");
			return (NULL);
		}
		argc = 32;
		bufp = malloc(sizeof(char *) * argc);
		if (bufp == NULL) {
			free(buf);
			buf = NULL;
			_kvm_err(kd, kd->program, "cannot allocate memory");
			return (NULL);
		}
		buflen = nchr;
	} else if (nchr > buflen) {
		p = realloc(buf, nchr);
		if (p != NULL) {
			buf = p;
			buflen = nchr;
		}
	}
	struct extern_proc *proc;
	oid[0] = CTL_KERN;
	oid[1] = KERN_PROC;
	oid[2] = env ? KERN_PROC_ENV : KERN_PROC_ARGS;
	oid[3] = proc->p_pid;
	bufsz = buflen;
	if (sysctl(oid, 4, buf, &bufsz, 0, 0) == -1) {
		/*
		 * If the supplied buf is too short to hold the requested
		 * value the sysctl returns with ENOMEM. The buf is filled
		 * with the truncated value and the returned bufsz is equal
		 * to the requested len.
		 */
		if (errno != ENOMEM || bufsz != (size_t)buflen)
			return (NULL);
		buf[bufsz - 1] = '\0';
		errno = 0;
	} else if (bufsz == 0)
		return (NULL);
	i = 0;
	p = buf;
	do {
		bufp[i++] = p;
		p += strlen(p) + 1;
		if (i >= argc) {
			argc += argc;
			nbufp = realloc(bufp, sizeof(char *) * argc);
			if (nbufp == NULL)
				return (NULL);
			bufp = nbufp;
		}
	} while (p < buf + bufsz);
	bufp[i++] = 0;
	return (bufp);
}

#if !defined(USRSTACK)
#warning USRSTACK not defined! using VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS
#include <mach/vm_types.h>
#define VM_MIN_KERNEL_ADDRESS ((vm_offset_t) 0xFFFFFF8000000000UL)
#define VM_MAX_KERNEL_ADDRESS ((vm_offset_t) 0xFFFFFFFFFFFFEFFFUL)
#define USRSTACK (VM_MAX_KERNEL_ADDRESS - VM_MIN_KERNEL_ADDRESS)
#endif

/*
 * Get the command args.  This code is now machine independent.
 */
char **
kvm_getargv(kvm_t *kd, const struct kinfo_proc *kp, int nchr)
{
	return (kvm_argv(kd, kp, 0, nchr));
}

char **
kvm_getenvv(kvm_t *kd, const struct kinfo_proc *kp, int nchr)
{
	return (kvm_argv(kd, kp, 1, nchr));
}

/*
 * Read from user space.  The user context is given by p.
 */
int
kvm_uread(kvm_t *kd, struct proc *p, u_long uva, char *buf, size_t len)
{
	char *cp;

	cp = buf;
	while (len > 0) {
		u_long pa;
		int cc;
		
		cc = _kvm_uvatop(kd, p, uva, &pa);
		if (cc > 0) {
			if (cc > len)
				cc = len;
			errno = 0;
			if (lseek(kd->pmfd, (off_t)pa, 0) == -1 && errno != 0) {
				_kvm_err(kd, 0, "invalid address (%lx)", uva);
				break;
			}
			cc = read(kd->pmfd, cp, cc);
			if (cc < 0) {
				_kvm_syserr(kd, 0, _PATH_MEM);
				break;
			} else if (cc < len) {
				_kvm_err(kd, kd->program, "short read");
				break;
			}
		} else if (ISALIVE(kd)) {
			/* try swap */
			char *dp;
			int cnt;

			dp = kvm_readswap(kd, p, uva, &cnt);
			if (dp == 0) {
				_kvm_err(kd, 0, "invalid address (%lx)", uva);
				return (0);
			}
			cc = MIN(cnt, len);
			bcopy(dp, cp, cc);
		} else
			break;
		cp += cc;
		uva += cc;
		len -= cc;
	}
	return (int)(cp - buf);
}
