/*-
 * Copyright (c) 2001 Matthew Dillon.  This code is distributed under
 * the BSD copyright, /usr/src/COPYRIGHT.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/pcpu.h>
#include <sys/eventhandler.h>	/* XX */
#include <sys/ktr.h>		/* XX */
#include <sys/signalvar.h>
#include <sys/sysproto.h>	/* XX */
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/ucontext.h>

void
cpu_critical_enter(void)
{
	struct thread *td = curthread;

	td->td_md.md_savecrit = intr_disable();
}

void
cpu_critical_exit(void)
{
	struct thread *td = curthread;

	intr_restore(td->td_md.md_savecrit);
}

/*
 * cpu_critical_fork_exit() - cleanup after fork
 *
 */
void
cpu_critical_fork_exit(void)
{
	struct thread *td = curthread;

	td->td_critnest = 1;
	td->td_md.md_savecrit = ALPHA_PSL_IPL_0;
}

/*
 * cpu_thread_link() - thread linkup, initialize machine-dependant fields
 */
void
cpu_thread_link(struct thread *td)
{
	td->td_md.md_savecrit = 0;
}

