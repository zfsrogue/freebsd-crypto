/*-
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
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
#if 0
static char sccsid[] = "@(#)ungetc.c	8.2 (Berkeley) 11/3/93";
#endif
static const char rcsid[] =
		"$Id$";
#endif /* LIBC_SCCS and not lint */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "local.h"
#ifdef _THREAD_SAFE
#include <pthread.h>
#include "pthread_private.h"
#endif

static int __submore __P((FILE *));

/*
 * Expand the ungetc buffer `in place'.  That is, adjust fp->_p when
 * the buffer moves, so that it points the same distance from the end,
 * and move the bytes in the buffer around as necessary so that they
 * are all at the end (stack-style).
 */
static int
__submore(fp)
	register FILE *fp;
{
	register int i;
	register unsigned char *p;

	if (fp->_ub._base == fp->_ubuf) {
		/*
		 * Get a new buffer (rather than expanding the old one).
		 */
		if ((p = malloc((size_t)BUFSIZ)) == NULL)
			return (EOF);
		fp->_ub._base = p;
		fp->_ub._size = BUFSIZ;
		p += BUFSIZ - sizeof(fp->_ubuf);
		for (i = sizeof(fp->_ubuf); --i >= 0;)
			p[i] = fp->_ubuf[i];
		fp->_p = p;
		return (0);
	}
	i = fp->_ub._size;
	p = realloc(fp->_ub._base, (size_t)(i << 1));
	if (p == NULL)
		return (EOF);
	/* no overlap (hence can use memcpy) because we doubled the size */
	(void)memcpy((void *)(p + i), (void *)p, (size_t)i);
	fp->_p = p + i;
	fp->_ub._base = p;
	fp->_ub._size = i << 1;
	return (0);
}

int
ungetc(c, fp)
	int c;
	register FILE *fp;
{
	if (c == EOF)
		return (EOF);
	if (!__sdidinit)
		__sinit();
#ifdef _THREAD_SAFE
	_thread_flockfile(fp,__FILE__,__LINE__);
#endif
	if ((fp->_flags & __SRD) == 0) {
		/*
		 * Not already reading: no good unless reading-and-writing.
		 * Otherwise, flush any current write stuff.
		 */
		if ((fp->_flags & __SRW) == 0) {
#ifdef _THREAD_SAFE
			_thread_funlockfile(fp);
#endif
			return (EOF);
		}
		if (fp->_flags & __SWR) {
			if (__sflush(fp)) {
#ifdef _THREAD_SAFE
				_thread_funlockfile(fp);
#endif
				return (EOF);
			}
			fp->_flags &= ~__SWR;
			fp->_w = 0;
			fp->_lbfsize = 0;
		}
		fp->_flags |= __SRD;
	}
	c = (unsigned char)c;

	/*
	 * If we are in the middle of ungetc'ing, just continue.
	 * This may require expanding the current ungetc buffer.
	 */
	if (HASUB(fp)) {
		if (fp->_r >= fp->_ub._size && __submore(fp)) {
#ifdef _THREAD_SAFE
			_thread_funlockfile(fp);
#endif
			return (EOF);
		}
		*--fp->_p = c;
		fp->_r++;
#ifdef _THREAD_SAFE
		_thread_funlockfile(fp);
#endif
		return (c);
	}
	fp->_flags &= ~__SEOF;

	/*
	 * If we can handle this by simply backing up, do so,
	 * but never replace the original character.
	 * (This makes sscanf() work when scanning `const' data.)
	 */
	if (fp->_bf._base != NULL && fp->_p > fp->_bf._base &&
	    fp->_p[-1] == c) {
		fp->_p--;
		fp->_r++;
#ifdef _THREAD_SAFE
		_thread_funlockfile(fp);
#endif
		return (c);
	}

	/*
	 * Create an ungetc buffer.
	 * Initially, we will use the `reserve' buffer.
	 */
	fp->_ur = fp->_r;
	fp->_up = fp->_p;
	fp->_ub._base = fp->_ubuf;
	fp->_ub._size = sizeof(fp->_ubuf);
	fp->_ubuf[sizeof(fp->_ubuf) - 1] = c;
	fp->_p = &fp->_ubuf[sizeof(fp->_ubuf) - 1];
	fp->_r = 1;
#ifdef _THREAD_SAFE
	_thread_funlockfile(fp);
#endif
	return (c);
}
