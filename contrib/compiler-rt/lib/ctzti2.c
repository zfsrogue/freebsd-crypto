/* ===-- ctzti2.c - Implement __ctzti2 -------------------------------------===
 *
 *                     The LLVM Compiler Infrastructure
 *
 * This file is dual licensed under the MIT and the University of Illinois Open
 * Source Licenses. See LICENSE.TXT for details.
 *
 * ===----------------------------------------------------------------------===
 *
 * This file implements __ctzti2 for the compiler_rt library.
 *
 * ===----------------------------------------------------------------------===
 */

#if __x86_64

#include "int_lib.h"

/* Returns: the number of trailing 0-bits */

/* Precondition: a != 0 */

si_int
__ctzti2(ti_int a)
{
    twords x;
    x.all = a;
    const di_int f = -(x.s.low == 0);
    return __builtin_ctzll((x.s.high & f) | (x.s.low & ~f)) +
              ((si_int)f & ((si_int)(sizeof(di_int) * CHAR_BIT)));
}

#endif
