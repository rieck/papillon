/*
 * Papillon - Solaris security module -  http://www.roqe.org/papillon
 * Copyright (c) 2000-2003,2006 Konrad Rieck <kr@roqe.org>
 * All rights reserved.
 * --
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes software developed by Konrad Rieck."
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * This software is provided by the author "as is" and any express or
 * implied warranties, including, but not limited to, the implied warranties
 * of merchantability and fitness for a particular purpose are disclaimed.
 *
 * In no event shall the author be liable for any direct, indirect,
 * incidental, special, exemplary, or consequential damages (including, but
 * not limited to, procurement of substitute goods or services; loss of use,
 * data or profits; or buisness interruption) however caused and on any
 * theory of liability, whether in contracr, strict liability, or tort
 * (including negligence or otherwise) arising in any way out of the use of
 * this software, even if advised of the possibility of such damage.
 * --
 * $Id: refcnt.c,v 1.4 2003/03/20 18:54:07 kr Exp $
 *
 * An implementation of a reference counter, in order to keep track 
 * who is calling the syscalls on smp machines. Thanks to Acpizer for
 * his code. 
 */

#define _KERNEL

#include "headers.h"

extern kmutex_t refcnt_lock;
static int refcount;

void inc_refcnt()
{
    ASSERT(refcount >= 0);
    mutex_enter(&refcnt_lock);
    refcount++;
    mutex_exit(&refcnt_lock);
}

void dec_refcnt()
{
    mutex_enter(&refcnt_lock);
    refcount--;
    mutex_exit(&refcnt_lock);
    ASSERT(refcount >= 0);
}

void init_refcnt()
{
    mutex_enter(&refcnt_lock);
    refcount = 0;
    mutex_exit(&refcnt_lock);
}

boolean_t check_refcnt()
{
    mutex_enter(&refcnt_lock);
    if (refcount > 0) {
        mutex_exit(&refcnt_lock);
        return B_FALSE;
    }

    mutex_exit(&refcnt_lock);
    return B_TRUE;
}
