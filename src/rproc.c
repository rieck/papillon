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
 * $Id: rproc.c,v 1.16 2003/03/20 18:54:07 kr Exp $
 *
 * This file contains the restricted proc routines. It is implemented by
 * redirecting calls to some proc vnode operations and checking permissions.
 */

#define _KERNEL

#include "headers.h"

#if defined(RSTPROC)

extern pap_config_t config;
extern int (*old_praccess) ();
extern krwlock_t config_rwlock;

int pap_praccess(struct vnode *vp, int mode, int flags, struct cred *cr)
{
    boolean_t access = B_TRUE;
    int error;
    prnode_t *pr;

    inc_refcnt();
    dcmn_err((CE_CONT, "praccess() vnode operation.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.rstproc)
        goto skip;

    pr = VTOP(vp);

    mutex_enter(&pr->pr_mutex);

    if (pr && pr->pr_common && pr->pr_common->prc_proc &&
        pr->pr_type != PR_PROCDIR &&
        cr->cr_ruid != SUSER_UID &&
        cr->cr_rgid != SUSER_GID &&
        cr->cr_ruid != pr->pr_common->prc_proc->p_cred->cr_ruid)
        access = B_FALSE;

    mutex_exit(&pr->pr_mutex);


  skip:
    if (access)
        error = old_praccess(vp, mode, flags, cr);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;
}

#endif                          /* RSTPROC */
