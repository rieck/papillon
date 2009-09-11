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
 * $Id: ppromisc.c,v 1.18 2003/04/25 14:24:19 kr Exp $
 *
 * The idea for this check was introduced by UDP in his module
 * solpromisc-1.0, eventhough I had something similar in my mind. :)
 */

#define _KERNEL

#if defined(PPROMISC)

#include "headers.h"

extern pap_syscall_t syscalls[];
#ifdef _64BIT
extern pap_syscall_t syscalls32[];
#endif

extern pap_config_t config;
extern kmutex_t promisc_lock;
extern krwlock_t config_rwlock;

void check_promisc(int fildes, dl_promiscon_req_t * promiscon)
{
    char *device;
    file_t *file;
    cred_t *cred;
    dev_t rdev;

    if (promiscon->dl_primitive == DL_PROMISCON_REQ &&
        promiscon->dl_level == DL_PROMISC_PHYS) {

        file = getf(fildes);

        if (!file)
            return;

        rdev = file->f_vnode->v_rdev;
        device = ddi_major_to_name(getmajor(rdev));
        cred = ddi_get_cred();

        log_msg(CE_WARN, "Promiscuous mode enabled on interface %s",
                device ? device : "unknown");

        releasef(fildes);
    }

    return;
}

int64_t pap_putmsg(int fildes, struct strbuf * ctlptr, struct strbuf
                   * dataptr, int *flagsp)
{
    struct strbuf kctlptr;
    dl_promiscon_req_t *kpromiscon;

    inc_refcnt();

    dcmn_err((CE_CONT, "putmsg() syscall.\n"));

    rw_enter(&config_rwlock, RW_READER);

    if (!config.ppromisc ||
        copyin(ctlptr, &kctlptr, sizeof(struct strbuf)) != 0)
        goto err;

    mutex_enter(&promisc_lock);

    kpromiscon = (dl_promiscon_req_t *) kmem_alloc(kctlptr.len, KM_SLEEP);
    if (!kpromiscon)
        goto err_and_unlock;

    if (copyin(kctlptr.buf, kpromiscon, kctlptr.len) != 0)
        goto err_and_free;

    check_promisc(fildes, kpromiscon);

  err_and_free:
    kmem_free(kpromiscon, kctlptr.len);
  err_and_unlock:
    mutex_exit(&promisc_lock);
  err:

    rw_exit(&config_rwlock);
    dec_refcnt();

    return syscalls[PUTMSG].sc(fildes, ctlptr, dataptr, flagsp);
}

#ifdef _64BIT
int64_t pap_putmsg32(int fildes, struct strbuf32 * ctlptr, struct strbuf32
                     * dataptr, int *flagsp)
{
    struct strbuf32 kctlptr;
    dl_promiscon_req_t *kpromiscon;

    inc_refcnt();

    dcmn_err((CE_CONT, "putmsg() syscall.\n"));

    rw_enter(&config_rwlock, RW_READER);

    if (!config.ppromisc ||
        copyin(ctlptr, &kctlptr, sizeof(struct strbuf)) != 0)
        goto err;

    mutex_enter(&promisc_lock);

    kpromiscon = (dl_promiscon_req_t *) kmem_alloc(kctlptr.len, KM_SLEEP);
    if (!kpromiscon)
        goto err_and_unlock;

    /*
     * There is something strange about kctlptr.buf. GCC says:
     * "... arg 1 of `copyin' makes pointer from integer without a cast"
     * Probably a typical 32 vs. 64bit casting problem. Fix me later.
     */
    if (copyin(kctlptr.buf, kpromiscon, kctlptr.len) != 0)
        goto err_and_free;

    check_promisc(fildes, kpromiscon);

  err_and_free:
    kmem_free(kpromiscon, kctlptr.len);
  err_and_unlock:
    mutex_exit(&promisc_lock);
  err:

    rw_exit(&config_rwlock);
    dec_refcnt();

    return syscalls32[PUTMSG].sc(fildes, ctlptr, dataptr, flagsp);
}

#endif                          /* _64BIT */
#endif                          /* PPROMISC */
