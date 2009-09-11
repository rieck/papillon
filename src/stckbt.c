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
 * $Id: stckbt.c,v 1.30 2003/09/08 16:38:12 kr Exp $
 *
 * This file contains everything related to the sticky bit on directories.
 * In other words the sym/hardlink and FIFO protection.
 */


#define _KERNEL

#include "headers.h"

extern pap_syscall_t syscalls[];
#ifdef _64BIT
extern pap_syscall_t syscalls32[];
#endif

extern pap_config_t config;
extern krwlock_t config_rwlock;

#if defined(FIFOPROT) || defined(SYMPROT)

/*
 * Symlink and Fifo protection. 
 */
int stckbt_checks(char *path, int oflag)
{
    vnode_t *fvp, *pvp;         /* file and parent vnode */
    vattr_t fvattr, pvattr;     /* file and parent vnode attributes */
    cred_t *cred;
    char k_path[MAX_PATH_LEN];
    boolean_t ret = B_TRUE;
    int len;

    if (lookupname((char *) path, UIO_USERSPACE, NO_FOLLOW, &pvp, &fvp))
        return B_TRUE;

    if (!fvp || !pvp)
        goto err_and_release;

    if (VOP_GETATTR(fvp, &fvattr, 0, ddi_get_cred()) != 0 ||
        VOP_GETATTR(pvp, &pvattr, 0, ddi_get_cred()) != 0)
        goto err_and_release;

    cred = ddi_get_cred();

#if defined(FIFOPROT)
    /*
     * Fifo protection
     */
    if ((oflag & O_CREAT) &&    /* create mode */
        cred->cr_ruid != SUSER_UID &&   /* not super-user */
        (pvattr.va_mode & S_ISVTX) &&   /* parent is sticky */
        fvp->v_type == VFIFO && /* file is FIFO */
        fvattr.va_uid != cred->cr_uid &&        /* file uid not cred uid */
        pvattr.va_uid != fvattr.va_uid) {       /* file uid not parent uid */

        if (copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & len) != 0)
            goto err_and_release;

        if (config.fifoprot == PAP_DENY) {
            log_msg(CE_WARN, "Denied opening FIFO %s", k_path);
            ret = B_FALSE;
        } else {
            log_msg(CE_WARN, "Opening FIFO %s", k_path);
        }
    }
#endif                          /* FIFOPROT */

#if defined(SYMPROT)
    /*
     * Symlink protection
     */
    if (ret && (pvattr.va_mode & S_ISVTX) &&    /* parent is sticky */
        fvp->v_type == VLNK &&  /* file is symlink */
        fvattr.va_uid != cred->cr_uid &&        /* file uid not cred uid */
        pvattr.va_uid != fvattr.va_uid) {       /* file uid not parent uid */

        if (copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & len) != 0)
            goto err_and_release;

        if (config.symprot == PAP_DENY) {
            log_msg(CE_WARN, "Denied following symlink %s", k_path);
            ret = B_FALSE;
        } else {
            log_msg(CE_WARN, "Following symlink %s", k_path);
        }
    }
#endif                          /* SYMPROT */

  err_and_release:
    if (fvp)
        VN_RELE(fvp);
    if (pvp)
        VN_RELE(pvp);

    return ret;
}

/*
 * open64() redirection.
 * Perform FIFO and symlink protections.
 */
int64_t pap_open64(const char *path, int oflag, mode_t mode)
{
    int64_t error;
    boolean_t access = B_TRUE;

    inc_refcnt();
    dcmn_err((CE_CONT, "open64() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.symprot && !config.fifoprot)
        goto skip;

    access = stckbt_checks((char *) path, oflag);

  skip:
    if (access)
        error = syscalls[OPEN64].sc(path, oflag, mode);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;
}

/*
 * open() redirection.
 * Perform fifo and symlink protections.
 */
int64_t pap_open(const char *path, int oflag, mode_t mode)
{
    int64_t error;
    boolean_t access = B_TRUE;

    inc_refcnt();
    dcmn_err((CE_CONT, "open() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.symprot && !config.fifoprot)
        goto skip;

    access = stckbt_checks((char *) path, oflag);

  skip:
    if (access)
        error = syscalls[OPEN].sc(path, oflag, mode);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;

}
#endif                          /* SYM- & FIFOPROT */


#if defined(HARDPROT)
/*
 * link() redirection.
 * Perform hardlink protection.
 */
int64_t pap_link(const char *existing, const char *new)
{
    struct vnode *vp;
    struct vattr vattr;
    cred_t *cred;
    boolean_t access = B_TRUE;
#ifndef SOLARIS8
    char k_existing[MAX_PATH_LEN];
    char k_new[MAX_PATH_LEN];
    int len;   
#endif 
    int64_t error;


    inc_refcnt();
    dcmn_err((CE_CONT, "link() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.hardprot ||
        lookupname((char *) existing, UIO_USERSPACE, NO_FOLLOW, NULLVPP,
                   &vp))
        goto err;

    if (!vp)
        goto err_and_release;

    if (VOP_GETATTR(vp, &vattr, 0, ddi_get_cred()) != 0)
        goto err_and_release;

    cred = ddi_get_cred();

    /*
     * Hardlink protection.
     */
    if (cred->cr_uid != SUSER_UID &&    /* not super-user */
        cred->cr_uid != vattr.va_uid) { /* file uid not cred uid */

#ifndef SOLARIS8
        /*
         * I have _NO_ idea why this crashs under Solaris 8. Maybe
         * the lookupname() aboves modifies the "existing" string, e.g.
         * moving it to kernel space. Anyway, I am not going to do
         * more fixes, because Solaris 9 behaves correctly.
         */
        if (copyinstr(existing, k_existing, MAX_PATH_LEN,
                      (size_t *) & len) != 0
            || copyinstr(new, k_new, MAX_PATH_LEN, (size_t *) & len) != 0)
            goto err_and_release;
#endif

        if (config.hardprot == PAP_DENY) {
#ifdef SOLARIS8
            log_msg(CE_WARN, "Denied creating hardlink");
#else
            log_msg(CE_WARN, "Denied creating hardlink from %s to %s",
                    k_existing, k_new);
#endif
            access = B_FALSE;
        } else {
#ifdef SOLARIS8
            log_msg(CE_WARN, "Creating hardlink");
#else
            log_msg(CE_WARN, "Creating hardlink from %s to %s",
                    k_existing, k_new);
#endif
        }
    }

  err_and_release:
    if (vp)
        VN_RELE(vp);
  err:
    if (access)
        error = syscalls[LINK].sc(existing, new);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;
}

#endif                          /* HARDPROT */

#ifdef _64BIT
#if defined(FIFOPROT) || defined(SYMPROT)
/*
 * open64() redirection.
 * Perform FIFO and symlink protections.
 */
int64_t pap_open64_32(const char *path, int oflag, mode_t mode)
{
    int64_t error;
    boolean_t access = B_TRUE;

    inc_refcnt();
    dcmn_err((CE_CONT, "open64_32() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.symprot && !config.fifoprot)
        goto skip;

    access = stckbt_checks((char *) path, oflag);

  skip:
    if (access)
        error = syscalls32[OPEN64].sc(path, oflag, mode);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;
}

/*
 * open() redirection.
 * Perform FIFO and symlink protections.
 */
int64_t pap_open32(const char *path, int oflag, mode_t mode)
{
    int64_t error;
    boolean_t access = B_TRUE;

    inc_refcnt();
    dcmn_err((CE_CONT, "open32() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    if (!config.symprot && !config.fifoprot)
        goto skip;

    access = stckbt_checks((char *) path, oflag);

  skip:
    if (access)
        error = syscalls32[OPEN].sc(path, oflag, mode);
    else
        error = set_errno(EPERM);

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;

}
#endif                          /* SYM- & FIFOPROT */
#endif                          /* _64BIT */
