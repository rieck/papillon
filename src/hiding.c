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
 * $Id: hiding.c,v 1.31 2003/03/20 18:54:07 kr Exp $
 *
 * Routines that hide the module as file, as module and from file listings. 
 * The functions operate on the vfs layer and should work on all underlaying
 * filesystems, probably even NFS.
 */

#define _KERNEL

#if defined(MODHIDING)

#include "headers.h"

/* 
 * Structure of the loaded modules
 */
extern struct modctl modules;

/*
 * Stuff defined in papillon.c
 */
extern struct modctl *this_module;
extern struct modlinkage modlinkage;
extern int (*old_vnlookup) ();
extern int (*old_vnreaddir) ();
extern kmutex_t readdir_lock;
extern krwlock_t config_rwlock;
extern pap_config_t config;
extern pap_modfiles_t modfiles[];

/*
 * Initially the module isn't hidden
 */
static boolean_t module_hidden = B_FALSE;

/*
 * The module is hidden by removing its entry from the cyclic doubly linked
 * list of current loaded modules. It is unhidden by inserting this entry   
 * into the list again.
 */
void hide_module(void)
{
    struct modctl *prev, *this;

    if ((module_hidden && config.modhiding) ||
        (!module_hidden && !config.modhiding))
        return;

    mutex_enter(&mod_lock);

    this = &modules;
    if (!module_hidden) {

        while (this->mod_linkage != &modlinkage) {
            this = this->mod_next;
            ASSERT(this != &modules);
        }

        this_module = this;

        cmn_err(CE_CONT, "Hiding module Papillon.\n");

        prev = this->mod_prev;

        prev->mod_next = this->mod_next;
        this->mod_next->mod_prev = prev;

        module_hidden = B_TRUE;

    } else {

        cmn_err(CE_CONT, "Unhiding module Papillon.\n");

        this_module->mod_next = this;
        this_module->mod_prev = this->mod_prev;
        this_module->mod_prev->mod_next = this_module;
        this_module->mod_next->mod_prev = this_module;

        this_module->mod_id = this_module->mod_prev->mod_id + 1;

        module_hidden = B_FALSE;
    }

    mutex_exit(&mod_lock);
}

boolean_t vnode_hidden(struct vnode *vp, boolean_t parent)
{
    int i;

    if (!vp)
        return B_FALSE;

    for (i = 0; CRED()->cr_ruid != SUSER_UID && modfiles[i].path; i++)
        if (parent) {
            if (modfiles[i].parent_vnode &&
                VN_CMP(modfiles[i].parent_vnode, vp))
                return B_TRUE;
        } else {
            if (modfiles[i].vnode && VN_CMP(modfiles[i].vnode, vp))
                return B_TRUE;
        }

    return B_FALSE;
}

boolean_t inode_hidden(ino_t i_number)
{
    int i;

    /*
     * Does the inode number 0 exist? Don't think so.
     */
    if (!i_number)
        return B_FALSE;
    for (i = 0; CRED()->cr_ruid != SUSER_UID && modfiles[i].path; i++) {

        dcmn_err((CE_CONT, "List inode %d == Hidden inode %d\n",
                  i_number, VTOI(modfiles[i].vnode)->i_number));

        if (modfiles[i].vnode &&
            i_number == VTOI(modfiles[i].vnode)->i_number)
            return B_TRUE;
    }

    return B_FALSE;
}

int pap_vnlookup(struct vnode *dvp, char *nm, struct vnode **vpp,
                 struct pathname *pnp, int flags, struct vnode *rdir,
                 struct cred *cred)
{
    int error;

    inc_refcnt();
    rw_enter(&config_rwlock, RW_READER);

    error = old_vnlookup(dvp, nm, vpp, pnp, flags, rdir, cred);

    if (config.modhiding && !error && vnode_hidden(*vpp, B_FALSE)) {
        dcmn_err((CE_CONT, "Hiding inode %d from lookup().\n",
                  VTOI(*vpp)->i_number));
        error = set_errno(ENOENT);
    }

    rw_exit(&config_rwlock);
    dec_refcnt();

    return error;
}

/*
 * This code has been adopted from Job de Haas' Kernmod-0.2.
 */
int pap_vnreaddir(struct vnode *vp, struct uio *uiop, struct cred *cr,
                  int *eofp)
{
    caddr_t base, buf;
    int len, count, cnt, reclen, offs, error;
    int oldoffs;
    struct dirent64 *idp, *prev_dp, *next_dp;

    inc_refcnt();
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Get I/O request length, base address for extracting the 
     * dirent64 structs. Also store the offset to cope with 
     * uiomove() executed later.
     */
    len = uiop->uio_iov->iov_len;
    base = uiop->uio_iov->iov_base;
    offs = uiop->uio_offset;
    count = len;

    error = (old_vnreaddir) (vp, uiop, cr, eofp);

    if (!config.modhiding || error || !vnode_hidden(vp, B_TRUE))
        goto err;

    /*
     * We are now inside the directory that contains the Papillon
     * module or other files to hide.
     */
    dcmn_err((CE_CONT, "Entering a directory containing hidden files\n"));

    /*
     * Calculate returned length, similar to the original getdents64().
     */
    oldoffs = uiop->uio_offset;
    len = len - uiop->uio_resid;

    if (len <= 0)
        goto err;

    mutex_enter(&readdir_lock);
    buf = kmem_zalloc(len, KM_SLEEP);

    if (!buf)
        goto err_and_unlock;

    /* 
     * getdents() = UIO_SYSSPACE / getdents64() = UIO_USERSPACE 
     * whispered a little bird into my ear.
     */
    if (uiop->uio_segflg == UIO_USERSPACE) {
        dcmn_err((CE_CONT, "Getting dirent64 from userland\n"));
        if (copyin(base, buf, len))
            goto err_and_free;
    } else {
        dcmn_err((CE_CONT, "Getting dirent64 from kernelland\n"));
        bcopy(base, buf, len);
    }

    idp = (struct dirent64 *) buf;
    prev_dp = NULL;
    cnt = 0;

    /*
     * Traverse the directory data looking for a match then let increase the
     * previous record length so this one will be hidden. If it is the first
     * field, copy the next field over this one and extend the reclen field
     * to cover for both.
     */
    while (cnt < len) {

        /*
         * We can safely access the inode of the mode, since we fooled the
         * lookup() and none will access the inode. No locking needed.
         */
        if (inode_hidden(idp->d_ino)) {

            dcmn_err((CE_CONT, "Hiding inode %d from readdir().\n",
                      idp->d_ino));

            reclen = idp->d_reclen;

            if (prev_dp) {
                cnt -= prev_dp->d_reclen;
                prev_dp->d_reclen += reclen;
                idp = prev_dp;
            } else {
                /*
                 * This is the first entry and it should be hidden. We do
                 * this by copying the next one over this one. Carefull to
                 * only do this if there is a next entry.
                 */
                if (cnt + reclen < len) {

                    next_dp = (struct dirent64 *) ((char *) idp + reclen);
                    bcopy((caddr_t) next_dp, (caddr_t) idp,
                          next_dp->d_reclen);

                    idp->d_reclen += reclen;
                    continue;

                    /*
                     * else: the only entry should be hidden. Will only
                     * happen with a small buffer and returning empty is
                     * wrong. Let it be for awhile. With libc this wont
                     * happen normally. ...Job said so, he's probably right.
                     */
                }
            }
        }

        cnt += idp->d_reclen;
        prev_dp = idp;
        idp = (struct dirent64 *) ((int64_t) idp + idp->d_reclen);
    }

    uiop->uio_iov->iov_base = base;
    uiop->uio_iov->iov_len = count;
    uiop->uio_offset = offs;
    uiop->uio_resid = count;
    uiomove(buf, len, UIO_READ, uiop);
    uiop->uio_offset = oldoffs;

  err_and_free:
    kmem_free(buf, len);
  err_and_unlock:
    mutex_exit(&readdir_lock);
  err:

    rw_exit(&config_rwlock);
    dec_refcnt();

    return (error);
}

#endif                          /* MODHIDING */
