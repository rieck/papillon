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
 * $Id: chroot.c,v 1.25 2003/09/08 16:31:52 kr Exp $
 *
 * Chroot protection. Initial implementation by Heiko Krupp. Ideas
 * have been adopted from the HAP-Linux kernel patch, chroot(), mount()
 * and mknod() interception.
 */

#define _KERNEL

#include "headers.h"

#if defined(CHROOTPROT)

extern pap_syscall_t syscalls[];
#ifdef _64BIT
extern pap_syscall_t syscalls32[];
#endif

extern pap_config_t config;
extern krwlock_t config_rwlock;

int64_t pap_chroot(const char *path)
{
    int64_t ret;
    char k_path[MAX_PATH_LEN];

    inc_refcnt();
    dcmn_err((CE_CONT, "chroot() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process
     */
    if (!config.chrootprot || !u.u_rdir) {
        ret = syscalls[CHROOT].sc(path);
        goto skip;
    }

    ret = copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied recursive chroot in %s", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Recursive chroot in %s", k_path);
        ret = syscalls[CHROOT].sc(path);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

int64_t pap_mount(const char *spec, const char *dir, int mflag, char *fst,
                  char *dp, int dl, char *op, int ol)
{
    char k_path[MAX_PATH_LEN];
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "mount() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process
     */
    if (!config.chrootprot || !u.u_rdir) {
        ret = syscalls[MOUNT].sc(spec, dir, mflag, fst, dp, dl, op, ol);
        goto skip;
    }

    ret = copyinstr(dir, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied mounting %s chroot'ed", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Mounting %s chroot'ed", k_path);
        ret = syscalls[MOUNT].sc(spec, dir, mflag, fst, dp, dl, op, ol);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

int64_t pap_mknod(const char *path, mode_t mode, dev_t dev)
{
    char k_path[MAX_PATH_LEN];
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "mknod() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process and
     * creation of a charakter/block device requested.
     */
    if (!config.chrootprot || !(u.u_rdir && (mode | S_IFCHR | S_IFBLK))) {
        ret = syscalls[MKNOD].sc(path, mode, dev);
        goto skip;
    }

    ret = copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied creating device node %s chroot'ed", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Creating device node %s chroot'ed", k_path);
        ret = syscalls[MKNOD].sc(path, mode, dev);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

int64_t pap_modctl(int cmd, uintptr_t a1, uintptr_t a2, uintptr_t a3,
                   uintptr_t a4, uintptr_t a5)
{
    int64_t ret;
    char k_path[MAX_PATH_LEN];

    /*
     * If not modloading jump directly to the original code. Don't
     * reference count or lock this syscall! If you do, you can't unload
     * Papillon, think twice!
     */
    if (cmd != MODLOAD)
        return syscalls[MODCTL].sc(cmd, a1, a2, a3, a4, a5);

    inc_refcnt();
    dcmn_err((CE_CONT, "() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process and
     * and loading a new module.
     */
    if (!config.chrootprot || !u.u_rdir) {
        ret = syscalls[MODCTL].sc(cmd, a1, a2, a3, a4, a5);
        goto skip;
    }

    ret = copyinstr((char *) a2, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied loading module %s chroot'ed", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Loading module %s chroot'ed", k_path);
        ret = syscalls[MODCTL].sc(cmd, a1, a2, a3, a4, a5);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

int64_t pap_chmod(const char *path, mode_t mode)
{
    char k_path[MAX_PATH_LEN];
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "chmod() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process and
     * mode +s.
     */
    if (!config.chrootprot || !(u.u_rdir && (mode | S_ISUID | S_ISGID))) {
        ret = syscalls[CHMOD].sc(path, mode);
        goto skip;
    }

    ret = copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied setting setuid bit on %s chroot'ed",
                k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Setting setuid bit on %s chroot'ed", k_path);
        ret = syscalls[CHMOD].sc(path, mode);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

int64_t pap_xmknod(const char *path, mode_t mode, dev_t dev)
{
    char k_path[MAX_PATH_LEN];
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "xmknod() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process and
     * creation of a charakter/block device requested.
     */
    if (!config.chrootprot || !(u.u_rdir && (mode | S_IFCHR | S_IFBLK))) {
        ret = syscalls[XMKNOD].sc(path, mode, dev);
        goto skip;
    }

    ret = copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied creating device node %s chroot'ed", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Creating device node %s chroot'ed", k_path);
        ret = syscalls[XMKNOD].sc(path, mode, dev);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}



#ifdef _64BIT
int64_t pap_xmknod32(const char *path, mode_t mode, dev_t dev)
{
    char k_path[MAX_PATH_LEN];
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "xmknod32() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

    /*
     * Skip if no chroot protection or no new root set for process and
     * creation of a charakter/block device requested.
     */
    if (!config.chrootprot || !(u.u_rdir && (mode | S_IFCHR | S_IFBLK))) {
        ret = syscalls32[XMKNOD].sc(path, mode, dev);
        goto skip;
    }

    ret = copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret);
    if (ret != 0)
        goto skip;

    if (config.chrootprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied creating device node %s chroot'ed", k_path);
        ret = set_errno(EPERM);
    } else {
        log_msg(CE_WARN, "Creating device node %s chroot'ed", k_path);
        ret = syscalls32[XMKNOD].sc(path, mode, dev);
    }

  skip:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

#endif                          /* _64BIT */
#endif                          /* CHROOTPROT */
