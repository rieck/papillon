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
 * $Id: setuid.c,v 1.8 2003/09/08 18:25:04 kr Exp $
 * 
 * This file contains the STDIO protection that only applies to setuid/setgid
 * files.
 */

#define _KERNEL

#include "headers.h"

#if defined(SECSTDFD) || defined(SEXECPROT)

#define STDIO(i) i==0?"STDIN":i==1?"STDOUT":"STDERR"

extern pap_syscall_t syscalls[];

extern pap_config_t config;
extern krwlock_t config_rwlock;

/*
 * White-list of programs (defined in papillon.c)
 */
extern char *pap_whitelist[];

int check_setuid_vnode(vnode_t * vp)
{
    vattr_t vattr;

    if (!vp)
        return B_FALSE;

    if (VOP_GETATTR(vp, &vattr, 0, ddi_get_cred()))
        return B_FALSE;

    if (vattr.va_mode & (S_ISUID | S_ISGID))
        return B_TRUE;

    return B_FALSE;
}

int check_setuid_file(char *path)
{
    vnode_t *vp;
    boolean_t ret = B_FALSE;

    if (!path)
        return B_FALSE;

    if (lookupname((char *) path, UIO_USERSPACE, NO_FOLLOW, NULL, &vp))
        return B_FALSE;

    ret = check_setuid_vnode(vp);

    VN_RELE(vp);
    return ret;
}

int64_t pap_execve(const char *path, char *const argv[], char *const envp[])
{
    uf_info_t *ufinfo;
    short i;
    boolean_t setuid = B_FALSE, fake_opened_fd[3];
    char k_path[MAX_PATH_LEN];
    char k_comm[MAXCOMLEN + 1];
    vnode_t *vp;
    int64_t ret;

    inc_refcnt();
    dcmn_err((CE_CONT, "execve() syscall.\n"));
    rw_enter(&config_rwlock, RW_READER);

#if defined(SEXECPROT)
    if (!config.sexecprot)
        goto next;

    /*
     * Check if the parent process's binary has the setuid bit set
     */
    mutex_enter(&pidlock);
    setuid = check_setuid_vnode(curproc->p_parent->p_exec);
    strncpy(k_comm, curproc->p_parent->p_user.u_comm, MAXCOMLEN);
    mutex_exit(&pidlock);

    if (!setuid)
        goto next;


    /*
     * Check if the give file exists. We don't check for modes, because
     * it is rather seldom that an existing file is called from a setuid
     * binary and hasn't appropriate permissions set. 
     */
    if (lookupname((char *) path, UIO_USERSPACE, FOLLOW, NULLVPP, &vp))
        goto next;
    VN_RELE(vp);

    if (copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret))
        goto next;

    /*
     * Check if the current programm is in our whitelist
     */
    for (i = 0; pap_whitelist[i] != NULL; i++)
        if (!strcmp(pap_whitelist[i], k_comm))
            goto next;

    if (config.sexecprot == PAP_DENY) {
        log_msg(CE_WARN, "Denied executing %s by setuid parent %s", k_path,
                k_comm);
        ret = set_errno(EPERM);
        goto deny;
    } else {
        log_msg(CE_WARN, "Executing %s by setuid parent %s", k_path, k_comm);
    }

#endif                          /* SEXECPROT */

  next:
#if defined(SECSTDFD)
    if (!config.secstdfd)
        goto skip;

    setuid = check_setuid_file((char *) path);
    ufinfo = P_FINFO(curproc);

    for (i = 0; setuid && ufinfo && i < 3; i++) {
        if (!ufinfo->fi_list[i].uf_file) {
            if (copyinstr(path, k_path, MAX_PATH_LEN, (size_t *) & ret) == 0)
                log_msg(CE_WARN, " Fake opening %s before executing %s",
                        STDIO(i), k_path);
            ufalloc(i);
            fake_opened_fd[i] = B_TRUE;
        } else {
            fake_opened_fd[i] = B_FALSE;
        }
    }
#endif                          /* SECSTDFD */

  skip:
    ret = syscalls[EXECVE].sc(path, argv, envp);

#if defined(SECSTDFD)
    for (i = 0; config.secstdfd && setuid && ufinfo && i < 3; i++) {
        if (fake_opened_fd[i]) {
            log_msg(CE_CONT, "Closing fake opened %s.", STDIO(i));
            closeandsetf(i, NULL);
        }
    }
#endif                          /* SECSTDFD */

  deny:
    rw_exit(&config_rwlock);
    dec_refcnt();

    return ret;
}

#endif                          /* SECSTDFD || SEXECPROT */
