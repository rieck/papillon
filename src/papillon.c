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
 * $Id: papillon.c,v 1.60 2003/09/08 18:15:59 kr Exp $
 *
 * The main part of the Papillon module. 
 */

#define _KERNEL

#include "headers.h"

/*
 * Default configuration
 * First line represents features which can be ON or OFF,
 * the second line represents protections which can be 
 * DENY, WARN or NONE.
 */
pap_config_t config = {
    /* rstproc, ppromisc, modhiding, secstdfd */
    PAP_ON, PAP_ON, PAP_OFF, PAP_ON,
    /* fifoprot, symprot, hardprot, chrootprot, sexecprot */
    PAP_DENY, PAP_DENY, PAP_DENY, PAP_DENY, PAP_DENY
};

/*
 * Hidden files
 * The first entry will be replaced with the module's filename and 
 * path.
 */
pap_modfiles_t modfiles[] = {
    {"*", NULL, NULL},
    {INITSCRIPT, NULL, NULL},
    {RC0SCRIPT, NULL, NULL},
    {RC1SCRIPT, NULL, NULL},
    {RC2SCRIPT, NULL, NULL},
    {RCSSCRIPT, NULL, NULL},
    {CONTROLPATH, NULL, NULL},
    {MODULE32PATH, NULL, NULL},
    {MODULE64PATH, NULL, NULL},
    {NULL, NULL, NULL}
};

/*
 * White-list for the setuid execution protection. All files within the list
 * are executed without passing the the setuid check. I personally would
 * recommend to remove ALL of the below, but you are on your own now.
 */
char *pap_whitelist[] = {
    "dtsession",
    "dtprintinfo",
    "pmconfig",
    "mail",
    NULL
};

/*
 * That's me. My modctl struct, my vnode and my parent vnode. 
 */
struct modctl *this_module;

/*
 * This is the loadable module wrapper.
 */
extern struct mod_ops mod_miscops;

/*
 * Structure of the system-entry table.
 */
#ifdef _64BIT
extern struct sysent sysent32[];
#else
extern struct sysent sysent[];
#endif


/* 
 * Structure of the loaded modules
 */
extern struct modctl modules;

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
    &mod_miscops,
    "Papillon v" VERSION
};

struct modlinkage modlinkage = {
    MODREV_1,
    (void *) &modlmisc,
    NULL
};

/*
 * Syscall redirection vector table. 
 */
pap_syscall_t syscalls[] = {

#if defined(HARDPROT)
    {0, (int64_t(*)())pap_link, SE_NOUNLOAD | SE_LOADED, SYS_link, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(SYMPROT) || defined(FIFOPROT)
    {0, (int64_t(*)())pap_open, SE_NOUNLOAD | SE_LOADED, SYS_open, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_open64, SE_NOUNLOAD | SE_LOADED, SYS_open64, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(SECSTDFD)
    {0, (int64_t(*)())pap_execve, SE_NOUNLOAD | SE_LOADED, SYS_execve, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(CHROOTPROT)
    {0, (int64_t(*)())pap_chroot, SE_NOUNLOAD | SE_LOADED, SYS_chroot, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_mount, SE_NOUNLOAD | SE_LOADED, SYS_mount, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_mknod, SE_NOUNLOAD | SE_LOADED, SYS_mknod, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_xmknod, SE_NOUNLOAD | SE_LOADED, SYS_xmknod, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_modctl, SE_NOUNLOAD | SE_LOADED, SYS_modctl, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_chmod, SE_NOUNLOAD | SE_LOADED, SYS_chmod, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(PPROMISC)
    {0, (int64_t(*)())pap_putmsg, SE_NOUNLOAD | SE_LOADED, SYS_putmsg,
     DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif
    {0, (int64_t(*)())pap_comm, SE_NOUNLOAD | SE_LOADED, SYS_papcomm, 3, 0},
    {0, 0, 0, 0, 0, 0}
};

#ifdef _64BIT
/*
 * Syscall redirection vector table. 
 */
pap_syscall_t syscalls32[] = {

#if defined(HARDPROT)
    {0, (int64_t(*)())pap_link, SE_NOUNLOAD | SE_LOADED, SYS_link, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(SYMPROT) || defined(FIFOPROT)
    {0, (int64_t(*)())pap_open32, SE_NOUNLOAD | SE_LOADED, SYS_open, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_open64_32, SE_NOUNLOAD | SE_LOADED, SYS_open64, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(SECSTDFD)
    {0, (int64_t(*)())pap_execve, SE_NOUNLOAD | SE_LOADED, SYS_execve, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(CHROOTPROT)
    {0, (int64_t(*)())pap_chroot, SE_NOUNLOAD | SE_LOADED, SYS_chroot, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_mount, SE_NOUNLOAD | SE_LOADED, SYS_mount, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_mknod, SE_NOUNLOAD | SE_LOADED, SYS_mknod, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_xmknod32, SE_NOUNLOAD | SE_LOADED, SYS_xmknod, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_modctl, SE_NOUNLOAD | SE_LOADED, SYS_modctl, DFLT_ARG, 0},
    {0, (int64_t(*)())pap_chmod, SE_NOUNLOAD | SE_LOADED, SYS_chmod, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif

#if defined(PPROMISC)
    {0, (int64_t(*)())pap_putmsg32, SE_NOUNLOAD | SE_LOADED, SYS_putmsg, DFLT_ARG, 0},
#else
    {0, 0, SE_NOUNLOAD | SE_LOADED, SYS_UNUSED, DFLT_ARG, 0},
#endif
    {0, (int64_t(*)())pap_comm, SE_NOUNLOAD | SE_LOADED, SYS_papcomm, 3, 0},

    {0, 0, 0, 0, 0, 0}
};

#endif                          /* _64BIT */

/*
 * Pointer to the proc filesystem vnode operations. 
 */
static struct vnodeops *procfs_vnodeops;

/*
 * Backup pointer for the old praccess(), readdir() and lookup() functions.
 */
int (*old_praccess) ();
int (*old_vnreaddir) ();
int (*old_vnlookup) ();

/*
 * Mutexes, Locks
 */
kmutex_t promisc_lock;
kmutex_t readdir_lock;
kmutex_t refcnt_lock;
krwlock_t config_rwlock;

/*
 * Restore the old syscall vectors saved in the syscall struct.
 */
void restore_old_syscalls()
{
    int i;

    for (i = 0; syscalls[i].index; i++) {
        if (syscalls[i].index != SYS_UNUSED) {
            dcmn_err((CE_CONT, "Restoring syscall %d.\n",
                      syscalls[i].index));
#ifdef _64BIT
            sysent32[syscalls32[i].index].sy_callc = syscalls32[i].sc;
            sysent32[syscalls32[i].index].sy_flags = syscalls32[i].flags;

            if (syscalls32[i].narg != DFLT_ARG)
                sysent32[syscalls32[i].index].sy_narg = syscalls32[i].onarg;
#endif

            sysent[syscalls[i].index].sy_callc = syscalls[i].sc;
            sysent[syscalls[i].index].sy_flags = syscalls[i].flags;

            if (syscalls[i].narg != DFLT_ARG)
                sysent[syscalls[i].index].sy_narg = syscalls[i].onarg;
        }
    }

}

/*
 * Store the old syscall vectors in the syscall struct.
 */
void store_old_syscalls()
{
    int i;

    for (i = 0; syscalls[i].index; i++) {
        if (syscalls[i].index != SYS_UNUSED) {
            dcmn_err((CE_CONT, "Storing syscall %d.\n", syscalls[i].index));

#ifdef _64BIT
            syscalls32[i].sc =
                (int64_t(*)())sysent32[syscalls32[i].index].sy_callc;
            syscalls32[i].flags = sysent32[syscalls32[i].index].sy_flags;
            syscalls32[i].onarg = sysent32[syscalls32[i].index].sy_narg;
#endif

            syscalls[i].sc =
                (int64_t(*)())sysent[syscalls[i].index].sy_callc;
            syscalls[i].flags = sysent[syscalls[i].index].sy_flags;
            syscalls[i].onarg = sysent[syscalls[i].index].sy_narg;

        }
    }
}

/*
 * Set the new syscall vectors specified in the syscall struct.
 */
void set_new_syscalls()
{
    int i;

    for (i = 0; syscalls[i].index; i++) {
        if (syscalls[i].index != SYS_UNUSED) {
            dcmn_err((CE_CONT, "Setting new syscall %d.\n",
                      syscalls[i].index));
#ifdef _64BIT

            if (syscalls32[i].sc == syscalls[i].sc &&
                sysent32[syscalls32[i].index].sy_callc !=
                sysent[syscalls[i].index].sy_callc)
                cmn_err(CE_PANIC, "32 and 64 bit syscalls are not "
                        "identical by default, but Papillon claims they "
                        "are!");

            sysent32[syscalls32[i].index].sy_callc = syscalls32[i].nc;
            sysent32[syscalls32[i].index].sy_flags = syscalls32[i].flags;

            if (syscalls32[i].narg != DFLT_ARG)
                sysent32[syscalls32[i].index].sy_narg = syscalls32[i].narg;
#endif
            sysent[syscalls[i].index].sy_callc = syscalls[i].nc;
            sysent[syscalls[i].index].sy_flags = syscalls[i].flags;

            if (syscalls[i].narg != DFLT_ARG)
                sysent[syscalls[i].index].sy_narg = syscalls[i].narg;
        }
    }
}

#if defined(MODHIDING)
/*
 * Lookup vnodes for files to hide. 
 */
void lookup_vnodes()
{
    int i;

    if (!this_module)
        cmn_err(CE_PANIC, "Could not find module Papillon in the loaded "
                "module list. But I AM module Papillon!?");

    /*
     * This is myself. Keep this in mind.
     */
    modfiles[0].path = this_module->mod_filename;

    for (i = 0; modfiles[i].path; i++)
        lookupname(modfiles[i].path, UIO_SYSSPACE, NO_FOLLOW,
                   &modfiles[i].parent_vnode, &modfiles[i].vnode);

    if (!modfiles[0].vnode || !modfiles[0].parent_vnode)
        cmn_err(CE_PANIC, "Could not find the module's file. This is "
                "impossible! Papillon has to be loaded from a file.");
}

/*
 * Release vnodes.. 
 */
void release_vnodes()
{
    int i;

    for (i = 0; modfiles[i].path; i++) {
        if (modfiles[i].vnode)
            VN_RELE(modfiles[i].vnode);
        if (modfiles[i].parent_vnode)
            VN_RELE(modfiles[i].parent_vnode);
    }

}

#endif

/*
 * Init and load the module.
 */
int _init()
{
    int i, cri;
    struct modctl *this;

    procfs_vnodeops = (struct vnodeops *) modgetsymvalue("prvnodeops", 0);

    if (!procfs_vnodeops) {
        cmn_err(CE_WARN, "Symbol prvnodeops not found, procfs module not "
                " loaded.");
        return set_errno(ENOENT);
    }

    if ((i = mod_install(&modlinkage)) != 0) {
        cmn_err(CE_WARN, "Could not load module.");
        return i;
    } else {
        cmn_err(CE_CONT, "Papillon v%s successfully loaded.\n", VERSION);
    }

    /*
     * Initialize mutexes
     */
    dcmn_err((CE_CONT, "Initializing locks.\n"));
    mutex_init(&refcnt_lock, NULL, MUTEX_DEFAULT, NULL);
    mutex_init(&promisc_lock, NULL, MUTEX_DEFAULT, NULL);
    mutex_init(&readdir_lock, NULL, MUTEX_DEFAULT, NULL);
    rw_init(&config_rwlock, NULL, RW_DRIVER, NULL);

    /*
     * Module is loaded, find it in the modules list
     */
    this = &modules;
    while (this->mod_linkage != &modlinkage) {
        this = this->mod_next;
        ASSERT(this != &modules);
    }
    this_module = this;

    /*
     * Look up file vnode and parent vnode of the modules filename
     * and store them for later use in hiding.c
     */
#if defined(MODHIDING)
    lookup_vnodes();
#endif

    /*
     * Initialize reference counter
     */
    init_refcnt();

    dcmn_err((CE_CONT, "Entering critical area.\n"));
    cri = ddi_enter_critical();

    /*
     * Change vnode operation for the filename of the module and its
     * parent vnode.
     * XXX: disable readdir() interception on 64bit system. *sigh* 
     */
#if defined(MODHIDING)
    if (modfiles[0].vnode->v_op) {
        old_vnlookup = modfiles[0].vnode->v_op->vop_lookup;
        old_vnreaddir = modfiles[0].vnode->v_op->vop_readdir;
        modfiles[0].vnode->v_op->vop_lookup = pap_vnlookup;
        modfiles[0].vnode->v_op->vop_readdir = pap_vnreaddir;
    }

    hide_module();
#endif

    /*
     * Change proc vnode access function. 
     */
#if defined(RSTPROC)
    if (procfs_vnodeops) {
        old_praccess = procfs_vnodeops->vop_access;
        procfs_vnodeops->vop_access = pap_praccess;
    }
#endif

    /*
     * Redirect syscalls. 
     */
    store_old_syscalls();
    set_new_syscalls();

    ddi_exit_critical(cri);
    dcmn_err((CE_CONT, "Leaving critical area.\n"));

    return i;
}

int _info(struct modinfo *modinfop)
{
    return (mod_info(&modlinkage, modinfop));
}

/* 
 * "fini" and unload the module.
 */
int _fini()
{
    int i, cri;

    if (!check_refcnt())
        return set_errno(EBUSY);

    dcmn_err((CE_CONT, "Entering critical area.\n"));
    cri = ddi_enter_critical();

    /*
     * Restore old syscall vectors. 
     */
    restore_old_syscalls();

    /*
     * Restore old vnode operations.
     */
#if defined(MODHIDING)
    if (modfiles[0].vnode->v_op) {
        modfiles[0].vnode->v_op->vop_lookup = old_vnlookup;
        modfiles[0].vnode->v_op->vop_readdir = old_vnreaddir;
    }
#endif

#if defined(RSTPROC)
    if (procfs_vnodeops)
        procfs_vnodeops->vop_access = old_praccess;
#endif

    ddi_exit_critical(cri);
    dcmn_err((CE_CONT, "Leaving critical area.\n"));

#if defined(MODHIDING)
    release_vnodes();
#endif

    /*
     * Destroy mutexes.
     */
    dcmn_err((CE_CONT, "Destroying locks.\n"));
    rw_destroy(&config_rwlock);
    mutex_destroy(&readdir_lock);
    mutex_destroy(&promisc_lock);
    mutex_destroy(&refcnt_lock);

    if ((i = mod_remove(&modlinkage)) != 0)
        cmn_err(CE_WARN, "Could not unload module.");
    else
        cmn_err(CE_CONT, "Papillon v%s successfully unloaded.\n", VERSION);

    return i;
}
