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
 * $Id: papillon.h,v 1.38 2003/09/08 17:00:31 kr Exp $
 *
 * General definitions and structs for the Papillon module.
 */

#ifndef _PAPILLON_H
#define _PAPILLON_H

#define SUSER_UID       0
#define SUSER_GID       0

/*
 * Very rarely are pathnames > 64 bytes, hence allocate space on
 * the stack for that rather then kmem_alloc it.
 */
#define MAX_PATH_LEN    64

#define SYS_papcomm     180

#define SYS_UNUSED      -1
#define DFLT_ARG        -1

#ifdef DEBUG
#define dcmn_err(X) cmn_err X
#else
#define dcmn_err(X)
#endif

/*
 * Configuration structure
 */
enum feature { PAP_OFF = 0, PAP_ON };
enum protection { PAP_NONE = 0, PAP_WARN, PAP_DENY };

typedef struct pap_config {
    enum feature rstproc;
    enum feature ppromisc;
    enum feature modhiding;
    enum feature secstdfd;

    enum protection fifoprot;
    enum protection symprot;
    enum protection hardprot;
    enum protection chrootprot;
    enum protection sexecprot;
} pap_config_t;

typedef struct pap_modfiles {
    char *path;
    vnode_t *vnode;
    vnode_t *parent_vnode;
} pap_modfiles_t;

/*
 * Structure for the syscall redirection
 */
typedef struct pap_syscall {

    int64_t(*sc) ();            /* Original syscall address */
    int64_t(*nc) ();            /* New syscall address */

#ifdef _LP64
    unsigned short flags;       /* Flags */
#else
    unsigned char flags;
#endif
    int index;                  /* Syscall index */
    char narg;                  /* Number of arguments, -1 = keep default */
    char onarg;                 /* Original value */
} pap_syscall_t;

/*
 * Possible request values. 
 */
enum request { GET, SET };

/*
 * Intercepted syscalls
 */
enum syscall_id { LINK = 0, OPEN, OPEN64, EXECVE, CHROOT, MOUNT, MKNOD,
    XMKNOD, MODCTL, CHMOD, PUTMSG, PAPCOMM
};
/* 
 * Papillon syscall definitions
 */
int64_t pap_open64(const char *path, int oflag, mode_t mode);
int64_t pap_open(const char *path, int oflag, mode_t mode);
int64_t pap_link(const char *existing, const char *new);
int64_t pap_execve(const char *path, char *const argv[], char *const envp[]);
int64_t pap_putmsg(int fildes, struct strbuf *ctlptr,
                   struct strbuf *dataptr, int *flagsp);
int64_t pap_comm(pap_config_t * c, enum request r, int force);
int64_t pap_chroot(const char *path);
int64_t pap_mount(const char *spec, const char *dir, int mflag, char
                  *fstype, char *dataptr, int datalen, char *optptr, int
                  optlen);
int64_t pap_mknod(const char *path, mode_t mode, dev_t dev);
int64_t pap_xmknod(const char *path, mode_t mode, dev_t dev);
int64_t pap_modctl(int cmd, uintptr_t a1, uintptr_t a2,
                   uintptr_t a3, uintptr_t a4, uintptr_t a5);
int64_t pap_chmod(const char *path, mode_t mode);

#if defined(_64BIT) && defined(_KERNEL)
int64_t pap_open32(const char *path, int oflag, mode_t mode);
int64_t pap_open64_32(const char *path, int oflag, mode_t mode);
int64_t pap_putmsg32(int fildes, struct strbuf32 *ctlptr,
                     struct strbuf32 *dataptr, int *flagsp);
int64_t pap_xmknod32(const char *path, mode_t mode, dev_t dev);
#endif

int pap_praccess(struct vnode *vp, int mode, int flags, struct cred *cr);
int pap_vnlookup(struct vnode *dvp, char *nm, struct vnode **vpp,
                 struct pathname *pnp, int flags, struct vnode *rdir,
                 struct cred *);
int pap_vnreaddir(struct vnode *vp, struct uio *uiop, struct cred *cr,
                  int *eofp);

/*
 * Hiding function from hiding.c
 */
void hide_module(void);

#endif                          /* _PAPILLON_H */
