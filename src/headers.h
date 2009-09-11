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
 * $Id: headers.h,v 1.13 2003/04/25 14:24:19 kr Exp $
 *
 * This file includes all needed system headers. If this is not 
 * elegant, let me know. 
 */

#ifndef _HEADERS_H
#define _HEADERS_H

#if defined(_64BIT) && defined(_KERNEL)
#define _SYSCALL32
#endif

#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/rwlock.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/pathname.h>
#include <sys/dirent.h>
#include <sys/fs/ufs_inode.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#if defined(_KERNEL)
#include <sys/proc.h>
#include <sys/procfs.h>
#include <sys/proc/prdata.h>
#endif
#include <sys/dlpi.h>
#include <sys/cred.h>
#if !defined(SOLARIS8)
#include <sys/cred_impl.h>
#endif

/* 
 * GCC 2.x and 3.0 may need this. But I told you to use newer GCC versions!
 */
#ifdef GCC
#include <stdarg.h>
#endif

#include "utils.h"
#include "refcnt.h"
#include "papillon.h"
#include "papctl.h"

#endif                          /* _HEADERS_H */
