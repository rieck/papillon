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
 * $Id: utils.c,v 1.7 2003/03/26 18:18:51 kr Exp $
 * 
 * Utility functions. Plain and boring.
 */

#define _KERNEL

#include "headers.h"

/*
 * Classical memset implementation used for compilers that play dirty macro
 * tricks with me and my headers and rely on memset(). :(
 */
void *memset(void *sp1, int c, size_t n)
{
    if (n != 0) {
        unsigned char *sp = sp1;
        do {
            *sp++ = (unsigned char) c;
        } while (--n != 0);
    }
    return (sp1);
}



void log_msg(int level, const char *fmt, ...)
{
    va_list ap;
    char buf[256];
    struct psinfo psinfo;

    va_start(ap, fmt);
    vsnprintf(buf, 255, fmt, ap);
    va_end(ap);

    mutex_enter(&curproc->p_lock);
    prgetpsinfo(curproc, &psinfo);
    mutex_exit(&curproc->p_lock);

    cmn_err(level, "%s (cmd: %s, pid: %d, uid: %d, gid: %d).%s", buf,
            psinfo.pr_psargs, ddi_get_pid(),
            ddi_get_cred()->cr_ruid, ddi_get_cred()->cr_rgid,
            (level == CE_CONT) ? "\n" : "");
}
