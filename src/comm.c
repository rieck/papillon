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
 * $Id: comm.c,v 1.15 2003/04/25 14:24:19 kr Exp $
 *
 * This file holds the Papillon communication syscall. The syscall is
 * protected by a read/write-lock. I know that's really strange for stuff
 * inside the kernel, but I guess the configuration is read a 1.000.000
 * times more often than written.
 */

#define _KERNEL

#include "headers.h"

/*
 * External configuration and rwlock. 
 */
extern pap_config_t config;
extern krwlock_t config_rwlock;

/*
 * This is the communication syscall, it only supports two requests: GET
 * and SET. 
 */
int64_t pap_comm(pap_config_t * c, enum request r, int force)
{
    int64_t ret = 0;

    inc_refcnt();

    /*
     * If pap_comm is called from an unprivileged user or from inside a 
     * chroot environment, deny access.
     */
    if (CRED()->cr_ruid != SUSER_UID || u.u_rdir) {
        dec_refcnt();
        return set_errno(EPERM);
    }

    switch (r) {

    case SET:
        log_msg(CE_CONT, "SET request for Papillon configuration");

        /*
         * This is the only case where we lock the config. Therefore
         * we are usign a rwlock and not a mutex. May someone from 
         * the Solaris kernel team comment this? ;)
         */
        if (!force && !rw_tryenter(&config_rwlock, RW_WRITER)) {
            ret = CONFIG_BLOCKED;
            break;
        }

        if (copyin(c, &config, sizeof(config)) != 0)
            ret = MEM_FAULT;

        if (!force)
            rw_exit(&config_rwlock);


#if defined(MODHIDING)
        /*
         * hides module if requested in config
         */
        hide_module();
#endif
        break;

    case GET:
        /*
         * This is annoying.
         * log_msg(CE_CONT, "GET request for Papillon configuration");
         */

        rw_enter(&config_rwlock, RW_READER);

        if (copyout(&config, c, sizeof(config)))
            ret = MEM_FAULT;

        rw_exit(&config_rwlock);
        break;

    default:
        ret = set_errno(EINVAL);
    }

    dec_refcnt();
    return ret;
}
