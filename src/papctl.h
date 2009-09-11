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
 * $Id: papctl.h,v 1.10 2003/04/11 09:28:17 kr Exp $
 */

#ifndef _PAPCTL_H
#define _PAPCTL_H

/*
 * Avoid working with too complex macros. Erhmm.
 */
#define F(X) (X==PAP_ON)?"on":"off"
#define P(X) (X==PAP_NONE)?"none":(X==PAP_WARN)?"warn":"deny"

/*
 * Possible error values.
 */
enum err_msg { NO_AUTH, NOT_LOADED = SIGSYS, INVALID_VALUE,
    INVALID_VARIABLE, MEM_FAULT, CONFIG_BLOCKED, EXCLUSIVE_OPTS,
    NO_FORCE
};


#endif                          /* _PAPCTL_H */
