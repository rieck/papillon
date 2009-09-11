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
 * $Id: papctl.c,v 1.20 2003/04/11 09:28:17 kr Exp $
 *
 * This is the Papillon control tool. It uses the unused syscall defined
 * in papillon.h in order to communicate with the module (even if it is
 * hidden). Most features can be toggles by using this tool when the 
 * module is loaded. Recompilation is not needed. 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "headers.h"

extern char *optarg;
extern int optind, opterr, optopt;

static pap_config_t c;
static int request = GET;
static int force = 0;

/*
 * Print the current status of the loaded module.
 */
void print_config()
{
    printf("\nCurrent configuration of the Papillon v%s module:\n"
           "\n  - Features\n", VERSION);
#ifdef RSTPROC
    printf("    Restricted Proc:               %s\n", F(c.rstproc));
#endif
#ifdef PPROMISC
    printf("    Pseudo Promiscuous Flag:       %s\n", F(c.ppromisc));
#endif
#ifdef MODHIDING
    printf("    Module Hiding:                 %s\n", F(c.modhiding));
#endif
#ifdef SECSTDFD
    printf("    Secure STDIO File Descriptors: %s\n", F(c.secstdfd));
#endif

    printf("\n  - Protections\n");
#ifdef SYMPROT
    printf("    Symlink Protection:            %s\n", P(c.symprot));
#endif
#ifdef HARDPROT
    printf("    Hardlink Protection:           %s\n", P(c.hardprot));
#endif
#ifdef FIFOPROT
    printf("    Fifo Protection:               %s\n", P(c.fifoprot));
#endif
#ifdef CHROOTPROT
    printf("    Chroot Protection:             %s\n", P(c.chrootprot));
#endif
#ifdef SEXECPROT
    printf("    Setuid Exec Protection:        %s\n", P(c.sexecprot));
#endif
    printf("\n");
}

/*
 * Print an error message according to the submited err_msg value.
 */
void print_error(int err_msg)
{
    fprintf(stderr, "Error %d \n", err_msg);

    switch (err_msg) {
    case NO_AUTH:
        fprintf(stderr, "You are not authorized to use this program.\n");
        break;
    case NOT_LOADED:
        fprintf(stderr, "Papillon is not loaded.\n");
        break;
    case INVALID_VALUE:
        fprintf(stderr,
                "The assigned value is invalid for this type of variable\n");
        break;
    case INVALID_VARIABLE:
        fprintf(stderr, "There is no such variable.\n");
        break;
    case MEM_FAULT:
        fprintf(stderr, "Ex/Importing from user- to kernelspace failed.\n");
        break;
    case CONFIG_BLOCKED:
        fprintf(stderr, "Configuration blocked.\n");
        break;
    case EXCLUSIVE_OPTS:
        fprintf(stderr, "Get requests and set requests are exclusive.\n");
        break;
    case NO_FORCE:
        fprintf(stderr, "Get request cannot be forced.\n");
        break;
    default:
        fprintf(stderr, "Unknown error. *sigh*\n");
    }
    exit(EXIT_FAILURE);
}

void print_version(void)
{
    printf("Papillon v%s Control   "
           "Copyright (c) 2000-2003 Konrad Rieck <kr@roqe.org>\n", VERSION);
}

/*
 * Guess what this does. 
 */
void print_usage()
{
    print_version();
    printf
        ("Usage: papctl [-fhHV] -g | -s variable=value [variable=value ...]\n"
         "Options:\n"
         "  -g                      get current configuration of the loaded module.\n"
         "  -s variable=value ...   set current configuration of the loaded module.\n"
         "  -f                      force setting current configuration.\n"
         "  -h                      print this help.\n"
         "  -H                      print list of variables and possible values.\n"
         "  -V                      print version information.\n"
         "\nExample:\n" "  papctl -s m=off f=warn c=none\n");
    exit(EXIT_FAILURE);
}

/*
 * Guess what this does. 
 */
void print_variables()
{
    printf("\n"
           "  Variable    Feature / Protection            Values\n"
           " ----------------------------------------------------------------\n"
#ifdef RSTPROC
           "      r       Restricted Proc                 on, off\n"
#endif
#ifdef PPROMISC
           "      p       Pseudo Promiscuous Flag         on, off\n"
#endif
#ifdef MODHIDING
           "      m       Module Hiding                   on, off\n"
#endif
#ifdef SECSTDFD
           "      i       Secure STDIO File Descriptors   on, off\n"
#endif
#ifdef SYMPROT
           "      s       Symbolic Link Protection        none, warn, deny\n"
#endif
#ifdef HARDPROT
           "      h       Hard Link Protection            none, warn, deny\n"
#endif
#ifdef FIFOPROT
           "      f       FIFO Protection                 none, warn, deny\n"
#endif
#ifdef CHROOTPROT
           "      c       Chroot Protection               none, warn, deny\n"
#endif
#ifdef SEXECPROT
           "      x       Setuid Exec Protection          none, warn, deny\n"
#endif
           "\n");
    exit(EXIT_FAILURE);
}

/*
 * Set a protection according to the given string. 
 */
int protection(char *variable)
{
    char *value;
    value = variable + 2;

    if (!strcmp(value, "none"))
        return PAP_NONE;
    else if (!strcmp(value, "warn"))
        return PAP_WARN;
    else if (!strcmp(value, "deny"))
        return PAP_DENY;
    else {
        printf("Variable: %s\n", variable);
        print_error(INVALID_VALUE);
        return -1;
    }
}

/*
 * Set a feature according to the given string. 
 */
int feature(char *variable)
{
    char *value;
    value = variable + 2;

    if (!strcmp(value, "on"))
        return PAP_ON;
    else if (!strcmp(value, "off"))
        return PAP_OFF;
    else {
        fprintf(stderr, "Variable: %s\n", variable);
        print_error(INVALID_VALUE);
        return -1;
    }
}

/*
 * Parse the strings gathered from the commandline
 */
void parse_variable(char *variable)
{
    if (variable[1] != '=')
        print_usage();

    switch ((int) variable[0]) {
#ifdef RSTPROC
    case 'r':
        c.rstproc = feature(variable);
        break;
#endif
#ifdef PPROMISC
    case 'p':
        c.ppromisc = feature(variable);
        break;
#endif
#ifdef MODHIDING
    case 'm':
        c.modhiding = feature(variable);
        break;
#endif
#ifdef SECSTDFD
    case 'i':
        c.secstdfd = feature(variable);
        break;
#endif
#ifdef SYMPROT
    case 's':
        c.symprot = protection(variable);
        break;
#endif
#ifdef HARDPROT
    case 'h':
        c.hardprot = protection(variable);
        break;
#endif
#ifdef FIFOPROT
    case 'f':
        c.fifoprot = protection(variable);
        break;
#endif
#ifdef CHROOTPROT
    case 'c':
        c.chrootprot = protection(variable);
        break;
#endif
#ifdef SEXECPROT
    case 'x':
        c.sexecprot = protection(variable);
        break;
#endif
    default:
        fprintf(stderr, "Variable: %s\n", variable);
        print_error(INVALID_VARIABLE);
    }
}


void parse_options(int argc, char *argv[])
{
    int c, r = 0;

    /*
     * Parse commandline options. 
     */
    while ((c = getopt(argc, argv, "fVgshH")) != EOF)
        switch (c) {
        case 'H':
            print_variables();
            break;
        case 'f':
            force = 1;
            break;
        case 'V':
            print_version();
            exit(EXIT_FAILURE);
            break;
        case 'g':
            request = GET;
            r |= 1;
            break;
        case 's':
            request = SET;
            r |= 2;
            break;
        default:
            print_usage();
        }

    /*
     * Do sanity check. Enough parameters, values inside range, etc...
     */
    if (r == 3)
        print_error(EXCLUSIVE_OPTS);

    if (request == GET && force)
        print_error(NO_FORCE);

    if (request == GET && argc > 2)
        print_usage();
}

int main(int argc, char *argv[])
{
    int i, ret, cnt;
    char **variables = NULL;

    if (getuid())
        print_error(NO_AUTH);

    parse_options(argc, argv);
    signal(SIGSYS, print_error);

    switch (request) {
    case GET:
        if (syscall(SYS_papcomm, &c, GET, force))
            print_error(MEM_FAULT);
        print_config();
        break;

    case SET:
        cnt = argc - optind;
        if (cnt < 1)
            print_usage();

        if (syscall(SYS_papcomm, &c, GET, force))
            print_error(MEM_FAULT);

        variables = (char **) malloc(sizeof(char *) * cnt);
        for (i = 0; i < cnt; i++) {
            variables[i] = strdup(argv[i + optind]);
            parse_variable(variables[i]);
        }

        ret = syscall(SYS_papcomm, &c, SET, force);

        if (ret)
            print_error(ret);

        print_config();
        break;
    }

    return EXIT_SUCCESS;
}
