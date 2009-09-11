#
# Papillon - Solaris security module -  http://www.roqe.org/papillon
# Copyright (c) 2000-2003,2006 Konrad Rieck <kr@roqe.org>
# $Id: Makefile,v 1.66 2003/09/08 16:45:01 kr Exp $
#

# You should not change your system configuration directory unless you store
# configuration and boot scripts in another directory, which is very strange.
SYSCONFDIR=/etc

# This is the location where the papctl program will be installed to.  You
# may change this to any path as long as the Papillon module and the command
# stay on the same type of filesystem. Otherwise the papctl command cannot
# be hidden.
SBINDIR=/usr/sbin

# This is the place where the Papillon module will be installed to. There is 
# no need to change this unless you know what you are doing. On 64 bit 
# systems the module should be installed in the sparcv9 subdirectory.
KERNELDIR=/usr/kernel/misc

# See the documentation for how to configure these variables. (../doc)
# Features to compile into Papillon.
FEATURES=  -DRSTPROC -DPPROMISC -DMODHIDING -DSECSTDFD

# Protections to compile into Papillon.
PROTECTIONS= -DHARDPROT -DFIFOPROT -DSYMPROT -DCHROOTPROT -DSEXECPROT

# Set compilation environment. 
# Sun C Compiler setup
#CC=cc
#COPTS=
#CFLAGS32=-xarch=generic
#CFLAGS64=-D_64BIT -xarch=generic64

# GCC version 3.x setup
CC=gcc
COPTS=-DGCC -Wall
CFLAGS32=-m32 
CFLAGS64=-D_64BIT -m64 

# This needs to be set for both compilers
COPTS += -DSVR4 -DSOL2 

# Uncomment to enable debugging. Not recommended for non-developers, may blast
# your syslog.
#COPTS += -DDEBUG

LD=/usr/ccs/bin/ld
LDFLAGS=-o

# You should not change these values. Unless you prefer to use non-standard 
# commands.

RM=/usr/bin/rm
LN=/usr/bin/ln
INSTALL=/usr/ucb/install

INITSCRIPT=$(SYSCONFDIR)/init.d/papillon
RC0SCRIPT=$(SYSCONFDIR)/rc0.d/K50papillon
RC1SCRIPT=$(SYSCONFDIR)/rc1.d/K50papillon
RC2SCRIPT=$(SYSCONFDIR)/rc2.d/S50papillon
RCSSCRIPT=$(SYSCONFDIR)/rcS.d/K50papillon
CONTROLPATH=$(SBINDIR)/$(CONTROL)

MODSCRIPT=init.papillon

# Do both GNU make and Solaris make style exec
VERSION:sh=cat ../VERSION
VERSION+= $(shell cat ../VERSION)
BITS:sh=/usr/bin/isainfo -b
BITS+= $(shell /usr/bin/isainfo -b)

RELEASE:sh=uname -r | cut -f2 -d.
RELEASE+= $(shell uname -r | cut -f2 -d.)

PACKAGE=papillon-$(VERSION)
MODULE=papillon
CONTROL=papctl

# PREFIX is only used for fake installations and thus designed for package
# building. Please don't change it! Read the documentation in ../doc instead
PREFIX=

C_FILES=papillon.c stckbt.c rproc.c setuid.c hiding.c ppromisc.c refcnt.c \
        comm.c chroot.c utils.c
H_FILES=papillon.h papctl.h headers.h refcnt.h utils.h
M_FILES=Makefile
MODULE32=$(MODULE)
O_FILES32=papillon.o stckbt.o rproc.o setuid.o hiding.o ppromisc.o refcnt.o \
          comm.o chroot.o utils.o

KERNELDIR64=$(KERNELDIR)/sparcv9
MODULE64=sparcv9/$(MODULE)
O_FILES64=sparcv9/papillon.o sparcv9/stckbt.o sparcv9/rproc.o \
	  sparcv9/setuid.o sparcv9/hiding.o sparcv9/ppromisc.o \
	  sparcv9/refcnt.o sparcv9/comm.o sparcv9/chroot.o \
          sparcv9/utils.o

HIDDEN_FILES=-DINITSCRIPT=\"$(INITSCRIPT)\" -DRC0SCRIPT=\"$(RC0SCRIPT)\" \
             -DRC1SCRIPT=\"$(RC1SCRIPT)\" -DRC2SCRIPT=\"$(RC2SCRIPT)\" \
             -DRCSSCRIPT=\"$(RCSSCRIPT)\" -DCONTROLPATH=\"$(CONTROLPATH)\" \
             -DMODULE32PATH=\"$(KERNELDIR)/$(MODULE)\" \
	     -DMODULE64PATH=\"$(KERNELDIR64)/$(MODULE)\"

CFLAGS=$(COPTS) $(FEATURES) $(PROTECTIONS) $(HIDDEN_FILES) \
       -DVERSION=\"$(VERSION)\" -DSOLARIS$(RELEASE)

all:		sane-gcc sparcv9 $(MODULE32) $(MODULE$(BITS)) $(CONTROL)

sane-gcc:
		./gcc-sane $(CC)

sparcv9:	
		mkdir sparcv9

%.o:		%.c
		$(CC) $(CFLAGS) $(CFLAGS32) -c -o $@ $<

sparcv9/%.o:	%.c sparcv9
		$(CC) $(CFLAGS) $(CFLAGS64) -c -o $@ $<

$(MODULE32):	$(O_FILES32)
		$(LD) $(LDFLAGS) $@ -r $(O_FILES32)
		sync

$(MODULE64):	$(O_FILES64)
		$(LD) $(LDFLAGS) $@ -r $(O_FILES64)
		sync

$(CONTROL):	papctl.c papctl.h
		$(CC) $(CFLAGS) -o $@ papctl.c	

install:	$(MODULE32) $(MODULE$(BITS)) $(CONTROL) $(MODSCRIPT)
		if test ! -z "$(PREFIX)" ; then \
			mkdir -p $(PREFIX)$(SBINDIR) ; \
			mkdir -p $(PREFIX)$(KERNELDIR) ; \
                        mkdir -p $(PREFIX)$(SYSCONFDIR)/init.d ; \
			for i in 0 1 2 3 S ; do \
				mkdir -p $(PREFIX)$(SYSCONFDIR)/rc$$i.d ; \
				chgrp sys $(PREFIX)$(SYSCONFDIR)/rc$$i.d ; \
			done ; \
			chgrp bin $(PREFIX)$(SBINDIR) ; \
			chgrp sys $(PREFIX)$(KERNELDIR) ; \
                        chgrp sys $(PREFIX)$(SYSCONFDIR)/init.d ; \
			chgrp root $(PREFIX) ; \
			chgrp sys $(PREFIX)/usr $(PREFIX)$(SYSCONFDIR) ; \
			chgrp sys $(PREFIX)/usr/kernel ; \
		fi
		$(INSTALL) -g bin -d $(PREFIX)$(SBINDIR)
		$(INSTALL) -g bin -m 700 $(CONTROL) $(PREFIX)$(CONTROLPATH)
		$(INSTALL) -g sys -d $(PREFIX)$(KERNELDIR)
		$(INSTALL) -g sys -m 700 $(MODULE32) $(PREFIX)$(KERNELDIR)/$(MODULE)
		if test "$(BITS)" = 64 ; then \
			mkdir -p $(PREFIX)$(KERNELDIR64) ; \
			chgrp sys $(PREFIX)$(KERNELDIR64) ; \
			$(INSTALL) -g sys -m 700 $(MODULE64) \
			$(PREFIX)$(KERNELDIR64)/$(MODULE) ; \
		fi
		$(INSTALL) -g sys -m 700 $(MODSCRIPT) $(PREFIX)$(INITSCRIPT)
# Remove old papillon version
		$(RM) -f $(PREFIX)/etc/rc?.d/*papillon
# Install new papillon version
		$(LN) -f $(PREFIX)$(INITSCRIPT) $(PREFIX)$(RC0SCRIPT)
		$(LN) -f $(PREFIX)$(INITSCRIPT) $(PREFIX)$(RC1SCRIPT)
		$(LN) -f $(PREFIX)$(INITSCRIPT) $(PREFIX)$(RC2SCRIPT)
		$(LN) -f $(PREFIX)$(INITSCRIPT) $(PREFIX)$(RCSSCRIPT)

uninstall:	$(INITSCRIPT) $(RC2SCRIPT)
# Remove old papillon version 
		$(RM) -f $(PREFIX)/etc/rc?.d/*papillon
# Remove new papillon version
		$(RM) -f $(PREFIX)$(INITSCRIPT)
		$(RM) -f $(CONTROLPATH) $(PREFIX)$(KERNELDIR)/$(MODULE)
		if test "$(BITS)" = 64 ; then \
			$(RM) -f $(PREFIX)$(KERNELDIR64)/$(MODULE) ; \
		fi

clean:
		rm -f $(MODULE32) $(MODULE64) $(CONTROL)
		rm -f $(O_FILES32) $(O_FILES64)
		rm -f *~ core
		rm -rf sparcv9

INDENT=indent
beautify: 
		$(INDENT) -kr -l77 -lc77 $(C_FILES) $(H_FILES)
		rm -f *~		
