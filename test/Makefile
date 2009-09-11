#
# Papillon - Solaris security module -  http://www.roqe.org/papillon 
# Copyright (c) 2000-2003 Konrad Rieck <kr@roqe.org>  
# $Id: Makefile,v 1.11 2003/03/20 18:54:07 kr Exp $ 
#

# Compiler settings
CC=gcc 

# - For GCC 3.x set FLAGS64=-m64
# - For Sun CC set FLAGS64=-generic64
FLAGS64=-m64 

TARGETS=stdioattack stdiovictim fifoattack chroottest 

all:	sparcv9 $(TARGETS) 

sparcv9:
	mkdir sparcv9

stdioattack:	stdioattack.c
	$(CC) -o $@ stdioattack.c
	$(CC) $(FLAGS64) -o sparcv9/$@ stdioattack.c

stdiovictim:	stdiovictim.c
	$(CC) -o $@ stdiovictim.c
	$(CC) $(FLAGS64) -o sparcv9/$@ stdiovictim.c

fifoattack:	fifoattack.c
	$(CC) -o $@ fifoattack.c
	$(CC) $(FLAGS64) -o sparcv9/$@ fifoattack.c

chroottest:	chroottest.c
	$(CC) -o $@ chroottest.c
	$(CC) $(FLAGS64) -o sparcv9/$@ chroottest.c

clean:
	rm -f $(TARGETS) 
	rm -f *~ *.core  core
	rm -rf sparcv9
