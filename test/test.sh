#!/bin/sh
# Papillon - Solaris security module -  http://www.roqe.org/papillon
# Copyright (c) 2000-2002 Konrad Rieck <kr@roqe.org>        
# $Id: test.sh,v 1.13 2003/03/20 18:54:07 kr Exp $
#

if [ -z "$2" ] ; then
   FAKEROOT=/tmp/fake
else
   FAKEROOT=$2
fi

if [ "`/usr/xpg4/bin/id -u`" != "0" ] ; then
   echo "You can only run this test as super-user. Sorry."
   exit 0
fi

if [ ! -x /usr/bin/isainfo ] ; then
   echo "The program isainfo is not installed at the usual place"
   exit 0
fi

if [ ! -f ./fifoattack -o ! -f ./stdioattack -o ! -f ./stdiovictim ] ; then
   echo "Compile the files in this directory first. Type \"make\""
   exit 0
fi

mkdir -p $FAKEROOT
chmod 1777 $FAKEROOT
chown sys:sys $FAKEROOT

BITS=`/usr/bin/isainfo -b`

# this function checks if we are able to view the init process 
restricted_proc() { 
   initpid=`su nobody -c "ps -u 0 | grep init"`
   if [ "x$initpid" != "x" ] ; then 
      echo "No"
   else 
      echo "Yes" 
   fi
}

# this function sets a hardlink from $1 to $2.
hardlink() { 
   if su nobody -c "ln $1 $2 2> /dev/null"; then 
      echo "No"
   else 
      echo "Yes"
   fi
}

# this function opens the symlink $1.
symlink() { 
   if cat $1 2> /dev/null ; then 
      echo "No"
   else 
      echo "Yes"
   fi
}


if [ "x$1" != "x-y" ] ; then
   echo "\nThis script will check if Papillon is running and all enabled"
   echo "protections are working.\n"
   echo "WARNING: In order to check for possible attacks, it is necessary to"
   echo "         create a vulnerable environment in $FAKEROOT. Before"
   echo "         proceeding, check that your machine is running in single"
   echo "         user mode or no local users have access to the vulnerable"
   echo "         environment.\n"
   echo "Continue (y/n): \c"
   read fake
   if [ "x$fake" != "xy" ] ; then
      exit 0
   else
      echo
   fi
fi

echo "* General environment"

echo "- Checking for a restricted proc...           \c"
restricted_proc

echo "- Checking for hardlink attack protection...  \c"
touch $FAKEROOT/victim
hardlink $FAKEROOT/victim $FAKEROOT/attack
rm -rf $FAKEROOT/victim $FAKEROOT/attack

echo "- Checking for symlink attack protection...   \c"
touch $FAKEROOT/victim
su nobody -c "ln -s $FAKEROOT/victim $FAKEROOT/attack"
symlink $FAKEROOT/attack
rm -rf $FAKEROOT/victim $FAKEROOT/attack

echo "\n* 32 bit environment"

echo "- Checking for fifo attack protection...      \c"
mkfifo $FAKEROOT/victim
chmod 777 $FAKEROOT/victim
su nobody -c "./fifoattack $FAKEROOT/victim"
rm -rf $FAKEROOT/victim

echo "- Checking for STDIO attack protection...     \c"
touch $FAKEROOT/victim
cp stdiovictim $FAKEROOT/suidexec
chmod 4755 $FAKEROOT/suidexec
su nobody -c "./stdioattack \"$FAKEROOT/suidexec $FAKEROOT/victim\""
if [ "x`cat $FAKEROOT/victim`" != "x" ] ; then
   echo "No"
else 
   echo "Yes"
fi

echo "- Checking for chroot protection...           \c"
cp /usr/bin/true $FAKEROOT
./chroottest /dev_null /true $FAKEROOT
rm -f $FAKEROOT/dev_null $FAKEROOT/true


if [ "x$BITS"="x64" ] ; then 
 
   echo "\n* 64 bit environment"
   echo "- Checking for STDIO attack protection...     \c"
   touch $FAKEROOT/victim
   cp sparcv9/stdiovictim $FAKEROOT/suidexec
   chmod 4755 $FAKEROOT/suidexec
   su nobody -c "./sparcv9/stdioattack \
                \"$FAKEROOT/suidexec $FAKEROOT/victim\""
   if [ "x`cat $FAKEROOT/victim`" != "x" ] ; then
      echo "No"
   else 
      echo "Yes"
   fi
   rm -rf $FAKEROOT/victim

   echo "- Checking for fifo attack protection...      \c"
   mkfifo $FAKEROOT/victim
   chmod 777 $FAKEROOT/victim
   su nobody -c "./sparcv9/fifoattack $FAKEROOT/victim"
   rm -rf $FAKEROOT/victim

   echo "- Checking for chroot protection...           \c"
   cp /usr/bin/true $FAKEROOT
   ./sparcv9/chroottest /dev_null /true $FAKEROOT
   rm -f $FAKEROOT/dev_null $FAKEROOT/true
fi

rm -rf $FAKEROOT/suidexec $FAKEROOT/victim
rm -rf $FAKEROOT

echo "\nDone."
