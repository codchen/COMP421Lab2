#
#	Sample Makefile for COMP 421 YFS and user programs.
#
#	The YFS server built will be named "yfs".  *ALL* Makefiles
#	for this lab must have a "yfs" rule in them, and must
#	produce a YFS server executable named "yfs" -- we will run
#	your Makefile and will grade the resulting executable
#	named "yfs".  Likewise, *ALL* Makefiles must have a rule
#	named "iolib.a" to make your YFS library.
#

#
#	Define the list of everything to be made by this Makefile.
#	The list should include "yfs" (the name of your server) and
#	"iolib.a" (the name of your library), plus the list of user
#	test programs you also want to be made by this Makefile.
#	For example, the definition below specifies to make Yalnix
#	test user programs test1, test2, and test3, all of which will
#	be linked with your library to enable them to use your
#	server.  You should modify this list to the list of your
#	own test programs.
#
#	For each user test program, the Makefile will make the
#	program out of a single correspondingly named source file.
#	In addition to this single source file for each test
#	program, each program will also be linked with your library.
#	For example, the Makefile will make test1 out of test1.c,
#	if you have a file named test1.c in this directory.
#
ALL = yfs iolib.a test1 test2 test3

#
#	You must modify the YFS_OBJS and YFS_SRCS definitions below.
#	YFS_OBJS should be a list of the .o files that make up your
#	YFS server, and YFS_SRCS should  be a list of the corresponding
#	source files that make up your serever.
#
YFS_OBJS = example1.o example2.o
YFS_SRCS = example1.c example2.c

#
#	You must also modify the IOLIB_OBJS and IOLIB_SRCS definitions
#	below.  IOLIB_OBJS should be a list of the .o files that make up
#	your YFS library, and IOLIB_SRCS should  be a list of the
#	corresponding source files that make up your library.
#
IOLIB_OBJS = example3.o example4.o
IOLIB_SRCS = example3.c example4.c

#
#	You should not have to modify anything else in this Makefile
#	below here.  If you want to, however, you may modify things
#	such as the definition of CFLAGS, for example.
#

LANG = gcc

PUBLIC_DIR = /clear/courses/comp421/pub

CPPFLAGS = -I$(PUBLIC_DIR)/include
CFLAGS = -g -Wall

%: %.o
	$(LINK.o) -o $@ $^ iolib.a $(LOADLIBES) $(LDLIBS)

LINK.o = $(PUBLIC_DIR)/bin/link-user-$(LANG) $(LDFLAGS) $(TARGET_ARCH)

%: %.c
%: %.cc
%: %.cpp

all: $(ALL)

yfs: $(YFS_OBJS)
	$(LINK.o) -o $@ $^ $(PUBLIC_DIR)/lib/print-yfs.o $(LOADLIBES) $(LDLIBS)

iolib.a: $(IOLIB_OBJS)
	rm -f $@
	ar rv $@ $(IOLIB_OBJS)
	ranlib $@

mkyfs: mkyfs.c
	$(CC) $(CPPFLAGS) -o mkyfs mkyfs.c

clean:
	rm -f $(YFS_OBJS) $(IOLIB_OBJS) $(ALL)

depend:
	$(CC) $(CPPFLAGS) -M $(YFS_SRCS) $(IOLIB_SRCS) > .depend

#include .depend
