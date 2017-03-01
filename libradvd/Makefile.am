#AUTOMAKE_OPTIONS = 1.2 foreign

#DEFS=  -DPATH_RADVD_CONF=\"$(PATH_RADVD_CONF)\" \
#	-DPATH_RADVD_LOG=\"$(PATH_RADVD_LOG)\" -DLOG_FACILITY=$(LOG_FACILITY) \
#	-DPATH_RADVD_PID=\"$(PATH_RADVD_PID)\" \
#	-DVERSION=\"$(VERSION)\" -DINET6=1
#INCLUDES=

# set where the include files will be copied
newincludedir = $(prefix)/include/libopenikev2_impl

# set the include path found by configure
INCLUDES = -I$(srcdir) -I. $(all_includes)

# cflags and include paths
AM_CFLAGS =  -MMD -O2 -Wall -g -Wall -Wpointer-arith  -Wcast-qual -Wcast-align \
	-Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
	-I.

lib_LTLIBRARIES = libradvd.la

libradvd_la_SOURCES = 	./device-common.c \
			./device.c \
			./gram.y \
			./interface.c \
			./log.c \
			./privsep.c \
			./process.c \
			./recv.c \
			./scanner.l \
			./send.c \
			./socket.c \
			./timer.c \
			./util.c \
                        ./radvd.c \
			radvd_wrapper.cpp

AM_YFLAGS = -d

BUILT_SOURCES = device.c

AM_CXXFLAGS =  -I.



noinst_HEADERS = 	./defaults.h \
                        ./includes.h \
                        ./pathnames.h \
                        ./radvd.h \
                        ./radvd_wrapper.h

newinclude_HEADERS =    ./radvd_wrapper.h


AM_LIBS = -lfl
