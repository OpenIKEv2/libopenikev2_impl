# not a GNU package. You can remove this line, if
# have all needed files, that a GNU package needs
AUTOMAKE_OPTIONS = foreign 1.4
ACLOCAL_AMFLAGS = -I m4
LDFLAGS = -Wl -rpath
#SUBDIRS = src

if compile_EAP_client 
SUBDIRS = libeapclient src
else
if compile_EAP_server
SUBDIRS = libradvd libeapserver src
else
SUBDIRS = src
endif
endif

