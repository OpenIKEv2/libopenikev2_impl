AC_INIT(configure.ac)

AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(libopenikev2_impl, 0.7)
AC_DEFINE(LIBOPENIKE_IMPL_VERSION, "0.7", [Version])

AC_DEFINE([_GNU_SOURCE], [], [whether compiling on Linux, glibc>=2.8 doesn't expose in6_pktinfo otherwise..])

AC_CONFIG_MACRO_DIR([m4])

AC_LANG_CPLUSPLUS
AC_PROG_CXX
AM_PROG_LIBTOOL



AC_PROG_INSTALL
AC_PATH_PROG(RM, rm, NOTFOUND)
if test "x$RM" = xNOTFOUND; then
	AC_MSG_ERROR(can't find rm in your path - check PATH)
fi
AC_PATH_PROG(SED, sed, NOTFOUND)
if test "x$SED" = xNOTFOUND; then
	AC_MSG_ERROR(can't find sed in your path - check PATH)
fi
dnl Not needed
AC_PATH_PROG(LN, ln)
AC_PROG_YACC
AM_PROG_LEX
AC_PATH_PROG(TAR, tar)
AC_PATH_PROG(GZIP, gzip)


# Check IPv6 support
AC_MSG_CHECKING([Checking for IPv6 support])
AC_TRY_LINK(
    [ 
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <netinet/in.h>], [struct sockaddr_in6 s; struct in6_addr t=in6addr_any; int i=AF_INET6; s; t.s6_addr[0] = 0;
    ],
    [
        AC_DEFINE(HAVE_IPv6, 1, [IPv6 support])
        AC_MSG_RESULT(yes)
    ],
    [
        AC_MSG_RESULT(no)
    ]
)

# Checks whether --enable-eap was given.
AC_ARG_ENABLE(eap, 
 [  --enable-eap[=client or server]      enables the client or server-side EAP methods implemetation],
 [ if   test "x$enableval" = "xclient" ; then
      eap=client; AC_DEFINE([EAP_CLIENT_ENABLED], [], [Client-side EAP methods implementation])
   elif test "x$enableval" = "xserver" ; then
      eap=server; AC_DEFINE([EAP_SERVER_ENABLED], [], [Server-side EAP methods implementation])
   else
	echo
	echo "Error!"
	echo "Use client or server in --enable-eap"
        exit -1
   fi
 ])
AM_CONDITIONAL(compile_EAP_client, [test "$enable_eap" = "client"])
AM_CONDITIONAL(compile_EAP_server, [test "$enable_eap" = "server"])



######################### CHECK FOR NEEDED KERNEL HEADERS ############################################
##### Check for PFKEYv2
AC_CHECK_HEADERS(
    linux/pfkeyv2.h,
    [],
    [
        AC_MSG_RESULT(** ERROR ** Cannot find pfkeyv2.h)
        exit
    ],
    []
)

# Check for XFRM
AC_CHECK_HEADERS(
    linux/xfrm.h,
    [],
    [
        AC_MSG_RESULT(** ERROR ** Cannot find xfrm.h)
        exit
    ],
    []
)

    # struct sadb_x_policy.sadb_x_policy_priority
    AC_CHECK_MEMBER(    struct xfrm_userpolicy_info.priority, 
    	               [AC_DEFINE(HAVE_XFRM_POLICY_PRIORITY, [],[Are XFRM policy priorities supported?])], 
    	               [
                        AC_MSG_RESULT(      ** libopenikev2_impl will be builded without XFRM policy priory support **.)
                       ],
    	               [#include "$kerneldir/linux/xfrm.h"]
    	               )
    
    AC_CHECK_MEMBER(    struct sadb_x_policy.sadb_x_policy_priority, 
                       [AC_DEFINE(HAVE_PFKEY_POLICY_PRIORITY, [],[Are XFRM policy priorities supported?])], 
                       [
                        AC_MSG_RESULT(      ** libopenikev2_impl will be builded without PFKEY policy priory support **.)
                       ],
                       [#include "$kerneldir/linux/pfkeyv2.h"]
                       )


######################### CHECK FOR LIBRARIES ############################################
#####Check if libopenikev2 is installed
    AC_CHECK_LIB(
        openikev2, 
        main,
        [], 
        [
            AC_MSG_RESULT(** ERROR ** You must install libopenikev2 in order to compile libopenikev2_impl.)
            exit
        ], 
        []
    )

AC_CHECK_HEADERS(
    "libopenikev2/ikesacontroller.h", 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libopenikev2 in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)


#####Check if libpthread is installed
AC_CHECK_LIB(
    pthread, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libpthread in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)

#####Check if openssl is installed
AC_CHECK_LIB(
    crypto, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libcrypto from openssl project in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)
AC_CHECK_HEADERS(
    openssl/engine.h, 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libcrypto from openssl project in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)

AC_CHECK_LIB(
    ssl, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libssl from openssl project in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)
AC_CHECK_HEADERS(
    openssl/ssl.h, 
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libssl from openssl project in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)

#####Check if openssl supports ECDH
AC_CHECK_HEADERS(openssl/ecdh.h)

AC_CHECK_LIB(
    ssl, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install libssl from openssl project in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)


if test "$enable_eap" = "client"; then

#####Check if krb5 is installed
AC_CHECK_LIB(
    krb5, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install krb5 in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)
AC_CHECK_HEADERS(
    krb5.h,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install krb5 in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)

fi



if test "$enable_eap" = "server"; then

#####Check if krb5 is installed
AC_CHECK_LIB(
    krb5, 
    main,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install krb5 in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)
AC_CHECK_HEADERS(
    krb5.h,
    [], 
    [
        AC_MSG_RESULT(** ERROR ** You must install krb5 in order to compile libopenikev2_impl.)
        exit
    ], 
    []
)

fi


dnl Checks for libraries.

AC_CHECK_LIB(c, inet_ntop,,
 AC_CHECK_LIB(inet6, inet_ntop,
  LIBS="$LIBS -linet6"
  ,
    AC_MSG_ERROR(can't continue without libinet6.a library - check your LDFLAGS)
 )
)
# prevent caching
unset ac_cv_lib_inet6_inet_ntop

dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(sys/time.h)
AC_HEADER_TIME

AC_CHECK_HEADER(netinet/ip6.h, hdrfound=yes, hdrfound=no)
if test "$hdrfound" = no
then
 # deprecated
 AC_CHECK_HEADER(netinet/ipv6.h, hdrfound=yes)
fi
if test "$hdrfound" = no
then
   AC_MSG_RESULT(no)
fi
unset hdrfound

AC_CHECK_HEADERS(ifaddrs.h sys/sockio.h getopt.h inttypes.h)
AC_CHECK_HEADERS(net/if_dl.h net/if_types.h net/if_arp.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(machine/param.h)
AC_CHECK_HEADERS(machine/limits.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

AC_MSG_CHECKING(whether struct sockaddr_in6 has sin6_scope_id)
AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>], [static struct sockaddr_in6 ac_sin6; int ac_size = 
sizeof (ac_sin6.sin6_scope_id);], [AC_MSG_RESULT(yes); AC_DEFINE([HAVE_SIN6_SCOPE_ID],
1, [whether struct sockaddr_in6 has sin6_scope_id])],
AC_MSG_RESULT(no))

AC_MSG_CHECKING(whether struct in6_addr has u6_addrXX and defines s6_addrXX)
AC_TRY_COMPILE([#include <netinet/in.h>], [static struct in6_addr in6_u; 
int u =  in6_u.s6_addr16;], [AC_MSG_RESULT(yes); AC_DEFINE([HAVE_IN6_ADDR_S6_ADDR],
1, [whether struct in6_addr has u6_addrXX and defines s6_addrXX])],
AC_MSG_RESULT(no))

dnl Checks for library functions.
AC_CHECK_FUNCS(getopt_long)

AC_SUBST(VERSION)
AC_SUBST(PATH_RADVD_CONF)
AC_SUBST(PATH_RADVD_PID)
AC_SUBST(PATH_RADVD_LOG)
AC_SUBST(LOG_FACILITY)

AC_OUTPUT(Makefile libradvd/Makefile libeapclient/Makefile libeapserver/Makefile src/Makefile)


