# set where the include files will be copied
newincludedir = $(prefix)/include/libopenikev2_impl

# set the include path found by configure
INCLUDES = -I$(top_srcdir)/utils \
    -I$(top_srcdir)/crypto \
    -I$(top_srcdir)/eap_peer \
    -I$(top_srcdir)/eapol_supp \
    $(all_includes)

# cflags and include paths
AM_CFLAGS =  -MMD -O2 -Wall -g \
    -I. -I./common -I./utils -I./crypto -I./rsn_supp \
    -DEAP_TLS -DEAP_FRM \
    -I$(DIR_KRB5)/src/include -L$(DIR_KRB5)/src/lib \
    -DIEEE8021X_EAPOL


lib_LTLIBRARIES = libeapclient.la

libeapclient_la_SOURCES = ./utils/common.c \
    ./utils/wpa_debug.c \
    ./utils/wpabuf.c \
    ./crypto/md5.c \
    ./crypto/crypto_openssl.c \
    ./utils/eloop.c \
    ./crypto/tls_openssl.c \
    ./crypto/aes_wrap.c \
    ./crypto/rc4.c \
    ./crypto/md4.c \
    ./crypto/sha1.c \
    ./crypto/des.c \
    ./common/wpa_ctrl.c \
    ./utils/os_unix.c \
    ./eap_peer/eap_frm_common.c \
    ./eap_peer/eap_tls_common.c \
    ./eap_peer/eap_tls.c \
    ./eap_common/chap.c \
    ./utils/prf_plus.c \
    ./eap_common/eap_common.c \
    ./eapol_supp/eapol_supp_sm.c \
    ./eap_peer/eap.c \
    ./eap_peer/eap_methods.c \
    ./eap_peer/eap_frm_kerb.c \
    eapsm.cpp



AM_CXXFLAGS =  -DEAP_TLS -DEAP_FRM \
    -I$(DIR_KRB5)/src/include \
    -L$(DIR_KRB5)/src/lib \
    -DIEEE8021X_EAPOL

newinclude_HEADERS = eapsm.h

noinst_HEADERS = ./utils/common.h \
    ./utils/prf_plus.h \
    ./utils/includes.h \
    ./utils/os.h \
    ./utils/pcsc_funcs.h \
    ./utils/ip_addr.h \
    ./utils/wpa_debug.h \
    ./utils/build_config.h \
    ./utils/uuid.h \
    ./utils/state_machine.h \
    ./utils/eloop.h \
    ./utils/base64.h \
    ./utils/wpabuf.h \
    ./crypto/tls.h \
    ./crypto/sha256.h \
    ./crypto/aes.h \
    ./crypto/sha1.h \
    ./crypto/crypto.h \
    ./crypto/dh_groups.h \
    ./crypto/ms_funcs.h \
    ./crypto/aes_wrap.h \
    ./crypto/rc4.h \
    ./crypto/md5.h \
    ./eap_peer/mschapv2.h \
    ./eap_peer/eap_tls_common.h \
    ./eap_peer/eap_frm_common.h \
    ./eap_peer/eap_config.h \
    ./eap_peer/config_ssid.h \
    ./eap_peer/eap.h \
    ./eap_peer/eap_i.h \
    ./eap_peer/eap_methods.h \
    ./eap_peer/tncc.h \
    ./eapol_supp/eapol_supp_sm.h \
    ./common/defs.h \
    ./eap_common/eap_common.h \
    ./eap_common/chap.h \
    ./eap_common/eap_defs.h \
    ./common/eapol_common.h \
    ./common/wpa_ctrl.h \
    ./common/wpa_common.h \
    ./common/version.h \
    ./common/privsep_commands.h \
    ./common/wireless_copy.h

AM_LIBS = -lkrb5

