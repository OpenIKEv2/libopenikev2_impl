newincludedir = $(prefix)/include/libopenikev2_impl

# set the include path found by configure

INCLUDES = $(all_includes)

if compile_EAP_client
INCLUDES +=  -I$(top_srcdir)/libeapclient -I$(top_srcdir)/libeapclient/utils \
	-I$(top_srcdir)/libeapclient/crypto -I$(top_srcdir)/libeapclient/eap_peer \
	-I$(top_srcdir)/libeapclient/eapol_supp -I$(top_srcdir)/libradvd $(all_includes)
endif

if compile_EAP_server
INCLUDES +=  -I$(top_srcdir)/libeapserver -I$(top_srcdir)/libeapserver/utils \
	-I$(top_srcdir)/libeapserver/crypto -I$(top_srcdir)/libeapserver/eap_server \
	-I$(top_srcdir)/libeapserver/eapol_supp -I$(top_srcdir)/libradvd $(all_includes)
endif





# the library search path.
lib_LTLIBRARIES = libopenikev2_impl.la
libopenikev2_impl_la_SOURCES = addressconfiguration.cpp \
	alarmcontrollerimplopenike.cpp authenticatoropenike.cpp authgenerator.cpp authgeneratorbtns.cpp \
	authgeneratorcert.cpp authgeneratorpsk.cpp authverifier.cpp authverifierbtns.cpp \
	authverifiercert.cpp authverifierpsk.cpp  certificatex509.cpp \
	certificatex509hashurl.cpp cipheropenssl.cpp conditionposix.cpp cryptocontrollerimplopenike.cpp \
	dhcpclient.cpp diffiehellmanellipticcurve.cpp diffiehellmanopenssl.cpp eapclient.cpp \
	eapmethod.cpp eapserver.cpp  \
	facade.cpp idtemplateany.cpp idtemplatedomainname.cpp \
	idtemplateexactmatch.cpp ikesacontrollerimplopenike.cpp ikesaexecuter.cpp \
	ikesareauthenticator.cpp  interfacelist.cpp ipaddressopenike.cpp \
	ipseccontrollerimplopenike.cpp ipseccontrollerimplpfkeyv2.cpp ipseccontrollerimplxfrm.cpp \
	keyringopenssl.cpp libnetlink.cpp logimplcolortext.cpp logimplhtml.cpp logimplopenike.cpp \
	logimpltext.cpp mutexposix.cpp networkcontrollerimplopenike.cpp \
	notifycontroller_auth_lifetime.cpp notifycontroller_mobike_supported.cpp \
	notifycontroller_update_sa_addresses.cpp policy.cpp pseudorandomfunctionopenssl.cpp \
	radiusmessage.cpp randomopenssl.cpp roadwarriorpolicies.cpp sarequest.cpp \
	semaphoreposix.cpp sendupdatesaaddressesreqcommand.cpp socketaddressposix.cpp \
        threadcontrollerimplposix.cpp threadposix.cpp udpsocket.cpp \
	utilsimpl.cpp \
	aaacontrollerimplradius.cpp  aaasenderradius.cpp

if compile_EAP_client
libopenikev2_impl_la_SOURCES += eapclientfrm.cpp  eapclientmd5.cpp  eapclienttls.cpp
endif

if compile_EAP_server
libopenikev2_impl_la_SOURCES +=  eapserverfrm.cpp eapservermd5.cpp eapserverradius.cpp
endif

newinclude_HEADERS = addressconfiguration.h alarmcontrollerimplopenike.h \
	authenticatoropenike.h authgenerator.h authgeneratorbtns.h authgeneratorcert.h \
	authgeneratorpsk.h authverifier.h authverifierbtns.h authverifiercert.h authverifierpsk.h \
	certificatex509.h certificatex509hashurl.h cipheropenssl.h \
	conditionposix.h cryptocontrollerimplopenike.h dhcpclient.h diffiehellmanellipticcurve.h \
	diffiehellmanopenssl.h eapclient.h  eapmethod.h \
	eapserver.h  \
	facade.h idtemplateany.h idtemplatedomainname.h \
	idtemplateexactmatch.h ikesacontrollerimplopenike.h ikesaexecuter.h ikesareauthenticator.h \
        interfacelist.h ipaddressopenike.h ipseccontrollerimplopenike.h \
	ipseccontrollerimplpfkeyv2.h ipseccontrollerimplxfrm.h keyringopenssl.h libnetlink.h \
	logimplcolortext.h logimplhtml.h logimplopenike.h logimpltext.h mutexposix.h \
	networkcontrollerimplopenike.h notifycontroller_auth_lifetime.h notifycontroller_mobike_supported.h \
	notifycontroller_update_sa_addresses.h policy.h pseudorandomfunctionopenssl.h \
	radiusmessage.h randomopenssl.h roadwarriorpolicies.h sarequest.h semaphoreposix.h \
	sendupdatesaaddressesreqcommand.h socketaddressposix.h threadcontrollerimplposix.h \
	threadposix.h udpsocket.h utilsimpl.h \
	aaacontrollerimplradius.h  aaasenderradius.h 

if compile_EAP_client
newinclude_HEADERS += eapclientfrm.h eapclientmd5.h eapclienttls.h
endif

if compile_EAP_server
newinclude_HEADERS += eapserverfrm.h eapservermd5.h eapserverradius.h
endif

libopenikev2_impl_la_LDFLAGS = -version-info 0:7:0

if compile_EAP_client
libopenikev2_impl_la_LIBADD = $(top_builddir)/libeapclient/libeapclient.la
AM_CXXFLAGS = -DEAP_MD5 -DEAP_TLS -DEAP_TLS_FUNCS -DEAP_TLS_OPENSSL \
	-DIEEE8021X_EAPOL
endif

if compile_EAP_server
libopenikev2_impl_la_LIBADD = $(top_builddir)/libeapserver/libeapserver.la
AM_CXXFLAGS =  -DEAP_MD5 -DEAP_TLS -DEAP_TLS_FUNCS -DEAP_TLS_OPENSSL \
	-DIEEE8021X_EAPOL
endif
