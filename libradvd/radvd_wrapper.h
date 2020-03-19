/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/



#ifndef EAPSM_H
#define EAPSM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netinet/in.h>

#include <netinet/ip6.h>
#include <string>
#include <libopenikev2/alarm.h>
#include <libopenikev2/alarmable.h>
#include <libopenikev2/ikesa.h>
#include <libopenikev2/busobserver.h>


namespace openikev2 {
    /**
     This class is used as a wrapper between openikev2 and a built-in radvd server.
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class RadvdWrapper : public Alarmable, public BusObserver  {


    protected:
        Alarm *periodic_send_alarm;
        IkeSa *associated_ike_sa;
        int  readin_config(const char *fname);
        void config_interface(void);

    public:

        RadvdWrapper( string config_file );
        void notifyAlarm( Alarm& alarm );
        void notifyBusEvent( const BusEvent& event );
        int sendRA(struct in6_addr *dest);
        virtual ~RadvdWrapper();
    };
}

#endif
