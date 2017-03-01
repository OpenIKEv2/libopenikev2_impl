/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*                                                                         *
*   This library is free software; you can redistribute it and/or         *
*   modify it under the terms of the GNU Lesser General Public            *
*   License as published by the Free Software Foundation; either          *
*   version 2.1 of the License, or (at your option) any later version.    *
*                                                                         *
*   This library is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *
*   Lesser General Public License for more details.                       *
*                                                                         *
*   You should have received a copy of the GNU Lesser General Public      *
*   License along with this library; if not, write to the Free Software   *
*   Foundation, Inc., 51 Franklin St, Fifth Floor,                        *
*   Boston, MA  02110-1301  USA                                           *
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
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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
