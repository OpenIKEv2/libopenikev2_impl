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

#include <libopenikev2/log.h>
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/buseventchildsa.h>
#include <libopenikev2/enums.h>
#include <libopenikev2/ikesa.h>
#include <libopenikev2/socketaddress.h>
#include <libopenikev2_impl/socketaddressposix.h>
#include <libopenikev2/buseventchildsa.h>
#include <string>
#include "radvd_wrapper.h"


extern FILE *yyin;
extern struct Interface *IfaceList;

extern char *conf_file;
extern int num_lines;
extern char *yytext;
extern int sock;

extern "C" {
#include "defaults.h"
#include "includes.h"
#include "pathnames.h"
#include "radvd.h"
}

namespace openikev2 {

RadvdWrapper::RadvdWrapper( string config_file ) {

        IfaceList=NULL;
        conf_file=NULL;
        sock = -1;

        /* get a raw socket for sending and receiving ICMPv6 messages */
        sock = open_icmpv6_socket();
        if (sock < 0)
            throw NetworkException( "radvd: Cannot open raw socket for ICMP RouteAdv sending." );
        //Log::writeLockedMessage( "NetworkController", "ICMP socket opened for RouterAdv messages.", Log::LOG_INFO, true );
        cout << "radvd: ICMP socket opened for RouterAdv messages." << endl;

        /* parse config file */
        conf_file = (char *) malloc (strlen(config_file.c_str()+1));

        conf_file = strcpy(conf_file, config_file.c_str());
        if (readin_config(config_file.c_str()) < 0)
            throw NetworkException( "radvd: Error reading config file." );
        //Log::writeLockedMessage( "NetworkController", "Radvd config file parsed successfully.", Log::LOG_INFO, true );
        cout << "radvd: Radvd config file parsed successfully." << endl;
        /* fill interface structure */
        config_interface();

        EventBus::getInstance().registerBusObserver( *this, BusEvent::CHILD_SA_EVENT );

}



void RadvdWrapper::notifyBusEvent( const BusEvent& event ) {
        // if CHILD_SA_EVENT
#ifdef HAVE_IPv6
        

	if ( event.type == BusEvent::CHILD_SA_EVENT ) {
            BusEventChildSa& busevent = ( BusEventChildSa& ) event;
            if ( busevent.child_sa_event_type == BusEventChildSa::CHILD_SA_ESTABLISHED ){
                if (busevent.ike_sa.peer_addr->getIpAddress().getFamily() == Enums::ADDR_IPV6)  {
			this->associated_ike_sa = &(busevent.ike_sa);              	
			this->periodic_send_alarm = new Alarm( ( *this ), 1000 );
			this->periodic_send_alarm->reset();

                	AlarmController::addAlarm(*this->periodic_send_alarm);
			
		}       
	    }
 	}
#endif
}



void RadvdWrapper::notifyAlarm ( Alarm& alarm ) {

	//SocketAddressPosix *peer_addr_posix = (SocketAddressPosix *) busevent.ike_sa.peer_addr.get();
	// Mirar esto que en alguna ocasión ha devuelto null.
        SocketAddressPosix *peer_addr_posix = (SocketAddressPosix *) this->associated_ike_sa->peer_addr.get();
	auto_ptr<sockaddr> sockaddress = peer_addr_posix->getSockAddr();
	sockaddr_in6* sa_in6 = ( sockaddr_in6* ) sockaddress.get();

	sendRA((struct in6_addr*) &(sa_in6->sin6_addr.s6_addr));
	// REPARAR ESTO, INTERBLOQUEO
        //alarm.reset();    
	//AlarmController::removeAlarm(alarm);
        //Alarm* alarm_ptr = &alarm;
        //delete alarm_ptr;
        this->periodic_send_alarm = NULL;
}



int RadvdWrapper::sendRA(struct in6_addr *dest){
	struct Interface *iface;

	/*
	 *	send advertisement using desired interfaces
	 */

	for(iface=IfaceList; iface; iface=iface->next)
	{
		if (iface->AdvSendAdvert)
		{
			/* send an initial advertisement */
			send_ra(sock, iface, dest);
			//Log::writeLockedMessage( "NetworkController", "Radvd sends a Router Advertisement to peer.", Log::LOG_INFO, true );
			cout << "radvd: Radvd sends a Router Advertisement to peer with address=";
			
			auto_ptr<ByteBuffer> dest_temp ( new ByteBuffer ( 16 ) );
		
			char* pointer = (char *) dest;
			for ( uint8_t i = 0; i < 16 ; i++ ) {
			    dest_temp->writeInt8( pointer[i] );
			}
			cout << dest_temp->toString() << endl;
		}
	}
        return 0;
}


int  RadvdWrapper::readin_config(const char *fname) {
	cout << "readin_config()" << endl;
	if ((yyin = fopen(fname, "r")) == NULL)
	{
		cout << "radvd: can't open config file." << endl;
		//flog(LOG_ERR, "can't open %s: %s", fname, strerror(errno));
		return (-1);
	}

	if (yyparse() != 0)
	{
		cout << "radvd: error parsing or activating the config file" << endl;
		//flog(LOG_ERR, "error parsing or activating the config file: %s", fname);
		return (-1);
	}
	
	fclose(yyin);
	return 0;
}



void RadvdWrapper::config_interface(void){
	struct Interface *iface;
	for(iface=IfaceList; iface; iface=iface->next)
	{
		if (iface->AdvLinkMTU)
			set_interface_linkmtu(iface->Name, iface->AdvLinkMTU);
		if (iface->AdvCurHopLimit)
			set_interface_curhlim(iface->Name, iface->AdvCurHopLimit);
		if (iface->AdvReachableTime)
			set_interface_reachtime(iface->Name, iface->AdvReachableTime);
		if (iface->AdvRetransTimer)
			set_interface_retranstimer(iface->Name, iface->AdvRetransTimer);
	}
}



RadvdWrapper::~RadvdWrapper() {

    close (sock);
    EventBus::getInstance().removeBusObserver( *this );
    //AlarmController::removeAlarm(*this->periodic_send_alarm);

    //Log::writeLockedMessage( "NetworkController", "Close ICMP socket and release radvd stuff.", Log::LOG_INFO, true );
    cout << "radvd: Closing ICMP socket and releasing radvd resources." << endl;
}

}
