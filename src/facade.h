/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#ifndef FACADE_H
#define FACADE_H

#include <libopenikev2/enums.h>
#include <libopenikev2/proposal.h>
#include <libopenikev2/ipaddress.h>

#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/networkcontroller.h>
#include <libopenikev2/cryptocontroller.h>
#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2/log.h>

#include "logimplopenike.h"
#include "threadcontrollerimplposix.h"
#include "ikesacontrollerimplopenike.h"
#include "networkcontrollerimplopenike.h"
#include "ipseccontrollerimplxfrm.h"
#include "logimplcolortext.h"
#include "cryptocontrollerimplopenike.h"
#include "alarmcontrollerimplopenike.h"

using namespace std;

namespace openikev2 {

    /**
        This class is a facade of libopenikev2_impl
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class Facade {
        protected:
            static auto_ptr<ThreadControllerImplPosix> thread_controller_impl;
            static auto_ptr<IpsecControllerImplOpenIKE> ipsec_controller_impl;
            static auto_ptr<NetworkControllerImplOpenIKE> network_controller_impl;
            static auto_ptr<CryptoControllerImplOpenIKE> crypto_controller_impl;
            static auto_ptr<LogImplOpenIKE> log_impl;
            static auto_ptr<AlarmControllerImplOpenIKE> alarm_controller_impl;
            static auto_ptr<IkeSaControllerImplOpenIKE> ike_sa_controller_impl;

        public:
            /**
             * Loads the controllers and make the basic initialization
             * @param log_filename Log output file
             */
            static void initialize(string log_filename);

            /**
             * Starts the main threads
             */
            static void startThreads();

            /**
             * Makes finalization tasks
             */
            static void finalize();

            /**
             * Creates a new basic IKE proposal using AES_128, SHA1 and MODP 1024
             * @return The new IKE proposal
             */
            static auto_ptr<Proposal> createBasicIkeProposal();

            /**
             * Creates a new basic IPSEC proposal using AES_128 (when needed), SHA1 and MODP 1024 (when needed)
             * @param ipsec_protocol IPSEC protocol (ESP or AH)
             * @param use_pfs Indicates if PFS is required
             * @return The new IPSEC proposal
             */
            static auto_ptr<Proposal> createBasicIpsecProposal( Enums::PROTOCOL_ID ipsec_protocol = Enums::PROTO_ESP, bool use_pfs = false );

            /**
             * Installs a new IPSEC security policy in the SPD
             * @param src_selector Source traffic selector (using the net/prefix form)
             * @param src_port Source traffic port
             * @param dst_selector Destination traffic selector (using the net/prefix form)
             * @param dst_port Destination traffic port
             * @param ip_protocol IP protocol (TCP, UDP, ...)
             * @param direction Policy direction (use ALL in order to create the symmetrical policies automatically also)
             * @param priority Policy priority
             * @param ipsec_protocol IPSEC protocol (ESP or AH)
             * @param mode IPSEC mode (transport or tunnel)
             * @param src_tunnel Source tunnel address (ommited when transport mode is selected)
             * @param dst_tunnel Destination tunnel address (ommited when transport mode is selected)
             */
            static void createIpsecPolicy( string src_selector, uint16_t src_port, string dst_selector, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION direction = Enums::DIR_ALL, Enums::POLICY_ACTION action = Enums::POLICY_ALLOW, uint32_t priority = 1000, Enums::PROTOCOL_ID ipsec_protocol = Enums::PROTO_NONE, Enums::IPSEC_MODE mode = Enums::TRANSPORT_MODE, string src_tunnel = "", string dst_tunnel = "" , bool autogen = false, bool sub = false  );

            static void deleteIpsecPolicy( string src_selector, uint16_t src_port, string dst_selector, uint16_t dst_port, uint8_t ip_protocol, Enums::DIRECTION direction);

            /**
             * Installs a new IPSEC security policy in the SPD
             * @param src_selector Source traffic selector (using the net/prefix form)
             * @param dst_selector Destination traffic selector (using the net/prefix form)
             * @param ip_protocol IP protocol (TCP, UDP, ...)
             * @param icmp_type ICMP type
             * @param icmp_code ICMP code
             * @param direction Policy direction (use ALL in order to create the symmetrical policies automatically also)
             * @param priority Policy priority
             * @param ipsec_protocol IPSEC protocol (ESP or AH)
             * @param mode IPSEC mode (transport or tunnel)
             * @param src_tunnel Source tunnel address (ommited when transport mode is selected)
             * @param dst_tunnel Destination tunnel address (ommited when transport mode is selected)
             */
            static void createIpsecPolicy( string src_selector, string dst_selector, uint8_t ip_protocol, uint8_t icmp_type, uint8_t icmp_code, Enums::DIRECTION direction = Enums::DIR_ALL, Enums::POLICY_ACTION action = Enums::POLICY_ALLOW, uint32_t priority = 1000, Enums::PROTOCOL_ID ipsec_protocol = Enums::PROTO_NONE, Enums::IPSEC_MODE mode = Enums::TRANSPORT_MODE, string src_tunnel = "", string dst_tunnel = "", bool autogen = false, bool sub = false  );

            /**
             * Obtains a NetworkPrefix based on a text representation
             * @param subnet Text representation
             * @return A new NetworkPrefix
             */
            static auto_ptr<NetworkPrefix> getNetworkPrefix( string subnet );
    };
};
#endif
