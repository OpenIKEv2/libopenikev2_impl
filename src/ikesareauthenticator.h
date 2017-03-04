/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
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
#ifndef IKE_SA_REAUTHENTICATOR_H
#define IKE_SA_REAUTHENTICATOR_H

#include <libopenikev2/busobserver.h>
#include <libopenikev2/alarm.h>
#include <libopenikev2/alarmable.h>
#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/attribute.h>

namespace openikev2 {

    /**
        This class represents an IKE_SA Reauthenticator, that is used to perform IKE_SA reauthentications
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class IkeSaReauthenticator : public Attribute, public BusObserver, public Alarmable {

            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<Alarm> alarm;      /**< Alarm that will notify us when IKE_SA must be reauthenticated */
            uint64_t spi;               /**< SPI value of the IKE_SA to be reauthenticated */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new IkeSaReauthenticator
             * @param spi SPI value of the IKE_SA to be reauthenticated
             * @param timeout Time before start reauthentication
             */
            IkeSaReauthenticator( uint64_t spi, uint32_t timeout );

            virtual void notifyAlarm( Alarm & alarm );

            virtual void notifyBusEvent( const BusEvent & event );

            virtual auto_ptr<Attribute> cloneAttribute() const ;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual ~IkeSaReauthenticator();

    };
};
#endif
