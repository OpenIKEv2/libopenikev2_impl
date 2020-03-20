/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2EAPSERVERMD5_H
#define OPENIKEV2EAPSERVERMD5_H

#include "eapserver.h"
#include <map>

namespace openikev2 {

    /**
     This class implements the EapServer abstract class, using the method MD5-CHALLENGE (only for example purposes)
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class EapServerMd5 : public EapServer {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<ByteArray> challenge;      /**< MD5 challenge bytes */
            map<string, string> user_map;       /**< User/Passwd map */
            string peer_id;                     /**< Peer ID (textual representation)*/

            /****************************** METHODS ******************************/
        protected:
            /**
             * Creates a new EapServerMd5
             */
            EapServerMd5();

            /**
             * Loads the user/password information from "filename"
             * @param filename File name where user/password information is stored.
             */
            virtual void readMapFile( string filename );

            /**
             * Reads a line of the user/password file
             * @param line Line wth the user/password information
             */
            virtual void readLine( string line );

        public:
            /**
             * Creates a new EapServerMd5 indicating the filename where the user DB is located
             * @param filename Filename where the user DB is located
             */
            EapServerMd5( string filename );

            virtual auto_ptr<Payload_EAP> generateInitialEapRequest( const ID& peer_id  );
            virtual auto_ptr<Payload_EAP> processEapResponse( const Payload_EAP& eap_response );
            virtual vector<EapPacket::EAP_TYPE> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<EapServer> clone() const;
            virtual ~EapServerMd5();

    };

}

#endif
