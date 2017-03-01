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
#ifndef OPENIKEV2AUTHENTICATOROPENIKE_H
#define OPENIKEV2AUTHENTICATOROPENIKE_H

#include <libopenikev2/authenticator.h>

#include "authgenerator.h"
#include "authverifier.h"
#include "eapclient.h"
#include "eapserver.h"

#include <map>

namespace openikev2 {

    /**
        This class implements the Authenticator abstract class. It allows to extend dynamically the authentication methods and EAP methods
        by defining new AuthGenerator, AuthVerifier, EapClient and EapServer subclasses.
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class AuthenticatorOpenIKE : public Authenticator {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<AuthGenerator> auth_generator;                     /**< AuthGenerator to generate AUTH payload */
            AutoVector<AuthVerifier> auth_verifiers;                    /**< AuthVerifier collection to verify the AUTH payload */
            map<Enums::AUTH_METHOD, AuthVerifier*> auth_verifiers_map;  /**< AuthVerifier map, to find the a suittable verifier by method */

            AutoVector<EapClient> eap_clients;                          /**< EapClient collection to perform the client side of an EAP authentication */
            AutoVector<EapServer> eap_servers;
            map<EapPacket::EAP_TYPE, EapClient*> eap_clients_map;       /**< EapClient map, to find the a suittable EAP client by method */
            EapClient* current_eap_client;                              /**< Current EapClient being used in the authentication */
            map<EapPacket::EAP_TYPE, EapServer*> eap_servers_map;
            EapServer* current_eap_server;                              /**< Current EapServer to perform the server side of an EAP authentication */
                                         

            /****************************** METHODS ******************************/
        protected:
            virtual auto_ptr<Payload_EAP> buildNack( const EapPacket& eap_request );

        public:
            /**
             * Creates a new empty AuthenticatorOpenIKE
             */
            AuthenticatorOpenIKE( );

            /**
             * Registers an AuthVerifier supporting a set of AUTH methods
             * @param auth_verifier AuthVerifier to be registered
             */
            virtual void registerAuthVerifier( auto_ptr<AuthVerifier> auth_verifier );

            /**
             * Sets the AuthGenerator to be used when creating AUTH payloads
             * @param auth_generator AuthGenerator to be used
             */
            virtual void setAuthGenerator( auto_ptr<AuthGenerator> auth_generator );

            /**
             * Register an EapClient supporint a set of EAP methods
             * @param eap_client EapClient to be registered
             */
            virtual void registerEapClient( auto_ptr<EapClient> eap_client );

            /**
             * Register an EapServer to be used when acting as a server in an EAP authentication
             * @param eap_server EapServer to be registered
             */
            virtual void registerEapServer( auto_ptr<EapServer> eap_server );


            //virtual void setEapServer( auto_ptr<EapServer> eap_server );

            /**
            * Generates the AUTH data to be signed (for PSK, Certificate authentication and others)
            * @param message Binary representation of the message to be signed
            * @param nonce Nonce to be signed
            * @param id ID to be signed
            * @param prf Pseudo random function to be used
            * @param prf_key PRF key
            * @return The AUTH data ready to be signed
            */
            static auto_ptr<ByteArray> generateAuthDataToBeSigned( const ByteArray& message, const ByteArray& nonce, const ID& id, const PseudoRandomFunction& prf, const ByteArray& prf_key );

            /**
            * Generates the auth field of an AUTH payload for the PSK method
            * @param message Binary representation of the message to be signed
            * @param nonce Nonce to be signed
            * @param id ID to be signed
            * @param prf Pseudo random function to be used
            * @param prf_key PRF key
            * @param psk Pre-shared key
            * @return The AUTH field to be included in an AUTH payload
            */
            static auto_ptr<ByteArray> generatePskAuthField ( const ByteArray& message, const ByteArray& nonce, const ID& id, const PseudoRandomFunction& prf, const ByteArray& prf_key, const ByteArray& psk );

            virtual bool initiatorUsesEap();
            virtual AutoVector<Payload_CERT_REQ> generateCertificateRequestPayloads( const IkeSa& ike_sa );
            virtual AutoVector<Payload_CERT> generateCertificatePayloads( const IkeSa& ike_sa, const vector<Payload_CERT_REQ*> payload_cert_req_r );
            virtual auto_ptr<Payload_AUTH> generateAuthPayload( const IkeSa& ike_sa );
            virtual bool verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa );
            virtual auto_ptr<Payload_EAP> processEapRequest( const Payload_EAP& eap_request );
            virtual auto_ptr<Payload_EAP> generateInitialEapRequest( const ID& peer_id );
            virtual void processEapSuccess ( const Payload_EAP& eap_success );
            virtual auto_ptr<Payload_EAP> processEapResponse( const Payload_EAP& eap_response, const ID& peer_id );
            virtual void processFinish( );
            virtual auto_ptr<Payload_AUTH> generateEapAuthPayload( const IkeSa& ike_sa );
            virtual bool verifyEapAuthPayload( const Message& received_message, const IkeSa& ike_sa );
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<Authenticator> clone() const;
            virtual ~AuthenticatorOpenIKE();

    };

}

#endif
