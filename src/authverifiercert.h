/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2AUTHVERIFIERCERT_H
#define OPENIKEV2AUTHVERIFIERCERT_H

#include "authverifier.h"
#include "certificatex509.h"
#include "certificatex509hashurl.h"

namespace openikev2 {

    /**
     Implementation of AuthVerifier using the standard certificate authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class AuthVerifierCert : public AuthVerifier{
            /****************************** ATTRIBUTES ******************************/
        protected:
            AutoVector<CertificateX509> ca_certificates;                    /**< Collection of CA certificates */
            AutoVector<CertificateX509> white_list_certificates;            /**< Collection of trusted certificates */
            AutoVector<CertificateX509> black_list_certificates;            /**> Collection of black listed certificates */

        public:
            bool send_cert_req;                                             /**< Indicates if we want to send CERT_REQ payloads */
            bool hash_url_support;                                          /**< Indicates if we supports HASH & URL */

             /****************************** METHODS ******************************/
        protected:
            /**
            * Verify a received certificate, checking the ID and validating it against the CA
            * @param peer_id Peer ID
            * @param payload_cert Received payload CERT
            * @return TRUE if the received certificate is valid. FALSE otherwise
            */
            bool verifyCertificate( const ID & peer_id, const Payload_CERT & payload_cert ) const;

            /**
             * Generates a CertificateX509 from a Payload_CERT
             * @param peer_certificate Received Payload_CERT
             * @return The CertificateX509. NULL if some any is found
             */
            virtual auto_ptr<CertificateX509> payloadToCertificate( const Payload_CERT& peer_certificate ) const;
            /**
             * Checks if the indicated certificate is in the black list
             * @param certificate Certificate
             * @return TRUE if is blacklisted. FALSE otherwise
             */
            virtual bool isBlackListed( const CertificateX509& certificate ) const;

            /**
             * Checks if the indicated certificate is in the white list
             * @param certificate Certificate
             * @return TRUE if is whitelisted. FALSE otherwise
             */
            virtual bool isWhiteListed( const CertificateX509& certificate ) const;

            /**
            * Obtains a peer certificate when no CERT payload is received. It looks for it in the white list.
            * @param peer_id Peer ID
            * @return The found peer certificate. NULL if no certificate is found.
            */
            virtual auto_ptr<CertificateX509> getPeerCertificate( const ID& peer_id )const ;

        public:
            /**
             * Creates a new AuthVerifierCert
             */
            AuthVerifierCert( );

            /**
             * Adds a CA X509 certificate.
             * The certificate must have the same Issuer and Subject name.
             * @param certificate CA certificate to be added.
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addCaCertificate( auto_ptr<CertificateX509> certificate );

            /**
             * Adds a X509 certificate in the White List
             * @param certificate Certificate to be added
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addWhiteListedCertificate( auto_ptr<CertificateX509> certificate );

            /**
             * Adds a X509 certificate in the Black List
             * @param certificate Certificate to be added
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addBlackListedCertificate( auto_ptr<CertificateX509> certificate );

            virtual AutoVector<Payload_CERT_REQ> generateCertificateRequestPayloads( const IkeSa& ike_sa );
            virtual bool verifyAuthPayload( const Message& received_message, const IkeSa& ike_sa );
            virtual vector<Enums::AUTH_METHOD> getSupportedMethods( ) const;
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthVerifier> clone() const;

            virtual ~AuthVerifierCert();
    };

}

#endif
