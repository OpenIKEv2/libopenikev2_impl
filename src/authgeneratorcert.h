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
#ifndef OPENIKEV2AUTHGENERATORCERT_H
#define OPENIKEV2AUTHGENERATORCERT_H

#include "authgenerator.h"
#include "certificatex509.h"
#include "certificatex509hashurl.h"

namespace openikev2 {

    /**
     Implementation of AuthGenerator using the standard certificate authentication method
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class AuthGeneratorCert : public AuthGenerator {
            /****************************** ATTRIBUTES ******************************/
        protected:
            CertificateX509* selected_certificate;                          /**< Selected certificate to generate AUTH payload */
            AutoVector<CertificateX509> ca_certificates;                    /**< Collection of CA certificates */
            AutoVector<CertificateX509> my_certificates;                    /**< Collection of user certificates */
            AutoVector<CertificateX509HashUrl> my_hash_url_certificates;    /**< Collection of user hash & url certificates */
        
        public:     
            bool send_cert;                                                 /**< Indicates if we want to send CERT payloads */

            /****************************** METHODS ******************************/
        protected:
            /**
             * Finds a matching certificate with a CERTREQ payload
             * @param certificate_request Received CERTREQ payload
             * @param peer_supports_hash_url Indicates if peer supports HASH & URL certificate encoding
             * @return The found certificate. NULL if no certifiacate is found.
             */
            virtual CertificateX509* findCertificate( const Payload_CERT_REQ& certificate_request, bool peer_supports_hash_url ) const;

            /**
             * Obtains a CA certificate by its public key hash
             * @param ca_public_key_hash CA public key hash
             * @return The found CA certificate. NULL if no certificate is found.
             */
            virtual CertificateX509* getCaByPublicKeyHash( const ByteArray& ca_public_key_hash ) const;

            /**
             * Find the issuer of the certificate in the CA certificate collection
             * @param certificate Certificate to find its CA certificate
             * @return CA certificate of the certificate. NULL if not found.
             */
            virtual CertificateX509* findCa( const CertificateX509& certificate ) const;

        public:
            /**
            * Creates a new AuthGeneratorCert.
            */
            AuthGeneratorCert( );

            /**
             * Adds a CA X509 certificate.
             * The certificate must have the same Issuer and Subject name.
             * @param certificate CA certificate to be added.
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addCaCertificate( auto_ptr<CertificateX509> certificate );

            /**
             * Adds an user X509 certificate.
             * The issuer CA of the certificate must be added before add the certificate.
             * @param certificate Certificate to be added
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addCertificate( auto_ptr<CertificateX509> certificate );

            /**
             * Adds an user X509 HASH & URL certificate.
             * The issuer CA of the certificate must be added before add the certificate.
             * @param certificate HASH & URL certificate to be added
             * @return TRUE if certificate can be added. FALSE otherwise.
             */
            virtual bool addCertificate( auto_ptr<CertificateX509HashUrl> certificate );

            virtual AutoVector<Payload_CERT> generateCertificatePayloads( const IkeSa& ike_sa, const vector<Payload_CERT_REQ*> payload_cert_req_r );
            virtual auto_ptr<Payload_AUTH> generateAuthPayload( const IkeSa& ike_sa );
            virtual string toStringTab( uint8_t tabs ) const;
            virtual auto_ptr<AuthGenerator> clone() const;

            virtual ~AuthGeneratorCert();
    };
}

#endif
