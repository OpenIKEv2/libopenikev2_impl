/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef CERTIFICATE_X509_HASH_URL_H
#define CERTIFICATE_X509_HASH_URL_H

#include "certificatex509.h"
#include "mutexposix.h"

namespace openikev2 {

    /**
        This class implements the Certificate interface using HASH & URL X509 certificates with openssl library
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class CertificateX509HashUrl : public CertificateX509 {
        public:
            string url;                 /**< URL where the certificate is */

        protected:
            static MutexPosix mutex;   /**< Mutex used to provide exclusive access to the HTTP_FETCH library */

            /**
             * Download and stores internally the X509 certificate from the indicated URL. The certificate must be in DER format
             * @param url URL where locate the DER encoded X509 certificate
             */
            void downloadCertificate( string url );

        public:
            /**
             * Creates a new CertificateX509HashUrl, setting the URL where it is located and the private key filename
             * @param url URL where the certificate is located
             * @param privatekey_filename Private key filename
             */
            CertificateX509HashUrl( string url, string privatekey_filename );

            /**
             * Creates a new CertificateX509HashUrl, cloning another one
             * @param other Other CertificateX509HashUrl to be cloned
             */
            CertificateX509HashUrl( const CertificateX509HashUrl& other );

            /**
             * Create a new CertificateX509HashUrl based on its binary representation.
             * @param byte_buffer Buffer containing the binary representation of the certificate
             */
            CertificateX509HashUrl( ByteBuffer& byte_buffer );

            virtual auto_ptr<Payload_CERT> getPayloadCert() const;

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual void getBinaryRepresentation( ByteBuffer& byte_buffer );

            virtual auto_ptr<CertificateX509> clone();

            virtual ~CertificateX509HashUrl();

    };
};
#endif
