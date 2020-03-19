/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef CERTIFICATE_X509_H
#define CERTIFICATE_X509_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/payload_cert.h>
#include <libopenikev2/id.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

using namespace std;

namespace openikev2 {

    /**
        This class implements the Certificate interface using X509 certificates with openssl library
        @author Pedro J. Fernandez Ruiz, Alejandro Perez Mendez <pedroj@um.es, alex@um.es>
    */
    class CertificateX509 : public Printable {
        friend class CertificateControllerOpenIKE;

            /****************************** ATTRIBUTES ******************************/
        public:
            X509* certificate;                          /**< Openssl internal representation of the X509 certificate */
            EVP_PKEY* private_key;                      /**< Openssl internal representation of the private key (RSA or DSA) */
            EVP_PKEY* public_key;                       /**< Openssl internal representation of the public key (RSA or DSA) */

            /****************************** METHODS ******************************/
        protected:

            /**
             * Creates a new empty X509 certificate.
             */
            CertificateX509( );

        public:
            /**
             * Creates a new X509 cerficicate setting its parameters
             * @param cert_filename Certificate file name
             * @param privatekey_filename Private key file name. If this parameter is NULL, then the certificate will has not private key.
             */
            CertificateX509( string cert_filename, string privatekey_filename );

            /**
             * Creates a new X509 certificate based on its binary (DER) representation
             * @param der_binary_representation Buffer containing the DER encoding of the X509 certificate
             */
            CertificateX509( ByteBuffer& der_binary_representation );

            /**
             * Creates a new X509 certificate cloning its parameters from another one
             * @param other Another X509 certificate
             */
            CertificateX509( const CertificateX509& other );

            /**
             * Indicates if this certificate is the issuer of another one (looking in the subject and issuer fields of the X509 structure)
             * @param other Other certificate
             * @return TRUE if this certificate is issuer of the other. FALSE otherwise.
             */
            virtual bool isIssuerOf( const CertificateX509 &other ) const;

            virtual string getSubjectName() const;

            virtual string getIssuerName() const;

            /**
             * Indicates if the certificate has the ID
             * @param id ID to be checked
             * @return TRUE if the certificate has the indicated ID. FALSE otherwise
             */
            virtual bool hasId( const ID& id) const;

            /**
             * Gets the DER encoding of the Subject name
             * @return The DER encoded subject name
             */
            virtual auto_ptr<ByteArray> getDerSubjectName( ) const;

            /**
             * Gets the private key
             * @return The private key
             */
            virtual auto_ptr<ByteArray> getPrivateKey( ) const;

            /**
             * Gets the public key SHA1 hash
             * @return The public key SHA1 hash (20 bytes)
             */
            virtual auto_ptr<ByteArray> getPublicKeyHash( ) const;

            /**
             * Gets the entire certificate SHA1 hash
             * @return The certificate fingerprint (20 bytes)
             */
            virtual auto_ptr<ByteArray> getFingerPrint() const;

            /**
             * Gets the public key
             * @return The public key
             */
            virtual auto_ptr<ByteArray> getPublicKey( ) const;

            virtual auto_ptr<Payload_CERT> getPayloadCert();

            virtual bool hasPrivateKey() const;

            virtual auto_ptr<ByteArray> signData( const ByteArray& data ) const;

            virtual bool verifyData( const ByteArray& data, const ByteArray& signature );

            virtual Enums::AUTH_METHOD getAuthMethod() const;

            virtual auto_ptr<CertificateX509> clone() const;

            virtual void getBinaryRepresentation( ByteBuffer& byte_buffer );

            virtual string toStringTab( uint8_t tabs ) const ;

            virtual X509* getInternalRepresentation() const;

            virtual ~CertificateX509();
    };
};
#endif
