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
#include "authverifiercert.h"

#include <libopenikev2/log.h>
#include "authenticatoropenike.h"

namespace openikev2 {

    AuthVerifierCert::AuthVerifierCert( ) { 
        static bool initialized = false;
        if ( !initialized ) {
            OpenSSL_add_all_algorithms();
            initialized = true;
        }
    }

    AuthVerifierCert::~AuthVerifierCert() {}

    AutoVector< Payload_CERT_REQ > AuthVerifierCert::generateCertificateRequestPayloads( const IkeSa & ike_sa ) {
        AutoVector<Payload_CERT_REQ> result;
        
        if (!this->send_cert_req)
            return result;

        // Creates the Payload CERTREQ if HASH & URL is supported
        if ( this->hash_url_support ) {
            auto_ptr<Payload_CERT_REQ> cert_req_hash_url ( new Payload_CERT_REQ( Enums::CERT_HASH_URL ) );

            for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ ) {
                auto_ptr<ByteArray> public_key_hash = ( *it ) ->getPublicKeyHash();
                cert_req_hash_url->addCaPublicKeyHash( public_key_hash );
            }

            result->push_back( cert_req_hash_url.release() );
        }

        // Creates the Payload CERTREQ for CERT_X509_SIGNATURE
        if ( this->hash_url_support ) {
            auto_ptr<Payload_CERT_REQ> cert_req_x509 ( new Payload_CERT_REQ( Enums::CERT_X509_SIGNATURE ) );

            for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ ) {
                auto_ptr<ByteArray> public_key_hash = ( *it ) ->getPublicKeyHash();
                cert_req_x509->addCaPublicKeyHash( public_key_hash );
            }

            result->push_back( cert_req_x509.release() );
        }
        
        return result;
    }

    bool AuthVerifierCert::verifyAuthPayload( const Message & received_message, const IkeSa & ike_sa ) {
        // Obtains the payload AUTH
        Payload_AUTH& received_payload_auth = ( Payload_AUTH& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_AUTH );

        // Obtains the first payload CERT
        Payload_CERT* payload_cert = ( Payload_CERT* ) received_message.getFirstPayloadByType( Payload::PAYLOAD_CERT );

        // Obtains the payload ID
        Payload_ID& payload_id = ike_sa.is_initiator ? ( Payload_ID& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_IDr ) : ( Payload_ID& ) received_message.getUniquePayloadByType( Payload::PAYLOAD_IDi );

        // The Message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_res : *ike_sa.ike_sa_init_req;

        // The PRF key
        ByteArray & prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pr : *ike_sa.key_ring->sk_pi;

        // Obtains the peer certificate
        auto_ptr<CertificateX509> peer_certificate( NULL );

        if ( payload_cert != NULL ) {
            // try to verify it
            if ( !this->verifyCertificate( *payload_id.id, *payload_cert ) ) {
                Log::writeMessage( "AuthenticatorOpenIKE", "Cannot verify the certificate", Log::LOG_ERRO, true );
                return false;
            }

            peer_certificate = this->payloadToCertificate( *payload_cert );
        }
        else {
            peer_certificate = this->getPeerCertificate( *payload_id.id );
        }

        if ( peer_certificate.get() == NULL ) {
            Log::writeMessage( "AuthenticatorOpenIKE", "There is no way to obtain the peer certificate", Log::LOG_ERRO, true );
            return false;
        }

        auto_ptr<ByteArray> auth_data = AuthenticatorOpenIKE::generateAuthDataToBeSigned(
                                            message_to_check.getBinaryRepresentation( ike_sa.receive_cipher.get() ),
                                            *ike_sa.my_nonce,
                                            *payload_id.id,
                                            *ike_sa.prf,
                                            prf_key
                                        );

        return peer_certificate->verifyData( *auth_data, received_payload_auth.getAuthField()  );
    }

    vector< Enums::AUTH_METHOD > AuthVerifierCert::getSupportedMethods( ) const {
        vector<Enums::AUTH_METHOD> result;

        result.push_back( Enums::AUTH_METHOD_RSA );
        result.push_back( Enums::AUTH_METHOD_DSS );

        return result;
    }

    string AuthVerifierCert::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_VERIFIER_CERT> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "hash_&_url_support=[" << boolToString( this->hash_url_support ) << "]\n";

        oss << Printable::generateTabs( tabs + 1 ) << "send_cert_req_payload=[" << boolToString( this->send_cert_req ) << "]\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<CA_CERTIFICATES> {\n";
        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<BLACK_LIST> {\n";
        for ( vector<CertificateX509*>::const_iterator it = this->black_list_certificates->begin(); it != this->black_list_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<WHITE_LIST> {\n";
        for ( vector<CertificateX509*>::const_iterator it = this->white_list_certificates->begin(); it != this->white_list_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< AuthVerifier > AuthVerifierCert::clone() const {
        auto_ptr<AuthVerifierCert> result ( new AuthVerifierCert(  ) );

        result->send_cert_req = this->send_cert_req;
        result->hash_url_support = this->hash_url_support;

        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            result->ca_certificates->push_back( new CertificateX509( * ( *it ) ) );

        for ( vector<CertificateX509*>::const_iterator it = this->white_list_certificates->begin(); it != this->white_list_certificates->end(); it++ )
            result->white_list_certificates->push_back( new CertificateX509( * ( *it ) ) );

        for ( vector<CertificateX509*>::const_iterator it = this->black_list_certificates->begin(); it != this->black_list_certificates->end(); it++ )
            result->black_list_certificates->push_back( new CertificateX509( * ( *it ) ) );

        return auto_ptr<AuthVerifier> ( result );
    }

    bool AuthVerifierCert::verifyCertificate( const ID & peer_id, const Payload_CERT & payload_cert ) const {
        // generates the Certificate object
        auto_ptr<CertificateX509> certificate = this->payloadToCertificate( payload_cert );

        if ( certificate.get() == NULL ) {
            Log::writeLockedMessage( "CertificateController", "Invalid certificate type: " + Enums::CERT_ENCODING_STR( payload_cert.cert_encoding ) + "\n", Log::LOG_ERRO, true );
            return false;
        }

        if ( !certificate->hasId( peer_id ) ) {
            Log::writeLockedMessage( "CertificateController", "Peer ID doesn't match the certificate ID", Log::LOG_ERRO, true );
            return false;
        }

        // Check the black list
        if ( this->isBlackListed( *certificate ) ) {
            Log::writeLockedMessage( "CertificateController", "Certificate is in the Black List", Log::LOG_ERRO, true );
            return false;
        }

        // Check the black list
        if ( this->isWhiteListed( *certificate ) ) {
            Log::writeLockedMessage( "CertificateController", "Certificate is in the White List", Log::LOG_WARN, true );
            return true;
        }

        // Verify using the CAs
        X509_STORE_CTX* cert_store_ctx = X509_STORE_CTX_new();
        X509_STORE* cert_store = X509_STORE_new();
        STACK_OF( X509 ) * cert_stack = sk_X509_new_null();

        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            sk_X509_push( cert_stack, ( *it ) ->certificate );
        
        X509_STORE_CTX_init( cert_store_ctx, cert_store, certificate->certificate, NULL );
        X509_STORE_CTX_trusted_stack( cert_store_ctx, cert_stack );
        bool result = X509_verify_cert( cert_store_ctx );

        X509_STORE_CTX_free( cert_store_ctx );
        X509_STORE_free( cert_store );
        sk_X509_free( cert_stack );

        return result;
    }

    auto_ptr< CertificateX509 > AuthVerifierCert::payloadToCertificate( const Payload_CERT & peer_certificate ) const {
        ByteBuffer certificate_data_buffer ( peer_certificate.getCertificateData() );
        if ( peer_certificate.cert_encoding == Enums::CERT_X509_SIGNATURE )
            return auto_ptr<CertificateX509> ( new CertificateX509( certificate_data_buffer ) );
        else if ( peer_certificate.cert_encoding == Enums::CERT_HASH_URL )
            return auto_ptr<CertificateX509> ( new CertificateX509HashUrl( certificate_data_buffer ) );
        else
            return auto_ptr<CertificateX509> ( NULL );
    }

    auto_ptr<CertificateX509> AuthVerifierCert::getPeerCertificate( const ID& peer_id ) const {
        for ( vector<CertificateX509*>::const_iterator it = this->white_list_certificates->begin(); it != this->white_list_certificates->end(); it++ ) {
            if ( ( *it ) ->hasId( peer_id ) )
                return ( *it ) ->clone();
        }

        return auto_ptr<CertificateX509> ( NULL );
    }

    bool AuthVerifierCert::addWhiteListedCertificate( auto_ptr<CertificateX509> certificate ) {
        this->white_list_certificates->push_back( certificate.release() );
        return true;
    }

    bool AuthVerifierCert::addBlackListedCertificate( auto_ptr<CertificateX509> certificate ) {
        this->black_list_certificates->push_back( certificate.release() );
        return true;
    }

    bool AuthVerifierCert::addCaCertificate( auto_ptr<CertificateX509> certificate ) {
        if ( !certificate->isIssuerOf( *certificate ) ) {
            Log::writeLockedMessage( "CertificateController", "The certificate doesn't appear to be a CA certificate" + certificate->toString(), Log::LOG_ERRO, true );
            return false;
        }

        this->ca_certificates->push_back( certificate.release() );
        return true;
    }

    bool AuthVerifierCert::isBlackListed( const CertificateX509 & certificate ) const {
        for ( vector<CertificateX509*>::const_iterator it = this->black_list_certificates->begin(); it != this->black_list_certificates->end(); it++ )
            if ( *( *it ) ->getDerSubjectName() == *certificate.getDerSubjectName() )
                return true;

        return false;
    }

    bool AuthVerifierCert::isWhiteListed( const CertificateX509 & certificate ) const {
        for ( vector<CertificateX509*>::const_iterator it = this->white_list_certificates->begin(); it != this->white_list_certificates->end(); it++ )
            if ( *( *it ) ->getDerSubjectName() == *certificate.getDerSubjectName() )
                return true;

        return false;
    }



}
