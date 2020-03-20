/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#include "authgeneratorcert.h"
#include <libopenikev2/log.h>
#include "authenticatoropenike.h"

namespace openikev2 {

    AuthGeneratorCert::AuthGeneratorCert( ) {
        this->selected_certificate = NULL;
    }

    AuthGeneratorCert::~AuthGeneratorCert() {}

    AutoVector< Payload_CERT > AuthGeneratorCert::generateCertificatePayloads( const IkeSa & ike_sa, const vector< Payload_CERT_REQ * > payload_cert_req_r ) {
        AutoVector<Payload_CERT> result;

        // Look for a matching certificate
        for ( vector<Payload_CERT_REQ*>::const_iterator it_cert_req = payload_cert_req_r.begin(); it_cert_req != payload_cert_req_r.end(); it_cert_req++ ) {
            CertificateX509* certificate = this->findCertificate( * ( *it_cert_req ) , ike_sa.peer_supports_hash_url );
            if ( certificate ) {
                this->selected_certificate = certificate;
                break;
            }
        }

        // If no certificate has been found and peer supports hash & url...
        if ( this->selected_certificate == NULL && ike_sa.peer_supports_hash_url )
            this->selected_certificate = ( this->my_hash_url_certificates->size() > 0 ) ? this->my_hash_url_certificates->front() : NULL;

        // If no certificate has been found...
        if ( this->selected_certificate == NULL )
            this->selected_certificate = ( this->my_certificates->size() > 0 ) ? this->my_certificates->front() : NULL;

        // Construct the CERT payload (if needed)
        if ( this->selected_certificate != NULL && this->send_cert )
            result->push_back ( this->selected_certificate->getPayloadCert().release() );

        return result;
    }

    auto_ptr< Payload_AUTH > AuthGeneratorCert::generateAuthPayload( const IkeSa & ike_sa ) {
        // The message to be checked
        Message& message_to_check = ike_sa.is_initiator ? *ike_sa.ike_sa_init_req : *ike_sa.ike_sa_init_res;

        // The PRF key to be used
        ByteArray& prf_key = ike_sa.is_initiator ? *ike_sa.key_ring->sk_pi : *ike_sa.key_ring->sk_pr;

        // sets the authentication method
        Enums::AUTH_METHOD auth_method = this->selected_certificate->getAuthMethod();

        // Generate the AUTH data
        auto_ptr<ByteArray> auth_data = AuthenticatorOpenIKE::generateAuthDataToBeSigned(
                                            message_to_check.getBinaryRepresentation( ike_sa.send_cipher.get() ),
                                            *ike_sa.peer_nonce,
                                            *ike_sa.getIkeSaConfiguration().my_id,
                                            *ike_sa.prf,
                                            prf_key
                                        );

        // generates the auth field
        auto_ptr<ByteArray> auth_field = this->selected_certificate->signData( *auth_data );

        return auto_ptr<Payload_AUTH> ( new Payload_AUTH( auth_method, auth_field ) );
    }

    string AuthGeneratorCert::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<AUTH_GENERATOR_CERT> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "send_cert_payload=[" << boolToString( this->send_cert ) << "]\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<CA_CERTIFICATES> {\n";
        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<MY_CERTIFICATES> {\n";
        for ( vector<CertificateX509*>::const_iterator it = this->my_certificates->begin(); it != this->my_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs + 1 ) << "<MY_HASH_URL_CERTIFICATES> {\n";
        for ( vector<CertificateX509HashUrl*>::const_iterator it = this->my_hash_url_certificates->begin(); it != this->my_hash_url_certificates->end(); it++ )
            oss << ( *it ) ->toStringTab( tabs + 2 );
        oss << Printable::generateTabs( tabs + 1 ) << "}\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    auto_ptr< AuthGenerator > AuthGeneratorCert::clone() const {
        auto_ptr<AuthGeneratorCert> result ( new AuthGeneratorCert(  ) );

        result->send_cert = this->send_cert;

        for ( vector<CertificateX509*>::const_iterator it = this->my_certificates->begin(); it != this->my_certificates->end(); it++ )
            result->my_certificates->push_back( new CertificateX509( * ( *it ) ) );

        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            result->ca_certificates->push_back( new CertificateX509( * ( *it ) ) );

        for ( vector<CertificateX509HashUrl*>::const_iterator it = this->my_hash_url_certificates->begin(); it != this->my_hash_url_certificates->end(); it++ )
            result->my_hash_url_certificates->push_back( new CertificateX509HashUrl( * ( *it ) ) );

        return auto_ptr<AuthGenerator> ( result );
    }

    CertificateX509* AuthGeneratorCert::findCertificate( const Payload_CERT_REQ & certificate_request, bool peer_supports_hash_url ) const {
        // If peer supports HASH & URL or directly he requests one of that type
        if ( certificate_request.encoding == Enums::CERT_HASH_URL || ( certificate_request.encoding == Enums::CERT_X509_SIGNATURE && peer_supports_hash_url ) ) {
            // Find a suittable HASH & URL certificate that matches one of the CERT_REQ CAs
            vector<ByteArray*> ca_public_key_hashes = certificate_request.getCaPublicKeyHashes();
            for ( vector<ByteArray*>::iterator hash_iterator = ca_public_key_hashes.begin(); hash_iterator != ca_public_key_hashes.end(); hash_iterator++ ) {
                CertificateX509* ca_certificate = this->getCaByPublicKeyHash( * ( *hash_iterator ) );

                if ( ca_certificate == NULL )
                    continue;

                for ( vector<CertificateX509HashUrl*>::const_iterator it = this->my_hash_url_certificates->begin(); it != this->my_hash_url_certificates->end(); it++ )
                    if ( ca_certificate->isIssuerOf( ( *( *it ) ) ) )
                        return ( *it );
            }
        }

        // If peer desires an CERT_X509_SIGNATURE certificate
        if ( certificate_request.encoding == Enums::CERT_X509_SIGNATURE ) {
            // Find a suittable HASH & URL certificate that matches one of the CERT_REQ CAs
            vector<ByteArray*> ca_public_key_hashes = certificate_request.getCaPublicKeyHashes();
            for ( vector<ByteArray*>::iterator hash_iterator = ca_public_key_hashes.begin(); hash_iterator != ca_public_key_hashes.end(); hash_iterator++ ) {
                CertificateX509* ca_certificate = this->getCaByPublicKeyHash( * ( *hash_iterator ) );

                if ( ca_certificate == NULL )
                    continue;

                for ( vector<CertificateX509*>::const_iterator it = this->my_certificates->begin(); it != this->my_certificates->end(); it++ )
                    if ( ca_certificate->isIssuerOf( ( *( *it ) ) ) )
                        return ( *it );
            }
        }

        // If the type of the certificate is not supported, then send the first of the CERT_X509_SIGNATURE certificates
        return NULL;
    }

    CertificateX509 * AuthGeneratorCert::getCaByPublicKeyHash( const ByteArray & ca_public_key_hash ) const {
        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ ) {
            if ( *( *it ) ->getPublicKeyHash() == ca_public_key_hash )
                return ( *it );
        }

        return NULL;
    }

    bool AuthGeneratorCert::addCertificate( auto_ptr<CertificateX509> certificate ) {
        if ( !certificate->hasPrivateKey() ) {
            Log::writeLockedMessage( "CertificateController", "All the user certificate must have private key", Log::LOG_ERRO, true );
            return false;
        }

        CertificateX509* issuer = this->findCa( *certificate );
        if ( issuer == NULL ) {
            Log::writeLockedMessage( "CertificateController", "Issuer not found in CA collection", Log::LOG_ERRO, true );
            return false;
        }

        this->my_certificates->push_back( certificate.release() );
        return true;
    }

    bool AuthGeneratorCert::addCertificate( auto_ptr<CertificateX509HashUrl> certificate ) {
        if ( !certificate->hasPrivateKey() ) {
            Log::writeLockedMessage( "CertificateController", "All the user certificate must have private key", Log::LOG_ERRO, true );
            return false;
        }

        CertificateX509* issuer = this->findCa( *certificate );
        if ( issuer == NULL ) {
            Log::writeLockedMessage( "CertificateController", "Issuer not found in CA collection", Log::LOG_ERRO, true );
            return false;
        }

        this->my_hash_url_certificates->push_back( certificate.release() );
        return true;
    }

    bool AuthGeneratorCert::addCaCertificate( auto_ptr<CertificateX509> certificate ) {
        if ( !certificate->isIssuerOf( *certificate ) ) {
            Log::writeLockedMessage( "CertificateController", "The certificate doesn't appear to be a CA certificate" + certificate->toString(), Log::LOG_ERRO, true );
            return false;
        }

        this->ca_certificates->push_back( certificate.release() );
        return true;
    }

    CertificateX509 * AuthGeneratorCert::findCa( const CertificateX509 & certificate ) const {
        for ( vector<CertificateX509*>::const_iterator it = this->ca_certificates->begin(); it != this->ca_certificates->end(); it++ )
            if ( ( *it ) ->isIssuerOf( certificate ) )
                return ( *it );
        return NULL;
    }


}




