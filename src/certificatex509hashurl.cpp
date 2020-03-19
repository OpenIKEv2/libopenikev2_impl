/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "certificatex509hashurl.h"

#include <assert.h>
#include <libopenikev2/utils.h>
#include <libopenikev2/exception.h>
#include "utilsimpl.h"

#include <openssl/pem.h>

// extern "C" {
// #include <http_fetcher.h>
// }

namespace openikev2 {

    MutexPosix CertificateX509HashUrl::mutex;

    CertificateX509HashUrl::CertificateX509HashUrl( string url, string privatekey_filename ) {
        this->downloadCertificate( url );
        this->url = url;
        this->public_key = X509_get_pubkey( this->certificate );
        this->private_key = NULL;

        FILE* privatekey_file = fopen( privatekey_filename.c_str(), "rb" );

        if ( privatekey_file == NULL )
            throw Exception( "Cannot open private key file: <" + privatekey_filename + ">" );

        this->private_key = PEM_read_PrivateKey( privatekey_file, NULL, NULL, NULL );

        if ( private_key == NULL )
            throw Exception( "Error reading private key file: <" + privatekey_filename + ">" );

        fclose( privatekey_file );
    }

    CertificateX509HashUrl::CertificateX509HashUrl( const CertificateX509HashUrl & other ) : CertificateX509( other ) {
        this->url = other.url;
    }

    CertificateX509HashUrl::CertificateX509HashUrl( ByteBuffer& byte_buffer ) {
        if ( byte_buffer.size() <= 20 )
            throw ParsingException( "Buffer is too small to contain a HASH & URL X509 certificate" );

        auto_ptr<ByteArray> received_hash = byte_buffer.readByteArray( 20 );
        auto_ptr<ByteArray> received_url = byte_buffer.readByteArray( byte_buffer.size() );

        this->url.assign( ( const char* ) received_url->getRawPointer(), received_url->size() );
        this->downloadCertificate( this->url );


        if ( ! ( *this->getFingerPrint() == *received_hash ) )
            throw ParsingException( "Invalid downloaded certificate: hash doesn't match" );

        this->public_key = X509_get_pubkey( this->certificate );
        this->private_key = NULL;
    }


CertificateX509HashUrl::~CertificateX509HashUrl() {}

    void CertificateX509HashUrl::downloadCertificate( string url ) {
//         uint8_t * buffer = NULL;

//         CertificateX509HashUrl::mutex.acquire();
//         int32_t rv = http_fetch( url.c_str(), ( char** ) & buffer );
//         CertificateX509HashUrl::mutex.release();

//         if ( rv < 0 )
//             throw Exception( "Error downloading HASH & URL certificate: " + UtilsImpl::charToString( ( char* ) http_strerror() ) );

//         ByteArray der_certificate( buffer, rv, rv, true );
// #if OPENSSL_VERSION_NUMBER >= 0x00908000L
//         this->certificate = d2i_X509( NULL, ( const unsigned char** ) & buffer, rv );
// #else
//         this->certificate = d2i_X509( NULL, &buffer, rv );
// #endif

//         if ( this->certificate == NULL )
//             throw ParsingException( "Error parsing certificate X509. Check if it exists and it is in DER format" );
    }

    string CertificateX509HashUrl::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<CERTIFICATE_X509_HASH> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "url=" << this->url << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "subject_name=" << this->getSubjectName() << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "der_subject_name=" << this->getDerSubjectName() ->toStringTab( tabs + 1 ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "issuer_name=" << this->getIssuerName() << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "public_key=" << this->getPublicKey() ->toStringTab( tabs + 1 ) << "\n";

        if ( this->private_key )
            oss << Printable::generateTabs( tabs + 1 ) << "private_key=" << this->getPrivateKey() ->toStringTab( tabs + 1 ) << "\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    void CertificateX509HashUrl::getBinaryRepresentation( ByteBuffer& byte_buffer ) {
        byte_buffer.writeByteArray( *this->getFingerPrint() );
        byte_buffer.writeBuffer( this->url.c_str(), this->url.size() );
    }

    auto_ptr<CertificateX509> CertificateX509HashUrl::clone( ) {
        return auto_ptr<CertificateX509> ( new CertificateX509HashUrl( *this ) );
    }

    auto_ptr< Payload_CERT > CertificateX509HashUrl::getPayloadCert( ) const {
        return auto_ptr<Payload_CERT> ( new Payload_CERT( Enums::CERT_HASH_URL, this->getPublicKey() ) );
    }
}

