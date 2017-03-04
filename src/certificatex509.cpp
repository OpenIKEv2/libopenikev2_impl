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
#include "certificatex509.h"

#include <libopenikev2/exception.h>
#include <libopenikev2/utils.h>
#include <openssl/pem.h>
#include <string.h>

#include <vector>

namespace openikev2 {

    CertificateX509::CertificateX509( ) {
        this->public_key = NULL;
        this->private_key = NULL;
        this->certificate = NULL;
    }

    CertificateX509::CertificateX509( string cert_filename, string privatekey_filename ) {
        // Read certificate file
        FILE * cert_file = fopen( cert_filename.c_str(), "rb" );

        if ( cert_file == NULL )
            throw Exception( "Cannot open certificate file: <" + cert_filename + ">" );

        this->certificate = PEM_read_X509( cert_file, NULL, NULL, NULL );

        fclose( cert_file );

        if ( certificate == NULL )
            throw Exception( "Error reading certificate file: <" + cert_filename + ">" );

        this->public_key = X509_get_pubkey( this->certificate );

        this->private_key = NULL;

        // if there is private key..
        if ( privatekey_filename != "" ) {
            FILE * privatekey_file = fopen( privatekey_filename.c_str(), "rb" );

            if ( privatekey_file == NULL )
                throw Exception( "Cannot open private key file: <" + privatekey_filename + ">" );

            this->private_key = PEM_read_PrivateKey( privatekey_file, NULL, NULL, NULL );

            if ( private_key == NULL )
                throw Exception( "Error reading private key file: <" + privatekey_filename + ">" );

            fclose( privatekey_file );
        }
    }

    CertificateX509::CertificateX509( const CertificateX509 & other ){
        // clones the X509 certificate
        this->certificate = X509_dup( other.certificate );

        this->public_key = NULL;
        this->private_key = NULL;

        // clones the other public key
        auto_ptr<ByteArray> other_public_key = other.getPublicKey();
        uint8_t* raw_data = other_public_key->getRawPointer();
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        d2i_PublicKey( other.public_key->type, &this->public_key, ( const unsigned char** ) & raw_data, other_public_key->size() );
#else
        d2i_PublicKey( other.public_key->type, &this->public_key, & raw_data, other_public_key->size() );
#endif

        // Clones the private key
        this->private_key = NULL;
        if ( other.private_key != NULL ) {
            auto_ptr<ByteArray> other_private_key = other.getPrivateKey();
            // Establish the private key value
            uint8_t* raw_data = other_private_key->getRawPointer();
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
            d2i_PrivateKey( other.private_key->type, &this->private_key, ( const unsigned char** ) & raw_data, other_private_key->size() );
#else
            d2i_PrivateKey( other.private_key->type, &this->private_key, &raw_data, other_private_key->size() );
#endif

        }
    }

    CertificateX509::CertificateX509( ByteBuffer& der_binary_representation ) {
        // reads certificate
        uint8_t * raw_pointer = der_binary_representation.getRawPointer();
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
        this->certificate = d2i_X509( NULL, ( const unsigned char** ) & raw_pointer, der_binary_representation.size() );
#else
        this->certificate = d2i_X509( NULL, & raw_pointer, der_binary_representation.size() );
#endif

        if ( certificate == NULL )
            throw ParsingException( "Error parsing certificate X509. It must be in DER format" );

        this->public_key = X509_get_pubkey( this->certificate );
        this->private_key = NULL;
    }

    CertificateX509::~CertificateX509() {
        X509_free( this->certificate );
        EVP_PKEY_free( this->public_key );
        EVP_PKEY_free( this->private_key );
    }

    void CertificateX509::getBinaryRepresentation( ByteBuffer& byte_buffer ) {
        uint8_t * temp = NULL;
        int32_t len = i2d_X509( this->certificate, &temp );
        if ( len < 0 )
            throw Exception( "Error generating X509 certificate binary representation." );

        // creates a ByteArray owning the memory
        ByteArray byte_array( temp, len, len, true );

        // writes into the ByteBuffer
        byte_buffer.writeByteArray( byte_array );
    }

    auto_ptr<ByteArray> CertificateX509::getPrivateKey( ) const {
        assert ( this->private_key != NULL );

        uint8_t* buffer = NULL;
        int32_t len = i2d_PrivateKey( this->private_key, &buffer );
        if ( len < 0 )
            throw Exception( "Illegal Private key in certificate" );

        return auto_ptr<ByteArray> ( new ByteArray( buffer, len, len, true ) );
    }

    auto_ptr<ByteArray> CertificateX509::getPublicKeyHash( ) const {
        auto_ptr<ByteArray> result ( new ByteArray( 20 ) );

        uint32_t len;
        X509_pubkey_digest( this->certificate, EVP_sha1(), result->getRawPointer(), &len );
        assert( len == 20 );

        result->setSize( 20 );
        return result;
    }

    auto_ptr< ByteArray > CertificateX509::getFingerPrint( ) const {
        auto_ptr<ByteArray> result ( new ByteArray( 20 ) );

        uint32_t len;
        X509_digest( this->certificate, EVP_sha1(), result->getRawPointer(), &len );
        assert( len == 20 );

        result->setSize( 20 );
        return result;
    }

    auto_ptr<ByteArray> CertificateX509::getPublicKey( ) const {
        uint8_t * buffer = NULL;
        int32_t len = i2d_PublicKey( this->public_key, &buffer );
        if ( len < 0 )
            throw Exception( "Illegal Public key in certificate" );

        return auto_ptr<ByteArray> ( new ByteArray( buffer, len, len, true ) );
    }

    auto_ptr<CertificateX509> CertificateX509::clone( ) const {
        return auto_ptr<CertificateX509> ( new CertificateX509( *this ) );
    }

    Enums::AUTH_METHOD CertificateX509::getAuthMethod( ) const {
        switch ( this->public_key->type ) {
            case EVP_PKEY_RSA:
            case EVP_PKEY_RSA2:
                return Enums::AUTH_METHOD_RSA;
            case EVP_PKEY_DSA:
            case EVP_PKEY_DSA1:
            case EVP_PKEY_DSA2:
            case EVP_PKEY_DSA3:
            case EVP_PKEY_DSA4:
                return Enums::AUTH_METHOD_DSS;
            default:
                assert( "X509 auth method not supported" && 0 );
        };
    }

    auto_ptr<ByteArray> CertificateX509::getDerSubjectName( ) const {
        X509_NAME * name = X509_get_subject_name( this->certificate );
        uint8_t *buffer = NULL;
        uint16_t len = i2d_X509_NAME( name, &buffer );
        return auto_ptr<ByteArray> ( new ByteArray ( buffer, len, len, true ) );
    }


    string CertificateX509::toStringTab( uint8_t tabs ) const {
        ostringstream oss;

        oss << Printable::generateTabs( tabs ) << "<CERTIFICATE_X509> {\n";

        oss << Printable::generateTabs( tabs + 1 ) << "subject_name=" << this->getSubjectName() << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "der_subject_name=" << this->getDerSubjectName() ->toStringTab( tabs + 2 ) << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "issuer_name=" << this->getIssuerName() << "\n";

        oss << Printable::generateTabs( tabs + 1 ) << "public_key=" << this->getPublicKey() ->toStringTab( tabs + 2 ) << "\n";

        if ( this->private_key )
            oss << Printable::generateTabs( tabs + 1 ) << "private_key=" << this->getPrivateKey() ->toStringTab( tabs + 2 ) << "\n";

        oss << Printable::generateTabs( tabs ) << "}\n";

        return oss.str();
    }

    bool CertificateX509::isIssuerOf( const CertificateX509 & other ) const {
        X509_NAME * my_subject_name = X509_get_subject_name( this->certificate );
        X509_NAME * other_issuer_name = X509_get_issuer_name( other.certificate );

        if ( X509_NAME_cmp( my_subject_name, other_issuer_name ) == 0 )
            return true;

        return false;
    }

    auto_ptr<ByteArray> CertificateX509::signData( const ByteArray & data ) const {
        assert ( this->private_key != NULL );

        // creates the buffer
        auto_ptr<ByteArray> result ( new ByteArray ( EVP_PKEY_size( this->private_key ) ) );

        EVP_MD_CTX ctx;

        int16_t rv = EVP_SignInit( &ctx, EVP_sha1() );
        assert ( rv >= 0 );

        rv = EVP_SignUpdate( &ctx, data.getRawPointer(), data.size() );
        assert ( rv >= 0 );

        uint32_t len = 0;
        rv = EVP_SignFinal( &ctx, result->getRawPointer(), &len, this->private_key );
        assert ( rv >= 0 );
        result->setSize( len );

        EVP_MD_CTX_cleanup( &ctx );

        return result;
    }

    bool CertificateX509::verifyData( const ByteArray & data, const ByteArray & signature ) {
        EVP_MD_CTX ctx;

        int16_t rv = EVP_VerifyInit( &ctx, EVP_sha1() );
        assert ( rv >= 0 );

        rv = EVP_VerifyUpdate( &ctx, data.getRawPointer(), data.size() );
        assert ( rv >= 0 );

        rv = EVP_VerifyFinal( &ctx, signature.getRawPointer(), signature.size(), this->public_key );
        assert ( rv >= 0 );

        EVP_MD_CTX_cleanup( &ctx );

        return rv;
    }

    string CertificateX509::getSubjectName( ) const {
        X509_NAME * name = X509_get_subject_name( this->certificate );

        char buffer[200];
        char *p = X509_NAME_oneline( name, buffer, 200 );

        if ( p != NULL )
            return p;

        return "";
    }

    string CertificateX509::getIssuerName( ) const {
        X509_NAME * name = X509_get_issuer_name( this->certificate );

        char buffer[200];
        char *p = X509_NAME_oneline( name, buffer, 200 );

        if ( p != NULL )
            return p;

        return "";
    }

    bool CertificateX509::hasId( const ID & id ) const {
        switch ( id.id_type ) {

            case Enums::ID_RFC822_ADDR: {
                    // creates the string representation of the ID
                    string id_str( ( char* ) id.id_data->getRawPointer(), id.id_data->size() );

                    // if the ID is contained in the Subject name, then return TRUE
                    X509_NAME * subject_name = X509_get_subject_name( this->certificate );
                    char temp[ 256 ];
                    int16_t rv = X509_NAME_get_text_by_NID( subject_name, NID_pkcs9_emailAddress, temp, 256 );
                    if ( rv > 0 )
                        if ( id_str == temp )
                            return true;

                    // else, tries with the subjectAltNames
                    STACK_OF( GENERAL_NAME ) * gens = static_cast < STACK_OF( GENERAL_NAME ) * > ( X509_get_ext_d2i( this->certificate, NID_subject_alt_name, NULL, NULL ) );
                    if ( gens != NULL ) {
                        for ( int index = 0; index < sk_GENERAL_NAME_num( gens ); index++ ) {
                            GENERAL_NAME *gen = sk_GENERAL_NAME_value( gens, index );
                            if ( gen->type == GEN_EMAIL ) {
                                string emailAltName = ( const char* ) ASN1_STRING_data ( gen->d.rfc822Name );
                                if ( emailAltName == id_str )
                                    return true;
                            }
                        }
                    }
                    sk_GENERAL_NAME_free( gens );
                    return false;
                }

            case Enums::ID_FQDN: {
                    // creates the string representation of the ID
                    string id_str( ( char* ) id.id_data->getRawPointer(), id.id_data->size() );

                    // tries to find it in the subjectAltNames
                    STACK_OF( GENERAL_NAME ) * gens = static_cast < STACK_OF( GENERAL_NAME ) * > ( X509_get_ext_d2i( this->certificate, NID_subject_alt_name, NULL, NULL ) );
                    if ( gens != NULL ) {
                        for ( int index = 0; index < sk_GENERAL_NAME_num( gens ); index++ ) {
                            GENERAL_NAME *gen = sk_GENERAL_NAME_value( gens, index );
                            if ( gen->type == GEN_DNS ) {
                                string dnsAltName = ( const char* ) ASN1_STRING_data ( gen->d.dNSName );
                                if ( dnsAltName == id_str )
                                    return true;
                            }
                        }
                    }
                    sk_GENERAL_NAME_free( gens );
                    return false;
                }

            case Enums::ID_IPV4_ADDR: {
                    // tries to find it in the subjectAltNames
                    STACK_OF( GENERAL_NAME ) * gens = static_cast < STACK_OF( GENERAL_NAME ) * > ( X509_get_ext_d2i( this->certificate, NID_subject_alt_name, NULL, NULL ) );
                    if ( gens != NULL ) {
                        for ( int index = 0; index < sk_GENERAL_NAME_num( gens ); index++ ) {
                            GENERAL_NAME *gen = sk_GENERAL_NAME_value( gens, index );
                            if ( gen->type == GEN_IPADD ) {
                                char * ipaddAltName = ( char* ) ASN1_STRING_data ( gen->d.iPAddress );
                                if ( ASN1_STRING_length ( gen->d.iPAddress ) == 4 && memcmp( ipaddAltName, id.id_data->getRawPointer(), 4 ) == 0 )
                                    return true;
                            }
                        }
                    }
                    sk_GENERAL_NAME_free( gens );
                    return false;
                }

            case Enums::ID_IPV6_ADDR: {
                    // tries to find it in the subjectAltNames
                    STACK_OF( GENERAL_NAME ) * gens = static_cast < STACK_OF( GENERAL_NAME ) * > ( X509_get_ext_d2i( this->certificate, NID_subject_alt_name, NULL, NULL ) );
                    if ( gens != NULL ) {
                        for ( int index = 0; index < sk_GENERAL_NAME_num( gens ); index++ ) {
                            GENERAL_NAME *gen = sk_GENERAL_NAME_value( gens, index );
                            if ( gen->type == GEN_IPADD ) {
                                char * ipaddAltName = ( char* ) ASN1_STRING_data ( gen->d.iPAddress );
                                if ( ASN1_STRING_length ( gen->d.iPAddress ) == 16 && memcmp( ipaddAltName, id.id_data->getRawPointer(), 16 ) == 0 )
                                    return true;
                            }
                        }
                    }
                    sk_GENERAL_NAME_free( gens );
                    return false;

                }

            case Enums::ID_DER_ASN1_DN: {
                    auto_ptr<ByteArray> data = this->getDerSubjectName();
                    return ( *data == *id.id_data );
                }

            default:
                return false;
        }
    }

    auto_ptr< Payload_CERT > CertificateX509::getPayloadCert( ) {
        auto_ptr<ByteBuffer> byte_buffer ( new ByteBuffer( MAX_MESSAGE_SIZE ) );
        this->getBinaryRepresentation( *byte_buffer );
        return auto_ptr<Payload_CERT> ( new Payload_CERT( Enums::CERT_X509_SIGNATURE, auto_ptr<ByteArray> ( byte_buffer ) ) );
    }

    bool CertificateX509::hasPrivateKey( ) const {
        return ( this->private_key != NULL );
    }

    X509 * CertificateX509::getInternalRepresentation( ) const {
        return this->certificate;
    }
}









