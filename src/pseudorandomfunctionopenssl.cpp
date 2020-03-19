/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "pseudorandomfunctionopenssl.h"

#include <assert.h>
#include <openssl/hmac.h>

namespace openikev2 {

    PseudoRandomFunctionOpenSSL::PseudoRandomFunctionOpenSSL( Enums::PRF_ID prf_algo ) {
        switch ( prf_algo ) {
            case Enums::PRF_HMAC_MD5:
                this->prf_evp = ( EVP_MD* ) EVP_md5();
                break;

            case Enums::PRF_HMAC_SHA1:
                this->prf_evp = ( EVP_MD* ) EVP_sha1();
                break;

            default:
                assert ( "prf function not supported" && 0 );
        }

        this->prf_size = EVP_MD_size ( this->prf_evp );
    }

    auto_ptr< ByteArray > PseudoRandomFunctionOpenSSL::prf( const ByteArray & key, const ByteArray & data ) const {
        auto_ptr<ByteArray> result ( new ByteArray( this->prf_size ) );

        uint32_t size;
        HMAC( this->prf_evp, key.getRawPointer(), key.size(), data.getRawPointer(), data.size(), result->getRawPointer(), &size );
        result->setSize( size );

        return result;
    }

    PseudoRandomFunctionOpenSSL::~PseudoRandomFunctionOpenSSL() {}
}
