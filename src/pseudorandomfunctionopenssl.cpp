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
