/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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

#include "diffiehellmanellipticcurve.h"

#ifdef HAVE_OPENSSL_ECDH_H

#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <assert.h>

#include <libopenikev2/exception.h>


namespace openikev2 {

    DiffieHellmanEllipticCurve::DiffieHellmanEllipticCurve( Enums::DH_ID group_id )
        : DiffieHellman (group_id) {
        uint16_t public_key_bytes_len;

        // creates the BN context
        this->bn_ctx = BN_CTX_new();

        // creates the EC_KEY object
        switch ( group_id ) {
            case 19:
                this->ec_key = EC_KEY_new_by_curve_name( NID_X9_62_prime256v1 );
                public_key_bytes_len = 32;
                break;
            case 20:
                this->ec_key = EC_KEY_new_by_curve_name( NID_secp384r1 );
                public_key_bytes_len = 48;
                break;
            case 21:
                this->ec_key = EC_KEY_new_by_curve_name( NID_secp521r1 );
                public_key_bytes_len = 66;
                break;
            default:
                assert ( "Invalid EC group" && 0 );
        }

        // Generates the keys
        if ( !EC_KEY_generate_key( this->ec_key ) )
            throw Exception( "Error generating EC key" );

        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();

        if ( !EC_POINT_get_affine_coordinates_GFp( EC_KEY_get0_group( this->ec_key ), EC_KEY_get0_public_key( this->ec_key ), x, y, this->bn_ctx ) )
            throw Exception( "Error obtaining affine coordinates" );

        // stores the public key
        uint8_t temp[public_key_bytes_len];
        auto_ptr<ByteBuffer> public_key ( new ByteBuffer( public_key_bytes_len * 2 ) );

        // put X value into temp variable
        uint32_t len = BN_bn2bin( x, temp );

        // writes X padding
        public_key->fillBytes( public_key_bytes_len - len, 0 );
        public_key->writeBuffer( temp, len );

        // put Y value into temp variable
        len = BN_bn2bin( y, temp );

        // writes X padding
        public_key->fillBytes( public_key_bytes_len - len, 0 );
        public_key->writeBuffer( temp, len );

        BN_free(x);
        BN_free(y);

        this->public_key = public_key;
    }

    ByteArray & DiffieHellmanEllipticCurve::getPublicKey() const {
        return *this->public_key;
    }

    void DiffieHellmanEllipticCurve::generateSharedSecret( const ByteArray & peer_public_key ) {
        if ( peer_public_key.size() != this->public_key->size() )
            throw Exception( "Invalid public key size" );

        // read the peer X,Y values
        BIGNUM *x = BN_bin2bn( peer_public_key.getRawPointer(), peer_public_key.size() / 2, NULL );
        BIGNUM *y = BN_bin2bn( peer_public_key.getRawPointer() + peer_public_key.size() / 2, peer_public_key.size() / 2, NULL );

        // obtains the peer EC_POINT
        EC_POINT* peer_point = EC_POINT_new( EC_KEY_get0_group( this->ec_key ) );
        if ( !EC_POINT_set_affine_coordinates_GFp( EC_KEY_get0_group( this->ec_key ), peer_point, x, y, this->bn_ctx ) )
            throw Exception( "Error obtaining peer EC_KEY value" );

        uint16_t alen = peer_public_key.size();
        uint8_t abuf [peer_public_key.size()];
        uint16_t aout = ECDH_compute_key( abuf, alen, peer_point, this->ec_key, NULL );

        BN_free(x);
        BN_free(y);
        EC_POINT_free(peer_point);

        this->shared_secret.reset ( new ByteArray( abuf, aout ) );
    }

    ByteArray & DiffieHellmanEllipticCurve::getSharedSecret() const {
        return *this->shared_secret;
    }

    DiffieHellmanEllipticCurve::~DiffieHellmanEllipticCurve() {
        BN_CTX_free( this->bn_ctx );
        EC_KEY_free( this->ec_key );
    }
}

#endif
