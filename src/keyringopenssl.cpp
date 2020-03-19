/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "keyringopenssl.h"

#include "pseudorandomfunctionopenssl.h"

#include <assert.h>

namespace openikev2 {

    KeyRingOpenSSL::KeyRingOpenSSL( const Proposal& proposal, const PseudoRandomFunction& prf ) {
        Transform * encr_transform = proposal.getFirstTransformByType( Enums::ENCR );
        Transform *integ_transform = proposal.getFirstTransformByType( Enums::INTEG );
        this->prf = (PseudoRandomFunction*) &prf;

        // sets the encr key size
        if ( encr_transform == NULL )
            this->encr_key_size = 0;
        else {
            switch ( encr_transform->id ) {
                case Enums::ENCR_DES :
                    this->encr_key_size = 8;
                    break;
                case Enums::ENCR_3DES :
                    this->encr_key_size = 24;
                    break;
                case Enums::ENCR_AES_CBC :
                    assert( encr_transform->attributes->size() == 1 );
                    assert( encr_transform->attributes->front() ->isTV );
                    assert( encr_transform->attributes->front() ->type == Enums::ATTR_KEY_LEN );

                    // In Transform attribute, KEY_LEN is specified in bits, but encr_size is expected in bytes
                    this->encr_key_size = encr_transform->attributes->front() ->TVvalue / 8;
                    break;
                default:
                    assert( "Unsupported encr algorithm" && 0 );
            }
        }

        // sets the integ key size
        if ( integ_transform == NULL )
            this->integ_key_size = 0;
        else {
            switch ( integ_transform->id ) {
                case Enums::AUTH_HMAC_MD5_96 :
                    this->integ_key_size = 16;
                    break;
                case Enums::AUTH_HMAC_SHA1_96 :
                    this->integ_key_size = 20;
                    break;
                default:
                    assert( 0 );
            }
        }


    }

    KeyRingOpenSSL::~KeyRingOpenSSL() {}

}





