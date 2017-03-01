/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj.fernandez@dif.um.es                 *
*   Alejandro Perez Mendez     alejandro_perez@dif.um.es                  *
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
#include "diffiehellmanopenssl.h"

#include <libopenikev2/bytebuffer.h>
#include <openssl/bn.h>
#include <assert.h>

namespace openikev2 {

    /*
     * Diffie-Hellman Groups defined for use with IKEv2
     */
    const char *modp_groups[] = {
        /* 0 */
        NULL,

        /* 1, MODP768 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",

        /* 2, MODP1024 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
        "FFFFFFFFFFFFFFFF",
        
        /* 3 */
        NULL,
        
        /* 4 */
        NULL,

        /* 5, MODP1536 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",

        /* 6 */
        NULL,

        /* 7 */
        NULL,

        /* 8 */
        NULL,

        /* 9 */
        NULL,

        /* 10 */
        NULL,

        /* 11 */
        NULL,

        /* 12 */
        NULL,

        /* 13 */
        NULL,

        /* 14, MODP2048 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",

        /* 15, MODP3072 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",

        /* 16, MODP4096 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
        "FFFFFFFFFFFFFFFF",

        /* 17, MODP6144 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
        "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
        "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
        "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
        "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
        "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
        "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
        "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
        "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
        "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
        "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
        "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
        "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
        "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
        "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
        "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
        "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
        "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
        "6DCC4024FFFFFFFFFFFFFFFF",

        /* 18, MODP8192 */
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
        "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
        "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
        "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
        "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
        "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
        "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
        "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
        "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
        "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
        "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
        "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
        "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
        "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
        "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
        "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
        "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
        "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
        "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
        "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
        "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
        "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF"
    };


    DiffieHellmanOpenSSL::DiffieHellmanOpenSSL( Enums::DH_ID group_id )
        : DiffieHellman(group_id)  {
        assert ( group_id <= 18 && modp_groups[ group_id ] != NULL );
        // Create a new DH instance
        this->dh = DH_new();

        // Generate DH key pair
        BN_hex2bn( &this->dh->p, modp_groups[ group_id ] );
        BN_hex2bn( &this->dh->g, "2" );
        DH_generate_key( this->dh );

        this->dh_key_size = DH_size( this->dh );

        // stores the public key
        this->public_key.reset ( new ByteArray( this->dh_key_size, 0 ) );
        uint16_t padding = this->dh_key_size - BN_num_bytes( dh->pub_key );
        uint32_t total = BN_bn2bin( dh->pub_key, &this->public_key->getRawPointer() [ padding ] );
        this->public_key->setSize( this->dh_key_size );
    }

    DiffieHellmanOpenSSL::~DiffieHellmanOpenSSL() {
        DH_free( dh );
    }

    ByteArray& DiffieHellmanOpenSSL::getPublicKey( ) const {
        return * this->public_key;
    }

    void DiffieHellmanOpenSSL::generateSharedSecret( const ByteArray& peer_public_key ) {
        // generates the shared secret
        this->shared_secret.reset ( new ByteArray( this->dh_key_size ) );
        BIGNUM *peer_key = BN_bin2bn( peer_public_key.getRawPointer(), peer_public_key.size(), NULL );
        uint16_t shared_secret_size = DH_compute_key( this->shared_secret->getRawPointer(), peer_key, this->dh );
        this->shared_secret->setSize( shared_secret_size );
        BN_free( peer_key );

        // set padding if needed
        int16_t padding = this->dh_key_size - shared_secret_size;
        if ( padding ) {
            auto_ptr<ByteBuffer> byte_buffer ( new ByteBuffer( this->dh_key_size ) );
            byte_buffer->fillBytes( padding, 0 );
            byte_buffer->writeByteArray( *this->shared_secret );
            this->shared_secret = byte_buffer;
        }
    }

    ByteArray& DiffieHellmanOpenSSL::getSharedSecret( ) const {
        return * this->shared_secret;
    }

}

