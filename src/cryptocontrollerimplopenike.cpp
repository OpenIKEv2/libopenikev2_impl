/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*   Alejandro Perez Mendez     alex@um.es                                 *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#include "cryptocontrollerimplopenike.h"

#include <libopenikev2/payload_nonce.h>
#include <libopenikev2/threadcontroller.h>
#include <libopenikev2/alarmcontroller.h>
#include <libopenikev2/configuration.h>
#include <libopenikev2/autolock.h>
#include <libopenikev2/exception.h>
#include <libopenikev2/log.h>

#include "keyringopenssl.h"
#include "diffiehellmanopenssl.h"
#include "cipheropenssl.h"
#include "randomopenssl.h"
#include "pseudorandomfunctionopenssl.h"
#include "diffiehellmanellipticcurve.h"

namespace openikev2 {

  vector<pthread_mutex_t> CryptoControllerImplOpenIKE::openssl_mutex;

  CryptoControllerImplOpenIKE::CryptoControllerImplOpenIKE() {
    CryptoControllerImplOpenIKE::opensslThreadSetup();

    // Create cookie secret and alarm
    this->mutex_cookie_secret = ThreadController::getMutex();
    this->random = this->getRandom();
    this->secret_version = 1;
    this->used_secret = false;
    this->cookie_secret = this->random->getRandomBytes( 16 );
  }

  CryptoControllerImplOpenIKE::~CryptoControllerImplOpenIKE() {
    if ( this->alarm_cookies_secret.get() )
      AlarmController::removeAlarm( *this->alarm_cookies_secret );
  }

  auto_ptr<DiffieHellman> CryptoControllerImplOpenIKE::getDiffieHellman( Enums::DH_ID group ) {
    if (group < 19)
        return auto_ptr<DiffieHellman> ( new DiffieHellmanOpenSSL( group ) );

    #ifdef HAVE_OPENSSL_ECDH_H
    else
        return auto_ptr<DiffieHellman> ( new DiffieHellmanEllipticCurve( group ) );
    #endif

  }

  auto_ptr< Cipher > CryptoControllerImplOpenIKE::getCipher( Proposal & proposal, auto_ptr< ByteArray > encr_key, auto_ptr< ByteArray > integ_key ) {
    assert( proposal.getFirstTransformByType( Enums::ENCR ) );
    assert( proposal.getFirstTransformByType( Enums::INTEG ) );

    return auto_ptr<Cipher> ( new CipherOpenSSL( (Enums::ENCR_ID) proposal.getFirstTransformByType( Enums::ENCR )->id,
                                                 (Enums::INTEG_ID) proposal.getFirstTransformByType( Enums::INTEG )->id,
                                                 encr_key,
                                                 integ_key
                                               )
                            );
  }

  auto_ptr<Random> CryptoControllerImplOpenIKE::getRandom( ) {
    return auto_ptr<Random> ( new RandomOpenSSL() );
  }

  auto_ptr< KeyRing > CryptoControllerImplOpenIKE::getKeyRing( Proposal & proposal, const PseudoRandomFunction& prf ) {
    return auto_ptr<KeyRing> ( new KeyRingOpenSSL( proposal, prf ) );
  }

  auto_ptr<PseudoRandomFunction> CryptoControllerImplOpenIKE::getPseudoRandomFunction( Transform & transform ) {
    return auto_ptr<PseudoRandomFunction> ( new PseudoRandomFunctionOpenSSL( (Enums::PRF_ID) transform.id ) );
  }

  auto_ptr< Payload_NOTIFY > CryptoControllerImplOpenIKE::generateCookie( Message & message ) {
    AutoLock auto_lock( *this->mutex_cookie_secret );

    this->used_secret = true;

    if ( this->alarm_cookies_secret.get() == NULL ) {
      auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();
      this->alarm_cookies_secret.reset( new Alarm( *this, general_conf->cookie_lifetime * 1000 ) );
      AlarmController::addAlarm( *this->alarm_cookies_secret );
      this->alarm_cookies_secret->reset();
    }

    Payload_NONCE *payload_nonce = ( Payload_NONCE* ) message.getFirstPayloadByType( Payload::PAYLOAD_NONCE );
    if ( payload_nonce == NULL )
      throw ParsingException( "Message hasn't any nonce. Cookie cannot be generated" );

    // data size = nonce_length + address_len + spi(8) + secret(16)
    ByteBuffer prf_data( payload_nonce->getNonceValue().size() + message.getSrcAddress().getIpAddress().getAddressSize() + 8 + 16 );
    prf_data.writeByteArray( payload_nonce->getNonceValue() );
    prf_data.writeByteArray( *message.getSrcAddress().getIpAddress().getBytes() );
    prf_data.writeByteArray( *message.getSrcAddress().getIpAddress().getBytes() );
    prf_data.writeByteArray( *this->cookie_secret );

    Transform prf_transform( Enums::PRF, Enums::PRF_HMAC_MD5 );
    ByteArray prf_key( "key", 3 );
    auto_ptr<PseudoRandomFunction> prf = this->getPseudoRandomFunction( prf_transform );
    auto_ptr<ByteArray> prf_result = prf->prf( prf_key, prf_data );

    auto_ptr<ByteBuffer> cookie_data( new ByteBuffer( 2 + prf_result->size() ) );
    cookie_data->writeInt16( secret_version );
    cookie_data->writeByteArray( *prf_result );

    return auto_ptr<Payload_NOTIFY> ( new Payload_NOTIFY( Payload_NOTIFY::COOKIE, Enums::PROTO_NONE, auto_ptr<ByteArray>( NULL ), auto_ptr<ByteArray> ( cookie_data ) ) );
  }

  void CryptoControllerImplOpenIKE::notifyAlarm( Alarm & alarm ) {
    AutoLock auto_lock( *this->mutex_cookie_secret );

    if ( !used_secret )
      return ;

    this->secret_version++;
    this->cookie_secret = this->random->getRandomBytes( 16 );
    this->used_secret = false;
    Log::writeLockedMessage( "CryptoController", "Cookie secret changed", Log::LOG_INFO, true );
    alarm.reset();
  }

  void CryptoControllerImplOpenIKE::opensslThreadSetup( ) {
    for ( uint32_t i = 0; i < CRYPTO_num_locks(); i++ ) {
      pthread_mutex_t mutex;
      pthread_mutex_init( &mutex, NULL );
      openssl_mutex.push_back( mutex );
    }

    CRYPTO_set_id_callback(( unsigned long( * )() ) pthreadsThreadIdCallback );
    CRYPTO_set_locking_callback(( void ( * )( int, int, const char*, int ) ) pthreadsLockingCallback );
  }

  unsigned long CryptoControllerImplOpenIKE::pthreadsThreadIdCallback( ) {
    return ( unsigned long ) pthread_self();
  }

  void CryptoControllerImplOpenIKE::pthreadsLockingCallback( int mode, int n, char *file, int line ) {
    if ( mode & CRYPTO_LOCK )
      pthread_mutex_lock( &openssl_mutex[ n ] );
    else {
      pthread_mutex_unlock( &openssl_mutex[ n ] );
    }
  }


}





