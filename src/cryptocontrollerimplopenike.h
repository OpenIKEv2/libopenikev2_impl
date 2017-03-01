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
#ifndef CRYPTOCONTROLLERIMPL_OPENIKE_H
#define CRYPTOCONTROLLERIMPL_OPENIKE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/cryptocontrollerimpl.h>
#include <libopenikev2/alarmable.h>
#include <libopenikev2/mutex.h>

namespace openikev2 {

    /**
        This class implements the CryptoControllerImpl abstract class
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
    */
    class CryptoControllerImplOpenIKE : public CryptoControllerImpl, public Alarmable {

            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<Mutex> mutex_cookie_secret;    /**< Mutex to control cookie secret access */
            auto_ptr<ByteArray> cookie_secret;      /**< Secret used in the cookie generation */
            uint16_t secret_version;                /**< Secret version */
            bool used_secret;                       /**< Secret uses. */
            auto_ptr<Random> random;                /**< Random object used in the secret generation */
            auto_ptr<Alarm> alarm_cookies_secret;   /**< Alarm to regenerate cookie secret periodically */

            static vector<pthread_mutex_t> openssl_mutex; /**< Mutex collection for openssl */
            /****************************** METHODS ******************************/
        protected:
            /**
             * Sets up the openssl thread configuration
             */
            static void opensslThreadSetup();
            
            /**
             * Openssl locking callback
             * @param mode Locking or unlocking
             * @param n Number of lock
             * @param file File being locking 
             * @param line Line in the file
             */
            static void pthreadsLockingCallback(int mode, int n, char *file, int line );
            
            /**
             * Openssl thread id callback
             * @return Thread id
             */
            static unsigned long pthreadsThreadIdCallback();
        
        public:
            /**
             * Creates a new CryptoControllerImplOpenIKE
             */
            CryptoControllerImplOpenIKE();

            virtual auto_ptr<DiffieHellman> getDiffieHellman( Enums::DH_ID group );

            virtual auto_ptr<Cipher> getCipher( Proposal& proposal, auto_ptr<ByteArray> encr_key, auto_ptr<ByteArray> integ_key );

            virtual auto_ptr<Random> getRandom();

            virtual auto_ptr<PseudoRandomFunction> getPseudoRandomFunction( Transform& tranform );

            virtual auto_ptr<KeyRing> getKeyRing( Proposal& proposal, const PseudoRandomFunction& prf );

            virtual auto_ptr<Payload_NOTIFY> generateCookie( Message& message );

            virtual void notifyAlarm( Alarm & alarm );

            virtual ~CryptoControllerImplOpenIKE();

    };
};
#endif
