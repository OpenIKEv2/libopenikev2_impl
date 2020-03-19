/***************************************************************************
*   Copyright (C) 2005 by                                                 *
*   Alejandro Perez Mendez     alex@um.es                                 *
*   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
*                                                                         *
*   This software may be modified and distributed under the terms         *
*   of the Apache license.  See the LICENSE file for details.             *
***************************************************************************/
#ifndef OPENIKEV2PSEUDORANDOMFUNCTION_OPENSSL_H
#define OPENIKEV2PSEUDORANDOMFUNCTION_OPENSSL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <libopenikev2/pseudorandomfunction.h>
#include <libopenikev2/transform.h>
#include <openssl/evp.h>


namespace openikev2 {

    /**
        This class implements the PseudoRandomFunction abstract class
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class PseudoRandomFunctionOpenSSL : public PseudoRandomFunction {

            /****************************** METHODS ******************************/
        protected:
            EVP_MD *prf_evp;              /**< OpenSSL representation of the PRF algorithm */

            /****************************** METHODS ******************************/
        public:
            PseudoRandomFunctionOpenSSL( Enums::PRF_ID prf_algo );

            virtual auto_ptr<ByteArray> prf( const ByteArray& key, const ByteArray& data ) const;

            virtual ~PseudoRandomFunctionOpenSSL();

    };

}

#endif
