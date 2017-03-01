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
        @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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
