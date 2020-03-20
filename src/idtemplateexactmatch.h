/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2IDTEMPLATEEXACTMATCH_H
#define OPENIKEV2IDTEMPLATEEXACTMATCH_H

#include <libopenikev2/idtemplate.h>

namespace openikev2 {

    /**
     This class implements the IdTemplate requiring an exact match with the indicated ID
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IdTemplateExactMatch : public IdTemplate {
            /****************************** ATTRIBUTES ******************************/
        protected:
            auto_ptr<ID> id;                /**< Internal ID */

            /****************************** METHODS ******************************/
        public:
            /**
             * Creates a new IdTemplateExactMatch
             * @param id ID to perform the exact match
             */
            IdTemplateExactMatch( auto_ptr<ID> id );

            virtual bool match( const ID& id ) const;

            virtual auto_ptr<IdTemplate> clone() const;

            virtual string toStringTab( uint8_t tabs ) const;

            virtual ~IdTemplateExactMatch();

    };

}

#endif
