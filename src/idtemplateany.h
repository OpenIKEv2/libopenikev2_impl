/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2IDTEMPLATEANY_H
#define OPENIKEV2IDTEMPLATEANY_H

#include <libopenikev2/idtemplate.h>

namespace openikev2 {

    /**
     This class implements the IdTemplate abstract class, martching any ID with the specified id type. If no id type is specified, it will match all the IDs
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IdTemplateAny : public IdTemplate{
            /****************************** ATTRIBUTES ******************************/
        protected:
            Enums::ID_TYPE id_type;         /**< ID type */
            bool match_type;                /**< Indicates if we want to match the type */

            /****************************** METHODS ******************************/
        public:
            IdTemplateAny();

            IdTemplateAny( Enums::ID_TYPE id_type );

            virtual bool match( const ID& id ) const;

            virtual auto_ptr<IdTemplate> clone() const;

            virtual string toStringTab( uint8_t tabs ) const;

            virtual ~IdTemplateAny();

    };

}

#endif
