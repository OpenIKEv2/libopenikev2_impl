/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2IDTEMPLATEDOMAINNAME_H
#define OPENIKEV2IDTEMPLATEDOMAINNAME_H

#include <libopenikev2/idtemplate.h>

namespace openikev2 {

    /**
     This class implements the IdTemplate abstract class, requiring that the type was RFC822 or FQDN and that the domain was the indicated one
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IdTemplateDomainName : public IdTemplate {
            /****************************** ATTRIBUTES ******************************/
        protected:
            string domainname;                  /**< Domain name */

            /****************************** METHODS ******************************/
        public:
            IdTemplateDomainName( string domainname );

            virtual bool match( const ID& id ) const;

            virtual auto_ptr<IdTemplate> clone() const;

            virtual string toStringTab( uint8_t tabs ) const;

            virtual ~IdTemplateDomainName();

    };

}

#endif
