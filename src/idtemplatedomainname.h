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
#ifndef OPENIKEV2IDTEMPLATEDOMAINNAME_H
#define OPENIKEV2IDTEMPLATEDOMAINNAME_H

#include <libopenikev2/idtemplate.h>

namespace openikev2 {

    /**
     This class implements the IdTemplate abstract class, requiring that the type was RFC822 or FQDN and that the domain was the indicated one
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alejandro_perez@dif.um.es, pedroj.fernandez@dif.um.es>
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
