/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
 *                                                                         *
 *   This software may be modified and distributed under the terms         *
 *   of the Apache license.  See the LICENSE file for details.             *
 ***************************************************************************/
#ifndef OPENIKEV2IKESACONTROLLERIMPLOPENIKE_H
#define OPENIKEV2IKESACONTROLLERIMPLOPENIKE_H

#include <libopenikev2/ikesacontroller.h>
#include <libopenikev2/threadcontroller.h>

namespace openikev2 {
    class IkeSaExecuter;

    /**
     This class implements the abstract class IkeSaControllerImpl
     @author Alejandro Perez Mendez, Pedro J. Fernandez Ruiz <alex@um.es, pedroj@um.es>
    */
    class IkeSaControllerImplOpenIKE : public IkeSaControllerImpl {
            friend class IkeSaExecuter;

            /****************************** ATTRIBUTES ******************************/
        protected:
            map <uint64_t, IkeSa*> ike_sa_collection;               /**< Active IKE_SA collection */
            deque<IkeSa*> scheduled_ike_sa_collection;              /**< IKE SAs waiting for a free IkeSaExecuter */
            map <uint64_t, bool> scheduled_ike_sa_map;              /**< Map to determine wich IKE SA is already in the waiting queue*/
            auto_ptr<Condition> condition_ike_sa;                   /**< Condition to synchronize the IkeSaExecuters */
            bool exiting;                                           /**< Mark if the we want to exit */
            uint32_t half_open_counter;                             /**< Half open IKE SA counter */
            auto_ptr<Mutex> mutex_half_open_counter;                /**< Mutex to control half-open counter accesses */
            auto_ptr<Mutex> mutex_spi;
            uint64_t current_spi;


            /****************************** METHODS ******************************/
        protected:
            /**
             * Gets the next IkeSa from the schedule queue
             * @return An IkeSa schedule for executing
             */
            virtual IkeSa& getScheduledIkeSa(  );

            /**
             * Adds an IkeSa to the schedule queue (if it is not already on it)
             * This method needs that the caller locks the mutex on the scheduled collection
             */
            virtual void scheduleIkeSa( IkeSa& ike_sa );

            /**
             * Check the state of the IkeSa after command execution.
             * If the IkeSa has been closed, then it is removed from the collection.
             * If the IkeSa has more commands to be executed, then it is re-scheduled for execution
             * @param ike_sa IkeSa to be checked
             * @param delete_ike_sa Indicates if the IkeSa wants has been closed
             */
            virtual void checkIkeSa( IkeSa& ike_sa, bool delete_ike_sa );

            /**
            * Removes the IkeSa from the collection and deletes it
            * @param ike_sa IkeSa to be deleted
            */
            virtual void deleteIkeSaController( IkeSa& ike_sa );

            virtual bool pushCommandByAddress( const IpAddress& addr, const IpAddress& peer_addr, auto_ptr<Command> command, bool priority );

            virtual IkeSa *getIkeSaByAddress( const IpAddress& addr, const IpAddress& peer_addr );


        public:
            IkeSaControllerImplOpenIKE ( uint16_t num_command_executer );

            virtual void incHalfOpenCounter();

            virtual void decHalfOpenCounter();

            virtual bool useCookies();

            virtual uint64_t nextSpi();

            virtual void addIkeSa( auto_ptr<IkeSa> ike_sa );

            virtual void requestChildSa( IpAddress& ike_sa_src_addr, IpAddress& ike_sa_dst_addr, auto_ptr<ChildSaRequest> child_sa_request );

            virtual void requestChildSaMobility( IpAddress& ike_sa_src_addr, IpAddress& ike_sa_dst_addr, auto_ptr<ChildSaRequest> child_sa_request, IpAddress& ike_sa_coa_addr, bool is_ha );

            virtual bool pushCommandByIkeSaSpi( uint64_t spi, auto_ptr<Command> command, bool priority );

            virtual IkeSa* getIkeSaByIkeSaSpi( uint64_t spi);

            virtual bool pushCommandByChildSaSpi( uint32_t spi, auto_ptr<Command> command, bool priority );

            virtual void exit();

            virtual bool isExiting();

            virtual ~IkeSaControllerImplOpenIKE();
    };

}

#endif
