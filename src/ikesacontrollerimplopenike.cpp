/***************************************************************************
 *   Copyright (C) 2005 by                                                 *
 *   Alejandro Perez Mendez     alex@um.es                                 *
 *   Pedro J. Fernandez Ruiz    pedroj@um.es                               *
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
#include "ikesacontrollerimplopenike.h"
#include "ikesaexecuter.h"

#include <libopenikev2/autolock.h>
#include <libopenikev2/log.h>
#include <libopenikev2/sendnewchildsareqcommand.h>
#include <libopenikev2/sendikesainitreqcommand.h>
#include <libopenikev2/closeikesacommand.h>
#include <libopenikev2/eventbus.h>
#include <libopenikev2/buseventcore.h>
#include <libopenikev2/buseventikesa.h>
#include <libopenikev2/configuration.h>
#include <libopenikev2/ipseccontroller.h>
#include <libopenikev2/boolattribute.h>
#include <libopenikev2/stringattribute.h>
#include <libopenikev2/networkcontroller.h>

#include "socketaddressposix.h"
#include "ipaddressopenike.h"
#include "threadposix.h"



namespace openikev2 {

    IkeSaControllerImplOpenIKE::IkeSaControllerImplOpenIKE( uint16_t num_command_executers  ) {
        // Exit process is not active
        this->exiting = false;

        this->condition_ike_sa = ThreadController::getCondition();

        this->mutex_half_open_counter = ThreadController::getMutex();

        this->mutex_spi = ThreadController::getMutex();

        this->half_open_counter = 0;

        this->current_spi = 1;

        for ( uint16_t i = 0; i < num_command_executers; i++ ) {
            IkeSaExecuter* ike_sa_executer = new IkeSaExecuter( *this, i );
            ike_sa_executer->start();
        }
        Log::writeLockedMessage( "IkeSaController", "IkeSaExecuters successfully started: [" + intToString( num_command_executers ) + "]", Log::LOG_THRD, true );
    }

    IkeSaControllerImplOpenIKE::~IkeSaControllerImplOpenIKE() {
    }

    IkeSa & IkeSaControllerImplOpenIKE::getScheduledIkeSa( ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        // waits until there is any IkeSa waiting available
        while ( this->scheduled_ike_sa_collection.size() == 0 )
            this->condition_ike_sa->wait();

        // gets the IkeSa
        IkeSa& ike_sa = *( this->scheduled_ike_sa_collection.front() );

        // removes the first IkeSa in the queue
        scheduled_ike_sa_collection.pop_front();

        return ike_sa;
    }

    void IkeSaControllerImplOpenIKE::scheduleIkeSa( IkeSa & ike_sa ) {
        // If the IKE SA is not already in the collection
        if ( !this->scheduled_ike_sa_map[ike_sa.my_spi] )
            this->scheduled_ike_sa_collection.push_back( &ike_sa );

        this->scheduled_ike_sa_map[ike_sa.my_spi] = true;

        this->condition_ike_sa->notify();
    }

    void IkeSaControllerImplOpenIKE::addIkeSa( auto_ptr<IkeSa> ike_sa ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        uint64_t spi = ike_sa->my_spi;

        Log::writeLockedMessage( "IkeSaController", "New IkeSa added: SPI=" + Printable::toHexString( &spi, 8 ) + " Count=[" + intToString( this->ike_sa_collection.size() ) + "]", Log::LOG_INFO, true );

        if ( ike_sa->hasMoreCommands() )
            this->scheduleIkeSa( *ike_sa );

        pair<uint64_t, IkeSa*> pair_to_be_included( spi, ike_sa.release() );

        this->ike_sa_collection.insert( pair_to_be_included );

    }

    void IkeSaControllerImplOpenIKE::requestChildSa( IpAddress& ike_sa_src_addr, IpAddress& ike_sa_dst_addr, auto_ptr<ChildSaRequest> child_sa_request ) {
        auto_ptr<Command> command ( new SendNewChildSaReqCommand( child_sa_request->clone() ) );

        bool exist_ike_sa = this->pushCommandByAddress( ike_sa_src_addr, ike_sa_dst_addr, command, false );

	IkeSa* current_ike_sa = this->getIkeSaByAddress(ike_sa_src_addr, ike_sa_dst_addr);

	auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

        // IF there is no IKE_SA between peers, then create a new one
	if(!exist_ike_sa) {
	    Log::writeLockedMessage( "IkeSaController", "IkeSa between IP=[" + ike_sa_src_addr.toString() + "] and IP=[" + ike_sa_dst_addr.toString() + "] does not exist. Creating a new one", Log::LOG_INFO, true );

	    // Create new IkeSa (INITIATOR)
	    auto_ptr<IkeSa> ike_sa ( new IkeSa( this->nextSpi(),
	                                        true,
	                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_src_addr.clone(), 500 ) ) ,
	                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_dst_addr.clone(), 500 ) )
	                                      ) );
	    this->incHalfOpenCounter();

	    command.reset ( new SendIkeSaInitReqCommand( child_sa_request ) );

	    ike_sa->pushCommand( command, false );

	    this->addIkeSa ( ike_sa );
	}
    }



void IkeSaControllerImplOpenIKE::requestChildSaMobility( IpAddress& ike_sa_src_addr, IpAddress& ike_sa_dst_addr, auto_ptr<ChildSaRequest> child_sa_request,  IpAddress& ike_sa_coa_addr, bool is_ha ) {

	if (is_ha){ // it is a HA

		// First, match the IKE_SA using the CoA
		auto_ptr<Command> command ( new SendNewChildSaReqCommand( child_sa_request->clone() ) );
		bool exist_ike_sa = false;
		IkeSa* current_ike_sa = this->getIkeSaByAddress( ike_sa_src_addr, ike_sa_coa_addr);
		if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)) {
			exist_ike_sa = this->pushCommandByAddress( ike_sa_src_addr, ike_sa_coa_addr, command, false );
		}
		else{
			if(current_ike_sa != NULL) {
					// Not in a IKE_SA_ESTABLISHED status, so drop the request.
					// The IKE_SA can't attend it now.
					Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy (1).", Log::LOG_WARN, true );
				        return;
			}
		}
		if (!exist_ike_sa) {
			Log::writeLockedMessage( "IkeSaController", "IkeSa between IP=[" + ike_sa_src_addr.toString() + "] and IP=[" + ike_sa_coa_addr.toString() + "] does not exist. Try again using HoA...", Log::LOG_INFO, true );
			// If not found, then use the HoA to match IKE_SA
			auto_ptr<Command> command2 ( new SendNewChildSaReqCommand( child_sa_request->clone() ) );
			current_ike_sa = this->getIkeSaByAddress(ike_sa_src_addr, ike_sa_dst_addr);
 			if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)) /* IKE_SA_ESTABLISHED */
				exist_ike_sa = this->pushCommandByAddress( ike_sa_src_addr , ike_sa_dst_addr, command2, false );
			else {
				if(current_ike_sa != NULL) {
					// Not in a IKE_SA_ESTABLISHED status, so drop the request.
					// The IKE_SA can't attend it now.
					Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy (2).", Log::LOG_WARN, true );
				        return;
				 }
				 else {	//TODO: Ask Mip6d for the HoA associated with the current CoA


				    	auto_ptr<IpAddress> hoa ( NetworkController::getHoAbyCoA(ike_sa_coa_addr) );
					if (hoa.get() == NULL){
						Log::writeLockedMessage( "NetworkController", "Droped command because no CoA matched in binding cache file.", Log::LOG_ERRO, true );
						return;
					}
				    	current_ike_sa = this->getIkeSaByAddress(ike_sa_src_addr, *hoa);
					if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)) /* IKE_SA_ESTABLISHED */
					{
						exist_ike_sa = this->pushCommandByAddress( ike_sa_src_addr, *hoa, command2, false );
					}
					else {
						if(current_ike_sa != NULL) {
							// Not in a IKE_SA_ESTABLISHED status, so drop the request.
							// The IKE_SA can't attend it now.
							Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy.", Log::LOG_WARN, true );
							return;
						}
					}
				}
			}
		}

		if (!exist_ike_sa) {

		    Log::writeLockedMessage( "IkeSaController", "IkeSa between IP=[" + ike_sa_src_addr.toString() + "] and IP=[" + ike_sa_dst_addr.toString() + "] does not exist. Creating a new one", Log::LOG_INFO, true );

		    // Create new IkeSa (RESPONDER) based on CoA, but it must be changed to HoA after IKE_AUTH exchange
		    auto_ptr<IkeSa> ike_sa ( new IkeSa( this->nextSpi(),
		                                        true,
		                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_src_addr.clone(), 500 ) ) ,
		                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_coa_addr.clone(), 500 ) )
		                                      ) );
		    this->incHalfOpenCounter();

		    command.reset ( new SendIkeSaInitReqCommand( child_sa_request ) );

		    ike_sa->pushCommand( command, false );

		    this->addIkeSa ( ike_sa );
		}
		else {
			if (child_sa_request->mode == Enums::TUNNEL_MODE){
				Log::writeLockedMessage( "NetworkController", "Soy HA y cambio mi CoA a IP=[" + ike_sa_coa_addr.toString() + "]", Log::LOG_WARN, true );
				auto_ptr<IpAddress> coa (ike_sa_coa_addr.clone());
				current_ike_sa->care_of_address.reset(new SocketAddressPosix(coa,500));
			}

		}



	}
	else{ // it is a MR

		// First, match the IKE_SA using the CoA
		auto_ptr<Command> command ( new SendNewChildSaReqCommand( child_sa_request->clone() ) );
		IkeSa* current_ike_sa = this->getIkeSaByAddress(ike_sa_coa_addr, ike_sa_dst_addr);
		bool exist_ike_sa = false;
		if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)){
			exist_ike_sa = this->pushCommandByAddress( ike_sa_coa_addr, ike_sa_dst_addr, command, false );
		}
		else {

			if(current_ike_sa != NULL) {
				// Not in a IKE_SA_ESTABLISHED status, so drop the request.
				// The IKE_SA can't attend it now.
				Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy (1).", Log::LOG_WARN, true );
			        return;
			 }

		}

		if (!exist_ike_sa) {
			Log::writeLockedMessage( "IkeSaController", "IkeSa between IP=[" + ike_sa_coa_addr.toString() + "] and IP=[" + ike_sa_dst_addr.toString() + "] does not exist. Try again using HoA...", Log::LOG_INFO, true );
			// If not found, then use the HoA to match IKE_SA
			auto_ptr<Command> command2 ( new SendNewChildSaReqCommand( child_sa_request->clone() ) );

			current_ike_sa = this->getIkeSaByAddress(ike_sa_src_addr, ike_sa_dst_addr);
 			if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)) /* IKE_SA_ESTABLISHED */
			{
				exist_ike_sa = this->pushCommandByAddress( ike_sa_src_addr , ike_sa_dst_addr, command2, false );
			}
			else {
				if(current_ike_sa != NULL) {
					// Not in a IKE_SA_ESTABLISHED status, so drop the request.
					// The IKE_SA can't attend it now.
					Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy (2).", Log::LOG_WARN, true );
				        return;
				 }
				 else {
			 		auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

					StringAttribute* string_attr = general_conf->attributemap->getAttribute<StringAttribute>( "home_address" );
					if (string_attr!=NULL ){
					    	auto_ptr<IpAddress> hoa ( new IpAddressOpenIKE( string_attr->value ));
					    	current_ike_sa = this->getIkeSaByAddress(*hoa, ike_sa_dst_addr);
						if ((current_ike_sa != NULL) && (current_ike_sa->getState()==10)) /* IKE_SA_ESTABLISHED */
						{
							exist_ike_sa = this->pushCommandByAddress( *hoa, ike_sa_dst_addr, command2, false );
						}
						else {
							if(current_ike_sa != NULL) {
								// Not in a IKE_SA_ESTABLISHED status, so drop the request.
								// The IKE_SA can't attend it now.
								Log::writeLockedMessage( "NetworkController", "Droped command because the IKE_SA is busy.", Log::LOG_WARN, true );
								return;
							}
						}
					}
				 }
			}
		}


		if (!exist_ike_sa) {

		    Log::writeLockedMessage( "IkeSaController", "IkeSa between IP=[" + ike_sa_src_addr.toString() + "] and IP=[" + ike_sa_dst_addr.toString() + "] does not exist. Creating a new one", Log::LOG_INFO, true );

		    // Create new IkeSa (INITIATOR) based on CoA, but it must be changed to HoA after IKE_AUTH exchange
		    auto_ptr<IkeSa> ike_sa ( new IkeSa( this->nextSpi(),
		                                        true,
		                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_coa_addr.clone(), 500 ) ) ,
		                                        auto_ptr<SocketAddress> ( new SocketAddressPosix( ike_sa_dst_addr.clone(), 500 ) )
		                                      ) );
		    Log::writeLockedMessage( "IkeSaController", "Just after IKE_SA creation ", Log::LOG_INFO, true );

		    this->incHalfOpenCounter();

		    command.reset ( new SendIkeSaInitReqCommand( child_sa_request ) );

		    ike_sa->pushCommand( command, false );

		    Log::writeLockedMessage( "IkeSaController", "The command was pushed in the new IKE SA and stored in the IKE_SA collection ", Log::LOG_INFO, true );

		    this->addIkeSa ( ike_sa );
		}
		else {
			if (child_sa_request->mode == Enums::TUNNEL_MODE){
				Log::writeLockedMessage( "NetworkController", "Soy MR y cambio mi CoA a IP=[" + ike_sa_coa_addr.toString() + "]", Log::LOG_WARN, true );
				auto_ptr<IpAddress> coa (ike_sa_coa_addr.clone());
				current_ike_sa->care_of_address.reset(new SocketAddressPosix(coa,500));
			}

		}


	}


    }



    bool IkeSaControllerImplOpenIKE::pushCommandByIkeSaSpi( uint64_t spi, auto_ptr<Command> command, bool priority ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.find( spi );

        // If spi value is not found
        if ( it == this->ike_sa_collection.end() )
            return false;

        // If spi value is found
        it->second->pushCommand( command, priority );

        this->scheduleIkeSa( *it->second );

        return true;
    }

    IkeSa* IkeSaControllerImplOpenIKE::getIkeSaByIkeSaSpi( uint64_t spi ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.find( spi );

        // If spi value is not found
        if ( it == this->ike_sa_collection.end() )
            return NULL;


        return it->second;

    }

    bool IkeSaControllerImplOpenIKE::pushCommandByChildSaSpi( uint32_t spi, auto_ptr<Command> command, bool priority ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        // For each IkeSa
        for ( map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.begin(); it != this->ike_sa_collection.end(); it++ ) {
            IkeSa * current_ike_sa = it->second;
            // If spi value is found
            if ( current_ike_sa->controlsChildSa( spi ) ) {
                it->second->pushCommand( command, priority );
                this->scheduleIkeSa( *it->second );
                return true;
            }
        }

        return false;
    }





    bool IkeSaControllerImplOpenIKE::pushCommandByAddress( const IpAddress & addr, const IpAddress & peer_addr, auto_ptr<Command> command, bool priority ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        // For each IkeSa
        for ( map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.begin(); it != this->ike_sa_collection.end(); it++ ) {
            IkeSa * current_ike_sa = ( *it ).second;

            // If Peer address is found
            if ( current_ike_sa->my_addr->getIpAddress() == addr && current_ike_sa->peer_addr->getIpAddress() == peer_addr ) {
                current_ike_sa->pushCommand( command, priority );
                this->scheduleIkeSa( *it->second );
                return true;
            }
        }

        // if not found, return false
        return false;
    }

    IkeSa* IkeSaControllerImplOpenIKE::getIkeSaByAddress( const IpAddress & addr, const IpAddress & peer_addr ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        // For each IkeSa
        for ( map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.begin(); it != this->ike_sa_collection.end(); it++ ) {
            IkeSa * current_ike_sa = ( *it ).second;

            // If Peer address is found
            if ( current_ike_sa->my_addr->getIpAddress() == addr && current_ike_sa->peer_addr->getIpAddress() == peer_addr ) {
                return current_ike_sa;
            }
        }

        // if not found, return false
        return NULL;
    }


    void IkeSaControllerImplOpenIKE::exit( ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        this->exiting = true;

        // If there isn't any active IKE SA , then the close operation is already done
        if ( this->exiting && this->ike_sa_collection.empty() ) {
            EventBus::getInstance().sendBusEvent( auto_ptr<BusEvent> ( new BusEventCore( BusEventCore::ALL_SAS_CLOSED ) ) );
            return ;
        }

        // else, then send close signal to each IKE SA
        for ( map<uint64_t, IkeSa*>::iterator it = this->ike_sa_collection.begin(); it != this->ike_sa_collection.end(); it++ ) {
            ( *it ).second->pushCommand( auto_ptr<Command> ( new CloseIkeSaCommand() ), true );
            this->scheduleIkeSa( *it->second );
        }
    }

    void IkeSaControllerImplOpenIKE::deleteIkeSaController( IkeSa & ike_sa ) {
        // Total number of IkeSa
        uint32_t count = this->ike_sa_collection.size();

        // Finds controller in IKE_SAs collection and deletes it
        assert ( this->ike_sa_collection.find( ike_sa.my_spi ) != this->ike_sa_collection.end() );
        assert ( this->scheduled_ike_sa_map.find( ike_sa.my_spi ) != this->scheduled_ike_sa_map.end() );

        this->ike_sa_collection.erase( ike_sa.my_spi );
        this->scheduled_ike_sa_map.erase ( ike_sa.my_spi );

        // Only must remove one and only one IkeSa from IKE_SA collection
        assert( count == ike_sa_collection.size() + 1 );

        // If this was the last remaining controller in the collection and we want to exit, then finish message controller
        if ( this->exiting && this->ike_sa_collection.empty() )
            EventBus::getInstance().sendBusEvent( auto_ptr<BusEvent> ( new BusEventCore( BusEventCore::ALL_SAS_CLOSED ) ) );

        Log::writeLockedMessage( "IkeSaController", "Delete IkeSa: SPI=" + Printable::toHexString( &ike_sa.my_spi, 8 ) + " Count=[" + intToString( this->ike_sa_collection.size() ) + "]", Log::LOG_INFO, true );
    }

    bool IkeSaControllerImplOpenIKE::isExiting( ) {
        return this->exiting;
    }

    void IkeSaControllerImplOpenIKE::decHalfOpenCounter( ) {
        assert( this->half_open_counter > 0 );

        AutoLock auto_lock( *this->mutex_half_open_counter );

        // Decrements counter
        this->half_open_counter--;

        Log::writeLockedMessage( "IkeSaController", "Decrement Half-open count: Count=[" + intToString( this->half_open_counter ) + "]", Log::LOG_HALF, true );
    }

    void IkeSaControllerImplOpenIKE::incHalfOpenCounter( ) {
        AutoLock auto_lock( *this->mutex_half_open_counter );

        // Increments counter
        this->half_open_counter++;

        Log::writeLockedMessage( "IkeSaController", "Increment Half-open count: Count=[" + intToString( this->half_open_counter ) + "]", Log::LOG_HALF, true );
    }

    bool IkeSaControllerImplOpenIKE::useCookies( ) {
        AutoLock auto_lock( *this->mutex_half_open_counter );

        auto_ptr<GeneralConfiguration> general_conf = Configuration::getInstance().getGeneralConfiguration();

        // If half open counter execeds a threshold value, then return true to start cookies DoS protection mechanism
        if ( half_open_counter >= general_conf->cookie_threshold )
            return true;

        return false;
    }

    void IkeSaControllerImplOpenIKE::checkIkeSa( IkeSa & ike_sa, bool delete_ike_sa ) {
        AutoLock auto_lock( *this->condition_ike_sa );

        this->scheduled_ike_sa_map[ike_sa.my_spi] = false;

        cout << "********* El booleano vale : " << delete_ike_sa << endl;

        if ( delete_ike_sa ) {
            // Deletes this ike_sa from the IkeSa list

            this->deleteIkeSaController( ike_sa );

            // We need to unlock the list after removing because deletion of an IKE_SA could lead use to a deadlock situation
            auto_lock.release();

            delete ( &ike_sa );

            return;
        }

        else if ( ike_sa.hasMoreCommands() ) {
            this->scheduleIkeSa( ike_sa );
        }
    }

    uint64_t IkeSaControllerImplOpenIKE::nextSpi() {
        AutoLock auto_lock( *this->mutex_spi );
        return current_spi++;
    }

}


