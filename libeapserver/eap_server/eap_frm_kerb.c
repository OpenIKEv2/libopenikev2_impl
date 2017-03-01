/*
 * hostapd / EAP-FRM server
 * Copyright (c) 2008, Fernando Bernal Hidalgo <fbernal@um.es>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#include "./utils/includes.h"

#include "../hostapd.h"
#include "./utils/common.h"
#include <k5-int.h>
#include <krb5/krb5.h>
#include "./crypto/aes_wrap.h"
#include "eap_server/eap_i.h"
#include "eap_server/eap_frm_common.h"
#include "radius/radius.h"
#include "utils/wpabuf.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct eap_frm_data {
	enum { FRM_1, FRM_3, SUCCESS, FAILURE } state;
	u8 rand_server[EAP_FRM_RAND_LEN];
	u8 rand_peer[EAP_FRM_RAND_LEN];
	u8 msk[EAP_MSK_LEN];
	u8 emsk[EAP_EMSK_LEN];
	u8 sk[EAP_FRM_MAX_SK_LEN];
	size_t sk_len;
	u8 pk[EAP_FRM_MAX_PK_LEN];
	size_t pk_len;
	u8 *id_peer;
	size_t id_peer_len;
	u8 *id_server;
	size_t id_server_len;
#define MAX_NUM_CSUITES 2
	struct eap_frm_csuite csuite_list[MAX_NUM_CSUITES];
	size_t csuite_count;
	int vendor; /* CSuite/Vendor */
	int specifier; /* CSuite/Specifier */
	u8 *message4;
	u16 message4_len;
};

krb5_auth_context auth_context = 0;
krb5_context context;

static const char * eap_frm_state_txt(int state)
{
	switch (state) {
	case FRM_1:
		return "FRM-1";
	case FRM_3:
		return "FRM-3";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}


static void eap_frm_state(struct eap_frm_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-FRM: %s -> %s",
		   eap_frm_state_txt(data->state),
		   eap_frm_state_txt(state));
	data->state = state;
}


static void * eap_frm_init(struct eap_sm *sm)
{
	struct eap_frm_data *data;

	data = wpabuf_alloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	
	data->state = FRM_1;

	/* TODO: add support for configuring ID_Server */
	
	data->id_server = (u8 *) strdup("hostapd");
	if (data->id_server)
		data->id_server_len = strlen((char *) data->id_server);

	data->csuite_count = 0;
	

	return data;
}


static void eap_frm_reset(struct eap_sm *sm, void *priv)
{
	struct eap_frm_data *data = priv;
	free(data->id_server);
	free(data->id_peer);
	free(data);
}


static struct wpabuf * eap_frm_build_frm_1(struct eap_sm *sm, struct eap_frm_data *data, int id)
{
	u8 *pos;
	size_t len;
	struct eap_hdr *req;

	wpa_printf(MSG_DEBUG, "EAP-FRM: Request/FRM-1");

	//F.BERNAL -- first message when the peer is associated	
	// TODO: parametrizar en el fichero de configuracion de openikev2.conf
	u8 *identity="supportwimax2";
	u16 identity_len = strlen(identity);
	len = 1 + 2 + identity_len; 
	
	struct wpabuf *resp1 = eap_msg_alloc(EAP_VENDOR_IETF,EAP_TYPE_FRM, len,EAP_CODE_REQUEST,id);
	
	
	if (resp1 == NULL) {
		wpa_printf(MSG_ERROR, "EAP-FRM: Failed to allocate memory for request/FRM-1");
		eap_frm_state(data, FAILURE);
		return NULL;
	}


	pos = wpabuf_head_u8(resp1);
        pos += resp1->used;
	resp1->used = len +5;
	
	*pos++ = EAP_FRM_OPCODE_FRM_1;

	WPA_PUT_BE16(pos,identity_len);
        pos +=2;
        os_memcpy(pos,identity,identity_len);

	return  resp1;
}


static struct wpabuf * eap_frm_build_frm_3(struct eap_sm *sm, struct eap_frm_data *data, int id)
{
	u8 *pos, *start;
	size_t len, miclen;
	struct eap_frm_csuite *csuite;
	struct eap_hdr *req;

	wpa_printf(MSG_DEBUG, "EAP-FRM: Request/FRM-3");
	
	//F.BERNAL -- message to send the peer the radius request (may be not necessary)

	len = 1+2+data->message4_len;

	 struct wpabuf *resp1 = eap_msg_alloc(EAP_VENDOR_IETF,EAP_TYPE_FRM, len,EAP_CODE_REQUEST,id);
	
	if (resp1 == NULL) {
		wpa_printf(MSG_ERROR, "EAP-FRM: Failed to allocate memory for request/FRM-3");
		eap_frm_state(data, FAILURE);
		return NULL;
	}

        pos = wpabuf_head_u8(resp1);
        pos += resp1->used;

	*pos++ = EAP_FRM_OPCODE_FRM_3;
	
	WPA_PUT_BE16(pos, data->message4_len);
	pos += 2;

	//F.BERNAL -- check this (may be not necessary)
	os_memcpy(pos,data->message4, data->message4_len);

	pos+=data->message4_len;
	resp1->used = len +5;

	return resp1;
}


static struct wpabuf * eap_frm_buildReq(struct eap_sm *sm, void *priv, int id)
{
	struct eap_frm_data *data = priv;
	size_t *reqDataLen;

	//printf("Estado FRM:%d\n", data->state);

	switch (data->state) {
	case FRM_1:
		return eap_frm_build_frm_1(sm, data, id);
	case FRM_3:
		return eap_frm_build_frm_3(sm, data, id);
	default:
		wpa_printf(MSG_DEBUG, "EAP-FRM: Unknown state %d in buildReq",
			   data->state);
		break;
	}
	return NULL;
}

static Boolean eap_frm_check(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{
	struct eap_frm_data *data = priv;
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_FRM, respData, &len);

	if (pos == NULL || len < 1) {
		wpa_printf(MSG_INFO, "EAP-FRM: Invalid frame");
		return TRUE;
	}

	wpa_printf(MSG_DEBUG, "EAP-FRM: Received frame: opcode=%d", *pos);

	//fernando: if return false it means that is ok
	if (data->state == FRM_1 && *pos == EAP_FRM_OPCODE_FRM_2)
		return FALSE;

	if (data->state == FRM_3 && *pos == EAP_FRM_OPCODE_FRM_4)
		return FALSE;

	if(data->state == FRM_3 && *pos == EAP_FRM_OPCODE_FRM_2) {
		printf("ENTRAMOS AQUI -- NUEVO ESTADO\n");
		data->state = FRM_1;		
		return FALSE;
	}

	wpa_printf(MSG_INFO, "EAP-FRM: Unexpected opcode=%d in state=%d", *pos, data->state);

	return TRUE;
}

void eap_frm_generate_key(struct eap_frm_data *data) 
{
	int i = 0;	
	krb5_error_code retval;
	 // Session key is the MSK
                        krb5_keyblock * keyblock;

                        if ((retval = krb5_auth_con_getkey(context, auth_context, &keyblock) )) {
                                com_err("Kerberos module error : ", retval, " while retrieving keyblock from auth_context structure\n");
                                return 0;
                        }

                        // keyblock->contents
                        // keyblock->length

                        int tam = keyblock->length;
                        if (keyblock->length < EAP_MSK_LEN)     tam = EAP_MSK_LEN;  // MSK of 64 bytes

                        u8 *key_derived = (u8 *) malloc(tam*sizeof(u8));
                        memset(key_derived, 0, tam*sizeof(u8));
                        memcpy(key_derived, keyblock->contents, keyblock->length);

                        u16 msk_len = EAP_MSK_LEN;

                        memcpy(data->msk, key_derived, msk_len);

        //printf ("********** ESTABLECIDA LA CLAVE MSK EN FRM=[");

	//for (i = 0; i<64; i++) printf("%X:", *(key_derived+i));
	//printf("]\n");

                       
                        free(key_derived);

}

static void eap_frm_process_frm_2(struct eap_sm *sm,  struct eap_frm_data *data,   u8 *respData, size_t respDataLen,   const u8 *payload, size_t payloadlen)
{
	const u8 *pos, *end;
	u16 alen;
	const struct eap_frm_csuite *csuite;
	size_t i, miclen;
	u8 mic[EAP_FRM_MAX_MIC_LEN];
	struct radius_msg *radiusReq;
	struct radius_msg *radiusRes;
	struct radius_attr_hdr * attrHdr;
	struct sockaddr_in ds;
	int s, length,index_attr;
	struct hostent *info;
	unsigned char buf[3000];
	u8 *buf1;

	// KRB5 related variables
    struct addrinfo *ap, aihints, *apstart;
    int aierr;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval;
    krb5_ccache ccdef;
    krb5_principal client_ppal, server_ppal;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    char * cname;
    krb5_keytab keytab = NULL;
    krb5_ticket * ticket;
    krb5_rcache rcache = 0;
    krb5_data  inbuf;
    krb5_data  outbuf;
    krb5_flags  ap_option;
	 char * servicename="netaccess";
	 char * keytabfn="/usr/local/var/krb5kdc/kadm5.keytab";
	// Local variables
    int authcontxt = 0, repcache = 0, clientticket = 0;

	int optimization_enabled =0;

	if (data->state != FRM_1)
		return;

	wpa_printf(MSG_DEBUG, "EAP-FRM: Received Response/FRM-2");

	pos = payload;
	end = payload + payloadlen;

	if (end - pos < 2) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Too short message for message length");
		eap_frm_state(data, FAILURE);
		return;
	}
	alen = WPA_GET_BE16(pos);
	pos += 2;
	if (end - pos < alen) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Too short message!!!");
		eap_frm_state(data, FAILURE);
		return;
	}
	u8 * message1 = malloc(alen);
	u16 message1_len = alen;
	if (message1 == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: No memory to allocate message");
		eap_frm_state(data,FAILURE);
		return;
	}

	memcpy(message1,pos,alen);

	//printf("PASAMOS PRIMERA PARTE\n");
	fflush(stdout);

	/*F.BERNAL -- the message sent by the peer is in message1
	*	      if information that is necessary to send to the peer must be placed in data->message4
	*/
	
	//printf(" 1\n");
	inbuf.data = (char *) malloc(message1_len*sizeof(char));	
	memcpy(inbuf.data, message1, message1_len);
	inbuf.length = message1_len;

	//printf("VALOR DEL TICKET\n");
	//print_hex(message1, message1_len);

	retval = krb5_init_context(&context);
    if (retval) {
            com_err("KERBEROS", retval, "while initializing krb5");
            exit(1);
    }


    // We obtain a handle indentifying the keytab file
    retval = krb5_kt_resolve(context, keytabfn, &keytab);
    if (retval) {
        com_err("KERBEROS", retval, "while resolving keytab file %s", optarg);
        exit(1);
    }
	
	//printf(" * Getting server principal....");
	fflush(stdout);

    retval = krb5_sname_to_principal(context, "supportwimax2", servicename, KRB5_NT_SRV_HST, &server_ppal);
    if (retval) {
        fprintf (stderr, " ERROR: <unable to create server principal ");
        com_err("KERBEROS", retval, "while creating server name for host <%s> service <%s>", servicename, servicename);
        exit(1);
    }
        if ((&inbuf) && (&inbuf)->length && ((&inbuf)->data[0] == 0x6c || (&inbuf)->data[0] == 0x4c)){
	//if(krb5_is_tgs_req(&inbuf)) { //reactive

		//printf("TGS_REQUEST\n");
		//print_hex(inbuf.data, inbuf.length);
		
	
		 //Fernando: comunication with the AAA server
        	radiusReq = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST,250);
	        radius_msg_make_authenticator(radiusReq,"hola",4);

	        length = 1+1+2+16;

		//length = 1+1+2+16;
        	attrHdr = radius_msg_add_attr(radiusReq,1,"rafa\0",4);
        	length += attrHdr->length;



	        //attrHdr = radius_msg_add_attr(radiusReq,21,message2,message2_len);
	        //length += attrHdr->length;

		u8 *pos = message1;
		size_t left = message1_len;
		

		while (left > 0) {
        	        int len;
                	if (left > RADIUS_MAX_ATTR_LEN)
        	                len = RADIUS_MAX_ATTR_LEN;
	                else
                	        len = left;

	                attrHdr = radius_msg_add_attr(radiusReq, 17, pos, len);
			length += attrHdr->length;                        

	                pos += len;
                	left -= len;
        	}
		
		//printf("Longitud %d", length);
	        radiusReq->hdr->length = htons(length);

        	radius_msg_dump(radiusReq);
	        ds.sin_family = AF_INET;

	        //fernando: check this
	        ds.sin_addr.s_addr = inet_addr("192.168.1.1");
        	ds.sin_port = htons(1812);

	        s = socket(AF_INET,SOCK_DGRAM,0);

        	if (s < 0) {
	                wpa_printf(MSG_DEBUG,"EAP-TPP: Comunication with AAA server has not be able to be stablished... Aborting!");
        	        eap_frm_state(data,FAILURE);
	        }

        	connect(s, (struct sockaddr *)&ds,sizeof(ds));
	        write(s,radiusReq->buf,radiusReq->buf_used);
	        length = recv(s,buf,sizeof(buf),0);
        	if (length < 0) {
                	printf("EAP-TPP: ERROR\n");
	        }
	        radiusRes = radius_msg_parse(buf, length);
	        radius_msg_dump(radiusRes);

        	u8 *buffer = NULL;
	        u8 *buffer1 = NULL;

	        u8 *Kab = NULL;
	        u16 Kab_len =0;


		u32 LKab = 0;
		data->message4_len = 0;
		buf1 = (u8 *) malloc(3000*sizeof(u8));
		u8 * aux_buf = buf1;
        	for(index_attr =0; index_attr < radiusReq->attr_used; index_attr++) {
                	struct radius_attr_hdr *rad_hdr = radius_get_attr_hdr(radiusRes,index_attr);
	                if(rad_hdr->type == 17) {
        	                //restamos dos a la longitud porque la longitud cuenta con dos bytes mas del atributo radius?



                        	int flen = rad_hdr->length - sizeof(*rad_hdr);
                        	memcpy(aux_buf, rad_hdr + 1, flen);
                        		
				//printf("LONGITUD - %d %d\n", rad_hdr->length, flen);
				data->message4_len += flen;
				aux_buf += flen;


        	        }

        	}

		data->message4 = (u8 *) malloc(data->message4_len*sizeof(u8));
                memcpy(data->message4, buf1, data->message4_len);		
		printf("valor longitud %d\n", data->message4_len);



	}
	else if ((&inbuf) && (&inbuf)->length && ((&inbuf)->data[0] == 0x6e || (&inbuf)->data[0] == 0x4e))	{

//      else if(krb5_is_ap_req(&inbuf)) { //proactive
		 //printf("2\n");
		fflush(stdout);
		 // We initialize the auth_context (structure which stores information of an authenticated connection)
	        retval = krb5_auth_con_init(context, &auth_context);
        	if (retval) {
	            fprintf(stderr, "Error while getting auth_context\n");
        	}
	        authcontxt = 1;
			// We get a replay cache. A replay cache is used to detect message replay when processing a message.
	        krb5_auth_con_getrcache(context, auth_context, &rcache);

        	if (rcache == NULL) {
	            retval = krb5_get_server_rcache(context,
                                            krb5_princ_component(context, server_ppal, 0),
                                            &rcache);

        	retval = krb5_auth_con_setrcache(context, auth_context, rcache);
        }
	//printf("3\n");
	fflush(stdout);
        if (retval) {
            fprintf(stderr, "Error while getting replay cache\n");
            
        }
	else {
		//printf("4\n");
	        repcache = 1;
		 // We read AP_REQ, parsing its arguments into a krb5_ticket readable structure.

        	retval = krb5_rd_req(context, &auth_context, &inbuf, server_ppal, keytab, &ap_option, &ticket);
	        //krb5_xfree(inbuf.data);
        	free(inbuf.data);

	        // We check if has happened any problem.
        	if (retval) {
	            fprintf (stderr, "      * 'krb5_rd_req' funtion failed : < %s >\n", error_message(retval));
        	    fflush(stdout);
	            
        	}
		else {
		        clientticket = 1;
			 // Successful ticket validation !
	        	// We response to the client with an AP-REP

			//to optimize this is not necessary

			if (ticket->enc_part2->authorization_data != NULL){

			       printf ("       * LLeva datos de autorización \n") ;

			       int i = 0;
			       krb5_authdata * ade; // Authorization Data Element
			       while (ticket->enc_part2->authorization_data[i] != NULL) {
			           ade = ticket->enc_part2->authorization_data[i];
			           printf ("          ADE => - Type: %d\n", ade->ad_type);
			           printf ("                 - Length: %d\n", ade->length); // krb5_octet * == unsigned char
			           printf ("                 - Contents: %s\n", ade->contents);  //  krb5_int32 == int
			           i++;
			       }

			} 

			if(ap_option & (AP_OPTS_MUTUAL_REQUIRED)) {
			        if ((retval = krb5_mk_rep(context, auth_context, &outbuf))) {
        			     fprintf(stderr, "Error while creating AP_REP message\n");             
	        		}
	
				data->message4 = (u8 *) malloc(outbuf.length*sizeof(u8));
				memcpy(data->message4, outbuf.data, outbuf.length);
				data->message4_len = outbuf.length;
				free(outbuf.data);
			}
			else {
				optimization_enabled = 1;
				//eap_frm_generate_key(data);
			}
			eap_frm_generate_key(data);

			//printf("RESPUESTA AL PEER\n");
			//print_hex(data->message4, data->message4_len);
		}
	}

        // Free reserved resources before waiting a new request

        if (clientticket) {
            krb5_free_ticket(context, ticket);
            clientticket = 0;
        }

        if (repcache) {
            krb5_rc_close(context, rcache);   /// nuevo
            krb5_auth_con_setrcache(context, auth_context, NULL);  /// nuevo
            repcache = 0;
        }

        if (authcontxt) {
            krb5_auth_con_free(context, auth_context);
            auth_context = 0;
            authcontxt = 0;
        }

	 // We free memory reserved resources
    	if (keytab)
       		krb5_kt_close(context, keytab);
	
	krb5_free_principal(context, server_ppal);
	krb5_free_context(context);

	}
	else {
	}		


	pos += alen;

	if (pos != end) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Ignored %d bytes of extra data in the end of FRM-2", end - pos);
	}

	//F.BERNAL -- when this function finish:  eap_frm_build_frm_3 is called
	//printf("SALIMOS\n");
	fflush(stdout);		
	if(optimization_enabled)
		eap_frm_state(data, SUCCESS);
	else	
		eap_frm_state(data, FRM_3);
}


static void eap_frm_process_frm_4(struct eap_sm *sm, struct eap_frm_data *data, u8 *respData, size_t respDataLen, const u8 *payload, size_t payloadlen)
{
	const u8 *pos, *end;
	u16 alen;
	size_t miclen;
	u8 mic[EAP_FRM_MAX_MIC_LEN];

	if (data->state != FRM_3)
		return;

	wpa_printf(MSG_DEBUG, "EAP-FRM: Received Response/FRM-4");

	//F.BERNAL -- here the last response from the peer is processed
	//eap_frm_generate_key(data);

	eap_frm_state(data, SUCCESS);	
}

static struct wpabuf * eap_frm_process(struct eap_sm *sm, void *priv, const struct wpabuf *reqData)
{
	struct eap_frm_data *data = priv;
	const u8 *pos;
	size_t len;

        pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_FRM, reqData, &len);

	if (pos == NULL || len < 1)
		return;

	switch (*pos) {
	case EAP_FRM_OPCODE_FRM_2:
		eap_frm_process_frm_2(sm, data, wpabuf_head_u8(reqData), reqData->used, pos + 1, len - 1);
		break;
	case EAP_FRM_OPCODE_FRM_4:
		eap_frm_process_frm_4(sm, data, wpabuf_head_u8(reqData), reqData->used, pos + 1, len - 1);
		break;
	}
}


static Boolean eap_frm_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_frm_data *data = priv;
	return data->state == SUCCESS || data->state == FAILURE;
}


static u8 * eap_frm_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_frm_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = malloc(EAP_MSK_LEN);
	if (key == NULL)
		return NULL;
	memcpy(key, data->msk, EAP_MSK_LEN);
	*len = EAP_MSK_LEN;

	return key;
}


static u8 * eap_frm_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_frm_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = malloc(EAP_EMSK_LEN);
	if (key == NULL)
		return NULL;
	memcpy(key, data->emsk, EAP_EMSK_LEN);
	*len = EAP_EMSK_LEN;

	return key;
}


static Boolean eap_frm_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_frm_data *data = priv;
	return data->state == SUCCESS;
}


int eap_server_frm_register(void)
{
	struct eap_method *eap;
	int ret;
	
	wpa_printf(MSG_DEBUG, "EAP-FRM: method registered");

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_FRM, "FRM");
	if (eap == NULL)
		return -1;

	eap->init = eap_frm_init;
	eap->reset = eap_frm_reset;
	eap->buildReq = eap_frm_buildReq;
	eap->check = eap_frm_check;
	eap->process = eap_frm_process;
	eap->isDone = eap_frm_isDone;
	eap->getKey = eap_frm_getKey;
	eap->isSuccess = eap_frm_isSuccess;
	//eap->get_emsk = eap_frm_get_emsk;

	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
	return ret;
}
