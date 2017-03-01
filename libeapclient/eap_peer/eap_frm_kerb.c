/*
 * EAP peer method: EAP-FRM 
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
#include "./utils/common.h"
#include "config_ssid.h"
#include "eap_frm_common.h"
#include <krb5/k5-int.h>
#include <krb5/krb5.h>
#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "./crypto/ms_funcs.h"
#include "utils/prf_plus.h"
#include "crypto/aes_wrap.h"

#define MUTUAL_REQUIRED 0


//unsigned int eapfrm_flag;

struct eap_frm_data {
	enum { frm_1, frm_3, SUCCESS, FAILURE } state;
	u8 rand_server[EAP_FRM_RAND_LEN];
	u8 rand_peer[EAP_FRM_RAND_LEN];
	u8 msk[EAP_MSK_LEN];
	u8 emsk[EAP_EMSK_LEN];
	u8 sk[EAP_FRM_MAX_SK_LEN];
	size_t sk_len;
	u8 pk[EAP_FRM_MAX_PK_LEN];
	size_t pk_len;
	u8 session_id;
	int session_id_set;
	u8 *id_peer;
	size_t id_peer_len;
	u8 *id_server;
	size_t id_server_len;
	int vendor; /* CSuite/Specifier */
	int specifier; /* CSuite/Specifier */
	u8 *psk;
	u8 *authenticator_id;
	u16 authenticator_len;
	size_t psk_len;
	u8 *Na;
	u16 Na_len;
};
u8 is_Reactive = 0;

static u8 * eap_frm_send_frm_2(struct eap_frm_data *data, u8 identifier, const u8 *csuite_list, size_t csuite_list_len, size_t *respDataLen);
static u8 * eap_frm_send_frm_4(struct eap_frm_data *data, u8 identifier, size_t *respDataLen);


#ifndef CONFIG_NO_STDOUT_DEBUG
static const char * eap_frm_state_txt(int state)
{
	//printf("LLAMANDO A VER ESTADO\n");
	fflush(stdout);
	switch (state) {
	case frm_1:
		return "FRM-1";
	case frm_3:
		return "FRM-3";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}
#endif /* CONFIG_NO_STDOUT_DEBUG */


static void eap_frm_state(struct eap_frm_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-FRM: %s -> %s", eap_frm_state_txt(data->state), eap_frm_state_txt(state));
	data->state = state;
}


static void eap_frm_deinit(struct eap_sm *sm, void *priv);


static void * eap_frm_init(struct eap_sm *sm)
{
	//struct wpa_ssid *config = eap_get_config(sm);
	struct eap_peer_config *config = eap_get_config(sm);

	struct eap_frm_data *data;

	if (config == NULL) {
		wpa_printf(MSG_INFO, "EAP-FRM: No configuration found");
		return NULL;
	}

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;
	data->state = frm_1;

	if (config->identity) {
		data->id_peer = os_malloc(config->identity_len);
		if (data->id_peer == NULL) {
			eap_frm_deinit(sm, data);
			return NULL;
		}
		os_memcpy(data->id_peer, config->identity, config->identity_len);
		data->id_peer_len = config->identity_len;
	}
	return data;
}


static void eap_frm_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_frm_data *data = priv;
	os_free(data->id_server);
	os_free(data->id_peer);
	os_free(data);
}


const u8 * eap_frm_process_id_server(struct eap_frm_data *data, const u8 *pos, const u8 *end)
{
	u16 alen;

	if (end - pos < 2) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Too short frm-1 packet");
		return NULL;
	}
	alen = WPA_GET_BE16(pos);
	pos += 2;
	if (end - pos < alen) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: ID_Server overflow");
		return NULL;
	}
	os_free(data->id_server);
	data->id_server = os_malloc(alen);
	if (data->id_server == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: No memory for ID_Server");
		return NULL;
	}
	os_memcpy(data->id_server, pos, alen);
	data->id_server_len = alen;
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-FRM: ID_Server", data->id_server, data->id_server_len);
	pos += alen;

	return pos;
}


const u8 * eap_frm_process_rand_server(struct eap_frm_data *data, const u8 *pos, const u8 *end)
{
	if (pos == NULL)
		return NULL;

	if (end - pos < EAP_FRM_RAND_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: RAND_Server overflow");
		return NULL;
	}
	os_memcpy(data->rand_server, pos, EAP_FRM_RAND_LEN);
	wpa_hexdump(MSG_DEBUG, "EAP-FRM: RAND_Server", data->rand_server, EAP_FRM_RAND_LEN);
	pos += EAP_FRM_RAND_LEN;

	return pos;
}


static int eap_frm_select_csuite(struct eap_sm *sm,
				  struct eap_frm_data *data,
				  const u8 *csuite_list,
				  size_t csuite_list_len)
{
	struct eap_frm_csuite *csuite;
	int i, count;

	count = csuite_list_len / sizeof(struct eap_frm_csuite);
	data->vendor = EAP_FRM_VENDOR_IETF;
	data->specifier = EAP_FRM_CIPHER_RESERVED;
	csuite = (struct eap_frm_csuite *) csuite_list;
	for (i = 0; i < count; i++) {
		int vendor, specifier;
		vendor = WPA_GET_BE32(csuite->vendor);
		specifier = WPA_GET_BE16(csuite->specifier);
		wpa_printf(MSG_DEBUG, "EAP-FRM: CSuite[%d]: %d:%d", i, vendor, specifier);
		if (data->vendor == EAP_FRM_VENDOR_IETF &&
		    data->specifier == EAP_FRM_CIPHER_RESERVED &&
		    eap_frm_supported_ciphersuite(vendor, specifier)) {
			data->vendor = vendor;
			data->specifier = specifier;
		}
		csuite++;
	}
	if (data->vendor == EAP_FRM_VENDOR_IETF &&
	    data->specifier == EAP_FRM_CIPHER_RESERVED) {
		wpa_msg(sm->msg_ctx, MSG_INFO, "EAP-FRM: No supported ciphersuite found");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-FRM: Selected ciphersuite %d:%d", data->vendor, data->specifier);

	return 0;
}


const u8 * eap_frm_process_csuite_list(struct eap_sm *sm,
					struct eap_frm_data *data,
					const u8 **list, size_t *list_len,
					const u8 *pos, const u8 *end)
{
	if (pos == NULL)
		return NULL;

	if (end - pos < 2) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Too short frm-1 packet");
		return NULL;
	}
	*list_len = WPA_GET_BE16(pos);
	pos += 2;
	if (end - pos < (int) *list_len) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: CSuite_List overflow");
		return NULL;
	}
	if (*list_len == 0 || (*list_len % sizeof(struct eap_frm_csuite))) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Invalid CSuite_List len %d", *list_len);
		return NULL;
	}
	*list = pos;
	pos += *list_len;

	if (eap_frm_select_csuite(sm, data, *list, *list_len) < 0)
		return NULL;

	return pos;
}

static u8 * eap_frm_process_frm_1(struct eap_sm *sm, struct eap_frm_data *data, struct eap_method_ret *ret, const u8 *reqData, size_t reqDataLen,  const u8 *payload, size_t payload_len, size_t *respDataLen)
{
	size_t csuite_list_len;
	const u8 *csuite_list, *pos, *end;
	const struct eap_hdr *req;
	u8 *resp;
	u16 alen;

	if (data->state != frm_1) {
		ret->ignore = TRUE;
		return NULL;
	}
	

	wpa_printf(MSG_DEBUG, "EAP-FRM: Received Request/frm-1");


	pos = payload;
        end = payload + payload_len;

        alen = WPA_GET_BE16(pos);
        pos+=2;

        data->authenticator_id = malloc(alen+1);
        data->authenticator_len = alen+1;
        memcpy(data->authenticator_id,pos,data->authenticator_len);
        pos+=data->authenticator_len;
	data->authenticator_id[alen+1] = "\0";


	req = (const struct eap_hdr *) reqData;

//        printf ("Flag bootstraping = %d\n", eapfrm_flag);
          
	/*krb5_cc_cursor  cursor;
  	krb5_creds credential;
	u8 found_realm=0;	
 	krb5_context context;
	krb5_ccache ccdef;
	krb5_error_code retval;
	
	krb5_init_context(&context);

 	krb5_cc_default(context,&ccdef);
	
  	krb5_cc_start_seq_get(context,ccdef,&cursor);
    	while(!(retval = krb5_cc_next_cred(context,ccdef,&cursor,&credential))) {
     		
             if(strcmp(credential.server->data[0].data,"krbtgt") == 0  &&   strcmp(credential.server->data[1].data, "UM.ES") == 0 ) {
     			found_realm=1;
			break;
	     }
  	}
	printf("PASANDO DEL WHILE\n");
	fflush(stdout);

	if(found_realm)
		krb5_cc_end_seq_get(context,ccdef,&cursor);

	printf("PASANDO DE LOS FREE\n");
        fflush(stdout); 
	krb5_cc_close(context,ccdef);
	 printf("PASANDO DE LOS FREE\n");
        fflush(stdout);
	krb5_free_context(context);
	printf("PASANDO DE LOS FREE\n");
	fflush(stdout);*/
	//if(found_realm) {
	
		resp = eap_frm_send_frm_2(data, req->identifier,  csuite_list, csuite_list_len, respDataLen);
		//printf("SALIENDO DE SEND FRM 2\n");
		 if (!MUTUAL_REQUIRED && !is_Reactive) {
                	eap_frm_generate_key(data);
	                eap_frm_state(data, SUCCESS);
        	        ret->methodState = METHOD_DONE;
                	ret->decision = DECISION_UNCOND_SUCC;
		 }
		 else eap_frm_state(data, frm_3);
	//}
	/*else {
		printf("ENTRANDO AQUI\n");
		fflush(stdout);
		struct wpabuf *respNak = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NAK, 1, EAP_CODE_RESPONSE, req->identifier);
		
		u8 *rpos = wpabuf_head_u8(respNak);
        	rpos += respNak->used;
        	*rpos++ = EAP_TYPE_EXT;
		respNak->used = 6;
		 resp =  wpabuf_head_u8(respNak);
		ret->methodState = METHOD_INIT;	
		//ret->decision = DECISION_FAIL;
		*respDataLen = respNak->used;
		printf("ENTRANDO A ENVIAR NAKKKKKKKKKKKKKKKKKKKKKKKKKKKKK\n");
		fflush(stdout);
		//eap_frm_state(data,FAILURE);
	}*/

	if (resp == NULL) {
		printf("RESP ES NULLLLL\n");
		eap_frm_state(data,FAILURE);
		return NULL;
	}
	return (u8 *) resp;
}

krb5_context context = 0;
krb5_auth_context auth_context = 0;
krb5_response* tgsrep = NULL;
krb5_creds my_creds;
krb5_creds *creds = NULL;
krb5_ccache ccdef = 0;

static u8 * eap_frm_send_frm_2(struct eap_frm_data *data, u8 identifier, const u8 *csuite_list, size_t csuite_list_len, size_t *respDataLen)
{
	struct eap_hdr *resp;
	size_t len, miclen;
	u8 *rpos, *start;
	struct eap_frm_csuite *csuite;
	u16 message1_len;

	// KRB5 related variables 
	
	krb5_data recv_data;
	krb5_data cksum_data;
	krb5_error_code retval;
	krb5_principal server_ppal, client_ppal;
	krb5_error *err_ret;
	krb5_ap_rep_enc_part *rep_ret;
	char * cname;
	short xmitlen;
	krb5_get_init_creds_opt *options = NULL;
	krb5_data  inbuf, outbuf;
	krb5_data * tgsreq_packet = NULL;


	char *service_name="netaccess";
	char *service_hostname=data->authenticator_id;
	char * client_ppal_name="delia";
	//service_hostname = "supportwimax2";
	//printf("VLAORRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR %s\n", service_hostname);
	//printf("LLAMANDO A SEND FRM 2\n");
	fflush(stdout);
	////
	// We initialize krb5 context (default realm, configuration file, encryption type, ... )
	////

	retval = krb5_init_context(&context);
	if (retval) {
		com_err("KERBEROS", retval, "while initializing krb5");
		exit(1);
	}

    //
    // We obtain the CLIENT PRINCIPAL
    //

   // printf(" * Getting client principal....");

    if ((retval = krb5_parse_name(context, client_ppal_name, &client_ppal))) {
        fprintf(stderr, "%s caused error while parsing name %s", "KERBEROS", client_ppal_name);
        return 0;
    }


 //printf(" * Getting server principal....");
    retval = krb5_sname_to_principal(context, service_hostname, service_name, KRB5_NT_UNKNOWN, &server_ppal);
    if (retval) {
        fprintf (stderr, " ERROR: <unable to create server principal ");
        com_err("KERBEROS", retval, "while creating server name for host <%s> service <%s>", service_hostname, service_name);
        return 0;
    }

//	 printf (" * Obtaining a session ticket from default credentials cache .... ");

    retval = krb5_cc_default(context, &ccdef);  // Default credential cache
    if (retval) {
        com_err("KERBEROS", retval, "while getting default ccache");
        exit(1);
    }

  //  printf ("OK!. Default credential cache is %s \n",krb5_cc_default_name(context));

    memset(&my_creds, 0, sizeof(my_creds));

    if ((retval = krb5_copy_principal(context, server_ppal, &my_creds.server))) {
        com_err("KERBEROS", retval, " while copying server principal: ");
        exit (1);
    }

    if ((retval = krb5_copy_principal(context, client_ppal, &my_creds.client))) {
        com_err("KERBEROS", retval, " while copying client principal: ");
        exit (1);
    }
	//printf("NO TIENE SENTIDO\n");
	fflush(stdout);
    retval = krb5_get_credentials(context, KRB5_GC_CACHED, ccdef, &my_creds, &creds);
	 krb5_data *outbuf_aux = NULL;
	
	//if(creds == NULL) printf("ES NULL CREDS DESPUES DE CREDENDITALs\n");
	//fflush(stdout);
	//printf("PASANDO DE CREADS\n");

    if(retval) { //no session ticket
	is_Reactive = 1;
	 /*** Creamos el TGS-REQ  ***/
	//printf("NO SESSION TICKET\n");
	//krb5_data *outbuf_aux = NULL;
   	retval = krb5_build_TGSREQ (context, 0, ccdef, &my_creds, &creds, &outbuf_aux, &tgsrep);
	//if(creds == NULL) printf("CREDS NULL EN BUILD TGSREQ\n");
	//fflush(stdout);
	outbuf.data = outbuf_aux->data;
	outbuf.length = outbuf_aux->length;
	//printf("SALIENDO DE NO SESSION TICKET\n");

	if (retval) {
	       com_err("KERBEROS", retval, "while building TGS_REQ initial credentials");
	       exit(1);
	}
    }
    else {
	//printf("CON TICKET\n");
	fflush(stdout);
	is_Reactive = 0;
	krb5_flags ap_option;
	if(MUTUAL_REQUIRED)
		ap_option = AP_OPTS_MUTUAL_REQUIRED;
	else
		ap_option = NULL;

	 if ((retval = krb5_mk_req_extended(context, &auth_context, ap_option, NULL, creds, &outbuf))) {
        	com_err("KERBEROS", retval, " while creating AP-REQ ");
        	exit(1);
    	}
	//printf("ENTRANDO A LIBERAR CREDS\n");
	fflush(stdout);
	krb5_free_creds(context, creds);

    }
	
	u8 *message1 = NULL;

	//F.BERNAL -- add payload
	message1 = (u8 *) malloc(outbuf.length*sizeof(u8));
	memcpy(message1,outbuf.data, outbuf.length);
	message1_len = outbuf.length;

	u8 *identidad = "rafa@upct.es\0";
	u8 *message2 = (u8 *) malloc(strlen(identidad)*sizeof(u8));
	u16 message2_len = strlen(identidad);

	wpa_printf(MSG_DEBUG, "EAP-FRM: Sending Response/frm-2");

	//F.BERNAL -- add length to len
	len = 1 + 2 + message1_len /*+ 1 + 2 + message2_len*/; //1+2 codigo y long frm

	
	struct wpabuf *resp1 = eap_msg_alloc(EAP_VENDOR_IETF,EAP_TYPE_FRM, len,EAP_CODE_RESPONSE,identifier);

	if (resp1 == NULL) {
		eap_frm_state(data,FAILURE);
		return NULL;
	}
	
	rpos = wpabuf_head_u8(resp1);
	rpos += resp1->used;

	*rpos++ = EAP_FRM_OPCODE_FRM_2;
	
	WPA_PUT_BE16(rpos,message1_len/*+message2_len*/);
	rpos +=2;
	os_memcpy(rpos,message1,message1_len);
	int i = 0;
	/*for (i = 0; i < message1_len;i++) {
		printf("%X:",*(message1+i));
	}*/
	resp1->used = len+resp1->used;
	respDataLen = resp1->used;

	 // Free resources
	if(outbuf_aux != NULL) free(outbuf_aux);
	//printf("ANTES DE LOS FREE\n");
	fflush(stdout);
    	krb5_free_principal(context, server_ppal);
    	krb5_free_principal(context, client_ppal);
	//printf("DESPUES DE LOS FREE\n");
	fflush(stdout);
    	//krb5_cc_close(context, ccdef); ver donde ponerlos

	return (u8 *) wpabuf_head_u8(resp1);
}


const u8 * eap_frm_validate_rand(struct eap_frm_data *data, const u8 *pos,
				  const u8 *end)
{
	if (end - pos < EAP_FRM_RAND_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "RAND_Peer");
		return NULL;
	}
	if (os_memcmp(pos, data->rand_peer, EAP_FRM_RAND_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: RAND_Peer in frm-2 and "
			   "frm-3 did not match");
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: RAND_Peer in frm-2",
			    data->rand_peer, EAP_FRM_RAND_LEN);
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: RAND_Peer in frm-3",
			    pos, EAP_FRM_RAND_LEN);
		return NULL;
	}
	pos += EAP_FRM_RAND_LEN;

	if (end - pos < EAP_FRM_RAND_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "RAND_Server");
		return NULL;
	}
	if (os_memcmp(pos, data->rand_server, EAP_FRM_RAND_LEN) != 0) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: RAND_Server in frm-1 and "
			   "frm-3 did not match");
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: RAND_Server in frm-1",
			    data->rand_server, EAP_FRM_RAND_LEN);
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: RAND_Server in frm-3",
			    pos, EAP_FRM_RAND_LEN);
		return NULL;
	}
	pos += EAP_FRM_RAND_LEN;

	return pos;
}


const u8 * eap_frm_validate_id_server(struct eap_frm_data *data,
				       const u8 *pos, const u8 *end)
{
	size_t len;

	if (pos == NULL)
		return NULL;

	if (end - pos < (int) 2) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "length(ID_Server)");
		return NULL;
	}

	len = WPA_GET_BE16(pos);
	pos += 2;

	if (end - pos < (int) len) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "ID_Server");
		return NULL;
	}

	if (len != data->id_server_len ||
	    os_memcmp(pos, data->id_server, len) != 0) {
		wpa_printf(MSG_INFO, "EAP-FRM: ID_Server did not match with "
			   "the one used in frm-1");
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-FRM: ID_Server in frm-1",
				  data->id_server, data->id_server_len);
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-FRM: ID_Server in frm-3",
				  pos, len);
	}

	pos += len;

	return pos;
}


const u8 * eap_frm_validate_csuite(struct eap_frm_data *data, const u8 *pos,
				    const u8 *end)
{
	int vendor, specifier;
	const struct eap_frm_csuite *csuite;

	if (pos == NULL)
		return NULL;

	if (end - pos < (int) sizeof(*csuite)) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "CSuite_Sel");
		return NULL;
	}
	csuite = (const struct eap_frm_csuite *) pos;
	vendor = WPA_GET_BE32(csuite->vendor);
	specifier = WPA_GET_BE16(csuite->specifier);
	pos += sizeof(*csuite);
	if (vendor != data->vendor || specifier != data->specifier) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: CSuite_Sel (%d:%d) does not "
			   "match with the one sent in frm-2 (%d:%d)",
			   vendor, specifier, data->vendor, data->specifier);
		return NULL;
	}

	return pos;
}


const u8 * eap_frm_validate_pd_payload_2(struct eap_frm_data *data,
					  const u8 *pos, const u8 *end)
{
	u16 alen;

	if (pos == NULL)
		return NULL;

	if (end - pos < 2) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "PD_Payload_2 length");
		return NULL;
	}
	alen = WPA_GET_BE16(pos);
	pos += 2;
	if (end - pos < alen) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for "
			   "%d-octet PD_Payload_2", alen);
		return NULL;
	}
	wpa_hexdump(MSG_DEBUG, "EAP-FRM: PD_Payload_2", pos, alen);
	pos += alen;

	return pos;
}


const u8 * eap_frm_validate_frm_3_mic(struct eap_frm_data *data,
					const u8 *payload,
					const u8 *pos, const u8 *end)
{
	size_t miclen;
	u8 mic[EAP_FRM_MAX_MIC_LEN];

	if (pos == NULL)
		return NULL;

	miclen = eap_frm_mic_len(data->vendor, data->specifier);
	if (end - pos < (int) miclen) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Message too short for MIC "
			   "(left=%d miclen=%d)", end - pos, miclen);
		return NULL;
	}
	if (eap_frm_compute_mic(data->sk, data->sk_len, data->vendor,
				 data->specifier, payload, pos - payload, mic)
	    < 0) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Failed to compute MIC");
		return NULL;
	}
	if (os_memcmp(mic, pos, miclen) != 0) {
		wpa_printf(MSG_INFO, "EAP-FRM: Incorrect MIC in frm-3");
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: Received MIC", pos, miclen);
		wpa_hexdump(MSG_DEBUG, "EAP-FRM: Computed MIC", mic, miclen);
		return NULL;
	}
	pos += miclen;

	return pos;
}


void eap_frm_generate_key(struct eap_frm_data *dataParam)
{

// Session key is the MSK
krb5_keyblock * keyblock;
krb5_error_code retval;

	if ((retval = krb5_auth_con_getkey(context, auth_context, &keyblock) )) {
		com_err("Kerberos module error : ", retval, " while retrieving keyblock from auth_context structure");
		return 0;
	}

                // keyblock->contents
                // keyblock->length

                int tam = keyblock->length;
                if (keyblock->length < 64)
                tam = 64;  // MSK of 64 bytes

                u8 *key_derived = (u8 *) malloc(tam*sizeof(u8));
                memset(key_derived, 0, tam*sizeof(u8));
                memcpy(key_derived, keyblock->contents, keyblock->length);

                u16 msk_len = EAP_MSK_LEN;
                memcpy(dataParam->msk, key_derived, msk_len);
		int i=0;
	/*	printf("VALOR DE MSK\n");
		for(i=0;i<msk_len;i++) {
			printf("%X:",*(key_derived+i));		
		}*/
                krb5_free_keyblock(context, keyblock);
                free (key_derived);
}




static u8 * eap_frm_process_frm_3(struct eap_sm *sm, struct eap_frm_data *data, struct eap_method_ret *ret, const u8 *reqData, size_t reqDataLen, const u8 *payload, size_t payload_len, size_t *respDataLen)
{
	u8 *resp;
	const struct eap_hdr *req;
	const u8 *pos, *end;
	size_t csuite_list_len;
        const u8 *csuite_list;

	u16 alen;
	krb5_error_code retval;

	krb5_ap_rep_enc_part *rep_ret;

	if (data->state != frm_3) {
		ret->ignore = TRUE;
		return NULL;
	}

	pos = payload;
	end = payload + payload_len;
	
	wpa_printf(MSG_DEBUG, "EAP-FRM: Received Request/frm-3");
	alen = WPA_GET_BE16(pos);
	pos+=2;
	
	u8 *message4 = malloc(alen);
	u16 message4_len = alen;	
	memcpy(message4,pos,message4_len);
	pos+=message4_len;

	//F.BERNAL -- here the message could be checked

	krb5_data respAP;
	respAP.length = message4_len;
	
	respAP.data = (char *) malloc(message4_len*sizeof(char));
	memcpy(respAP.data,message4,message4_len);
	
	if ((&respAP) && (&respAP)->length && ((&respAP)->data[0] == 0x6d || (&respAP)->data[0] == 0x4d)) {	
	//if(krb5_is_tgs_rep(&respAP)) { //session ticket from kdc
		 /*** Process and check ASREP ***/
		//printf("ENTRNADO A COMPROBAR TGS\n");
		fflush(stdout);
		tgsrep->response.data = (char *) malloc(respAP.length*sizeof(char));
		memcpy(tgsrep->response.data, respAP.data, respAP.length);
		tgsrep->response.length = respAP.length;
		//print_hex(tgsrep->response.data, tgsrep->response.length);
		//printf("PASAMOS DE COPIAR\n");
		fflush(stdout);
		if(my_creds.server == NULL) printf("my_creds.server ES NULL\n");
		fflush(stdout);
    		retval = krb5_process_and_check_TGSREP (context, 0, ccdef, &my_creds, &creds, tgsrep);
		//printf("SALIMOS\n");
		fflush(stdout);
		if (retval) {
		       com_err("KERBEROS", retval, "while processing TGS_REP received from KDC");
		       exit(1);
		}

		if(tgsrep != NULL)
			free(tgsrep);
		krb5_cc_close(context, ccdef);
		krb5_free_creds(context,creds);
		if(auth_context)
			//krb5_auth_con_free(context,auth_context);
		krb5_free_context(context);
		u8 *resp;
		req = (const struct eap_hdr *) reqData;		
		//sending ticket to obtain a service access 
		resp = eap_frm_send_frm_2(data, req->identifier,  csuite_list, csuite_list_len, respDataLen);
		//here this state must be success to optimize
		if(MUTUAL_REQUIRED)
			eap_frm_state(data, frm_3);
		else {
			 eap_frm_generate_key(data);	
			 eap_frm_state(data, SUCCESS);
			 ret->methodState = METHOD_DONE;
		         ret->decision = DECISION_UNCOND_SUCC;
		}
		
		return resp;

	}
	
        else if ((&respAP) && (&respAP)->length && ((&respAP)->data[0] == 0x6f || (&respAP)->data[0] == 0x4f)) {
//else if (krb5_is_ap_rep(&respAP)) { //response from service
		 if ((retval = krb5_rd_rep(context, auth_context, &respAP, &rep_ret))) {
        	 	if (rep_ret) krb5_free_ap_rep_enc_part(context, rep_ret);
        		free(respAP.data);
        		com_err("KERBEROS", retval, " while parsing and decrypting received AP-REP from service server");
	        	exit(1);
		}
		

		eap_frm_generate_key(data);


		krb5_cc_close(context, ccdef);
                if(auth_context)
                        krb5_auth_con_free(context,auth_context);
                krb5_free_context(context);
	}
	
	
	if (pos != end) {
		wpa_printf(MSG_DEBUG, "EAP-FRM: Ignored %d bytes of extra data in the end of frm-2", end - pos);
	}
	
	req = (const struct eap_hdr *) reqData;

	resp = eap_frm_send_frm_4(data, req->identifier, respDataLen);

	if (resp == NULL) {
		eap_frm_state(data, FAILURE);
		return NULL;
	}

	eap_frm_state(data, SUCCESS);
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_UNCOND_SUCC;
	return (u8 *) resp;
}


static u8 * eap_frm_send_frm_4(struct eap_frm_data *data, u8 identifier, size_t *respDataLen)
{
	struct eap_hdr *resp;
	u8 *rpos, *start;
	size_t len;

	wpa_printf(MSG_DEBUG, "EAP-FRM: Sending Response/frm-4");

	//F.BERNAL -- necessary data could be added here

	len = 1;

	struct wpabuf * resp1 = eap_msg_alloc(EAP_VENDOR_IETF,EAP_TYPE_FRM, len,EAP_CODE_RESPONSE,identifier);
	if (resp1 == NULL)
		return NULL;
	
	rpos = wpabuf_head_u8(resp1);
	rpos += resp1->used;

	*rpos++ = EAP_FRM_OPCODE_FRM_4;
	//WPA_PUT_BE16(rpos,0);
	
	//F.BERNAL -- copy data in rpos with memcpy (if it is necessary)

	resp1->used = len + 5;
	*respDataLen = resp1->used;

	//printf("PASAMOS EL LIO\n");
	fflush(stdout);

	/*if (auth_context)
       		krb5_auth_con_free(context, auth_context);*/

	 //krb5_free_context(context);



	return  wpabuf_head_u8(resp1);
}

static struct wpabuf * eap_frm_process(struct eap_sm *sm, void *priv, struct eap_method_ret *ret, const struct wpabuf *reqData_out) 
{


	struct eap_frm_data *data = priv;
        struct wpabuf *resp1;
	u8 *resp;
	u16 respDataLen;
        const u8 *pos;
        size_t len;
       	//printf("ENTRANDO EN FRM PROCESS\n"); 
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_FRM, reqData_out, &len);
	u8 * reqData = wpabuf_head_u8(reqData_out);
	u16 reqDataLen = reqData_out->used;

        if (pos == NULL || len < 1) {
                ret->ignore = TRUE;
                return NULL;
        }

        wpa_printf(MSG_DEBUG, "EAP-FRM: Received frame: opcode %d", *pos);

        ret->ignore = FALSE;
        ret->methodState = METHOD_MAY_CONT;
        ret->decision = DECISION_FAIL;
        ret->allowNotifications = FALSE;


        switch (*pos) {
        case EAP_FRM_OPCODE_FRM_1:
                resp = eap_frm_process_frm_1(sm, data, ret, reqData,
                                               reqDataLen, pos + 1, len - 1,
                                               &respDataLen);
                break;
        case EAP_FRM_OPCODE_FRM_3:
                resp = eap_frm_process_frm_3(sm, data, ret, reqData,
                                               reqDataLen, pos + 1, len - 1,
                                               &respDataLen);
                break;
        default:
                wpa_printf(MSG_DEBUG, "EAP-FRM: Ignoring message with "
                           "unknown opcode %d", *pos);
                ret->ignore = TRUE;
                return NULL;
        }
	resp1 = wpabuf_alloc(respDataLen);
	u8 *aux = wpabuf_head_u8(resp1);
	memcpy(aux, resp, respDataLen);
	resp1->used = respDataLen;
        return resp1;

}

static Boolean eap_frm_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_frm_data *data = priv;
	return data->state == SUCCESS;
}


static u8 * eap_frm_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_frm_data *data = priv;
	u8 *key;
	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(EAP_MSK_LEN);
	if (key == NULL) return NULL;

	os_memcpy(key, data->msk, EAP_MSK_LEN);
	*len = EAP_MSK_LEN;
	return key;
}


static u8 * eap_frm_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_frm_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = os_malloc(EAP_EMSK_LEN);
	if (key == NULL)
		return NULL;
	os_memcpy(key, data->emsk, EAP_EMSK_LEN);
	*len = EAP_EMSK_LEN;

	return key;
}


int eap_peer_frm_register(void)
{
	struct eap_method *eap;
	int ret;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION, EAP_VENDOR_IETF, EAP_TYPE_FRM, "FRM");
	if (eap == NULL)
		return -1;

	eap->init = eap_frm_init;
	eap->deinit = eap_frm_deinit;
	eap->process = eap_frm_process;
	eap->isKeyAvailable = eap_frm_isKeyAvailable;
	eap->getKey = eap_frm_getKey;
	//eap->get_emsk = eap_frm_get_emsk;

	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret;
}
