
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <netlink/attr.h>
#include <linux/nlipc_aa6.h>

#include "mip_nlipc.h"
#include "debug.h"
#include "conf.h"
#include "mn.h"
#include "ha.h"
#include "libnetlink/nl_ipc.h"

#ifdef ENABLE_FB
#include "fb.h"
#endif

static struct nl_ipc *handle = NULL;
static pthread_t recvworker;
static pthread_mutex_t global_lock = PTHREAD_MUTEX_INITIALIZER;

struct mip_nlipc_udata mip_nlipc_userdata = {
#ifdef ENABLE_FB
	.fb_lock = PTHREAD_MUTEX_INITIALIZER,
	.fb_cond = PTHREAD_COND_INITIALIZER,
	.fb_entries = LIST_HEAD_INIT(mip_nlipc_userdata.fb_entries)
#endif
};



/** Flow Bindings functions **/

#ifdef ENABLE_FB
int mip_nlipc_send_fb_setidentity(struct in6_addr *peer, struct fbentry *fbe, int nolock)
{
	int err = 0;
	struct mip_nlmsg *mip_nlmsg = NULL;
	struct nl_ipc_msg ipc_msg = {
		.msg_type = MSG_MIP_FB_SETIDENTITY,
		.peer_id = IPC_ID_POLICYD,
		.flags = NL_IPC_F_ACK,
		.req_id = 0
	};

	ipc_msg.data = nlmsg_alloc();
	if (!ipc_msg.data) {
		printf("Error while creating a fb identity message\n");
		return -1;
	}

	mip_nlmsg = (struct mip_nlmsg *) nlmsg_reserve(ipc_msg.data, sizeof(*mip_nlmsg),
	                                               NLMSG_ALIGNTO);
	memcpy(&mip_nlmsg->hoa, peer, sizeof(mip_nlmsg->hoa));

	NLA_PUT_U16(ipc_msg.data, NLATTR_FB_FID, fbe->fid);
	NLA_PUT_U16(ipc_msg.data, NLATTR_FB_PRIORITY, fbe->priority);
	NLA_PUT_U16(ipc_msg.data, NLATTR_FB_SOPT_BR, fbe->bid);
	NLA_PUT_TYPE(ipc_msg.data, struct flow_ts_ipv6, NLATTR_FB_SOPT_TS, fbe->ts);

	if (nolock)
		err = nl_ipc_send_nolock(handle, IPC_GROUP_AA6, &ipc_msg);
	else
		err = nl_ipc_send(handle, IPC_GROUP_AA6, &ipc_msg);
	if (err)
		printf("Error while sending a fb_setidentity message\n");
	else
		err = ipc_msg.req_id;

out_err:
	nlmsg_free(ipc_msg.data);
	return err;

nla_put_failure:
	err = -1;
	printf("Error while preparing a fb_setidentity message\n");
	goto out_err;
}

int mip_nlipc_send_fb_setsummary(struct in6_addr *peer, struct list_head *fb_summary, int fb_count,
                                 int nolock)
{
	int err = 0, n = 0;
	struct list_head *l;
	struct mip_nlmsg *mip_nlmsg = NULL;
	struct nl_ipc_msg ipc_msg = {
		.msg_type = MSG_MIP_FB_SETSUMMARY,
		.peer_id = IPC_ID_POLICYD,
		.flags = NL_IPC_F_ACK,
		.req_id = 0
	};
	uint16_t summary[fb_count];

	ipc_msg.data = nlmsg_alloc();
	if (!ipc_msg.data) {
		printf("Error while creating a fb_setsummary message\n");
		return -1;
	}

	mip_nlmsg = (struct mip_nlmsg *) nlmsg_reserve(ipc_msg.data, sizeof(*mip_nlmsg),
	                                               NLMSG_ALIGNTO);
	memcpy(&mip_nlmsg->hoa, peer, sizeof(mip_nlmsg->hoa));

	list_for_each(l, fb_summary) {
		if (n >= fb_count)
			break;
		struct fbentry *fbe = list_entry(l, struct fbentry, list);
		summary[n++] = fbe->fid;
		fbe->hoa = peer;
	}

	err = nla_put(ipc_msg.data, NLATTR_FB_SUMMARY, fb_count * sizeof(uint16_t), summary);
	if (err) {
		printf("Error while preparing a fb_setsummary message\n");
		goto out_err;
	}

	if (nolock)
		err = nl_ipc_send_nolock(handle, IPC_GROUP_AA6, &ipc_msg);
	else
		err = nl_ipc_send(handle, IPC_GROUP_AA6, &ipc_msg);
	if (err)
		printf("Error while sending a fb_setsummary message\n");
	else
		err = ipc_msg.req_id;

out_err:
	nlmsg_free(ipc_msg.data);
	return err;
}

int mip_nlipc_send_fb_getsummary(struct in6_addr *peer, int nolock)
{
	int err = 0;
	struct mip_nlmsg *mip_nlmsg = NULL;
	struct nl_ipc_msg ipc_msg = {
		.msg_type = MSG_MIP_FB_GETSUMMARY,
		.peer_id = IPC_ID_POLICYD,
		.flags = 0,
		.req_id = 0
	};

	ipc_msg.data = nlmsg_alloc();
	if (!ipc_msg.data) {
		printf("Error while creating a fb_getsummary message\n");
		return -1;
	}

	mip_nlmsg = (struct mip_nlmsg *) nlmsg_reserve(ipc_msg.data, sizeof(*mip_nlmsg),
	                                               NLMSG_ALIGNTO);
	memcpy(&mip_nlmsg->hoa, peer, sizeof(mip_nlmsg->hoa));

	if (nolock)
		err = nl_ipc_send_nolock(handle, IPC_GROUP_AA6, &ipc_msg);
	else
		err = nl_ipc_send(handle, IPC_GROUP_AA6, &ipc_msg);
	if (err)
		printf("Error while sending a fb_getsummary message\n");
	else
		err = ipc_msg.req_id;

	nlmsg_free(ipc_msg.data);
	return err;
}


/**
 * Reception callbacks
 */

static int _recv_fb_setsummary_cback(int seqid, struct nlattr *attributes[],
                                     struct mip_nlipc_udata *userdata)
{
	struct list_head *l, *n;
	int i, err = 0, summary_cnt = 0;
	uint16_t *summary;

	if (!attributes[NLATTR_FB_SUMMARY]) {
		err = -EINVAL;
		goto out_err;
	}

	summary_cnt = nla_len(attributes[NLATTR_FB_SUMMARY]) / sizeof(uint16_t);
	if (nla_len(attributes[NLATTR_FB_SUMMARY]) % sizeof(uint16_t) != 0) {
		err = -EINVAL;
		goto out_err;
	}
	summary = (uint16_t*) nla_data(attributes[NLATTR_FB_SUMMARY]);

	pthread_mutex_lock(&userdata->fb_lock);
	list_for_each_safe(l, n, &userdata->fb_entries) {
		struct fbentry *fbe = list_entry(l, struct fbentry, acklist);
		if (fbe->seqid != seqid)
			continue;
		list_del(l);
		fbe->status = IP6_FLOWI_S_FID_NOT_FOUND;
		for (i=0; i<summary_cnt; i++) {
			if (summary[i] == fbe->fid) {
				fbe->status = IP6_FLOWI_S_OK;
				break;
			}
		}
	}
	pthread_cond_signal(&userdata->fb_cond);
	pthread_mutex_unlock(&userdata->fb_lock);

out_err:
	return 0;
}

static int _rack_fb_setidentity_cback(int seqid, int status,
                                      struct mip_nlipc_udata *userdata)
{
	struct list_head *l, *n;

	pthread_mutex_lock(&userdata->fb_lock);
	list_for_each_safe(l, n, &userdata->fb_entries) {
		struct fbentry *fbe = list_entry(l, struct fbentry, acklist);
		if (fbe->seqid != seqid)
			continue;
		list_del(l);
		fbe->status = fb_syserr2fberr(status);
		pthread_cond_signal(&userdata->fb_cond);
		break;
	}
	pthread_mutex_unlock(&userdata->fb_lock);

	return 0;
}

static int _rack_fb_setsummary_cback(int seqid, int status,
                                     struct mip_nlipc_udata *userdata)
{
	struct list_head *l, *n;
	struct fbentry *fbe = NULL;
	int new_seqid;

	pthread_mutex_lock(&userdata->fb_lock);
	list_for_each_safe(l, n, &userdata->fb_entries) {
		fbe = list_entry(l, struct fbentry, acklist);
		if (fbe->seqid != seqid)
			continue;
		/**
		 * Send a getsummary summary message to discover which flows doesn't exist.
		 * This design may look weird, it adds complexity and overhead. The
		 * purpose is to respect consistency and principles of Netlink messaging.
		 */
		if (status == ESRCH)
			goto send_getsummary;
	
		/* Success or unknown status */
		fbe->status = IP6_FLOWI_S_OK;
		list_del(l);
	}
	pthread_cond_signal(&userdata->fb_cond);

out_unlock:
	pthread_mutex_unlock(&userdata->fb_lock);
	return 0;

send_getsummary:
	new_seqid = mip_nlipc_send_fb_getsummary(fbe->hoa, 1);
	list_for_each_safe(l, n, &userdata->fb_entries) {
		fbe = list_entry(l, struct fbentry, acklist);
		if (fbe->seqid != seqid)
			continue;
		fbe->status = FB_S_UNSYNCED_GETSUM;
		if (new_seqid > 0)
			fbe->seqid = new_seqid;
		else
			list_del(l);
	}
	goto out_unlock;
}

#else
int mip_nlipc_send_fb_setidentity(struct in6_addr *peer __attribute__((unused)),
                                  struct fbentry *fbe __attribute__((unused)),
                                  int nolock __attribute__((unused)))
{
	printf("Unsupported feature");
	return -ENOSYS;
}

int mip_nlipc_send_fb_setsummary(struct in6_addr *peer __attribute__((unused)),
                                 struct list_head *fb_summary __attribute__((unused)),
                                 int fb_count __attribute__((unused)),
                                 int nolock __attribute__((unused)))
{
	printf("Unsupported feature");
	return -ENOSYS;
}

int mip_nlipc_send_fb_getsummary(struct in6_addr *peer __attribute__((unused)),
                                 int nolock __attribute__((unused)))
{
	printf("Unsupported feature");
	return -ENOSYS;
}
#endif





/** MCoA functions **/


static int _mcoa_create_setbinding(struct nl_ipc_msg *ipc_msg, struct mip_nlipc_binding *be)
{
        struct mip_nlmsg *mip = NULL;

	ipc_msg->data = nlmsg_alloc();
	if (!ipc_msg->data) {
		printf("Error while creating a mcoa_setbinding message\n");
		return -ENOMEM;
	}

	mip = (struct mip_nlmsg *) nlmsg_reserve(ipc_msg->data, sizeof(*mip),
	                                               NLMSG_ALIGNTO);
	memcpy(&mip->hoa, &be->hoa, sizeof(mip->hoa));

	NLA_PUT_TYPE(ipc_msg->data, struct in6_addr, NLATTR_MCOA_COA, be->coa);
	NLA_PUT_TYPE(ipc_msg->data, struct in6_addr, NLATTR_MCOA_HAA, be->haa);
	NLA_PUT_TYPE(ipc_msg->data, struct timespec, NLATTR_MCOA_EXPIRES, be->expires);
	NLA_PUT_U16(ipc_msg->data, NLATTR_MCOA_BID, be->bid);
	NLA_PUT_U16(ipc_msg->data, NLATTR_MCOA_FLAGS, be->flags);
	NLA_PUT_U16(ipc_msg->data, NLATTR_MCOA_SEQ, be->seq);

	return 0;
nla_put_failure:
	nlmsg_free(ipc_msg->data);
	return -ENOMEM;
}


int mip_nlipc_send_mcoa_setbinding(struct mip_nlipc_binding *be)
{
	int err = 0;
	struct nl_ipc_msg ipc_msg = {
		.msg_type = MSG_MIP_MCOA_SETBINDING,
		.flags = NL_IPC_F_MCAST,
		.req_id = 0
	};

	err = _mcoa_create_setbinding(&ipc_msg, be);
	if (err)
		goto out_err;

	err = nl_ipc_send(handle, IPC_GROUP_AA6, &ipc_msg);
	nlmsg_free(ipc_msg.data);

out_err:
	return err;
}

static int _recv_mcoa_getbinding_cback(struct in6_addr *hoa, struct nlattr *attributes[], struct nl_ipc_msg *reply)
{
	int err = 0;
	struct mip_nlipc_binding be = {};


	/* Can't process the message */
	if (!reply)
		return 0;

	memcpy(&be.hoa, hoa, sizeof(struct in6_addr));

	if (attributes[NLATTR_MCOA_BID])
		be.bid = nla_get_u16(attributes[NLATTR_MCOA_BID]);

	if (attributes[NLATTR_MCOA_COA]) {
		if (nla_len(attributes[NLATTR_MCOA_COA]) != sizeof(struct in6_addr)) {
			err = -EINVAL;
			goto out_err;
		}
		memcpy(&be.coa, nla_data(attributes[NLATTR_MCOA_COA]), sizeof(struct in6_addr));
	}

	if (attributes[NLATTR_MCOA_HAA]) {
		if (nla_len(attributes[NLATTR_MCOA_HAA]) != sizeof(struct in6_addr)) {
			err = -EINVAL;
			goto out_err;
		}
		memcpy(&be.haa, nla_data(attributes[NLATTR_MCOA_HAA]), sizeof(struct in6_addr));
	}


	if (is_mn())
		err = mn_mcoa_getbinding(hoa, &be);
	else if (is_ha())
		err = ha_mcoa_getbinding(hoa, &be);
	else
		err = -ENOSYS;

	if (err)
		goto out_err;

	/* Send the binding */
	reply->msg_type = MSG_MIP_MCOA_SETBINDING;
	err = _mcoa_create_setbinding(reply, &be);

out_err:
	return err;
}

static int _rack_mcoa_setbinding_cback(int seqid __attribute__((unused)),
                                       int status __attribute__((unused)))
{
	/* For now, ignore it */
	return 0;
}



/** Callbacks **/

static int _msg_on_data(int group_id, struct nl_ipc_msg *ipc_msg, void *return_value, void *userdata)
{
	int err = 0;
	struct nlattr *attributes[NLATTR_MAX + 1];
	struct mip_nlmsg *mip = NULL;


	if ((ipc_msg->msg_type != MSG_MIP_FB_SETSUMMARY) &&
	    (ipc_msg->msg_type != MSG_MIP_MCOA_GETBINDING))
		return 0;

	err = nlmsg_parse(nlmsg_hdr(ipc_msg->data), sizeof(struct mip_nlmsg),
	                  attributes, NLATTR_MAX, NULL);
	if (err)
		goto out_err;
	mip = (struct mip_nlmsg *) nlmsg_data(nlmsg_hdr(ipc_msg->data));

	switch (ipc_msg->msg_type) {
#ifdef ENABLE_FB
	case MSG_MIP_FB_SETSUMMARY:
		_recv_fb_setsummary_cback(ipc_msg->req_id, attributes,
		                          (struct mip_nlipc_udata *) userdata);
		return NL_IPC_A_OK;
#endif
	case MSG_MIP_MCOA_GETBINDING:
		err = _recv_mcoa_getbinding_cback(&mip->hoa, attributes, (struct nl_ipc_msg *) return_value);
		if (!err)
			return NL_IPC_A_REPLY;
		break;
	}


out_err:
        if (err)
                printf("Operation returned error %d\n", -err);

        if (return_value) {
                /* Send a ack */
                *((int*) return_value) = -err;
                printf("Send a ACK: %d\n", *((int*) return_value));
                return NL_IPC_A_ACK;
        }

	return NL_IPC_A_OK;
}

static int _msg_on_acked(int group_id, struct nl_ipc_msg *ipc_msg, int error_code, void *userdata)
{
	struct nlattr *attributes[NLATTR_MAX + 1];

	switch (ipc_msg->msg_type) {
#ifdef ENABLE_FB
	case MSG_MIP_FB_SETIDENTITY:
		_rack_fb_setidentity_cback(ipc_msg->req_id, error_code,
		                           (struct mip_nlipc_udata *) userdata);
		break;
	case MSG_MIP_FB_SETSUMMARY:
		_rack_fb_setsummary_cback(ipc_msg->req_id, error_code,
		                          (struct mip_nlipc_udata *) userdata);
		break;
#endif
	case MSG_MIP_MCOA_SETBINDING:
		_rack_mcoa_setbinding_cback(ipc_msg->req_id, error_code);
		break;
	default:
		return 0;
	}

	return NL_IPC_A_OK;
}


#if 0
/*
 * test connection for initialization
 */
int send_test_connection(const char *testdata, const char *peer)
{
	int err = 0;
	struct aa6_msg_test_connection *pload = NULL;
	struct nl_ipc_msg ipc_msg = {
		.msg_type = MSG_TEST_CONNECTION,
		.peer_id = peer,
		.flags = NL_IPC_F_ACK,
		.req_id = 0,
		.data = NULL
	};
	printf("== send_test_connection ==\n");

	ipc_msg.data = nlmsg_alloc();
	if (!ipc_msg.data) {
		printf("Error while creating a message\n");
		return -1;
	}
	
	pload = (struct aa6_msg_test_connection *) 
		nlmsg_reserve(ipc_msg.data, sizeof(*pload), NLMSG_ALIGNTO);
	strncpy((char*) &pload->mydata, testdata, sizeof(pload->mydata) - 1);

	/* Send the message */
	err = nl_ipc_send(handle, IPC_GROUP_AA6, &ipc_msg);

out_err:
	nlmsg_free(ipc_msg.data);
	return err;
}
#endif


void *_recvloop(void *userdata) {
	int err, timeout;

	pthread_dbg("thread started");
	do {
		timeout = 10000;
		err = nl_ipc_recvloop(handle, timeout);
	} while (err == -NLE_AGAIN);
	pthread_exit(NULL);
}

int mip_nlipc_recvloop(void)
{
	if (pthread_create(&recvworker, NULL, _recvloop, NULL))
		return -1;
	return 0;
}

static int _mutex_lock(void *userdata)
{
	pthread_mutex_lock((pthread_mutex_t *) userdata);
	return 0;
}

static int _mutex_unlock(void *userdata)
{
	pthread_mutex_unlock((pthread_mutex_t *) userdata);
	return 0;
}

void mip_nlipc_lock(void)
{
	pthread_mutex_lock(&global_lock);
}

void mip_nlipc_unlock(void)
{
	pthread_mutex_unlock(&global_lock);
}

struct nl_ipc_msg_type aa6_types[] = {
/*	{.type = MSG_TEST_CONNECTION, .hdr_len = sizeof(struct aa6_msg_test_connection)},*/
	{.type = MSG_MIP_FB_SETIDENTITY, .hdr_len = sizeof(struct mip_nlmsg)},
	{.type = MSG_MIP_FB_SETSUMMARY, .hdr_len = sizeof(struct mip_nlmsg)},
	{.type = MSG_MIP_FB_GETSUMMARY, .hdr_len = sizeof(struct mip_nlmsg)},
	{.type = MSG_MIP_MCOA_SETBINDING, .hdr_len = sizeof(struct mip_nlmsg)},
	{.type = MSG_MIP_MCOA_GETBINDING, .hdr_len = sizeof(struct mip_nlmsg)},
	{.type = 0, .hdr_len = 0},
};
const struct nl_ipc_group ipc_group_aa6 = {
	.on_recv = _msg_on_data,
	.on_acked = _msg_on_acked,
	.on_timeout = NULL,
	.userdata = &mip_nlipc_userdata,
	.msg_types = aa6_types
};

int mip_nlipc_init(void)
{
	int err = 0;

	/* Initialize the library */
	handle = nl_ipc_init(IPC_ID_IPMOBILITY);
	if (!handle)
		goto out_err;

	/* Setup locking */
	nl_ipc_override_mutex(handle, _mutex_lock, _mutex_unlock, &global_lock);

	/* Open a socket to group NLIPC_GROUP_AA6 */
	err = nl_ipc_connect(handle, IPC_GROUP_AA6, &ipc_group_aa6);
	if (err)
		goto out_err;
#if 0
	/* Send a data to server */
	err = send_test_connection("test", "test connection", "aa6-receiver");
	if (err)
		printf("Error sending the message %d\n", err);
#endif
	return 0;

out_err:
	nl_ipc_finish(handle);
	printf("Client stops with error %d: %s\n", -err, nl_geterror(-err));
	return err;
}

void mip_nlipc_destroy(void)
{
	/* Close the socket on group GROUP_TEST */
	nl_ipc_close(handle, IPC_GROUP_AA6);
	nl_ipc_finish(handle);
}

