
#ifndef MIP_NLIPC_H
#define MIP_NLIPC_H

#include <pthread.h>
#include "tqueue.h"


struct mip_nlipc_binding {
	struct in6_addr hoa;
	struct in6_addr coa;
	struct in6_addr haa;
	struct timespec expires;
	uint16_t bid;
	uint16_t flags;
	uint16_t seq;
};

struct mip_nlipc_udata {
#ifdef ENABLE_FB
	pthread_mutex_t fb_lock;
	pthread_cond_t fb_cond;
	struct list_head fb_entries;
#endif
};

extern struct mip_nlipc_udata mip_nlipc_userdata;

int mip_nlipc_init(void);
void mip_nlipc_destroy(void);
int mip_nlipc_recvloop(void);
void mip_nlipc_lock(void);
void mip_nlipc_unlock(void);

/* int mip_nlipc_test_connection(const char *testdata, const char *peer); */

struct fbentry;
int mip_nlipc_send_fb_setidentity(struct in6_addr *peer, struct fbentry *fbe, int nolock);
int mip_nlipc_send_fb_setsummary(struct in6_addr *peer, struct list_head *fb_summary, int fb_count,
                                 int nolock);
int mip_nlipc_send_fb_getsummary(struct in6_addr *peer, int nolock);

int mip_nlipc_send_mcoa_setbinding(struct mip_nlipc_binding *be);

#endif /* MIP_NLIPC_H */
