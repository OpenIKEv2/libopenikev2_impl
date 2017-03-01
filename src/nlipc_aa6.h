
#ifndef _NLIPC_FB_H
#define _NLIPC_FB_H

#define IPC_GROUP_AA6 0x02

#define NLATTR_FB_FID         0x0101 /* uint16_t */
#define NLATTR_FB_PRIORITY    0x0102 /* uint16_t */
#define NLATTR_FB_SOPT_BR     0x0103 /* (complex data) */
#define NLATTR_FB_SOPT_TS     0x0104 /* struct flow_ts_ipv6 */
#define NLATTR_FB_SUMMARY     0x0105 /* (complex data) */

#define NLATTR_MCOA_COA       0x0111 /* struct in6_addr */
#define NLATTR_MCOA_HAA       0x0112 /* struct in6_addr */
#define NLATTR_MCOA_BID       0x0113 /* uint16_t */
#define NLATTR_MCOA_SEQ       0x0114 /* uint16_t */
#define NLATTR_MCOA_FLAGS     0x0115 /* uint16_t */
#define NLATTR_MCOA_EXPIRES   0x0116 /* struct timespec */

#define NLATTR_MAX            0x0117

#define MSG_MIP_FB_SETIDENTITY 0x0101
#define MSG_MIP_FB_SETSUMMARY  0x0102
#define MSG_MIP_FB_GETSUMMARY  0x0103

#define MSG_MIP_MCOA_SETBINDING 0x0111
#define MSG_MIP_MCOA_GETBINDING 0x0112

#define IPC_ID_NLIPC_UTIL   "nlipc_util"
#define IPC_ID_FBCLIENT     "fbclient"
#define IPC_ID_POLICYD      "policyd"
#define IPC_ID_IPMOBILITY   "ipmobility"
#define IPC_ID_IKE          "ike"


struct flow_ts_ipv6 {
	struct in6_addr src_beg;
	struct in6_addr src_end;
	struct in6_addr dst_beg;
	struct in6_addr dst_end;
	uint16_t spi_beg;
	uint16_t spi_end;
	uint16_t sport_beg;
	uint16_t sport_end;
	uint16_t dport_beg;
	uint16_t dport_end;
	uint32_t fl_beg;
	uint32_t fl_end;
	uint8_t tc_beg;
	uint8_t tc_end;
	uint8_t nh_beg;
	uint8_t nh_end;
};

struct mip_nlmsg {
	struct in6_addr hoa;
};

#endif

