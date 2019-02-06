/*
 * Copyright (c) 2016 VMware, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __OVS_DP_INTERFACE_CT_EXT_H_
#define __OVS_DP_INTERFACE_CT_EXT_H_ 1

/* Conntrack Netlink headers */
#define NFNL_TYPE_CT_GET (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_GET)
#define NFNL_TYPE_CT_DEL (NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_DELETE)
#define IS_NFNL_CMD(nlmsgType) ((nlmsgType == NFNL_TYPE_CT_GET) \
                                 || (nlmsgType == NFNL_TYPE_CT_DEL))
#define OVS_NL_CT_ATTR_MAX (IPCTNL_MSG_MAX - 1)

#define OVS_CT_FAMILY  "ovs_ct"
#define OVS_CT_MCGROUP "ovs_ct"
#define OVS_CT_VERSION 1

/* File: nfnetlink.h */
enum nfnetlink_groups {
    NFNLGRP_NONE,
#define NFNLGRP_NONE                NFNLGRP_NONE
    NFNLGRP_CONNTRACK_NEW,
#define NFNLGRP_CONNTRACK_NEW       NFNLGRP_CONNTRACK_NEW
    NFNLGRP_CONNTRACK_UPDATE,
#define NFNLGRP_CONNTRACK_UPDATE    NFNLGRP_CONNTRACK_UPDATE
    NFNLGRP_CONNTRACK_DESTROY,
#define NFNLGRP_CONNTRACK_DESTROY   NFNLGRP_CONNTRACK_DESTROY
    NFNLGRP_CONNTRACK_EXP_NEW,
#define NFNLGRP_CONNTRACK_EXP_NEW   NFNLGRP_CONNTRACK_EXP_NEW
    NFNLGRP_CONNTRACK_EXP_UPDATE,
#define NFNLGRP_CONNTRACK_EXP_UPDATE    NFNLGRP_CONNTRACK_EXP_UPDATE
    NFNLGRP_CONNTRACK_EXP_DESTROY,
#define NFNLGRP_CONNTRACK_EXP_DESTROY   NFNLGRP_CONNTRACK_EXP_DESTROY
    NFNLGRP_NFTABLES,
#define NFNLGRP_NFTABLES    NFNLGRP_NFTABLES
    __NFNLGRP_MAX,
};
#define NFNLGRP_MAX (__NFNLGRP_MAX - 1)

struct nfgenmsg {
    UINT8  nfgen_family;        /* AF_xxx (AF_UNSPEC/AF_INET/AF_INET6) */
    UINT8  version;             /* nfnetlink version (currently set to v0) */
    UINT16 res_id;              /* resource id (unused in Windows) */
    struct ovs_header ovsHdr;   /* Pad this for Windows */
};

#define NFNETLINK_V0    0
#define NFNL_SUBSYS_ID(x)   ((x & 0xff00) >> 8)
#define NFNL_MSG_TYPE(x)    (x & 0x00ff)

#define NFNL_SUBSYS_NONE                0
#define NFNL_SUBSYS_CTNETLINK           1
#define NFNL_SUBSYS_CTNETLINK_EXP       2
#define NFNL_SUBSYS_QUEUE               3
#define NFNL_SUBSYS_ULOG                4
#define NFNL_SUBSYS_OSF                 5
#define NFNL_SUBSYS_IPSET               6
#define NFNL_SUBSYS_ACCT                7
#define NFNL_SUBSYS_CTNETLINK_TIMEOUT   8
#define NFNL_SUBSYS_CTHELPER            9
#define NFNL_SUBSYS_NFTABLES            10
#define NFNL_SUBSYS_NFT_COMPAT          11
#define NFNL_SUBSYS_COUNT               12

#define NFNL_MSG_BATCH_BEGIN    NLMSG_MIN_TYPE
#define NFNL_MSG_BATCH_END      NLMSG_MIN_TYPE+1

/* File: nf_conntrack_common.h */
enum ip_conntrack_info {
    IP_CT_ESTABLISHED,
    IP_CT_RELATED,
    IP_CT_NEW,
    IP_CT_IS_REPLY,
    IP_CT_ESTABLISHED_REPLY = IP_CT_ESTABLISHED + IP_CT_IS_REPLY,
    IP_CT_RELATED_REPLY = IP_CT_RELATED + IP_CT_IS_REPLY,
    IP_CT_NEW_REPLY = IP_CT_NEW + IP_CT_IS_REPLY,
    IP_CT_NUMBER = IP_CT_IS_REPLY * 2 - 1
};

enum ip_conntrack_status {
    IPS_EXPECTED_BIT = 0,
    IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),
    IPS_SEEN_REPLY_BIT = 1,
    IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),
    IPS_ASSURED_BIT = 2,
    IPS_ASSURED = (1 << IPS_ASSURED_BIT),
    IPS_CONFIRMED_BIT = 3,
    IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),
    IPS_SRC_NAT_BIT = 4,
    IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),
    IPS_DST_NAT_BIT = 5,
    IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),
    IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),
    IPS_SEQ_ADJUST_BIT = 6,
    IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),
    IPS_SRC_NAT_DONE_BIT = 7,
    IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),
    IPS_DST_NAT_DONE_BIT = 8,
    IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),
    IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),
    IPS_DYING_BIT = 9,
    IPS_DYING = (1 << IPS_DYING_BIT),
    IPS_FIXED_TIMEOUT_BIT = 10,
    IPS_FIXED_TIMEOUT = (1 << IPS_FIXED_TIMEOUT_BIT),
    IPS_TEMPLATE_BIT = 11,
    IPS_TEMPLATE = (1 << IPS_TEMPLATE_BIT),
    IPS_UNTRACKED_BIT = 12,
    IPS_UNTRACKED = (1 << IPS_UNTRACKED_BIT),
};

enum ip_conntrack_events {
    IPCT_NEW,
    IPCT_RELATED,
    IPCT_DESTROY,
    IPCT_REPLY,
    IPCT_ASSURED,
    IPCT_PROTOINFO,
    IPCT_HELPER,
    IPCT_MARK,
    IPCT_NATSEQADJ,
    IPCT_SECMARK,
    IPCT_LABEL,
};

enum ip_conntrack_expect_events {
    IPEXP_NEW,
    IPEXP_DESTROY,
};

#define NF_CT_EXPECT_PERMANENT  0x1
#define NF_CT_EXPECT_INACTIVE   0x2
#define NF_CT_EXPECT_USERSPACE  0x4

/* File: nfnetlink_conntrack.h */
enum cntl_msg_types {
    IPCTNL_MSG_CT_NEW,
    IPCTNL_MSG_CT_GET,
    IPCTNL_MSG_CT_DELETE,
    IPCTNL_MSG_CT_GET_CTRZERO,
    IPCTNL_MSG_CT_GET_STATS_CPU,
    IPCTNL_MSG_CT_GET_STATS,
    IPCTNL_MSG_CT_GET_DYING,
    IPCTNL_MSG_CT_GET_UNCONFIRMED,
    IPCTNL_MSG_MAX
};

enum ctnl_exp_msg_types {
    IPCTNL_MSG_EXP_NEW,
    IPCTNL_MSG_EXP_GET,
    IPCTNL_MSG_EXP_DELETE,
    IPCTNL_MSG_EXP_GET_STATS_CPU,
    IPCTNL_MSG_EXP_MAX
};

enum ctattr_type {
    CTA_UNSPEC,
    CTA_TUPLE_ORIG,
    CTA_TUPLE_REPLY,
    CTA_STATUS,
    CTA_PROTOINFO,
    CTA_HELP,
    CTA_NAT_SRC,
#define CTA_NAT CTA_NAT_SRC
    CTA_TIMEOUT,
    CTA_MARK,
    CTA_COUNTERS_ORIG,
    CTA_COUNTERS_REPLY,
    CTA_USE,
    CTA_ID,
    CTA_NAT_DST,
    CTA_TUPLE_MASTER,
    CTA_NAT_SEQ_ADJ_ORIG,
    CTA_NAT_SEQ_ADJ_REPLY,
    CTA_SECMARK,
    CTA_ZONE,
    CTA_SECCTX,
    CTA_TIMESTAMP,
    CTA_MARK_MASK,
    CTA_LABELS,
    CTA_LABELS_MASK,
    __CTA_MAX
};
#define CTA_MAX (__CTA_MAX - 1)

enum ctattr_tuple {
    CTA_TUPLE_UNSPEC,
    CTA_TUPLE_IP,
    CTA_TUPLE_PROTO,
    __CTA_TUPLE_MAX
};
#define CTA_TUPLE_MAX (__CTA_TUPLE_MAX - 1)

enum ctattr_ip {
    CTA_IP_UNSPEC,
    CTA_IP_V4_SRC,
    CTA_IP_V4_DST,
    CTA_IP_V6_SRC,
    CTA_IP_V6_DST,
    __CTA_IP_MAX
};
#define CTA_IP_MAX (__CTA_IP_MAX - 1)

enum ctattr_l4proto {
    CTA_PROTO_UNSPEC,
    CTA_PROTO_NUM,
    CTA_PROTO_SRC_PORT,
    CTA_PROTO_DST_PORT,
    CTA_PROTO_ICMP_ID,
    CTA_PROTO_ICMP_TYPE,
    CTA_PROTO_ICMP_CODE,
    CTA_PROTO_ICMPV6_ID,
    CTA_PROTO_ICMPV6_TYPE,
    CTA_PROTO_ICMPV6_CODE,
    __CTA_PROTO_MAX
};
#define CTA_PROTO_MAX (__CTA_PROTO_MAX - 1)

enum ctattr_protoinfo {
    CTA_PROTOINFO_UNSPEC,
    CTA_PROTOINFO_TCP,
    CTA_PROTOINFO_DCCP,
    CTA_PROTOINFO_SCTP,
    __CTA_PROTOINFO_MAX
};
#define CTA_PROTOINFO_MAX (__CTA_PROTOINFO_MAX - 1)

enum ctattr_protoinfo_tcp {
    CTA_PROTOINFO_TCP_UNSPEC,
    CTA_PROTOINFO_TCP_STATE,
    CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
    CTA_PROTOINFO_TCP_WSCALE_REPLY,
    CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
    CTA_PROTOINFO_TCP_FLAGS_REPLY,
    __CTA_PROTOINFO_TCP_MAX
};
#define CTA_PROTOINFO_TCP_MAX (__CTA_PROTOINFO_TCP_MAX - 1)

enum ctattr_protoinfo_dccp {
    CTA_PROTOINFO_DCCP_UNSPEC,
    CTA_PROTOINFO_DCCP_STATE,
    CTA_PROTOINFO_DCCP_ROLE,
    CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ,
    __CTA_PROTOINFO_DCCP_MAX,
};
#define CTA_PROTOINFO_DCCP_MAX (__CTA_PROTOINFO_DCCP_MAX - 1)

enum ctattr_protoinfo_sctp {
    CTA_PROTOINFO_SCTP_UNSPEC,
    CTA_PROTOINFO_SCTP_STATE,
    CTA_PROTOINFO_SCTP_VTAG_ORIGINAL,
    CTA_PROTOINFO_SCTP_VTAG_REPLY,
    __CTA_PROTOINFO_SCTP_MAX
};
#define CTA_PROTOINFO_SCTP_MAX (__CTA_PROTOINFO_SCTP_MAX - 1)

enum ctattr_counters {
    CTA_COUNTERS_UNSPEC,
    CTA_COUNTERS_PACKETS,
    CTA_COUNTERS_BYTES,
    CTA_COUNTERS32_PACKETS,
    CTA_COUNTERS32_BYTES,
    __CTA_COUNTERS_MAX
};
#define CTA_COUNTERS_MAX (__CTA_COUNTERS_MAX - 1)

enum ctattr_tstamp {
    CTA_TIMESTAMP_UNSPEC,
    CTA_TIMESTAMP_START,
    CTA_TIMESTAMP_STOP,
    __CTA_TIMESTAMP_MAX
};
#define CTA_TIMESTAMP_MAX (__CTA_TIMESTAMP_MAX - 1)

enum ctattr_nat {
    CTA_NAT_UNSPEC,
    CTA_NAT_V4_MINIP,
#define CTA_NAT_MINIP CTA_NAT_V4_MINIP
    CTA_NAT_V4_MAXIP,
#define CTA_NAT_MAXIP CTA_NAT_V4_MAXIP
    CTA_NAT_PROTO,
    CTA_NAT_V6_MINIP,
    CTA_NAT_V6_MAXIP,
    __CTA_NAT_MAX
};
#define CTA_NAT_MAX (__CTA_NAT_MAX - 1)

enum ctattr_protonat {
    CTA_PROTONAT_UNSPEC,
    CTA_PROTONAT_PORT_MIN,
    CTA_PROTONAT_PORT_MAX,
    __CTA_PROTONAT_MAX
};
#define CTA_PROTONAT_MAX (__CTA_PROTONAT_MAX - 1)

enum ctattr_natseq {
    CTA_NAT_SEQ_UNSPEC,
    CTA_NAT_SEQ_CORRECTION_POS,
    CTA_NAT_SEQ_OFFSET_BEFORE,
    CTA_NAT_SEQ_OFFSET_AFTER,
    __CTA_NAT_SEQ_MAX
};
#define CTA_NAT_SEQ_MAX (__CTA_NAT_SEQ_MAX - 1)

enum ctattr_expect {
    CTA_EXPECT_UNSPEC,
    CTA_EXPECT_MASTER,
    CTA_EXPECT_TUPLE,
    CTA_EXPECT_MASK,
    CTA_EXPECT_TIMEOUT,
    CTA_EXPECT_ID,
    CTA_EXPECT_HELP_NAME,
    CTA_EXPECT_ZONE,
    CTA_EXPECT_FLAGS,
    CTA_EXPECT_CLASS,
    CTA_EXPECT_NAT,
    CTA_EXPECT_FN,
    __CTA_EXPECT_MAX
};
#define CTA_EXPECT_MAX (__CTA_EXPECT_MAX - 1)

enum ctattr_expect_nat {
    CTA_EXPECT_NAT_UNSPEC,
    CTA_EXPECT_NAT_DIR,
    CTA_EXPECT_NAT_TUPLE,
    __CTA_EXPECT_NAT_MAX
};
#define CTA_EXPECT_NAT_MAX (__CTA_EXPECT_NAT_MAX - 1)

enum ctattr_help {
    CTA_HELP_UNSPEC,
    CTA_HELP_NAME,
    CTA_HELP_INFO,
    __CTA_HELP_MAX
};
#define CTA_HELP_MAX (__CTA_HELP_MAX - 1)

enum ctattr_secctx {
    CTA_SECCTX_UNSPEC,
    CTA_SECCTX_NAME,
    __CTA_SECCTX_MAX
};
#define CTA_SECCTX_MAX (__CTA_SECCTX_MAX - 1)

enum ctattr_stats_cpu {
    CTA_STATS_UNSPEC,
    CTA_STATS_SEARCHED,
    CTA_STATS_FOUND,
    CTA_STATS_NEW,
    CTA_STATS_INVALID,
    CTA_STATS_IGNORE,
    CTA_STATS_DELETE,
    CTA_STATS_DELETE_LIST,
    CTA_STATS_INSERT,
    CTA_STATS_INSERT_FAILED,
    CTA_STATS_DROP,
    CTA_STATS_EARLY_DROP,
    CTA_STATS_ERROR,
    CTA_STATS_SEARCH_RESTART,
    __CTA_STATS_MAX,
};
#define CTA_STATS_MAX (__CTA_STATS_MAX - 1)

enum ctattr_stats_global {
    CTA_STATS_GLOBAL_UNSPEC,
    CTA_STATS_GLOBAL_ENTRIES,
    __CTA_STATS_GLOBAL_MAX,
};
#define CTA_STATS_GLOBAL_MAX (__CTA_STATS_GLOBAL_MAX - 1)

enum ctattr_expect_stats {
    CTA_STATS_EXP_UNSPEC,
    CTA_STATS_EXP_NEW,
    CTA_STATS_EXP_CREATE,
    CTA_STATS_EXP_DELETE,
    __CTA_STATS_EXP_MAX,
};
#define CTA_STATS_EXP_MAX (__CTA_STATS_EXP_MAX - 1)

/* File: nf_conntrack_tcp.h */
enum tcp_conntrack {
    TCP_CONNTRACK_NONE,
    TCP_CONNTRACK_SYN_SENT,
    TCP_CONNTRACK_SYN_RECV,
    TCP_CONNTRACK_ESTABLISHED,
    TCP_CONNTRACK_FIN_WAIT,
    TCP_CONNTRACK_CLOSE_WAIT,
    TCP_CONNTRACK_LAST_ACK,
    TCP_CONNTRACK_TIME_WAIT,
    TCP_CONNTRACK_CLOSE,
    TCP_CONNTRACK_LISTEN,
#define TCP_CONNTRACK_SYN_SENT2 TCP_CONNTRACK_LISTEN
    TCP_CONNTRACK_MAX,
    TCP_CONNTRACK_IGNORE,
    TCP_CONNTRACK_RETRANS,
    TCP_CONNTRACK_UNACK,
    TCP_CONNTRACK_TIMEOUT_MAX
};

#define IP_CT_TCP_FLAG_WINDOW_SCALE     0x01
#define IP_CT_TCP_FLAG_SACK_PERM        0x02
#define IP_CT_TCP_FLAG_CLOSE_INIT       0x04
#define IP_CT_TCP_FLAG_BE_LIBERAL       0x08
#define IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED  0x10
#define IP_CT_TCP_FLAG_MAXACK_SET       0x20

struct nf_ct_tcp_flags {
    UINT8 flags;
    UINT8 mask;
};

#endif /* __OVS_DP_INTERFACE_CT_EXT_H_ */
