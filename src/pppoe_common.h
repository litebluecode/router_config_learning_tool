#ifndef __PPPOE_COMMON_H
#define __PPPOE_COMMON_H

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include "config.h"

#include <sys/socket.h>
#include <sys/types.h>
#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif

#include <stdio.h>		/* For FILE */
#include <sys/types.h>		/* For pid_t */

/* How do we access raw Ethernet devices? */
#undef USE_LINUX_PACKET

#if defined(HAVE_NETPACKET_PACKET_H) || defined(HAVE_LINUX_IF_PACKET_H)
#define USE_LINUX_PACKET 1
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#include <netinet/in.h>

#ifdef HAVE_NETINET_IF_ETHER_H
#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif


/* Ethernet frame types according to RFC 2516 */
#define ETH_PPPOE_DISCOVERY 0x8863
#define ETH_PPPOE_SESSION   0x8864

/* But some brain-dead peers disobey the RFC, so frame types are variables */
/* Assume nobody brain-dead */
//extern UINT16_t Eth_PPPOE_Discovery;
//extern UINT16_t Eth_PPPOE_Session;

/* PPPoE codes */
#define CODE_PADI           0x09
#define CODE_PADO           0x07
#define CODE_PADR           0x19
#define CODE_PADS           0x65
#define CODE_PADT           0xA7

/* Extensions from draft-carrel-info-pppoe-ext-00 */
/* I do NOT like PADM or PADN, but they are here for completeness */
#define CODE_PADM           0xD3
#define CODE_PADN           0xD4

#define CODE_SESS           0x00

/* PPPoE Tags */
#define TAG_END_OF_LIST        0x0000
#define TAG_SERVICE_NAME       0x0101
#define TAG_AC_NAME            0x0102
#define TAG_HOST_UNIQ          0x0103
#define TAG_AC_COOKIE          0x0104
#define TAG_VENDOR_SPECIFIC    0x0105
#define TAG_RELAY_SESSION_ID   0x0110
#define TAG_PPP_MAX_PAYLOAD    0x0120
#define TAG_SERVICE_NAME_ERROR 0x0201
#define TAG_AC_SYSTEM_ERROR    0x0202
#define TAG_GENERIC_ERROR      0x0203

/* Extensions from draft-carrel-info-pppoe-ext-00 */
/* I do NOT like these tags one little bit */
#define TAG_HURL               0x111
#define TAG_MOTM               0x112
#define TAG_IP_ROUTE_ADD       0x121

/* Discovery phase states */
#define STATE_SENT_PADI     0
#define STATE_RECEIVED_PADO 1
#define STATE_SENT_PADR     2
#define STATE_SESSION       3
#define STATE_TERMINATED    4

/* How many PADI/PADS attempts? */
#define MAX_PADI_ATTEMPTS 3

/* Initial timeout for PADO/PADS */
#define PADI_TIMEOUT 5

/* States for scanning PPP frames */
#define STATE_WAITFOR_FRAME_ADDR 0
#define STATE_DROP_PROTO         1
#define STATE_BUILDING_PACKET    2

/* Special PPP frame characters */
#define FRAME_ESC    0x7D
#define FRAME_FLAG   0x7E
#define FRAME_ADDR   0xFF
#define FRAME_CTRL   0x03
#define FRAME_ENC    0x20

#define IPV4ALEN     4
#define SMALLBUF   256

/* Allow for 1500-byte PPPoE data which makes the
   Ethernet packet size bigger by 8 bytes */
#define ETH_JUMBO_LEN (ETH_DATA_LEN+8)

/* A PPPoE Packet, including Ethernet headers */
typedef struct PPPoEPacketStruct {
    struct ethhdr ethHdr;	/* Ethernet header */
#ifdef PACK_BITFIELDS_REVERSED
    unsigned int type:4;	/* PPPoE Type (must be 1) */
    unsigned int ver:4;		/* PPPoE Version (must be 1) */
#else
    unsigned int ver:4;		/* PPPoE Version (must be 1) */
    unsigned int type:4;	/* PPPoE Type (must be 1) */
#endif
    unsigned int code:8;	/* PPPoE code */
    unsigned int session:16;	/* PPPoE session */
    unsigned int length:16;	/* Payload length */
    unsigned char payload[ETH_JUMBO_LEN]; /* A bit of room to spare */
} __packed PPPoEPacket;

/* Header size of a PPPoE packet */
#define PPPOE_OVERHEAD 6  /* type, code, session, length */
#define HDR_SIZE (sizeof(struct ethhdr) + PPPOE_OVERHEAD)
#define MAX_PPPOE_PAYLOAD (ETH_JUMBO_LEN - PPPOE_OVERHEAD)
#define PPP_OVERHEAD 2
#define MAX_PPPOE_MTU (MAX_PPPOE_PAYLOAD - PPP_OVERHEAD)
#define TOTAL_OVERHEAD (PPPOE_OVERHEAD + PPP_OVERHEAD)

/* Normal PPPoE MTU without jumbo frames */
#define ETH_PPPOE_MTU (ETH_DATA_LEN - TOTAL_OVERHEAD)

/* PPPoE Tag */
typedef struct PPPoETagStruct {
    unsigned int type:16;	/* tag type */
    unsigned int length:16;	/* Length of payload */
    unsigned char payload[ETH_JUMBO_LEN]; /* A LOT of room to spare */
} __packed PPPoETag;
/* Header size of a PPPoE tag */
#define TAG_HDR_SIZE 4

/* Chunk to read from stdin */
#define READ_CHUNK 4096

/* Function passed to parsePacket */
typedef void ParseFunc(UINT16_t type,
		       UINT16_t len,
		       unsigned char *data,
		       void *extra);

#define PPPINITFCS16    0xffff  /* Initial FCS value */

/* Keep track of the state of a connection -- collect everything in
   one spot */

typedef struct PPPoEConnectionStruct {
    int discoveryState;		/* Where we are in discovery */
    int discoverySocket;	/* Raw socket for discovery frames */
    int sessionSocket;		/* Raw socket for session frames */
    unsigned char myEth[ETH_ALEN]; /* My MAC address */
    unsigned char peerEth[ETH_ALEN]; /* Peer's MAC address */
#ifdef PLUGIN
    unsigned char req_peer_mac[ETH_ALEN]; /* required peer MAC address */
    unsigned char req_peer;     /* require mac addr to match req_peer_mac */
#endif

    UINT16_t session;		/* Session ID */
    char *ifName;		/* Interface name */
    char *serviceName;		/* Desired service name, if any */
    char *acName;		/* Desired AC name, if any */
    int synchronous;		/* Use synchronous PPP */
    char *hostUniq;		/* Host-Uniq tag, if any */
    int printACNames;		/* Just print AC names */
    int skipDiscovery;		/* Skip discovery */
    int noDiscoverySocket;	/* Don't even open discovery socket */
    int killSession;		/* Kill session and exit */
    FILE *debugFile;		/* Debug file for dumping packets */
    int numPADOs;		/* Number of PADO packets received */
    PPPoETag cookie;		/* We have to send this if we get it */
    PPPoETag relayId;		/* Ditto */
    int PADSHadError;           /* If PADS had an error tag */
    int discoveryTimeout;       /* Timeout for discovery packets */
#ifdef PLUGIN
    int seenMaxPayload;
    int mtu;
    int mru;
#endif
} PPPoEConnection;


#define CHECK_ROOM(cursor, start, len) \
do {\
    if (((cursor)-(start))+(len) > MAX_PPPOE_PAYLOAD) { \
        ERR("Would create too-long packet, now=%d, add right away=%d", ((cursor)-(start)), (len)); \
        return; \
    } \
} while(0)


int parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra);
void parseLogErrs(UINT16_t typ, UINT16_t len, unsigned char *data, void *xtra);

void sendPADT(PPPoEConnection *conn, char const *msg);


/* Function Prototypes */
void fatalSys(char const *str);
void rp_fatal(char const *str);
void printErr(char const *str);
void sysErr(char const *str);


/************************** for Session ********************************/

typedef struct PPPSubProtocolPacketStruct {
    unsigned short protocol;    /* PPP sub protocol */
    unsigned char code;
    unsigned char identifier;
    unsigned short length;  /* count from "code" to "the end of data[1]" */
    unsigned char data[1];
#if 0
    union {
        struct LCPPacketStruct {
            unsigned char LCPCode;
            unsigned char identifier;
            unsigned short length;
            unsigned char *options;
        } LCP;
        struct PAPPacketStruct {
            unsigned char authCode;
            unsigned char identifier;
            unsigned short length;
            unsigned char peerIDLength;
            unsigned char *peerID;
            unsigned char passwdLength;
            unsigned char *passwd;
        } PAP;
    } payload;
#endif
} __packed PPPSubProtocolPacket;

/* Header size of a PPPoE Sub protocol packet */
#define MIN_PPP_SUB_PROTO_HDR_SIZE 6
#define TOTOAL_PPP_SUB_PROTO_HDR_SIZE (sizeof(struct ethhdr) + \
                PPPOE_OVERHEAD + MIN_PPP_SUB_PROTO_HDR_SIZE)

typedef struct PPPSubProtoOptionStruct {
    unsigned char type;	/* type */
    unsigned char length;	/* Length of all option */
    unsigned char option[1]; /* option variable */
} __packed PPPSubProtoOption;


/*
 * Protocol field values.
 */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
//#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */


/*
 *  CP (LCP, IPCP, etc.) codes.
 */
#define CONFREQ		1	/* Configuration Request */
#define CONFACK		2	/* Configuration Ack */
#define CONFNAK		3	/* Configuration Nak */
#define CONFREJ		4	/* Configuration Reject */
#define TERMREQ		5	/* Termination Request */
#define TERMACK		6	/* Termination Ack */
#define CODEREJ		7	/* Code Reject */

/*
 * LCP-specific packet types (code numbers).
 */
#define PROTREJ		8	/* Protocol Reject */
#define ECHOREQ		9	/* Echo Request */
#define ECHOREP		10	/* Echo Reply */
#define DISCREQ		11	/* Discard Request */
#define IDENTIF			12	/* Identification */
#define TIMEREM		13	/* Time Remaining */

/*
 * Options.
 */
#define CI_MRU				1	/* Maximum Receive Unit */
#define CI_AUTHTYPE		3	/* Authentication Type */
#define CI_MAGICNUMBER	5	/* Magic Number */

#define DEFMRU		1480 //1500		/* Try for this */
#define MINMRU		128		/* No MRUs below this */
#define MAXMRU	16384		/* Normally limit MRU to this */


/* PAP Auth Code */
#define PAP_AREQ	1
#define PAP_AACK	2
#define PAP_ANAK	3

#define PAP_AUTH_FAIL_STRING "Authentication failure"

#define OPT_BIT(B) (1<<(B))
struct LCPOptionValueStruct {
    unsigned short LCP_option_peer_max_receive_unit;
    unsigned short LCP_option_peer_authtype;
    unsigned int LCP_option_peer_magic_number;
    unsigned int LCP_option_set_map;
};

#ifndef MAX_AUTH_BUF_LEN
#define MAX_AUTH_BUF_LEN 64
#endif

typedef struct {
    int rx_count;
    //unsigned char srcMac[ETH_ALEN];
    //unsigned char destMac[ETH_ALEN];
    unsigned char peer_auth_user[MAX_AUTH_BUF_LEN+1];
    unsigned char peer_auth_passwd[MAX_AUTH_BUF_LEN+1];
    unsigned char peer_auth_count;
} PppoeProbeInfo;


struct LCPOptionValueStruct negoOpt;

unsigned char nak_option_payload[MAX_PPPOE_PAYLOAD];
unsigned short nak_option_payload_len; 

unsigned char peer_option_payload[MAX_PPPOE_PAYLOAD];
unsigned short peer_option_payload_len; 


int parseSessionPacket(PPPSubProtocolPacket *sPacket, ParseFunc *func, void *extra);
int parsePAPPacket(PPPSubProtocolPacket *sPacket, PppoeProbeInfo *pppoeProbeInfoPtr);

#endif
