#ifndef __PPPOE_LEARNER_H
#define __PPPOE_LEARNER_H

#include "config.h"
#include "pppoe_common.h"
#include "event.h"


/* An Ethernet interface */
typedef struct {
    char name[IFNAMSIZ+1];	/* Interface name */
    int discovery_sock;			/* Socket for discovery frames */
    int session_sock;			/* Socket for session frames */
    unsigned char mac[ETH_ALEN]; /* MAC address */
    EventHandler *eh;		/* Event handler for this interface */
    EventHandler *session_eh;		/* Event handler for this interface */
    UINT16_t mtu;               /* MTU of interface */
} Interface;


#define FLAG_RECVD_PADT      1
#define FLAG_USER_SET        2
#define FLAG_IP_SET          4
#define FLAG_SENT_PADT       8
#define FLAG_GOT_ECHO_REQUEST  0x10
#define FLAG_SENT_ECHO_REPLAY   0x20

/* Server Discovery phase states */
typedef enum ConnectionStateEnum {
    ConnectionStateIdle = 0,
    //ConnectionStateWaitPADI = 1,
    ConnectionStateSentPADO = 2,
    //ConnectionStateWaitPADR = 3,
    ConnectionStateSentPADS = 4,
    ConnectionStateNakLCP = 5,
    ConnectionStateAckLCP = 6,
    ConnectionStateWaitPAP = 7,
    ConnectionStateGotPAP = 8,
    ConnectionStateTerminated = 9,
} ConnectionState_t;



/* A client session */
typedef struct ClientSessionStruct {
    struct ClientSessionStruct *next; /* In list of free or active sessions */
    //PppoeSessionFunctionTable *funcs; /* Function table */
    //pid_t pid;			/* PID of child handling session */
    ConnectionState_t ConnectionState;    /* new add for self LCP/PAP stage control */
    Interface *ethif;		/* Ethernet interface */
    //unsigned char myip[IPV4ALEN]; /* Local IP address */
    //unsigned char peerip[IPV4ALEN]; /* Desired IP address of peer */
    UINT16_t sessID;		/* Session number */
    unsigned char peerMac[ETH_ALEN]; /* Peer's Ethernet address */
    unsigned int flags;		/* Various flags */
    time_t startTime;		/* When session started */
    char const *serviceName;	/* Service name */
    UINT16_t requested_mtu;     /* Requested PPP_MAX_PAYLOAD  per RFC 4638 */
    unsigned int session_pkt_cnt;
    unsigned int lcp_authtype_ack;
    unsigned int magic;
} ClientSession;


typedef struct {
    //int is_start_learn;
    PppoeProbeInfo pppoeProbe;
} PppoeLearnInfo;

PppoeLearnInfo pppoeLearnInfo;

void pppoeLearnerTermHandler(int sig);
int pppoeLearnerInit(unsigned char *ifname);
int pppoeLearnerDeinit(void);


#endif
