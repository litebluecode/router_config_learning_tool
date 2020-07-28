#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include "pppoe_learner.h"
#include "packet.h"

#include <sys/socket.h>
#include <sys/types.h>
#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif

#include "md5.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/file.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#include <time.h>

#include <signal.h>

PppoeLearnInfo pppoeLearnInfo;

static char *SESS_CODE_STR[TIMEREM] = {
    "ConfReq", "ConfAck", "ConfNack", "ConfRej",
    "TermReq", "TermAck", "CodeRej", "ProtRej",
    "EchoReq", "EchoRep", "DiscReq", "Identif", "TimeRem"};

char *getSessCodeStr(int code)
{
    //DBG("code=%d, str=%s", code, SESS_CODE_STR[code]);
    if (code >= CONFREQ && code <= TIMEREM)
    {
        return SESS_CODE_STR[code];
    }

    return "UnknownCode";
}

#define control_session_started(x) (void) 0
#define control_session_terminated(x) (void) 0
#define control_exit() (void) 0
//#define realpeerip peerip

void InterfaceHandler(EventSelector *es,
			int fd, unsigned int flags, void *data);
void InterfaceSessionHandler(EventSelector *es,
                    int fd, unsigned int flags, void *data);
static void sendErrorPADS(int sock, unsigned char *source, unsigned char *dest,
			  int errorTag, char *errorMsg);





/* Offset of first session */
size_t SessOffset = 0;


/* Requested max_ppp_payload */
static UINT16_t max_ppp_payload = 0;

//static int Debug = 0;


/* Random seed for cookie generation */
#define SEED_LEN 16
#define MD5_LEN 16
#define COOKIE_LEN (MD5_LEN + sizeof(pid_t)) /* Cookie is 16-byte MD5 + PID of server */

static unsigned char CookieSeed[SEED_LEN];

#define MAXLINE 512

/* Our local IP address */
unsigned char LocalIP[IPV4ALEN] = {10, 0, 0, 1}; /* Counter optionally STARTS here */
unsigned char RemoteIP[IPV4ALEN] = {10, 67, 15, 1}; /* Counter STARTS here */

static PPPoETag hostUniq;
static PPPoETag relayId;
static PPPoETag receivedCookie;
static PPPoETag requestedService;

#define HOSTNAMELEN 256

/* Service-Names we advertise */
#define MAX_SERVICE_NAMES 1
static int NumServiceNames = 1;
#define MY_SERVICE_NAME "pppoe-server"
static char const *ServiceNames[MAX_SERVICE_NAMES] = {MY_SERVICE_NAME};


/* Access concentrator name */
char *ACName = "ACS";


Interface pppoeIface = {
    .name = LISTEN_INTERFACE_NAME,
};


#if 1
ClientSession WorkSession = {
    .ethif = &pppoeIface,
    .sessID = 0x1900,   /* = 25 */
    .flags = 0,
    .serviceName = MY_SERVICE_NAME,
    .requested_mtu = 1492,
    .ConnectionState = ConnectionStateIdle,
};
#endif


/**********************************************************************
* %FUNCTION: PppoeStopSession
* %ARGUMENTS:
*  ses -- the session
*  reason -- reason session is being stopped.
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Kills pppd.
***********************************************************************/
static void
PppoeStopSession(ClientSession *ses,
		 char const *reason)
{
    /* Temporary structure for sending PADT's. */
    PPPoEConnection conn;
    unsigned char nullMac[ETH_ALEN];

    memset(nullMac, 0, ETH_ALEN);
    if (memcmp(ses->peerMac, nullMac, ETH_ALEN) != 0) {
        memset(&conn, 0, sizeof(conn));
        conn.hostUniq = NULL;

        memcpy(conn.myEth, ses->ethif->mac, ETH_ALEN);
        conn.discoverySocket = ses->ethif->discovery_sock;
        conn.session = ses->sessID;
        memcpy(conn.peerEth, ses->peerMac, ETH_ALEN);
        sendPADT(&conn, reason);
    }
    memset(WorkSession.peerMac, 0, ETH_ALEN);
    WorkSession.sessID = htons(ntohs(WorkSession.sessID) + 1);
    WorkSession.session_pkt_cnt = 0;
    WorkSession.lcp_authtype_ack = 0;
    ses->flags |= FLAG_SENT_PADT;
    ses->ConnectionState = ConnectionStateIdle;
}


/**********************************************************************
*%FUNCTION: killAllSessions
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills all pppd processes (and hence all PPPoE sessions)
***********************************************************************/
void
killAllSessions(void)
{
    PppoeStopSession(&WorkSession, "Shutting Down");
}


/**********************************************************************
*%FUNCTION: parsePADITags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADI packet
***********************************************************************/
void
parsePADITags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_PPP_MAX_PAYLOAD:
	if (len == sizeof(max_ppp_payload)) {
	    memcpy(&max_ppp_payload, data, sizeof(max_ppp_payload));
	    max_ppp_payload = ntohs(max_ppp_payload);
	    if (max_ppp_payload <= ETH_PPPOE_MTU) {
		max_ppp_payload = 0;
	    }
	}
	break;
    case TAG_SERVICE_NAME:
	/* Copy requested service name */
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    }
}

/**********************************************************************
*%FUNCTION: parsePADRTags
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks interesting tags out of a PADR packet
***********************************************************************/
void
parsePADRTags(UINT16_t type, UINT16_t len, unsigned char *data,
	      void *extra)
{
    switch(type) {
    case TAG_PPP_MAX_PAYLOAD:
	if (len == sizeof(max_ppp_payload)) {
	    memcpy(&max_ppp_payload, data, sizeof(max_ppp_payload));
	    max_ppp_payload = ntohs(max_ppp_payload);
	    if (max_ppp_payload <= ETH_PPPOE_MTU) {
		max_ppp_payload = 0;
	    }
	}
	break;
    case TAG_RELAY_SESSION_ID:
	relayId.type = htons(type);
	relayId.length = htons(len);
	memcpy(relayId.payload, data, len);
	break;
    case TAG_HOST_UNIQ:
	hostUniq.type = htons(type);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, data, len);
	break;
    case TAG_AC_COOKIE:
	receivedCookie.type = htons(type);
	receivedCookie.length = htons(len);
	memcpy(receivedCookie.payload, data, len);
	break;
    case TAG_SERVICE_NAME:
	requestedService.type = htons(type);
	requestedService.length = htons(len);
	memcpy(requestedService.payload, data, len);
	break;
    }
}


void
parseLCPOption(UINT16_t option, UINT16_t optLen, unsigned char *data,
	      void *extra)
{
    memcpy(peer_option_payload + peer_option_payload_len, data, optLen);
    peer_option_payload_len += optLen;

    switch (option) {
        case CI_MRU:
            if (optLen != 4) {
                WARN("invalid option MRU optLen=%d", optLen);
                break;
            }
            negoOpt.LCP_option_peer_max_receive_unit = ntohs(*((unsigned short *)data+2));
            negoOpt.LCP_option_set_map |= OPT_BIT(CI_MRU);
            break;
        case CI_AUTHTYPE:
            if (optLen != 4) {
                WARN("invalid option authtype optLen=%d", optLen);
                break;
            }
            negoOpt.LCP_option_peer_authtype = ntohs(*((unsigned short *)data+2));
            negoOpt.LCP_option_set_map |= OPT_BIT(CI_AUTHTYPE);
            break;
        case CI_MAGICNUMBER:
            if (optLen != 6) {
                WARN("invalid option magic optLen=%d", optLen);
                break;
            }
            negoOpt.LCP_option_peer_magic_number = ntohl(*((unsigned int *)data+2));
            negoOpt.LCP_option_set_map |= OPT_BIT(CI_MAGICNUMBER);
            break;
        default:
            if ((nak_option_payload_len + optLen) > MAX_PPPOE_PAYLOAD) {
                ERR("nak option optLen error! (nak %d + optLen %d > max %d)",
                    nak_option_payload_len, optLen, MAX_PPPOE_PAYLOAD);
            }
            memcpy(nak_option_payload + nak_option_payload_len, data, optLen);
            nak_option_payload_len += optLen;

            if (option >= 32)
            {
                WARN("option too big, cant process! %d", option);
            }
            negoOpt.LCP_option_set_map |= OPT_BIT(option);
            WARN("unsupport parse option %#x, map=%#x", option, negoOpt.LCP_option_set_map);
            return;
    }
}


/**********************************************************************
*%FUNCTION: fatalSys
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to stderr and syslog and exits.
***********************************************************************/
void
fatalSys(char const *str)
{
    char buf[SMALLBUF];
    snprintf(buf, SMALLBUF, "%s: %s", str, strerror(errno));
    printErr(buf);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: sysErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message plus the errno value to syslog.
***********************************************************************/
void
sysErr(char const *str)
{
    char buf[1024];
    sprintf(buf, "%.256s: %.256s", str, strerror(errno));
    printErr(buf);
}

/**********************************************************************
*%FUNCTION: rp_fatal
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog and exits.
***********************************************************************/
void
rp_fatal(char const *str)
{
    printErr(str);
    control_exit();
    exit(EXIT_FAILURE);
}

/**********************************************************************
*%FUNCTION: genCookie
*%ARGUMENTS:
* peerEthAddr -- peer Ethernet address (6 bytes)
* myEthAddr -- my Ethernet address (6 bytes)
* seed -- random cookie seed to make things tasty (16 bytes)
* cookie -- buffer which is filled with server PID and
*           md5 sum of previous items
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Forms the md5 sum of peer MAC address, our MAC address and seed, useful
* in a PPPoE Cookie tag.
***********************************************************************/
void
genCookie(unsigned char const *peerEthAddr,
	  unsigned char const *myEthAddr,
	  unsigned char const *seed,
	  unsigned char *cookie)
{
    struct MD5Context ctx;
    pid_t pid = getpid();

    MD5Init(&ctx);
    MD5Update(&ctx, peerEthAddr, ETH_ALEN);
    MD5Update(&ctx, myEthAddr, ETH_ALEN);
    MD5Update(&ctx, seed, SEED_LEN);
    MD5Final(cookie, &ctx);
    memcpy(cookie+MD5_LEN, &pid, sizeof(pid));
}



void
processLCPEchoRequest(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket pado;
    PPPoETag acname;
    PPPoETag servname;
    PPPoETag cookie;
    size_t acname_len;
    unsigned char *cursor = pado.payload;
    UINT16_t plen;

    int sock = ethif->discovery_sock;
    int i;
    int ok = 0;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	ERR("PADI packet from non-unicast source address");
	return;
    }

    acname.type = htons(TAG_AC_NAME);
    acname_len = strlen(ACName);
    acname.length = htons(acname_len);
    memcpy(acname.payload, ACName, acname_len);

    relayId.type = 0;
    hostUniq.type = 0;
    requestedService.type = 0;
    max_ppp_payload = 0;

    parsePacket(packet, parsePADITags, NULL);

    /* If PADI specified non-default service name, and we do not offer
       that service, DO NOT send PADO */
    if (requestedService.type) {
	int slen = ntohs(requestedService.length);
	if (slen) {
	    for (i=0; i<NumServiceNames; i++) {
		if (slen == strlen(ServiceNames[i]) &&
		    !memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		    ok = 1;
		    break;
		}
	    }
	} else {
	    ok = 1;		/* Default service requested */
	}
    } else {
	ok = 1;			/* No Service-Name tag in PADI */
    }

    if (!ok) {
	/* PADI asked for unsupported service */
	return;
    }

    /* Generate a cookie */
    cookie.type = htons(TAG_AC_COOKIE);
    cookie.length = htons(COOKIE_LEN);
    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookie.payload);

    /* Construct a PADO packet */
    memcpy(pado.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pado.ethHdr.h_source, myAddr, ETH_ALEN);
    pado.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    pado.ver = 1;
    pado.type = 1;
    pado.code = CODE_PADO;
    pado.session = 0;
    plen = TAG_HDR_SIZE + acname_len;

    CHECK_ROOM(cursor, pado.payload, acname_len+TAG_HDR_SIZE);
    memcpy(cursor, &acname, acname_len + TAG_HDR_SIZE);
    cursor += acname_len + TAG_HDR_SIZE;

    /* If we asked for an MTU, handle it */
    if (max_ppp_payload > ETH_PPPOE_MTU && ethif->mtu > 0) {
	/* Shrink payload to fit */
	if (max_ppp_payload > ethif->mtu - TOTAL_OVERHEAD) {
	    max_ppp_payload = ethif->mtu - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_JUMBO_LEN - TOTAL_OVERHEAD) {
	    max_ppp_payload = ETH_JUMBO_LEN - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_PPPOE_MTU) {
	    PPPoETag maxPayload;
	    UINT16_t mru = htons(max_ppp_payload);
	    maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
	    maxPayload.length = htons(sizeof(mru));
	    memcpy(maxPayload.payload, &mru, sizeof(mru));
	    CHECK_ROOM(cursor, pado.payload, sizeof(mru) + TAG_HDR_SIZE);
	    memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
	    cursor += sizeof(mru) + TAG_HDR_SIZE;
	    plen += sizeof(mru) + TAG_HDR_SIZE;
	}
    }
    /* If no service-names specified on command-line, just send default
       zero-length name.  Otherwise, add all service-name tags */
    servname.type = htons(TAG_SERVICE_NAME);
    if (!NumServiceNames) {
	servname.length = 0;
	CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE);
	memcpy(cursor, &servname, TAG_HDR_SIZE);
	cursor += TAG_HDR_SIZE;
	plen += TAG_HDR_SIZE;
    } else {
	for (i=0; i<NumServiceNames; i++) {
	    int slen = strlen(ServiceNames[i]);
	    servname.length = htons(slen);
	    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE+slen);
	    memcpy(cursor, &servname, TAG_HDR_SIZE);
	    memcpy(cursor+TAG_HDR_SIZE, ServiceNames[i], slen);
	    cursor += TAG_HDR_SIZE+slen;
	    plen += TAG_HDR_SIZE+slen;
	}
    }

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE + COOKIE_LEN);
    memcpy(cursor, &cookie, TAG_HDR_SIZE + COOKIE_LEN);
    cursor += TAG_HDR_SIZE + COOKIE_LEN;
    plen += TAG_HDR_SIZE + COOKIE_LEN;

    if (relayId.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(hostUniq.length)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pado.length = htons(plen);
    sendPacket(sock, (unsigned char *)&pado, (int) (plen + HDR_SIZE));
    WorkSession.ConnectionState = ConnectionStateNakLCP;

}



void
startPPPD(ClientSession *cliSession)
{
    if (!cliSession) {
        return;
    }
    INFO("enter session stage!");
    WorkSession.session_pkt_cnt = 0;
    WorkSession.magic = rand();
 
}



/**********************************************************************
*%FUNCTION: processPADI
*%ARGUMENTS:
* ethif -- Interface
* packet -- PPPoE PADI packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADO packet back to client
***********************************************************************/
void
processPADI(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket pado;
    PPPoETag acname;
    PPPoETag servname;
    PPPoETag cookie;
    size_t acname_len;
    unsigned char *cursor = pado.payload;
    UINT16_t plen;

    int sock = ethif->discovery_sock;
    int i;
    int ok = 0;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	ERR("PADI packet from non-unicast source address");
	return;
    }

    acname.type = htons(TAG_AC_NAME);
    acname_len = strlen(ACName);
    acname.length = htons(acname_len);
    memcpy(acname.payload, ACName, acname_len);

    relayId.type = 0;
    hostUniq.type = 0;
    requestedService.type = 0;
    max_ppp_payload = 0;

    parsePacket(packet, parsePADITags, NULL);

    /* If PADI specified non-default service name, and we do not offer
       that service, DO NOT send PADO */
    if (requestedService.type) {
	int slen = ntohs(requestedService.length);
	if (slen) {
	    for (i=0; i<NumServiceNames; i++) {
		if (slen == strlen(ServiceNames[i]) &&
		    !memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		    ok = 1;
		    break;
		}
	    }
	} else {
	    ok = 1;		/* Default service requested */
	}
    } else {
	ok = 1;			/* No Service-Name tag in PADI */
    }

    if (!ok) {
	/* PADI asked for unsupported service */
	return;
    }

    /* Generate a cookie */
    cookie.type = htons(TAG_AC_COOKIE);
    cookie.length = htons(COOKIE_LEN);
    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookie.payload);

    /* Construct a PADO packet */
    memcpy(pado.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pado.ethHdr.h_source, myAddr, ETH_ALEN);
    pado.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    pado.ver = 1;
    pado.type = 1;
    pado.code = CODE_PADO;
    pado.session = 0;
    plen = TAG_HDR_SIZE + acname_len;

    CHECK_ROOM(cursor, pado.payload, acname_len+TAG_HDR_SIZE);
    memcpy(cursor, &acname, acname_len + TAG_HDR_SIZE);
    cursor += acname_len + TAG_HDR_SIZE;

    /* If we asked for an MTU, handle it */
    if (max_ppp_payload > ETH_PPPOE_MTU && ethif->mtu > 0) {
	/* Shrink payload to fit */
	if (max_ppp_payload > ethif->mtu - TOTAL_OVERHEAD) {
	    max_ppp_payload = ethif->mtu - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_JUMBO_LEN - TOTAL_OVERHEAD) {
	    max_ppp_payload = ETH_JUMBO_LEN - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_PPPOE_MTU) {
	    PPPoETag maxPayload;
	    UINT16_t mru = htons(max_ppp_payload);
	    maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
	    maxPayload.length = htons(sizeof(mru));
	    memcpy(maxPayload.payload, &mru, sizeof(mru));
	    CHECK_ROOM(cursor, pado.payload, sizeof(mru) + TAG_HDR_SIZE);
	    memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
	    cursor += sizeof(mru) + TAG_HDR_SIZE;
	    plen += sizeof(mru) + TAG_HDR_SIZE;
	}
    }
    /* If no service-names specified on command-line, just send default
       zero-length name.  Otherwise, add all service-name tags */
    servname.type = htons(TAG_SERVICE_NAME);
    if (!NumServiceNames) {
	servname.length = 0;
	CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE);
	memcpy(cursor, &servname, TAG_HDR_SIZE);
	cursor += TAG_HDR_SIZE;
	plen += TAG_HDR_SIZE;
    } else {
	for (i=0; i<NumServiceNames; i++) {
	    int slen = strlen(ServiceNames[i]);
	    servname.length = htons(slen);
	    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE+slen);
	    memcpy(cursor, &servname, TAG_HDR_SIZE);
	    memcpy(cursor+TAG_HDR_SIZE, ServiceNames[i], slen);
	    cursor += TAG_HDR_SIZE+slen;
	    plen += TAG_HDR_SIZE+slen;
	}
    }

    CHECK_ROOM(cursor, pado.payload, TAG_HDR_SIZE + COOKIE_LEN);
    memcpy(cursor, &cookie, TAG_HDR_SIZE + COOKIE_LEN);
    cursor += TAG_HDR_SIZE + COOKIE_LEN;
    plen += TAG_HDR_SIZE + COOKIE_LEN;

    if (relayId.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	CHECK_ROOM(cursor, pado.payload, ntohs(hostUniq.length)+TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pado.length = htons(plen);
    sendPacket(sock, (unsigned char *)&pado, (int) (plen + HDR_SIZE));
    WorkSession.ConnectionState = ConnectionStateSentPADO;

    DBG("got "MAC_STR_FMT" PADI, response PADR!", MAC_STR(packet->ethHdr.h_source));
}

/**********************************************************************
*%FUNCTION: processPADT
*%ARGUMENTS:
* ethif -- interface
* packet -- PPPoE PADT packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Kills session whose session-ID is in PADT packet.
***********************************************************************/
void
processPADT(Interface *ethif, PPPoEPacket *packet, int len)
{
    //size_t i;

    unsigned char *myAddr = ethif->mac;

    /* Ignore PADT's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    if ((ntohs(WorkSession.sessID) - 1) == ntohs(packet->session)) {
        /* ignore last terminated session */
        return;
    } else if (ntohs(WorkSession.sessID) != ntohs(packet->session)) {
        ERR("Session index %u doesn't match session number %u",
            (unsigned int) ntohs(WorkSession.sessID), (unsigned int) ntohs(packet->session));
        return;
    }

    /* If source MAC does not match, do not kill session */
    if (memcmp(packet->ethHdr.h_source, WorkSession.peerMac, ETH_ALEN)) {
	WARN("PADT for session %u received from "
	       "%02X:%02X:%02X:%02X:%02X:%02X; should be from "
	       "%02X:%02X:%02X:%02X:%02X:%02X",
	       (unsigned int) ntohs(packet->session),
	       packet->ethHdr.h_source[0],
	       packet->ethHdr.h_source[1],
	       packet->ethHdr.h_source[2],
	       packet->ethHdr.h_source[3],
	       packet->ethHdr.h_source[4],
	       packet->ethHdr.h_source[5],
	       WorkSession.peerMac[0],
	       WorkSession.peerMac[1],
	       WorkSession.peerMac[2],
	       WorkSession.peerMac[3],
	       WorkSession.peerMac[4],
	       WorkSession.peerMac[5]);
	return;
    }
    WorkSession.flags |= FLAG_RECVD_PADT;
    parsePacket(packet, parseLogErrs, NULL);
    WorkSession.ConnectionState = ConnectionStateTerminated;

    DBG("got "MAC_STR_FMT" PADT, response PADT!", MAC_STR(packet->ethHdr.h_source));

    //Sessions[i].funcs->stop(&Sessions[i], "Received PADT");
    PppoeStopSession(&WorkSession, "Received PADT");
}

/**********************************************************************
*%FUNCTION: processPADR
*%ARGUMENTS:
* ethif -- Ethernet interface
* packet -- PPPoE PADR packet
* len -- length of received packet
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet back to client and starts a PPP session if PADR
* packet is OK.
***********************************************************************/
void
processPADR(Interface *ethif, PPPoEPacket *packet, int len)
{
    unsigned char cookieBuffer[COOKIE_LEN];
    ClientSession *cliSession;
    //pid_t child;
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    int i;
    int sock = ethif->discovery_sock;
    unsigned char *myAddr = ethif->mac;
    int slen = 0;
    char const *serviceName = NULL;

    /* Initialize some globals */
    relayId.type = 0;
    hostUniq.type = 0;
    receivedCookie.type = 0;
    requestedService.type = 0;

    /* Ignore PADR's not directed at us */
    if (memcmp(packet->ethHdr.h_dest, myAddr, ETH_ALEN)) return;

    /* Ignore PADR's from non-unicast addresses */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	ERR("PADR packet from non-unicast source address");
	return;
    }

    max_ppp_payload = 0;
    parsePacket(packet, parsePADRTags, NULL);

    /* Check that everything's cool */
    if (!receivedCookie.type) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Is cookie kosher? */
    if (receivedCookie.length != htons(COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    genCookie(packet->ethHdr.h_source, myAddr, CookieSeed, cookieBuffer);
    if (memcmp(receivedCookie.payload, cookieBuffer, COOKIE_LEN)) {
	/* Drop it -- do not send error PADS */
	return;
    }

    /* Check service name */
    if (!requestedService.type) {
	ERR("Received PADR packet with no SERVICE_NAME tag");
	sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
		      TAG_SERVICE_NAME_ERROR, MY_SERVICE_NAME": Server: No service name tag");
	return;
    }

    slen = ntohs(requestedService.length);
    if (slen) {
	/* Check supported services */
	for(i=0; i<NumServiceNames; i++) {
	    if (slen == strlen(ServiceNames[i]) &&
		!memcmp(ServiceNames[i], &requestedService.payload, slen)) {
		serviceName = ServiceNames[i];
		break;
	    }
	}

	if (!serviceName) {
	    ERR("Received PADR packet asking for unsupported service %.*s", (int) ntohs(requestedService.length), requestedService.payload);
	    sendErrorPADS(sock, myAddr, packet->ethHdr.h_source,
			  TAG_SERVICE_NAME_ERROR, MY_SERVICE_NAME": Server: Invalid service name tag");
	    return;
	}
    } else {
	serviceName = "";
    }

    /* Looks cool... find a slot for the session */
    cliSession = &WorkSession;

    /* Set up client session peer Ethernet address */
    memcpy(cliSession->peerMac, packet->ethHdr.h_source, ETH_ALEN);
    cliSession->ethif = ethif;
    cliSession->flags = 0;
    //cliSession->funcs = &DefaultSessionFunctionTable;
    cliSession->startTime = time(NULL);
    cliSession->serviceName = serviceName;
#if 0
    /* In the child process */

    /* Reset signal handlers to default */
    signal(SIGTERM, SIG_DFL);
    signal(SIGINT, SIG_DFL);
#endif


    /* Send PADS and Start pppd */
    memcpy(pads.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, myAddr, ETH_ALEN);
    pads.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;

    pads.session = cliSession->sessID;
    plen = 0;

    /* Copy requested service name tag back in.  If requested-service name
       length is zero, and we have non-zero services, use first service-name
       as default */
    if (!slen && NumServiceNames) {
	slen = strlen(ServiceNames[0]);
	memcpy(&requestedService.payload, ServiceNames[0], slen);
	requestedService.length = htons(slen);
    }
    memcpy(cursor, &requestedService, TAG_HDR_SIZE+slen);
    cursor += TAG_HDR_SIZE+slen;
    plen += TAG_HDR_SIZE+slen;

    /* If we asked for an MTU, handle it */
    if (max_ppp_payload > ETH_PPPOE_MTU && ethif->mtu > 0) {
	/* Shrink payload to fit */
	if (max_ppp_payload > ethif->mtu - TOTAL_OVERHEAD) {
	    max_ppp_payload = ethif->mtu - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_JUMBO_LEN - TOTAL_OVERHEAD) {
	    max_ppp_payload = ETH_JUMBO_LEN - TOTAL_OVERHEAD;
	}
	if (max_ppp_payload > ETH_PPPOE_MTU) {
	    PPPoETag maxPayload;
	    UINT16_t mru = htons(max_ppp_payload);
	    maxPayload.type = htons(TAG_PPP_MAX_PAYLOAD);
	    maxPayload.length = htons(sizeof(mru));
	    memcpy(maxPayload.payload, &mru, sizeof(mru));
	    CHECK_ROOM(cursor, pads.payload, sizeof(mru) + TAG_HDR_SIZE);
	    memcpy(cursor, &maxPayload, sizeof(mru) + TAG_HDR_SIZE);
	    cursor += sizeof(mru) + TAG_HDR_SIZE;
	    plen += sizeof(mru) + TAG_HDR_SIZE;
	    cliSession->requested_mtu = max_ppp_payload;
	}
    }

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(sock, (unsigned char *)&pads, (int) (plen + HDR_SIZE));
    cliSession->ConnectionState = ConnectionStateSentPADS;

    DBG("got "MAC_STR_FMT" PADR, response PADS!", MAC_STR(packet->ethHdr.h_source));

    startPPPD(cliSession);
}

/**********************************************************************
*%FUNCTION: pppoe_learner_termHandler
*%ARGUMENTS:
* sig -- signal number
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Called by SIGTERM or SIGINT.  Causes all sessions to be killed!
***********************************************************************/
void
pppoeLearnerTermHandler(int sig)
{
    INFO("Terminating on signal %d -- killing all PPPoE sessions", sig);
    killAllSessions();

}


/**********************************************************************
*%FUNCTION: sendErrorPADS
*%ARGUMENTS:
* sock -- socket to write to
* source -- source Ethernet address
* dest -- destination Ethernet address
* errorTag -- error tag
* errorMsg -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADS packet with an error message
***********************************************************************/
void
sendErrorPADS(int sock,
	      unsigned char *source,
	      unsigned char *dest,
	      int errorTag,
	      char *errorMsg)
{
    PPPoEPacket pads;
    unsigned char *cursor = pads.payload;
    UINT16_t plen;
    PPPoETag err;
    int elen = strlen(errorMsg);

    memcpy(pads.ethHdr.h_dest, dest, ETH_ALEN);
    memcpy(pads.ethHdr.h_source, source, ETH_ALEN);
    pads.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    pads.ver = 1;
    pads.type = 1;
    pads.code = CODE_PADS;

    pads.session = 0;
    plen = 0;

    err.type = htons(errorTag);
    err.length = htons(elen);

    memcpy(err.payload, errorMsg, elen);
    memcpy(cursor, &err, TAG_HDR_SIZE+elen);
    cursor += TAG_HDR_SIZE + elen;
    plen += TAG_HDR_SIZE + elen;

    if (relayId.type) {
	memcpy(cursor, &relayId, ntohs(relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(relayId.length) + TAG_HDR_SIZE;
    }
    if (hostUniq.type) {
	memcpy(cursor, &hostUniq, ntohs(hostUniq.length) + TAG_HDR_SIZE);
	cursor += ntohs(hostUniq.length) + TAG_HDR_SIZE;
	plen += ntohs(hostUniq.length) + TAG_HDR_SIZE;
    }
    pads.length = htons(plen);
    sendPacket(sock, (unsigned char *)&pads, (int) (plen + HDR_SIZE));

    DBG("response error PADS to "MAC_STR_FMT"!", MAC_STR(dest));
}


void
serverProcessPacket(Interface *i)
{
    int len;
    PPPoEPacket packet;
    int sock;

    if (!i)
    {
        ERR("interface empty!");
        return;
    }
    sock = i->discovery_sock;

    //DBG("GOT pkt! if=%s", i->name);
    if (receivePacket(sock, (unsigned char *)&packet, sizeof(PPPoEPacket), &len) < 0) {
        ERR("failed receivePacket!");
        return;
    }

    if (len < HDR_SIZE) {
	/* Impossible - ignore */
        ERR("len=%d Impossible !", len);
	return;
    }

    /* Sanity check on packet */
    if (packet.ver != 1 || packet.type != 1) {
	/* Syslog an error */
        ERR("ver=%d, type=%d is error!", packet.ver, packet.type);
	return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	ERR("Bogus PPPoE length field (%u)",
	       (unsigned int) ntohs(packet.length));
	return;
    }

    switch(packet.code) {
        case CODE_PADI:
            processPADI(i, &packet, len);
            break;
        case CODE_PADR:
            processPADR(i, &packet, len);
            break;
        case CODE_PADT:
            processPADT(i, &packet, len);
            break;
        case CODE_SESS:
            WARN("Got session pkt from "MAC_STR_FMT" in Discovery socket process function!",
                MAC_STR(packet.ethHdr.h_source));
            break;
        case CODE_PADO:
        case CODE_PADS:
            /* Ignore PADO and PADS totally */
            break;
        default:
            /* Syslog an error */
            break;
    }
}



void
processConfigureRequest(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket cfgPkt;
    PPPSubProtocolPacket *subProtoPkt = (PPPSubProtocolPacket *)packet->payload;

    unsigned char *cursor = cfgPkt.payload;
    unsigned short *sub_len_ptr = NULL;
    UINT16_t plen = 0;
    UINT16_t sub_len = 0;
    unsigned int resp_option_set_map = 0; // for NAK and Reject

    int cfg_ack = CONFACK;
    int sock = ethif->session_sock;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	ERR("PADI packet from non-unicast source address");
	return;
    }

    ++WorkSession.session_pkt_cnt;

    if (parseSessionPacket(subProtoPkt, parseLCPOption, NULL)) {
        ERR("failed parseSessionPacket!");
        return;
    }

    do {
        // chk map
        int chkbits = (OPT_BIT(CI_MRU) | OPT_BIT(CI_MAGICNUMBER));

        resp_option_set_map = negoOpt.LCP_option_set_map;
        //DBG("option map=%#x, need map=%#x", negoOpt.LCP_option_set_map, chkbits);

        if (negoOpt.LCP_option_set_map & ~chkbits) {
#ifdef ACCEPT_ALL_OPTION
            WARN("option map=%#x (%#x), accept all", negoOpt.LCP_option_set_map, chkbits);

            if ((negoOpt.LCP_option_set_map & OPT_BIT(CI_AUTHTYPE)) && 
                (negoOpt.LCP_option_peer_authtype != PPP_PAP)) {
                WARN("option AuthType=%d missmatch!", negoOpt.LCP_option_peer_authtype);
                cfg_ack = CONFREJ;
                break;
            }
            cfg_ack = CONFACK;
#else
            WARN("option map=%#x not right! need map=%#x, reject", negoOpt.LCP_option_set_map, chkbits);
            cfg_ack = CONFREJ;
            resp_option_set_map &= ~chkbits;
            resp_option_set_map &= ~(OPT_BIT(CI_AUTHTYPE));
            if (!resp_option_set_map) {
                WARN("CfgReq Ignore option auth type, out.");
                return;
            }
#endif

            break;
        }

        if (negoOpt.LCP_option_set_map & OPT_BIT(CI_MRU))
        {
#if 0
            if (negoOpt.LCP_option_peer_max_receive_unit != DEFMRU) {
                INFO("option MRU=%d missmatch!", negoOpt.LCP_option_peer_max_receive_unit);
                cfg_ack = CONFNAK;
            } else {
                resp_option_set_map &= ~(OPT_BIT(CI_MRU));
            }
#endif
        }
        else
        {
            INFO("option MRU not found!");
#if 0
            cfg_ack = CONFNAK;
            resp_option_set_map = OPT_BIT(CI_MRU);
            break;
#else
            return;
#endif
        }

        if (negoOpt.LCP_option_set_map & OPT_BIT(CI_MAGICNUMBER))
        {
#if 0
            if (negoOpt.LCP_option_peer_magic_number != WorkSession.magic) {
                INFO("option MagicNum=%d missmatch!", negoOpt.LCP_option_peer_magic_number);
                cfg_ack = CONFNAK;
            } else {
                resp_option_set_map &= ~(OPT_BIT(CI_MAGICNUMBER));
            }
#endif
        }
        else
        {
            INFO("option MagicNum not found!");
#if 0
            cfg_ack = CONFNAK;
            resp_option_set_map = OPT_BIT(CI_MAGICNUMBER);
            break;
#else
            return;
#endif
        }

    } while (0);

    // first cfg req, send PAP option
    if (WorkSession.session_pkt_cnt == 1)
    {
        /* Construct a session packet */
        memcpy(cfgPkt.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
        memcpy(cfgPkt.ethHdr.h_source, myAddr, ETH_ALEN);
        cfgPkt.ethHdr.h_proto = htons(ETH_PPPOE_SESSION);
        cfgPkt.ver = 1;
        cfgPkt.type = 1;
        cfgPkt.code = CODE_SESS;
        cfgPkt.session = WorkSession.sessID;
        plen = 0;

        // ppp protocol
        *(unsigned short *)cursor = htons(PPP_LCP);
        cursor += 2;
        plen += 2;

        sub_len = 0;

        // code
        *((unsigned char *)cursor++) = CONFREQ;
        ++sub_len;

        // identifier
        *((unsigned char *)cursor++) = subProtoPkt->identifier;
        ++sub_len;

        // sub proto len
        sub_len_ptr = (unsigned short *)cursor;
        cursor += 2;
        sub_len += 2;

        // option: MRU
        *((unsigned char *)cursor++) = CI_MRU;        // type
        *((unsigned char *)cursor++) = 4;                  // len
        *((unsigned short *)cursor) = htons(DEFMRU);           // val
        cursor += 2;
        sub_len += 4;   // 1 + 1 + 2

        // option: Auth Type
        *((unsigned char *)cursor++) = CI_AUTHTYPE;        // type
        *((unsigned char *)cursor++) = 4;                  // len
        *((unsigned short *)cursor) = htons(PPP_PAP);           // val
        cursor += 2;
        sub_len += 4;   // 1 + 1 + 2

        // option: Magic Num
        *((unsigned char *)cursor++) = CI_MAGICNUMBER;      // type
        *((unsigned char *)cursor++) = 6;               // len
        *((unsigned int *)cursor) = htonl(WorkSession.magic);           // val
        cursor += 4;
        sub_len += 6;   // 1 + 1 + 4

        *sub_len_ptr = htons(sub_len);
        plen += sub_len;

        cfgPkt.length = htons(plen);
        sendPacket(sock, (unsigned char *)&cfgPkt, (int) (plen + HDR_SIZE));

        WorkSession.ConnectionState = ConnectionStateAckLCP;

        DBG("got "MAC_STR_FMT" first ConfReq, response my ConfReq!", MAC_STR(packet->ethHdr.h_source));
    }
    else
    {
        /* Construct a session packet */
        memcpy(cfgPkt.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
        memcpy(cfgPkt.ethHdr.h_source, myAddr, ETH_ALEN);
        cfgPkt.ethHdr.h_proto = htons(ETH_PPPOE_SESSION);
        cfgPkt.ver = 1;
        cfgPkt.type = 1;
        cfgPkt.code = CODE_SESS;
        cfgPkt.session = WorkSession.sessID;
        plen = 0;

        // ppp protocol
        *(unsigned short *)cursor = htons(PPP_LCP);
        cursor += 2;
        plen += 2;

        sub_len = 0;

        // code
        *((unsigned char *)cursor++) = cfg_ack;
        ++sub_len;

        // identifier
        *((unsigned char *)cursor++) = subProtoPkt->identifier;
        ++sub_len;

        // sub proto len
        sub_len_ptr = (unsigned short *)cursor;
        cursor += 2;
        sub_len += 2;

        if (cfg_ack == CONFACK)
        {
#ifdef ACCEPT_ALL_OPTION
            memcpy(cursor, peer_option_payload, peer_option_payload_len);
            //hexdump("peer payload", peer_option_payload, peer_option_payload_len);
            cursor += peer_option_payload_len;
            sub_len += peer_option_payload_len;
#else
            // option: MRU
            *((unsigned char *)cursor++) = CI_MRU;        // type
            *((unsigned char *)cursor++) = 4;                  // len
            *((unsigned short *)cursor) = htons(negoOpt.LCP_option_peer_max_receive_unit);           // val
            cursor += 2;
            sub_len += 4;   // 1 + 1 + 2

            // option: Auth Type
            *((unsigned char *)cursor++) = CI_AUTHTYPE;        // type
            *((unsigned char *)cursor++) = 4;                  // len
            *((unsigned short *)cursor) = htons(PPP_PAP);           // val
            cursor += 2;
            sub_len += 4;   // 1 + 1 + 2

            // option: Magic Num
            *((unsigned char *)cursor++) = CI_MAGICNUMBER;      // type
            *((unsigned char *)cursor++) = 6;               // len
            *((unsigned int *)cursor) = htonl(negoOpt.LCP_option_peer_magic_number);           // val
            cursor += 4;
            sub_len += 6;   // 1 + 1 + 4
#endif
        }
        else if (cfg_ack == CONFNAK)
        {
            if (resp_option_set_map & OPT_BIT(CI_MRU)) {
                *((unsigned char *)cursor++) = CI_MRU;        // type
                *((unsigned char *)cursor++) = 4;                  // len
                *((unsigned short *)cursor) = htons(negoOpt.LCP_option_peer_max_receive_unit); // val
                cursor += 2;
                sub_len += 4;   // 1 + 1 + 2
            }    
            if (resp_option_set_map & OPT_BIT(CI_MAGICNUMBER)) {
                *((unsigned char *)cursor++) = CI_MAGICNUMBER;      // type
                *((unsigned char *)cursor++) = 6;               // len
                *((unsigned int *)cursor) = htonl(negoOpt.LCP_option_peer_magic_number); // val
                cursor += 4;
                sub_len += 6;   // 1 + 1 + 4
            }
        }
        else if (cfg_ack == CONFREJ)
        {
            memcpy(cursor, nak_option_payload, nak_option_payload_len);
            //hexdump("nak payload", nak_option_payload, nak_option_payload_len);
            cursor += nak_option_payload_len;
            sub_len += nak_option_payload_len;
        }
        else
        {
            ERR("invalid cfg_ack=%s", getSessCodeStr(cfg_ack));
            return;
        }

        *sub_len_ptr = htons(sub_len);
        plen += sub_len;

        cfgPkt.length = htons(plen);
        sendPacket(sock, (unsigned char *)&cfgPkt, (int) (plen + HDR_SIZE));

        WorkSession.ConnectionState = ConnectionStateAckLCP;

        DBG("got "MAC_STR_FMT" ConfReq, response cfg_ack=%s!",
            MAC_STR(packet->ethHdr.h_source), getSessCodeStr(cfg_ack));
    }

}

void
processConfigureAck(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPSubProtocolPacket *subProtoPkt = (PPPSubProtocolPacket *)packet->payload;

    int cfg_ack = 0;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
	ERR("PADI packet from non-unicast source address");
	return;
    }

    ++WorkSession.session_pkt_cnt;

    if (parseSessionPacket(subProtoPkt, parseLCPOption, NULL)) {
        ERR("failed parseSessionPacket!");
        return;
    }

    do {
        // chk map
        int chkbits = (OPT_BIT(CI_MRU) | OPT_BIT(CI_MAGICNUMBER));

        if (!WorkSession.lcp_authtype_ack) {
            chkbits |= OPT_BIT(CI_AUTHTYPE);
        }

        //DBG("option map=%#x, need map=%#x", negoOpt.LCP_option_set_map, chkbits);

        if (negoOpt.LCP_option_set_map & ~chkbits) {
            WARN("option map=%#x not right! need map=%#x", negoOpt.LCP_option_set_map, chkbits);
            cfg_ack = 0;
            break;
        }

        if (negoOpt.LCP_option_set_map & OPT_BIT(CI_MRU)) {
            if (negoOpt.LCP_option_peer_max_receive_unit != DEFMRU) {
                //WARN("option MRU=%d missmatch!", negoOpt.LCP_option_peer_max_receive_unit);
                cfg_ack = 0;
                break;
            }
        } else {
            WARN("option MRU not found!");
            cfg_ack = 0;
            break;
        }

        if (!WorkSession.lcp_authtype_ack)
        {
            if (negoOpt.LCP_option_set_map & OPT_BIT(CI_AUTHTYPE)) {
                if (negoOpt.LCP_option_peer_authtype != PPP_PAP) {
                    WARN("option AuthType=%d missmatch!", negoOpt.LCP_option_peer_authtype);
                    cfg_ack = 0;
                    break;
                }
            } else {
                WARN("option AuthType not found!");
                cfg_ack = 0;
                break;
            }
        }

        if (negoOpt.LCP_option_set_map & OPT_BIT(CI_MAGICNUMBER)) {
            if (negoOpt.LCP_option_peer_magic_number != WorkSession.magic) {
                WARN("option MagicNum=%d missmatch!", negoOpt.LCP_option_peer_magic_number);
                cfg_ack = 0;
                break;
            }
        } else {
            WARN("option MagicNum not found!");
            cfg_ack = 0;
            break;
        }

        cfg_ack = 1;

        if (!WorkSession.lcp_authtype_ack && negoOpt.LCP_option_set_map & OPT_BIT(CI_AUTHTYPE)) {
            WorkSession.lcp_authtype_ack = 1;
            INFO("LCP auth type is agreed!");
        }
    } while (0);

    // confirm ack

    if (cfg_ack == 1)
    {
        //DBG("cfg_ack 1");
        WorkSession.ConnectionState = ConnectionStateAckLCP;
    }
    else if (cfg_ack == 0)
    {
        //DBG("cfg_ack 0");
        WorkSession.ConnectionState = ConnectionStateNakLCP;
    }

}


void
processAuthRequest(Interface *ethif, PPPoEPacket *packet, int len)
{
    PPPoEPacket cfgPkt;
    PPPSubProtocolPacket *subProtoPkt = (PPPSubProtocolPacket *)packet->payload;

    unsigned char *cursor = cfgPkt.payload;
    unsigned short *sub_len_ptr = NULL;
    UINT16_t plen = 0;
    UINT16_t sub_len = 0;

    int sock = ethif->session_sock;
    unsigned char *myAddr = ethif->mac;

    /* Ignore PADI's which don't come from a unicast address */
    if (NOT_UNICAST(packet->ethHdr.h_source)) {
    ERR("PADI packet from non-unicast source address");
    return;
    }

    ++WorkSession.session_pkt_cnt;

    if (parsePAPPacket(subProtoPkt, &pppoeLearnInfo.pppoeProbe)) {
        ERR("failed parsePAPPacket!");
        return;
    }

    /* Construct a session packet */
    memcpy(cfgPkt.ethHdr.h_dest, packet->ethHdr.h_source, ETH_ALEN);
    memcpy(cfgPkt.ethHdr.h_source, myAddr, ETH_ALEN);
    cfgPkt.ethHdr.h_proto = htons(ETH_PPPOE_SESSION);
    cfgPkt.ver = 1;
    cfgPkt.type = 1;
    cfgPkt.code = CODE_SESS;
    cfgPkt.session = WorkSession.sessID;
    plen = 0;

    // ppp protocol
    *(unsigned short *)cursor = htons(PPP_PAP);
    cursor += 2;
    plen += 2;

    sub_len = 0;

    // code
    *((unsigned char *)cursor++) = PAP_ANAK;
    ++sub_len;

    // identifier
    *((unsigned char *)cursor++) = subProtoPkt->identifier;
    ++sub_len;

    // sub proto len
    sub_len_ptr = (unsigned short *)cursor;
    cursor += 2;
    sub_len += 2;

    // msg len
    *((unsigned char *)cursor++) = strlen(PAP_AUTH_FAIL_STRING);
    ++sub_len;
    memcpy(cursor, PAP_AUTH_FAIL_STRING, strlen(PAP_AUTH_FAIL_STRING));
    sub_len += strlen(PAP_AUTH_FAIL_STRING);

    *sub_len_ptr = htons(sub_len);
    plen += sub_len;

    cfgPkt.length = htons(plen);
    sendPacket(sock, (unsigned char *)&cfgPkt, (int) (plen + HDR_SIZE));

    WorkSession.ConnectionState = ConnectionStateTerminated;

    DBG("got "MAC_STR_FMT" AuthReq, response PAP_ANAK!",
        MAC_STR(packet->ethHdr.h_source));

    PppoeStopSession(&WorkSession, PAP_AUTH_FAIL_STRING);

    learnerStopLearn(NetConTypePPPoE);

}



void
serverProcessSessionPacket(Interface *i)
{
    int len;
    PPPoEPacket packet;
    int sock;
    PPPSubProtocolPacket *pSubPkt = NULL;
    unsigned char nullMac[ETH_ALEN];


    if (!i)
    {
        ERR("interface empty!");
        return;
    }
    sock = i->session_sock;

    //DBG("GOT pkt! if=%s", i->name);
    if (receivePacket(sock, (unsigned char *)&packet, sizeof(PPPoEPacket), &len) < 0) {
        ERR("failed receivePacket!");
        return;
    }

    if (len < HDR_SIZE) {
	/* Impossible - ignore */
        ERR("len=%d Impossible !", len);
	return;
    }

    /* Sanity check on packet */
    if (packet.ver != 1 || packet.type != 1) {
	/* Syslog an error */
        ERR("ver=%d, type=%d is error!", packet.ver, packet.type);
	return;
    }

    /* Check length */
    if (ntohs(packet.length) + HDR_SIZE > len) {
	ERR("Bogus PPPoE length field (%u), len (%u)", (unsigned int) ntohs(packet.length), len);
	return;
    }

    if (WorkSession.ConnectionState < ConnectionStateSentPADS || 
        WorkSession.ConnectionState >= ConnectionStateTerminated)
    {
        ERR("ConnectionState=%d is not right!", WorkSession.ConnectionState);
        return;
    }


    memset(nullMac, 0, ETH_ALEN);
    if (memcmp(WorkSession.peerMac, nullMac, ETH_ALEN) != 0) {
        if (memcmp(packet.ethHdr.h_source, WorkSession.peerMac, ETH_ALEN) != 0) {
            ERR("Not working service peer mac="MAC_STR_FMT"! Ignore it.",
                MAC_STR(packet.ethHdr.h_source));
            return;
        }
    }

    if (packet.ethHdr.h_proto != htons(ETH_PPPOE_SESSION)) {
        ERR("Rx packet h_proto=%#x error! peer="MAC_STR_FMT"! Ignore it.",
            ntohs(packet.ethHdr.h_proto), MAC_STR(packet.ethHdr.h_source));
        return;
    }

    if (packet.code != CODE_SESS) {
        ERR("Rx packet Not CODE_SESS code(%d)! peer="MAC_STR_FMT"! Ignore it.",
             packet.code, MAC_STR(packet.ethHdr.h_source));
        return;
    }

    pSubPkt = (PPPSubProtocolPacket *)packet.payload;

    //DBG("got Session pkt, sub: proto=%#x, code=%d, idt=%#x, len=%d",
    //    ntohs(pSubPkt->protocol), pSubPkt->code, pSubPkt->identifier, ntohs(pSubPkt->length));

    if (ntohs(pSubPkt->protocol) == PPP_LCP) {
        switch (pSubPkt->code) {
            case CONFREQ:
                processConfigureRequest(i, &packet, len);
                break;
            case CONFACK:
                processConfigureAck(i, &packet, len);
                break;
            case TERMREQ:
                //processTerminateRequest(i, &packet, len);
                break;
            case TERMACK:
                //processTerminateAck(i, &packet, len);
                break;
        }
    } else if (ntohs(pSubPkt->protocol) == PPP_PAP) {
        switch (pSubPkt->code) {
            case PAP_AREQ:
                processAuthRequest(i, &packet, len);
                break;
            default:
                ERR("unsupport PAP code=%d", (pSubPkt->code));
                break;
        }
    } else {
        ERR("Rx packet sub protocol=%#x is not supported! peer="MAC_STR_FMT"! Ignore it.",
             ntohs(pSubPkt->protocol), MAC_STR(packet.ethHdr.h_source));
        return;
    }

}
/**********************************************************************
* %FUNCTION: InterfaceHandler
* %ARGUMENTS:
*  es -- event selector (ignored)
*  fd -- file descriptor which is readable
*  flags -- ignored
*  data -- Pointer to the Interface structure
* %RETURNS:
*  Nothing
* %DESCRIPTION:
*  Handles a packet ready at an interface
***********************************************************************/
void
InterfaceHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    serverProcessPacket((Interface *)data);
}

void
InterfaceSessionHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    serverProcessSessionPacket((Interface *)data);
}

extern EventSelector *event_selector;
int pppoeLearnerInit(unsigned char *ifname)
{
    int i;
    FILE *fp;

    if (ifname && strlen(ifname) > 0)
    {
        strcpy(pppoeIface.name, (const char *)ifname);
    }
    ERR("listen on interface %s", pppoeIface.name);

    /* Initialize our random cookie.  Try /dev/urandom; if that fails,
       use PID and rand() */
    fp = fopen("/dev/urandom", "r");
    if (fp) {
	unsigned int x;
	fread(&x, 1, sizeof(x), fp);
	srand(x);
	fread(&CookieSeed, 1, SEED_LEN, fp);
	fclose(fp);
    } else {
	srand((unsigned int) getpid() * (unsigned int) time(NULL));
	CookieSeed[0] = getpid() & 0xFF;
	CookieSeed[1] = (getpid() >> 8) & 0xFF;
	for (i=2; i<SEED_LEN; i++) {
	    CookieSeed[i] = (rand() >> (i % 9)) & 0xFF;
	}
    }


    memset(&pppoeLearnInfo, 0, sizeof(pppoeLearnInfo));

    /* Init interface and interface socket */
    pppoeIface.mtu = 0;
    pppoeIface.discovery_sock = openInterface(pppoeIface.name, ETH_PPPOE_DISCOVERY);
    if (pppoeIface.discovery_sock <= 0) {
        ERR("Failed open discovery_sock!");
        return -1;
    }
    pppoeIface.session_sock = openInterface(pppoeIface.name, ETH_PPPOE_SESSION);
    if (pppoeIface.session_sock <= 0) {
        ERR("Failed open session_sock!");
        return -1;
    }

    if (getIfaceNetInfo(pppoeIface.name, pppoeIface.discovery_sock,
        pppoeIface.mac, &pppoeIface.mtu) < 0) {
        ERR("Failed get %s net info!", pppoeIface.name);
        return -1;
    }


    /* Init event handler */
    /* Create event handler for each interface */
    //for (i = 0; i<NumInterfaces; i++) {
        pppoeIface.eh = Event_AddHandler(event_selector,
                            pppoeIface.discovery_sock,
                            EVENT_FLAG_READABLE,
                            InterfaceHandler,
                            &pppoeIface);

        if (!pppoeIface.eh) {
            rp_fatal("Event_AddHandler for discovery failed");
        }

        pppoeIface.session_eh = Event_AddHandler(event_selector,
                            pppoeIface.session_sock,
                            EVENT_FLAG_READABLE,
                            InterfaceSessionHandler,
                            &pppoeIface);

        if (!pppoeIface.session_eh) {
            rp_fatal("Event_AddHandler for session failed");
        }
    //}


    return 0;
}

int pppoeLearnerDeinit(void)
{
    if (pppoeIface.eh) {
        int ret = Event_DelHandler(event_selector, pppoeIface.eh);
        if (ret != 0) {
            ERR("Event_DelHandler eh error %d", ret);
        }
        pppoeIface.eh = NULL;
    }
    if (pppoeIface.session_eh) {
        int ret = Event_DelHandler(event_selector, pppoeIface.session_eh);
        if (ret != 0) {
            ERR("Event_DelHandler session_eh error %d", ret);
        }
        pppoeIface.session_eh = NULL;
    }


    if (pppoeIface.discovery_sock) {
        close(pppoeIface.discovery_sock);
        pppoeIface.discovery_sock = 0;
    }
    if (pppoeIface.session_sock) {
        close(pppoeIface.session_sock);
        pppoeIface.session_sock = 0;
    }

    return 0;
}

