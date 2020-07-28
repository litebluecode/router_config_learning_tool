/***********************************************************************
*
* common.c
*
* Implementation of user-space PPPoE redirector for Linux.
*
* Common functions used by PPPoE client and server
*
* Copyright (C) 2000-2012 by Roaring Penguin Software Inc.
*
* This program may be distributed according to the terms of the GNU
* General Public License, version 2 or (at your option) any later version.
*
* LIC: GPL
*
***********************************************************************/

/* For vsnprintf prototype */
#define _ISOC99_SOURCE 1
#define _GNU_SOURCE 1

#include "config.h"
#include "pppoe_common.h"

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/types.h>
#include <pwd.h>

#include "packet.h"

#if 0
/* Are we running SUID or SGID? */
int IsSetID = 0;

static uid_t saved_uid = (uid_t) -2;
static uid_t saved_gid = (uid_t) -2;
#endif


/**********************************************************************
*%FUNCTION: parsePacket
*%ARGUMENTS:
* packet -- the PPPoE discovery packet to parse
* func -- function called for each tag in the packet
* extra -- an opaque data pointer supplied to parsing function
*%RETURNS:
* 0 if everything went well; -1 if there was an error
*%DESCRIPTION:
* Parses a PPPoE discovery packet, calling "func" for each tag in the packet.
* "func" is passed the additional argument "extra".
***********************************************************************/
int
parsePacket(PPPoEPacket *packet, ParseFunc *func, void *extra)
{
    UINT16_t len = ntohs(packet->length);
    unsigned char *curTag;
    UINT16_t tagType, tagLen;

    if (packet->ver != 1) {
	ERR("Invalid PPPoE version (%d)", (int) packet->ver);
	return -1;
    }
    if (packet->type != 1) {
	ERR("Invalid PPPoE type (%d)", (int) packet->type);
	return -1;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_JUMBO_LEN - PPPOE_OVERHEAD) { /* 6-byte overhead for PPPoE header */
	ERR("Invalid PPPoE packet length (%u)", len);
	return -1;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while(curTag - packet->payload < len) {
	/* Alignment is not guaranteed, so do this by hand... */
	tagType = (((UINT16_t) curTag[0]) << 8) +
	    (UINT16_t) curTag[1];
	tagLen = (((UINT16_t) curTag[2]) << 8) +
	    (UINT16_t) curTag[3];
	if (tagType == TAG_END_OF_LIST) {
	    return 0;
	}
	if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
	    ERR("Invalid PPPoE tag length (%u)", tagLen);
	    return -1;
	}
	func(tagType, tagLen, curTag+TAG_HDR_SIZE, extra);
	curTag = curTag + TAG_HDR_SIZE + tagLen;
    }
    return 0;
}

#if 0
/**********************************************************************
*%FUNCTION: findTag
*%ARGUMENTS:
* packet -- the PPPoE discovery packet to parse
* type -- the type of the tag to look for
* tag -- will be filled in with tag contents
*%RETURNS:
* A pointer to the tag if one of the specified type is found; NULL
* otherwise.
*%DESCRIPTION:
* Looks for a specific tag type.
***********************************************************************/
unsigned char *
findTag(PPPoEPacket *packet, UINT16_t type, PPPoETag *tag)
{
    UINT16_t len = ntohs(packet->length);
    unsigned char *curTag;
    UINT16_t tagType, tagLen;

    if (packet->ver != 1) {
	ERR("Invalid PPPoE version (%d)", (int) packet->ver);
	return NULL;
    }
    if (packet->type != 1) {
	ERR("Invalid PPPoE type (%d)", (int) packet->type);
	return NULL;
    }

    /* Do some sanity checks on packet */
    if (len > ETH_JUMBO_LEN - 6) { /* 6-byte overhead for PPPoE header */
	ERR("Invalid PPPoE packet length (%u)", len);
	return NULL;
    }

    /* Step through the tags */
    curTag = packet->payload;
    while(curTag - packet->payload < len) {
	/* Alignment is not guaranteed, so do this by hand... */
	tagType = (((UINT16_t) curTag[0]) << 8) +
	    (UINT16_t) curTag[1];
	tagLen = (((UINT16_t) curTag[2]) << 8) +
	    (UINT16_t) curTag[3];
	if (tagType == TAG_END_OF_LIST) {
	    return NULL;
	}
	if ((curTag - packet->payload) + tagLen + TAG_HDR_SIZE > len) {
	    ERR("Invalid PPPoE tag length (%u)", tagLen);
	    return NULL;
	}
	if (tagType == type) {
	    memcpy(tag, curTag, tagLen + TAG_HDR_SIZE);
	    return curTag;
	}
	curTag = curTag + TAG_HDR_SIZE + tagLen;
    }
    return NULL;
}

/**********************************************************************
*%FUNCTION: switchToRealID
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sets effective user-ID and group-ID to real ones.  Aborts on failure
***********************************************************************/
void
switchToRealID (void) {
    if (IsSetID) {
	if (saved_uid == (uid_t) -2) saved_uid = geteuid();
	if (saved_gid == (uid_t) -2) saved_gid = getegid();
	if (setegid(getgid()) < 0) {
	    printErr("setgid failed");
	    exit(EXIT_FAILURE);
	}
	if (seteuid(getuid()) < 0) {
	    printErr("seteuid failed");
	    exit(EXIT_FAILURE);
	}
    }
}

/**********************************************************************
*%FUNCTION: switchToEffectiveID
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sets effective user-ID and group-ID back to saved gid/uid
***********************************************************************/
void
switchToEffectiveID (void) {
    if (IsSetID) {
	if (setegid(saved_gid) < 0) {
	    printErr("setgid failed");
	    exit(EXIT_FAILURE);
	}
	if (seteuid(saved_uid) < 0) {
	    printErr("seteuid failed");
	    exit(EXIT_FAILURE);
	}
    }
}

/**********************************************************************
*%FUNCTION: dropPrivs
*%ARGUMENTS:
* None
*%RETURNS:
* Nothing
*%DESCRIPTION:
* If effective ID is root, try to become "nobody".  If that fails and
* we're SUID, switch to real user-ID
***********************************************************************/
void
dropPrivs(void)
{
    struct passwd *pw = NULL;
    int ok = 0;
    if (geteuid() == 0) {
	pw = getpwnam("nobody");
	if (pw) {
	    if (setgid(pw->pw_gid) < 0) ok++;
	    if (setuid(pw->pw_uid) < 0) ok++;
	}
    }
    if (ok < 2 && IsSetID) {
	setegid(getgid());
	seteuid(getuid());
    }
}
#endif

/**********************************************************************
*%FUNCTION: printErr
*%ARGUMENTS:
* str -- error message
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Prints a message to stderr and syslog.
***********************************************************************/
void
printErr(char const *str)
{
    fprintf(stderr, "pppoe: %s\n", str);
    ERR("pppoe: %s", str);
}


/**********************************************************************
*%FUNCTION: strDup
*%ARGUMENTS:
* str -- string to copy
*%RETURNS:
* A malloc'd copy of str.  Exits if malloc fails.
***********************************************************************/
char *
strDup(char const *str)
{
    char *copy = malloc(strlen(str)+1);
    if (!copy) {
	rp_fatal("strdup failed");
    }
    strcpy(copy, str);
    return copy;
}

/**********************************************************************
*%FUNCTION: computeTCPChecksum
*%ARGUMENTS:
* ipHdr -- pointer to IP header
* tcpHdr -- pointer to TCP header
*%RETURNS:
* The computed TCP checksum
***********************************************************************/
UINT16_t
computeTCPChecksum(unsigned char *ipHdr, unsigned char *tcpHdr)
{
    UINT32_t sum = 0;
    UINT16_t count = ipHdr[2] * 256 + ipHdr[3];
    UINT16_t tmp;

    unsigned char *addr = tcpHdr;
    unsigned char pseudoHeader[12];

    /* Count number of bytes in TCP header and data */
    count -= (ipHdr[0] & 0x0F) * 4;

    memcpy(pseudoHeader, ipHdr+12, 8);
    pseudoHeader[8] = 0;
    pseudoHeader[9] = ipHdr[9];
    pseudoHeader[10] = (count >> 8) & 0xFF;
    pseudoHeader[11] = (count & 0xFF);

    /* Checksum the pseudo-header */
    sum += * (UINT16_t *) pseudoHeader;
    sum += * ((UINT16_t *) (pseudoHeader+2));
    sum += * ((UINT16_t *) (pseudoHeader+4));
    sum += * ((UINT16_t *) (pseudoHeader+6));
    sum += * ((UINT16_t *) (pseudoHeader+8));
    sum += * ((UINT16_t *) (pseudoHeader+10));

    /* Checksum the TCP header and data */
    while (count > 1) {
	memcpy(&tmp, addr, sizeof(tmp));
	sum += (UINT32_t) tmp;
	addr += sizeof(tmp);
	count -= sizeof(tmp);
    }
    if (count > 0) {
	sum += (unsigned char) *addr;
    }

    while(sum >> 16) {
	sum = (sum & 0xffff) + (sum >> 16);
    }
    return (UINT16_t) ((~sum) & 0xFFFF);
}

/**********************************************************************
*%FUNCTION: clampMSS
*%ARGUMENTS:
* packet -- PPPoE session packet
* dir -- either "incoming" or "outgoing"
* clampMss -- clamp value
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Clamps MSS option if TCP SYN flag is set.
***********************************************************************/
void
clampMSS(PPPoEPacket *packet, char const *dir, int clampMss)
{
    unsigned char *tcpHdr;
    unsigned char *ipHdr;
    unsigned char *opt;
    unsigned char *endHdr;
    unsigned char *mssopt = NULL;
    UINT16_t csum;

    int len, minlen;

    /* check PPP protocol type */
    if (packet->payload[0] & 0x01) {
        /* 8 bit protocol type */

        /* Is it IPv4? */
        if (packet->payload[0] != 0x21) {
            /* Nope, ignore it */
            return;
        }

        ipHdr = packet->payload + 1;
	minlen = 41;
    } else {
        /* 16 bit protocol type */

        /* Is it IPv4? */
        if (packet->payload[0] != 0x00 ||
            packet->payload[1] != 0x21) {
            /* Nope, ignore it */
            return;
        }

        ipHdr = packet->payload + 2;
	minlen = 42;
    }

    /* Is it too short? */
    len = (int) ntohs(packet->length);
    if (len < minlen) {
	/* 20 byte IP header; 20 byte TCP header; at least 1 or 2 byte PPP protocol */
	return;
    }

    /* Verify once more that it's IPv4 */
    if ((ipHdr[0] & 0xF0) != 0x40) {
	return;
    }

    /* Is it a fragment that's not at the beginning of the packet? */
    if ((ipHdr[6] & 0x1F) || ipHdr[7]) {
	/* Yup, don't touch! */
	return;
    }
    /* Is it TCP? */
    if (ipHdr[9] != 0x06) {
	return;
    }

    /* Get start of TCP header */
    tcpHdr = ipHdr + (ipHdr[0] & 0x0F) * 4;

    /* Is SYN set? */
    if (!(tcpHdr[13] & 0x02)) {
	return;
    }

    /* Compute and verify TCP checksum -- do not touch a packet with a bad
       checksum */
    csum = computeTCPChecksum(ipHdr, tcpHdr);
    if (csum) {
	ERR("Bad TCP checksum %x", (unsigned int) csum);

	/* Upper layers will drop it */
	return;
    }

    /* Look for existing MSS option */
    endHdr = tcpHdr + ((tcpHdr[12] & 0xF0) >> 2);
    opt = tcpHdr + 20;
    while (opt < endHdr) {
	if (!*opt) break;	/* End of options */
	switch(*opt) {
	case 1:
	    opt++;
	    break;

	case 2:
	    if (opt[1] != 4) {
		/* Something fishy about MSS option length. */
		ERR("Bogus length for MSS option (%u) from %u.%u.%u.%u",
		       (unsigned int) opt[1],
		       (unsigned int) ipHdr[12],
		       (unsigned int) ipHdr[13],
		       (unsigned int) ipHdr[14],
		       (unsigned int) ipHdr[15]);
		return;
	    }
	    mssopt = opt;
	    break;
	default:
	    if (opt[1] < 2) {
		/* Someone's trying to attack us? */
		ERR("Bogus TCP option length (%u) from %u.%u.%u.%u",
		       (unsigned int) opt[1],
		       (unsigned int) ipHdr[12],
		       (unsigned int) ipHdr[13],
		       (unsigned int) ipHdr[14],
		       (unsigned int) ipHdr[15]);
		return;
	    }
	    opt += (opt[1]);
	    break;
	}
	/* Found existing MSS option? */
	if (mssopt) break;
    }

    /* If MSS exists and it's low enough, do nothing */
    if (mssopt) {
	unsigned mss = mssopt[2] * 256 + mssopt[3];
	if (mss <= clampMss) {
	    return;
	}

	mssopt[2] = (((unsigned) clampMss) >> 8) & 0xFF;
	mssopt[3] = ((unsigned) clampMss) & 0xFF;
    } else {
	/* No MSS option.  Don't add one; we'll have to use 536. */
	return;
    }

    /* Recompute TCP checksum */
    tcpHdr[16] = 0;
    tcpHdr[17] = 0;
    csum = computeTCPChecksum(ipHdr, tcpHdr);
    (* (UINT16_t *) (tcpHdr+16)) = csum;
}

/***********************************************************************
*%FUNCTION: sendPADT
*%ARGUMENTS:
* conn -- PPPoE connection
* msg -- if non-NULL, extra error message to include in PADT packet.
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADT packet
***********************************************************************/
void
sendPADT(PPPoEConnection *conn, char const *msg)
{
    PPPoEPacket packet;
    unsigned char *cursor = packet.payload;

    UINT16_t plen = 0;

    /* Do nothing if no session established yet */
    if (!conn->session) return;

    /* Do nothing if no discovery socket */
    if (conn->discoverySocket < 0) return;

    memcpy(packet.ethHdr.h_dest, conn->peerEth, ETH_ALEN);
    memcpy(packet.ethHdr.h_source, conn->myEth, ETH_ALEN);

    packet.ethHdr.h_proto = htons(ETH_PPPOE_DISCOVERY);
    packet.ver = 1;
    packet.type = 1;
    packet.code = CODE_PADT;
    packet.session = conn->session;

    /* Reset Session to zero so there is no possibility of
       recursive calls to this function by any signal handler */
    conn->session = 0;

    /* If we're using Host-Uniq, copy it over */
    if (conn->hostUniq) {
	PPPoETag hostUniq;
	int len = (int) strlen(conn->hostUniq);
	hostUniq.type = htons(TAG_HOST_UNIQ);
	hostUniq.length = htons(len);
	memcpy(hostUniq.payload, conn->hostUniq, len);
	CHECK_ROOM(cursor, packet.payload, len + TAG_HDR_SIZE);
	memcpy(cursor, &hostUniq, len + TAG_HDR_SIZE);
	cursor += len + TAG_HDR_SIZE;
	plen += len + TAG_HDR_SIZE;
    }

    /* Copy error message */
    if (msg) {
	PPPoETag err;
	size_t elen = strlen(msg);
	err.type = htons(TAG_GENERIC_ERROR);
	err.length = htons(elen);
	strcpy((char *) err.payload, msg);
	memcpy(cursor, &err, elen + TAG_HDR_SIZE);
	cursor += elen + TAG_HDR_SIZE;
	plen += elen + TAG_HDR_SIZE;
    }

    /* Copy cookie and relay-ID if needed */
    if (conn->cookie.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(conn->cookie.length) + TAG_HDR_SIZE);
	memcpy(cursor, &conn->cookie, ntohs(conn->cookie.length) + TAG_HDR_SIZE);
	cursor += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
	plen += ntohs(conn->cookie.length) + TAG_HDR_SIZE;
    }

    if (conn->relayId.type) {
	CHECK_ROOM(cursor, packet.payload,
		   ntohs(conn->relayId.length) + TAG_HDR_SIZE);
	memcpy(cursor, &conn->relayId, ntohs(conn->relayId.length) + TAG_HDR_SIZE);
	cursor += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
	plen += ntohs(conn->relayId.length) + TAG_HDR_SIZE;
    }

    packet.length = htons(plen);
    sendPacket(conn->discoverySocket, (unsigned char *)&packet, (int) (plen + HDR_SIZE));
}

/***********************************************************************
*%FUNCTION: sendPADTf
*%ARGUMENTS:
* conn -- PPPoE connection
* msg -- printf-style format string
* args -- arguments for msg
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Sends a PADT packet with a formatted message
***********************************************************************/
void
sendPADTf(PPPoEConnection *conn, char const *fmt, ...)
{
    char msg[512];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    msg[511] = 0;

    sendPADT(conn, msg);
}

/**********************************************************************
*%FUNCTION: pktLogErrs
*%ARGUMENTS:
* pkt -- packet type (a string)
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Logs error tags
***********************************************************************/
void
pktLogErrs(char const *pkt,
	   UINT16_t type, UINT16_t len, unsigned char *data,
	   void *extra)
{
    char const *str;
    //char const *fmt = "%s: %s: %.*s";
    switch(type) {
    case TAG_SERVICE_NAME_ERROR:
	str = "Service-Name-Error";
	break;
    case TAG_AC_SYSTEM_ERROR:
	str = "System-Error";
	break;
    default:
	str = "Generic-Error";
    }

    ERR("%s: %s: %.*s", pkt, str, (int) len, data);
    fprintf(stderr, "%s: %s: %.*s", pkt, str, (int) len, data);
    fprintf(stderr, "\n");
}

/**********************************************************************
*%FUNCTION: parseLogErrs
*%ARGUMENTS:
* type -- tag type
* len -- tag length
* data -- tag data
* extra -- extra user data
*%RETURNS:
* Nothing
*%DESCRIPTION:
* Picks error tags out of a packet and logs them.
***********************************************************************/
void
parseLogErrs(UINT16_t type, UINT16_t len, unsigned char *data,
	     void *extra)
{
    pktLogErrs("PADT", type, len, data, extra);
}

struct LCPOptionValueStruct negoOpt;

unsigned char nak_option_payload[MAX_PPPOE_PAYLOAD] = {0};
unsigned short nak_option_payload_len = 0; 

unsigned char peer_option_payload[MAX_PPPOE_PAYLOAD] = {0};
unsigned short peer_option_payload_len = 0; 

int
parseSessionPacket(PPPSubProtocolPacket *sPacket, ParseFunc *func, void *extra)
{
    UINT16_t len;
    unsigned char *curOptPtr;
    UINT16_t optType, optLen;

    if (!sPacket || !func) {
        ERR("args empty!");
        return -1;
    }

    len = ntohs(sPacket->length);

    /* reinit */
    negoOpt.LCP_option_set_map = 0;
    nak_option_payload_len = 0;
    peer_option_payload_len = 0;
    memset(nak_option_payload, 0, sizeof(nak_option_payload));
    memset(peer_option_payload, 0, sizeof(peer_option_payload));


    /* exclude protocol in PPPSubProtocolPacketStruct */
    len -= (MIN_PPP_SUB_PROTO_HDR_SIZE - sizeof(unsigned short));
    /* Do some sanity checks on packet */
    if (len > (ETH_JUMBO_LEN - TOTOAL_PPP_SUB_PROTO_HDR_SIZE)) {
	ERR("Invalid PPPoE packet length (%u), max=%u", len,
                    (ETH_JUMBO_LEN - TOTOAL_PPP_SUB_PROTO_HDR_SIZE));
	return -1;
    }

    /* Step through the option */
    curOptPtr = sPacket->data;
    while (curOptPtr - sPacket->data < len) {
        optType = (UINT16_t) curOptPtr[0];    
        optLen = (UINT16_t) curOptPtr[1];
    //DBG("opt=%d, len=%u, type=%d, len=%d", (curOptPtr - sPacket->data), len, optType, optLen);

        if ((curOptPtr - sPacket->data) + optLen > len) {
            ERR("Invalid option length! opt len=%u, hdr=%d, len=%u",
                optLen, (curOptPtr - sPacket->data), len);
            return -1;
        }

#if 0
        DBG("parse opt=%d, optlen=%d", optType, optLen);
        hexdump("parse opt ", curOptPtr, optLen);
#endif

        func(optType, optLen, curOptPtr, extra);
        curOptPtr = curOptPtr + optLen;
    }
    return 0;
}


int
parsePAPPacket(PPPSubProtocolPacket *sPacket, PppoeProbeInfo *pppoeProbeInfoPtr)
{
    UINT16_t len;
    unsigned char *curPtr;
    unsigned char user[MAX_AUTH_BUF_LEN+1] = {0};
    unsigned char passwd[MAX_AUTH_BUF_LEN+1] = {0};
    UINT16_t ulen, plen;

    if (!sPacket || !pppoeProbeInfoPtr) {
        ERR("args empty!");
        return -1;
    }

    len = ntohs(sPacket->length);

    /* reinit */
    memset(pppoeProbeInfoPtr->peer_auth_user, 0, sizeof(pppoeProbeInfoPtr->peer_auth_user));
    memset(pppoeProbeInfoPtr->peer_auth_passwd, 0, sizeof(pppoeProbeInfoPtr->peer_auth_passwd));


    /* exclude protocol in PPPSubProtocolPacketStruct */
    len -= (MIN_PPP_SUB_PROTO_HDR_SIZE - sizeof(unsigned short));
    /* Do some sanity checks on packet */
    if (len > (ETH_JUMBO_LEN - TOTOAL_PPP_SUB_PROTO_HDR_SIZE)) {
	ERR("Invalid PPPoE packet length (%u), max=%u", len,
                    (ETH_JUMBO_LEN - TOTOAL_PPP_SUB_PROTO_HDR_SIZE));
	return -1;
    }

    curPtr = sPacket->data;

    // get user len and value
    ulen = curPtr[0];
    if (ulen >= len || ulen > MAX_AUTH_BUF_LEN) {
        ERR("user len=%d too big! sublen=%d, max ulen=%d", ulen, len, MAX_AUTH_BUF_LEN);
        return -1;
    }
    ++curPtr;
    memcpy(user, curPtr, ulen);
    curPtr += ulen;

    // get passwd len and value
    plen = curPtr[0];
    if (plen >= len || plen > MAX_AUTH_BUF_LEN) {
        ERR("user len=%d too big! sublen=%d, max ulen=%d", ulen, len, MAX_AUTH_BUF_LEN);
        return -1;
    }
    ++curPtr;
    memcpy(passwd, curPtr, plen);
    curPtr += plen;

    // check length
    if (1 + ulen + 1 + plen != len) {
        ERR("length error! 1 + ulen(%d) + 1 + plen(%d) != len(%d)!", ulen, plen, len);
        return -1;
    }

    if (ulen == 0 || plen == 0) {
        ERR("length error! ulen=%d, plen=%d!", ulen, plen);
        return -1;
    }

    INFO("Got PAP account info, user=[%s], passwd=[%s]", user, passwd);
    memcpy(pppoeProbeInfoPtr->peer_auth_user, user, ulen);
    memcpy(pppoeProbeInfoPtr->peer_auth_passwd, passwd, plen);
    ++pppoeProbeInfoPtr->peer_auth_count;

    return 0;
}


