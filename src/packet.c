#include "config.h"
#include <sys/socket.h>
#include <sys/types.h>
#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>
#elif defined(HAVE_LINUX_IF_PACKET_H)
#include <linux/if_packet.h>
#endif

#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif

#ifdef HAVE_NETINET_IF_ETHER_H
#include <sys/types.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <linux/sockios.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif

#include "packet.h"


#ifdef PRINT_ALL_DEBUG
char g_is_print_hexdump = 0;
#else
char g_is_print_hexdump = 0;
#endif
void hexdump(unsigned char *title, unsigned char *data, int data_len)
{
    if (g_is_print_hexdump) {
#define HDSTRLEN 5120
#define PER_LINE_CHAR_NUM 16

        unsigned char BUF[HDSTRLEN+16];
        int i = 0;
        int alen = 0;
        int dlen = 0;

        if (data == NULL || data_len <= 0)
        	return;

        memset(BUF, 0, sizeof(BUF));

        while (alen < HDSTRLEN && data_len > dlen) {
        	for (i = 0; (i < PER_LINE_CHAR_NUM) && (dlen < data_len); i++) {
        		alen += snprintf(BUF+alen, HDSTRLEN, "%02X ", data[dlen++]);
        	}
        	if (i == PER_LINE_CHAR_NUM) {
        		alen += snprintf(BUF+alen, HDSTRLEN, "\n");
        	}
        }

        printf("\n--- dump %s, len=%d, max=%d, hex value=\n%s\n", title, data_len, dlen, BUF);
        printf("------------------------------------------------\n");
    }
}


#include <ctype.h>
int my_ipv4_inet_aton(const char *cp, __be32 *addrptr)
{
    __be32 addr;
    int value;
    int part;

    if (cp == NULL) {
        return 0;
    }

    addr = 0;
    for (part = 1; part <= 4; part++) {

        if (!isdigit(*cp))
            return 0;

        value = 0;
        while (isdigit(*cp)) {
            value *= 10;
            value += *cp++ - '0';
            if (value > 255)
                return 0;
        }

        if (part < 4) {
            if (*cp++ != '.')
                return 0;
        } else {
            char c = *cp++;
            if (c != '\0' && !isspace(c))
                return 0;
        }

        addr <<= 8;
        addr |= value;
    }

    if (addrptr) {
        *addrptr = htonl(addr);
    }

    return 1;
}



int getIfaceNetInfo(char const *ifname, const int fd, unsigned char *hwaddr, UINT16_t *mtu)
{
    struct ifreq ifr;

    if (fd <= 2) {
        ERR("getIfaceNetInfo: invalid fd=%d", fd);
        return -1;
    }

    /* Fill in hardware address */
    if (hwaddr) {
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        fatalSys("getIfaceNetInfo: ioctl(SIOCGIFHWADDR)");
    }
    memcpy(hwaddr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
#ifdef ARPHRD_ETHER
    if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        char buffer[256];
        sprintf(buffer, "%s: Interface %.16s is not Ethernet", __func__, ifname);
        rp_fatal(buffer);
    }
#endif
    if (NOT_UNICAST(hwaddr)) {
        char buffer[256];
        sprintf(buffer,
            "%s: Interface %.16s has broadcast/multicast MAC address??",
            __func__, ifname);
        rp_fatal(buffer);
    }
    }

    /* Sanity check on MTU */
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        fatalSys("getIfaceNetInfo: ioctl(SIOCGIFMTU)");
    }
    if (ifr.ifr_mtu < ETH_DATA_LEN) {
        char buffer[256];
        sprintf(buffer, "getIfaceNetInfo: Interface %.16s has MTU of %d -- should be %d.  You may have serious connection problems.",
            ifname, ifr.ifr_mtu, ETH_DATA_LEN);
        printErr(buffer);
    }
    if (mtu) *mtu = ifr.ifr_mtu;

    return 0;
}

/**********************************************************************
*%FUNCTION: openInterface
*%ARGUMENTS:
* ifname -- name of interface
* type -- Ethernet frame type
* hwaddr -- if non-NULL, set to the hardware address
* mtu    -- if non-NULL, set to the MTU
*%RETURNS:
* A raw socket for talking to the Ethernet card.  Exits on error.
*%DESCRIPTION:
* Opens a raw Ethernet socket
***********************************************************************/
int
openInterface(char const *ifname, UINT16_t type)
{
    int optval=1;
    int fd;
    struct ifreq ifr;
    int domain, stype;

#ifdef HAVE_STRUCT_SOCKADDR_LL
    struct sockaddr_ll sa;
#else
    struct sockaddr sa;
#endif

    memset(&sa, 0, sizeof(sa));

#ifdef HAVE_STRUCT_SOCKADDR_LL
    domain = PF_PACKET;
    stype = SOCK_RAW;
#else
    domain = PF_INET;
    stype = SOCK_PACKET;
#endif

    DBG("ifname=%s, type=%#x", ifname, (type));
    if ((fd = socket(domain, stype, htons(type))) < 0) {
	/* Give a more helpful message for the common error case */
	if (errno == EPERM) {
            ERR("socket: %s", strerror(errno));
            rp_fatal("openInterface: Cannot create raw socket -- must be run as root.");
	}
        ERR("socket: %s", strerror(errno));
        fatalSys("openInterface: socket");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        ERR("setsockopt SO_BROADCAST: %s", strerror(errno));
        fatalSys("openInterface: setsockopt SO_BROADCAST");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(optval)) < 0) {
        ERR("setsockopt SO_REUSEADDR: %s", strerror(errno));
        fatalSys("openInterface: setsockopt SO_REUSEADDR");
    }

#ifdef HAVE_STRUCT_SOCKADDR_LL
    /* Get interface index */
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(type);

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        ERR("ioctl SIOCGIFINDEX: %s", strerror(errno));
        fatalSys("openInterface: ioctl(SIOCFIGINDEX): Could not get interface index");
    }
    sa.sll_ifindex = ifr.ifr_ifindex;

#else
    strcpy(sa.sa_data, ifname);
#endif

    /* We're only interested in packets on specified interface */
    if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
        ERR("bind: %s", strerror(errno));
        fatalSys("openInterface: bind");
    }

    return fd;
}

int openInterfaceForUDP(char const *ifname, UINT16_t port)
{
    int optval=1;
    int fd;
    int domain, stype, type;
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof(sa));

    domain = PF_INET;
    stype = SOCK_DGRAM;
    type = 0; //IPPROTO_UDP;

    DBG("ifname=%s, port=%d, type=%#x", ifname, port, (type));
    if ((fd = socket(domain, stype, htons(type))) < 0) {
	/* Give a more helpful message for the common error case */
	if (errno == EPERM) {
            ERR("socket: %s", strerror(errno));
            rp_fatal("openInterfaceForUDP: Cannot create raw socket -- must be run as root.");
	}
        ERR("socket: %s", strerror(errno));
        fatalSys("openInterfaceForUDP: socket");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval)) < 0) {
        ERR("setsockopt SO_BROADCAST: %s", strerror(errno));
        fatalSys("openInterfaceForUDP: setsockopt broadcast");
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval , sizeof(optval)) < 0) {
        ERR("setsockopt SO_REUSEADDR: %s", strerror(errno));
        fatalSys("openInterfaceForUDP: setsockopt SO_REUSEADDR");
    }

    /* We're only interested in packets on specified interface */
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)+1) < 0) {
        ERR("setsockopt SO_BINDTODEVICE: %s", strerror(errno));
        fatalSys("openInterfaceForUDP: setsockopt SO_BINDTODEVICE");
    }

    memset(&sa, 0, sizeof(struct sockaddr_in));

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        ERR("bind: %s", strerror(errno));
        fatalSys("openInterfaceForUDP: bind");
    }

    return fd;
}


/***********************************************************************
*%FUNCTION: sendPacket
*%ARGUMENTS:
* sock -- socket to send to
* pkt -- the packet to transmit
* size -- size of packet (in bytes)
*%RETURNS:
* 0 on success; -1 on failure
*%DESCRIPTION:
* Transmits a packet
***********************************************************************/
int sendPacket(int sock, unsigned char *pkt, int size)
{
    int slen = 0;

    if (size < MIN_ETH_BODY_SIZE) {
        //DBG("size=%d too small, reset to %d", size, MIN_ETH_BODY_SIZE);
        memset(pkt + size, 0, MIN_ETH_BODY_SIZE-size);
        size = MIN_ETH_BODY_SIZE;
    }
    hexdump("sendPacket", pkt, size);

    slen = send(sock, pkt, size, 0);
    if (slen < 0 && (errno != ENOBUFS)) {
	sysErr("send (sendPacket)");
	return -1;
    }
    return 0;
}

int sendUdpPacket(int sock, unsigned char *pkt, int size,
        struct sockaddr_in *pLocalAddr)
{
    int slen = 0;

    if (size < MIN_ETH_BODY_SIZE) {
        //DBG("size=%d too small, reset to %d", size, MIN_ETH_BODY_SIZE);
        memset(pkt + size, 0, MIN_ETH_BODY_SIZE-size);
        size = MIN_ETH_BODY_SIZE;
    }
    hexdump("sendUdpPacket", pkt, size);

    slen = sendto(sock, pkt, size, 0, (struct sockaddr *) &pLocalAddr, sizeof(struct sockaddr_in));
    if (slen < 0 && (errno != ENOBUFS)) {
	sysErr("sendto (sendUdpPacket)");
	return -1;
    }
    return 0;
}


/***********************************************************************
*%FUNCTION: receivePacket
*%ARGUMENTS:
* sock -- socket to read from
* pkt -- place to store the received packet
* pkt_size -- store the received packet's buffer size
* size -- set to size of packet in bytes
*%RETURNS:
* >= 0 if all OK; < 0 if error
*%DESCRIPTION:
* Receives a packet
***********************************************************************/
int receivePacket(int sock, unsigned char *pkt, int pktSize, int *rxLength)
{
    if ((*rxLength = recv(sock, pkt, pktSize, 0)) < 0) {
	sysErr("recv (receivePacket)");
	return -1;
    }

    return 0;
}

int receiveUdpPacket(int sock, unsigned char *pkt, int pktSize,
            int *pRxLength, struct sockaddr_in *pRemoteAddr)
{
    socklen_t addr_len = sizeof(struct sockaddr_in);

    if (!pkt || !pRxLength || !pRemoteAddr) {
        ERR("empty args!");
        return -1;
    }

    if ((*pRxLength = recvfrom(sock, pkt, pktSize, 0, (struct sockaddr *)pRemoteAddr,
        &addr_len)) < 0) {
	sysErr("recv (receiveUdpPacket)");
	return -1;
    }
    DBG("receive pkt come from %s:%d\n",
        inet_ntoa(pRemoteAddr->sin_addr), ntohs(pRemoteAddr->sin_port));

    return 0;
}

