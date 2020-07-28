#ifndef __PACKET_H
#define __PACKET_H

#include "config.h"
#include <netinet/in.h>
#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif


/* True if Ethernet address is broadcast or multicast */
#define NOT_UNICAST(e) ((e[0] & 0x01) != 0)
#define BROADCAST(e) ((e[0] & e[1] & e[2] & e[3] & e[4] & e[5]) == 0xFF)
#define NOT_BROADCAST(e) ((e[0] & e[1] & e[2] & e[3] & e[4] & e[5]) != 0xFF)

#define MAC_STR_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC_STR(_mac) _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]

#define	INET4_STR_FMT "%d.%d.%d.%d"
#if 0
#define	INET4_STR_ARGS(ADDR) \
    ((ADDR) & 0xff), (((ADDR) >> 8) & 0xff), (((ADDR) >> 16) & 0xff), (((ADDR) >> 24) & 0xff)
#else
#define	INET4_STR_ARGS(ADDR) \
    (((ADDR) >> 24) & 0xff), (((ADDR) >> 16) & 0xff), (((ADDR) >> 8) & 0xff), ((ADDR) & 0xff)
#endif

int getIfaceNetInfo(char const *ifname, const int fd, unsigned char *hwaddr, UINT16_t *mtu);

int openInterface(char const *ifname, UINT16_t type);
int sendPacket(int sock, unsigned char *pkt, int size);
int receivePacket(int sock, unsigned char *pkt, int pktSize, int *rxLength);

int openInterfaceForUDP(char const *ifname, UINT16_t port);
int sendUdpPacket(int sock, unsigned char *pkt, int size,
        struct sockaddr_in *pLocalAddr);
int receiveUdpPacket(int sock, unsigned char *pkt, int pktSize,
            int *pRxLength, struct sockaddr_in *pRemoteAddr);

#endif
