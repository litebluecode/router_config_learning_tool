#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#if defined(HAVE_LINUX_IF_H)
#include <linux/if.h>
#elif defined(HAVE_NET_IF_H)
#include <net/if.h>
#endif
#include <linux/ip.h>
#include <linux/udp.h>


#include "ipaddr_learner.h"
#include "packet.h" // openInterfaceForUDP


#define ETH_ARP                               0x0806
#define ETH_IP                                  0x0800

/* DHCP Packet */
#define DHCP_SERVER_PORT            67
#define DHCP_CLIENT_PORT             68
#define DNS_PORT                             53
#define DHCP_MAGIC_KEY                0x63825363

/* DHCP Options */
#define TAG_REQUESTED_IP	((uint8_t)  50)
#define TAG_DHCP_MESSAGE	((uint8_t)  53)
#define TAG_CLIENT_ID		((uint8_t)  61)
#define TAG_END			((uint8_t) 255)

/* DHCP Message types (values for TAG_DHCP_MESSAGE option) */
#define DHCPDISCOVER	1
#define DHCPOFFER		2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8

/* BOOTP OPCODE */
#define BOOTPREPLY	2
#define BOOTPREQUEST	1

struct BootpPacketStruct {
	uint8_t		bp_op;		/* packet opcode type */
	uint8_t		bp_htype;	/* hardware addr type */
	uint8_t		bp_hlen;	/* hardware addr length */
	uint8_t		bp_hops;	/* gateway hops */
	uint32_t	bp_xid;		/* transaction ID */
	uint16_t	bp_secs;	/* seconds since boot began */
	uint16_t	bp_flags;	/* flags */
	struct in_addr	bp_ciaddr;	/* client IP address */
	struct in_addr	bp_yiaddr;	/* 'your' IP address */
	struct in_addr	bp_siaddr;	/* server IP address */
	struct in_addr	bp_giaddr;	/* gateway IP address */
	uint8_t		bp_chaddr[16];	/* client hardware address */
	uint8_t		bp_sname[64];	/* server host name */
	uint8_t		bp_file[128];	/* boot file name */
	uint8_t		bp_vend[64];	/* vendor-specific area */
} __packed;


IpaddrMgntIface ipaddrIface = {
    .name = LISTEN_INTERFACE_NAME,
};

IpaddrLearnInfo ipaddrLearnInfo;


static int constructArpResp(unsigned char *arpRespPkt, unsigned char *arpReqPkt, int length)
{
    struct ArpPacketBodyStruct {
        unsigned char       ar_sha[ETH_ALEN];   /* sender hardware address  */
        unsigned char       ar_sip[4];      /* sender IP address        */
        unsigned char       ar_tha[ETH_ALEN];   /* target hardware address  */
        unsigned char       ar_tip[4];      /* target IP address        */
    } __packed;

    struct ethhdr *reqEthHdr = (struct ethhdr *)arpReqPkt;
    struct ethhdr *respEthHdr = (struct ethhdr *)arpRespPkt;
    struct arphdr *reqArpHdr = (struct arphdr *)(reqEthHdr +1);
    struct arphdr *respArpHdr = (struct arphdr *)(respEthHdr +1);
    struct ArpPacketBodyStruct *reqArpBody = (struct ArpPacketBodyStruct *)(reqArpHdr + 1); // after ar_op
    struct ArpPacketBodyStruct *respArpBody = (struct ArpPacketBodyStruct *)(respArpHdr + 1); // after ar_op

    memcpy(arpRespPkt, arpReqPkt, length);

    memcpy(respEthHdr->h_dest, reqEthHdr->h_source, ETH_ALEN);
    memcpy(respEthHdr->h_source, ipaddrIface.mac, ETH_ALEN);

    respArpHdr->ar_op = htons(ARPOP_REPLY);

    memcpy(respArpBody->ar_sha, ipaddrIface.mac, ETH_ALEN);
    memcpy(respArpBody->ar_sip, reqArpBody->ar_tip, 4);
    memcpy(respArpBody->ar_tha, reqArpBody->ar_sha, ETH_ALEN);
    memcpy(respArpBody->ar_tip, reqArpBody->ar_sip, 4);

    return length;
}

void ipaddrProcessArpPacket(IpaddrMgntIface *i)
{
    int len;
    unsigned char packet[MAX_PACKET_LEN+1] = {0};
    unsigned char arpRespPacket[MAX_PACKET_LEN+1] = {0};
    int plen;
    int sock;
    struct ethhdr *eth = NULL;
    struct arphdr *arph = NULL;
    unsigned char *arpPtr = NULL;

    if (!i)
    {
        ERR("interface empty!");
        return;
    }
    sock = i->arp_sock;

    if (receivePacket(sock, (unsigned char *)&packet, MAX_PACKET_LEN, &len) < 0) {
        ERR("failed receivePacket!");
        return;
    }
    //DBG("GOT pkt! if=%s, len=%d", i->name, len);
    hexdump("arp", packet, len);

    /* Check */
    eth = (struct ethhdr *)packet;

#ifdef LISTEN_ON_LAN_IFACE
    if (checkIsExistDevicesNode(eth->h_source) != 0) {
        WARN("ignore already exist sta="MAC_STR_FMT, MAC_STR(eth->h_source));
        return;
    }
#endif

    arph = (struct arphdr *)(eth +1);
    arpPtr = (unsigned char *)arph + 8; // after ar_op

    if (arph->ar_hln != 6 || arph->ar_pln != 4) {
        WARN("address len(mac %d, ip %d) not right!", arph->ar_hln, arph->ar_pln);
        return;
    }

    if (ntohs(arph->ar_op) == ARPOP_REQUEST) {  // ARP REQUEST, 1
        unsigned char *tmpArpPtr = NULL;
        unsigned int sAddr, dAddr;

        tmpArpPtr = arpPtr + arph->ar_hln;
        sAddr = (unsigned int)ntohl(*(unsigned int *)tmpArpPtr);
        tmpArpPtr += (arph->ar_pln + arph->ar_hln);
        dAddr = (unsigned int)ntohl(*(unsigned int *)tmpArpPtr);

        if (sAddr == dAddr) {
            WARN("src ip="INET4_STR_FMT" and dest ip="INET4_STR_FMT" is common!",
                INET4_STR_ARGS(sAddr), INET4_STR_ARGS(dAddr));
            return;
        }
        if (sAddr == 0 || dAddr == 0) {
            WARN("src ip="INET4_STR_FMT" and dest ip="INET4_STR_FMT", maybe these ip is not static!",
                INET4_STR_ARGS(sAddr), INET4_STR_ARGS(dAddr));
            return;
        }
        INFO("rx pkt indicate src ip="INET4_STR_FMT", dest ip="INET4_STR_FMT,
            INET4_STR_ARGS(sAddr), INET4_STR_ARGS(dAddr));

        memcpy(ipaddrLearnInfo.arpProbe.srcMac, arpPtr, arph->ar_hln);
        arpPtr += arph->ar_hln;

        if (ntohl(*(unsigned int *)arpPtr) != 0 && ntohl(*(unsigned int *)arpPtr) != 0xFFFFFFFF) {
            ipaddrLearnInfo.arpProbe.ipAddr = (unsigned int)ntohl(*(unsigned int *)arpPtr);
        }
        arpPtr += arph->ar_pln;

        memcpy(ipaddrLearnInfo.arpProbe.destMac, arpPtr, arph->ar_hln);
        arpPtr += arph->ar_hln;

        if (ntohl(*(unsigned int *)arpPtr) != 0 && ntohl(*(unsigned int *)arpPtr) != 0xFFFFFFFF) {
            ipaddrLearnInfo.arpProbe.gwAddr = (unsigned int)ntohl(*(unsigned int *)arpPtr);
        }
        arpPtr += arph->ar_pln;

        INFO("ARP request, src ("MAC_STR_FMT", "INET4_STR_FMT"), dest ("MAC_STR_FMT", "INET4_STR_FMT")",
            MAC_STR(ipaddrLearnInfo.arpProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.ipAddr),
            MAC_STR(ipaddrLearnInfo.arpProbe.destMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.gwAddr)
        );

    } else {
        WARN("not process arp operation %d", ntohs(arph->ar_op));
        return;
    }

    INFO("GOT ARP request, src ("MAC_STR_FMT", "INET4_STR_FMT"), dest ("MAC_STR_FMT", "INET4_STR_FMT")",
        MAC_STR(ipaddrLearnInfo.arpProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.ipAddr),
        MAC_STR(ipaddrLearnInfo.arpProbe.destMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.gwAddr)
    );

    ipaddrLearnInfo.arpProbe.rx_count++;
    ipaddrLearnInfo.is_start_learn++;

    plen = constructArpResp(arpRespPacket, packet, len);
    if (plen <= 0) {
        return;
    }
    sendPacket(sock, arpRespPacket, plen);

}

void ipaddrProcessIpv4Packet(IpaddrMgntIface *i)
{
    int len;
    unsigned char packet[MAX_PACKET_LEN+1] = {0};
    int sock;
    struct ethhdr *eth = NULL;      // eth header
    struct iphdr *iph = NULL;       // ip header
    struct udphdr *udph = NULL;   // udp header

    if (!i)
    {
        ERR("interface empty!");
        return;
    }
    sock = i->ipv4_sock;

    if (receivePacket(sock, (unsigned char *)&packet, MAX_PACKET_LEN, &len) < 0) {
        ERR("failed receivePacket!");
        return;
    }
    eth = (struct ethhdr *)packet;

    iph = (struct iphdr *)(eth + 1);
    if (iph->protocol != IPPROTO_UDP) {
        //DBG("ignore pkt, protocol=%d", iph->protocol);
        return;
    }

    udph = (struct udphdr *)((unsigned char *)iph + iph->ihl * 4);
    if (ntohs(udph->dest) == DNS_PORT) {
        if (memcmp(ipaddrLearnInfo.arpProbe.srcMac, (eth->h_source), ETH_ALEN) != 0) {
            DBG("DNS need ARP Request smac="MAC_STR_FMT"! ignore smac="MAC_STR_FMT", proto=%#x",
                MAC_STR(ipaddrLearnInfo.arpProbe.srcMac), MAC_STR(eth->h_source), ntohs(eth->h_proto));
            return;
        }

        DBG("GOT DNS pkt! if=%s, len=%d", i->name, len);
        hexdump("DNS", packet, len);

        memcpy(ipaddrLearnInfo.dnsProbe.destMac, (eth->h_dest), ETH_ALEN);
        memcpy(ipaddrLearnInfo.dnsProbe.srcMac, (eth->h_source), ETH_ALEN);

        //ipaddrLearnInfo.dnsProbe.ipAddr = ntohl(iph->saddr);

        if ((ntohl(iph->daddr) != ipaddrLearnInfo.dnsProbe.dns1Addr) &&
                (ntohl(iph->daddr) != ipaddrLearnInfo.dnsProbe.dns2Addr)) {
            if (ipaddrLearnInfo.dnsProbe.dns1Addr == 0) {
                ipaddrLearnInfo.dnsProbe.dns1Addr = ntohl(iph->daddr);
            } else {
                ipaddrLearnInfo.dnsProbe.dns2Addr = ntohl(iph->daddr);
            }
            DBG("get one dns="INET4_STR_FMT, INET4_STR_ARGS(ntohl(iph->daddr)));
        } else {
            //DBG("already exist, ignore this dns ip="INET4_STR_FMT, INET4_STR_ARGS(ntohl(iph->daddr)));
            return;
        }

        INFO("GOT DNS request, src=("MAC_STR_FMT", "INET4_STR_FMT"), "
            "dest=("MAC_STR_FMT"), dns=("INET4_STR_FMT", "INET4_STR_FMT")",
            MAC_STR(ipaddrLearnInfo.dnsProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.ipAddr),
            MAC_STR(ipaddrLearnInfo.dnsProbe.destMac),
            INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.dns1Addr), INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.dns2Addr)
        );

        ipaddrLearnInfo.dnsProbe.rx_count++;
        ipaddrLearnInfo.is_start_learn++;

    } else if (ntohs(udph->dest) == DHCP_SERVER_PORT) {
        unsigned char *dhcpBody = (unsigned char *)(udph + 1);
        int last_len = ntohs(udph->len);
        struct BootpPacketStruct *bootph = NULL;   // bootp header
        unsigned char *dhcpHdr = NULL;
        unsigned char *dhcpOptPtr = NULL;   // dhpc opt
        int dhcpOptAlen = 0; // dhcp options all length
        unsigned char haveBootp = 0, haveDhcpOpt = 0;
        unsigned char opCode, opLen;

        DBG("GOT DHCP pkt! if=%s, len=%d", i->name, len);
        hexdump("DHCP", packet, len);

        /* Check and Save Net info */
        if (*(unsigned int *)dhcpBody != htonl(DHCP_MAGIC_KEY)) {
            /* BOOTP */
            haveBootp = 1;
            bootph = (struct BootpPacketStruct *)dhcpBody;
            if (bootph->bp_op != BOOTPREQUEST) {
                WARN("bootp opcode=%d is not request!", bootph->bp_op);
                return;
            }
    
            if (bootph->bp_htype == 1 && bootph->bp_hlen == ETH_ALEN) {
#ifdef LISTEN_ON_LAN_IFACE
                if (checkIsExistDevicesNode(bootph->bp_chaddr) != 0) {
                    WARN("ignore already exist sta="MAC_STR_FMT, MAC_STR(bootph->bp_chaddr));
                    return;
                }
#endif
    
                memcpy(ipaddrLearnInfo.dhcpProbe.srcMac, bootph->bp_chaddr, ETH_ALEN);
            }
    
            if (last_len < sizeof(struct BootpPacketStruct)) {
                WARN("last_len=%d error, bootp len=%d", last_len, sizeof(struct BootpPacketStruct));
                return;
            }
            last_len -= sizeof(struct BootpPacketStruct);
            dhcpHdr = (unsigned char *)(bootph + 1);
        } else {
            dhcpHdr = (unsigned char *)(packet);
        }
    
        if (last_len > 0 && (*(unsigned int *)dhcpHdr == htonl(DHCP_MAGIC_KEY))) {
            /* DHCP OPTION */
            if (last_len <= sizeof(unsigned int)) {
                WARN("last_len=%d error!", last_len);
                return;
            }
            dhcpOptAlen = last_len - sizeof(unsigned int);
            dhcpOptPtr = (unsigned char *)dhcpHdr + 1;
            while (dhcpOptAlen > 0) {
                opCode = *((unsigned char *)dhcpOptPtr);
                opLen = *((unsigned char *)dhcpOptPtr + 1);
    
                if (2 + opLen > dhcpOptAlen) {
                    WARN("ERROR this opLen=%d, opCode=%d, dhcpOptAlen=%d!",
                        opLen, opCode, dhcpOptAlen);
                    break;
                }
    
                //DBG("get opcode=%d, len=%d", opCode, opLen);
                if (opCode == TAG_DHCP_MESSAGE) {
                    if ((*((unsigned char *)dhcpOptPtr + 2) == DHCPDISCOVER) ||
                        (*((unsigned char *)dhcpOptPtr + 2) == DHCPREQUEST)) {
                        haveDhcpOpt = 1;
                    } else {
                        WARN("dhcp msg value=%d, not discover/request!", *((unsigned char *)dhcpOptPtr + 2));
                        haveDhcpOpt = 1;
                    }
                } else if (opCode == TAG_CLIENT_ID) {
                    if ((*((unsigned char *)dhcpOptPtr + 2) == 1) && (opLen == ETH_ALEN + 1)) {
                        unsigned char *client_mac = (dhcpOptPtr + 2 + 1);
    
#ifdef LISTEN_ON_LAN_IFACE
                        if (checkIsExistDevicesNode(client_mac) != 0) {
                            WARN("ignore already exist sta="MAC_STR_FMT, MAC_STR(client_mac));
                            return;
                        }
#endif
    
                        memcpy(ipaddrLearnInfo.dhcpProbe.srcMac, client_mac, ETH_ALEN);
                    }
                } else if (opCode == TAG_REQUESTED_IP) {
                    if (opLen == sizeof(unsigned int)) {
                        ipaddrLearnInfo.dhcpProbe.ipAddr = *(unsigned int *)(dhcpOptPtr + 2);
                    }
                } else if (opCode == TAG_END) {
                    break;
                }
    
                if (dhcpOptAlen < (2 + opLen) || dhcpOptAlen <= opLen) {
                    WARN("ERROR dhcpOptAlen=%d, opLen=%d!", dhcpOptAlen, opLen);
                    break;
                }
                dhcpOptAlen -= (2 + opLen);
                dhcpOptPtr += (2 + opLen);
            }
        }
    
        if (haveBootp == 0 && haveDhcpOpt == 0) {
            WARN("Not found bootp info(%d) or dhcp option info(%d)!", haveBootp, haveDhcpOpt);
            return;
        }
    
        INFO("GOT DHCP request, src ("MAC_STR_FMT", "INET4_STR_FMT"), dest ("MAC_STR_FMT", "INET4_STR_FMT")",
            MAC_STR(ipaddrLearnInfo.dhcpProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.dhcpProbe.ipAddr),
            MAC_STR(ipaddrLearnInfo.dhcpProbe.destMac), INET4_STR_ARGS(ipaddrLearnInfo.dhcpProbe.gwAddr)
        );
    
        ipaddrLearnInfo.dhcpProbe.rx_count++;
        ipaddrLearnInfo.is_start_learn++;

    } else {
        return;
    }

}

void ipaddrIfaceArpHandler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    //DBG("get");
    ipaddrProcessArpPacket((IpaddrMgntIface *)data);
}

void ipaddrIfaceIpv4Handler(EventSelector *es,
		 int fd,
		 unsigned int flags,
		 void *data)
{
    //DBG("get");
    ipaddrProcessIpv4Packet((IpaddrMgntIface *)data);
}


extern EventSelector *event_selector;
int ipaddrLearnerInit(unsigned char *ifname)
{
    if (ifname && strlen(ifname) > 0)
    {
        strcpy(ipaddrIface.name, ifname);
    }
    ERR("listen on interface %s", ipaddrIface.name);

    memset(&ipaddrLearnInfo, 0, sizeof(ipaddrLearnInfo));

    /* Init interface and interface socket */
    ipaddrIface.mtu = 0;
    ipaddrIface.arp_sock = openInterface(ipaddrIface.name, ETH_ARP);
    if (ipaddrIface.arp_sock <= 0) {
        ERR("Failed open arp_sock!");
        return -1;
    }
    ipaddrIface.ipv4_sock = openInterface(ipaddrIface.name, ETH_IP);
    if (ipaddrIface.ipv4_sock <= 0) {
        ERR("Failed open ipv4_sock!");
        return -1;
    }

    if (getIfaceNetInfo(ipaddrIface.name, ipaddrIface.arp_sock,
        ipaddrIface.mac, &ipaddrIface.mtu) < 0) {
        ERR("Failed get %s net info!", ipaddrIface.name);
        return -1;
    }

    /* Init event handler */
    ipaddrIface.arp_eh = Event_AddHandler(event_selector,
                        ipaddrIface.arp_sock,
                        EVENT_FLAG_READABLE,
                        ipaddrIfaceArpHandler,
                        &ipaddrIface);

    if (!ipaddrIface.arp_eh) {
        rp_fatal("Event_AddHandler ARP failed");
    }

    ipaddrIface.ipv4_eh = Event_AddHandler(event_selector,
                        ipaddrIface.ipv4_sock,
                        EVENT_FLAG_READABLE,
                        ipaddrIfaceIpv4Handler,
                        &ipaddrIface);

    if (!ipaddrIface.ipv4_eh) {
        rp_fatal("Event_AddHandler ipv4 failed");
    }

    return 0;
}
int ipaddrLearnerDeinit(void)
{
    if (ipaddrIface.arp_eh) {
        int ret = Event_DelHandler(event_selector, ipaddrIface.arp_eh);
        if (ret != 0) {
            ERR("Event_DelHandler arp_eh error %d", ret);
        }
        ipaddrIface.arp_eh = NULL;
    }
    if (ipaddrIface.ipv4_eh) {
        int ret = Event_DelHandler(event_selector, ipaddrIface.ipv4_eh);
        if (ret != 0) {
            ERR("Event_DelHandler ipv4_eh error %d", ret);
        }
        ipaddrIface.ipv4_eh = NULL;
    }
    //DBG("finish close event handler");


    if (ipaddrIface.arp_sock) {
        close(ipaddrIface.arp_sock);
        ipaddrIface.arp_sock = 0;
    }
    if (ipaddrIface.ipv4_sock) {
        close(ipaddrIface.ipv4_sock);
        ipaddrIface.ipv4_sock = 0;
    }
    //DBG("finish close sock");

    return 0;
}



