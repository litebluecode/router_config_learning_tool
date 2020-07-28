#ifndef __IPADDR_LEARNER_H
#define __IPADDR_LEARNER_H

#include "config.h"
#include "event.h"
#include "ipaddr_learner.h"

#ifdef HAVE_LINUX_IF_ETHER_H
#include <linux/if_ether.h>
#endif


#define MAX_PACKET_LEN 1500


typedef struct {
    char name[IFNAMSIZ+1];	/* Interface name */
    unsigned char mac[ETH_ALEN]; /* MAC address */
    UINT16_t mtu;               /* MTU of interface */
    int arp_sock;
    int ipv4_sock;       // DHCP + DNS
    EventHandler *arp_eh;
    EventHandler *ipv4_eh;   // DHCP + DNS
} IpaddrMgntIface;


typedef struct {
    int rx_count;
    unsigned char srcMac[ETH_ALEN];     /* The client which send the request */
    unsigned char destMac[ETH_ALEN];    /* Maybe broadcast */
    unsigned int ipAddr;
    unsigned int netmask;
    unsigned int gwAddr;
    unsigned int dns1Addr;
    unsigned int dns2Addr;
} IpaddrProbeInfo;

typedef struct {
    int is_start_learn;
    /* TODO: need remove redundant members, separate 'IpaddrProbeInfo' */
    IpaddrProbeInfo arpProbe;
    IpaddrProbeInfo dhcpProbe;
    IpaddrProbeInfo dnsProbe;
} IpaddrLearnInfo;

IpaddrLearnInfo ipaddrLearnInfo;


int ipaddrLearnerInit(unsigned char *ifname);
int ipaddrLearnerDeinit(void);


#endif
