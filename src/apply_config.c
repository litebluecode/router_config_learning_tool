#include "config.h"
#include "apply_config.h"
#include "packet.h"
#include "pppoe_learner.h"
#include "ipaddr_learner.h"

#include <string.h>

int g_apply_probe_config = 1;
unsigned int g_update_idx = 100;

const char *learnStateText[] = {"init", "learning", "timeout", "failed", "succeed"};


int ledControl(enum LedCtrlTypeEnum ctrlType)
{
    switch (ctrlType) {
        case LedCtrlTypeStart:
            //DBG("LedCtrlTypeStart");
            /* manually implement */
            break;

        case LedCtrlTypeOk:
            //DBG("LedCtrlTypeOk");
            /* manually implement */
            break;

        case LedCtrlTypeFailed:
            //DBG("LedCtrlTypeFailed");
            /* manually implement */
            break;

        case LedCtrlTypeOver:
        default:
            //DBG("LedCtrlTypeOver");
            /* manually implement */
            break;
    }

    return 0;
}

void resetInterfacePhy(void)
{
#ifdef LISTEN_ON_LAN_IFACE
#define INTERFACE_PHY_ID "2"  // LAN
#else
#define INTERFACE_PHY_ID "1"  // WAN
#endif

    /* manually implement */
#if 0
    system("echo "INTERFACE_PHY_ID" 0 > /proc/phyPower " \
        "&& sleep 3 " \
        "&& echo "INTERFACE_PHY_ID" 1 > /proc/phyPower");
#endif

}


int setCfgLearnState(LearnState_t state)
{
    /* manually implement */

    return 0;
}

int saveCfgLearnResult(NetConType_t type, LearnState_t state, IpaddrProbeInfo *pIpProbe, PppoeProbeInfo *pPppoeProbe)
{
    /* manually implement */

    return 0;
}

extern void dumpLearnedInfo(void);

int applyProbeNetConfig(int is_timeout)
{
    NetConType_t netConType = NetConTypeUnknown;
    IpaddrProbeInfo netaddrProbe;
    int ret = 0;
    LearnState_t state = learnStateSucceed;

    dumpLearnedInfo();

    if (pppoeLearnInfo.pppoeProbe.peer_auth_count > 0) {
        netConType = NetConTypePPPoE;
    } else if (ipaddrLearnInfo.dhcpProbe.rx_count > 0) {
        netConType = NetConTypeDHCP;
    } else if (ipaddrLearnInfo.arpProbe.rx_count > 0) {
        netConType = NetConTypeStatic;
    }

    /* print learn result */
    ERR("------------------------- Report ---------------------------");
    switch (netConType) {
        case NetConTypePPPoE :
            ERR("--- learn %s: target net type is %s, account (UserName=%s, Passwd=%s)",
                learnStateText[state],
                netConTypeText[netConType],
                pppoeLearnInfo.pppoeProbe.peer_auth_user,
                pppoeLearnInfo.pppoeProbe.peer_auth_passwd);
            break;

        case NetConTypeDHCP:
            ERR("--- learn %s: target net type is %s",
                learnStateText[state],
                netConTypeText[netConType]);
            break;

        case NetConTypeStatic:
            if (ipaddrLearnInfo.arpProbe.ipAddr == 0 || ipaddrLearnInfo.arpProbe.gwAddr == 0 ) {
                state = learnStateFailed;
                ERR("--- learn %s: %s ipaddr empty! info (IP="INET4_STR_FMT", Gateway="INET4_STR_FMT")",
                    learnStateText[state],
                    netConTypeText[netConType],
                    INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.ipAddr),
                    INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.gwAddr));
                ret = -1;
                break;
            }

            /* ipaddr copy from ARP probe info */
            memset(&netaddrProbe, 0, sizeof(IpaddrProbeInfo));
            netaddrProbe.ipAddr = ipaddrLearnInfo.arpProbe.ipAddr;
            netaddrProbe.gwAddr = ipaddrLearnInfo.arpProbe.gwAddr;
            if (ipaddrLearnInfo.arpProbe.netmask != 0) {
                netaddrProbe.netmask = ipaddrLearnInfo.arpProbe.netmask;
            } else {
                netaddrProbe.netmask = 0xFFFFFF00;
            }
            /* DNS addr copy from DNS probe info */
            if (ipaddrLearnInfo.dnsProbe.dns1Addr != 0) {
                netaddrProbe.dns1Addr = ipaddrLearnInfo.dnsProbe.dns1Addr;
            } else {
                netaddrProbe.dns1Addr = netaddrProbe.gwAddr;
            }
            if (ipaddrLearnInfo.dnsProbe.dns2Addr != 0) {
                netaddrProbe.dns2Addr = ipaddrLearnInfo.dnsProbe.dns2Addr;
            } else {
                netaddrProbe.dns2Addr = netaddrProbe.gwAddr;
            }

            ERR("--- learn %s: target net type is %s, info (IP="INET4_STR_FMT", Netmask="INET4_STR_FMT", Gateway="INET4_STR_FMT")",
                learnStateText[state],
                netConTypeText[netConType],
                INET4_STR_ARGS(netaddrProbe.ipAddr),
                INET4_STR_ARGS(netaddrProbe.netmask),
                INET4_STR_ARGS(netaddrProbe.gwAddr));

            if (ipaddrLearnInfo.dnsProbe.dns1Addr != ipaddrLearnInfo.dnsProbe.dns2Addr) {
                ERR("--- (DNS1="INET4_STR_FMT", DNS2="INET4_STR_FMT")",
                    INET4_STR_ARGS(netaddrProbe.dns1Addr),
                    INET4_STR_ARGS(netaddrProbe.dns2Addr));
            } else {
                ERR("--- (DNS="INET4_STR_FMT")",
                    INET4_STR_ARGS(netaddrProbe.dns1Addr));
            }
            break;

        case NetConTypeUnknown:
        default:
            ret = -1;
            if (is_timeout) {
                state = learnStateTimeout;
            } else {
                state = learnStateFailed;
            }
            ERR("--- learn %s: Failed probe net config!",
                learnStateText[state]);
    }
    ERR("------------------------------------------------------------");

    saveCfgLearnResult(netConType, state, &netaddrProbe, &pppoeLearnInfo.pppoeProbe);

    if (state == learnStateSucceed) {
        if (!g_apply_probe_config)
        {
#if 1
            ERR("User set NOT APPLY..");
            return 0;
#endif
        }

        // Apply wan config

    }

    return ret;
}


