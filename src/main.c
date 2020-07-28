#include "config.h"
#include "packet.h"
#include "pppoe_learner.h"
#include "ipaddr_learner.h"
#include "apply_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>


char LOG_LEVEL_CHAR[MAX_LOG_LEVEL] = {'G', 'A', 'C', 'E', 'W', 'N', 'I', 'D'};
int my_debug_level = MY_DEF_DEBUG_LEVEL;
int gLearnTime = MAKE_A_DECISION_TIME;
int isLearnedConfig = 0;

/* Event Selector */
EventSelector *event_selector;

const char *netConTypeText[NetConTypeMaxNum] = {"Unknown", "DHCP", "STATIC", "PPPoE"};


void dumpLearnedInfo(void)
{
    INFO("PPPoE info, auth cnt=%d, username=[%s], passwd=[%s]",
        pppoeLearnInfo.pppoeProbe.peer_auth_count,
        pppoeLearnInfo.pppoeProbe.peer_auth_user, pppoeLearnInfo.pppoeProbe.peer_auth_passwd);
    INFO("ARP info, cnt=%d, src=("MAC_STR_FMT", "INET4_STR_FMT"), dest=("MAC_STR_FMT", "INET4_STR_FMT")",
        ipaddrLearnInfo.arpProbe.rx_count,
        MAC_STR(ipaddrLearnInfo.arpProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.ipAddr),
        MAC_STR(ipaddrLearnInfo.arpProbe.destMac), INET4_STR_ARGS(ipaddrLearnInfo.arpProbe.gwAddr));
    INFO("DHCP info, cnt=%d, src=("MAC_STR_FMT", "INET4_STR_FMT"), dest=("MAC_STR_FMT", "INET4_STR_FMT")",
        ipaddrLearnInfo.dhcpProbe.rx_count,
        MAC_STR(ipaddrLearnInfo.dhcpProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.dhcpProbe.ipAddr),
        MAC_STR(ipaddrLearnInfo.dhcpProbe.destMac), INET4_STR_ARGS(ipaddrLearnInfo.dhcpProbe.gwAddr));
    INFO("DNS info, cnt=%d, src=("MAC_STR_FMT", "INET4_STR_FMT"), "
        "dest=("MAC_STR_FMT"), dns=("INET4_STR_FMT", "INET4_STR_FMT")",
        ipaddrLearnInfo.dnsProbe.rx_count,
        MAC_STR(ipaddrLearnInfo.dnsProbe.srcMac), INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.ipAddr),
        MAC_STR(ipaddrLearnInfo.dnsProbe.destMac),
        INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.dns1Addr), INET4_STR_ARGS(ipaddrLearnInfo.dnsProbe.dns2Addr));

}

static uint8_t is_finish_learn_work = 0;
static void learnerTermHandler(int sig);
static void learnerTimeoutHandler(int sig);


int eventHandleInit(void)
{
    /* Create event selector */
    event_selector = Event_CreateSelector();
    if (!event_selector) {
	rp_fatal("Could not create EventSelector -- probably out of memory");
    }

    /* Set signal handlers for SIGTERM and SIGINT */
    if (Event_HandleSignal(event_selector, SIGTERM, learnerTermHandler) < 0 ||
	Event_HandleSignal(event_selector, SIGINT, learnerTermHandler) < 0) {
        ERR("Event_HandleSignal: %s", strerror(errno));
        fatalSys("Event_HandleSignal");
    }

    if (Event_HandleSignal(event_selector, SIGALRM, learnerTimeoutHandler) < 0) {
        ERR("Event_HandleSignal SIGALRM: %s", strerror(errno));
        fatalSys("Event_HandleSignal SIGALRM");
    }

    return 0;
}

int eventLoop(void)
{
    int i;

    for(;;) {
        i = Event_HandleEvent(event_selector);
        if (i < 0) {
            ERR("Event_HandleEvent: %s", strerror(errno));
            fatalSys("Event_HandleEvent");
        }
    }

    return 0;
}

static int eventHandleDeinit()
{
    //DBG("destroy event selector..");
    Event_DestroySelector(event_selector);

    return 0;
}

static void learnerTermHandler(int sig)
{
    if (is_finish_learn_work) {
        ERR("already finish learn work, sth error?");
        return;
    }
    is_finish_learn_work = 1;

    pppoeLearnerTermHandler(sig);
    pppoeLearnerDeinit();
    ipaddrLearnerDeinit();
    eventHandleDeinit();

    dumpLearnedInfo();

    if (sig == 0) {
        ERR("%s normal quit!\n", SERVER_NAME);
    } else {
        ERR("%s quit! (reason is user-kill, signal=%d)\n", SERVER_NAME, sig);
    }

    setCfgLearnState(learnStateFailed);

    ledControl(LedCtrlTypeOver);

    closelog();
    if (sig == 0) {
        exit(0);
    } else {
        exit(1);
    }

}


int learnerStopLearn(NetConType_t learnType)
{
    ERR("learned net %s info!", netConTypeText[learnType]);
    isLearnedConfig = 1;
    kill(getpid(), SIGALRM);
    return 0;
}

static void learnerTimeoutHandler(int sig)
{
    int ret;

    if (is_finish_learn_work) {
        ERR("already finish learn work, sth error?");
        return;
    }
    is_finish_learn_work = 1;

    if (sig == SIGALRM) {
        ERR("-----------------------------");
        ERR("--- pid %d: learn time(%d) is up! ---", getpid(), gLearnTime);
        ERR("-----------------------------");
    }

    pppoeLearnerTermHandler(sig);
    pppoeLearnerDeinit();
    ipaddrLearnerDeinit();
    eventHandleDeinit();

    ret = applyProbeNetConfig((sig != 0));

    if (sig == 0) {
        ERR("%s normal quit!\n", SERVER_NAME);
    } else {
        ERR("%s quit! (reason is %s, signal=%d)\n", SERVER_NAME,
            isLearnedConfig ? "learned-config" : "timeout", sig);
    }

    if (ret == 0) {
        ledControl(LedCtrlTypeOk);
    } else {
        ledControl(LedCtrlTypeFailed);
    }

    sleep(2);
    ledControl(LedCtrlTypeOver);

    closelog();

    if (ret == 0) {
        exit(0);
    } else {
        exit(1);
    }

}

int main(int argc, char *argv[])
{
    int arg_id = 0;
    char user_ifname[IFNAMSIZ+1] = {0};	/* Interface name */

    /* Initialize syslog */
    openlog(SERVER_NAME, LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(LOG_DEBUG));

    arg_id = 1;
    while (argc > arg_id) {
        if (strncmp(argv[arg_id], "-I", 2) == 0) {
            strcpy(user_ifname, argv[arg_id]+2);
        } else if (strcmp(argv[arg_id], "-d") == 0) {
            my_debug_level = LOG_DEBUG;
        } else if (strcmp(argv[arg_id], "-x") == 0) {
            g_is_print_hexdump = 1;
        } else if (strcmp(argv[arg_id], "-n") == 0) {
            g_apply_probe_config = 0;
        } else if (strncmp(argv[arg_id], "-t", 2) == 0) {
            int learnSeconds = atoi((char *)argv[arg_id] + 2);
            if (learnSeconds > 0 && learnSeconds <= MAX_CFG_LEARN_TIME) {
                gLearnTime = learnSeconds;
            } else {
                ERR("-t time, default %d, max=%d!", MAKE_A_DECISION_TIME, MAX_CFG_LEARN_TIME);
                return -1;
            }
        } else {
            goto PRINT_USAGE;
        }
        ++arg_id;
    }

    if (strlen(user_ifname) < 1)
    {
        ERR("Must set listen interface name! See the output of command 'ifconfig'.");
        goto PRINT_USAGE;
    }

    DBG("%s start up! Learn seconds=%d, listen interface=%s, dbg=%c (%d, %s), %s\n",
        SERVER_NAME, gLearnTime, user_ifname,
        LOG_LEVEL_CHAR[my_debug_level], my_debug_level,
        g_is_print_hexdump ? "dump pkt" : "-",
        g_apply_probe_config ? "will apply config" : "-");

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
    eventHandleInit();
    pppoeLearnerInit(user_ifname);
    ipaddrLearnerInit(user_ifname);

    ledControl(LedCtrlTypeStart);

    resetInterfacePhy();

    DBG("start learn..");
    alarm(gLearnTime);
    setCfgLearnState(learnStateLearning);

    eventLoop();

    learnerTimeoutHandler(0);

    return 0;

PRINT_USAGE:
    ERR("usage: %s\n"
        "\t -I(listen network interface name)\n"
        "\t -d(enable debug)\n"
        "\t -a(immediate apply config, default)\n"
        "\t -n(not apply config)\n"
        "\t -t(survey time, unit seconds, default %d, max %d)\n"
        "\t -h(show this usage)\n",
        argv[0], MAKE_A_DECISION_TIME, MAX_CFG_LEARN_TIME);
    ERR("example: %s -Ieth0 -t30", argv[0]);
    return -1;
}


