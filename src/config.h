#ifndef __CONFIG_H
#define __CONFIG_H


/*********************** User Set Macro ************************/

//#define PRINT_ALL_DEBUG             /* print all debug log */
#define PRINT_TO_CONSOLE    /* print to console, if not, only print to syslog */


/**************** Config Macro (DON'T EDIT!)********************/

#define SERVER_NAME "router_config_learning_tool"
extern int g_apply_probe_config;   /* should apply PPPoE account and ip config when we get it ?*/

#define ACCEPT_ALL_OPTION    /* accept peer all option */

#include <syslog.h>
/* priorities defined in syslog.h */
//#define LOG_EMERG       0       /* system is unusable */
//#define LOG_ALERT       1       /* action must be taken immediately */
//#define LOG_CRIT        2       /* critical conditions */
//#define LOG_ERR         3       /* error conditions */
//#define LOG_WARNING     4       /* warning conditions */
//#define LOG_NOTICE      5       /* normal but significant condition */
//#define LOG_INFO        6       /* informational */
//#define LOG_DEBUG       7       /* debug-level messages */

/* priorities defined in syslog.h */
#ifdef PRINT_ALL_DEBUG
#define MY_DEF_DEBUG_LEVEL LOG_DEBUG
#else
#define MY_DEF_DEBUG_LEVEL LOG_ERR
#endif


#define MAX_LOG_LEVEL (LOG_DEBUG+1)
char LOG_LEVEL_CHAR[MAX_LOG_LEVEL];
extern int my_debug_level;

#include <stdio.h>
#ifdef PRINT_TO_CONSOLE
#define DO_PRINT(type, fmt, ...) { \
    if (type <= my_debug_level && type >= 0) { \
        syslog(type, "%s-%d: "fmt"\n", __func__, __LINE__, ##__VA_ARGS__); \
        printf("%s %c %s-%d: "fmt"\n", SERVER_NAME, LOG_LEVEL_CHAR[type], __func__, __LINE__, ##__VA_ARGS__); \
    } \
}
#else
#define DO_PRINT(type, fmt, ...) { \
    if (type <= my_debug_level && type >= 0) { \
        syslog(type, "%s-%d: "fmt"\n", __func__, __LINE__, ##__VA_ARGS__); \
    } \
}
#endif


#define DBG(...) DO_PRINT(LOG_DEBUG, ##__VA_ARGS__)
#define INFO(...) DO_PRINT(LOG_INFO, ##__VA_ARGS__)
#define WARN(...) DO_PRINT(LOG_WARNING, ##__VA_ARGS__)
#define ERR(...) DO_PRINT(LOG_ERR, ##__VA_ARGS__)

extern char g_is_print_hexdump;
extern void hexdump(unsigned char *title, unsigned char *data, int data_len);

extern void fatalSys(char const *str);
extern void sysErr(char const *str);
extern void rp_fatal(char const *str);
extern void printErr(char const *str);

#define __packed __attribute__((__packed__))


#define LISTEN_INTERFACE_NAME "eth1"

#define MIN_ETH_BODY_SIZE 60 /* Exclude FCS */

#define DEFAULT_NETMASK_STR "255.255.255.0"

#define MAKE_A_DECISION_TIME 120

#define MAX_CFG_LEARN_TIME 300

/* copy from apmib.h */
//#define MIB_PPP_USER_NAME			106
//#define MIB_PPP_PASSWORD		107
//#define MIB_WAN_DHCP			104

/* Net connect type */
typedef enum {
    NetConTypeUnknown = 0,
    NetConTypeDHCP,
    NetConTypeStatic,
    NetConTypePPPoE,
    //NetConTypePPPoEStatic,
    NetConTypeMaxNum,
} NetConType_t;

extern const char *netConTypeText[NetConTypeMaxNum];

extern int learnerStopLearn(NetConType_t learnType);


/*********************** rp-pppoe config.h ******************************/
/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */
/* LIC: GPL */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#define HAVE_SYS_WAIT_H 1

/* Define to `int' if <sys/types.h> doesn't define.  */
/* #undef pid_t */

/* Define as the return type of signal handlers (int or void).  */
#define RETSIGTYPE void

/* Define if the setvbuf function takes the buffering type as its second
   argument and the buffer pointer as the third, as on System V
   before release 3.  */
/* #undef SETVBUF_REVERSED */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

#define HAVE_STRUCT_SOCKADDR_LL 1

/* The number of bytes in a unsigned int.  */
#define SIZEOF_UNSIGNED_INT 4

/* The number of bytes in a unsigned long.  */
#define SIZEOF_UNSIGNED_LONG 4

/* The number of bytes in a unsigned short.  */
#define SIZEOF_UNSIGNED_SHORT 2

/* Define if you have the select function.  */
#define HAVE_SELECT 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strtol function.  */
#define HAVE_STRTOL 1

/* Define if you have the <asm/types.h> header file.  */
#define HAVE_ASM_TYPES_H 1

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <getopt.h> header file.  */
#define HAVE_GETOPT_H 1

/* Define if you have the <linux/if_ether.h> header file.  */
#define HAVE_LINUX_IF_ETHER_H 1

/* Define if you have kernel-mode PPPoE in Linux file.  */
/* #undef HAVE_LINUX_KERNEL_PPPOE */

/* Define if you have the <linux/if_packet.h> header file.  */
#define HAVE_LINUX_IF_PACKET_H 1

/* Define if you have the <linux/if_pppox.h> header file.  */
/* #undef HAVE_LINUX_IF_PPPOX_H */
#define HAVE_LINUX_IF_PPPOX_H 1

/* Define if you have the <net/bpf.h> header file.  */
/* #undef HAVE_NET_BPF_H */

/* Define if you have the <net/if_arp.h> header file.  */
#define HAVE_NET_IF_ARP_H 1

/* Define if you have the <net/ethernet.h> header file.  */
#define HAVE_NET_ETHERNET_H 1

/* Define if you have the <net/if.h> header file.  */
#define HAVE_NET_IF_H 1

/* Define if you have the <linux/if.h> header file.  */
#define HAVE_LINUX_IF_H 1

/* Define if you have the <net/if_dl.h> header file.  */
/* #undef HAVE_NET_IF_DL_H */

/* Define if you have the <net/if_ether.h> header file.  */
/* #undef HAVE_NET_IF_ETHER_H */

/* Define if you have the <net/if_types.h> header file.  */
/* #undef HAVE_NET_IF_TYPES_H */

/* Define if you have the <netinet/if_ether.h> header file.  */
#define HAVE_NETINET_IF_ETHER_H 1

/* Define if you have the <netpacket/packet.h> header file.  */
#define HAVE_NETPACKET_PACKET_H 1

/* Define if you have the <sys/cdefs.h> header file.  */
#define HAVE_SYS_CDEFS_H 1

/* Define if you have the <sys/dlpi.h> header file.  */
/* #undef HAVE_SYS_DLPI_H */

/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1

/* Define if you have the <sys/param.h> header file.  */
#define HAVE_SYS_PARAM_H 1

/* Define if you have the <sys/socket.h> header file.  */
#define HAVE_SYS_SOCKET_H 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1

/* Define if you have the <sys/uio.h> header file.  */
#define HAVE_SYS_UIO_H 1

/* Define if you have the <syslog.h> header file.  */
#define HAVE_SYSLOG_H 1

/* Define if you have the <unistd.h> header file.  */
#define HAVE_UNISTD_H 1

/* Define if you have the N_HDLC line discipline in pty.h */
#define HAVE_N_HDLC 1

/* Define if bitfields are packed in reverse order */
#define PACK_BITFIELDS_REVERSED 1

/* Define to include debugging code */
#define DEBUGGING_ENABLED 1


/* Define various integer types -- assumes a char is 8 bits */
#if SIZEOF_UNSIGNED_SHORT == 2
typedef unsigned short UINT16_t;
#elif SIZEOF_UNSIGNED_INT == 2
typedef unsigned int UINT16_t;
#else
#error Could not find a 16-bit integer type
#endif

#if SIZEOF_UNSIGNED_SHORT == 4
typedef unsigned short UINT32_t;
#elif SIZEOF_UNSIGNED_INT == 4
typedef unsigned int UINT32_t;
#elif SIZEOF_UNSIGNED_LONG == 4
typedef unsigned long UINT32_t;
#else
#error Could not find a 32-bit integer type
#endif


#endif
