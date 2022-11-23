#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "includes.h"
#include "attack.h"
#include "util.h"


void attack_parse(char *buf, int len, char *cncIpAddress)
{
    int i;
    uint32_t duration;
    ATTACK_VECTOR vector;
    char *strs[10] = {"UDP", "VSE", "DNS", "SYN", "ACK", "STOMP", "GREIP", "GREETH", "UDP_PLAIN", "HTTP"};
    
    uint8_t targs_len, opts_len;
    struct attack_target *targs = NULL;

    // Read in attack duration uint32_t
    if (len < sizeof (uint32_t))
        goto cleanup;
    duration = ntohl(*((uint32_t *)buf));
    buf += sizeof (uint32_t);
    len -= sizeof (uint32_t);

    // Read in attack ID uint8_t
    if (len == 0)
        goto cleanup;
    vector = (ATTACK_VECTOR)*buf++;
    len -= sizeof (uint8_t);

    // Read in target count uint8_t
    if (len == 0)
        goto cleanup;
    targs_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);
    if (targs_len == 0)
        goto cleanup;

    // Read in all targs
    if (len < ((sizeof (ipv4_t) + sizeof (uint8_t)) * targs_len))
        goto cleanup;
        
    FILE *fp;
    if ((fp = fopen("mirai_cnc.log", "a"))==NULL) {
        printf("He удается открыть файл.\n");
        exit(1);
    }
        
    targs = calloc(targs_len, sizeof (struct attack_target));
    for (i = 0; i < targs_len; i++)
    {
        targs[i].addr = *((ipv4_t *)buf);
        buf += sizeof (ipv4_t);
        
        
        ipv4_t ipaddr = targs[i].addr;
        char *str_targ;

        memset(str_targ, 0, sizeof(char) * 50);	
	sprintf(str_targ, "%d.%d.%d.%d", (ipaddr >> 24)&0xFF, (ipaddr >> 16)&0xFF, (ipaddr >> 8)&0xFF, (ipaddr)&0xFF);

        fprintf(fp, "%d:%s:%s:%" PRIu32 ":%s\n", (int)time(NULL), cncIpAddress, strs[vector], duration, str_targ);
        
        
        targs[i].netmask = (uint8_t)*buf++;
        len -= (sizeof (ipv4_t) + sizeof (uint8_t));

        targs[i].sock_addr.sin_family = AF_INET;
        targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
    }
    fclose(fp);

    // Read in flag count uint8_t
    if (len < sizeof (uint8_t))
        goto cleanup;
    opts_len = (uint8_t)*buf++;
    len -= sizeof (uint8_t);

    // Read in all opts
    if (opts_len > 0)
    {
        for (i = 0; i < opts_len; i++)
        {
            uint8_t val_len;

            // Read in key uint8
            if (len < sizeof (uint8_t))
                goto cleanup;
            buf++;
            len -= sizeof (uint8_t);

            // Read in data length uint8
            if (len < sizeof (uint8_t))
                goto cleanup;
            val_len = (uint8_t)*buf++;
            len -= sizeof (uint8_t);

            if (len < val_len)
                goto cleanup;
            buf += val_len;
            len -= val_len;
        }
    }

    errno = 0;

    // Cleanup
    cleanup:
    if (targs != NULL)
        free(targs);
}
