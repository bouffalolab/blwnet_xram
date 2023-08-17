/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include "blctl.h"
#include "../common.h"

static blctl_handle_t ctl = NULL;
static struct ip_info ip_info;

static const char *shell_script;

static enum {
    EVENT_NONE,
    EVENT_CARD_INSERTED,
    EVENT_CARD_DEAD,
    EVENT_IP_UPDATE,
    EVENT_DISCONNECT,
} event = EVENT_NONE;

static int read_msg()
{
    int ret = 0;
    ctl_port_msg_hdr_t *hdr;
    ctl_port_msg_ip_update_t *ip_msg;

    ret = blctl_msg_recv(ctl, (void *)&hdr, 1000);
    if (ret) {
        return -1;
    }

    switch (hdr->type) {
    case CTL_PORT_MSG_CARD_INSERTED:
        event = EVENT_CARD_INSERTED;
        break;
    case CTL_PORT_MSG_CARD_DEAD:
        event = EVENT_CARD_DEAD;
        break;
    case CTL_PORT_MSG_DISCONNECT:
        event = EVENT_DISCONNECT;
        break;
    case CTL_PORT_MSG_IP_UPDATE:
        ip_msg = (ctl_port_msg_ip_update_t *)hdr;;
        event = EVENT_IP_UPDATE;
        memcpy(&ip_info, &ip_msg->ip_info, sizeof(ip_msg->ip_info));
        break;
    default:
        return -1;
    }
    return 0;
}

static int execute_script()
{
    char enva_buf[128];
    uint8_t *p;

    switch (event) {
    case EVENT_CARD_INSERTED:
        setenv("EVENT", "CARD_INSERTED", 1);
        break;
    case EVENT_CARD_DEAD:
        setenv("EVENT", "CARD_DEAD", 1);
        break;
    case EVENT_DISCONNECT:
        setenv("EVENT", "DISCONNECT", 1);
        break;
    case EVENT_IP_UPDATE:
        setenv("EVENT", "IP_UPDATE", 1);

        p = &ip_info.ip4_addr[0];
        snprintf(enva_buf, sizeof(enva_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        setenv("BF_IP", enva_buf, 1);

        p = &ip_info.ip4_mask[0];
        snprintf(enva_buf, sizeof(enva_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        setenv("BF_MASK", enva_buf, 1);

        p = &ip_info.ip4_gw[0];
        snprintf(enva_buf, sizeof(enva_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        setenv("BF_GW", enva_buf, 1);

        p = &ip_info.ip4_dns1[0];
        snprintf(enva_buf, sizeof(enva_buf), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        setenv("BF_DNS", enva_buf, 1);
        break;
    default:
        return -1;
        break;
    }

    system(shell_script);

    return 0;
}


static void daemonize()
{
    pid_t sid;
    pid_t pid;

    pid = fork();
    if (pid > 0) {
        exit(0);
    } else if (pid < 0) {
        exit(-1);
    }
    if ((sid = setsid()) < 0) {
        exit(-1);
    }

    pid = fork();
    if (pid > 0) {
        exit(0);
    } else if (pid < 0) {
        exit(-1);
    }

    chdir("/");
    umask(0);
}

static void exit_handler(void)
{
    blctl_deinit(ctl);
}

static void sig_handler(int signum)
{
    (void)signum;
    exit(0);
}

int main(int argc, char *argv[])
{
    int ret;

    if (!(argc == 2)) {
        fprintf(stderr, "Usage: %s <shell script>\n", *argv);
        exit(-1);
    }
    daemonize();
    shell_script = strdup(argv[1]);
    if (!shell_script) {
        fprintf(stderr, "mem alloc\n");
        exit(-1);
    }

    if ((ret = blctl_init2(&ctl, true))) {
        printf("init ret %d\r\n", ret);
        return 1;
    }
    atexit(exit_handler);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (1) {
        if (read_msg()) {
            continue;
        }
        execute_script();
    }
    return 0;
}
