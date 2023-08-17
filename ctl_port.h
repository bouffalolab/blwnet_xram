/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef CTL_PORT_H_MFQCNVLT
#define CTL_PORT_H_MFQCNVLT

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/mutex.h>

#include "config.h"
#ifdef BL_INTF_SDIO
#include "bl_sdio_eth.h"
#elif defined(BL_INTF_USB)
#include "bl_usb_eth.h"
#elif defined(BL_INTF_XRAM)
#include "bl_xram_eth.h"
#endif
#include "rnm_msg.h"

#include "common.h"

#define CTL_PORT_SESSIONS 2

struct ctl_port_session {
    bool used;
    u32 pid;
    u16 session_id;
    u32 flags;
};

struct blctl_dev {
    struct mutex mutex;
    struct sock *nl_sock;
    struct ctl_port_session sessions[CTL_PORT_SESSIONS];
    u16 last_session_id;

    uint8_t read_buf[CTL_PORT_MSG_LEN_MAX];
};

int bl_register_ctl_port(void);
void bl_release_ctl_port(void);

int bl_notify_daemon_simple_event(struct bl_eth_device *dev, enum ctl_port_event event);
int bl_notify_sta_ip(struct bl_eth_device *dev, rnm_sta_ip_update_ind_msg_t *msg);
int bl_forward_cmd_to_userspace(rnm_base_msg_t *msg, size_t len);

#endif /* end of include guard: CTL_PORT_H_MFQCNVLT */
