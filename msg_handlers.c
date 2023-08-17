/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#include "msg_handlers.h"
#include "ctl_port.h"

static void handle_sta_ip_update_ind(struct bl_eth_device *dev, const void *data_ptr, const uint16_t data_len)
{
    struct net_device *net;
#ifndef BL_INTF_XRAM
    net = dev->net;
#else
    net = dev->net[BL_STA_IFACE_IDX];
#endif
    printk("Update IP\n");
    if (data_len != sizeof(rnm_sta_ip_update_ind_msg_t)) {
        BUG();
        return;
    }
    bl_notify_sta_ip(dev, (rnm_sta_ip_update_ind_msg_t *)data_ptr);
    netif_carrier_on(net);
    netif_wake_queue(net);
    dev->sta_connected = true;
#ifndef BL_INTF_XRAM
    dev->mode = BL_MODE_STA;
#endif
}

static void handle_ping(struct bl_eth_device *dev)
{
#if CARD_DEAD_CHECK
    dev->last_ping_recv_time = jiffies;
#endif
}

static bool forward_to_userspace_needed(rnm_base_msg_t *cmd)
{
    bool ret = false;

    if (cmd->flags & RNM_MSG_FLAG_ACK) {
        ret = true;
    }
    return ret;
}

void bl_handle_cmd(struct bl_eth_device *dev, const void *data_ptr, const uint16_t data_len)
{
    rnm_base_msg_t *cmd = (rnm_base_msg_t *)data_ptr;
    struct net_device *net_sta, *net_ap;
#ifdef BL_INTF_XRAM
    net_sta = dev->net[BL_STA_IFACE_IDX];
    net_ap = dev->net[BL_AP_IFACE_IDX];
#else
    net_sta = dev->net;
    net_ap = net_sta;
#endif

    if (!(data_len >= sizeof(*cmd))) {
        BUG();
        return;
    }
    switch (cmd->cmd) {
#ifdef BL_INTF_XRAM
    case BF1B_CMD_GET_MAC_ADDR:
        if (!dev->mac_set) {
            rnm_mac_addr_ind_msg_t *msg = (rnm_mac_addr_ind_msg_t *)cmd;
            memcpy(dev->sta_mac, msg->sta_mac, ETH_ALEN);
            memcpy(dev->ap_mac, msg->ap_mac, ETH_ALEN);
            bl_change_eth_mac(dev);
            dev->mac_set = true;
        }
        break;
#endif
    case BF1B_CMD_STA_CONNECTED_IND:
        netif_carrier_on(net_sta);
        netif_wake_queue(net_sta);
        dev->sta_connected = true;
        printk("Connected to AP\n");
        break;
    case BF1B_CMD_STA_DISCONNECTED_IND:
        if (dev->sta_connected == true) {
            dev->sta_connected = false;
            printk("Disconnected from AP\n");
            netif_carrier_off(net_sta);
            netif_stop_queue(net_sta);
            bl_notify_daemon_simple_event(dev, CTL_PORT_MSG_DISCONNECT);
        }
        break;
    case BF1B_CMD_STA_IP_UPDATE_IND:
        handle_sta_ip_update_ind(dev, data_ptr, data_len);
        break;
    case BF1B_CMD_AP_STARTED_IND:
        printk("AP started\n");
        netif_carrier_on(net_ap);
        netif_start_queue(net_ap);
        break;
    case BF1B_CMD_AP_STOPPED_IND:
        printk("AP stopped\n");
        netif_carrier_off(net_ap);
        netif_start_queue(net_ap);
        break;
    case BF1B_CMD_PING:
        handle_ping(dev);
        break;
    default:
        break;
    }
    if (forward_to_userspace_needed(cmd)) {
        bl_forward_cmd_to_userspace(cmd, data_len);
    }
}
