/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#include "wifi.h"

#include <linux/etherdevice.h>
#include <linux/version.h>

#ifdef BL_INTF_SDIO
#include "bl_sdio_eth.h"
#elif defined(BL_INTF_USB)
#include "bl_usb_eth.h"
#elif defined(BL_INTF_XRAM)
#include "bl_xram_eth.h"
#endif

const char *bl_mode_to_str(const bl_wifi_mode_t mode)
{
    const char *str[] = {
        [BL_MODE_NONE]    = "NONE",
        [BL_MODE_STA]     = "STA",
        [BL_MODE_AP]      = "AP",
        [BL_MODE_STA_AP]  = "STA_AP",
        [BL_MODE_SNIFFER] = "SNIFFER",
        [BL_MODE_MAX]     = "UNKNOWN",
    };

    if (BL_MODE_NONE <= mode && mode < BL_MODE_MAX) {
        return str[mode];
    } else {
        return str[BL_MODE_MAX];
    }
}

int bl_mode_xfer(bl_wifi_mode_t *mode, const bl_wifi_mode_t new_mode, bl_wifi_mode_t *old_mode)
{
    int ret = 0;

    if (old_mode) {
        *old_mode = *mode;
    }
    if (new_mode == *mode) {
        goto exit;
    }
    if (*mode == BL_MODE_NONE) {
        *mode = new_mode;
    } else if (*mode == BL_MODE_STA) {
        *mode = new_mode;
    } else if (*mode == BL_MODE_AP) {
        *mode = new_mode;
    } else {
        ret = -1;
    }
exit:
    return ret;
}

void bl_change_eth_mac(void *dev)
{
    u8 *mac;
    struct bl_eth_device *d = dev;

#ifndef BL_INTF_XRAM
    mac = d->sta_mac;
    if (d->mode == BL_MODE_AP)
        mac = d->ap_mac;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
    eth_hw_addr_set(d->net, mac);
#else
    memcpy(d->net->dev_addr, mac, ETH_ALEN);
#endif
#else
    size_t i;
    for (i = 0; i < 2; ++i) {
        struct net_device *nd = d->net[i];
        if (i == BL_STA_IFACE_IDX) {
            mac = d->sta_mac;
        } else {
            mac = d->ap_mac;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
        eth_hw_addr_set(nd, mac);
#else
        memcpy(nd->dev_addr, mac, ETH_ALEN);
#endif
    }
#endif
}
