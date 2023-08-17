/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

#include "main.h"
#include "xram_msg_handlers.h"
#include "bl_xram_eth.h"
#include "xram_msgs.h"
#include "ctl_port.h"

void bl_build_simple_cmd_msg(rnm_base_msg_t *msg, uint16_t cmd)
{
    memset(msg, 0, sizeof(*msg));
    msg->cmd = cmd;
}

int bl_push_host2device_msg(const uint8_t *payload, size_t len)
{
    struct bl_eth_device *dev;
    struct sk_buff *skb = NULL;
    struct bl_skb_info *info;

    mutex_lock(&gl_dev.mutex);

    dev = gl_dev.eth_dev;
    if (!dev) {
        mutex_unlock(&gl_dev.mutex);
        return -1;
    }

    if (!(skb = alloc_skb(BL_NEEDED_HEADROOM_LEN + len, GFP_KERNEL))) {
        mutex_unlock(&gl_dev.mutex);
        return -ENOMEM;
    }
    skb_reserve(skb, BL_NEEDED_HEADROOM_LEN);
    skb_put(skb, len);
    skb_copy_to_linear_data(skb, payload, len);
    info = (struct bl_skb_info *)skb->cb;
    info->type = BL_SKB_CMD;

    skb_queue_tail(&dev->tx_sk_list, skb);

    queue_work(dev->workqueue, &dev->main_work);

    mutex_unlock(&gl_dev.mutex);

    return 0;
}

int bl_append_xram_hdr(struct bl_eth_device *dev, struct sk_buff *skb)
{
    int headroom;
    xram_net_data_hdr_t hdr;
    struct bl_skb_info *info;
    u8 major;
    size_t f_idx = BL_XRAM_DBG_STATS_TX;

    headroom = skb_headroom(skb) - BL_NEEDED_HEADROOM_LEN;

    if ((skb_header_cloned(skb) || headroom < 0) &&
         pskb_expand_head(skb, headroom < 0 ? -headroom : 0, 0, GFP_KERNEL)) {
        pr_err("%s: adjust failed\n", __func__);
        return -1;
    }

    info = (struct bl_skb_info *)skb->cb;
    memset(&hdr, 0, sizeof(hdr));
    memcpy(&hdr.header, XRAM_NET_HEADER, 4);
    hdr.len = skb->len;
    if (info->type == BL_SKB_CMD) {
        major = XRAM_NET_MSG_TYPE_COMMAND;
        dev->dbg_stats.xram_cmd_pkts[f_idx]++;
        dev->dbg_stats.xram_cmd_bytes[f_idx] += hdr.len;
    } else {
        major = XRAM_NET_MSG_TYPE_FRAME;
        if (info->iface == BL_SKB_AP) {
            hdr.flag = XRAM_NET_DATA_FLAG_AP_FRAME;
            dev->dbg_stats.xram_eth_pkts[f_idx][BL_XRAM_DBG_STATS_AP]++;
            dev->dbg_stats.xram_eth_bytes[f_idx][BL_XRAM_DBG_STATS_AP] += hdr.len;
        } else {
            dev->dbg_stats.xram_eth_pkts[f_idx][BL_XRAM_DBG_STATS_STA]++;
            dev->dbg_stats.xram_eth_bytes[f_idx][BL_XRAM_DBG_STATS_STA] += hdr.len;
        }
    }
    hdr.type = XRAM_NET_DATA_TYPE_MAKE(major, XRAM_NET_DEV_TYPE_WIFI);

    skb_push(skb, sizeof(hdr));
    skb_copy_to_linear_data(skb, &hdr, sizeof(hdr));

    return 0;
}

int bl_handle_rx_data(struct bl_eth_device *dev, struct sk_buff *skb)
{
    struct bl_skb_info *info = (struct bl_skb_info *)skb->cb;
    struct rtnl_link_stats64 *stats;

    if (info->type == BL_SKB_CMD) {
        bl_handle_cmd(dev, skb->data, skb->len);
        dev_kfree_skb_any(skb);
    } else if (info->type == BL_SKB_ETH_FRAME) {
        struct net_device *nd;
        if (info->iface == BL_SKB_STA) {
            nd = dev->net[BL_STA_IFACE_IDX];
            stats = &dev->stats[BL_STA_IFACE_IDX];
        } else {
            nd = dev->net[BL_AP_IFACE_IDX];
            stats = &dev->stats[BL_AP_IFACE_IDX];
        }
        skb->dev = nd;
        skb->protocol = eth_type_trans(skb, nd);
        stats->rx_packets++;
        stats->rx_bytes += skb->len;

        netif_rx(skb);
    } else {
        pr_warn("Unknown data type 0x%x\n", info->type);
        dev_kfree_skb_any(skb);
    }

    return 0;
}
