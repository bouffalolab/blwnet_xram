/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "config.h"
#include "wifi.h"

#define BL_ETH_TX_TIMEOUT       (30 * HZ)

#define BL_NDEV_FLOW_CTRL_STOP      32
#define BL_NDEV_FLOW_CTRL_RESTART   16

#define BL_TXQ_NDEV_FLOW_CTRL 1

#define BL_STA_IFACE_IDX 0
#define BL_AP_IFACE_IDX 1

#define BL_DRV_NAME "blwnet"

// TODO move to dts
#define BL_IPC0_REG_ADDR 0x2000a800
#define BL_IPC2_REG_ADDR 0x30005000
#define BL_IPC_REG_LEN 64
#define BL_XRAM_ADDR 0x22020000
#define BL_XRAM_LEN (16 * 1024)

struct ipc_regs {
    u32 cpu1_ipc_iswr;  /* 0x00 */
    u32 cpu1_ipc_irsrr;
    u32 cpu1_ipc_icr;
    u32 cpu1_ipc_iusr;
    u32 cpu1_ipc_iucr;  /* 0x10 */
    u32 cpu1_ipc_ilslr;
    u32 cpu1_ipc_ilshr;
    u32 cpu1_ipc_isr;
    u32 cpu0_ipc_iswr;  /* 0x20 */
    u32 cpu0_ipc_irsrr;
    u32 cpu0_ipc_icr;
    u32 cpu0_ipc_iusr;
    u32 cpu0_ipc_iucr;  /* 0x30 */
    u32 cpu0_ipc_ilslr;
    u32 cpu0_ipc_ilshr;
    u32 cpu0_ipc_isr;
} __attribute__ ((packed));

struct xram_ring_info {
    u32 __iomem *read;
    u32 __iomem *write;
    u8 __iomem *buffer;
    u32 buffer_size;
};

struct bl_xram_netdev_priv {
    struct bl_eth_device *dev;
    size_t idx;
};

struct bl_xram_txrx_desc {
    struct sk_buff *cur_skb;
    size_t processed;
    size_t left;
};

#define BL_XRAM_DBG_STATS_TX 0
#define BL_XRAM_DBG_STATS_RX 1
#define BL_XRAM_DBG_STATS_STA 0
#define BL_XRAM_DBG_STATS_AP 1

struct bl_xram_dbg_stats {
    u64 xram_cmd_pkts[2];
    u64 xram_cmd_bytes[2];
    u64 xram_eth_pkts[2][2];
    u64 xram_eth_bytes[2][2];
};

struct bl_eth_device {
    struct ipc_regs __iomem *ipc0_regs;
    struct ipc_regs __iomem *ipc2_regs;
    uint8_t __iomem *xram;
    unsigned int irq;
    bool irq_requested;
    u8 net_ring_events;
    spinlock_t net_ring_events_lock;
    struct xram_ring_info tx_ring, rx_ring;
    bool reset;
    struct bl_xram_txrx_desc tx_desc, rx_desc;

    u8 status;
    struct net_device *net[2];
    struct rtnl_link_stats64 stats[2];
    u8 sta_mac[ETH_ALEN];
    u8 ap_mac[ETH_ALEN];
    bool mac_set;

    bool sta_connected;

    struct sk_buff_head tx_sk_list;
    struct sk_buff_head rx_sk_list;

    struct work_struct main_work;
    struct workqueue_struct *workqueue;

    struct dentry *debugfs_root;
    struct bl_xram_dbg_stats dbg_stats;
};

#define BL_UNMASK_IRQ(dev, bits) writel(bits, &dev->ipc2_regs->cpu0_ipc_iusr)
#define BL_MASK_IRQ(dev, bits) writel(bits, &dev->ipc2_regs->cpu0_ipc_iucr)

#define BL_NOTIFY_NET_EVENT(dev, event) writel(BL_M0_NET_EVENT_TO_RAW(event), &dev->ipc0_regs->cpu1_ipc_iswr)

enum xram_ring_event {
    EVENT_RESET,
    EVENT_WRITE,
    EVENT_READ,
    EVENT_MAX,
    EVENT_RESET_BIT = 1 << EVENT_RESET,
    EVENT_WRITE_BIT = 1 << EVENT_WRITE,
    EVENT_READ_BIT = 1 << EVENT_READ,
};

// TODO move to dts
#define BL_XRAM_RING_EVENT_MASK (0x7)
#define BL_D0_NET_IPI_IDX 1
#define BL_D0_NET_EVENT(raw_status) ((raw_status >> (EVENT_MAX * BL_D0_NET_IPI_IDX)) & BL_XRAM_RING_EVENT_MASK)
#define BL_M0_NET_IPI_IDX 1
#define BL_M0_NET_EVENT_TO_RAW(event) ((0x1 << event) << (EVENT_MAX * BL_M0_NET_IPI_IDX))

#define BL_NET_RING_TX_OFFSET       0x1348
#define BL_NET_RING_RX_OFFSET       0x0348
#define BL_NET_RING_TX_READ_OFFSET  0xc8
#define BL_NET_RING_TX_WRITE_OFFSET 0x88
#define BL_NET_RING_TX_BUF_SIZE     4088
#define BL_NET_RING_RX_READ_OFFSET  0x48
#define BL_NET_RING_RX_WRITE_OFFSET 0x108
#define BL_NET_RING_RX_BUF_SIZE     4088

typedef enum xram_net_dev_type {
    XRAM_NET_DEV_TYPE_WIFI = 0,
    XRAM_NET_DEV_TYPE_WIRED,
    XRAM_NET_DEV_TYPE_MAX
} xram_net_dev_type_t;

typedef enum xram_net_msg_type {
    XRAM_NET_MSG_TYPE_COMMAND,
    XRAM_NET_MSG_TYPE_FRAME,
    XRAM_NET_MSG_TYPE_SNIFFER_PKT,
} xram_net_msg_type_t;

#define XRAM_NET_HEADER ("\x72\x69\x6e\x67")

#pragma pack(push, 1)
typedef struct xram_net_data_hdr {
    uint32_t header; // should be named magic
    uint16_t type;   // LSB: major, of xram_net_msg_type_t
                     // MSB: minor, subtype, iface index, etc
    uint16_t flag;
    uint16_t len;
    uint16_t crc16;
} xram_net_data_hdr_t;
#pragma pack(pop)

#define XRAM_NET_DATA_TYPE_MAJOR(x) ((x)->type & 0xff)
#define XRAM_NET_DATA_TYPE_MINOR(x) ((x)->type >> 8)
#define XRAM_NET_DATA_TYPE_MAKE(major, minor) ((major) | (((minor) << 8) & 0xff00))
#define XRAM_NET_DATA_HDR_LEN (sizeof(xram_net_data_hdr_t))

#define XRAM_NET_DATA_FLAG_FRAG     (0x1 << 0)
#define XRAM_NET_DATA_FLAG_AP_FRAME (0x1 << 1)
#define XRAM_NET_DATA_FLAG_SNIFFER_FRAME (0x1 << 2)
#define XRAM_NET_DATA_IS_FRAG(flag) ((flag & XRAM_NET_DATA_FLAG_FRAG) == XRAM_NET_DATA_FLAG_FRAG)

#define BL_NEEDED_HEADROOM_LEN XRAM_NET_DATA_HDR_LEN

typedef enum {
    BL_SKB_CMD,
    BL_SKB_ETH_FRAME,
    BL_SKB_STA,
    BL_SKB_AP,
} bl_skb_type;

struct bl_skb_info {
    bl_skb_type type;
    bl_skb_type iface;
};
