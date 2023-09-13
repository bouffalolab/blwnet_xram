/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/of.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/debugfs.h>

#include "asm-generic/io.h"
#include "main.h"
#include "bl_xram_eth.h"
#include "xram_msg_handlers.h"
#include "ctl_port.h"

static int bl_eth_open(struct net_device *net)
{
    int retval = 0;
    struct bl_xram_netdev_priv *priv = netdev_priv(net);
    struct bl_eth_device *dev = priv->dev;
    (void)dev;

    return retval;
}

static int bl_eth_close(struct net_device *net)
{
    netif_carrier_off(net);
    netif_stop_queue(net);

    return 0;
}

static int bl_queue_skb(struct sk_buff *skb, struct bl_eth_device *dev, size_t idx)
{
    struct bl_skb_info *info = (struct bl_skb_info *)skb->cb;
    struct rtnl_link_stats64 *stats;

    info->type = BL_SKB_ETH_FRAME;
    if (idx == BL_AP_IFACE_IDX) {
        info->iface = BL_SKB_AP;
        stats = &dev->stats[BL_AP_IFACE_IDX];
    } else {
        info->iface = BL_SKB_STA;
        stats = &dev->stats[BL_STA_IFACE_IDX];
    }
    skb_queue_tail(&dev->tx_sk_list, skb);
    stats->tx_packets++;
    stats->tx_bytes += skb->len;

    if (skb_queue_len(&dev->tx_sk_list) > BL_NDEV_FLOW_CTRL_STOP) {
        dev->status |= BL_TXQ_NDEV_FLOW_CTRL;
        netif_stop_queue(dev->net[idx]);
    }

    return 0;
}

static int bl_eth_xmit(struct sk_buff *skb, struct net_device *net)
{
    struct bl_xram_netdev_priv *priv = netdev_priv(net);
    struct bl_eth_device *dev = priv->dev;
    size_t idx = priv->idx;

    skb_tx_timestamp(skb);
    bl_queue_skb(skb, dev, idx);

    queue_work(dev->workqueue, &dev->main_work);

    return NETDEV_TX_OK;
}

static void bl_eth_tx_timeout(struct net_device *net
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
        , unsigned int txqueue
#endif
)
{
    struct bl_xram_netdev_priv *priv = netdev_priv(net);
    struct bl_eth_device *dev = priv->dev;

    dev->stats[priv->idx].tx_errors++;
}

static
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
struct rtnl_link_stats64 *
#else
void
#endif
bl_get_stats64(struct net_device *net, struct rtnl_link_stats64 *stats)
{
    struct bl_xram_netdev_priv *priv = netdev_priv(net);
    struct bl_eth_device *dev = priv->dev;

    memcpy(stats, &dev->stats[priv->idx], sizeof(*stats));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
    return stats;
#endif
}

static const struct net_device_ops bl_eth_netdev_ops = {
    .ndo_open = bl_eth_open,
    .ndo_stop = bl_eth_close,
    .ndo_start_xmit = bl_eth_xmit,
    .ndo_tx_timeout = bl_eth_tx_timeout,
    .ndo_get_stats64 = bl_get_stats64,
};

static void bl_rx_data_process(struct bl_eth_device *dev)
{
    struct sk_buff *skb;

    while ((skb = skb_dequeue(&dev->rx_sk_list))) {
        bl_handle_rx_data(dev, skb);
    }
}

#define BL_GET_RING_HEAD(ring) readl((ring)->read)
#define BL_GET_RING_TAIL(ring) readl((ring)->write)
#define BL_GET_RING_BUF_SIZE(ring) ((ring)->buffer_size)
#define BL_SET_RING_HEAD(ring, pos) writel((pos), (ring)->read)
#define BL_SET_RING_TAIL(ring, pos) writel((pos), (ring)->write)

static inline ssize_t ring_used_size(struct xram_ring_info *ring)
{
    size_t head, tail, tlen;
    head = BL_GET_RING_HEAD(ring);
    tail = BL_GET_RING_TAIL(ring);
    tlen = BL_GET_RING_BUF_SIZE(ring);
    if (head >= tlen || tail >= tlen) {
        return -1;
    }
    return (tail - head + tlen) % tlen;
}

static inline ssize_t ring_free_size(struct xram_ring_info *ring)
{
    ssize_t used_size = ring_used_size(ring);
    if (used_size < 0) {
        return -1;
    }
    return BL_GET_RING_BUF_SIZE(ring) - used_size - 1;
}

// Write to ring buffer assuming there is enough free room
static void ring_write(struct bl_eth_device *dev, const u8 *buf, size_t len)
{
    struct xram_ring_info *ring = &dev->tx_ring;
    u32 buf_sz;
    size_t len1 = len, len2 = 0;
    u16 pos, new_pos;

    pos = BL_GET_RING_TAIL(ring);
    buf_sz = BL_GET_RING_BUF_SIZE(ring);
    new_pos = (pos + len) % buf_sz;
    if (new_pos < pos) {
        len1 = buf_sz - pos;
        len2 = len - len1;
    }
    memcpy_toio(ring->buffer + pos, buf, len1);
    memcpy_toio(ring->buffer, buf + len1, len2);
    BL_SET_RING_TAIL(ring, new_pos);
    BL_NOTIFY_NET_EVENT(dev, EVENT_WRITE);
}

// Read from ring buffer assuming there is enough used room
static void ring_read(struct bl_eth_device *dev, u8 *buf, size_t len)
{
    struct xram_ring_info *ring = &dev->rx_ring;
    u32 buf_sz;
    size_t len1 = len, len2 = 0;
    u16 pos, new_pos;

    pos = BL_GET_RING_HEAD(ring);
    buf_sz = BL_GET_RING_BUF_SIZE(ring);
    new_pos = (pos + len) % buf_sz;
    if (new_pos < pos) {
        len1 = buf_sz - pos;
        len2 = len - len1;
    }
    memcpy_fromio(buf, ring->buffer + pos, len1);
    memcpy_fromio(buf + len1, ring->buffer, len2);
    BL_SET_RING_HEAD(ring, new_pos);
    BL_NOTIFY_NET_EVENT(dev, EVENT_READ);
}

static void bl_reset_txrx(struct bl_eth_device *dev)
{
    struct bl_xram_txrx_desc *desc[2] = {&dev->tx_desc, &dev->rx_desc};
    size_t i;

    BL_SET_RING_HEAD(&dev->tx_ring, 0);
    BL_SET_RING_TAIL(&dev->tx_ring, 0);

    for (i = 0; i < 2; ++i) {
        struct bl_xram_txrx_desc *d = desc[i];
        if (d->cur_skb) {
            dev_kfree_skb_any(d->cur_skb);
            d->cur_skb = NULL;
        }

        d->processed = 0;
        d->left = 0;
    }

    dev->reset = true;
}

static void bl_submit_get_mac_cmd(struct bl_eth_device *dev)
{
    rnm_base_msg_t msg;

    if (dev->mac_set) {
        return;
    }
    bl_build_simple_cmd_msg(&msg, BF1B_CMD_GET_MAC_ADDR);
    bl_push_host2device_msg((uint8_t *)&msg, sizeof(msg));
}

static void xram_net_info_cvt(struct bl_eth_device *dev, const xram_net_data_hdr_t *hdr, struct bl_skb_info *info)
{
    size_t f_idx = BL_XRAM_DBG_STATS_RX;
    if (XRAM_NET_DATA_TYPE_MAJOR(hdr) == XRAM_NET_MSG_TYPE_COMMAND) {
        info->type = BL_SKB_CMD;
        dev->dbg_stats.xram_cmd_pkts[f_idx]++;
        dev->dbg_stats.xram_cmd_bytes[f_idx] += hdr->len;
    } else {
        info->type = BL_SKB_ETH_FRAME;
        if (hdr->flag & XRAM_NET_DATA_FLAG_AP_FRAME) {
            info->iface = BL_SKB_AP;
            dev->dbg_stats.xram_eth_pkts[f_idx][BL_XRAM_DBG_STATS_AP]++;
            dev->dbg_stats.xram_eth_bytes[f_idx][BL_XRAM_DBG_STATS_AP] += hdr->len;
        } else {
            info->iface = BL_SKB_STA;
            dev->dbg_stats.xram_eth_pkts[f_idx][BL_XRAM_DBG_STATS_STA]++;
            dev->dbg_stats.xram_eth_bytes[f_idx][BL_XRAM_DBG_STATS_STA] += hdr->len;
        }
    }
}

static void bl_read_progress(struct bl_eth_device *dev)
{
    struct bl_xram_txrx_desc *xfer = &dev->rx_desc;
    struct sk_buff *skb;
    ssize_t len;
    struct xram_ring_info *ring = &dev->rx_ring;

    if (!dev->reset) {
        return;
    }

    while (1) {
        len = ring_used_size(ring);
        if (len < 0) {
            BUG();
            break;
        }
        if (len == 0) {
            break;
        }

        if (xfer->cur_skb) {
            u8 *buf = xfer->cur_skb->data + xfer->processed;
            if (len >= xfer->left) {
                ring_read(dev, buf, xfer->left);
                skb_queue_tail(&dev->rx_sk_list, xfer->cur_skb);
                xfer->cur_skb = NULL;
                xfer->processed = 0;
                xfer->left = 0;
            } else {
                ring_read(dev, buf, len);
                xfer->processed += len;
                xfer->left -= len;
            }
        } else {
            xram_net_data_hdr_t hdr;
            struct bl_skb_info *info;

            if (!(len >= XRAM_NET_DATA_HDR_LEN)) {
                break;
            }
            ring_read(dev, (u8 *)&hdr, XRAM_NET_DATA_HDR_LEN);
            // TODO? more check
            if (memcmp(&hdr.header, XRAM_NET_HEADER, 4)) {
                pr_err("xram header magic wrong\n");
                break;
            }

            skb = dev_alloc_skb(hdr.len);
            if (!skb) {
                break;
            }
            skb_put(skb, hdr.len);
            info = (struct bl_skb_info *)skb->cb;
            xram_net_info_cvt(dev, &hdr, info);
            xfer->cur_skb = skb;
            xfer->processed = 0;
            xfer->left = hdr.len;
        }
    }
}

static void bl_write_progress(struct bl_eth_device *dev)
{
    struct bl_xram_txrx_desc *xfer = &dev->tx_desc;
    struct sk_buff *skb;
    ssize_t len;
    struct xram_ring_info *ring = &dev->tx_ring;

    if (!dev->reset) {
        return;
    }

    while (xfer->cur_skb || !skb_queue_empty(&dev->tx_sk_list)) {
        len = ring_free_size(ring);
        if (len < 0) {
            BUG();
            break;
        }
        if (len == 0) {
            break;
        }

        if (xfer->cur_skb) {
            const u8 *buf = xfer->cur_skb->data + xfer->processed;
            if (len >= xfer->left) {
                ring_write(dev, buf, xfer->left);
                dev_kfree_skb_any(xfer->cur_skb);
                xfer->cur_skb = NULL;
                xfer->processed = 0;
                xfer->left = 0;
            } else {
                ring_write(dev, buf, len);
                xfer->processed += len;
                xfer->left -= len;
            }
        } else {
            skb = skb_dequeue(&dev->tx_sk_list);
            if (!skb) {
                break;
            }
            if (bl_append_xram_hdr(dev, skb)) {
                dev_kfree_skb_any(skb);
                continue;
            }

            xfer->cur_skb = skb;
            xfer->processed = 0;
            xfer->left = skb->len;
        }
    }

    if (unlikely(dev->status & BL_TXQ_NDEV_FLOW_CTRL) && skb_queue_len(&dev->tx_sk_list) < BL_NDEV_FLOW_CTRL_RESTART) {
        dev->status &= ~BL_TXQ_NDEV_FLOW_CTRL;
        netif_wake_queue(dev->net[0]);
        netif_wake_queue(dev->net[1]);
    }
}

static void bl_process_net_ring_events(struct bl_eth_device *dev, u8 events)
{
    if (events & EVENT_RESET_BIT) {
        bl_reset_txrx(dev);
        BL_NOTIFY_NET_EVENT(dev, EVENT_RESET);
        bl_submit_get_mac_cmd(dev);
    }

    bl_read_progress(dev);
    bl_write_progress(dev);
}

static void bl_main_wq_hdlr(struct work_struct *work)
{
    struct bl_eth_device *dev = container_of(work, struct bl_eth_device, main_work);

    while (1) {
        u8 events;
        spin_lock_irq(&dev->net_ring_events_lock);
        events = dev->net_ring_events;
        dev->net_ring_events = 0;
        spin_unlock_irq(&dev->net_ring_events_lock);

        if (events == 0) {
            break;
        }

        bl_process_net_ring_events(dev, events);
    }

    bl_read_progress(dev);
    bl_write_progress(dev);

    bl_rx_data_process(dev);
}

static u32 bl_eth_ethtool_op_get_link(struct net_device *net)
{
    struct bl_xram_netdev_priv *priv = netdev_priv(net);
    struct bl_eth_device *dev = priv->dev;
    return netif_carrier_ok(dev->net[priv->idx]);
}

static const struct ethtool_ops ops = {
    .get_link = bl_eth_ethtool_op_get_link
};

static void free_netdevs(struct bl_eth_device *dev)
{
    int i;
    for (i = 0; i < 2; ++i) {
        if (dev->net[i]) {
            netif_carrier_off(dev->net[i]);
            netif_tx_stop_all_queues(dev->net[i]);
            unregister_netdev(dev->net[i]);
            free_netdev(dev->net[i]);
            dev->net[i] = NULL;
        }
    }
}

static struct net_device *init_netdev(struct bl_eth_device *dev, size_t idx)
{
    int ret;
    struct net_device *netdev = NULL;

    struct bl_xram_netdev_priv *priv;
    netdev = alloc_etherdev(sizeof(struct bl_xram_netdev_priv));
    if (!netdev) {
        goto err_alloc;
    }

    netdev->netdev_ops = &bl_eth_netdev_ops;
    netdev->watchdog_timeo = BL_ETH_TX_TIMEOUT;
    strcpy(netdev->name, "bleth%d");
    netdev->needed_headroom = BL_NEEDED_HEADROOM_LEN;
    netdev->ethtool_ops = &ops;

    priv = netdev_priv(netdev);
    priv->idx = idx;
    priv->dev = dev;

    if ((ret = register_netdev(netdev))) {
        goto err_register;
    }

    netif_carrier_off(netdev);
    netif_tx_stop_all_queues(netdev);

    return netdev;

err_register:
    free_netdev(netdev);
    netdev = NULL;
err_alloc:
    return NULL;
}

static int init_netdevs(struct bl_eth_device *dev)
{
    int i;

    for (i = 0; i < 2; ++i) {
        struct net_device *netdev = init_netdev(dev, i);
        if (netdev) {
            dev->net[i] = netdev;
        } else {
            free_netdevs(dev);
            return -1;
        }
    }

    return 0;
}

static irqreturn_t ipc_irq_handler(int irq, void *dev_id)
{
    struct bl_eth_device *dev = dev_id;
    u32 val;
    u8 events;

    val = readl(&dev->ipc2_regs->cpu0_ipc_irsrr);
    events = BL_D0_NET_EVENT(val);
    writel(val, &dev->ipc2_regs->cpu0_ipc_icr);

    spin_lock(&dev->net_ring_events_lock);
    dev->net_ring_events |= events;
    spin_unlock(&dev->net_ring_events_lock);

    queue_work(dev->workqueue, &dev->main_work);

    return IRQ_HANDLED;
}

static void bl_ipc_deinit(struct bl_eth_device *dev)
{
    BL_MASK_IRQ(dev, -1u);

    if (dev->ipc0_regs) {
        iounmap(dev->ipc0_regs);
        dev->ipc0_regs = NULL;
    }
    if (dev->ipc2_regs) {
        iounmap(dev->ipc2_regs);
        dev->ipc2_regs = NULL;
    }
    if (dev->xram) {
        iounmap(dev->xram);
        dev->xram = NULL;
    }
    if (dev->irq_requested) {
        free_irq(dev->irq, dev);
        dev->irq_requested = false;
    }
}

static int bl_ipc_init(struct bl_eth_device *dev)
{
    int ret;

    dev->net_ring_events = 0;
    spin_lock_init(&dev->net_ring_events_lock);
    if ((dev->ipc0_regs = ioremap(BL_IPC0_REG_ADDR, BL_IPC_REG_LEN)) == NULL) {
        goto err;
    }
    if ((dev->ipc2_regs = ioremap(BL_IPC2_REG_ADDR, BL_IPC_REG_LEN)) == NULL) {
        goto err;
    }
    if ((dev->xram = ioremap(BL_XRAM_ADDR, BL_XRAM_LEN)) == NULL) {
        goto err;
    }

    dev->tx_ring.read = (u32 *)(dev->xram + BL_NET_RING_TX_READ_OFFSET);
    dev->tx_ring.write = (u32 *)(dev->xram + BL_NET_RING_TX_WRITE_OFFSET);
    dev->tx_ring.buffer = dev->xram + BL_NET_RING_TX_OFFSET;
    dev->tx_ring.buffer_size = BL_NET_RING_TX_BUF_SIZE;

    dev->rx_ring.read = (u32 *)(dev->xram + BL_NET_RING_RX_READ_OFFSET);
    dev->rx_ring.write = (u32 *)(dev->xram + BL_NET_RING_RX_WRITE_OFFSET);
    dev->rx_ring.buffer = dev->xram + BL_NET_RING_RX_OFFSET;
    dev->rx_ring.buffer_size = BL_NET_RING_RX_BUF_SIZE;

    if ((ret = request_irq(dev->irq, ipc_irq_handler, 0, BL_DRV_NAME, dev))) {
        goto err;
    } else {
        BL_UNMASK_IRQ(dev, -1u);
        dev->irq_requested = true;
    }

    return 0;

err:
    bl_ipc_deinit(dev);
    return -ENOMEM;
}


static int stats_info(struct seq_file *s, void *data)
{
    struct bl_eth_device *dev = s->private;
    struct xram_ring_info *ring = &dev->tx_ring;
    struct bl_xram_dbg_stats *stats = &dev->dbg_stats;
    int i;

    for (i = 0; i < 2; ++i) {
        const char *dir = i == BL_XRAM_DBG_STATS_TX ? "TX" : "RX";
        seq_printf(s, "%s cmds %llu, %llu bytes\n", dir,
                stats->xram_cmd_pkts[i],
                stats->xram_cmd_bytes[i]);

        seq_printf(s, "%s STA frames %llu, %llu bytes\n"
                "%s AP frames %llu, %llu bytes\n",
                dir,
                stats->xram_eth_pkts[i][BL_XRAM_DBG_STATS_STA],
                stats->xram_eth_bytes[i][BL_XRAM_DBG_STATS_STA],
                dir,
                stats->xram_eth_pkts[i][BL_XRAM_DBG_STATS_AP],
                stats->xram_eth_bytes[i][BL_XRAM_DBG_STATS_AP]);
        seq_printf(s, "\n");
    }

    seq_printf(s, "\n");

    seq_printf(s, "TX ring read ptr %u, write ptr %u, used %zd, free %zd\n",
            BL_GET_RING_HEAD(ring),
            BL_GET_RING_TAIL(ring),
            ring_used_size(ring),
            ring_free_size(ring));
    ring = &dev->rx_ring;
    seq_printf(s, "RX ring read ptr %u, write ptr %u, used %zd, free %zd\n",
            BL_GET_RING_HEAD(ring),
            BL_GET_RING_TAIL(ring),
            ring_used_size(ring),
            ring_free_size(ring));
    return 0;
}

static int stats_info_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_info, inode->i_private);
}

static struct file_operations stats_info_fops = {
    .owner = THIS_MODULE,
    .open = stats_info_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};

static void bl_debugfs_init(struct bl_eth_device *dev)
{
    dev->debugfs_root = debugfs_create_dir(BL_DRV_NAME, NULL);
    if (!dev->debugfs_root)
        return;

    debugfs_create_file("stats_info", 0100, dev->debugfs_root, dev, &stats_info_fops);
}

static int bl_xram_eth_init(struct platform_device *pdev)
{
    int retval = -EINVAL;
    struct bl_eth_device *dev = NULL;

    if (platform_get_irq(pdev, 0) < 0) {
        return -EINVAL;
    }
    if ((dev = kcalloc(1, sizeof(*dev), GFP_KERNEL)) == NULL) {
        return -ENOMEM;
    }

    dev->irq = platform_get_irq(pdev, 0);

    dev->workqueue = alloc_workqueue("BL_WORK_QUEUE", WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
    if (!dev->workqueue) {
        retval = -ENOMEM;
        goto err_create_wkq;
    }
    INIT_WORK(&dev->main_work, bl_main_wq_hdlr);

    skb_queue_head_init(&dev->tx_sk_list);
    skb_queue_head_init(&dev->rx_sk_list);

    if ((retval = init_netdevs(dev))) {
        goto err_init_netdevs;
    }
    mutex_lock(&gl_dev.mutex);
    gl_dev.eth_dev = dev;
    mutex_unlock(&gl_dev.mutex);

    bl_debugfs_init(dev);

    if ((retval = bl_ipc_init(dev))) {
        goto err_ipc;
    }

    pr_info("BL eth attached\n");

    return 0;

err_ipc:
    free_netdevs(dev);
err_init_netdevs:
    destroy_workqueue(dev->workqueue);
err_create_wkq:
    kfree(dev);
    mutex_lock(&gl_dev.mutex);
    gl_dev.eth_dev = NULL;
    mutex_unlock(&gl_dev.mutex);

    return retval;
}

static int bl_xram_eth_deinit(struct platform_device *pdev)
{
    struct bl_eth_device *dev;

    mutex_lock(&gl_dev.mutex);
    dev = gl_dev.eth_dev;
    BL_MASK_IRQ(dev, -1u);

    disable_irq(dev->irq);

    flush_workqueue(dev->workqueue);
    destroy_workqueue(dev->workqueue);

    free_netdevs(dev);

    if (dev->debugfs_root)
        debugfs_remove_recursive(dev->debugfs_root);

    bl_reset_txrx(dev);

    bl_ipc_deinit(dev);

    skb_queue_purge(&dev->tx_sk_list);
    skb_queue_purge(&dev->rx_sk_list);

    kfree(dev);
    gl_dev.eth_dev = NULL;
    mutex_unlock(&gl_dev.mutex);

    pr_info("BL eth disconnected\n");

    return 0;
}

#ifdef CONFIG_OF
static const struct of_device_id bflb_ipc_match[] = {
    { .compatible = "bflb-ipc", },
    {},
};
MODULE_DEVICE_TABLE(of, bflb_ipc_match);
#endif

static struct platform_driver bflb_ipc_platform_driver = {
    .probe  = bl_xram_eth_init,
    .remove = bl_xram_eth_deinit,
    .driver = {
        .name = BL_DRV_NAME,
        .of_match_table = of_match_ptr(bflb_ipc_match),
    },
};

int bl_register_eth_drv(void)
{
    return platform_driver_register(&bflb_ipc_platform_driver);
}

void bl_unregister_eth_drv(void)
{
    platform_driver_unregister(&bflb_ipc_platform_driver);
}
