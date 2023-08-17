/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/delay.h>

#include "version.h"
#include "main.h"
#ifdef BL_INTF_SDIO
#include "tty.h"
#endif

struct bl_device gl_dev;

int __init bl_mod_init(void)
{
    int ret;

    printk("Registering blwnet version %s\n", BL_WNET_VERSION);

    mutex_init(&gl_dev.mutex);

#ifdef BL_INTF_SDIO
    if ((ret = bl_tty_init())) {
        return ret;
    }
#endif
    if ((ret = bl_register_ctl_port()) != 0) {
        return ret;
    }

    return bl_register_eth_drv();
}

void __exit bl_mod_exit(void)
{
    mutex_lock(&gl_dev.mutex);
    gl_dev.status |= BL_DEVICE_STATUS_DRV_REMOVING;
    mutex_unlock(&gl_dev.mutex);
    bl_release_ctl_port();
    bl_unregister_eth_drv();
#ifdef BL_INTF_SDIO
    bl_tty_exit();
#endif
}

bool bl_card_ok(void)
{
    int nok = 0;
    if (!(gl_dev.status & BL_DEVICE_STATUS_CARD_PRESENT)) {
        ++nok;
    }
#if CARD_DEAD_CHECK
    if (gl_dev.status & BL_DEVICE_STATUS_CARD_DEAD) {
        ++nok;
    }
#endif
    if (gl_dev.status & BL_DEVICE_STATUS_CARD_REMOVING) {
        ++nok;
    }
    if (gl_dev.status & BL_DEVICE_STATUS_DRV_REMOVING) {
        ++nok;
    }
    return !nok;
}

module_init(bl_mod_init);
module_exit(bl_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("qwang <qwang@bouffalolab.com>");
MODULE_DESCRIPTION("Bouffalolab BL6XY net driver");
