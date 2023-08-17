/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef MSG_HANDLERS_H_H6RXKLZN
#define MSG_HANDLERS_H_H6RXKLZN

#ifdef BL_INTF_SDIO
#include "bl_sdio_eth.h"
#elif defined(BL_INTF_USB)
#include "bl_usb_eth.h"
#elif defined(BL_INTF_XRAM)
#include "bl_xram_eth.h"
#endif

int bl_push_host2device_msg(const uint8_t *payload, size_t len);
void bl_handle_cmd(struct bl_eth_device *dev, const void *data_ptr, const uint16_t data_len);

#endif /* end of include guard: MSG_HANDLERS_H_H6RXKLZN */
