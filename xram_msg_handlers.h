/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#include "bl_xram_eth.h"
#include "msg_handlers.h"

int bl_handle_rx_data(struct bl_eth_device *dev, struct sk_buff *skb);

void bl_build_simple_cmd_msg(rnm_base_msg_t *msg, uint16_t cmd);
int bl_append_xram_hdr(struct bl_eth_device *dev, struct sk_buff *skb);
