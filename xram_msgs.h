/*
 *  Copyright (C) Bouffalo Lab 2016-2023
 *  SPDX-License-Identifier: GPL-2.0-only
 */
#pragma once

#ifdef BUILD_USERSPACE
#include <stdbool.h>
#include <stdint.h>
#else
#include <linux/kernel.h>
#endif

#include "rnm_msg.h"
