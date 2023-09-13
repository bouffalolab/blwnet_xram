##  Copyright (C) Bouffalo Lab 2016-2023
##  SPDX-License-Identifier: Apache-2.0

override CFLAGS += -DBUILD_USERSPACE -g
CC ?= gcc
AR ?= ar

.PHONY: all
all: blctl blctld

CTLLIB = libblctl.a

$(CTLLIB): blctl.o blctl_ota.o utils.o
	$(AR) rcu $@ $^

blctl.o: blctl.c blctl.h
	$(CC) $(CFLAGS) -c $< -o $@

blctl_ota.o: blctl_ota.c blctl.h
	$(CC) $(CFLAGS) -c $< -o $@

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c $< -o $@


blctl: blctl_main.o $(CTLLIB)
	$(CC) $(CFLAGS) $^ -o $@ -L. -lblctl -lpthread

blctl_main.o: blctl_main.c utils.h
	$(CC) $(CFLAGS) -c $< -o $@


blctld: blctld_main.o $(CTLLIB)
	$(CC) $(CFLAGS) $^ -o $@ -L. -lblctl -lpthread

blctld_main.o: blctld_main.c
	$(CC) $(CFLAGS) -c $< -o $@


.PHONY: clean
clean:
	rm -rf blctld blctl *.o
