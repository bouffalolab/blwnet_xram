# blwnet_xram
Linux virtual Ethernet driver and utility enabling BL808 Linux to use on-chip Wi-Fi

## Overview
The entire software is mainly divided into two parts: M0 firmware and Linux software.
The M0 firmware runs the Wi-Fi protocol stack, providing a virtual Ethernet interface. The Linux software connects this Ethernet interface to the Linux system, utilizing the Wi-Fi functionality provided by M0.

blwnet_xram itself manages the Ethernet interface and command channel, and is divided into two parts: the kernel driver and the user-space control program.
The driver communicates downwards with M0 through shared memory and IPC, and communicates upwards with the user-space control program via netlink socket.

The driver will create two interfaces: bleth0 for STA (Station) and bleth1 for AP (Access Point). The program blctl is used for control, such as sending association and scan commands, among others.

At present, STA, AP and STA/AP mixed modes are supported.

## Get started
Documentation in this section and the one following is **deprecated** as blwnet_xram
is already integrated into [Bouffalo Buildroot](https://github.com/bouffalolab/buildroot_bouffalo).
However, the Wi-Fi usage guide remains important. Please use the buildroot to build all components.

This section provides a quick guide to experience Wi-Fi functionality. For instructions on compiling the related binary files, please refer to the next section.

1. Environment requirements
- Linux PC
- BL808 board with >= 8MB flash(tested: Sipeed M1S)

2. Download bl_iot_sdk
  ```bash
  git clone --recursive https://github.com/bouffalolab/bl_iot_sdk.git
  ```

3. Build M0 and D0 firmwares
  ```bash
  cd bl_iot_sdk/customer_app/bl808/bl808_demo_linux
  ./build_all
  ```
romfs/c906.bin and bl808_demo_linux.bin will be generated.

4. Burn bins to chip
- Open Bouffalo Lab Dev Cube, which can be obtained from https://dev.bouffalolab.com/download
- Select chip mode to BL808
- Refer to the diagram below for configuring the burning options.
![Alt text](doc/burn.png?raw=true "Burning options")
- Make BL808 enter flashing mode
- Click "Create & Download"

5. Reset BL808
- M0 firmware will boot Linux. Linux console should be available on D0 UART(PIN 16, 17).

6. Use Wi-Fi
- First load the kernel module
  ```bash
  insmod blwnet.ko
  ```
- Use blctl to send commands

  Scan
  ```bash
  ./blctl wifi_scan
  ```
  Obtain scan results
  ```bash
  ./blctl wifi_scan_results
  ```
  Connect to AP
  ```bash
  ./blctl connect_ap <ssid> [password]
  ```
  Once connected, obtain IP addresses via DHCP
  ```bash
  udhcpc -i bleth0
  ```
  Start AP
  ```bash
  [CHANNEL=chn] ./blctl start_ap <ssid> [password]
  ifconfig bleth1 192.169.99.1
  udhcpd udhcpd.conf # See userspace/udhcpd.conf for example
  ```
  How to act as a Wi-Fi gateway
  - Connect to AP and obtain IP address
  - Start AP using the same channel as connected AP
  - Enable IP forwarding, NAT:
  ```bash
  sysctl -w net.ipv4.ip_forward=1
  iptables -t nat -A POSTROUTING -s 192.169.99.0/24 -j MASQUERADE
  ```
  For more command options, see output of:
  ```bash
  ./blctl
  ```

## How to build bins
### hw.dtb
```bash
# hw808c.dts is located in bl_iot_sdk/customer_app/bl808/bl808_demo_linux
dtc -I dts -O dtb -o hw.dtb hw808c.dts
```

### OpenSBI & Kernel Image
Refer to https://github.com/bouffalolab/bl808_linux.


Main steps:

#### Kernel Image
```bash
cp c906.config .config
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- menuconfig # enter menuconfig, change nothing, save&exit
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- Image
xz --check=crc32 --lzma2=dict=32KiB -k arch/riscv/boot/Image
```
arch/riscv/boot/Image.xz will be generated.

#### OpenSBI
Note that PINMUX might need to be changed. See https://github.com/bouffalolab/bl808_linux/blob/main/patch/m1sdock/m1sdock_uart_pin_def.patch.

Kernel address is at 0x50200000: change FW_JUMP_ADDR in platform/thead/c910/config.mk.

### Kernel driver blwnet.ko and utility blctl
1. First make sure that you can build kernel image in the previous step
2. Make a complete build of kernel. This is crucial for building the out-of-tree kernel module.
```bash
cd bl808_linux/linux-5.10.4-808/
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -j
```
3. Build driver and utility
```bash
cd blwnet_xram
# Replace <kernel_dir> with kernel path in the previous step
make CONFIG_BL_INTF=XRAM KDIR=<kernel_dir> ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- CC=riscv64-unknown-linux-gnu-gcc AR=riscv64-unknown-linux-gnu-ar -j
```
blwnet.ko and userspace/blctl will be generated.

### rootfs.cpio.gz
Not available at the moment.

## Known issues
- Some blctl sub commands might not work. For example: OTA is not tested.
- Interface carrier state will be lost if set down and up manually.
- Linux clock may be far from accurate.
