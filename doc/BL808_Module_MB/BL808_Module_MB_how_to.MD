## Get started
This section provides a quick guide to experience Wi-Fi functionality in BL808_Module_MB

1. Environment requirements
- Linux PC
- BL808_Module_MB

2. Download bl_iot_sdk
  ```bash
  git clone --recursive git@github.com:bouffalolab/bl_iot_sdk.git
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
- Set up the board according to the pictures below.
![Alt text](https://github.com/fangzheli/blwnet_xram/blob/BL808_Module_MB_doc/doc/BL808_Module_MB/BL808_Module_MB_setup1.jpg)
![Alt text](https://github.com/fangzheli/blwnet_xram/blob/BL808_Module_MB_doc/doc/BL808_Module_MB/BL808_Module_MB_setup2.jpg)
- Connect the board to PC according to the picture below.
![Alt text](https://github.com/fangzheli/blwnet_xram/blob/BL808_Module_MB_doc/doc/BL808_Module_MB/BL808_Module_MB_burn_setup.jpg)
- Make BL808 enter flashing mode
- Click "Create & Download"

5. Reset BL808
- M0 firmware will boot Linux. Linux console should be available on D0 UART(PIN 16, 17).
- Reconnect the board to PC as the running mode
- Connect the UART to serial port to PC according to the picture below.
![Alt text](doc/BL808_Module_MB/BL808_Module_MB_running_setup.jpg)
