# Reverse engineering notes


## Prior reverse engineering/driver development efforts

 * [DC11011100/jua365-driver: Reverse Engineering Effort for JUA365 (2x HDMI-to-USB 3.0 Adapter)][jua365-driver]
   * This repo contains a USB packet capture of the proprietary driver querying
     a Trigger 6 device, as well as a prototype of a tool that is intended to
     replay captured USB data.
   * The prototype replay tool appears to only be able to find and open the
     device using libusb, and is missing the data replay functionality.


## Hardware/Firmware


### Trigger 5

 * Unknown 8-bit or 16-bit CPU
 * No firmware updates available.
 * Can't extract firmware without destroying device.


### Trigger 6

 * Andes NDS32 CPU
 * Firmware is based on the μC/OS-II RTOS.


## Protocol


 * [Trigger 5](Protocol-T5.md)
 * [Trigger 6](Protocol-T6.md)


[jua365-driver]: https://archive.softwareheritage.org/browse/origin/?origin_url=https://github.com/DC11011100/jua365-driver
