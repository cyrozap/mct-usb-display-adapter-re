# Magic Control Technology (MCT) USB Display Adapter Reverse Engineering

Magic Control Technology Corporation (MCT, [website][mct]) is a Taiwanese
fabless semiconductor company that designs chips for use in computer peripherals
and multimedia equipment.

The targets of this reverse engineering effort are MCT's "Trigger 5" and
"Trigger VI" ("Trigger 6") USB-to-display adapters, the drivers for which only
support Windows and Mac OS. The goal of this project is to document the protocol
these chips use so a Linux driver can be written to support them and the display
adapters that use them.


## Reverse engineering notes

See [doc/Notes.md](doc/Notes.md).


## Quick start


### Software dependencies

* Python 3
* [PyUSB][pyusb]
* For parsing T6 firmware images:
  * [Kaitai Struct Compiler][ksc]
  * [Kaitai Struct Python Runtime][kspr]


### Procedure

1. Install dependencies.
2. Use `./test_t5.py` to replay some packets to the Trigger 5 dongle. This is
   work-in-progress research code and doesn't do much yet.


## Hardware info


### Trigger 5 devices

 * [StarTech USB32HDES][usb32hdes] / [j5create JUA254/JUA255][jua254]
   * MCT Trigger 5 T5-302
   * 16 MB RAM
   * HDMI output
     * 1080p60


### Trigger VI (Trigger 6) devices

 * [StarTech USB32DPES2][usb32dpes2]
   * MCT Trigger VI T6-688L
   * 64 MB RAM
   * DP output
     * 4k30
 * [StarTech USB32HD2][usb32hd2] / j5create [JUA365][jua365]/[JCA365][jca365]
   * MCT Trigger VI T6-688SL
   * 64 MB RAM
   * Silicon Image Sil9136-3
   * Dual HDMI outputs
     * 1x 4k30
     * 1x 1080p60
 * StarTech [USB32HD4][usb32hd4]/[USBC2HD4][usbc2hd4] / [j5create JCA366][jca366]
   * MCT Trigger VI T6-688SL
   * ITE IT66121
   * Quad HDMI outputs
     * 4x 1080p60


[mct]: https://mct.com.tw/
[pyusb]: https://github.com/pyusb/pyusb
[ksc]: https://github.com/kaitai-io/kaitai_struct_compiler
[kspr]: https://github.com/kaitai-io/kaitai_struct_python_runtime
[usb32hdes]: https://www.startech.com/en-us/audio-video-products/usb32hdes
[usb32dpes2]: https://www.startech.com/en-us/audio-video-products/usb32dpes2
[usb32hd2]: https://www.startech.com/en-us/audio-video-products/usb32hd2
[usb32hd4]: https://www.startech.com/en-us/audio-video-products/usb32hd4
[usbc2hd4]: https://www.startech.com/en-us/audio-video-products/usbc2hd4
[jua254]: https://en.j5create.com/products/jua254
[jua365]: https://en.j5create.com/products/jua365
[jca365]: https://en.j5create.com/products/jca365
[jca366]: https://en.j5create.com/products/jca366
