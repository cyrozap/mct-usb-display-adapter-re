# Reverse engineering notes


## General info

Used in:
 * [StarTech USB32HDES][usb32hdes]
   * MCT Trigger 5 T5-302
   * 16 MB RAM
   * HDMI output
     * 1080p60
 * [StarTech USB32DPES2][usb32dpes2]
   * MCT Trigger VI T6-688L
   * 64 MB RAM
   * DP output
     * 4k30
 * [StarTech USB32HD2][usb32hd2]
   * MCT Trigger VI T6-688SL
   * 64 MB RAM
   * Silicon Image Sil9136-3
   * Dual HDMI outputs
     * 1x 4k30
     * 1x 1080p60
 * StarTech [USB32HD4][usb32hd4]/[USBC2HD4][usbc2hd4]
   * MCT Trigger VI T6-688SL
   * ITE IT66121
   * Quad HDMI outputs
     * 4x 1080p60


## Protocol

 * Big-endian values, usually, but not always.
 * USB control endpoint commands (0xXX, 0xYY: bmRequestType, bRequest):
   * 0x40, 0xc3: Set video mode/timings.
     * wValue: Index into the supported video modes array.
     * >H: Vertical resolution.
     * >H: Horizontal resolution.
     * >H: Line total pixels minus one.
     * >H: Line sync pulse minus one.
     * >H: Line back porch minus one.
     * >H: 255
     * >H: 255
     * >H: Horizontal resolution minus one.
     * >H: Frame total lines minus one.
     * >H: Frame sync pulse minus one.
     * >H: Frame back porch minus one.
     * >H: 255
     * >H: 255
     * >H: Vertical resolution minus one.
     * 7B: Unknown, maybe something to do with the pixel clock frequency?
   * 0x40, 0xc4: Set 32-bit register value.
     * wIndex: Register address, aligned to 32-bit words (divisible by 4).
     * wLength: Number of bytes, always 4.
       * Writing fewer than 4 bytes results in the corruption of the next (4 -
         wLength) bytes.
   * 0x40, 0xc8: Set 32-bit register value?
     * wIndex: Register address?
   * 0xc0, 0x91: Unknown.
     * wValue: Unknown.
   * 0xc0, 0xa1: Get chip info?
     * wLength: 512
   * 0xc0, 0xa4: Get array of video modes supported by the chip.
     * wLength: 420
   * 0xc0, 0xa5: Read internal memory/MMIO registers.
     * wIndex: Memory address.
     * wLength: Number of bytes, 1-4.
     * Memory is byte-addressable, but reads will wrap at the word boundary.
       * e.g., if register 0xABCD is set to 0x12345678 (big-endian), and a
         4-byte read at 0xABD0 (0xABCD + 3) is performed, the data read back
	 will be 0x78123456 (big-endian).
   * 0xc0, 0xa6: Check if monitor is connected (HPD).
     * Returns 1 if connected, 0 otherwise (16-bit value).
   * 0xc0, 0xa7: Get RAM size in kilobits?
   * 0xc0, 0xa8: Get 128-byte EDID page.
     * wValue: Page index.
     * Data only valid if monitor connected--otherwise just sends 128 bytes of
       data that were left in the USB buffer.
   * 0xc0, 0xd1: Firmware reset.
     * wValue: 0x0000, 0x0001, 0x0201
     * wLength: 1
 * USB bulk endpoint:
   * Seems to be used exclusively for sequences of display/data transfer
     commands.
   * Image data is compressed with an unknown algorithm.


[usb32hdes]: https://www.startech.com/en-us/audio-video-products/usb32hdes
[usb32dpes2]: https://www.startech.com/en-us/audio-video-products/usb32dpes2
[usb32hd2]: https://www.startech.com/en-us/audio-video-products/usb32hd2
[usb32hd4]: https://www.startech.com/en-us/audio-video-products/usb32hd4
[usbc2hd4]: https://www.startech.com/en-us/audio-video-products/usbc2hd4
