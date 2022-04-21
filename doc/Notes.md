# Reverse engineering notes


## General info

Used in:
 * [StarTech USB32HDES][usb32hdes] / [j5create JUA254/JUA255][jua254]
   * MCT Trigger 5 T5-302
   * 16 MB RAM
   * HDMI output
     * 1080p60
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


## Protocol


### Trigger 5

 * Big-endian values, usually, but not always.
 * Pixel positions and offsets are measured from the top left corner of the
   screen/image, and images are scanned out left-to-right, top-to-bottom.
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
   * 0x40, 0xc8: Set cursor position.
     * wValue: X-position, in pixels.
     * wIndex: Y-position, in pixels.
   * 0xc0, 0x91: Keepalive (keep the display output active).
     * wValue: 0x0002
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
     * wValue: 0xff, unknown.
     * wIndex: 3, unknown.
     * Returns 1 if connected, 0 otherwise (16-bit value).
   * 0xc0, 0xa7: Get RAM size in kilobits?
   * 0xc0, 0xa8: Get 128-byte EDID page.
     * wValue: Page index.
     * wLength: 128
     * Data only valid if monitor connected--otherwise just sends 128 bytes of
       data that were left in the USB buffer.
   * 0xc0, 0xd1: Firmware reset.
     * wValue: 0x0000, 0x0001, 0x0201
     * wLength: 1
 * USB bulk endpoint:
   * Seems to be used exclusively for sequences of display/data transfer
     commands.
   * Image data is compressed with an algorithm similar to JPEG.
     * Compressed output shows signs of DCT and blocking artifacts.
     * Blocks are 8x8 pixels.
     * Probably JPEG with a non-standard data encoding (no quantization or
       Huffman tables in the transmitted data).
   * Packet format:
     * B: Magic number identifying the start of the packet header: 0xfb
     * B: Header length, always 20 (0x14).
     * <H: Frame counter and packet flags.
       * Lower 12 bits: Frame counter. Increment by 1 for each frame to be
         displayed.
       * Upper 4 bits: Packet flags.
         * Bit 0: Compression enabled.
         * Bits 1-2: Bit depth.
           * 0: 24-bit
           * 1: 32-bit
           * 2: 16-bit
     * <H: Horizontal pixel offset info.
       * Lower 13 bits: Horizontal pixel offset.
       * Upper 3 bits: Unknown.
     * <H: Vertical pixel offset info.
       * Lower 13 bits: Vertical pixel offset.
       * Upper 3 bits: Unknown.
     * <H: Width info.
       * Lower 13 bits: Frame pixel width.
       * Upper 3 bits: Unknown.
     * <H: Height info.
       * Lower 13 bits: Frame pixel height.
       * Upper 3 bits: Unknown.
     * <I: Payload info.
       * Lower 28 bits: The length of the payload in bytes.
       * Upper 4 bits: Flags.
         * 0x3: Enable cursor.
         * 0x5: Disable cursor.
     * B: Other flags.
       * Bit 0: Unknown, must be set.
     * B: Unknown.
     * B: Unknown.
     * B: Header checksum.
       * To calculate the checksum, simply sum all the previous bytes (starting
         with the Magic), then negate that sum and take the lowest 8 bits.
     * N bytes: Packet payload.
       * The length and data format of this payload are specified in the header.


### Trigger 6

TODO


[usb32hdes]: https://www.startech.com/en-us/audio-video-products/usb32hdes
[usb32dpes2]: https://www.startech.com/en-us/audio-video-products/usb32dpes2
[usb32hd2]: https://www.startech.com/en-us/audio-video-products/usb32hd2
[usb32hd4]: https://www.startech.com/en-us/audio-video-products/usb32hd4
[usbc2hd4]: https://www.startech.com/en-us/audio-video-products/usbc2hd4
[jua254]: https://en.j5create.com/products/jua254
[jua365]: https://en.j5create.com/products/jua365
[jca365]: https://en.j5create.com/products/jca365
[jca366]: https://en.j5create.com/products/jca366
