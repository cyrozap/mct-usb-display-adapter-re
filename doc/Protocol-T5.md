# Trigger 5 protocol


## Notes

 * Values are sometimes little-endian, other times big-endian.
 * Pixel positions and offsets are measured from the top left corner of the
   screen/image, and images are scanned out left-to-right, top-to-bottom.


## USB control endpoint commands

Commands are in the form of "0xXX, 0xYY", where "0xXX" is the bmRequestType
value, and "0xYY" is the bRequest value.

 * 0x40, 0xc3: Set video mode/timings.
   * wValue: Index into the supported video modes array.
   * wLength:
     * 0: Standard video mode.
     * 35: Custom video mode.
   * `>H`: Vertical resolution.
   * `>H`: Horizontal resolution.
   * `>H`: Line total pixels minus one.
   * `>H`: Line sync pulse minus one.
   * `>H`: Line back porch minus one.
   * `>H`: 255
   * `>H`: 255
   * `>H`: Horizontal resolution minus one.
   * `>H`: Frame total lines minus one.
   * `>H`: Frame sync pulse minus one.
   * `>H`: Frame back porch minus one.
   * `>H`: 255
   * `>H`: 255
   * `>H`: Vertical resolution minus one.
   * `5B`: Pixel clock PLL configuration.
     * `B`: Pre-divider
     * `B`: Multiplier 0
     * `B`: Multiplier 1
     * `B`: Divisor 0
     * `B`: Divisor 1 (must be a power of two)
     * Examples:
       * 01280a1904 (800x600, 1056x628, 40 MHz, hpol-p-vpol-p)
       * 01291a2904 (1024x768, 1344x806, 65 MHz, hpol-n-vpol-n)
       * 01270a1e02 (1024x768, 1344x806, 65 MHz, hpol-p-vpol-n)
       * 012d213204 (1280x720, 1664x748, 74 MHz, hpol-p-vpol-p)
       * 012d183202 (1280x1024, 1688x1066, 108 MHz, hpol-p-vpol-p)
       * 0131112302 (1680x1050, 1840x1080, 119 MHz, hpol-n-vpol-p)
       * 012d243202 (1600x1200, 2160x1250, 162 MHz, hpol-p-vpol-p)
       * 012c1b2802 (1920x1080, 2200x1125, 148 MHz, hpol-p-vpol-p)
   * `B`: Horizontal sync polarity.
     * 0: Positive
     * 1: Negative.
   * `B`: Vertical sync polarity.
     * 0: Positive
     * 1: Negative.
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
 * 0xc0, 0xa1: Get firmware info?
   * wLength: 512
   * Return value:
     * `B`: Version major?
     * `B`: Version minor?
     * `B`: Version patch?
     * `8B`: Unknown.
     * `B`: Year, starting at 2000.
     * `B`: Month.
     * `B`: Day.
 * 0xc0, 0xa4: Get array of video modes supported by the chip.
   * wLength: 420
   * Return value:
     * `>H`: Number of modes.
     * `2B`: Null padding bytes.
     * Array of N modes, where each mode has the form of:
       * `B`: Refresh rate in Hz.
       * `B`: Pixel clock in MHz.
       * `B`: Bits per pixel.
       * `B`: Mode number.
       * `<H`: Height in pixels.
       * `<H`: Width in pixels.
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
 * 0xc0, 0xa7: Get some flags?
   * wLength: 4
   * Returns 32-bit little-endian integer.
 * 0xc0, 0xa8: Get 128-byte EDID block.
   * wValue: Block number.
   * wLength: 128
   * Data only valid if monitor connected--otherwise just sends 128 bytes of
     data that were left in the USB buffer.
 * 0xc0, 0xd1: Firmware reset.
   * wValue: 0x0000, 0x0001, 0x0201
   * wLength: 1


## USB bulk endpoint

 * Seems to be used exclusively for sequences of display/data transfer
   commands.
 * Image data is compressed with an algorithm similar to JPEG.
   * Compressed output shows signs of DCT and blocking artifacts.
   * Blocks are 8x8 pixels.
   * Probably JPEG with a non-standard data encoding (no quantization or
     Huffman tables in the transmitted data).
 * Packet format:
   * `B`: Magic number identifying the start of the packet header: 0xfb
   * `B`: Header length, always 20 (0x14).
   * `<H`: Frame counter and packet flags.
     * Lower 12 bits: Frame counter. Increment by 1 for each frame to be
       displayed.
     * Upper 4 bits: Packet flags.
       * Bit 0: Compression enabled.
       * Bits 1-2: Bit depth.
         * 0: 24-bit
         * 1: 32-bit
         * 2: 16-bit
   * `<H`: Horizontal pixel offset info.
     * Lower 13 bits: Horizontal pixel offset.
     * Upper 3 bits: Unknown.
   * `<H`: Vertical pixel offset info.
     * Lower 13 bits: Vertical pixel offset.
     * Upper 3 bits: Unknown.
   * `<H`: Width info.
     * Lower 13 bits: Frame pixel width.
     * Upper 3 bits: Unknown.
   * `<H`: Height info.
     * Lower 13 bits: Frame pixel height.
     * Upper 3 bits: Unknown.
   * `<I`: Payload info.
     * Lower 28 bits: The length of the payload in bytes.
     * Upper 4 bits: Flags.
       * 0x3: Enable cursor.
       * 0x5: Disable cursor.
   * `B`: Other flags.
     * Bit 0: Unknown, must be set.
   * `B`: Unknown.
   * `B`: Unknown.
   * `B`: Header checksum.
     * To calculate the checksum, simply sum all the previous bytes (starting
       with the Magic), then negate that sum and take the lowest 8 bits.
   * N bytes: Packet payload.
     * The length and data format of this payload are specified in the header.
