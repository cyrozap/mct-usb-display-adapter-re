# Reverse engineering notes


## Prior reverse engineering/driver development efforts

 * [DC11011100/jua365-driver: Reverse Engineering Effort for JUA365 (2x HDMI-to-USB 3.0 Adapter)][jua365-driver]
   * Unfortunately, the repo was taken offline at some point, and the Internet
     Archive only captured the landing page and not any of the source code or
     capture files.


## Protocol


### Trigger 5


#### Notes

 * Values are sometimes little-endian, other times big-endian.
 * Pixel positions and offsets are measured from the top left corner of the
   screen/image, and images are scanned out left-to-right, top-to-bottom.


#### USB control endpoint commands

Commands are in the form of "0xXX, 0xYY", where "0xXX" is the bmRequestType
value, and "0xYY" is the bRequest value.

 * 0x40, 0xc3: Set video mode/timings.
   * wValue: Index into the supported video modes array.
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
   * `5B`: Unknown, maybe something to do with the pixel clock frequency?
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
       * `<H`: Width in pixels.
       * `<H`: Height in pixels.
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


#### USB bulk endpoint

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


### Trigger 6


#### USB control endpoint commands

Commands are in the form of "0xXX, 0xYY", where "0xXX" is the bmRequestType
value, and "0xYY" is the bRequest value.

 * 0x40, 0x03: Enable/disable video output?
   * wIndex:
     * 0x0000: Disable video output?
     * 0x0001: Enable video output?
 * 0x40, 0x04: Set cursor position?
   * wValue: Horizontal pixel position?
   * wIndex: Vertical pixel position?
 * 0x40, 0x05: Set cursor visibility?
   * wIndex:
     * 0x0000: Hidden?
     * 0x0001: Visible?
 * 0x40, 0x10: Upload cursor data?
   * wIndex: Byte offset into cursor data array.
   * wLength: N
   * Data: N bytes of 64x64-pixel cursor data in BGRA8888? or RGBA8888? format.
 * 0x40, 0x12: Set video mode?
   * wLength: 32
 * 0x40, 0x23: Unknown.
   * wLength: 40
 * 0x40, 0x24: Unknown.
   * wLength: 16
 * 0x40, 0x30: Unknown.
 * 0x40, 0x31: Unknown.
 * 0xc0, 0x80: Get EDID block.
   * wValue: Byte offset.
   * wIndex: Video output index (0 or 1).
   * wLength: 128
 * 0xc0, 0x87: Get connector status.
   * wValue: Video output index (0 or 1).
   * wLength: 1
   * Return value:
     * 0x00: Disconnected.
     * 0x01: Connected.
 * 0xc0, 0x88: Unknown.
   * wLength: 1
 * 0xc0, 0x89: Get array of video modes supported by the chip.
   * wValue: Video output index (0 or 1).
   * wIndex: Byte offset.
   * wLength: 512
 * 0xc0, 0xa1: Unknown.
   * wIndex: Video output index (0 or 1)?
   * wLength: 16
 * 0xc0, 0xa2: Unknown.
   * wLength: 16
 * 0xc0, 0xa3: Unknown.
   * wLength: 40
 * 0xc0, 0xa4: Unknown.
   * wIndex: Video output index (0 or 1)?
   * wLength: 16
 * 0xc0, 0xa5: Get audio descriptor?
   * wLength: 32
 * 0xc0, 0xb0: Get adapter info field.
   * wIndex: Field number.
     * 0: "Hardware Platform" (`<I`).
     * 1: "Boot Code Version" (`<I`).
     * 2: "Image Code Version" (`<I`).
     * 3: "Project Code" (16 byte null-terminated string).
     * 4: "Vendor Command Version" (`<I`).
     * 5: "Serial Number" (length 8).
 * 0xc0, 0xb1: Get adapter session info?
   * wIndex: Session number.
     * 0: Video (length 132)?
     * 3: Audio (length 132)?
 * 0xc0, 0xb3: Get adapter DISP data?
   * wLength: 112
 * 0xc0, 0xb4: Unknown.
 * 0xc0, 0xcc: Unknown.
   * wValue: 1
   * wLength: 104


#### USB bulk endpoint

For each chunk of data you want to send to a virtual device ("session"), you
first send a 32-byte "select session" packet to select what session you want to
send the following packet to.

So for example, if you want to send 16-bit PCM data to the Audio session (number
3), you first send a "select session" packet to select session 3 and inform the
device how much data is being sent to the session, and then in the next packet
you send the raw PCM data (the length of which was specified in the "select
session" packet).

 * "Select Session" packet format:
   * `<I`: Session number.
     * 0: Video
     * 3: Audio
     * 5: Firmware update
   * `<I`: Total session payload length in bytes.
   * `<I`: Destination address?
     * 0x00000030 for uncompressed, 0x03000000 for JPEG?
     * Sending to 0x00000030 the address stays constant?
       * But then it becomes 0x00c55590?
   * `<I`: Length of the following data packet?
   * `<I`: Count of payload bytes written?
   * `<I`: Video output index?
   * `<I`: Unknown.
   * `<I`: Unknown.
 * Audio session data format:
   * N bytes: Raw dual-channel 16-bit little-endian signed PCM data.
 * Video session packet format:
   * `<I`: Packet type? Values seen: 3, 4, 7
   * `<I`: The length of the payload after this 0x30-byte header.
   * `<I`: Session sequence counter (starts at 1).
   * `<I`: Unknown. Values seen: 6, 9
   * `<H`: Height/width?
   * `<H`: Width/height?.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * `<I`: Unknown.
   * N bytes: JPEG image file.
     * Literally a full JPEG file, not just JPEG image data.
     * Length is specified in the "data length" field of the packet header.
 * Firmware update session data format:
   * N bytes: The the entire firmware image file, the format of which is
     specified in the [Kaitai Struct definition][t6img].


#### USB interrupt endpoint

Each packet is 64 bytes long.

 * `<I`: Packet type?
   * Values seen:
     * 0x04: Status change?
     * 0x20: Current state?
     * 0x80: Firmware update status?
 * `<I`: Unknown.
 * `<I`: Unknown.
 * `<I`: Packet counter? Increments by one with every 0x04-type packet received.
 * `<I`: Unknown.
   * Values seen:
     * Packet type 0x04: 0x01000000, 0x04000000
       * Flags?
         * Bit 25: Connector 1 status change.
         * Bit 24: Connector 0 status change.
     * Packet types 0x20, 0x80: 0x00000000
 * `<I`: Unknown.
 * `<I`: Unknown.
 * `<I`: Unknown.
 * `<I`: Unknown.
   * Values seen:
     * Packet types 0x04, 0x80: 0x00000000
     * Packet type 0x20: 0x02000000, 0x45000000
       * Flags?
         * Bit 30: Unknown.
         * Bit 26: Connector 1 status. (0: Disconnected, 1: Connected)
         * Bit 25: Connector 0 status. (0: Disconnected, 1: Connected)
         * Bit 24: Unknown.
 * `<I`: Unknown.
 * `<I`: Unknown.
 * `<I`: Unknown.
   * Values seen:
     * Packet types 0x04, 0x20: 0x00000000
     * Packet type 0x80: 0x05010000, 0x05010002, 0x05010003, 0x05010004
 * `<I`: Unknown.
   * Values seen:
     * Packet types 0x04, 0x20: 0x00000000
     * Packet type 0x80: 0x00010000 through 0x00120000, inclusive


[jua365-driver]: https://web.archive.org/web/20210328021458/https://github.com/DC11011100/jua365-driver
[t6img]: ../mct_t6img.ksy
