# Trigger 6 protocol


## USB control endpoint commands

Commands are in the form of "0xXX, 0xYY", where "0xXX" is the bmRequestType
value, and "0xYY" is the bRequest value.

 * 0x40, 0x03: Set video output state
   * wValue: Video output index (0 or 1).
   * wIndex:
     * 0x0000: Disable video output
     * 0x0001: Enable video output
 * 0x40, 0x04: Set cursor position
   * wValue: Horizontal pixel position
   * wIndex: Vertical pixel position
 * 0x40, 0x05: Set cursor state
   * wValue: Cursor index, 0-9
   * wIndex:
     * 0x0000: Hidden
     * 0x0001: Visible
 * 0x40, 0x10: Upload cursor data
   * wValue: Cursor index, 0-9
   * wIndex: Byte offset into cursor data array.
   * wLength: N
   * Data: N bytes of 64x64-pixel cursor data in BGRA8888? or RGBA8888? format.
 * 0x40, 0x12: Set video mode
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
       * Response values:
         * 0: "Lite", 48 MHz base clock
         * 1: "Super Lite", 40 MHz base clock
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


## USB bulk endpoint

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


## USB interrupt endpoint

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


[t6img]: ../mct_t6img.ksy
