# Trigger 2 protocol

## Notes

sisusb lists the VID/PID of Trigger 2 devices, but it doesn't probe.
```
sisusb 3-2:1.0: Invalid USB2VGA device
sisusb 3-2:1.0: probe with driver sisusb failed with error -22
```

## USB bulk endpoint commands

The commands are sent to 0x02, 0x03 and 0x04 OUT endpoints, any return value
is observed to be replied in the 0x81 endpoint. Endpoints 0x85 and 0x06 are
not observed to be used.

### 0x03 OUT endpoint:

 * 0x02: Write one byte to a register.
   * `>H`: Constant, 0x0001.
   * `>H`: 16-bit register address.
   * `B`: Register value.
   * Examples:
     * `020001feb043`: Write 0x43 to register 0xfeb0.
     * `020001fc2801`: Write 0x01 to register 0xfc28.
 * 0x04: Send a variable length list.
   * `<H`: Payload length N
   * N bytes: payload
 * 0x05: Read one byte from a register.
   * `<H`: 16-bit register address.
   * Return a 1 byte value on endpoint 0x81.
   * Examples:
     * `05b0fe`: Read register 0xfeb0.
     * `05a3fc`: Read register 0xfca3.
 * 0x0a: 768 bytes of zeroes
 * 0x16: Send a variable length list.
   * `<H`: Payload length N
   * N bytes: payload
 * 0x1b: Read EDID.
   * Sent: `1b8000a000800000`.
   * Returns 512 bytes on endpoint 0x81.
 * 0x1d: Device information?
   * Sent: `1d8000ae00000100`.
   * Returns 512 bytes on endpoint 0x81.
   * Contains VID/PID `07115200`.
 * 0x22: Some 62-byte register packet
 * 0x90: ?
 * 0x91: ?
   * Returns 512 bytes on endpoint 0x81.

### 0x04 OUT endpoint:

 * 0x05: Send a variable length list.
   * `<H`: Payload length N
   * N bytes: payload

### 0x02 OUT endpoint:

 * 0x11: Some form of buffer update
   * `<I`: Address or offset.
   * `<H`: Width / 4.
   * `<H`: Height / 4.
   * `<H`: Width.
   * `<H`: Height.
   * `<H`: 0x1000.
   * `<H`: 0x1000.
   * `B`: 0x04.
   * `<3B`: Payload length, width * height / 8.
   * N bytes: Zeroes.
 * 0x13: Send a compressed framebuffer update.
   * `<I`: Address-looking value
   * `<I`: Address-looking value, always same as above
   * `B`: Unknown, always zero.
   * `<H`: Width.
   * `<H`: Height rounded up to next multiple of 16.
   * `<H`: Width.
   * `<H`: Height rounded up to next multiple of 16.
   * `B`: Unknown, always zero.
   * `<H`: 0x0040.
   * `<H`: 0x0040.
   * `<I`: Unknown.
   * `<3B`: Width * height * 3.
   * `<3B`: Compressed payload length in bytes.
   * `3B`: Always `300528`.
   * N bytes: Compressed framebuffer payload.
 * 0x16: ?