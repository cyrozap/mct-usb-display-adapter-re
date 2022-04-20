#!/usr/bin/env python3

import argparse
import itertools
import struct
import time

import usb


CONTROL_OUT = usb.util.CTRL_OUT | usb.util.CTRL_TYPE_VENDOR | usb.util.CTRL_RECIPIENT_DEVICE
CONTROL_IN = usb.util.CTRL_IN | usb.util.CTRL_TYPE_VENDOR | usb.util.CTRL_RECIPIENT_DEVICE


def checksum(data : bytes):
    return (-sum(data)) & 0xff

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--memory-dump-file", type=str, default="", help="If set, device memory will be dumped to the file named by this argument.")
    args = parser.parse_args()

    dev = usb.core.find(idVendor=0x0711, idProduct=0x5800)
    if dev is None:
        raise ValueError('Our device is not connected')

    # Check configuration.
    try:
        cfg = dev.get_active_configuration()
    except usb.core.USBError:
        cfg = None
    if cfg is None or cfg.bConfigurationValue != 1:
        dev.set_configuration(1)

    #dev.default_timeout = 3000

    # Get device info?
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa1, 0, 0, 512)).hex())
    print()

    # No idea.
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa7, 0, 0, 4)).hex())
    print()

    # Get list of video modes supported by the chip.
    modes = bytes(dev.ctrl_transfer(CONTROL_IN, 0xa4, 0, 0, 420))
    print(modes.hex())
    modes_count = struct.unpack_from('>H', modes, 0)[0]
    for i in range(modes_count):
        element = modes[4+8*i:4+8*(i+1)]
        refresh_rate, pixel_clk, bit_depth, index, height, width = struct.unpack('<BBBBHH', element)
        print("  {}: Mode {:>2}: {:>4} x {:>4} x {:>2} bits @ {:>3} fps, {:>3} Hz pixel clock".format(
            element.hex(), index, width, height, bit_depth, refresh_rate, pixel_clk))
    print()

    for i in range(6):
        # HPD/monitor presence
        print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa6, 0x00ff, 0x0003, 2)).hex())
    print()

    for i in range(4):
        # EDID page read
        print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa8, i, 0, 128)).hex())
    print()

    # Firmware reset.
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xd1, 0, 0, 1)).hex())
    print()

    # Set video timings.
    height = 1080
    width = 1920
    line_pixels = 2200
    line_sync_pulse = 44
    line_back_porch = 148
    frame_lines = 1125
    frame_sync_pulse = 5
    frame_back_porch = 36
    video_timings = struct.pack('>HH HHHHHH HHHHHH'.replace(' ',''),
            height, width,
            line_pixels-1, line_sync_pulse-1, line_back_porch-1, 256-1, 256-1, width-1,
            frame_lines-1, frame_sync_pulse-1, frame_back_porch-1, 256-1, 256-1, height-1,
            )
    video_timings += bytes.fromhex('012c1b28020000')
    assert video_timings == bytes.fromhex('043807800897002b009300ff00ff077f04640004002300ff00ff0437012c1b28020000')  # 1080p60
    #assert video_timings == bytes.fromhex('02d00500067f007f00bf00ff00ff04ff02eb0004001300ff00ff02cf012d2132040000')  # 720p60
    print(video_timings.hex())
    dev.ctrl_transfer(CONTROL_OUT, 0xc3, 15, 0, video_timings)
    print()

    # Firmware reset.
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xd1, 0x0201, 0, 1)).hex())
    print()

    # Get register value?
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa5, 0, 0xec34, 4)).hex())
    print()

    # Set register value?
    value = bytes.fromhex('60000010')
    dev.ctrl_transfer(CONTROL_OUT, 0xc4, 0, 0xec34, value)

    # Get register value?
    print(bytes(dev.ctrl_transfer(CONTROL_IN, 0xa5, 0, 0xec34, 4)).hex())
    print()

    # Disable cursor.
    dev.ctrl_transfer(CONTROL_OUT, 0xc4, 0, 0xe868, struct.pack('<I', 0x00000001))

    if args.memory_dump_file:
        print("Dumping memory...")
        memory = bytearray(struct.pack('>I', 0xdeaddead) * (0x10000//4))
        for addr in itertools.chain(range(0x0000, 0xa010, 4), range(0xa020, 0xb000, 4), range(0xc000, 0x10000, 4)):
            data_bytes = bytes(dev.ctrl_transfer(CONTROL_IN, 0xa5, 0, addr, 4))
            data_be = struct.unpack('>I', data_bytes)[0]
            data_le = struct.unpack('<I', data_bytes)[0]
            print("0x{:04x}: {:08x} (LE: 0x{:08x})".format(addr, data_be, data_le))
            struct.pack_into('>I', memory, addr, data_be)
        open(args.memory_dump_file, 'wb').write(memory)
        print("Done!")
        print()

    # Clear the image FIFO.
    payload = bytes(struct.pack('<I', (0 << 16) | (0 << 8) | 0)[:3] * width * height)
    for counter in range(3):
        # Write image data.
        header = struct.pack('<BBHHHHHIBBB', 0xfb, 0x14, (0 << 13) | (0 << 12) | counter, 0, 0, width, height, len(payload), 0x01, 0, 0)
        header += bytes([checksum(header)])
        bulk_data = header + payload
        dev.write(1, bulk_data)

    # Send keepalive command.
    dev.ctrl_transfer(CONTROL_IN, 0x91, 0x0002, 0, 1)

    # Upload cursor image. Cursor pixel format is BGRA32, not RGBA32.
    c_width = 64
    c_height = c_width
    c_x = (width-c_width)//2
    c_y = (height-c_height)//2
    payload = b''
    for j in range(c_height):
        for i in range(c_width):
            if i < c_width // 2:
                if i >= c_width // 4 and i < (3 * c_width) // 4 and j >= c_height // 4 and j < (3 * c_height) // 4:
                    # Red
                    payload += struct.pack('<I', (0xff//2 << 24) | (0xff << 16) | (0 << 8) | 0)
                else:
                    # Black
                    payload += struct.pack('<I', (0xff << 24) | (0 << 16) | (0 << 8) | 0)
            else:
                if i >= c_width // 4 and i < (3 * c_width) // 4 and j >= c_height // 4 and j < (3 * c_height) // 4:
                    # Blue
                    payload += struct.pack('<I', (0xff//2 << 24) | (0 << 16) | (0 << 8) | 0xff)
                else:
                    # White
                    payload += struct.pack('<I', (0xff << 24) | (0xff << 16) | (0xff << 8) | 0xff)
    header = struct.pack('<BBHHHHHIBBB', 0xfb, 0x14, (1 << 13) | (0 << 12) | 0, c_x, c_y, c_width, c_height, len(payload), 0x01, 1 << 4, 0)
    header += bytes([checksum(header)])
    bulk_data = header + payload
    dev.write(1, bulk_data)

    # Enable cursor.
    header = struct.pack('<BBHHHHHIBBB', 0xfb, 0x14, (1 << 13) | (0 << 12) | 1, c_x, c_y, c_width, c_height, 3 << 28, 0x01, 0x00, 0)
    header += bytes([checksum(header)])
    bulk_data = header
    dev.write(1, bulk_data)

    # Send images to the display.
    print("Running color cycle...")
    last_keepalive = time.monotonic_ns()
    counter = 0
    state = "IG"
    red = 255
    green = 0
    blue = 0
    speed = 5
    dx = speed
    dy = speed
    while True:
        dev.ctrl_transfer(CONTROL_OUT, 0xc8, c_x, c_y)

        payload = bytes(struct.pack('<I', (red << 16) | (green << 8) | blue)[:3] * width * height)
        header = struct.pack('<BBHHHHHIBBB', 0xfb, 0x14, (0 << 13) | (0 << 12) | counter, 0, 0, width, height, len(payload), 0x01, 0, 0)
        header += bytes([checksum(header)])
        bulk_data = header + payload

        # Write image data.
        dev.write(1, bulk_data)

        current_keepalive = time.monotonic_ns()
        if current_keepalive - last_keepalive > 2e9:
            # Send keepalive command.
            dev.ctrl_transfer(CONTROL_IN, 0x91, 0x0002, 0, 1)
            last_keepalive = current_keepalive

        # State machine for cycling through the hue.
        if state == "IG":
            green += 1
            if green == 255:
                state = "DR"
        elif state == "DR":
            red -= 1
            if not red:
                state = "IB"
        elif state == "IB":
            blue += 1
            if blue == 255:
                state = "DG"
        elif state == "DG":
            green -= 1
            if not green:
                state = "IR"
        elif state == "IR":
            red += 1
            if red == 255:
                state = "DB"
        else:
            blue -= 1
            if not blue:
                state = "IG"

        if c_x <= 0 or c_x >= width-c_width:
            dx = -dx
        if c_y <= 0 or c_y >= height-c_height:
            dy = -dy
        c_x += dx
        c_y += dy

        counter += 1
        counter &= 0xfff


if __name__ == "__main__":
    main()
