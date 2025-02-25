// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_t5.c - Wireshark dissector for MCT's Trigger 5 protocol.
 *  Copyright (C) 2023-2024  Forest Crossman <cyrozap@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdint.h>

#include <epan/conversation.h>
#include <epan/dissectors/packet-usb.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/reassemble.h>

#include "proto_t5.h"


static const int CTRL_BREQ_OFFSET = 0;
static const int CTRL_WVAL_OFFSET = 1;
static const int CTRL_WIDX_OFFSET = 3;
static const int CTRL_WLEN_OFFSET = 5;
static const int CTRL_SETUP_DATA_OFFSET = 7;

typedef struct header_info_s {
    uint16_t frame_info;
    uint16_t horiz_offset;
    uint16_t vert_offset;
    uint16_t width;
    uint16_t height;
    uint32_t payload_len;
    uint32_t payload_flags;
} header_info_t;

typedef struct fragment_info_s {
    uint32_t header_fragment_frame_num;
    uint32_t fragment_offset;
    uint32_t fragment_len;
    uint32_t packet_len_remaining;
} fragment_info_t;

typedef struct bulk_conv_info_s {
    fragment_info_t * last_fragment_info;
    wmem_map_t * header_info_by_frame_num;
    wmem_map_t * fragment_info_by_frame_num;
} bulk_conv_info_t;

typedef struct static_range_s {
    unsigned nranges;
    range_admin_t ranges[1];
} static_range_t;

static const uint32_t MCT_USB_VID = 0x0711;

static const static_range_t MCT_USB_PID_RANGE = {
    .nranges = 1,
    .ranges = {
        { .low = (MCT_USB_VID << 16) | 0x5800, .high = (MCT_USB_VID << 16) | 0x581F },
    },
};

#define CTRL_REQ_C3 0xC3
#define CTRL_REQ_C4 0xC4
#define CTRL_REQ_C8 0xC8
#define CTRL_REQ_91 0x91
#define CTRL_REQ_A1 0xA1
#define CTRL_REQ_A4 0xA4
#define CTRL_REQ_A5 0xA5
#define CTRL_REQ_A6 0xA6
#define CTRL_REQ_A7 0xA7
#define CTRL_REQ_A8 0xA8
#define CTRL_REQ_D1 0xD1

static const value_string CONTROL_REQS[] = {
    { CTRL_REQ_C3, "Set video mode/timings" },
    { CTRL_REQ_C4, "Set 32-bit register value" },
    { CTRL_REQ_C8, "Set cursor position" },
    { CTRL_REQ_91, "Keepalive" },
    { CTRL_REQ_A1, "Get firmware info" },
    { CTRL_REQ_A4, "Get array of video modes supported by the chip" },
    { CTRL_REQ_A5, "Read internal memory/MMIO registers" },
    { CTRL_REQ_A6, "Check if monitor is connected (HPD)" },
    { CTRL_REQ_A7, "Get some flags?" },
    { CTRL_REQ_A8, "Get 128-byte EDID block" },
    { CTRL_REQ_D1, "Firmware reset" },
    { 0, NULL },
};

#define PIXEL_FMT_24_BIT 0
#define PIXEL_FMT_32_BIT 1
#define PIXEL_FMT_16_BIT 2
static const value_string PIXEL_FMTS[] = {
    { PIXEL_FMT_24_BIT, "24-bit" },
    { PIXEL_FMT_32_BIT, "32-bit" },
    { PIXEL_FMT_16_BIT, "16-bit" },
    { 0, NULL },
};

static const true_false_string tfs_sync_polarity = { "Negative", "Positive" };

static dissector_handle_t T5_HANDLE = NULL;

static reassembly_table T5_REASSEMBLY_TABLE = { 0 };

static int PROTO_T5 = -1;

static int HF_T5_CONTROL_REQ = -1;

static int HF_T5_CONTROL_REQ_WVAL = -1;
static int HF_T5_CONTROL_REQ_WIDX = -1;
static int HF_T5_CONTROL_REQ_WLEN = -1;
static int HF_T5_CONTROL_REQ_UNKNOWN_DATA = -1;

static int HF_T5_CONTROL_REQ_CURSOR_X = -1;
static int HF_T5_CONTROL_REQ_CURSOR_Y = -1;

static int HF_T5_CONTROL_REQ_EDID_BLOCK_NUMBER = -1;
static int HF_T5_CONTROL_REQ_EDID_BLOCK_DATA = -1;

static int HF_T5_CONTROL_REQ_FIRMWARE_VERSION = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MAJ = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MIN = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_VERSION_PATCH = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_UNKNOWN = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_DATE = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_DATE_YEAR = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_DATE_MONTH = -1;
static int HF_T5_CONTROL_REQ_FIRMWARE_DATE_DAY = -1;

static int HF_T5_CONTROL_REQ_REG_ADDR = -1;
static int HF_T5_CONTROL_REQ_REG_DATA = -1;

static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_COUNT = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_DATA = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_REFRESH_RATE_HZ = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_PIXEL_CLOCK_MHZ = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_BPP = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_MODE_NUM = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_WIDTH = -1;
static int HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_HEIGHT = -1;

static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_INDEX = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_TOTAL_PIXELS_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_SYNC_PULSE_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_BACK_PORCH_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_0 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_1 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_TOTAL_LINES_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_SYNC_PULSE_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_BACK_PORCH_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_2 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_3 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_PRE_DIV = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL0 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL1 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV0 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV1 = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_SYNC_POLARITY = -1;
static int HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_SYNC_POLARITY = -1;

static hf_register_info HF_T5_CONTROL[] = {
    { &HF_T5_CONTROL_REQ,
        { "Request type", "trigger5.control.request",
        FT_UINT8, BASE_HEX, VALS(CONTROL_REQS), 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_WVAL,
        { "wValue", "trigger5.control.wValue",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_WIDX,
        { "wIndex", "trigger5.control.wIndex",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_WLEN,
        { "wLength", "trigger5.control.wLength",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_UNKNOWN_DATA,
        { "Unknown data", "trigger5.control.unknown_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_CURSOR_X,
        { "Cursor X-position", "trigger5.control.cursor_x",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_CURSOR_Y,
        { "Cursor Y-position", "trigger5.control.cursor_y",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_EDID_BLOCK_NUMBER,
        { "EDID block number", "trigger5.control.edid.block_number",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_EDID_BLOCK_DATA,
        { "EDID block data", "trigger5.control.edid.block_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_VERSION,
        { "Firmware version", "trigger5.control.firmware_info.version",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MAJ,
        { "Major version?", "trigger5.control.firmware_info.version.major",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MIN,
        { "Minor version?", "trigger5.control.firmware_info.version.minor",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_VERSION_PATCH,
        { "Patch version?", "trigger5.control.firmware_info.version.patch",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_UNKNOWN,
        { "Unknown", "trigger5.control.firmware_info.unk",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_DATE,
        { "Firmware date", "trigger5.control.firmware_info.date",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_DATE_YEAR,
        { "Firmware year", "trigger5.control.firmware_info.version.year",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_DATE_MONTH,
        { "Firmware month", "trigger5.control.firmware_info.version.month",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_FIRMWARE_DATE_DAY,
        { "Firmware day", "trigger5.control.firmware_info.version.day",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_REG_ADDR,
        { "Register address", "trigger5.control.reg_addr",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_REG_DATA,
        { "Register data", "trigger5.control.reg_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_COUNT,
        { "Video modes count", "trigger5.control.get_video_modes.count",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_DATA,
        { "Video modes data", "trigger5.control.get_video_modes.data",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE,
        { "Video mode info", "trigger5.control.get_video_modes.video_mode",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_REFRESH_RATE_HZ,
        { "Refresh rate (Hz)", "trigger5.control.get_video_modes.video_mode.refresh_rate_hz",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_PIXEL_CLOCK_MHZ,
        { "Pixel clock (MHz)", "trigger5.control.get_video_modes.video_mode.pixel_clock_mhz",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_BPP,
        { "Bits per pixel", "trigger5.control.get_video_modes.video_mode.bpp",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_MODE_NUM,
        { "Mode number", "trigger5.control.get_video_modes.video_mode.number",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_HEIGHT,
        { "Height", "trigger5.control.get_video_modes.video_mode.height",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_WIDTH,
        { "Width", "trigger5.control.get_video_modes.video_mode.width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_INDEX,
        { "Video mode index", "trigger5.control.set_video_mode.index",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM,
        { "Custom video mode", "trigger5.control.set_video_mode.custom",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION,
        { "Vertical resolution", "trigger5.control.set_video_mode.custom.vertical_res",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION,
        { "Horizontal resolution", "trigger5.control.set_video_mode.custom.horizontal_res",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_TOTAL_PIXELS_MINUS_ONE,
        { "Line total pixels minus one", "trigger5.control.set_video_mode.custom.line_total_pixels_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_SYNC_PULSE_MINUS_ONE,
        { "Line sync pulse minus one", "trigger5.control.set_video_mode.custom.line_sync_pulse_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_BACK_PORCH_MINUS_ONE,
        { "Line back porch minus one", "trigger5.control.set_video_mode.custom.line_back_porch_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_0,
        { "Unknown 0", "trigger5.control.set_video_mode.custom.unk0",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_1,
        { "Unknown 1", "trigger5.control.set_video_mode.custom.unk1",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION_MINUS_ONE,
        { "Horizontal resolution minus one", "trigger5.control.set_video_mode.custom.horizontal_res_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_TOTAL_LINES_MINUS_ONE,
        { "Frame total lines minus one", "trigger5.control.set_video_mode.custom.frame_total_lines_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_SYNC_PULSE_MINUS_ONE,
        { "Frame sync pulse minus one", "trigger5.control.set_video_mode.custom.frame_sync_pulse_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_BACK_PORCH_MINUS_ONE,
        { "Frame back porch minus one", "trigger5.control.set_video_mode.custom.frame_back_porch_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_2,
        { "Unknown 2", "trigger5.control.set_video_mode.custom.unk2",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_3,
        { "Unknown 3", "trigger5.control.set_video_mode.custom.unk3",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION_MINUS_ONE,
        { "Vertical resolution minus one", "trigger5.control.set_video_mode.custom.vertical_res_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG,
        { "Pixel clock PLL configuration", "trigger5.control.set_video_mode.custom.pixel_clock_pll_config",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_PRE_DIV,
        { "Pre-divider", "trigger5.control.set_video_mode.custom.pll_config.pre_div",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL0,
        { "Multiplier 0", "trigger5.control.set_video_mode.custom.pll_config.mul0",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL1,
        { "Multiplier 1", "trigger5.control.set_video_mode.custom.pll_config.mul1",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV0,
        { "Divisor 0", "trigger5.control.set_video_mode.custom.pll_config.div0",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV1,
        { "Divisor 1", "trigger5.control.set_video_mode.custom.pll_config.div1",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_SYNC_POLARITY,
        { "Horizontal sync polarity", "trigger5.control.set_video_mode.custom.horizontal_sync_polarity",
        FT_BOOLEAN, BASE_DEC, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_SYNC_POLARITY,
        { "Vertical sync polarity", "trigger5.control.set_video_mode.custom.vertical_sync_polarity",
        FT_BOOLEAN, BASE_DEC, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
};

typedef struct field_sizes_s {
    int * hf;
    int size;
} field_sizes_t;

static const field_sizes_t set_video_mode_fields[] = {
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION, 2 },

    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_TOTAL_PIXELS_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_SYNC_PULSE_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_BACK_PORCH_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_0, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_1, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION_MINUS_ONE, 2 },

    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_TOTAL_LINES_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_SYNC_PULSE_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_BACK_PORCH_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_2, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_UNK_3, 2 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION_MINUS_ONE, 2 },

    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG, 5 },

    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_SYNC_POLARITY, 1 },
    { &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_SYNC_POLARITY, 1 },
};

static const field_sizes_t get_video_modes_mode_fields[] = {
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_REFRESH_RATE_HZ, 1 },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_PIXEL_CLOCK_MHZ, 1 },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_BPP, 1 },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_MODE_NUM, 1 },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_HEIGHT, 2 },
    { &HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE_WIDTH, 2 },
};

static int HF_T5_BULK_MAGIC = -1;
static int HF_T5_BULK_HEADER_LEN = -1;
static int HF_T5_BULK_FRAME_INFO = -1;
static int HF_T5_BULK_FRAME_INFO_UNK = -1;
static int HF_T5_BULK_FRAME_INFO_PIXEL_FMT = -1;
static int HF_T5_BULK_FRAME_INFO_COMPRESSION_ENABLED = -1;
static int HF_T5_BULK_FRAME_INFO_FRAME_COUNTER = -1;
static int HF_T5_BULK_H_OFFSET = -1;
static int HF_T5_BULK_V_OFFSET = -1;
static int HF_T5_BULK_WIDTH = -1;
static int HF_T5_BULK_HEIGHT = -1;
static int HF_T5_BULK_PAYLOAD_INFO = -1;
static int HF_T5_BULK_PAYLOAD_FLAGS = -1;
static int HF_T5_BULK_PAYLOAD_LEN = -1;
static int HF_T5_BULK_OTHER_FLAGS = -1;
static int HF_T5_BULK_HEADER_CHECKSUM = -1;
static int HF_T5_BULK_PAYLOAD_FRAGMENT = -1;
static int HF_T5_BULK_REASSEMBLED_PAYLOAD = -1;

static hf_register_info HF_T5_BULK[] = {
    { &HF_T5_BULK_MAGIC,
        { "Header magic", "trigger5.bulk.magic",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_HEADER_LEN,
        { "Header length", "trigger5.bulk.header_len",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAME_INFO,
        { "Frame info", "trigger5.bulk.frame_info",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAME_INFO_UNK,
        { "Unknown flag", "trigger5.bulk.frame_info.unk",
        FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAME_INFO_PIXEL_FMT,
        { "Pixel format", "trigger5.bulk.frame_info.pixel_fmt",
        FT_UINT16, BASE_DEC, VALS(PIXEL_FMTS), 0x6000, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAME_INFO_COMPRESSION_ENABLED,
        { "Compression enabled", "trigger5.bulk.frame_info.compression_enabled",
        FT_BOOLEAN, 16, NULL, 0x1000, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAME_INFO_FRAME_COUNTER,
        { "Frame counter", "trigger5.bulk.frame_info.counter",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0FFF, NULL, HFILL }
    },
    { &HF_T5_BULK_H_OFFSET,
        { "Horizontal offset", "trigger5.bulk.horizontal_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x1FFF, NULL, HFILL }
    },
    { &HF_T5_BULK_V_OFFSET,
        { "Vertical offset", "trigger5.bulk.vertical_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x1FFF, NULL, HFILL }
    },
    { &HF_T5_BULK_WIDTH,
        { "Width", "trigger5.bulk.width",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x1FFF, NULL, HFILL }
    },
    { &HF_T5_BULK_HEIGHT,
        { "Height", "trigger5.bulk.height",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x1FFF, NULL, HFILL }
    },
    { &HF_T5_BULK_PAYLOAD_INFO,
        { "Payload info", "trigger5.bulk.payload_info",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_PAYLOAD_FLAGS,
        { "Payload flags", "trigger5.bulk.payload_info.flags",
        FT_UINT32, BASE_HEX, NULL, 0xF0000000, NULL, HFILL }
    },
    { &HF_T5_BULK_PAYLOAD_LEN,
        { "Payload length", "trigger5.bulk.payload_info.len",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0FFFFFFF, NULL, HFILL }
    },
    { &HF_T5_BULK_OTHER_FLAGS,
        { "Other flags", "trigger5.bulk.other_flags",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_HEADER_CHECKSUM,
        { "Header checksum", "trigger5.bulk.header_checksum",
        FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_PAYLOAD_FRAGMENT,
        { "Payload fragment", "trigger5.bulk.payload_fragment",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_BULK_REASSEMBLED_PAYLOAD,
        { "Reassembled payload", "trigger5.bulk.reassembled_payload",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
};

static int HF_T5_BULK_FRAGMENTS = -1;
static int HF_T5_BULK_FRAGMENT = -1;
static int HF_T5_BULK_FRAGMENT_OVERLAP = -1;
static int HF_T5_BULK_FRAGMENT_OVERLAP_CONFLICTS = -1;
static int HF_T5_BULK_FRAGMENT_MULTIPLE_TAILS = -1;
static int HF_T5_BULK_FRAGMENT_TOO_LONG_FRAGMENT = -1;
static int HF_T5_BULK_FRAGMENT_ERROR = -1;
static int HF_T5_BULK_FRAGMENT_COUNT = -1;
static int HF_T5_BULK_REASSEMBLED_IN = -1;
static int HF_T5_BULK_REASSEMBLED_LENGTH = -1;

static int ETT_T5_BULK_FRAGMENT = -1;
static int ETT_T5_BULK_FRAGMENTS = -1;

static const fragment_items T5_BULK_FRAG_ITEMS = {
    &ETT_T5_BULK_FRAGMENT,
    &ETT_T5_BULK_FRAGMENTS,
    &HF_T5_BULK_FRAGMENTS,
    &HF_T5_BULK_FRAGMENT,
    &HF_T5_BULK_FRAGMENT_OVERLAP,
    &HF_T5_BULK_FRAGMENT_OVERLAP_CONFLICTS,
    &HF_T5_BULK_FRAGMENT_MULTIPLE_TAILS,
    &HF_T5_BULK_FRAGMENT_TOO_LONG_FRAGMENT,
    &HF_T5_BULK_FRAGMENT_ERROR,
    &HF_T5_BULK_FRAGMENT_COUNT,
    &HF_T5_BULK_REASSEMBLED_IN,
    &HF_T5_BULK_REASSEMBLED_LENGTH,
    NULL,
    "Packet fragments",
};

static hf_register_info HF_T5_BULK_FRAG[] = {
    { &HF_T5_BULK_FRAGMENTS,
        { "Packet fragments", "trigger5.bulk.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT,
        { "Packet fragment", "trigger5.bulk.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_OVERLAP,
        { "Packet fragment overlap", "trigger5.bulk.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_OVERLAP_CONFLICTS,
        { "Packet fragment overlapping with conflicting data", "trigger5.bulk.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_MULTIPLE_TAILS,
        { "Packet has multiple tail fragments", "trigger5.bulk.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_TOO_LONG_FRAGMENT,
        { "Packet fragment too long", "trigger5.bulk.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_ERROR,
        { "Packet defragmentation error", "trigger5.bulk.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_FRAGMENT_COUNT,
        { "Packet fragment count", "trigger5.bulk.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_REASSEMBLED_IN,
        { "Reassembled in", "trigger5.bulk.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T5_BULK_REASSEMBLED_LENGTH,
        { "Reassembled length", "trigger5.bulk.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
};

static int ETT_T5 = -1;
static int ETT_T5_FIRMWARE_VERSION = -1;
static int ETT_T5_FIRMWARE_DATE = -1;
static int ETT_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM = -1;
static int ETT_T5_VIDEO_MODE_PLL_CONFIG = -1;
static int ETT_T5_VIDEO_MODES = -1;
static int ETT_T5_VIDEO_MODE_INFO = -1;
static int ETT_T5_BULK_FRAME_INFO = -1;
static int * const ETT[] = {
    &ETT_T5,
    &ETT_T5_FIRMWARE_VERSION,
    &ETT_T5_FIRMWARE_DATE,
    &ETT_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM,
    &ETT_T5_VIDEO_MODE_PLL_CONFIG,
    &ETT_T5_VIDEO_MODES,
    &ETT_T5_VIDEO_MODE_INFO,
    &ETT_T5_BULK_FRAME_INFO,
    &ETT_T5_BULK_FRAGMENT,
    &ETT_T5_BULK_FRAGMENTS,
};

static expert_field EI_T5_BULK_HEADER_CHECKSUM_INVALID = EI_INIT;

static ei_register_info EI_T5_BULK[] = {
    { &EI_T5_BULK_HEADER_CHECKSUM_INVALID,
        { "trigger5.bulk.header_checksum_invalid", PI_CHECKSUM, PI_WARN,
            "Header checksum is invalid", EXPFILL }
    },
};

static uint8_t bulk_header_checksum(const uint8_t *buf, uint32_t len) {
    int32_t checksum = 0;

    for (size_t i = 0; i < len; i++) {
        checksum += buf[i];
    }

    return (-checksum) & 0xFF;
}

static uint8_t bulk_header_checksum_tvb_offset(tvbuff_t *tvb, uint32_t offset, uint32_t len) {
    tvb_ensure_bytes_exist(tvb, offset, len);
    const uint8_t * buf = tvb_get_ptr(tvb, offset, len);

    return bulk_header_checksum(buf, len);
}

static int handle_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, urb_info_t *urb) {
    bool in_not_out = urb->direction != 0;
    bool setup_not_completion = urb->is_setup;
    uint8_t bRequest = urb->usb_trans_info->setup.request;
    uint16_t wValue = urb->usb_trans_info->setup.wValue;
    uint16_t wIndex = urb->usb_trans_info->setup.wIndex;
    uint16_t wLength = urb->usb_trans_info->setup.wLength;

    if (!in_not_out && !setup_not_completion) {
        /* We don't care about completions for OUT requests */
        return 0;
    }

    if (((urb->usb_trans_info->setup.requesttype >> 5) & 0x3) != 2) {
        /* We only care about vendor requests */
        return 0;
    }

    proto_item * t5_tree_item = proto_tree_add_item(ptree, PROTO_T5, tvb, 0, -1, ENC_NA);
    proto_tree * tree = proto_item_add_subtree(t5_tree_item, ETT_T5);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trigger 5");

    if (setup_not_completion) {
        proto_tree_add_item(tree, HF_T5_CONTROL_REQ, tvb, CTRL_BREQ_OFFSET, 1, ENC_LITTLE_ENDIAN);
    } else {
        proto_item * it = proto_tree_add_uint(tree, HF_T5_CONTROL_REQ, tvb, 0, 0, bRequest);
        proto_item_set_generated(it);
    }

    switch (bRequest) {
        case CTRL_REQ_A8:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_EDID_BLOCK_NUMBER, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_EDID_BLOCK_NUMBER, tvb, 0, 0, wValue));
            }
            break;
        case CTRL_REQ_C3:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_INDEX, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_INDEX, tvb, 0, 0, wValue));
            }
            break;
        case CTRL_REQ_A5:
        case CTRL_REQ_C4:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_REG_ADDR, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_REG_ADDR, tvb, 0, 0, wIndex));
            }
            break;
        case CTRL_REQ_C8:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_CURSOR_X, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_CURSOR_Y, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_CURSOR_X, tvb, 0, 0, wValue));
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_CURSOR_Y, tvb, 0, 0, wIndex));
            }
            break;
        default:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_WVAL, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_WIDX, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_WVAL, tvb, 0, 0, wValue));
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_WIDX, tvb, 0, 0, wIndex));
            }
            break;
    }

    if (setup_not_completion) {
        proto_tree_add_item(tree, HF_T5_CONTROL_REQ_WLEN, tvb, CTRL_WLEN_OFFSET, 2, ENC_LITTLE_ENDIAN);
    } else {
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_WLEN, tvb, 0, 0, wLength));
    }

    if (!in_not_out && setup_not_completion) {
        /* OUT Setup */
        switch (bRequest) {
            case CTRL_REQ_C3:
                if (wLength >= 35) {
                    proto_item * custom_mode_item = proto_tree_add_item(tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM, tvb, CTRL_SETUP_DATA_OFFSET, 35, ENC_NA);
                    proto_tree * custom_mode_tree = proto_item_add_subtree(custom_mode_item, ETT_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM);

                    uint32_t h_res = 0;
                    uint32_t v_res = 0;
                    uint32_t clocks_per_frame = 1;
                    double pll_freq_khz = 0;

                    int field_offset = 0;
                    for (int i = 0; i < array_length(set_video_mode_fields); i++) {
                        proto_item * item = proto_tree_add_item(custom_mode_tree, *set_video_mode_fields[i].hf, tvb, CTRL_SETUP_DATA_OFFSET+field_offset, set_video_mode_fields[i].size, ENC_BIG_ENDIAN);

                        if (set_video_mode_fields[i].hf == &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_VERTICAL_RESOLUTION) {
                            v_res = tvb_get_ntohs(tvb, CTRL_SETUP_DATA_OFFSET+field_offset);
                        } else if (set_video_mode_fields[i].hf == &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_HORIZONTAL_RESOLUTION) {
                            h_res = tvb_get_ntohs(tvb, CTRL_SETUP_DATA_OFFSET+field_offset);
                        } else if (
                            (set_video_mode_fields[i].hf == &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_LINE_TOTAL_PIXELS_MINUS_ONE) ||
                            (set_video_mode_fields[i].hf == &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_FRAME_TOTAL_LINES_MINUS_ONE)) {
                            clocks_per_frame *= tvb_get_ntohs(tvb, CTRL_SETUP_DATA_OFFSET+field_offset) + 1;
                        } else if (set_video_mode_fields[i].hf == &HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG) {
                            proto_tree * item_tree = proto_item_add_subtree(item, ETT_T5_VIDEO_MODE_PLL_CONFIG);

                            uint32_t pre_div = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_PRE_DIV, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+0, 1, ENC_BIG_ENDIAN, &pre_div);
                            uint32_t mul0 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL0, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+1, 1, ENC_BIG_ENDIAN, &mul0);
                            uint32_t mul1 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_MUL1, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+2, 1, ENC_BIG_ENDIAN, &mul1);
                            uint32_t div0 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV0, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+3, 1, ENC_BIG_ENDIAN, &div0);
                            uint32_t div1 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_SET_VIDEO_MODE_CUSTOM_PLL_CONFIG_DIV1, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+4, 1, ENC_BIG_ENDIAN, &div1);

                            pll_freq_khz = 10e3 / pre_div * mul0 * mul1 / div0 / div1;
                            proto_item_append_text(item, ": %.5g MHz", pll_freq_khz/1e3);
                        }

                        field_offset += set_video_mode_fields[i].size;
                    }

                    double refresh_rate = (pll_freq_khz*1e3) / clocks_per_frame;
                    proto_item_append_text(custom_mode_item, ": %d x %d @ %.5g Hz", h_res, v_res, refresh_rate);
                }
                break;
            case CTRL_REQ_C4:
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_REG_DATA, tvb, CTRL_SETUP_DATA_OFFSET, -1, ENC_NA);
                break;
            default:
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_UNKNOWN_DATA, tvb, CTRL_SETUP_DATA_OFFSET, -1, ENC_NA);
                break;
        }
    } else if (in_not_out && !setup_not_completion) {
        /* IN Completion */
        switch (bRequest) {
            case CTRL_REQ_A1:
                {
                    proto_item * version_item = proto_tree_add_item(tree, HF_T5_CONTROL_REQ_FIRMWARE_VERSION, tvb, 0, 3, ENC_NA);
                    proto_tree * version_tree = proto_item_add_subtree(version_item, ETT_T5_FIRMWARE_VERSION);
                    uint32_t major = 0;
                    proto_tree_add_item_ret_uint(version_tree, HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MAJ, tvb, 0, 1, ENC_BIG_ENDIAN, &major);
                    uint32_t minor = 0;
                    proto_tree_add_item_ret_uint(version_tree, HF_T5_CONTROL_REQ_FIRMWARE_VERSION_MIN, tvb, 1, 1, ENC_BIG_ENDIAN, &minor);
                    uint32_t patch = 0;
                    proto_tree_add_item_ret_uint(version_tree, HF_T5_CONTROL_REQ_FIRMWARE_VERSION_PATCH, tvb, 2, 1, ENC_BIG_ENDIAN, &patch);
                    proto_item_append_text(version_item, ": %d.%d.%d", major, minor, patch);

                    proto_tree_add_item(tree, HF_T5_CONTROL_REQ_FIRMWARE_UNKNOWN, tvb, 3, 8, ENC_NA);

                    proto_item * date_item = proto_tree_add_item(tree, HF_T5_CONTROL_REQ_FIRMWARE_DATE, tvb, 11, 3, ENC_NA);
                    proto_tree * date_tree = proto_item_add_subtree(date_item, ETT_T5_FIRMWARE_DATE);
                    uint32_t year = 0;
                    proto_tree_add_item_ret_uint(date_tree, HF_T5_CONTROL_REQ_FIRMWARE_DATE_YEAR, tvb, 11, 1, ENC_BIG_ENDIAN, &year);
                    uint32_t month = 0;
                    proto_tree_add_item_ret_uint(date_tree, HF_T5_CONTROL_REQ_FIRMWARE_DATE_MONTH, tvb, 12, 1, ENC_BIG_ENDIAN, &month);
                    uint32_t day = 0;
                    proto_tree_add_item_ret_uint(date_tree, HF_T5_CONTROL_REQ_FIRMWARE_DATE_DAY, tvb, 13, 1, ENC_BIG_ENDIAN, &day);
                    proto_item_append_text(date_item, ": %04d.%02d.%02d", 2000 + year, month, day);
                }
                break;
            case CTRL_REQ_A4:
                {
                    proto_tree_add_item(tree, HF_T5_CONTROL_REQ_GET_VIDEO_MODES_COUNT, tvb, 0, 2, ENC_BIG_ENDIAN);
                    proto_item * video_modes_item = proto_tree_add_item(tree, HF_T5_CONTROL_REQ_GET_VIDEO_MODES_DATA, tvb, 4, -1, ENC_NA);
                    proto_tree * video_modes_tree = proto_item_add_subtree(video_modes_item, ETT_T5_VIDEO_MODES);
                    for (int offset = 4; offset < tvb_reported_length(tvb); offset += 8) {
                        proto_item * video_mode_item = proto_tree_add_item(video_modes_tree, HF_T5_CONTROL_REQ_GET_VIDEO_MODES_VIDEO_MODE, tvb, offset, 8, ENC_NA);
                        proto_tree * video_mode_tree = proto_item_add_subtree(video_mode_item, ETT_T5_VIDEO_MODE_INFO);

                        int field_offset = 0;
                        for (int i = 0; i < array_length(get_video_modes_mode_fields); i++) {
                            proto_tree_add_item(video_mode_tree, *get_video_modes_mode_fields[i].hf, tvb, offset+field_offset, get_video_modes_mode_fields[i].size, ENC_LITTLE_ENDIAN);
                            field_offset += get_video_modes_mode_fields[i].size;
                        }
                    }
                }
                break;
            case CTRL_REQ_A5:
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_REG_DATA, tvb, 0, -1, ENC_NA);
                break;
            case CTRL_REQ_A8:
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_EDID_BLOCK_DATA, tvb, 0, 128, ENC_NA);
                break;
            default:
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_UNKNOWN_DATA, tvb, 0, -1, ENC_NA);
                break;
        }
    }

    return tvb_captured_length(tvb);
}

static int handle_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, urb_info_t *urb) {
    if (urb->direction) {
        return 0;
    }

    /* BULK 1 OUT */

    proto_item * t5_tree_item = proto_tree_add_item(ptree, PROTO_T5, tvb, 0, -1, ENC_NA);
    proto_tree * tree = proto_item_add_subtree(t5_tree_item, ETT_T5);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trigger 5");

    conversation_t * conversation = find_or_create_conversation(pinfo);
    bulk_conv_info_t * bulk_conv_info = (bulk_conv_info_t *)conversation_get_proto_data(conversation, PROTO_T5);
    if (!bulk_conv_info) {
        bulk_conv_info = wmem_new(wmem_file_scope(), bulk_conv_info_t);
        bulk_conv_info->last_fragment_info = NULL;
        bulk_conv_info->header_info_by_frame_num = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        bulk_conv_info->fragment_info_by_frame_num = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

        conversation_add_proto_data(conversation, PROTO_T5, bulk_conv_info);
    }

    fragment_info_t * fragment_info = NULL;
    if (!PINFO_FD_VISITED(pinfo)) {
        if ((bulk_conv_info->last_fragment_info == NULL) || (bulk_conv_info->last_fragment_info->packet_len_remaining == 0)) {
            /* Packet with header */

            if (tvb_get_ntohs(tvb, 0) != 0xfb14) {
                return 0;
            }

            /* Create new header info */
            header_info_t * header_info = wmem_new(wmem_file_scope(), header_info_t);
            header_info->frame_info = tvb_get_letohs(tvb, 2);
            header_info->horiz_offset = tvb_get_letohs(tvb, 4) & 0x1FFF;
            header_info->vert_offset = tvb_get_letohs(tvb, 6) & 0x1FFF;
            header_info->width = tvb_get_letohs(tvb, 8) & 0x1FFF;
            header_info->height = tvb_get_letohs(tvb, 10) & 0x1FFF;
            header_info->payload_len = tvb_get_letohl(tvb, 12) & 0x0FFFFFFF;
            header_info->payload_flags = tvb_get_letohl(tvb, 12) >> 28;

            wmem_map_insert(bulk_conv_info->header_info_by_frame_num, GUINT_TO_POINTER(pinfo->num), header_info);

            /* Create new packet info */
            fragment_info = wmem_new(wmem_file_scope(), fragment_info_t);
            fragment_info->header_fragment_frame_num = pinfo->num;
            fragment_info->fragment_offset = 0;
            uint32_t total_packet_length = 20 + header_info->payload_len;
            fragment_info->fragment_len = MIN(total_packet_length, tvb_reported_length(tvb));
            fragment_info->packet_len_remaining = total_packet_length - fragment_info->fragment_len;

            bulk_conv_info->last_fragment_info = fragment_info;

            wmem_map_insert(bulk_conv_info->fragment_info_by_frame_num, GUINT_TO_POINTER(pinfo->num), fragment_info);
        } else {
            /* Fragment */
            header_info_t * header_info = wmem_map_lookup(bulk_conv_info->header_info_by_frame_num,
                                                          GUINT_TO_POINTER(bulk_conv_info->last_fragment_info->header_fragment_frame_num));
            if (header_info) {
                /* Create new frame info */
                fragment_info = wmem_new(wmem_file_scope(), fragment_info_t);
                fragment_info->header_fragment_frame_num = bulk_conv_info->last_fragment_info->header_fragment_frame_num;
                fragment_info->fragment_offset = bulk_conv_info->last_fragment_info->fragment_offset + bulk_conv_info->last_fragment_info->fragment_len;
                fragment_info->fragment_len = MIN(bulk_conv_info->last_fragment_info->packet_len_remaining, tvb_reported_length(tvb));
                fragment_info->packet_len_remaining = bulk_conv_info->last_fragment_info->packet_len_remaining - fragment_info->fragment_len;

                bulk_conv_info->last_fragment_info = fragment_info;

                wmem_map_insert(bulk_conv_info->fragment_info_by_frame_num, GUINT_TO_POINTER(pinfo->num), fragment_info);
            }
        }
    } else {
        fragment_info = wmem_map_lookup(bulk_conv_info->fragment_info_by_frame_num, GUINT_TO_POINTER(pinfo->num));
    }

    if (!fragment_info) {
        return 0;
    }

    header_info_t * header_info = header_info = wmem_map_lookup(bulk_conv_info->header_info_by_frame_num, GUINT_TO_POINTER(fragment_info->header_fragment_frame_num));
    if (!header_info) {
        return 0;
    }

    tvbuff_t * next_tvb = NULL;

    bool packet_has_header = pinfo->num == fragment_info->header_fragment_frame_num;
    if (packet_has_header) {
        /* Packet with header */
        proto_tree_add_item(tree, HF_T5_BULK_MAGIC, tvb, 0, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_HEADER_LEN, tvb, 1, 1, ENC_LITTLE_ENDIAN);

        proto_item * frame_info_item = proto_tree_add_item(tree, HF_T5_BULK_FRAME_INFO, tvb, 2, 2, ENC_NA);
        proto_tree * frame_info_tree = proto_item_add_subtree(frame_info_item, ETT_T5_BULK_FRAME_INFO);
        proto_tree_add_item(frame_info_tree, HF_T5_BULK_FRAME_INFO_UNK, tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(frame_info_tree, HF_T5_BULK_FRAME_INFO_PIXEL_FMT, tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(frame_info_tree, HF_T5_BULK_FRAME_INFO_COMPRESSION_ENABLED, tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(frame_info_tree, HF_T5_BULK_FRAME_INFO_FRAME_COUNTER, tvb, 2, 2, ENC_LITTLE_ENDIAN);

        proto_tree_add_item(tree, HF_T5_BULK_H_OFFSET, tvb, 4, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_V_OFFSET, tvb, 6, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_WIDTH, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_HEIGHT, tvb, 10, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_PAYLOAD_FLAGS, tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_PAYLOAD_LEN, tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, HF_T5_BULK_OTHER_FLAGS, tvb, 16, 1, ENC_LITTLE_ENDIAN);
        uint32_t header_checksum = 0;
        proto_item * checksum_item = proto_tree_add_item_ret_uint(tree, HF_T5_BULK_HEADER_CHECKSUM, tvb, 19, 1, ENC_LITTLE_ENDIAN, &header_checksum);
        if (bulk_header_checksum_tvb_offset(tvb, 0, 19) != header_checksum) {
            expert_add_info(pinfo, checksum_item, &EI_T5_BULK_HEADER_CHECKSUM_INVALID);
        }
        proto_tree_add_item(tree, HF_T5_BULK_PAYLOAD_FRAGMENT, tvb, 20, MIN(header_info->payload_len, tvb_captured_length(tvb) - 20), ENC_NA);

        if ((20 + header_info->payload_len > fragment_info->fragment_len)) {
            /* Fragmented */
            pinfo->fragmented = true;
        } else {
            /* Not fragmented */
            next_tvb = tvb;
        }
    } else {
        /* Fragment */
        pinfo->fragmented = true;

        proto_item * frame_info_item = proto_tree_add_none_format(tree, HF_T5_BULK_FRAME_INFO, tvb, 0, 0, "Frame info");
        proto_item_set_generated(frame_info_item);
        proto_tree * frame_info_tree = proto_item_add_subtree(frame_info_item, ETT_T5_BULK_FRAME_INFO);
        proto_item_set_generated(proto_tree_add_boolean(frame_info_tree, HF_T5_BULK_FRAME_INFO_UNK, tvb, 0, 0, header_info->frame_info));
        proto_item_set_generated(proto_tree_add_uint(frame_info_tree, HF_T5_BULK_FRAME_INFO_PIXEL_FMT, tvb, 0, 0, header_info->frame_info));
        proto_item_set_generated(proto_tree_add_boolean(frame_info_tree, HF_T5_BULK_FRAME_INFO_COMPRESSION_ENABLED, tvb, 0, 0, header_info->frame_info));
        proto_item_set_generated(proto_tree_add_uint(frame_info_tree, HF_T5_BULK_FRAME_INFO_FRAME_COUNTER, tvb, 0, 0, header_info->frame_info));

        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_H_OFFSET, tvb, 0, 0, header_info->horiz_offset));
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_V_OFFSET, tvb, 0, 0, header_info->vert_offset));
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_WIDTH, tvb, 0, 0, header_info->width));
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_HEIGHT, tvb, 0, 0, header_info->height));
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_PAYLOAD_FLAGS, tvb, 0, 0, header_info->payload_flags << 28));
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_BULK_PAYLOAD_LEN, tvb, 0, 0, header_info->payload_len));

        proto_tree_add_item(tree, HF_T5_BULK_PAYLOAD_FRAGMENT, tvb, 0, MIN(fragment_info->fragment_len, tvb_captured_length(tvb)), ENC_NA);
    }

    if (pinfo->fragmented) {
        /* Fragmented */
        bool more_frags = fragment_info->packet_len_remaining > 0;

        fragment_head * frag_head = fragment_add_check(&T5_REASSEMBLY_TABLE,
            tvb, 0, pinfo, 0, NULL, fragment_info->fragment_offset, tvb_captured_length(tvb), more_frags);

        next_tvb = process_reassembled_data(tvb, 0, pinfo, "Reassembled Packet", frag_head, &T5_BULK_FRAG_ITEMS, NULL, tree);

        if (frag_head) {
            /* Reassembled */
            col_append_str(pinfo->cinfo, COL_INFO, " (Packet Reassembled)");
        } else {
            /* Failed to reassemble. This can happen when a packet captures less data than was reported, which will
             * always happen with bulk transfers greater than ~240 kB on Linux. The proprietary driver likes to send
             * very large bulk transfers to the device, in the range of hundreds of kilobytes to several megabytes, so
             * unless a special capture setup is used (e.g., a Linux kernel modified to capture very large USB packets,
             * or a hardware USB analyzer) most fragmented video packets will fail to be reassembled. */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment offset %u)", fragment_info->fragment_offset);
        }
    }

    if (next_tvb) {
        proto_tree_add_item(tree, HF_T5_BULK_REASSEMBLED_PAYLOAD, next_tvb, 20, MIN(header_info->payload_len, tvb_captured_length(next_tvb) - 20), ENC_NA);
    }

    return tvb_captured_length(tvb);
}

static int handle_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, urb_info_t *urb) {
    if (!urb->direction) {
        return 0;
    }

    /* INTERRUPT IN */

    return tvb_captured_length(tvb);
}

static int dissect_t5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    urb_info_t * urb = (urb_info_t *)data;

    switch (urb->transfer_type) {
        case URB_CONTROL:
            return handle_control(tvb, pinfo, tree, urb);
        case URB_BULK:
            return handle_bulk(tvb, pinfo, tree, urb);
        case URB_INTERRUPT:
            return handle_interrupt(tvb, pinfo, tree, urb);
        default:
            return 0;
    };
}

void proto_register_trigger5(void) {
    proto_register_subtree_array(ETT, array_length(ETT));

    PROTO_T5 = proto_register_protocol(
        "Magic Control Technology Trigger 5",
        "MCT T5",
        "trigger5"
    );

    reassembly_table_register(&T5_REASSEMBLY_TABLE, &addresses_reassembly_table_functions);

    proto_register_field_array(PROTO_T5, HF_T5_CONTROL, array_length(HF_T5_CONTROL));
    proto_register_field_array(PROTO_T5, HF_T5_BULK, array_length(HF_T5_BULK));
    proto_register_field_array(PROTO_T5, HF_T5_BULK_FRAG, array_length(HF_T5_BULK_FRAG));

    expert_module_t * expert = expert_register_protocol(PROTO_T5);
    expert_register_field_array(expert, EI_T5_BULK, array_length(EI_T5_BULK));

    T5_HANDLE = register_dissector("trigger5", dissect_t5, PROTO_T5);
}

void proto_reg_handoff_trigger5(void) {
    dissector_add_uint_range("usb.product", (range_t *)&MCT_USB_PID_RANGE, T5_HANDLE);
    dissector_add_for_decode_as("usb.device", T5_HANDLE);
}
