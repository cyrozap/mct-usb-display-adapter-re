// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_t5.c - Wireshark dissector for MCT's Trigger 5 protocol.
 *  Copyright (C) 2023  Forest Crossman <cyrozap@gmail.com>
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

#include <stdint.h>

#include <epan/dissectors/packet-usb.h>
#include <epan/proto.h>

#include "proto_t5.h"


static const int CTRL_BREQ_OFFSET = 0;
static const int CTRL_WVAL_OFFSET = 1;
static const int CTRL_WIDX_OFFSET = 3;
static const int CTRL_WLEN_OFFSET = 5;
static const int CTRL_SETUP_DATA_OFFSET = 7;

static const uint32_t MCT_USB_VID = 0x0711;

static const range_t MCT_USB_PID_RANGE = {
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

static const true_false_string tfs_sync_polarity = { "Negative", "Positive" };

static dissector_handle_t T5_HANDLE = NULL;

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

static int HF_T5_CONTROL_REQ_VIDEO_MODES_COUNT = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODES_DATA = -1;

static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_REFRESH_RATE_HZ = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_PIXEL_CLOCK_MHZ = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_BPP = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_MODE_NUM = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_WIDTH = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_HEIGHT = -1;

static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_INDEX = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_TOTAL_PIXELS_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_SYNC_PULSE_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_BACK_PORCH_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_0 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_1 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_TOTAL_LINES_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_SYNC_PULSE_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_BACK_PORCH_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_2 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_3 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION_MINUS_ONE = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_4 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL0 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL1 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV0 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV1 = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_SYNC_POLARITY = -1;
static int HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_SYNC_POLARITY = -1;

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
    { &HF_T5_CONTROL_REQ_VIDEO_MODES_COUNT,
        { "Video modes count", "trigger5.control.video_modes.count",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODES_DATA,
        { "Video modes data", "trigger5.control.video_modes.data",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO,
        { "Video mode info", "trigger5.control.video_modes.video_mode",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_REFRESH_RATE_HZ,
        { "Refresh rate (Hz)", "trigger5.control.video_modes.video_mode.refresh_rate_hz",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_PIXEL_CLOCK_MHZ,
        { "Pixel clock (MHz)", "trigger5.control.video_modes.video_mode.pixel_clock_mhz",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_BPP,
        { "Bits per pixel", "trigger5.control.video_modes.video_mode.bpp",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_MODE_NUM,
        { "Mode number", "trigger5.control.video_modes.video_mode.number",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_HEIGHT,
        { "Height", "trigger5.control.video_modes.video_mode.height",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_WIDTH,
        { "Width", "trigger5.control.video_modes.video_mode.width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_INDEX,
        { "Video mode index", "trigger5.control.video_mode.index",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION,
        { "Vertical resolution", "trigger5.control.video_mode.vertical_res",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION,
        { "Horizontal resolution", "trigger5.control.video_mode.horizontal_res",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_TOTAL_PIXELS_MINUS_ONE,
        { "Line total pixels minus one", "trigger5.control.video_mode.line_total_pixels_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_SYNC_PULSE_MINUS_ONE,
        { "Line sync pulse minus one", "trigger5.control.video_mode.line_sync_pulse_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_BACK_PORCH_MINUS_ONE,
        { "Line back porch minus one", "trigger5.control.video_mode.line_back_porch_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_0,
        { "Unknown 0", "trigger5.control.video_mode.unk0",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_1,
        { "Unknown 1", "trigger5.control.video_mode.unk1",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION_MINUS_ONE,
        { "Horizontal resolution minus one", "trigger5.control.video_mode.horizontal_res_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_TOTAL_LINES_MINUS_ONE,
        { "Frame total lines minus one", "trigger5.control.video_mode.frame_total_lines_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_SYNC_PULSE_MINUS_ONE,
        { "Frame sync pulse minus one", "trigger5.control.video_mode.frame_sync_pulse_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_BACK_PORCH_MINUS_ONE,
        { "Frame back porch minus one", "trigger5.control.video_mode.frame_back_porch_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_2,
        { "Unknown 2", "trigger5.control.video_mode.unk2",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_3,
        { "Unknown 3", "trigger5.control.video_mode.unk3",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION_MINUS_ONE,
        { "Vertical resolution minus one", "trigger5.control.video_mode.vertical_res_minus_one",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_4,
        { "Unknown 4", "trigger5.control.video_mode.unk4",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG,
        { "PLL configuration", "trigger5.control.video_mode.pll_config",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL0,
        { "Multiplier 0", "trigger5.control.video_mode.pll_config.mul0",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL1,
        { "Multiplier 1", "trigger5.control.video_mode.pll_config.mul1",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV0,
        { "Divisor 0", "trigger5.control.video_mode.pll_config.div0",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV1,
        { "Divisor 1", "trigger5.control.video_mode.pll_config.div1",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_SYNC_POLARITY,
        { "Horizontal sync polarity", "trigger5.control.video_mode.horizontal_sync_polarity",
        FT_BOOLEAN, BASE_DEC, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_SYNC_POLARITY,
        { "Vertical sync polarity", "trigger5.control.video_mode.vertical_sync_polarity",
        FT_BOOLEAN, BASE_DEC, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
};

typedef struct field_sizes_s {
    int * hf;
    int size;
} field_sizes_t;

static const field_sizes_t video_mode_set_fields[] = {
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION, 2 },

    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_TOTAL_PIXELS_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_SYNC_PULSE_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_LINE_BACK_PORCH_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_0, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_1, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_RESOLUTION_MINUS_ONE, 2 },

    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_TOTAL_LINES_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_SYNC_PULSE_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_FRAME_BACK_PORCH_MINUS_ONE, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_2, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_3, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_RESOLUTION_MINUS_ONE, 2 },

    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_UNK_4, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG, 4 },

    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_HORIZONTAL_SYNC_POLARITY, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_VERTICAL_SYNC_POLARITY, 1 },
};

static const field_sizes_t video_mode_get_fields[] = {
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_REFRESH_RATE_HZ, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_PIXEL_CLOCK_MHZ, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_BPP, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_MODE_NUM, 1 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_HEIGHT, 2 },
    { &HF_T5_CONTROL_REQ_VIDEO_MODE_INFO_WIDTH, 2 },
};

static int ETT_T5 = -1;
static int ETT_T5_FIRMWARE_VERSION = -1;
static int ETT_T5_FIRMWARE_DATE = -1;
static int ETT_T5_VIDEO_MODE_PLL_CONFIG = -1;
static int ETT_T5_VIDEO_MODES = -1;
static int ETT_T5_VIDEO_MODE_INFO = -1;
static int * const ETT[] = {
    &ETT_T5,
    &ETT_T5_FIRMWARE_VERSION,
    &ETT_T5_FIRMWARE_DATE,
    &ETT_T5_VIDEO_MODE_PLL_CONFIG,
    &ETT_T5_VIDEO_MODES,
    &ETT_T5_VIDEO_MODE_INFO,
};

static int handle_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, usb_conv_info_t *usb_conv_info) {
    gboolean in_not_out = usb_conv_info->direction != 0;
    gboolean setup_not_completion = usb_conv_info->is_setup;
    uint8_t bRequest = usb_conv_info->usb_trans_info->setup.request;
    uint16_t wValue = usb_conv_info->usb_trans_info->setup.wValue;
    uint16_t wIndex = usb_conv_info->usb_trans_info->setup.wIndex;
    uint16_t wLength = usb_conv_info->usb_trans_info->setup.wLength;

    if (!in_not_out && !setup_not_completion) {
        /* We don't care about completions for OUT requests */
        return 0;
    }

    if (((usb_conv_info->usb_trans_info->setup.requesttype >> 5) & 0x3) != 2) {
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
                proto_tree_add_item(tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_INDEX, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_INDEX, tvb, 0, 0, wValue));
            }
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
                {
                    int field_offset = 0;
                    for (int i = 0; i < array_length(video_mode_set_fields); i++) {
                        proto_item * item = proto_tree_add_item(tree, *video_mode_set_fields[i].hf, tvb, CTRL_SETUP_DATA_OFFSET+field_offset, video_mode_set_fields[i].size, ENC_BIG_ENDIAN);
                        if (video_mode_set_fields[i].hf == &HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG) {
                            proto_tree * item_tree = proto_item_add_subtree(item, ETT_T5_VIDEO_MODE_PLL_CONFIG);

                            uint32_t mul0 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL0, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+0, 1, ENC_BIG_ENDIAN, &mul0);
                            uint32_t mul1 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_MUL1, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+1, 1, ENC_BIG_ENDIAN, &mul1);
                            uint32_t div0 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV0, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+2, 1, ENC_BIG_ENDIAN, &div0);
                            uint32_t div1 = 0;
                            proto_tree_add_item_ret_uint(item_tree, HF_T5_CONTROL_REQ_VIDEO_MODE_DETAILS_PLL_CONFIG_DIV1, tvb, CTRL_SETUP_DATA_OFFSET+field_offset+3, 1, ENC_BIG_ENDIAN, &div1);

                            uint32_t pll_freq_khz = 10000 * mul0 * mul1 / div0 / div1;
                            proto_item_append_text(item, ": %d.%03d MHz pixel clock", pll_freq_khz/1000, pll_freq_khz%1000);
                        }
                        field_offset += video_mode_set_fields[i].size;
                    }
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
                    proto_tree_add_item(tree, HF_T5_CONTROL_REQ_VIDEO_MODES_COUNT, tvb, 0, 2, ENC_BIG_ENDIAN);
                    proto_item * video_modes_item = proto_tree_add_item(tree, HF_T5_CONTROL_REQ_VIDEO_MODES_DATA, tvb, 4, -1, ENC_NA);
                    proto_tree * video_modes_tree = proto_item_add_subtree(video_modes_item, ETT_T5_VIDEO_MODES);
                    for (int offset = 4; offset < tvb_reported_length(tvb); offset += 8) {
                        proto_item * video_mode_item = proto_tree_add_item(video_modes_tree, HF_T5_CONTROL_REQ_VIDEO_MODE_INFO, tvb, offset, 8, ENC_NA);
                        proto_tree * video_mode_tree = proto_item_add_subtree(video_mode_item, ETT_T5_VIDEO_MODE_INFO);

                        int field_offset = 0;
                        for (int i = 0; i < array_length(video_mode_get_fields); i++) {
                            proto_tree_add_item(video_mode_tree, *video_mode_get_fields[i].hf, tvb, offset+field_offset, video_mode_get_fields[i].size, ENC_LITTLE_ENDIAN);
                            field_offset += video_mode_get_fields[i].size;
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

static int handle_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ptree, usb_conv_info_t *usb_conv_info) {
    if (!(usb_conv_info->endpoint == 1 && !usb_conv_info->direction)) {
        return 0;
    }

    /* BULK 1 OUT */

    proto_tree_add_item(ptree, PROTO_T5, tvb, 0, -1, ENC_NA);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trigger 5");

    return tvb_captured_length(tvb);
}

static int handle_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_conv_info_t *usb_conv_info) {
    if (!usb_conv_info->direction) {
        return 0;
    }

    /* INTERRUPT IN */

    return tvb_captured_length(tvb);
}

static int dissect_t5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    usb_conv_info_t * usb_conv_info = (usb_conv_info_t *)data;

    switch (usb_conv_info->endpoint) {
        case 0:
            return handle_control(tvb, pinfo, tree, usb_conv_info);
        case 1:
            return handle_bulk(tvb, pinfo, tree, usb_conv_info);
        case 4:
            return handle_interrupt(tvb, pinfo, tree, usb_conv_info);
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

    proto_register_field_array(PROTO_T5, HF_T5_CONTROL, array_length(HF_T5_CONTROL));

    T5_HANDLE = register_dissector("trigger5", dissect_t5, PROTO_T5);
}

void proto_reg_handoff_trigger5(void) {
    dissector_add_uint_range("usb.product", (range_t *)&MCT_USB_PID_RANGE, T5_HANDLE);
    dissector_add_for_decode_as("usb.device", T5_HANDLE);
}
