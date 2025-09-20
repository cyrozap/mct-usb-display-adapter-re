// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_t6.c - Wireshark dissector for MCT's Trigger 6 protocol.
 *  Copyright (C) 2023-2025  Forest Crossman <cyrozap@gmail.com>
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
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/reassemble.h>

#include "proto_t6.h"


static const int CTRL_BREQ_OFFSET = 0;
static const int CTRL_WVAL_OFFSET = 1;
static const int CTRL_WIDX_OFFSET = 3;
static const int CTRL_WLEN_OFFSET = 5;
static const int CTRL_SETUP_DATA_OFFSET = 7;

typedef enum {
    SELECTOR,
    FRAGMENT,
} frame_type;

typedef struct selector_info_s {
    uint32_t frame_num;
    uint32_t session_num;
    uint32_t payload_len;
    uint32_t dest_addr;
    uint32_t frag_len;
    uint32_t frag_offset;
} selector_info_t;

typedef struct frame_info_s {
    frame_type type;
    selector_info_t * selector_info;
    uint32_t payload_len_remaining;
    uint32_t frag_len_remaining;
} frame_info_t;

typedef struct session_conv_info_s {
    frame_info_t * last_frame;
} session_conv_info_t;

typedef struct bulk_conv_info_s {
    frame_info_t * last_frame;
    wmem_map_t * session_conv_info_by_session_num;
    wmem_map_t * frame_info_by_frame_num;
} bulk_conv_info_t;

typedef struct bigger_range_s {
    unsigned nranges;
    range_admin_t ranges[4];
} bigger_range_t;

static const uint32_t MCT_USB_VID = 0x0711;
static const uint32_t INSIGNIA_USB_VID = 0x19FF;
static const uint32_t HP_USB_VID = 0x03F0;

#define USB_VID_PID(vid, pid) ((vid << 16) | pid)

static const bigger_range_t MCT_USB_PID_RANGE = {
    .nranges = 4,
    .ranges = {
        { .low = USB_VID_PID(MCT_USB_VID, 0x5600), .high = USB_VID_PID(MCT_USB_VID, 0x561F) },
        { .low = USB_VID_PID(INSIGNIA_USB_VID, 0x5600), .high = USB_VID_PID(INSIGNIA_USB_VID, 0x561F) },
        { .low = USB_VID_PID(HP_USB_VID, 0x0182), .high = USB_VID_PID(HP_USB_VID, 0x0182) },
        { .low = USB_VID_PID(HP_USB_VID, 0x0788), .high = USB_VID_PID(HP_USB_VID, 0x0788) },
    },
};

#define SESSION_VIDEO 0
#define SESSION_AUDIO 3
#define SESSION_FW_UPDATE 5
static const value_string SESSIONS[] = {
    { SESSION_VIDEO, "Video" },
    { SESSION_AUDIO, "Audio" },
    { SESSION_FW_UPDATE, "Firmware update" },
    { 0, NULL },
};

#define INFO_FIELD_HW_PLAT 0
#define INFO_FIELD_BOOT_CODE 1
#define INFO_FIELD_IMAGE_CODE 2
#define INFO_FIELD_PROJECT_CODE 3
#define INFO_FIELD_VENDOR_CMD_VER 4
#define INFO_FIELD_SERIAL 5
static const value_string INFO_FIELDS[] = {
    { INFO_FIELD_HW_PLAT, "Hardware Platform" },
    { INFO_FIELD_BOOT_CODE, "Boot Code Version" },
    { INFO_FIELD_IMAGE_CODE, "Image Code Version" },
    { INFO_FIELD_PROJECT_CODE, "Project Code" },
    { INFO_FIELD_VENDOR_CMD_VER, "Vendor Command Version" },
    { INFO_FIELD_SERIAL, "Serial Number" },
    { 0, NULL },
};

static const value_string HARDWARE_PLATFORMS[] = {
    { 0, "Lite" },
    { 1, "Super Lite" },
    { 0, NULL },
};

#define CONTROL_REQ_03 0x03
#define CONTROL_REQ_04 0x04
#define CONTROL_REQ_05 0x05
#define CONTROL_REQ_10 0x10
#define CONTROL_REQ_12 0x12
#define CONTROL_REQ_80 0x80
#define CONTROL_REQ_87 0x87
#define CONTROL_REQ_88 0x88
#define CONTROL_REQ_89 0x89
#define CONTROL_REQ_A5 0xA5
#define CONTROL_REQ_B0 0xB0
#define CONTROL_REQ_B1 0xB1
#define CONTROL_REQ_B3 0xB3
static const value_string CONTROL_REQS[] = {
    { CONTROL_REQ_03, "Set video output state" },
    { CONTROL_REQ_04, "Set cursor position" },
    { CONTROL_REQ_05, "Set cursor state" },
    { CONTROL_REQ_10, "Upload cursor data" },
    { CONTROL_REQ_12, "Set video mode" },
    { CONTROL_REQ_80, "Get EDID block" },
    { CONTROL_REQ_87, "Get connector status" },
    { CONTROL_REQ_88, "Get video RAM size" },
    { CONTROL_REQ_89, "Get video modes" },
    { CONTROL_REQ_A5, "Get audio descriptor?" },
    { CONTROL_REQ_B0, "Get adapter info field" },
    { CONTROL_REQ_B1, "Get adapter session info?" },
    { CONTROL_REQ_B3, "Get adapter config blob?" },
    { 0, NULL },
};

#define CONF_TYPE_UHAL 0x4C414855
#define CONF_TYPE_DISP 0x50534944
#define CONF_TYPE_AUD_ 0x5F445541
#define CONF_TYPE_GPIO 0x4F495047
static const value_string CONF_TYPES[] = {
    { CONF_TYPE_UHAL, "UHAL" },
    { CONF_TYPE_DISP, "DISP" },
    { CONF_TYPE_AUD_, "AUD_" },
    { CONF_TYPE_GPIO, "GPIO" },
    { 0, NULL },
};

static const value_string DVO_TRANSMITTER_TYPES[] = {
    { 0, "None?" },
    { 3, "HDMI?" },
    { 7, "DP?" },
    { 0, NULL },
};

static const value_string CURSOR_PIXEL_FORMATS[] = {
    { 1, "RGBA?" },
    { 0, NULL },
};

static const true_false_string tfs_sync_polarity = { "Positive", "Negative" };
static const true_false_string tfs_timing = { "Customer", "Standard" };

static dissector_handle_t T6_HANDLE = NULL;

static reassembly_table T6_REASSEMBLY_TABLE = { 0 };
static reassembly_table T6_CONTROL_CURSOR_UPLOAD_REASSEMBLY_TABLE = { 0 };

static int PROTO_T6 = -1;

static int HF_T6_CONTROL_REQ = -1;

static int HF_T6_CONTROL_REQ_WVAL = -1;
static int HF_T6_CONTROL_REQ_WIDX = -1;
static int HF_T6_CONTROL_REQ_WLEN = -1;
static int HF_T6_CONTROL_REQ_UNKNOWN_DATA = -1;

static int HF_T6_CONTROL_REQ_CURSOR_POS_X = -1;
static int HF_T6_CONTROL_REQ_CURSOR_POS_Y = -1;
static int HF_T6_CONTROL_REQ_CURSOR_IDX = -1;
static int HF_T6_CONTROL_REQ_CURSOR_ENABLE = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_BYTE_OFFSET = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_FORMAT = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_WIDTH = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_HEIGHT = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_STRIDE = -1;
static int HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_DATA = -1;

static int HF_T6_CONTROL_REQ_VIDEO_CONN_IDX = -1;
static int HF_T6_CONTROL_REQ_VIDEO_OUTPUT_ENABLE = -1;

static int HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET = -1;
static int HF_T6_CONTROL_REQ_EDID_BLOCK_DATA = -1;

static int HF_T6_CONTROL_REQ_VIDEO_CONNECTOR_STATUS = -1;

static int HF_T6_CONTROL_REQ_VIDEO_RAM_SIZE_MB = -1;

static int HF_T6_CONTROL_REQ_VIDEO_MODES_BYTE_OFFSET = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODES_DATA = -1;

static int HF_T6_CONTROL_REQ_VIDEO_MODE = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PIXEL_CLK_KHZ = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_REFRESH_RATE_HZ = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_TOTAL_PIXELS = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PIXELS = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PLUS_FRONT_PORCH_PIXELS = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_SYNC_WIDTH = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_TOTAL_LINES = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_LINES = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_PLUS_FRONT_PORCH_LINES = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_SYNC_WIDTH = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FNUM = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FDEN = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_IDIV = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X2_EN = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X4_EN = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_HORIZONTAL_SYNC_POLARITY = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_VERTICAL_SYNC_POLARITY = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_REDUCED_BLANKING = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_RESERVED = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_TIMING = -1;

static int HF_T6_CONTROL_REQ_INFO_FIELD_IDX = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_HW_PLAT = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_BOOT_CODE = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_IMAGE_CODE = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_PROJECT_CODE = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_VENDOR_CMD_VER = -1;
static int HF_T6_CONTROL_REQ_INFO_FIELD_SERIAL = -1;

static int HF_T6_CONTROL_REQ_SESSION_INFO_NUM = -1;
static int HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_VID = -1;
static int HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_PID = -1;
static int HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_NAME = -1;

static int HF_T6_CONTROL_REQ_CONF_INFO_TYPE = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_SIZE = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_VDEV_VID = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_VDEV_PID = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_VDEV_NAME = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_VERSION = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_ROTATE = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_RESET = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_OFFSET = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_COUNT = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_LINK_INTERFACES = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_OFFSET = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_COUNT = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_LINK_INTERFACES = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_I2C = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_I2C = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_TRANSMITTER = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_I2C = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_RESERVED = -1;
static int HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_I2C = -1;

static hf_register_info HF_T6_CONTROL[] = {
    { &HF_T6_CONTROL_REQ,
        { "Request type", "trigger6.control.request",
        FT_UINT8, BASE_HEX, VALS(CONTROL_REQS), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_WVAL,
        { "wValue", "trigger6.control.wValue",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_WIDX,
        { "wIndex", "trigger6.control.wIndex",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_WLEN,
        { "wLength", "trigger6.control.wLength",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_UNKNOWN_DATA,
        { "Unknown data", "trigger6.control.unknown_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_POS_X,
        { "Cursor X-position", "trigger6.control.cursor_pos.x",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_POS_Y,
        { "Cursor Y-position", "trigger6.control.cursor_pos.y",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_IDX,
        { "Cursor index", "trigger6.control.cursor_index",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_ENABLE,
        { "Cursor enable", "trigger6.control.cursor_enable",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_BYTE_OFFSET,
        { "Cursor data byte offset", "trigger6.control.cursor_data_byte_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA,
        { "Cursor data", "trigger6.control.cursor_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_FORMAT,
        { "Pixel format", "trigger6.control.cursor_data.pixel_format",
        FT_UINT16, BASE_DEC, VALS(CURSOR_PIXEL_FORMATS), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_WIDTH,
        { "Width (pixels)", "trigger6.control.cursor_data.width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_HEIGHT,
        { "Height (pixels)", "trigger6.control.cursor_data.height",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_STRIDE,
        { "Stride (bytes)", "trigger6.control.cursor_data.stride",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_DATA,
        { "Pixel data", "trigger6.control.cursor_data.pixel_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_CONN_IDX,
        { "Video connector index", "trigger6.control.video_connector",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_OUTPUT_ENABLE,
        { "Video output enable", "trigger6.control.video_enable",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET,
        { "EDID byte offset", "trigger6.control.edid.byte_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_EDID_BLOCK_DATA,
        { "EDID block data", "trigger6.control.edid.block_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_CONNECTOR_STATUS,
        { "Video output connected", "trigger6.control.video_output_connected",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_RAM_SIZE_MB,
        { "Video RAM size (MB)", "trigger6.control.video_ram_size_mb",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODES_BYTE_OFFSET,
        { "Video modes byte offset", "trigger6.control.video_modes.byte_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODES_DATA,
        { "Video modes data", "trigger6.control.video_modes.data",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE,
        { "Video mode data", "trigger6.control.video_mode",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PIXEL_CLK_KHZ,
        { "Pixel clock (kHz)", "trigger6.control.video_mode.pixel_clk_khz",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_REFRESH_RATE_HZ,
        { "Refresh rate (Hz)", "trigger6.control.video_mode.refresh_rate_hz",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_TOTAL_PIXELS,
        { "Line total pixels", "trigger6.control.video_mode.line_total_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PIXELS,
        { "Line active pixels", "trigger6.control.video_mode.line_active_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PLUS_FRONT_PORCH_PIXELS,
        { "Line active plus front porch pixels", "trigger6.control.video_mode.line_active_plus_front_porch_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_SYNC_WIDTH,
        { "Line sync width", "trigger6.control.video_mode.line_sync_width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_TOTAL_LINES,
        { "Frame total lines", "trigger6.control.video_mode.frame_total_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_LINES,
        { "Frame active lines", "trigger6.control.video_mode.frame_active_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_PLUS_FRONT_PORCH_LINES,
        { "Frame active plus front porch lines", "trigger6.control.video_mode.frame_active_plus_front_porch_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_SYNC_WIDTH,
        { "Frame sync width", "trigger6.control.video_mode.frame_sync_width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG,
        { "Pixel clock PLL configuration", "trigger6.control.video_mode.pixel_clock_pll_config",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FNUM,
        { "Fractional Numerator (PLL P)", "trigger6.control.video_mode.pixel_clock_pll_config.fnum",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FDEN,
        { "Fractional Denominator (PLL Q)", "trigger6.control.video_mode.pixel_clock_pll_config.fden",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_IDIV,
        { "Integer Divisor (PLL N)", "trigger6.control.video_mode.pixel_clock_pll_config.idiv",
        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL,
        { "Multiplier", "trigger6.control.video_mode.pixel_clock_pll_config.mul",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X2_EN,
        { "x2 multiplier enabled", "trigger6.control.video_mode.pixel_clock_pll_config.mul.x2_en",
        FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X4_EN,
        { "x4 multiplier enabled", "trigger6.control.video_mode.pixel_clock_pll_config.mul.x4_en",
        FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_HORIZONTAL_SYNC_POLARITY,
        { "Horizontal sync polarity", "trigger6.control.video_mode.horizontal_sync_polarity",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_VERTICAL_SYNC_POLARITY,
        { "Vertical sync polarity", "trigger6.control.video_mode.vertical_sync_polarity",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_sync_polarity), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_REDUCED_BLANKING,
        { "Reduced blanking", "trigger6.control.video_mode.reduced_blanking",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS,
        { "Flags", "trigger6.control.video_mode.flags",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_RESERVED,
        { "Reserved", "trigger6.control.video_mode.flags.reserved",
        FT_UINT8, BASE_HEX, NULL, 0xFE, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_TIMING,
        { "Timing", "trigger6.control.video_mode.flags.timing",
        FT_BOOLEAN, 8, TFS(&tfs_timing), 0x01, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_IDX,
        { "Info field", "trigger6.control.info_field.index",
        FT_UINT16, BASE_HEX, VALS(INFO_FIELDS), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_HW_PLAT,
        { "Hardware Platform", "trigger6.control.info_field.hw_plat",
        FT_UINT32, BASE_HEX, VALS(HARDWARE_PLATFORMS), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_BOOT_CODE,
        { "Boot Code Version", "trigger6.control.info_field.boot_code",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_IMAGE_CODE,
        { "Image Code Version", "trigger6.control.info_field.image_code",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_PROJECT_CODE,
        { "Project Code", "trigger6.control.info_field.project_code",
        FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_VENDOR_CMD_VER,
        { "Vendor Command Version", "trigger6.control.info_field.vendor_cmd_ver",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_SERIAL,
        { "Serial Number", "trigger6.control.info_field.serial",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_SESSION_INFO_NUM,
        { "Session number", "trigger6.control.session_info.num",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_VID,
        { "Virtual device vendor ID", "trigger6.control.session_info.vid",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_PID,
        { "Virtual device product ID", "trigger6.control.session_info.pid",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_NAME,
        { "Virtual device name", "trigger6.control.session_info.name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_TYPE,
        { "Configuration type", "trigger6.control.conf_info.type",
        FT_UINT32, BASE_HEX, VALS(CONF_TYPES), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_SIZE,
        { "Configuration size", "trigger6.control.conf_info.size",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_VDEV_VID,
        { "Virtual device vendor ID", "trigger6.control.conf_info.disp.vid",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_VDEV_PID,
        { "Virtual device product ID", "trigger6.control.conf_info.disp.pid",
        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_VDEV_NAME,
        { "Virtual device name", "trigger6.control.conf_info.disp.name",
        FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_VERSION,
        { "Configuration version", "trigger6.control.conf_info.version",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION,
        { "Display function", "trigger6.control.conf_info.disp_func",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_ROTATE,
        { "Rotate", "trigger6.control.conf_info.disp_func.rotate",
        FT_UINT32, BASE_HEX, NULL, 0x000000F0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_RESET,
        { "Reset", "trigger6.control.conf_info.disp_func.reset",
        FT_BOOLEAN, 32, NULL, 0x00000008, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS,
        { "Display 0 capabilities", "trigger6.control.conf_info.disp0_caps",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_OFFSET,
        { "Video modes offset", "trigger6.control.conf_info.disp0_caps.video_modes_offset",
        FT_UINT32, BASE_HEX_DEC, NULL, 0xFFFF0000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_COUNT,
        { "Video modes count", "trigger6.control.conf_info.disp0_caps.video_modes_count",
        FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_RESERVED,
        { "Reserved", "trigger6.control.conf_info.disp0_caps.resered",
        FT_UINT32, BASE_HEX, NULL, 0x000000F0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_LINK_INTERFACES,
        { "Link interfaces", "trigger6.control.conf_info.disp0_caps.link_interfaces",
        FT_UINT32, BASE_DEC, NULL, 0x0000000F, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS,
        { "Display 1 capabilities", "trigger6.control.conf_info.disp1_caps",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_OFFSET,
        { "Video modes offset", "trigger6.control.conf_info.disp1_caps.video_modes_offset",
        FT_UINT32, BASE_HEX_DEC, NULL, 0xFFFF0000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_COUNT,
        { "Video modes count", "trigger6.control.conf_info.disp1_caps.video_modes_count",
        FT_UINT32, BASE_DEC, NULL, 0x0000FF00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_RESERVED,
        { "Reserved", "trigger6.control.conf_info.disp1_caps.resered",
        FT_UINT32, BASE_HEX, NULL, 0x000000F0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_LINK_INTERFACES,
        { "Link interfaces", "trigger6.control.conf_info.disp1_caps.link_interfaces",
        FT_UINT32, BASE_DEC, NULL, 0x0000000F, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE,
        { "Display interface", "trigger6.control.conf_info.disp_intf",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_RESERVED,
        { "LVDS reserved", "trigger6.control.conf_info.disp_intf.lvds_reserved",
        FT_UINT32, BASE_HEX, NULL, 0xFC000000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_I2C,
        { "LVDS I2C", "trigger6.control.conf_info.disp_intf.lvds_i2c",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x03000000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_RESERVED,
        { "DVI reserved", "trigger6.control.conf_info.disp_intf.dvi_reserved",
        FT_UINT32, BASE_HEX, NULL, 0x00FC0000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_I2C,
        { "DVI I2C", "trigger6.control.conf_info.disp_intf.dvi_i2c",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x00030000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_TRANSMITTER,
        { "DVO transmitter", "trigger6.control.conf_info.disp_intf.dvo_transmitter",
        FT_UINT32, BASE_DEC, VALS(DVO_TRANSMITTER_TYPES), 0x0000F000, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_RESERVED,
        { "DVO reserved", "trigger6.control.conf_info.disp_intf.dvo_reserved",
        FT_UINT32, BASE_HEX, NULL, 0x00000C00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_I2C,
        { "DVO I2C", "trigger6.control.conf_info.disp_intf.dvo_i2c",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x00000300, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_RESERVED,
        { "DAC reserved", "trigger6.control.conf_info.disp_intf.dac_reserved",
        FT_UINT32, BASE_HEX, NULL, 0x000000FC, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_I2C,
        { "DAC I2C", "trigger6.control.conf_info.disp_intf.dac_i2c",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x00000003, NULL, HFILL }
    },
};

static int HF_T6_BULK_SESSION_SELECTOR = -1;
static int HF_T6_BULK_SESSION_NUM = -1;
static int HF_T6_BULK_SESSION_PAYLOAD_LEN = -1;
static int HF_T6_BULK_SESSION_PAYLOAD_DEST_ADDR = -1;
static int HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_LENGTH = -1;
static int HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_OFFSET = -1;
static int HF_T6_BULK_SESSION_PAYLOAD_DATA = -1;

static hf_register_info HF_T6_BULK[] = {
    { &HF_T6_BULK_SESSION_SELECTOR,
        { "Session selector in", "trigger6.bulk.session.selector_in",
        FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_NUM,
        { "Session number", "trigger6.bulk.session.num",
        FT_UINT32, BASE_DEC, VALS(SESSIONS), 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_PAYLOAD_LEN,
        { "Session payload length", "trigger6.bulk.session.payload.len",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_PAYLOAD_DEST_ADDR,
        { "Session payload destination address", "trigger6.bulk.session.payload.dest_addr",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_LENGTH,
        { "Session payload fragment length", "trigger6.bulk.session.payload.frag_len",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_OFFSET,
        { "Session payload fragment offset", "trigger6.bulk.session.payload.frag_offset",
        FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_BULK_SESSION_PAYLOAD_DATA,
        { "Session payload data", "trigger6.bulk.session.payload.data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
};

static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP_CONFLICTS = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_MULTIPLE_TAILS = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_TOO_LONG_FRAGMENT = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_ERROR = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_COUNT = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_IN = -1;
static int HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_LENGTH = -1;

static int ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT = -1;
static int ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS = -1;

static const fragment_items T6_CONTROL_CURSOR_UPLOAD_FRAG_ITEMS = {
    &ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT,
    &ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP_CONFLICTS,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_MULTIPLE_TAILS,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_TOO_LONG_FRAGMENT,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_ERROR,
    &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_COUNT,
    &HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_IN,
    &HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_LENGTH,
    NULL,
    "Payload fragments",
};

static hf_register_info HF_T6_CONTROL_CURSOR_UPLOAD_FRAG[] = {
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS,
        { "Payload fragments", "trigger6.control.cursor_data.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT,
        { "Payload fragment", "trigger6.control.cursor_data.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP,
        { "Payload fragment overlap", "trigger6.control.cursor_data.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_OVERLAP_CONFLICTS,
        { "Payload fragment overlapping with conflicting data", "trigger6.control.cursor_data.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_MULTIPLE_TAILS,
        { "Payload has multiple tail fragments", "trigger6.control.cursor_data.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_TOO_LONG_FRAGMENT,
        { "Payload fragment too long", "trigger6.control.cursor_data.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_ERROR,
        { "Payload defragmentation error", "trigger6.control.cursor_data.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT_COUNT,
        { "Payload fragment count", "trigger6.control.cursor_data.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_IN,
        { "Reassembled in", "trigger6.control.cursor_data.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_CONTROL_CURSOR_UPLOAD_REASSEMBLED_LENGTH,
        { "Reassembled length", "trigger6.control.cursor_data.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
};

static int HF_T6_BULK_FRAGMENTS = -1;
static int HF_T6_BULK_FRAGMENT = -1;
static int HF_T6_BULK_FRAGMENT_OVERLAP = -1;
static int HF_T6_BULK_FRAGMENT_OVERLAP_CONFLICTS = -1;
static int HF_T6_BULK_FRAGMENT_MULTIPLE_TAILS = -1;
static int HF_T6_BULK_FRAGMENT_TOO_LONG_FRAGMENT = -1;
static int HF_T6_BULK_FRAGMENT_ERROR = -1;
static int HF_T6_BULK_FRAGMENT_COUNT = -1;
static int HF_T6_BULK_REASSEMBLED_IN = -1;
static int HF_T6_BULK_REASSEMBLED_LENGTH = -1;

static int ETT_T6_BULK_FRAGMENT = -1;
static int ETT_T6_BULK_FRAGMENTS = -1;

static const fragment_items T6_BULK_FRAG_ITEMS = {
    &ETT_T6_BULK_FRAGMENT,
    &ETT_T6_BULK_FRAGMENTS,
    &HF_T6_BULK_FRAGMENTS,
    &HF_T6_BULK_FRAGMENT,
    &HF_T6_BULK_FRAGMENT_OVERLAP,
    &HF_T6_BULK_FRAGMENT_OVERLAP_CONFLICTS,
    &HF_T6_BULK_FRAGMENT_MULTIPLE_TAILS,
    &HF_T6_BULK_FRAGMENT_TOO_LONG_FRAGMENT,
    &HF_T6_BULK_FRAGMENT_ERROR,
    &HF_T6_BULK_FRAGMENT_COUNT,
    &HF_T6_BULK_REASSEMBLED_IN,
    &HF_T6_BULK_REASSEMBLED_LENGTH,
    NULL,
    "Payload fragments",
};

static hf_register_info HF_T6_BULK_FRAG[] = {
    { &HF_T6_BULK_FRAGMENTS,
        { "Payload fragments", "trigger6.bulk.session.payload.fragments",
        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT,
        { "Payload fragment", "trigger6.bulk.session.payload.fragment",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_OVERLAP,
        { "Payload fragment overlap", "trigger6.bulk.session.payload.fragment.overlap",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_OVERLAP_CONFLICTS,
        { "Payload fragment overlapping with conflicting data", "trigger6.bulk.session.payload.fragment.overlap.conflicts",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_MULTIPLE_TAILS,
        { "Payload has multiple tail fragments", "trigger6.bulk.session.payload.fragment.multiple_tails",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_TOO_LONG_FRAGMENT,
        { "Payload fragment too long", "trigger6.bulk.session.payload.fragment.too_long_fragment",
        FT_BOOLEAN, 0, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_ERROR,
        { "Payload defragmentation error", "trigger6.bulk.session.payload.fragment.error",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_FRAGMENT_COUNT,
        { "Payload fragment count", "trigger6.bulk.session.payload.fragment.count",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_REASSEMBLED_IN,
        { "Reassembled in", "trigger6.bulk.session.payload.reassembled.in",
        FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
    },
    { &HF_T6_BULK_REASSEMBLED_LENGTH,
        { "Reassembled length", "trigger6.bulk.session.payload.reassembled.length",
        FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
    },
};

typedef struct field_sizes_s {
    int * hf;
    int size;
} field_sizes_t;

static const field_sizes_t video_mode_fields[] = {
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PIXEL_CLK_KHZ, 4 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_REFRESH_RATE_HZ, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_TOTAL_PIXELS, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PIXELS, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PLUS_FRONT_PORCH_PIXELS, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_SYNC_WIDTH, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_TOTAL_LINES, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_LINES, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_PLUS_FRONT_PORCH_LINES, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_SYNC_WIDTH, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG, 6 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_HORIZONTAL_SYNC_POLARITY, 1 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_VERTICAL_SYNC_POLARITY, 1 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_REDUCED_BLANKING, 1 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS, 1 },
};

static int ETT_T6 = -1;
static int ETT_T6_VIDEO_MODES = -1;
static int ETT_T6_VIDEO_MODE = -1;
static int ETT_T6_VIDEO_MODE_PLL_CONFIG = -1;
static int ETT_T6_VIDEO_MODE_PLL_CONFIG_MUL = -1;
static int ETT_T6_VIDEO_MODE_FLAGS = -1;
static int ETT_T6_CURSOR_DATA = -1;
static int ETT_T6_CONF_INFO_DISPLAY_FUNCTION = -1;
static int ETT_T6_CONF_INFO_DISP0_CAPS = -1;
static int ETT_T6_CONF_INFO_DISP1_CAPS = -1;
static int ETT_T6_CONF_INFO_DISPLAY_INTERFACE = -1;
static int * const ETT[] = {
    &ETT_T6,
    &ETT_T6_VIDEO_MODES,
    &ETT_T6_VIDEO_MODE,
    &ETT_T6_VIDEO_MODE_PLL_CONFIG,
    &ETT_T6_VIDEO_MODE_PLL_CONFIG_MUL,
    &ETT_T6_VIDEO_MODE_FLAGS,
    &ETT_T6_CURSOR_DATA,
    &ETT_T6_CONF_INFO_DISPLAY_FUNCTION,
    &ETT_T6_CONF_INFO_DISP0_CAPS,
    &ETT_T6_CONF_INFO_DISP1_CAPS,
    &ETT_T6_CONF_INFO_DISPLAY_INTERFACE,
    &ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENT,
    &ETT_T6_CONTROL_CURSOR_UPLOAD_FRAGMENTS,
    &ETT_T6_BULK_FRAGMENT,
    &ETT_T6_BULK_FRAGMENTS,
};

static void dissect_cursor_upload(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, uint16_t cursor_index, uint16_t cursor_data_byte_offset) {
    tvbuff_t * next_tvb = NULL;

    bool initial_and_fragmented = false;
    if (cursor_data_byte_offset == 0) {
        uint16_t height = tvb_get_letohs(tvb, 4);
        uint16_t pitch = tvb_get_letohs(tvb, 6);
        uint32_t total_cursor_bytes = height * pitch;
        if (total_cursor_bytes > tvb_captured_length(tvb)) {
            initial_and_fragmented = true;
        }
    }

    if (initial_and_fragmented || (cursor_data_byte_offset > 0)) {
        /* Fragmented */
        pinfo->fragmented = true;

        /* TODO: Keep track of the initial cursor upload requests and the number of bytes remaining to upload, then use
         * that value to determine if more fragments are needed.
         *
         * For now, just assume that if the payload size is not exactly 512 bytes (a full packet) the cursor data is
         * fragmented. */
        bool more_frags = tvb_captured_length(tvb) == 512;

        fragment_head * frag_head = fragment_add_check(&T6_CONTROL_CURSOR_UPLOAD_REASSEMBLY_TABLE,
            tvb, 0, pinfo, cursor_index, NULL,
            cursor_data_byte_offset, tvb_captured_length(tvb), more_frags);

        next_tvb = process_reassembled_data(tvb, 0, pinfo, "Reassembled Cursor Data", frag_head, &T6_CONTROL_CURSOR_UPLOAD_FRAG_ITEMS, NULL, tree);

        if (frag_head) {
            /* Reassembled */
            col_append_str(pinfo->cinfo, COL_INFO, " (Cursor Data Reassembled)");
        } else {
            /* Failed to reassemble. This can happen when a packet captures less data than was reported. */
            col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment offset %u)", cursor_data_byte_offset);
        }
    } else {
        /* Not fragmented */
        next_tvb = tvb;
    }

    if (next_tvb) {
        proto_item * cursor_data_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CURSOR_DATA, next_tvb, 0, -1, ENC_NA);
        proto_tree * cursor_data_tree = proto_item_add_subtree(cursor_data_item, ETT_T6_CURSOR_DATA);
        proto_tree_add_item(cursor_data_tree, HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_FORMAT, next_tvb, 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cursor_data_tree, HF_T6_CONTROL_REQ_CURSOR_DATA_WIDTH, next_tvb, 2, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cursor_data_tree, HF_T6_CONTROL_REQ_CURSOR_DATA_HEIGHT, next_tvb, 4, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cursor_data_tree, HF_T6_CONTROL_REQ_CURSOR_DATA_STRIDE, next_tvb, 6, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(cursor_data_tree, HF_T6_CONTROL_REQ_CURSOR_DATA_PIXEL_DATA, next_tvb, 8, -1, ENC_LITTLE_ENDIAN);
    }
}

static double dissect_pll_config(proto_item *item, tvbuff_t *tvb) {
    double pll_freq_khz = 0;

    proto_tree * item_tree = proto_item_add_subtree(item, ETT_T6_VIDEO_MODE_PLL_CONFIG);

    uint32_t fnum = 0;
    proto_tree_add_item_ret_uint(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FNUM, tvb, 0, 2, ENC_LITTLE_ENDIAN, &fnum);

    uint32_t fden = 0;
    proto_tree_add_item_ret_uint(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_FDEN, tvb, 2, 2, ENC_LITTLE_ENDIAN, &fden);

    uint32_t idiv = 0;
    proto_tree_add_item_ret_uint(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_IDIV, tvb, 4, 1, ENC_LITTLE_ENDIAN, &idiv);

    proto_item * mul2_item = proto_tree_add_item(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL, tvb, 5, 1, ENC_NA);
    proto_tree * mul2_tree = proto_item_add_subtree(mul2_item, ETT_T6_VIDEO_MODE_PLL_CONFIG_MUL);

    bool x2_en = false;
    proto_tree_add_item_ret_boolean(mul2_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X2_EN, tvb, 5, 1, ENC_LITTLE_ENDIAN, &x2_en);

    bool x4_en = false;
    proto_tree_add_item_ret_boolean(mul2_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG_MUL_X4_EN, tvb, 5, 1, ENC_LITTLE_ENDIAN, &x4_en);

    uint32_t mul = 1;

    if (x2_en) {
        mul *= 2;
    }

    if (x4_en) {
        mul *= 4;
    }

    proto_item_append_text(mul2_item, ": %d", mul);

    /* TODO: Replace "40" with base clock MHz value based on parsed hardware platform value (Lite: 48 MHz, Super Lite:
     * 40 MHz). Pass through args from main dissector function? */
    pll_freq_khz = ((fnum + fden * idiv) * mul * 40) / 32.0;
    if (pll_freq_khz < 100000) {
        proto_item_append_text(item, ": %.5g MHz", pll_freq_khz/1e3);
    } else {
        proto_item_append_text(item, ": %.6g MHz", pll_freq_khz/1e3);
    }

    return pll_freq_khz;
}

static void dissect_video_mode_flags(proto_item *item, tvbuff_t *tvb) {
    proto_tree * item_tree = proto_item_add_subtree(item, ETT_T6_VIDEO_MODE_FLAGS);
    proto_tree_add_item(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_RESERVED, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(item_tree, HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS_TIMING, tvb, 0, 1, ENC_LITTLE_ENDIAN);
}

static void dissect_video_mode(proto_tree *tree, tvbuff_t *tvb) {
    proto_item * video_mode_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_MODE, tvb, 0, 32, ENC_NA);
    proto_tree * video_mode_tree = proto_item_add_subtree(video_mode_item, ETT_T6_VIDEO_MODE);

    uint32_t refresh_rate_hz_reported = 0;
    uint32_t clocks_per_frame = 1;
    uint32_t h_res = 0;
    uint32_t v_res = 0;
    double pll_freq_khz = 0;

    int field_offset = 0;
    for (int i = 0; i < array_length(video_mode_fields); i++) {
        proto_item * item = proto_tree_add_item(video_mode_tree, *video_mode_fields[i].hf, tvb, field_offset, video_mode_fields[i].size, ENC_LITTLE_ENDIAN);

        if (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_REFRESH_RATE_HZ) {
            refresh_rate_hz_reported = tvb_get_letohs(tvb, field_offset);
        } else if (
            (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_TOTAL_PIXELS) ||
            (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_TOTAL_LINES)) {
            clocks_per_frame *= tvb_get_letohs(tvb, field_offset);
        } else if (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PIXELS) {
            h_res = tvb_get_letohs(tvb, field_offset);
        } else if (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_LINES) {
            v_res = tvb_get_letohs(tvb, field_offset);
        } else if (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_PLL_CONFIG) {
            pll_freq_khz = dissect_pll_config(item, tvb_new_subset_length(tvb, field_offset, 6));
        } else if (video_mode_fields[i].hf == &HF_T6_CONTROL_REQ_VIDEO_MODE_FLAGS) {
            dissect_video_mode_flags(item, tvb_new_subset_length(tvb, field_offset, 1));
        }

        field_offset += video_mode_fields[i].size;
    }

    double refresh_rate_hz_actual = (pll_freq_khz*1e3) / clocks_per_frame;
    proto_item_append_text(video_mode_item, ": %d x %d @ %d Hz (%.5g Hz)", h_res, v_res, refresh_rate_hz_reported, refresh_rate_hz_actual);
}

static int handle_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, urb_info_t *urb) {
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

#define DISSECT_CONTROL_REQ_SETUP_FIELD(HFINDEX, OFFSET, LENGTH, FIELD)                 \
    if (setup_not_completion) {                                                         \
        proto_tree_add_item(tree, HFINDEX, tvb, OFFSET, LENGTH, ENC_LITTLE_ENDIAN);     \
    } else {                                                                            \
        proto_item_set_generated(proto_tree_add_uint(tree, HFINDEX, tvb, 0, 0, FIELD)); \
    }
#define DISSECT_CONTROL_REQ_SETUP_FIELD_BREQ(HFINDEX) \
    DISSECT_CONTROL_REQ_SETUP_FIELD(HFINDEX, CTRL_BREQ_OFFSET, 1, bRequest)
#define DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HFINDEX) \
    DISSECT_CONTROL_REQ_SETUP_FIELD(HFINDEX, CTRL_WVAL_OFFSET, 2, wValue)
#define DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HFINDEX) \
    DISSECT_CONTROL_REQ_SETUP_FIELD(HFINDEX, CTRL_WIDX_OFFSET, 2, wIndex)
#define DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HFINDEX) \
    DISSECT_CONTROL_REQ_SETUP_FIELD(HFINDEX, CTRL_WLEN_OFFSET, 2, wLength)

    DISSECT_CONTROL_REQ_SETUP_FIELD_BREQ(HF_T6_CONTROL_REQ)

    switch (bRequest) {
        case CONTROL_REQ_03:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_VIDEO_CONN_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_VIDEO_OUTPUT_ENABLE)
            break;
        case CONTROL_REQ_04:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_CURSOR_POS_X)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_CURSOR_POS_Y)
            break;
        case CONTROL_REQ_05:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_CURSOR_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_CURSOR_ENABLE)
            break;
        case CONTROL_REQ_10:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_CURSOR_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_CURSOR_DATA_BYTE_OFFSET)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_12:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_VIDEO_CONN_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_80:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_VIDEO_CONN_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_87:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_VIDEO_CONN_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_88:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_89:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_VIDEO_CONN_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_VIDEO_MODES_BYTE_OFFSET)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_B0:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_INFO_FIELD_IDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        case CONTROL_REQ_B1:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_SESSION_INFO_NUM)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
        default:
            DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL(HF_T6_CONTROL_REQ_WVAL)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX(HF_T6_CONTROL_REQ_WIDX)
            DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN(HF_T6_CONTROL_REQ_WLEN)
            break;
    }

#undef DISSECT_CONTROL_REQ_SETUP_FIELD
#undef DISSECT_CONTROL_REQ_SETUP_FIELD_BREQ
#undef DISSECT_CONTROL_REQ_SETUP_FIELD_WVAL
#undef DISSECT_CONTROL_REQ_SETUP_FIELD_WIDX
#undef DISSECT_CONTROL_REQ_SETUP_FIELD_WLEN

    if (!in_not_out && setup_not_completion) {
        /* OUT Setup */
        // printf("CONTROL OUT: 0x%02x\n", bRequest);
        switch (bRequest) {
            case CONTROL_REQ_10:
                dissect_cursor_upload(tree, tvb_new_subset_remaining(tvb, CTRL_SETUP_DATA_OFFSET), pinfo, wValue, wIndex);
                break;
            case CONTROL_REQ_12:
                dissect_video_mode(tree, tvb_new_subset_length(tvb, CTRL_SETUP_DATA_OFFSET, 32));
                break;
            default:
                if (tvb_captured_length(tvb) > CTRL_SETUP_DATA_OFFSET) {
                    proto_tree_add_item(tree, HF_T6_CONTROL_REQ_UNKNOWN_DATA, tvb, CTRL_SETUP_DATA_OFFSET, -1, ENC_NA);
                }
                break;
        }
    } else if (in_not_out && !setup_not_completion) {
        /* IN Completion */
        switch (bRequest) {
            case CONTROL_REQ_80:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_EDID_BLOCK_DATA, tvb, 0, 128, ENC_NA);
                break;
            case CONTROL_REQ_87:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_CONNECTOR_STATUS, tvb, 0, 1, ENC_LITTLE_ENDIAN);
                break;
            case CONTROL_REQ_88:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_RAM_SIZE_MB, tvb, 0, 1, ENC_LITTLE_ENDIAN);
                break;
            case CONTROL_REQ_89:
                {
                    proto_item * video_modes_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_DATA, tvb, 0, -1, ENC_NA);
                    proto_tree * video_modes_tree = proto_item_add_subtree(video_modes_item, ETT_T6_VIDEO_MODES);
                    for (int offset = 0; offset < tvb_reported_length(tvb); offset += 32) {
                        dissect_video_mode(video_modes_tree, tvb_new_subset_length(tvb, offset, 32));
                    }
                }
                break;
            case CONTROL_REQ_B0:
                switch (wIndex) {
                    case INFO_FIELD_HW_PLAT:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_HW_PLAT, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case INFO_FIELD_BOOT_CODE:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_BOOT_CODE, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case INFO_FIELD_IMAGE_CODE:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_IMAGE_CODE, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case INFO_FIELD_PROJECT_CODE:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_PROJECT_CODE, tvb, 0, -1, ENC_ASCII);
                        break;
                    case INFO_FIELD_VENDOR_CMD_VER:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_VENDOR_CMD_VER, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case INFO_FIELD_SERIAL:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_SERIAL, tvb, 0, -1, ENC_NA);
                        break;
                    default:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_UNKNOWN_DATA, tvb, 0, -1, ENC_NA);
                        break;
                }
                break;
            case CONTROL_REQ_B1:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_VID, tvb, 0, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_PID, tvb, 2, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_NAME, tvb, 4, 64, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                break;
            case CONTROL_REQ_B3:
                {
                    uint32_t conf_type = 0;
                    proto_tree_add_item_ret_uint(tree, HF_T6_CONTROL_REQ_CONF_INFO_TYPE, tvb, 0, 4, ENC_LITTLE_ENDIAN, &conf_type);
                    proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_SIZE, tvb, 4, 4, ENC_LITTLE_ENDIAN);
                    switch (conf_type) {
                        case CONF_TYPE_DISP:
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_VID, tvb, 12, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_PID, tvb, 14, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_NAME, tvb, 16, 64, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VERSION, tvb, 80, 4, ENC_LITTLE_ENDIAN);

                            proto_item * disp_func_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION, tvb, 84, 4, ENC_NA);
                            proto_tree * disp_func_tree = proto_item_add_subtree(disp_func_item, ETT_T6_CONF_INFO_DISPLAY_FUNCTION);
                            proto_tree_add_item(disp_func_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_ROTATE, tvb, 84, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_func_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_FUNCTION_RESET, tvb, 84, 4, ENC_LITTLE_ENDIAN);

                            proto_item * disp0_caps_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS, tvb, 88, 4, ENC_NA);
                            proto_tree * disp0_caps_tree = proto_item_add_subtree(disp0_caps_item, ETT_T6_CONF_INFO_DISP0_CAPS);
                            proto_tree_add_item(disp0_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_OFFSET, tvb, 88, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp0_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_VIDEO_MODES_COUNT, tvb, 88, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp0_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_RESERVED, tvb, 88, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp0_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP0_CAPS_LINK_INTERFACES, tvb, 88, 4, ENC_LITTLE_ENDIAN);

                            proto_item * disp1_caps_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS, tvb, 92, 4, ENC_NA);
                            proto_tree * disp1_caps_tree = proto_item_add_subtree(disp1_caps_item, ETT_T6_CONF_INFO_DISP1_CAPS);
                            proto_tree_add_item(disp1_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_OFFSET, tvb, 92, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp1_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_VIDEO_MODES_COUNT, tvb, 92, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp1_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_RESERVED, tvb, 92, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp1_caps_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISP1_CAPS_LINK_INTERFACES, tvb, 92, 4, ENC_LITTLE_ENDIAN);

                            proto_item * disp_intf_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE, tvb, 96, 4, ENC_NA);
                            proto_tree * disp_intf_tree = proto_item_add_subtree(disp_intf_item, ETT_T6_CONF_INFO_DISPLAY_INTERFACE);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_RESERVED, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_LVDS_I2C, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_RESERVED, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVI_I2C, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_TRANSMITTER, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_RESERVED, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DVO_I2C, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_RESERVED, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(disp_intf_tree, HF_T6_CONTROL_REQ_CONF_INFO_DISPLAY_INTERFACE_DAC_I2C, tvb, 96, 4, ENC_LITTLE_ENDIAN);
                            break;
                    }
                }
                break;
            default:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_UNKNOWN_DATA, tvb, 0, -1, ENC_NA);
                break;
        }
    }

    return tvb_captured_length(tvb);
}

static int handle_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, urb_info_t *urb) {
    if (urb->direction) {
        /* BULK 1 IN */
    } else if (!urb->direction) {
        /* BULK 2 OUT */
        conversation_t * conversation = find_or_create_conversation(pinfo);
        bulk_conv_info_t * bulk_conv_info = (bulk_conv_info_t *)conversation_get_proto_data(conversation, PROTO_T6);
        if (!bulk_conv_info) {
            bulk_conv_info = wmem_new(wmem_file_scope(), bulk_conv_info_t);
            bulk_conv_info->last_frame = NULL;
            bulk_conv_info->session_conv_info_by_session_num = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
            bulk_conv_info->frame_info_by_frame_num = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

            conversation_add_proto_data(conversation, PROTO_T6, bulk_conv_info);
        }

        frame_info_t * frame_info = NULL;
        if (!PINFO_FD_VISITED(pinfo)) {
            if ((bulk_conv_info->last_frame == NULL) || (bulk_conv_info->last_frame->frag_len_remaining == 0)) {
                /* Selector */

                /* Create new selector info */
                selector_info_t * selector_info = wmem_new(wmem_file_scope(), selector_info_t);
                selector_info->frame_num = pinfo->num;
                selector_info->session_num = tvb_get_letohl(tvb, 0);
                selector_info->payload_len = tvb_get_letohl(tvb, 4);
                selector_info->dest_addr = tvb_get_letohl(tvb, 8);
                selector_info->frag_len = tvb_get_letohl(tvb, 12);
                selector_info->frag_offset = tvb_get_letohl(tvb, 16);

                /* Create new frame info */
                frame_info = wmem_new(wmem_file_scope(), frame_info_t);
                frame_info->type = SELECTOR;
                frame_info->selector_info = selector_info;
                frame_info->payload_len_remaining = selector_info->payload_len - selector_info->frag_offset;
                frame_info->frag_len_remaining = selector_info->frag_len;

                bulk_conv_info->last_frame = frame_info;

                session_conv_info_t * session_conv_info = wmem_map_lookup(bulk_conv_info->session_conv_info_by_session_num, GUINT_TO_POINTER(selector_info->session_num));
                if (!session_conv_info) {
                    session_conv_info = wmem_new(wmem_file_scope(), session_conv_info_t);
                }
                session_conv_info->last_frame = frame_info;

                wmem_map_insert(bulk_conv_info->session_conv_info_by_session_num, GUINT_TO_POINTER(selector_info->session_num), session_conv_info);
                wmem_map_insert(bulk_conv_info->frame_info_by_frame_num, GUINT_TO_POINTER(pinfo->num), frame_info);
            } else {
                /* Fragment */
                selector_info_t * selector_info = bulk_conv_info->last_frame->selector_info;
                session_conv_info_t * session_conv_info = wmem_map_lookup(bulk_conv_info->session_conv_info_by_session_num, GUINT_TO_POINTER(selector_info->session_num));
                if (session_conv_info) {
                    frame_info_t * last_frame_in_session = session_conv_info->last_frame;

                    /* Create new frame info */
                    frame_info = wmem_new(wmem_file_scope(), frame_info_t);
                    frame_info->type = FRAGMENT;
                    frame_info->selector_info = selector_info;
                    frame_info->payload_len_remaining = last_frame_in_session->payload_len_remaining - tvb_reported_length(tvb);
                    frame_info->frag_len_remaining = last_frame_in_session->frag_len_remaining - tvb_reported_length(tvb);

                    bulk_conv_info->last_frame = frame_info;

                    session_conv_info->last_frame = frame_info;

                    wmem_map_insert(bulk_conv_info->frame_info_by_frame_num, GUINT_TO_POINTER(pinfo->num), frame_info);
                }
            }
        } else {
            frame_info = wmem_map_lookup(bulk_conv_info->frame_info_by_frame_num, GUINT_TO_POINTER(pinfo->num));
        }

        if (!frame_info) {
            return 0;
        }

        if (frame_info->type == SELECTOR) {
            /* Selector */
            proto_tree_add_item(tree, HF_T6_BULK_SESSION_NUM, tvb, 0, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, HF_T6_BULK_SESSION_PAYLOAD_LEN, tvb, 4, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, HF_T6_BULK_SESSION_PAYLOAD_DEST_ADDR, tvb, 8, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_LENGTH, tvb, 12, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree, HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_OFFSET, tvb, 16, 4, ENC_LITTLE_ENDIAN);
        } else {
            /* Fragment */
            selector_info_t * selector_info = frame_info->selector_info;

            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_SELECTOR, tvb, 0, 0, selector_info->frame_num));
            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_NUM, tvb, 0, 0, selector_info->session_num));
            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_PAYLOAD_LEN, tvb, 0, 0, selector_info->payload_len));
            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_PAYLOAD_DEST_ADDR, tvb, 0, 0, selector_info->dest_addr));
            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_LENGTH, tvb, 0, 0, selector_info->frag_len));
            proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_BULK_SESSION_PAYLOAD_FRAGMENT_OFFSET, tvb, 0, 0, selector_info->frag_offset));

            tvbuff_t * next_tvb = NULL;
            if ((selector_info->payload_len > selector_info->frag_len) || (selector_info->frag_len > tvb_reported_length(tvb))) {
                /* Fragmented */
                pinfo->fragmented = true;

                uint32_t calc_frag_offset = selector_info->payload_len - frame_info->payload_len_remaining - tvb_reported_length(tvb);
                bool more_frags = frame_info->payload_len_remaining > 0;

                fragment_head * frag_head = fragment_add_check(&T6_REASSEMBLY_TABLE,
                    tvb, 0, pinfo, selector_info->session_num, NULL,
                    calc_frag_offset, tvb_captured_length(tvb), more_frags);

                next_tvb = process_reassembled_data(tvb, 0, pinfo, "Reassembled Payload", frag_head, &T6_BULK_FRAG_ITEMS, NULL, tree);

                if (frag_head) {
                    /* Reassembled */
                    col_append_str(pinfo->cinfo, COL_INFO, " (Payload Reassembled)");
                } else {
                    /* Failed to reassemble. This can happen when a packet captures less data than was reported, which
                     * seems to be common with captured firmware updates. */
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (Fragment offset %u)", calc_frag_offset);
                }
            } else {
                /* Not fragmented */
                next_tvb = tvb;
            }

            if (next_tvb) {
                proto_tree_add_item(tree, HF_T6_BULK_SESSION_PAYLOAD_DATA, next_tvb, 0, -1, ENC_NA);
            }
        }
    } else {
        return 0;
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

static int dissect_t6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    urb_info_t * urb = (urb_info_t *)data;

    proto_item * t6_tree_item = proto_tree_add_item(tree, PROTO_T6, tvb, 0, -1, ENC_NA);
    proto_tree * t6_tree = proto_item_add_subtree(t6_tree_item, ETT_T6);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trigger 6");

    switch (urb->transfer_type) {
        case URB_CONTROL:
            return handle_control(tvb, pinfo, t6_tree, urb);
        case URB_BULK:
            return handle_bulk(tvb, pinfo, t6_tree, urb);
        case URB_INTERRUPT:
            return handle_interrupt(tvb, pinfo, t6_tree, urb);
        default:
            return 0;
    };
}

void proto_register_trigger6(void) {
    proto_register_subtree_array(ETT, array_length(ETT));

    PROTO_T6 = proto_register_protocol(
        "Magic Control Technology Trigger 6",
        "MCT T6",
        "trigger6"
    );

    reassembly_table_register(&T6_REASSEMBLY_TABLE, &addresses_reassembly_table_functions);
    reassembly_table_register(&T6_CONTROL_CURSOR_UPLOAD_REASSEMBLY_TABLE, &addresses_reassembly_table_functions);

    proto_register_field_array(PROTO_T6, HF_T6_CONTROL, array_length(HF_T6_CONTROL));
    proto_register_field_array(PROTO_T6, HF_T6_CONTROL_CURSOR_UPLOAD_FRAG, array_length(HF_T6_CONTROL_CURSOR_UPLOAD_FRAG));
    proto_register_field_array(PROTO_T6, HF_T6_BULK, array_length(HF_T6_BULK));
    proto_register_field_array(PROTO_T6, HF_T6_BULK_FRAG, array_length(HF_T6_BULK_FRAG));

    T6_HANDLE = register_dissector("trigger6", dissect_t6, PROTO_T6);
}

void proto_reg_handoff_trigger6(void) {
    dissector_add_uint_range("usb.product", (range_t *)&MCT_USB_PID_RANGE, T6_HANDLE);
    dissector_add_for_decode_as("usb.device", T6_HANDLE);
}
