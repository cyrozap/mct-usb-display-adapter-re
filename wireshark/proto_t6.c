// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_t6.c - Wireshark dissector for MCT's Trigger 6 protocol.
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
#include <epan/packet.h>
#include <epan/proto.h>

#include "proto_t6.h"


static const int CTRL_BREQ_OFFSET = 0;
static const int CTRL_WVAL_OFFSET = 1;
static const int CTRL_WIDX_OFFSET = 3;
static const int CTRL_WLEN_OFFSET = 5;
static const int CTRL_SETUP_DATA_OFFSET = 7;

typedef struct bigger_range_s {
    guint nranges;
    range_admin_t ranges[2];
} bigger_range_t;

static const uint32_t MCT_USB_VID = 0x0711;
static const uint32_t INSIGNIA_USB_VID = 0x19FF;

static bigger_range_t MCT_USB_PID_RANGE = {
    .nranges = 2,
    .ranges = {
        { .low = (MCT_USB_VID << 16) | 0x5600, .high = (MCT_USB_VID << 16) | 0x561F },
        { .low = (INSIGNIA_USB_VID << 16) | 0x5600, .high = (INSIGNIA_USB_VID << 16) | 0x561F },
    },
};

static const value_string INFO_FIELDS[] = {
    { 0, "Hardware Platform" },
    { 1, "Boot Code Version" },
    { 2, "Image Code Version" },
    { 3, "Project Code" },
    { 4, "Vendor Command Version" },
    { 5, "Serial Number" },
    { 0, NULL },
};

static const value_string CONTROL_REQS[] = {
    { 0x80, "Get EDID block" },
    { 0x87, "Get connector status?" },
    { 0x89, "Get video modes" },
    { 0xb0, "Get adapter info field" },
    { 0xb1, "Get adapter session info?" },
    { 0xb3, "Get adapter config blob?" },
    { 0, NULL },
};

static const value_string CONF_TYPES[] = {
    { 0x4C414855, "UHAL" },
    { 0x50534944, "DISP" },
    { 0x5F445541, "AUD_" },
    { 0x4F495047, "GPIO" },
    { 0, NULL },
};

static dissector_handle_t T6_HANDLE = NULL;

static int PROTO_T6 = -1;

static int HF_T6_CONTROL_REQ = -1;

static int HF_T6_CONTROL_REQ_WVAL = -1;
static int HF_T6_CONTROL_REQ_WIDX = -1;
static int HF_T6_CONTROL_REQ_WLEN = -1;
static int HF_T6_CONTROL_REQ_UNKNOWN_DATA = -1;

static int HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET = -1;
static int HF_T6_CONTROL_REQ_EDID_BLOCK_DATA = -1;

static int HF_T6_CONTROL_REQ_VIDEO_MODES_OUTPUT_IDX = -1;
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
static int HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_8 = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_9 = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_10 = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_0 = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_1 = -1;
static int HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_11 = -1;

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
    { &HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET,
        { "EDID byte offset", "trigger6.control.edid.byte_offset",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_EDID_BLOCK_DATA,
        { "EDID block data", "trigger6.control.edid.block_data",
        FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODES_OUTPUT_IDX,
        { "Output index", "trigger6.control.video_modes.output_index",
        FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL }
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
        { "Video mode data", "trigger6.control.video_modes.video_mode",
        FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_PIXEL_CLK_KHZ,
        { "Pixel clock (kHz)", "trigger6.control.video_modes.video_mode.pixel_clk_khz",
        FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_REFRESH_RATE_HZ,
        { "Refresh rate (HZ)", "trigger6.control.video_modes.video_mode.refresh_rate_hz",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_TOTAL_PIXELS,
        { "Line total pixels", "trigger6.control.video_modes.video_mode.line_total_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PIXELS,
        { "Line active pixels", "trigger6.control.video_modes.video_mode.line_active_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_ACTIVE_PLUS_FRONT_PORCH_PIXELS,
        { "Line active plus front porch pixels", "trigger6.control.video_modes.video_mode.line_active_plus_front_porch_pixels",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_LINE_SYNC_WIDTH,
        { "Line sync width", "trigger6.control.video_modes.video_mode.line_sync_width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_TOTAL_LINES,
        { "Frame total lines", "trigger6.control.video_modes.video_mode.frame_total_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_LINES,
        { "Frame active lines", "trigger6.control.video_modes.video_mode.frame_active_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_ACTIVE_PLUS_FRONT_PORCH_LINES,
        { "Frame active plus front porch lines", "trigger6.control.video_modes.video_mode.frame_active_plus_front_porch_lines",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_FRAME_SYNC_WIDTH,
        { "Frame sync width", "trigger6.control.video_modes.video_mode.frame_sync_width",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_8,
        { "Unknown 8", "trigger6.control.video_modes.video_mode.unk8",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_9,
        { "Unknown 9", "trigger6.control.video_modes.video_mode.unk9",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_10,
        { "Unknown 10", "trigger6.control.video_modes.video_mode.unk10",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_0,
        { "Sync polarity 0", "trigger6.control.video_modes.video_mode.sync_polarity_0",
        FT_BOOLEAN, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_1,
        { "Sync polarity 1", "trigger6.control.video_modes.video_mode.sync_polarity_1",
        FT_BOOLEAN, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_11,
        { "Unknown 11", "trigger6.control.video_modes.video_mode.unk11",
        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_IDX,
        { "Info field", "trigger6.control.info_field.index",
        FT_UINT16, BASE_HEX, VALS(INFO_FIELDS), 0x0, NULL, HFILL }
    },
    { &HF_T6_CONTROL_REQ_INFO_FIELD_HW_PLAT,
        { "Hardware Platform", "trigger6.control.info_field.hw_plat",
        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
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
};

typedef struct video_mode_s {
    int * hf;
    int size;
} video_mode_t;

static const video_mode_t video_mode_fields[] = {
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
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_8, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_9, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_10, 2 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_0, 1 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_SYNC_POLARITY_1, 1 },
    { &HF_T6_CONTROL_REQ_VIDEO_MODE_UNK_11, 2 },
};

static int ETT_T6 = -1;
static int ETT_T6_VIDEO_MODES = -1;
static int ETT_T6_VIDEO_MODE = -1;
static int * const ETT[] = {
    &ETT_T6,
    &ETT_T6_VIDEO_MODES,
    &ETT_T6_VIDEO_MODE,
};

static int handle_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_conv_info_t  *usb_conv_info) {
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

    if (setup_not_completion) {
        proto_tree_add_item(tree, HF_T6_CONTROL_REQ, tvb, CTRL_BREQ_OFFSET, 1, ENC_LITTLE_ENDIAN);
    } else {
        proto_item * it = proto_tree_add_uint(tree, HF_T6_CONTROL_REQ, tvb, 0, 0, bRequest);
        proto_item_set_generated(it);
    }

    switch (bRequest) {
        case 0x80:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_EDID_BYTE_OFFSET, tvb, 0, 0, wValue));
            }
            break;
        case 0x89:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_OUTPUT_IDX, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_BYTE_OFFSET, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_OUTPUT_IDX, tvb, 0, 0, wValue));
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_BYTE_OFFSET, tvb, 0, 0, wIndex));
            }
            break;
        case 0xb0:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_IDX, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_INFO_FIELD_IDX, tvb, 0, 0, wIndex));
            }
            break;
        case 0xb1:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_NUM, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_SESSION_INFO_NUM, tvb, 0, 0, wIndex));
            }
            break;
        default:
            if (setup_not_completion) {
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_WVAL, tvb, CTRL_WVAL_OFFSET, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_WIDX, tvb, CTRL_WIDX_OFFSET, 2, ENC_LITTLE_ENDIAN);
            } else {
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_WVAL, tvb, 0, 0, wValue));
                proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_WIDX, tvb, 0, 0, wIndex));
            }
            break;
    }

    if (setup_not_completion) {
        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_WLEN, tvb, CTRL_WLEN_OFFSET, 2, ENC_LITTLE_ENDIAN);
    } else {
        proto_item_set_generated(proto_tree_add_uint(tree, HF_T6_CONTROL_REQ_WLEN, tvb, 0, 0, wLength));
    }

    if (!in_not_out && setup_not_completion) {
        /* OUT Setup */
        // printf("CONTROL OUT: 0x%02x\n", bRequest);
        switch (bRequest) {
            case 0x12:
                {
                    int field_offset = 0;
                    for (int i = 0; i < array_length(video_mode_fields); i++) {
                        proto_tree_add_item(tree, *video_mode_fields[i].hf, tvb, CTRL_SETUP_DATA_OFFSET+field_offset, video_mode_fields[i].size, ENC_LITTLE_ENDIAN);
                        field_offset += video_mode_fields[i].size;
                    }
                }
                break;
        }
    } else if (in_not_out && !setup_not_completion) {
        /* IN Completion */
        switch (bRequest) {
            case 0x80:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_EDID_BLOCK_DATA, tvb, 0, 128, ENC_NA);
                break;
            case 0x89:
                {
                    proto_item * video_modes_item = proto_tree_add_item(tree, HF_T6_CONTROL_REQ_VIDEO_MODES_DATA, tvb, 0, -1, ENC_NA);
                    proto_tree * video_modes_tree = proto_item_add_subtree(video_modes_item, ETT_T6_VIDEO_MODES);
                    for (int offset = 0; offset < tvb_reported_length(tvb); offset += 32) {
                        proto_item * video_mode_item = proto_tree_add_item(video_modes_tree, HF_T6_CONTROL_REQ_VIDEO_MODE, tvb, offset, 32, ENC_NA);
                        proto_tree * video_mode_tree = proto_item_add_subtree(video_mode_item, ETT_T6_VIDEO_MODE);

                        int field_offset = 0;
                        for (int i = 0; i < array_length(video_mode_fields); i++) {
                            proto_tree_add_item(video_mode_tree, *video_mode_fields[i].hf, tvb, offset+field_offset, video_mode_fields[i].size, ENC_LITTLE_ENDIAN);
                            field_offset += video_mode_fields[i].size;
                        }
                    }
                }
                break;
            case 0xb0:
                switch (wIndex) {
                    case 0:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_HW_PLAT, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case 1:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_BOOT_CODE, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case 2:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_IMAGE_CODE, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case 3:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_PROJECT_CODE, tvb, 0, -1, ENC_ASCII);
                        break;
                    case 4:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_VENDOR_CMD_VER, tvb, 0, 4, ENC_LITTLE_ENDIAN);
                        break;
                    case 5:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_INFO_FIELD_SERIAL, tvb, 0, -1, ENC_NA);
                        break;
                    default:
                        proto_tree_add_item(tree, HF_T6_CONTROL_REQ_UNKNOWN_DATA, tvb, 0, -1, ENC_NA);
                        break;
                }
                break;
            case 0xb1:
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_VID, tvb, 0, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_PID, tvb, 2, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(tree, HF_T6_CONTROL_REQ_SESSION_INFO_VDEV_NAME, tvb, 4, 64, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
                break;
            case 0xb3:
                {
                    uint32_t conf_type = 0;
                    proto_tree_add_item_ret_uint(tree, HF_T6_CONTROL_REQ_CONF_INFO_TYPE, tvb, 0, 4, ENC_LITTLE_ENDIAN, &conf_type);
                    proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_SIZE, tvb, 4, 4, ENC_LITTLE_ENDIAN);
                    switch (conf_type) {
                        case 0x50534944:
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_VID, tvb, 12, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_PID, tvb, 14, 2, ENC_LITTLE_ENDIAN);
                            proto_tree_add_item(tree, HF_T6_CONTROL_REQ_CONF_INFO_VDEV_NAME, tvb, 16, 64, ENC_UTF_16 | ENC_LITTLE_ENDIAN);
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

static int handle_bulk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_conv_info_t  *usb_conv_info) {
    if (usb_conv_info->endpoint == 1 && usb_conv_info->direction) {
        /* BULK 1 IN */
    } else if (usb_conv_info->endpoint == 2 && !usb_conv_info->direction) {
        /* BULK 2 OUT */
    } else {
        return 0;
    }

    return tvb_captured_length(tvb);
}

static int handle_interrupt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, usb_conv_info_t  *usb_conv_info) {
    /* INTERRUPT IN */

    return tvb_captured_length(tvb);
}

static int dissect_t6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    usb_conv_info_t  *usb_conv_info = (usb_conv_info_t *)data;

    proto_item * t6_tree_item = proto_tree_add_item(tree, PROTO_T6, tvb, 0, -1, ENC_NA);
    proto_tree * t6_tree = proto_item_add_subtree(t6_tree_item, ETT_T6);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Trigger 6");

    switch (usb_conv_info->endpoint) {
        case 0:
            return handle_control(tvb, pinfo, t6_tree, usb_conv_info);
        case 1:
        case 2:
            return handle_bulk(tvb, pinfo, t6_tree, usb_conv_info);
        case 3:
            if (!usb_conv_info->direction) {
                return 0;
            }
            return handle_interrupt(tvb, pinfo, t6_tree, usb_conv_info);;
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

    proto_register_field_array(PROTO_T6, HF_T6_CONTROL, array_length(HF_T6_CONTROL));

    T6_HANDLE = register_dissector("trigger6", dissect_t6, PROTO_T6);
}

void proto_reg_handoff_trigger6(void) {
    dissector_add_uint_range("usb.product", (range_t *)&MCT_USB_PID_RANGE, T6_HANDLE);
    dissector_add_for_decode_as("usb.device", T6_HANDLE);
}
