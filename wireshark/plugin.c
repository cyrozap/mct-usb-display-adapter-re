// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  plugin.c - Wireshark dissector for MCT's Trigger 6 protocol.
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

#include <epan/proto.h>

#include "proto_t6.h"


char const plugin_version[] = "0.1.0";
uint32_t const plugin_want_major = 4;
uint32_t const plugin_want_minor = 0;


static void proto_register_all(void) {
    proto_register_trigger6();
}

static void proto_reg_handoff_all(void) {
    proto_reg_handoff_trigger6();
}

static const proto_plugin plugin = {
    .register_protoinfo = proto_register_all,
    .register_handoff = proto_reg_handoff_all,
};

void plugin_register(void) {
    proto_register_plugin(&plugin);
}
