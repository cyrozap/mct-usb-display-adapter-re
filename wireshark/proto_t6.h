// SPDX-License-Identifier: GPL-2.0-or-later

/*
 *  proto_t6.h - Wireshark dissector for MCT's Trigger 6 protocol.
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

#ifndef PROTO_T6_H_INCLUDED
#define PROTO_T6_H_INCLUDED

void proto_register_trigger6(void);
void proto_reg_handoff_trigger6(void);

#endif // PROTO_T6_H_INCLUDED
