# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright (C) 2023  Forest Crossman <cyrozap@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


CFLAGS := $(shell pkg-config --cflags glib-2.0) -I/usr/include/wireshark -std=c17 -fPIC -Wall -Wpedantic -Werror -O2
LDFLAGS := -lwireshark


all: mct_trigger.so

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

mct_trigger.so: plugin.o proto_t6.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^

install: mct_trigger.so
	install -Dm755 $< $(HOME)/.local/lib/wireshark/plugins/4.0/epan/$<

link: mct_trigger.so
	ln -s $(CURDIR)/$< $(HOME)/.local/lib/wireshark/plugins/4.0/epan/$<

clean:
	rm -f *.o *.so


.PHONY: all clean install link
