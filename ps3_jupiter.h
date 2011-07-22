
/*
 * PS3 Jupiter
 *
 * Copyright (C) 2011 glevand <geoffrey.levand@mail.ru>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published
 * by the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _PS3_JUPITER_H
#define _PS3_JUPITER_H

#include "ps3_eurus.h"

struct ps3_jupiter_event {
	u32 unknown1;
	u32 unknown2;
	u32 unknown3;
	u32 unknown4;
	u8 res[48];
};

struct ps3_jupiter_event_listener {
	struct list_head list;
	void (*function)(struct ps3_jupiter_event_listener *listener,
		struct ps3_jupiter_event *event);
	unsigned long data;
};

int ps3_jupiter_register_event_listener(struct ps3_jupiter_event_listener *listener);

int ps3_jupiter_unregister_event_listener(struct ps3_jupiter_event_listener *listener);

int ps3_jupiter_exec_eurus_cmd(enum ps3_eurus_cmd cmd,
	void *payload, unsigned int payload_length,
	unsigned int *response_status,
	unsigned int *response_length, void *response);

#endif
