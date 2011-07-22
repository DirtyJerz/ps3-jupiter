
/*
 * PS3 Eurus
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

#ifndef _PS3_EURUS_H
#define _PS3_EURUS_H

#include <linux/types.h>

enum ps3_eurus_cmd {
	PS3_EURUS_CMD_0x29			= 0x29,
	PS3_EURUS_CMD_0x203			= 0x203,
	PS3_EURUS_CMD_0x207			= 0x207,
	PS3_EURUS_CMD_GET_SCAN_RESULTS		= 0x1033,
	PS3_EURUS_CMD_START_SCAN		= 0x1035,
	PS3_EURUS_CMD_SET_MAC_ADDRESS		= 0x1041,
	PS3_EURUS_CMD_0x105F			= 0x105f,
	PS3_EURUS_CMD_0x114F			= 0x114f,
	PS3_EURUS_CMD_0x116F			= 0x116f,
	PS3_EURUS_CMD_0x1171			= 0x1171,
};

struct ps3_eurus_hdr {
	__le16 cmd;
	__le16 tag;
	__le16 status;
	__le16 payload_length;
	u8 res[4];
} __packed;

struct ps3_eurus_cmd_0x29 {
	u8 unknown1;
	u8 unknown2;
};

struct ps3_eurus_cmd_0x203 {
	__le32 unknown;
};

struct ps3_eurus_cmd_0x207 {
	__le32 unknown;
};

struct ps3_eurus_cmd_set_mac_address {
	u8 mac_addr[6];
} __packed;

struct ps3_eurus_cmd_0x116f {
	__le32 unknown;
} __packed;

#endif
