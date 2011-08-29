
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

enum ps3_eurus_cmd_id {
	PS3_EURUS_CMD_SET_ANTENNA		= 0x0029,
	PS3_EURUS_CMD_0x203			= 0x0203,
	PS3_EURUS_CMD_0x207			= 0x0207,
	PS3_EURUS_CMD_ASSOCIATE			= 0x1001,
	PS3_EURUS_CMD_GET_COMMON_CONFIG		= 0x1003,
	PS3_EURUS_CMD_SET_COMMON_CONFIG		= 0x1005,
	PS3_EURUS_CMD_GET_WEP_CONFIG		= 0x1013,
	PS3_EURUS_CMD_SET_WEP_CONFIG		= 0x1015,
	PS3_EURUS_CMD_GET_WPA_CONFIG		= 0x1017,
	PS3_EURUS_CMD_SET_WPA_CONFIG		= 0x1019,
	PS3_EURUS_CMD_0x1031			= 0x1031,
	PS3_EURUS_CMD_GET_SCAN_RESULTS		= 0x1033,
	PS3_EURUS_CMD_START_SCAN		= 0x1035,
	PS3_EURUS_CMD_DISASSOCIATE		= 0x1037,
	PS3_EURUS_CMD_SET_MAC_ADDR		= 0x1041,
	PS3_EURUS_CMD_0x105f			= 0x105f,
	PS3_EURUS_CMD_0x1109			= 0x1109,
	PS3_EURUS_CMD_0x110b			= 0x110b,
	PS3_EURUS_CMD_0x110d			= 0x110d,
	PS3_EURUS_CMD_0x114f			= 0x114f,
	PS3_EURUS_CMD_0x115b			= 0x115b,
	PS3_EURUS_CMD_0x1161			= 0x1161,
	PS3_EURUS_CMD_0x116f			= 0x116f,
	PS3_EURUS_CMD_GET_MAC_ADDR		= 0x1117,
	PS3_EURUS_CMD_0x1171			= 0x1171,
};

enum ps3_eurus_event_id {
	PS3_EURUS_EVENT_DEVICE_READY		= 0x00000001,

	PS3_EURUS_EVENT_BEACON_LOST		= 0x00000001,
	PS3_EURUS_EVENT_CONNECTED		= 0x00000002,
	PS3_EURUS_EVENT_SCAN_COMPLETED		= 0x00000004,
	PS3_EURUS_EVENT_WPA_CONNECTED		= 0x00000020,
	PS3_EURUS_EVENT_WPA_ERROR		= 0x00000040,

	PS3_EURUS_EVENT_DEAUTH			= 0x00000001,
};

struct ps3_eurus_cmd_hdr {
	__le16 id;
	__le16 tag;
	__le16 status;
	__le16 payload_length;
	u8 res[4];
} __packed;

struct ps3_eurus_cmd_set_antenna {
	u8 unknown1;
	u8 unknown2;
};

struct ps3_eurus_cmd_0x203 {
	__le32 unknown;
};

struct ps3_eurus_cmd_0x207 {
	__le32 unknown;
};

struct ps3_eurus_cmd_0x1031 {
	u8 unknown;
	u8 res;
} __packed;

struct ps3_eurus_cmd_set_mac_addr {
	u8 mac_addr[6];
} __packed;

struct ps3_eurus_cmd_0x105f {
	__le16 channel_info;
	u8 mac_addr[6];
	u8 unknown2;
	u8 unknown3;
} __packed;

struct ps3_eurus_cmd_0x1109 {
	__le16 unknown1;
	__le16 unknown2;
	__le16 unknown3;
	__le16 unknown4;
	__le16 unknown5;
	u8 res[2];
	__le16 unknown6;
	__le16 unknown7;
	u8 unknown8[6];
} __packed;

struct ps3_eurus_cmd_0x110b {
	__le32 unknown1;
	u8 res[4];
	__le32 unknown2;
} __packed;

struct ps3_eurus_cmd_0x110d {
	u8 res1[12];
	__le32 unknown1;
	__le32 unknown2;
	__le32 unknown3;
	__le32 unknown4;
	__le32 unknown5;
	__le32 unknown6;
	__le32 unknown7;
	u8 res2[88];
} __packed;

struct ps3_eurus_cmd_0x114f {
	u8 res[1304];
} __packed;

struct ps3_eurus_cmd_0x115b {
	__le32 unknown;
	u8 mac_addr[6];
	u8 res[84];
} __packed;

struct ps3_eurus_cmd_0x1161 {
	u8 res[28];
	__be32 unknown;
} __packed;

struct ps3_eurus_cmd_0x116f {
	__le32 unknown;
} __packed;

struct ps3_eurus_cmd_get_mac_addr {
	__le16 count;
	u8 mac_addr[0];
} __packed;

struct ps3_eurus_event_hdr {
	__le32 type;
	__le32 id;
	__le32 unknown1;
	__le32 payload_length;
	__le32 unknown2;
};

struct ps3_eurus_event {
	struct ps3_eurus_event_hdr hdr;
	u8 payload[44];
};

#endif
