
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
	PS3_EURUS_CMD_SET_AP_SSID		= 0x0005,
	PS3_EURUS_CMD_0xf			= 0x000f,
	PS3_EURUS_CMD_SET_AP_CHANNEL		= 0x0011,
	PS3_EURUS_CMD_SET_ANTENNA		= 0x0029,
	PS3_EURUS_CMD_0x61			= 0x0061,
	PS3_EURUS_CMD_0x65			= 0x0065,
	PS3_EURUS_CMD_GET_FW_VERSION		= 0x0099,
	PS3_EURUS_CMD_0x1dd			= 0x01dd,
	PS3_EURUS_CMD_0x1ed			= 0x01ed,
	PS3_EURUS_CMD_GET_HW_REVISION		= 0x01fb,
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
	PS3_EURUS_CMD_GET_RSSI			= 0x103d,
	PS3_EURUS_CMD_SET_MAC_ADDR		= 0x1041,
	PS3_EURUS_CMD_0x105f			= 0x105f,
	PS3_EURUS_CMD_0x1109			= 0x1109,
	PS3_EURUS_CMD_0x110b			= 0x110b,
	PS3_EURUS_CMD_0x110d			= 0x110d,
	PS3_EURUS_CMD_0x114f			= 0x114f,
	PS3_EURUS_CMD_0x115b			= 0x115b,
	PS3_EURUS_CMD_SET_MCAST_ADDR_FILTER	= 0x1161,
	PS3_EURUS_CMD_GET_MCAST_ADDR_FILTER	= 0x1165,
	PS3_EURUS_CMD_0x116f			= 0x116f,
	PS3_EURUS_CMD_GET_MAC_ADDR		= 0x1117,
	PS3_EURUS_CMD_0x1171			= 0x1171,
};

enum ps3_eurus_cmd_status {
	PS3_EURUS_CMD_OK			= 0x0001,
};

enum ps3_eurus_event_type {
	PS3_EURUS_EVENT_TYPE_0x40		= 0x00000040,
	PS3_EURUS_EVENT_TYPE_0x80		= 0x00000080,
	PS3_EURUS_EVENT_TYPE_0x400		= 0x00000400,
};

enum ps3_eurus_event_id {
	PS3_EURUS_EVENT_DEVICE_READY		= 0x00000001,

	/* event type 0x80 */

	PS3_EURUS_EVENT_BEACON_LOST		= 0x00000001,
	PS3_EURUS_EVENT_CONNECTED		= 0x00000002,
	PS3_EURUS_EVENT_SCAN_COMPLETED		= 0x00000004,
	PS3_EURUS_EVENT_WPA_CONNECTED		= 0x00000020,
	PS3_EURUS_EVENT_WPA_ERROR		= 0x00000040,

	PS3_EURUS_EVENT_DEAUTH			= 0x00000001,
};

enum ps3_eurus_opmode {
	PS3_EURUS_OPMODE_11B			= 0x00,
	PS3_EURUS_OPMODE_11G			= 0x01,
	PS3_EURUS_OPMODE_11BG			= 0x02,
};

enum ps3_eurus_wep_security {
	PS3_EURUS_WEP_SECURITY_NONE		= 0x00,
	PS3_EURUS_WEP_SECURITY_40BIT		= 0x01,
	PS3_EURUS_WEP_SECURITY_104BIT		= 0x02,
};

enum ps3_eurus_wpa_security {
	PS3_EURUS_WPA_SECURITY_WPA		= 0x00,
	PS3_EURUS_WPA_SECURITY_WPA2		= 0x01,
};

enum ps3_eurus_wpa_psk_type {
	PS3_EURUS_WPA_PSK_PASSPHRASE		= 0x00,
	PS3_EURUS_WPA_PSK_BIN			= 0x01,
};

enum ps3_eurus_wpa_cipher_suite {
	PS3_EURUS_WPA_CIPHER_SUITE_WPA_TKIP	= 0x0050f202,
	PS3_EURUS_WPA_CIPHER_SUITE_WPA_AES	= 0x0050f204,
	PS3_EURUS_WPA_CIPHER_SUITE_WPA2_TKIP	= 0x000fac02,
	PS3_EURUS_WPA_CIPHER_SUITE_WPA2_AES	= 0x000fac04,
};

enum ps3_eurus_wpa_akm_suite {
	PS3_EURUS_WPA_AKM_SUITE_WPA_PSK		= 0x0050f202,
	PS3_EURUS_WPA_AKM_SUITE_WPA2_PSK	= 0x000fac02,
};

struct ps3_eurus_cmd_hdr {
	__le16 id;			/* enum ps3_eurus_cmd_id */
	__le16 tag;
	__le16 status;			/* enum ps3_eurus_cmd_status */
	__le16 payload_length;
	u8 res[4];
} __packed;

struct ps3_eurus_cmd_set_ap_ssid {
	u8 ssid[32];
	u8 res[4];
} __packed;

struct ps3_eurus_cmd_0xf {
	u8 unknown[35];
	__le16 channel;
} __packed;

struct ps3_eurus_cmd_set_ap_channel {
	u8 channel;
} __packed;

struct ps3_eurus_cmd_set_antenna {
	u8 unknown1;
	u8 unknown2;
} __packed;

struct ps3_eurus_cmd_get_fw_version {
	u8 version[62];
} __packed;

struct ps3_eurus_cmd_0x61 {
	u8 unknown;
} __packed;

struct ps3_eurus_cmd_0x65 {
	u8 unknown;
} __packed;

struct ps3_eurus_cmd_0x1dd {
	u8 unknown;
} __packed;

struct ps3_eurus_cmd_0x1ed {
	__le32 unknown1;
	u8 unknown2;
	u8 unknown3;
	u8 unknown4;
	u8 unknown5;
	u8 unknown6;
	u8 unknown7;
	u8 unknown8;
} __packed;

struct ps3_eurus_cmd_get_hw_revision {
	u8 unknown[4];
} __packed;

struct ps3_eurus_cmd_0x203 {
	__le32 unknown;
} __packed;

struct ps3_eurus_cmd_0x207 {
	__le32 unknown;
} __packed;

struct ps3_eurus_cmd_associate {
	u8 unknown;
} __packed;

struct ps3_eurus_cmd_common_config {
	u8 unknown1;
	u8 unknown2;
	u8 opmode;	/* enum ps3_eurus_opmode */
	u8 unknown3;
	u8 bssid[6];
	u8 ie[0];
} __packed;

struct ps3_eurus_cmd_wep_config {
	u8 unknown1;
	u8 security;		/* enum ps3_eurus_wep_security */
	__le16 unknown2;
	u8 key[4][16];
} __packed;

struct ps3_eurus_cmd_wpa_config {
	u8 unknown;
	u8 security;			/* enum ps3_eurus_wpa_security */
	u8 psk_type;			/* enum ps3_eurus_wpa_psk_type */
	u8 psk[64];
	__be32 group_cipher_suite;	/* enum ps3_eurus_wpa_cipher_suite */
	__be32 pairwise_cipher_suite;	/* enum ps3_eurus_wpa_cipher_suite */
	__be32 akm_suite;		/* enum ps3_eurus_wpa_akm_suite */
} __packed;

struct ps3_eurus_cmd_0x1031 {
	u8 unknown1;
	u8 unknown2;
} __packed;

struct ps3_eurus_scan_result {
	__le16 length;
	u8 bssid[6];
	u8 rssi;
	u8 unknown[9];
	u8 ie[0];
} __packed;

struct ps3_eurus_cmd_get_scan_results {
	u8 count;
	struct ps3_eurus_scan_result result[0];
} __packed;

struct ps3_eurus_cmd_diassociate {
	u8 unknown;
} __packed;

struct ps3_eurus_cmd_set_mac_addr {
	u8 mac_addr[6];
} __packed;

struct ps3_eurus_cmd_get_rssi {
	u8 res[10];
	u8 rssi;
} __packed;

struct ps3_eurus_cmd_0x105f {
	__le16 channel_info;
	u8 mac_addr[6];
	u8 unknown1;
	u8 unknown2;
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

struct ps3_eurus_cmd_mcast_addr_filter {
	__le32 word[8];
} __packed;

struct ps3_eurus_cmd_0x116f {
	__le32 unknown;
} __packed;

struct ps3_eurus_cmd_get_mac_addr {
	__le16 count;	/* number of MAC addresses */
	u8 mac_addr[0];
} __packed;

struct ps3_eurus_event_hdr {
	__le32 type;			/* enum ps3_eurus_event_type */
	__le32 id;			/* enum ps3_eurus_event_id */
	__le32 unknown1;
	__le32 payload_length;
	__le32 unknown2;
} __packed;

struct ps3_eurus_event {
	struct ps3_eurus_event_hdr hdr;
	u8 payload[44];
} __packed;

#endif
