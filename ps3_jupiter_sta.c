
/*
 * PS3 Jupiter STA
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/usb.h>

#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_arp.h>
#include <linux/ieee80211.h>
#include <net/iw_handler.h>

#include "ps3_eurus.h"
#include "ps3_jupiter.h"

#define PS3_JUPITER_STA_CMD_BUFSIZE		2048

#define PS3_JUPITER_STA_EP			0x6

#define PS3_JUPITER_STA_WEP_KEYS		4

#define PS3_JUPITER_STA_WPA_PSK_LENGTH		32

#define PS3_JUPITER_STA_RX_URBS			4

enum ps3_jupiter_sta_scan_status {
	PS3_JUPITER_STA_SCAN_INVALID = 0,
	PS3_JUPITER_STA_SCAN_IN_PROGRESS,
	PS3_JUPITER_STA_SCAN_OK
};

enum ps3_jupiter_sta_assoc_status {
	PS3_JUPITER_STA_ASSOC_INVALID = 0,
	PS3_JUPITER_STA_ASSOC_IN_PROGRESS,
	PS3_JUPITER_STA_ASSOC_OK
};

enum ps3_jupiter_sta_config_bits {
	PS3_JUPITER_STA_CONFIG_ESSID_SET = 0,
	PS3_JUPITER_STA_CONFIG_BSSID_SET,
	PS3_JUPITER_STA_CONFIG_WPA_PSK_SET
};

enum ps3_jupiter_sta_opmode {
	PS3_JUPITER_STA_OPMODE_11B = 0,
	PS3_JUPITER_STA_OPMODE_11G,
	PS3_JUPITER_STA_OPMODE_11BG
};

enum ps3_jupiter_sta_auth_mode {
	PS3_JUPITER_STA_AUTH_OPEN = 0,
	PS3_JUPITER_STA_AUTH_SHARED_KEY
};

enum ps3_jupiter_sta_wpa_mode {
	PS3_JUPITER_STA_WPA_MODE_NONE = 0,
	PS3_JUPITER_STA_WPA_MODE_WPA,
	PS3_JUPITER_STA_WPA_MODE_WPA2
};

enum ps3_jupiter_sta_cipher_mode {
	PS3_JUPITER_STA_CIPHER_NONE = 0,
	PS3_JUPITER_STA_CIPHER_WEP,
	PS3_JUPITER_STA_CIPHER_TKIP,
	PS3_JUPITER_STA_CIPHER_AES
};

struct ps3_jupiter_sta_scan_result {
	struct list_head list;

	u8 bssid[6];
	u16 capability;
	u8 rssi;

	u8 *essid_ie;
	u8 *ds_param_set_ie;
	u8 *supp_rates_ie;
	u8 *ext_supp_rates_ie;
	u8 *rsn_ie;
	u8 *wpa_ie;

	unsigned int ie_length;
	u8 ie[0];
};

struct ps3_jupiter_sta_dev {
	struct net_device *netdev;

	struct usb_device *udev;

	spinlock_t lock;

	struct iw_public_data wireless_data;
	struct iw_statistics wireless_stat;

	struct ps3_jupiter_event_listener event_listener;

	u16 channel_info;

	struct mutex scan_lock;
	struct list_head scan_result_list;
	enum ps3_jupiter_sta_scan_status scan_status;
	struct completion scan_done_comp;

	unsigned long config_status;

	enum ps3_jupiter_sta_opmode opmode;

	enum ps3_jupiter_sta_auth_mode auth_mode;

	enum ps3_jupiter_sta_wpa_mode wpa_mode;
	enum ps3_jupiter_sta_cipher_mode group_cipher_mode;
	enum ps3_jupiter_sta_cipher_mode pairwise_cipher_mode;

	u8 essid[IW_ESSID_MAX_SIZE];
	unsigned int essid_length;

	u8 bssid[ETH_ALEN];
	u8 active_bssid[ETH_ALEN];

	unsigned long key_config_status;
	u8 key[PS3_JUPITER_STA_WEP_KEYS][IW_ENCODING_TOKEN_MAX];
	unsigned int key_length[PS3_JUPITER_STA_WEP_KEYS];
	unsigned int curr_key_index;

	u8 psk[PS3_JUPITER_STA_WPA_PSK_LENGTH];

	struct mutex assoc_lock;
	struct workqueue_struct *assoc_queue;
	struct delayed_work assoc_work;
	enum ps3_jupiter_sta_assoc_status assoc_status;
	struct completion assoc_done_comp;

	struct urb *rx_urb[PS3_JUPITER_STA_RX_URBS];
};

static const int ps3_jupiter_sta_channel_freq[] = {
	2412,
	2417,
	2422,
	2427,
	2432,
	2437,
	2442,
	2447,
	2452,
	2457,
	2462,
	2467,
	2472,
	2484
};

static const int ps3_jupiter_sta_bitrate[] = {
	1000000,
	2000000,
	5500000,
	11000000,
	6000000,
	9000000,
	12000000,
	18000000,
	24000000,
	36000000,
	48000000,
	54000000
};

static void ps3_jupiter_sta_free_scan_results(struct ps3_jupiter_sta_dev *jstad);

static int ps3_jupiter_sta_start_scan(struct ps3_jupiter_sta_dev *jstad,
	u8 *essid, size_t essid_length, u16 channels);

static char *ps3_jupiter_sta_translate_scan_result(struct ps3_jupiter_sta_dev *jstad,
	struct ps3_jupiter_sta_scan_result *scan_result,
	struct iw_request_info *info, char *stream, char *ends);

static void ps3_jupiter_sta_start_assoc(struct ps3_jupiter_sta_dev *jstad);

static int ps3_jupiter_sta_disassoc(struct ps3_jupiter_sta_dev *jstad);

static void ps3_jupiter_sta_reset_state(struct ps3_jupiter_sta_dev *jstad);

/*
 * ps3_jupiter_sta_send_iw_ap_event
 */
static void ps3_jupiter_sta_send_iw_ap_event(struct ps3_jupiter_sta_dev *jstad, u8 *bssid)
{
	union iwreq_data iwrd;

	memset(&iwrd, 0, sizeof(iwrd));

	if (bssid)
		memcpy(iwrd.ap_addr.sa_data, bssid, ETH_ALEN);

	iwrd.ap_addr.sa_family = ARPHRD_ETHER;

	wireless_send_event(jstad->netdev, SIOCGIWAP, &iwrd, NULL);
}

/*
 * ps3_jupiter_sta_get_name
 */
static int ps3_jupiter_sta_get_name(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	strcpy(wrqu->name, "IEEE 802.11bg");

	return 0;
}

/*
 * ps3_jupiter_sta_get_nick
 */
static int ps3_jupiter_sta_get_nick(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	strcpy(extra, "ps3_jupiter_sta");
	wrqu->data.length = strlen(extra);
	wrqu->data.flags = 1;

	return 0;
}

/*
 * ps3_jupiter_sta_get_range
 */
static int ps3_jupiter_sta_get_range(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_point *point = &wrqu->data;
	struct iw_range *range = (struct iw_range *) extra;
	unsigned int i, chan;

	point->length = sizeof(struct iw_range);
	memset(range, 0, sizeof(struct iw_range));

	range->we_version_compiled = WIRELESS_EXT;
	range->we_version_source = 22;

	for (i = 0, chan = 0;
	     (i < ARRAY_SIZE(ps3_jupiter_sta_channel_freq)) && (chan < IW_MAX_FREQUENCIES); i++) {
		if (jstad->channel_info & (1 << i)) {
			range->freq[chan].i = i + 1;
			range->freq[chan].m = ps3_jupiter_sta_channel_freq[i];
			range->freq[chan].e = 6;
			chan++;
		}
	}

	range->num_frequency = chan;
	range->old_num_frequency = chan;
	range->num_channels = chan;
	range->old_num_channels = chan;

	for (i = 0; i < ARRAY_SIZE(ps3_jupiter_sta_bitrate); i++)
		range->bitrate[i] = ps3_jupiter_sta_bitrate[i];
	range->num_bitrates = i;

	range->max_qual.qual = 100;
	range->max_qual.level = 100;
	range->avg_qual.qual = 50;
	range->avg_qual.level = 50;
	range->sensitivity = 0;

	IW_EVENT_CAPA_SET_KERNEL(range->event_capa);
	IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWAP);
	IW_EVENT_CAPA_SET(range->event_capa, SIOCGIWSCAN);

	range->enc_capa = IW_ENC_CAPA_WPA | IW_ENC_CAPA_WPA2 |
	    IW_ENC_CAPA_CIPHER_TKIP | IW_ENC_CAPA_CIPHER_CCMP |
	    IW_ENC_CAPA_4WAY_HANDSHAKE;

	range->encoding_size[0] = 5;
	range->encoding_size[1] = 13;
	range->encoding_size[2] = 32;
	range->num_encoding_sizes = 3;
	range->max_encoding_tokens = 4;

	range->scan_capa = IW_SCAN_CAPA_ESSID | IW_SCAN_CAPA_CHANNEL;

	return 0;
}

/*
 * ps3_jupiter_sta_set_mode
 */
static int ps3_jupiter_sta_set_mode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	return (wrqu->mode == IW_MODE_INFRA) ? 0 : -EOPNOTSUPP;
}

/*
 * ps3_jupiter_sta_get_mode
 */
static int ps3_jupiter_sta_get_mode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	wrqu->mode = IW_MODE_INFRA;

	return 0;
}

/*
 * ps3_jupiter_sta_set_scan
 */
static int ps3_jupiter_sta_set_scan(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_scan_req *scan_req;
	u8 *essid = NULL;
	size_t essid_length = 0;
	u16 channels = jstad->channel_info;

	if (wrqu->data.length == sizeof(*scan_req)) {
		if (wrqu->data.flags & IW_SCAN_THIS_ESSID) {
			scan_req = (struct iw_scan_req *) extra;
			essid = scan_req->essid;
			essid_length = scan_req->essid_len;
		}

		/*XXX: get channels from scan request */
	}

	return ps3_jupiter_sta_start_scan(jstad, essid, essid_length, channels);
}

/*
 * ps3_jupiter_sta_get_scan
 */
static int ps3_jupiter_sta_get_scan(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct ps3_jupiter_sta_scan_result *scan_result;
	char *stream = extra;
	char *ends = stream + wrqu->data.length;
	int err;

	if (mutex_lock_interruptible(&jstad->scan_lock))
		return -EAGAIN;

	if (jstad->scan_status == PS3_JUPITER_STA_SCAN_IN_PROGRESS) {
		err = -EAGAIN;
		goto done;
	} else if (jstad->scan_status == PS3_JUPITER_STA_SCAN_INVALID) {
		err = -ENODEV;
		goto done;
	}

	/* translate scan results */

	list_for_each_entry(scan_result, &jstad->scan_result_list, list) {
		stream = ps3_jupiter_sta_translate_scan_result(jstad, scan_result,
		    info, stream, ends);

		if ((ends - stream) <= IW_EV_ADDR_LEN) {
			err = -E2BIG;
			goto done;
		}
	}

	wrqu->data.length = stream - extra;
	wrqu->data.flags = 0;

	err = 0;

done:

	mutex_unlock(&jstad->scan_lock);

	return err;
}

/*
 * ps3_jupiter_sta_set_auth
 */
static int ps3_jupiter_sta_set_auth(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_param *param = &wrqu->param;
	unsigned long irq_flags;
	int err = 0;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	switch (param->flags & IW_AUTH_INDEX) {
	case IW_AUTH_WPA_VERSION:
		if (param->value & IW_AUTH_WPA_VERSION_DISABLED) {
			jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_NONE;
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
		} else if (param->value & IW_AUTH_WPA_VERSION_WPA) {
			jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_WPA;
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_TKIP;
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_TKIP;
		} else if (param->value & IW_AUTH_WPA_VERSION_WPA2) {
			jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_WPA2;
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_AES;
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_AES;
		}
	break;
	case IW_AUTH_CIPHER_GROUP:
		if (param->value & IW_AUTH_CIPHER_NONE)
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
		else if (param->value & (IW_AUTH_CIPHER_WEP40 | IW_AUTH_CIPHER_WEP104))
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
		else if (param->value & IW_AUTH_CIPHER_TKIP)
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_TKIP;
		else if (param->value & IW_AUTH_CIPHER_CCMP)
			jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_AES;
	break;
	case IW_AUTH_CIPHER_PAIRWISE:
		if (param->value & IW_AUTH_CIPHER_NONE)
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
		else if (param->value & (IW_AUTH_CIPHER_WEP40 | IW_AUTH_CIPHER_WEP104))
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
		else if (param->value & IW_AUTH_CIPHER_TKIP)
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_TKIP;
		else if (param->value & IW_AUTH_CIPHER_CCMP)
			jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_AES;
	break;
	case IW_AUTH_80211_AUTH_ALG:
		if (param->value & IW_AUTH_ALG_OPEN_SYSTEM)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_OPEN;
		else if (param->value & IW_AUTH_ALG_SHARED_KEY)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_SHARED_KEY;
		else
			err = -EINVAL;
	break;
	case IW_AUTH_WPA_ENABLED:
		if (param->value)
			jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_WPA;
		else
			jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_NONE;
	break;
	case IW_AUTH_KEY_MGMT:
		if (!(param->value & IW_AUTH_KEY_MGMT_PSK))
			err = -EOPNOTSUPP;
	break;
	default:
		err = -EOPNOTSUPP;
	}

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_get_auth
 */
static int ps3_jupiter_sta_get_auth(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_param *param = &wrqu->param;
	unsigned long irq_flags;
	int err = 0;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	switch (param->flags & IW_AUTH_INDEX) {
	case IW_AUTH_WPA_VERSION:
	switch (jstad->wpa_mode) {
	case PS3_JUPITER_STA_WPA_MODE_WPA:
		param->value |= IW_AUTH_WPA_VERSION_WPA;
	break;
	case PS3_JUPITER_STA_WPA_MODE_WPA2:
		param->value |= IW_AUTH_WPA_VERSION_WPA2;
	break;
	default:
		param->value |= IW_AUTH_WPA_VERSION_DISABLED;
	}
	break;
	case IW_AUTH_80211_AUTH_ALG:
	switch (jstad->auth_mode) {
	case PS3_JUPITER_STA_AUTH_OPEN:
		param->value |= IW_AUTH_ALG_OPEN_SYSTEM;
	break;
	case PS3_JUPITER_STA_AUTH_SHARED_KEY:
		param->value |= IW_AUTH_ALG_SHARED_KEY;
	break;
	}
	break;
	case IW_AUTH_WPA_ENABLED:
	switch (jstad->wpa_mode) {
	case PS3_JUPITER_STA_WPA_MODE_WPA:
	case PS3_JUPITER_STA_WPA_MODE_WPA2:
		param->value = 1;
	break;
	default:
		param->value = 0;
	}
	break;
	default:
		err = -EOPNOTSUPP;
	}

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_set_essid
 */
static int ps3_jupiter_sta_set_essid(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	unsigned long irq_flags;

	if (IW_ESSID_MAX_SIZE < wrqu->essid.length)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (wrqu->essid.flags) {
		memcpy(jstad->essid, extra, wrqu->essid.length);
		jstad->essid_length = wrqu->essid.length;
		set_bit(PS3_JUPITER_STA_CONFIG_ESSID_SET, &jstad->config_status);
	} else {
		clear_bit(PS3_JUPITER_STA_CONFIG_ESSID_SET, &jstad->config_status);
	}

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	ps3_jupiter_sta_start_assoc(jstad);

	return 0;
}

/*
 * ps3_jupiter_sta_get_essid
 */
static int ps3_jupiter_sta_get_essid(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	unsigned long irq_flags;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (test_bit(PS3_JUPITER_STA_CONFIG_ESSID_SET, &jstad->config_status)) {
		memcpy(extra, jstad->essid, jstad->essid_length);
		wrqu->essid.length = jstad->essid_length;
		wrqu->essid.flags = 1;
	} else {
		wrqu->essid.flags = 0;
	}

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return 0;
}

/*
 * ps3_jupiter_sta_set_ap
 */
static int ps3_jupiter_sta_set_ap(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	unsigned long irq_flags;

	if (wrqu->ap_addr.sa_family != ARPHRD_ETHER)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (is_valid_ether_addr(wrqu->ap_addr.sa_data)) {
		memcpy(jstad->bssid, wrqu->ap_addr.sa_data, ETH_ALEN);
		set_bit(PS3_JUPITER_STA_CONFIG_BSSID_SET, &jstad->config_status);
	} else {
		memset(jstad->bssid, 0, ETH_ALEN);
	}

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return 0;
}

/*
 * ps3_jupiter_sta_get_ap
 */
static int ps3_jupiter_sta_get_ap(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	unsigned long irq_flags;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	wrqu->ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(wrqu->ap_addr.sa_data, jstad->bssid, ETH_ALEN);

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return 0;
}

/*
 * ps3_jupiter_sta_set_encode
 */
static int ps3_jupiter_sta_set_encode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_point *enc = &wrqu->encoding;
	__u16 flags = enc->flags & IW_ENCODE_FLAGS;
	int key_index = enc->flags & IW_ENCODE_INDEX;
	int key_index_provided;
	unsigned long irq_flags;
	int err = 0;

	if (key_index > PS3_JUPITER_STA_WEP_KEYS)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (key_index) {
		key_index--;
		key_index_provided = 1;
	} else {
		key_index = jstad->curr_key_index;
		key_index_provided = 0;
	}

	if (flags & IW_ENCODE_NOKEY) {
		if (!(flags & ~IW_ENCODE_NOKEY) && key_index_provided) {
			jstad->curr_key_index = key_index;
			goto done;
		}

		if (flags & IW_ENCODE_DISABLED) {
			if (key_index_provided) {
				clear_bit(key_index, &jstad->key_config_status);
			} else {
				jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
				jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
				jstad->key_config_status = 0;
			}
		}

		if (flags & IW_ENCODE_OPEN)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_OPEN;
		else if (flags & IW_ENCODE_RESTRICTED)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_SHARED_KEY;
	} else {
		if (enc->length > IW_ENCODING_TOKEN_MAX) {
			err = -EINVAL;
			goto done;
		}

		memcpy(jstad->key[key_index], extra, enc->length);
		jstad->key_length[key_index] = enc->length;
		set_bit(key_index, &jstad->key_config_status);

		jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
		jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_WEP;
	}

done:

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_get_encode
 */
static int ps3_jupiter_sta_get_encode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_point *enc = &wrqu->encoding;
	int key_index = enc->flags & IW_ENCODE_INDEX;
	int key_index_provided;
	unsigned long irq_flags;
	int err = 0;

	if (key_index > PS3_JUPITER_STA_WEP_KEYS)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (key_index) {
		key_index--;
		key_index_provided = 1;
	} else {
		key_index = jstad->curr_key_index;
		key_index_provided = 0;
	}

	if (jstad->group_cipher_mode == PS3_JUPITER_STA_CIPHER_WEP) {
		switch (jstad->auth_mode) {
		case PS3_JUPITER_STA_AUTH_OPEN:
			enc->flags |= IW_ENCODE_OPEN;
			break;
		case PS3_JUPITER_STA_AUTH_SHARED_KEY:
			enc->flags |= IW_ENCODE_RESTRICTED;
			break;
		}
	} else {
		enc->flags = IW_ENCODE_DISABLED;
	}

	if (test_bit(key_index, &jstad->key_config_status)) {
		if (enc->length < jstad->key_length[key_index]) {
			err = -EINVAL;
			goto done;
		}

		memcpy(extra, jstad->key[key_index], jstad->key_length[key_index]);
		enc->length = jstad->key_length[key_index];
	} else {
		enc->length = 0;
		enc->flags |= IW_ENCODE_NOKEY;
	}

	enc->flags |= (key_index + 1);

done:

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_set_encodeext
 */
static int ps3_jupiter_sta_set_encodeext(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_point *enc = &wrqu->encoding;
	struct iw_encode_ext *enc_ext = (struct iw_encode_ext *) extra;
	__u16 flags = enc->flags & IW_ENCODE_FLAGS;
	int key_index = enc->flags & IW_ENCODE_INDEX;
	unsigned long irq_flags;
	int err = 0;

	if (key_index > PS3_JUPITER_STA_WEP_KEYS)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (key_index)
		key_index--;
	else
		key_index = jstad->curr_key_index;

	if (!enc->length && (enc_ext->ext_flags & IW_ENCODE_EXT_SET_TX_KEY)) {
		jstad->curr_key_index = key_index;
	} else if ((enc_ext->alg == IW_ENCODE_ALG_NONE) || (flags & IW_ENCODE_DISABLED)) {
		jstad->auth_mode = PS3_JUPITER_STA_AUTH_OPEN;
		jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_NONE;
		jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
		jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
	} else if (enc_ext->alg == IW_ENCODE_ALG_WEP) {
		if (flags & IW_ENCODE_OPEN)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_OPEN;
		else if (flags & IW_ENCODE_RESTRICTED)
			jstad->auth_mode = PS3_JUPITER_STA_AUTH_SHARED_KEY;

		if (enc_ext->key_len > IW_ENCODING_TOKEN_MAX) {
			err = -EINVAL;
			goto done;
		}

		memcpy(jstad->key[key_index], enc_ext->key, enc_ext->key_len);
		jstad->key_length[key_index] = enc_ext->key_len;
		set_bit(key_index, &jstad->key_config_status);
	} else if (enc_ext->alg == IW_ENCODE_ALG_PMK) {
		if (enc_ext->key_len != PS3_JUPITER_STA_WPA_PSK_LENGTH) {
			err = -EINVAL;
			goto done;
		}

		memcpy(jstad->psk, enc_ext->key, enc_ext->key_len);
		set_bit(PS3_JUPITER_STA_CONFIG_WPA_PSK_SET, &jstad->config_status);
	}

done:

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_get_encodeext
 */
static int ps3_jupiter_sta_get_encodeext(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	struct iw_point *enc = &wrqu->encoding;
	struct iw_encode_ext *enc_ext = (struct iw_encode_ext *) extra;
	int key_index = enc->flags & IW_ENCODE_INDEX;
	unsigned long irq_flags;
	int err = 0;

	if ((enc->length - sizeof(struct iw_encode_ext)) < 0)
		return -EINVAL;

	if (key_index > PS3_JUPITER_STA_WEP_KEYS)
		return -EINVAL;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	if (key_index)
		key_index--;
	else
		key_index = jstad->curr_key_index;

	memset(enc_ext, 0, sizeof(*enc_ext));

	switch (jstad->group_cipher_mode) {
	case PS3_JUPITER_STA_CIPHER_WEP:
		enc_ext->alg = IW_ENCODE_ALG_WEP;
		enc->flags |= IW_ENCODE_ENABLED;
	break;
	case PS3_JUPITER_STA_CIPHER_TKIP:
		enc_ext->alg = IW_ENCODE_ALG_TKIP;
		enc->flags |= IW_ENCODE_ENABLED;
	break;
	case PS3_JUPITER_STA_CIPHER_AES:
		enc_ext->alg = IW_ENCODE_ALG_CCMP;
		enc->flags |= IW_ENCODE_ENABLED;
	break;
	default:
		enc_ext->alg = IW_ENCODE_ALG_NONE;
		enc->flags |= IW_ENCODE_NOKEY;
	}

	if (!(enc->flags & IW_ENCODE_NOKEY)) {
		if ((enc->length - sizeof(struct iw_encode_ext)) < jstad->key_length[key_index]) {
			err = -E2BIG;
			goto done;
		}

		if (test_bit(key_index, &jstad->key_config_status))
			memcpy(enc_ext->key, jstad->key[key_index], jstad->key_length[key_index]);
	}

done:

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

#ifdef CONFIG_WEXT_PRIV
/*
 * ps3_jupiter_sta_set_opmode
 */
static int ps3_jupiter_sta_set_opmode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	int opmode = *(int *) extra;
	unsigned long irq_flags;
	int err = 0;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	switch (opmode) {
	case PS3_JUPITER_STA_OPMODE_11B:
	case PS3_JUPITER_STA_OPMODE_11G:
	case PS3_JUPITER_STA_OPMODE_11BG:
		jstad->opmode = opmode;
	break;
	default:
		err = -EINVAL;
	}

done:

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return err;
}

/*
 * ps3_jupiter_sta_get_opmode
 */
static int ps3_jupiter_sta_get_opmode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);
	unsigned long irq_flags;

	spin_lock_irqsave(&jstad->lock, irq_flags);

	memcpy(extra, &jstad->opmode, sizeof(jstad->opmode));
	wrqu->data.length = sizeof(jstad->opmode);

	spin_unlock_irqrestore(&jstad->lock, irq_flags);

	return 0;
}
#endif

/*
 * ps3_jupiter_sta_get_wireless_stats
 */
static struct iw_statistics *ps3_jupiter_sta_get_wireless_stats(struct net_device *netdev)
{
	/*XXX: implement */

	return NULL;
}

/*
 * ps3_jupiter_sta_open
 */
static int ps3_jupiter_sta_open(struct net_device *netdev)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);

	/*XXX: implement */

	ps3_jupiter_sta_start_assoc(jstad);

	netif_start_queue(netdev);

	return 0;
}

/*
 * ps3_jupiter_sta_stop
 */
static int ps3_jupiter_sta_stop(struct net_device *netdev)
{
	struct ps3_jupiter_sta_dev *jstad = netdev_priv(netdev);

	/*XXX: implement */

	cancel_delayed_work(&jstad->assoc_work);

	if (jstad->assoc_status == PS3_JUPITER_STA_ASSOC_OK)
		ps3_jupiter_sta_disassoc(jstad);

	ps3_jupiter_sta_free_scan_results(jstad);

	ps3_jupiter_sta_reset_state(jstad);

	netif_stop_queue(netdev);

	return 0;
}

/*
 * ps3_jupiter_sta_start_xmit
 */
static int ps3_jupiter_sta_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_multicast_list
 */
static void ps3_jupiter_sta_set_multicast_list(struct net_device *netdev)
{
	/*XXX: implement */
}

/*
 * ps3_jupiter_sta_change_mtu
 */
static int ps3_jupiter_sta_change_mtu(struct net_device *netdev, int new_mtu)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_tx_timeout
 */
static void ps3_jupiter_sta_tx_timeout(struct net_device *netdev)
{
	/*XXX: implement */
}

/*
 * ps3_jupiter_sta_poll_controller
 */
static void ps3_jupiter_sta_poll_controller(struct net_device *netdev)
{
	/*XXX: implement */
}

/*
 * ps3_jupiter_sta_get_drvinfo
 */
static void ps3_jupiter_sta_get_drvinfo(struct net_device *netdev, struct ethtool_drvinfo *info)
{
	/*XXX: implement */
}

/*
 * ps3_jupiter_sta_get_link
 */
static u32 ps3_jupiter_sta_get_link(struct net_device *netdev)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_rx_csum
 */
static int ps3_jupiter_sta_set_rx_csum(struct net_device *netdev, u32 data)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_rx_csum
 */
static u32 ps3_jupiter_sta_get_rx_csum(struct net_device *netdev)
{
	/*XXX: implement */

	return 0;
}

static const iw_handler ps3_jupiter_sta_iw_handler[] =
{
	IW_HANDLER(SIOCGIWNAME,		ps3_jupiter_sta_get_name),
	IW_HANDLER(SIOCGIWNICKN,	ps3_jupiter_sta_get_nick),
	IW_HANDLER(SIOCGIWRANGE,	ps3_jupiter_sta_get_range),
	IW_HANDLER(SIOCSIWMODE,		ps3_jupiter_sta_set_mode),
	IW_HANDLER(SIOCGIWMODE,		ps3_jupiter_sta_get_mode),
	IW_HANDLER(SIOCSIWSCAN,		ps3_jupiter_sta_set_scan),
	IW_HANDLER(SIOCGIWSCAN,		ps3_jupiter_sta_get_scan),
	IW_HANDLER(SIOCSIWAUTH,		ps3_jupiter_sta_set_auth),
	IW_HANDLER(SIOCGIWAUTH,		ps3_jupiter_sta_get_auth),
	IW_HANDLER(SIOCSIWESSID,	ps3_jupiter_sta_set_essid),
	IW_HANDLER(SIOCGIWESSID,	ps3_jupiter_sta_get_essid),
	IW_HANDLER(SIOCSIWAP,		ps3_jupiter_sta_set_ap),
	IW_HANDLER(SIOCGIWAP,		ps3_jupiter_sta_get_ap),
	IW_HANDLER(SIOCSIWENCODE,	ps3_jupiter_sta_set_encode),
	IW_HANDLER(SIOCGIWENCODE,	ps3_jupiter_sta_get_encode),
	IW_HANDLER(SIOCSIWENCODEEXT,	ps3_jupiter_sta_set_encodeext),
	IW_HANDLER(SIOCGIWENCODEEXT,	ps3_jupiter_sta_get_encodeext),
};

#ifdef CONFIG_WEXT_PRIV
static const iw_handler ps3_jupiter_sta_iw_priv_handler[] = {
	ps3_jupiter_sta_set_opmode,
	ps3_jupiter_sta_get_opmode,
};

enum {
	PS3_JUPITER_STA_IW_PRIV_SET_MODE = SIOCIWFIRSTPRIV,
	PS3_JUPITER_STA_IW_PRIV_GET_MODE,
};

static struct iw_priv_args ps3_jupiter_sta_iw_priv_args[] = {
	{
		.cmd = PS3_JUPITER_STA_IW_PRIV_SET_MODE,
		.set_args = IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
		.name = "set_opmode"
	},
	{
		.cmd = PS3_JUPITER_STA_IW_PRIV_GET_MODE,
		.get_args = IW_PRIV_TYPE_INT | IW_PRIV_SIZE_FIXED | 1,
		.name = "get_opmode"
	},
};
#endif

static const struct iw_handler_def ps3_jupiter_sta_iw_handler_def = {
	.standard		= ps3_jupiter_sta_iw_handler,
	.num_standard		= ARRAY_SIZE(ps3_jupiter_sta_iw_handler),
#ifdef CONFIG_WEXT_PRIV
	.private		= ps3_jupiter_sta_iw_priv_handler,
	.num_private		= ARRAY_SIZE(ps3_jupiter_sta_iw_priv_handler),
	.private_args		= ps3_jupiter_sta_iw_priv_args,
	.num_private_args	= ARRAY_SIZE(ps3_jupiter_sta_iw_priv_args),
#endif
	.get_wireless_stats	= ps3_jupiter_sta_get_wireless_stats,
};

static const struct net_device_ops ps3_jupiter_sta_net_device_ops = {
	.ndo_open		= ps3_jupiter_sta_open,
	.ndo_stop		= ps3_jupiter_sta_stop,
	.ndo_start_xmit		= ps3_jupiter_sta_start_xmit,
	.ndo_set_multicast_list = ps3_jupiter_sta_set_multicast_list,
	.ndo_change_mtu		= ps3_jupiter_sta_change_mtu,
	.ndo_tx_timeout		= ps3_jupiter_sta_tx_timeout,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= ps3_jupiter_sta_poll_controller,
#endif
};

static const struct ethtool_ops ps3_jupiter_sta_ethtool_ops = {
	.get_drvinfo	= ps3_jupiter_sta_get_drvinfo,
	.get_link	= ps3_jupiter_sta_get_link,
	.get_tx_csum	= ethtool_op_get_tx_csum,
	.set_tx_csum	= ethtool_op_set_tx_csum,
	.set_rx_csum	= ps3_jupiter_sta_set_rx_csum,
	.get_rx_csum	= ps3_jupiter_sta_get_rx_csum,
};

/*
 * ps3_jupiter_sta_rx_urb_complete
 */
static void ps3_jupiter_sta_rx_urb_complete(struct urb *urb)
{
	struct ps3_jupiter_sta_dev *jstad = urb->context;
	struct usb_device *udev = jstad->udev;

	/*XXX: implement */

	dev_dbg(&udev->dev, "Rx URB completed (%d)\n", urb->status);

	switch (urb->status) {
	case 0:
	break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
	return;
	default:
		dev_err(&udev->dev, "Rx URB failed (%d)\n", urb->status);
	break;
	}
}

/*
 * ps3_jupiter_sta_free_scan_results
 */
static void ps3_jupiter_sta_free_scan_results(struct ps3_jupiter_sta_dev *jstad)
{
	struct ps3_jupiter_sta_scan_result *scan_result, *tmp;

	list_for_each_entry_safe(scan_result, tmp, &jstad->scan_result_list, list) {
		list_del(&scan_result->list);
		kfree(scan_result);
	}
}

/*
 * ps3_jupiter_sta_start_scan
 */
static int ps3_jupiter_sta_start_scan(struct ps3_jupiter_sta_dev *jstad,
	u8 *essid, size_t essid_length, u16 channels)
{
	struct ps3_eurus_cmd_start_scan *eurus_cmd_start_scan;
	struct usb_device *udev = jstad->udev;
	unsigned char *buf = NULL;
	unsigned int payload_length, status;
	unsigned int i, chan;
	u8 *chan_ie, *essid_ie;
	int err;

	if (mutex_lock_interruptible(&jstad->scan_lock))
		return -ERESTARTSYS;

	if (jstad->scan_status == PS3_JUPITER_STA_SCAN_IN_PROGRESS) {
		err = 0;
		goto done;
	}

	dev_dbg(&udev->dev, "starting new scan\n");

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto done;
	}

	eurus_cmd_start_scan = (struct ps3_eurus_cmd_start_scan *) buf;
	memset(eurus_cmd_start_scan, 0, 0x100);
	eurus_cmd_start_scan->unknown2 = 0x1;
	eurus_cmd_start_scan->unknown3 = cpu_to_le16(0x64);

	chan_ie = eurus_cmd_start_scan->ie;
	chan_ie[0] = WLAN_EID_DS_PARAMS;	/* ie id */
	chan_ie[1] = 0x0;			/* ie length */

	for (i = 0, chan = 0; i < ARRAY_SIZE(ps3_jupiter_sta_channel_freq); i++) {
		if (channels & (1 << i)) {
			chan_ie[2 + chan] = i + 1;
			chan++;
		}
	}

	chan_ie[1] = chan; /* ie length */
	payload_length = chan_ie + 2 + chan_ie[1] - (u8 *) eurus_cmd_start_scan;

	if (essid && essid_length) {
		essid_ie = chan_ie + 2 + chan_ie[1];
		essid_ie[0] = WLAN_EID_SSID; 	/* ie id */
		essid_ie[1] = essid_length;	/* ie length */
		memcpy(essid_ie + 2, essid, essid_length);
	
		payload_length += 2 + essid_ie[1];
	}

	init_completion(&jstad->scan_done_comp);

	jstad->scan_status = PS3_JUPITER_STA_SCAN_IN_PROGRESS;

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_START_SCAN,
	    eurus_cmd_start_scan, payload_length, &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	err = 0;

done:

	if (err)
		jstad->scan_status = PS3_JUPITER_STA_SCAN_INVALID;

	if (buf)
		kfree(buf);

	mutex_unlock(&jstad->scan_lock);

	return err;
}

/*
 * ps3_jupiter_sta_get_scan_results
 */
static int ps3_jupiter_sta_get_scan_results(struct ps3_jupiter_sta_dev *jstad)
{
	struct ps3_eurus_cmd_get_scan_results *eurus_cmd_get_scan_results;
	struct ps3_eurus_scan_result *eurus_scan_result;
	struct ps3_jupiter_sta_scan_result *scan_result;
	unsigned char *buf;
	unsigned int status, response_length;
	size_t eurus_scan_result_length, ie_length;
	unsigned int i;
	u8 *ie;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	eurus_cmd_get_scan_results = (struct ps3_eurus_cmd_get_scan_results *) buf;
	memset(eurus_cmd_get_scan_results, 0, PS3_EURUS_SCAN_RESULTS_MAXSIZE);

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_GET_SCAN_RESULTS,
	    eurus_cmd_get_scan_results, PS3_EURUS_SCAN_RESULTS_MAXSIZE, &status,
	    &response_length, eurus_cmd_get_scan_results);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	/* free old scan results */

	ps3_jupiter_sta_free_scan_results(jstad);

	/* add each scan result to list */

	for (i = 0, eurus_scan_result = eurus_cmd_get_scan_results->result;
	     i < eurus_cmd_get_scan_results->count; i++) {
		eurus_scan_result_length = le16_to_cpu(eurus_scan_result->length) + sizeof(eurus_scan_result->length);
		ie_length = (u8 *) eurus_scan_result + eurus_scan_result_length - eurus_scan_result->ie;

		scan_result = kzalloc(sizeof(*scan_result) + ie_length, GFP_KERNEL);
		if (!scan_result)
			goto next;

		memcpy(scan_result->bssid, eurus_scan_result->bssid, sizeof(eurus_scan_result->bssid));
		scan_result->capability = le16_to_cpu(eurus_scan_result->capability);
		scan_result->rssi = eurus_scan_result->rssi;

		memcpy(scan_result->ie, eurus_scan_result->ie, ie_length);
		scan_result->ie_length = ie_length;

		for (ie = scan_result->ie; ie < (scan_result->ie + scan_result->ie_length); ie += (2 + ie[1])) {
			switch (ie[0]) {
			case WLAN_EID_SSID:
				scan_result->essid_ie = ie;
			break;
			case WLAN_EID_SUPP_RATES:
				scan_result->supp_rates_ie = ie;
			break;
			case WLAN_EID_DS_PARAMS:
				scan_result->ds_param_set_ie = ie;
			break;
			case WLAN_EID_RSN:
				scan_result->rsn_ie = ie;
			break;
			case WLAN_EID_EXT_SUPP_RATES:
				scan_result->ext_supp_rates_ie = ie;
			break;
			case WLAN_EID_GENERIC:
			{
				/* WPA */

				static const u8 wpa_oui[] = { 0x00, 0x50, 0xf2 };

				if (((sizeof(wpa_oui) + 1) <= ie[1]) &&
				    !memcmp(&ie[2], wpa_oui, sizeof(wpa_oui)) &&
				    (ie[2 + sizeof(wpa_oui)] == 0x1))
					scan_result->wpa_ie = ie;
			}
			break;
			}
		}

		list_add_tail(&scan_result->list, &jstad->scan_result_list);

	next:

		/* move to next scan result */

		eurus_scan_result = (struct ps3_eurus_scan_result *) ((u8 *) eurus_scan_result +
		    eurus_scan_result_length);
	}

	err = 0;

done:

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_sta_translate_scan_result
 */
static char *ps3_jupiter_sta_translate_scan_result(struct ps3_jupiter_sta_dev *jstad,
	struct ps3_jupiter_sta_scan_result *scan_result,
	struct iw_request_info *info, char *stream, char *ends)
{
	struct iw_event iwe;
	char *tmp;
	unsigned int i;

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(iwe.u.ap_addr.sa_data, scan_result->bssid, ETH_ALEN);
	stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_ADDR_LEN);

	if (scan_result->essid_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWESSID;
		iwe.u.data.flags = 1;
		iwe.u.data.length = scan_result->essid_ie[1];
		stream = iwe_stream_add_point(info, stream, ends, &iwe, &scan_result->essid_ie[2]);
	}

	if (scan_result->ds_param_set_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = SIOCGIWFREQ;
		iwe.u.freq.m = scan_result->ds_param_set_ie[2];
		iwe.u.freq.e = 0;
		iwe.u.freq.i = 0;
		stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_FREQ_LEN);
	}

	tmp = stream + iwe_stream_lcp_len(info);

	if (scan_result->supp_rates_ie) {
		for (i = 0; i < scan_result->supp_rates_ie[1]; i++) {
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWRATE;
			iwe.u.bitrate.fixed = 0;
			iwe.u.bitrate.disabled = 0;
			iwe.u.bitrate.value = (scan_result->supp_rates_ie[2 + i] & 0x7f) * 500000;
			tmp = iwe_stream_add_value(info, stream, tmp, ends, &iwe, IW_EV_PARAM_LEN);
		}
	}

	if (scan_result->ext_supp_rates_ie) {
		for (i = 0; i < scan_result->ext_supp_rates_ie[1]; i++) {
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWRATE;
			iwe.u.bitrate.fixed = 0;
			iwe.u.bitrate.disabled = 0;
			iwe.u.bitrate.value = (scan_result->ext_supp_rates_ie[2 + i] & 0x7f) * 500000;
			tmp = iwe_stream_add_value(info, stream, tmp, ends, &iwe, IW_EV_PARAM_LEN);
		}
	}

	stream = tmp;

	iwe.cmd = SIOCGIWMODE;
	if (scan_result->capability & (WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_IBSS)) {
		if (scan_result->capability & WLAN_CAPABILITY_ESS)
			iwe.u.mode = IW_MODE_MASTER;
		else
			iwe.u.mode = IW_MODE_ADHOC;
		stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_UINT_LEN);
	}

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWENCODE;
	if (scan_result->capability & WLAN_CAPABILITY_PRIVACY)
		iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
	else
		iwe.u.data.flags = IW_ENCODE_DISABLED;
	iwe.u.data.length = 0;
	stream = iwe_stream_add_point(info, stream, ends, &iwe, scan_result->bssid);

	if (scan_result->rsn_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = IWEVGENIE;
		iwe.u.data.length = 2 + scan_result->rsn_ie[1];
		stream = iwe_stream_add_point(info, stream, ends, &iwe, scan_result->rsn_ie);
	}

	if (scan_result->wpa_ie) {
		memset(&iwe, 0, sizeof(iwe));
		iwe.cmd = IWEVGENIE;
		iwe.u.data.length = 2 + scan_result->wpa_ie[1];
		stream = iwe_stream_add_point(info, stream, ends, &iwe, scan_result->wpa_ie);
	}

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = IWEVQUAL;
	iwe.u.qual.updated  = IW_QUAL_ALL_UPDATED | IW_QUAL_QUAL_INVALID | IW_QUAL_NOISE_INVALID;
	iwe.u.qual.level = ps3_eurus_rssi2percentage(scan_result->rssi);
	iwe.u.qual.qual = ps3_eurus_rssi2percentage(scan_result->rssi);
	iwe.u.qual.noise = 0;
	stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_QUAL_LEN);

	return stream;
}

/*
 * ps3_jupiter_sta_find_best_scan_result
 */
static struct ps3_jupiter_sta_scan_result *ps3_jupiter_sta_find_best_scan_result(struct ps3_jupiter_sta_dev *jstad)
{
	struct ps3_jupiter_sta_scan_result *scan_result, *best_scan_result;
	u8 *essid;
	unsigned int essid_length;

	best_scan_result = NULL;

	/* traverse scan results */

	list_for_each_entry(scan_result, &jstad->scan_result_list, list) {
		if (scan_result->essid_ie) {
			essid = &scan_result->essid_ie[2];
			essid_length = scan_result->essid_ie[1];
		} else {
			essid = NULL;
			essid_length = 0;
		}

		if ((essid_length != jstad->essid_length) ||
		    strncmp(essid, jstad->essid, essid_length))
			continue;

		if (test_bit(PS3_JUPITER_STA_CONFIG_BSSID_SET, &jstad->config_status)) {
			if (!compare_ether_addr(jstad->bssid, scan_result->bssid)) {
				best_scan_result = scan_result;
				break;
			} else {
				continue;
			}
		}

		switch (jstad->wpa_mode) {
		case PS3_JUPITER_STA_WPA_MODE_NONE:
			if ((jstad->group_cipher_mode == PS3_JUPITER_STA_CIPHER_WEP) &&
			    !(scan_result->capability & WLAN_CAPABILITY_PRIVACY))
				continue;
		break;
		case PS3_JUPITER_STA_WPA_MODE_WPA:
			if (!scan_result->wpa_ie)
				continue;
		break;
		case PS3_JUPITER_STA_WPA_MODE_WPA2:
			if (!scan_result->rsn_ie)
				continue;
		break;
		}

		if (!best_scan_result || (best_scan_result->rssi > scan_result->rssi))
			best_scan_result = scan_result;
	}

	return best_scan_result;
}

/*
 * ps3_jupiter_sta_assoc
 */
static int ps3_jupiter_sta_assoc(struct ps3_jupiter_sta_dev *jstad,
	struct ps3_jupiter_sta_scan_result *scan_result)
{
	struct ps3_eurus_cmd_0x1ed *eurus_cmd_0x1ed;
	struct ps3_eurus_cmd_common_config *eurus_cmd_common_config;
	struct ps3_eurus_cmd_wep_config *eurus_cmd_wep_config;
	struct ps3_eurus_cmd_wpa_config *eurus_cmd_wpa_config;
	struct ps3_eurus_cmd_associate *eurus_cmd_associate;
	unsigned char *buf = NULL;
	unsigned int payload_length, status;
	u8 *ie;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	eurus_cmd_0x1ed = (struct ps3_eurus_cmd_0x1ed *) buf;
	memset(eurus_cmd_0x1ed, 0, sizeof(*eurus_cmd_0x1ed));
	eurus_cmd_0x1ed->unknown2 = 0x1;
	eurus_cmd_0x1ed->unknown3 = 0x2;
	eurus_cmd_0x1ed->unknown4 = 0xff;
	eurus_cmd_0x1ed->unknown5 = 0x16;	/*XXX: 0x4 if AP doesn't support rate 54Mbps */
	eurus_cmd_0x1ed->unknown6 = 0x4;
	eurus_cmd_0x1ed->unknown7 = 0xa;
	eurus_cmd_0x1ed->unknown8 = 0x16;	/*XXX: 0x4 if AP doesn't support rate 54Mbps */

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_0x1ed,
	    eurus_cmd_0x1ed, sizeof(*eurus_cmd_0x1ed), &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	/* set common configuration */

	eurus_cmd_common_config = (struct ps3_eurus_cmd_common_config *) buf;
	memset(eurus_cmd_common_config, 0, sizeof(*eurus_cmd_common_config));

	switch (jstad->opmode) {
	case PS3_JUPITER_STA_OPMODE_11B:
		eurus_cmd_common_config->opmode = PS3_EURUS_OPMODE_11B;
	break;
	case PS3_JUPITER_STA_OPMODE_11G:
		eurus_cmd_common_config->opmode = PS3_EURUS_OPMODE_11G;
	break;
	case PS3_JUPITER_STA_OPMODE_11BG:
		eurus_cmd_common_config->opmode = PS3_EURUS_OPMODE_11BG;
	break;
	}

	memcpy(eurus_cmd_common_config->bssid, scan_result->bssid, sizeof(scan_result->bssid));

	payload_length = sizeof(*eurus_cmd_common_config);

	ie = eurus_cmd_common_config->ie;

	ie[0] = WLAN_EID_SSID;
	ie[1] = jstad->essid_length;
	memcpy(&ie[2], jstad->essid, jstad->essid_length);

	payload_length += (2 + ie[1]);
	ie += (2 + ie[1]);

	if (scan_result->ds_param_set_ie) {
		memcpy(ie, scan_result->ds_param_set_ie, 2 + scan_result->ds_param_set_ie[1]);

		payload_length += (2 + ie[1]);
		ie += (2 + ie[1]);
	}

	if ((jstad->opmode == PS3_JUPITER_STA_OPMODE_11B) ||
	    (jstad->opmode == PS3_JUPITER_STA_OPMODE_11BG)) {
		ie[0] = WLAN_EID_SUPP_RATES;
		ie[1] = 0x4;
		ie[2] = (0x80 | 0x2);	/* 1Mbps */
		ie[3] = (0x80 | 0x4);	/* 2Mbps */
		ie[4] = (0x80 | 0xb);	/* 5.5MBps */
		ie[5] = (0x80 | 0x16);	/* 11Mbps */

		payload_length += (2 + ie[1]);
		ie += (2 + ie[1]);
	}

	if ((jstad->opmode == PS3_JUPITER_STA_OPMODE_11G) ||
	    (jstad->opmode == PS3_JUPITER_STA_OPMODE_11BG)) {
		if (jstad->opmode == PS3_JUPITER_STA_OPMODE_11G)
			ie[0] = WLAN_EID_SUPP_RATES;
		else
			ie[0] = WLAN_EID_EXT_SUPP_RATES;
		ie[1] = 0x8;
		ie[2] = 0xc;	/* 6Mbps */
		ie[3] = 0x12;	/* 9Mbps */
		ie[4] = 0x18;	/* 12Mbps */
		ie[5] = 0x24;	/* 18Mbps */
		ie[6] = 0x30;	/* 24Mbps */
		ie[7] = 0x48;	/* 36Mbps */
		ie[8] = 0x60;	/* 48Mbps */
		ie[9] = 0x6c;	/* 54Mbps */

		payload_length += (2 + ie[1]);
		ie += (2 + ie[1]);
	}

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_SET_COMMON_CONFIG,
	    eurus_cmd_common_config, payload_length, &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	if (jstad->wpa_mode == PS3_JUPITER_STA_WPA_MODE_NONE) {
		/* set WEP configuration */

		/*XXX: implement */

		eurus_cmd_wep_config = (struct ps3_eurus_cmd_wep_config *) buf;
		memset(eurus_cmd_wep_config, 0, sizeof(*eurus_cmd_wep_config));

		err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_SET_WEP_CONFIG,
		    eurus_cmd_wep_config, sizeof(*eurus_cmd_wep_config), &status, NULL, NULL);
		if (err)
			goto done;

		if (status != PS3_EURUS_CMD_OK) {
			err = -EIO;
			goto done;
		}
	} else {
		/* set WPA configuration */

		eurus_cmd_wpa_config = (struct ps3_eurus_cmd_wpa_config *) buf;
		memset(eurus_cmd_wpa_config, 0, sizeof(*eurus_cmd_wpa_config));

		eurus_cmd_wpa_config->unknown = 0x1;

		switch (jstad->wpa_mode) {
		case PS3_JUPITER_STA_WPA_MODE_WPA:
			eurus_cmd_wpa_config->security_mode = PS3_EURUS_WPA_SECURITY_WPA;
			if (jstad->group_cipher_mode == PS3_JUPITER_STA_CIPHER_TKIP)
				eurus_cmd_wpa_config->group_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA_TKIP;
			else
				eurus_cmd_wpa_config->group_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA_AES;
			if (jstad->pairwise_cipher_mode == PS3_JUPITER_STA_CIPHER_TKIP)
				eurus_cmd_wpa_config->pairwise_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA_TKIP;
			else
				eurus_cmd_wpa_config->pairwise_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA_AES;
			eurus_cmd_wpa_config->akm_suite = PS3_EURUS_WPA_AKM_SUITE_WPA_PSK;
		break;
		case PS3_JUPITER_STA_WPA_MODE_WPA2:
			eurus_cmd_wpa_config->security_mode = PS3_EURUS_WPA_SECURITY_WPA2;
			if (jstad->group_cipher_mode == PS3_JUPITER_STA_CIPHER_TKIP)
				eurus_cmd_wpa_config->group_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA2_TKIP;
			else
				eurus_cmd_wpa_config->group_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA2_AES;
			if (jstad->pairwise_cipher_mode == PS3_JUPITER_STA_CIPHER_TKIP)
				eurus_cmd_wpa_config->pairwise_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA2_TKIP;
			else
				eurus_cmd_wpa_config->pairwise_cipher_suite = PS3_EURUS_WPA_CIPHER_SUITE_WPA2_AES;
			eurus_cmd_wpa_config->akm_suite = PS3_EURUS_WPA_AKM_SUITE_WPA2_PSK;
		break;
		default:
			/* to make compiler happy */ ;
		}

		eurus_cmd_wpa_config->psk_type = PS3_EURUS_WPA_PSK_BIN;
		memcpy(eurus_cmd_wpa_config->psk, jstad->psk, sizeof(jstad->psk));

		err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_SET_WPA_CONFIG,
		    eurus_cmd_wpa_config, sizeof(*eurus_cmd_wpa_config), &status, NULL, NULL);
		if (err)
			goto done;

		if (status != PS3_EURUS_CMD_OK) {
			err = -EIO;
			goto done;
		}
	}

	init_completion(&jstad->assoc_done_comp);

	jstad->assoc_status = PS3_JUPITER_STA_ASSOC_IN_PROGRESS;

	eurus_cmd_associate = (struct ps3_eurus_cmd_associate *) buf;
	memset(eurus_cmd_associate, 0, sizeof(*eurus_cmd_associate));

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_ASSOCIATE,
	    eurus_cmd_associate, sizeof(*eurus_cmd_associate), &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	err = wait_for_completion_timeout(&jstad->assoc_done_comp, 5 * HZ);
	if (!err) {
		/* timeout */
		ps3_jupiter_sta_disassoc(jstad);
		err = -EIO;
		goto done;
	}

	jstad->assoc_status = PS3_JUPITER_STA_ASSOC_OK;

	memcpy(jstad->active_bssid, scan_result->bssid, sizeof(scan_result->bssid));

	err = 0;

done:

	if (err)
		jstad->assoc_status = PS3_JUPITER_STA_ASSOC_INVALID;

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_sta_assoc_worker
 */
static void ps3_jupiter_sta_assoc_worker(struct work_struct *work)
{
	struct ps3_jupiter_sta_dev *jstad = container_of(work, struct ps3_jupiter_sta_dev, assoc_work.work);
	struct usb_device *udev = jstad->udev;
	u8 *essid;
	unsigned int essid_length;
	int scan_lock = 0;
	struct ps3_jupiter_sta_scan_result *best_scan_result;
	int err;

	mutex_lock(&jstad->assoc_lock);

	if (jstad->assoc_status != PS3_JUPITER_STA_ASSOC_INVALID) {
		mutex_unlock(&jstad->assoc_lock);
		return;
	}

	dev_dbg(&udev->dev, "starting new association\n");

	if (jstad->scan_status != PS3_JUPITER_STA_SCAN_OK) {
		/* start scan and wait for scan results */

		if (test_bit(PS3_JUPITER_STA_CONFIG_ESSID_SET, &jstad->config_status)) {
			essid = jstad->essid;
			essid_length = jstad->essid_length;
		} else {
			essid = NULL;
			essid_length = 0;
		}

		err = ps3_jupiter_sta_start_scan(jstad, essid, essid_length, jstad->channel_info);
		if (err)
			goto done;

		wait_for_completion(&jstad->scan_done_comp);
	}

	mutex_lock(&jstad->scan_lock);
	scan_lock = 1;

	if (jstad->scan_status != PS3_JUPITER_STA_SCAN_OK)
		goto done;

	best_scan_result = ps3_jupiter_sta_find_best_scan_result(jstad);
	if (!best_scan_result) {
		dev_dbg(&udev->dev, "no suitable scan result was found\n");
		goto done;
	}

	err = ps3_jupiter_sta_assoc(jstad, best_scan_result);
	if (err) {
		dev_dbg(&udev->dev, "association failed (%d)\n", err);
		goto done;
	}

done:

	if (scan_lock)
		mutex_unlock(&jstad->scan_lock);

	if (jstad->assoc_status == PS3_JUPITER_STA_ASSOC_OK)
		ps3_jupiter_sta_send_iw_ap_event(jstad, jstad->active_bssid);
	else
		ps3_jupiter_sta_send_iw_ap_event(jstad, NULL);

	mutex_unlock(&jstad->assoc_lock);
}

/*
 * ps3_jupiter_sta_start_assoc
 */
static void ps3_jupiter_sta_start_assoc(struct ps3_jupiter_sta_dev *jstad)
{
	if (!test_bit(PS3_JUPITER_STA_CONFIG_ESSID_SET, &jstad->config_status))
		return;

	if ((jstad->wpa_mode == PS3_JUPITER_STA_WPA_MODE_NONE) &&
	    (jstad->group_cipher_mode == PS3_JUPITER_STA_CIPHER_WEP) &&
	    !jstad->key_config_status)
		return;

	if ((jstad->wpa_mode != PS3_JUPITER_STA_WPA_MODE_NONE) &&
	    !test_bit(PS3_JUPITER_STA_CONFIG_WPA_PSK_SET, &jstad->config_status))
		return;

	queue_delayed_work(jstad->assoc_queue, &jstad->assoc_work, 0);
}

/*
 * ps3_jupiter_sta_disassoc
 */
static int ps3_jupiter_sta_disassoc(struct ps3_jupiter_sta_dev *jstad)
{
	struct ps3_eurus_cmd_diassociate *eurus_cmd_diassociate;
	unsigned char *buf = NULL;
	unsigned int status;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	eurus_cmd_diassociate = (struct ps3_eurus_cmd_diassociate *) buf;
	memset(eurus_cmd_diassociate, 0, sizeof(*eurus_cmd_diassociate));

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_DISASSOCIATE,
	    eurus_cmd_diassociate, sizeof(*eurus_cmd_diassociate), &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	err = 0;

done:

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_sta_event_scan_completed
 */
static void ps3_jupiter_sta_event_scan_completed(struct ps3_jupiter_sta_dev *jstad)
{
	union iwreq_data iwrd;
	int err;

	mutex_lock(&jstad->scan_lock);

	err = ps3_jupiter_sta_get_scan_results(jstad);
	if (err)
		goto done;

	jstad->scan_status = PS3_JUPITER_STA_SCAN_OK;

	complete(&jstad->scan_done_comp);

	memset(&iwrd, 0, sizeof(iwrd));
	wireless_send_event(jstad->netdev, SIOCGIWSCAN, &iwrd, NULL);

done:

	if (err)
		jstad->scan_status = PS3_JUPITER_STA_SCAN_INVALID;

	mutex_unlock(&jstad->scan_lock);
}

/*
 * ps3_jupiter_sta_event_connected
 */
static void ps3_jupiter_sta_event_connected(struct ps3_jupiter_sta_dev *jstad, u32 event_id)
{
	u32 expected_event_id;

	switch (jstad->wpa_mode) {
	case PS3_JUPITER_STA_WPA_MODE_NONE:
		expected_event_id = PS3_EURUS_EVENT_CONNECTED;
	break;
	case PS3_JUPITER_STA_WPA_MODE_WPA:
	case PS3_JUPITER_STA_WPA_MODE_WPA2:
		expected_event_id = PS3_EURUS_EVENT_WPA_CONNECTED;
	break;
	}

	if (expected_event_id == event_id) {
		complete(&jstad->assoc_done_comp);
		netif_carrier_on(jstad->netdev);
	}
}

/*
 * ps3_jupiter_sta_event_disconnected
 */
static void ps3_jupiter_sta_event_disconnected(struct ps3_jupiter_sta_dev *jstad)
{
	int assoc_lock = 0;

	if (mutex_trylock(&jstad->assoc_lock))
		assoc_lock = 1;

	ps3_jupiter_sta_disassoc(jstad);

	if (jstad->assoc_status == PS3_JUPITER_STA_ASSOC_OK)
		ps3_jupiter_sta_send_iw_ap_event(jstad, NULL);

	jstad->assoc_status = PS3_JUPITER_STA_ASSOC_INVALID;

	netif_carrier_off(jstad->netdev);

	if (assoc_lock)
		mutex_unlock(&jstad->assoc_lock);
}

/*
 * ps3_jupiter_sta_event_handler
 */
static void ps3_jupiter_sta_event_handler(struct ps3_jupiter_event_listener *listener,
	struct ps3_eurus_event *event)
{
	struct ps3_jupiter_sta_dev *jstad = (struct ps3_jupiter_sta_dev *) listener->data;
	struct usb_device *udev = jstad->udev;

	dev_dbg(&udev->dev, "got event (0x%08x 0x%08x 0x%08x 0x%08x 0x%08x)\n",
	    event->hdr.type, event->hdr.id, event->hdr.unknown1,
	    event->hdr.payload_length, event->hdr.unknown2);

	switch (event->hdr.type) {
	case PS3_EURUS_EVENT_TYPE_0x40:
		switch (event->hdr.id) {
		case PS3_EURUS_EVENT_DEAUTH:
			ps3_jupiter_sta_event_disconnected(jstad);
		break;
		}
	break;
	case PS3_EURUS_EVENT_TYPE_0x80:
		switch (event->hdr.id) {
		case PS3_EURUS_EVENT_SCAN_COMPLETED:
			ps3_jupiter_sta_event_scan_completed(jstad);
		break;
		case PS3_EURUS_EVENT_CONNECTED:
		case PS3_EURUS_EVENT_WPA_CONNECTED:
			ps3_jupiter_sta_event_connected(jstad, event->hdr.id);
		break;
		case PS3_EURUS_EVENT_BEACON_LOST:
			ps3_jupiter_sta_event_disconnected(jstad);
		break;
		}
	break;
	}
}

/*
 * ps3_jupiter_sta_setup_netdev
 */
static int ps3_jupiter_sta_setup_netdev(struct ps3_jupiter_sta_dev *jstad)
{
	struct usb_device *udev = jstad->udev;
	struct net_device *netdev = jstad->netdev;
	struct ps3_eurus_cmd_get_mac_addr_list *eurus_cmd_get_mac_addr_list;
	struct ps3_eurus_cmd_set_mac_addr *eurus_cmd_set_mac_addr;
	unsigned char *buf = NULL;
	unsigned int status, response_length;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* get MAC address list */

	eurus_cmd_get_mac_addr_list = (struct ps3_eurus_cmd_get_mac_addr_list *) buf;
	memset(eurus_cmd_get_mac_addr_list, 0, PS3_EURUS_MAC_ADDR_LIST_MAXSIZE);

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_GET_MAC_ADDR_LIST,
	    eurus_cmd_get_mac_addr_list, PS3_EURUS_MAC_ADDR_LIST_MAXSIZE, &status,
	    &response_length, eurus_cmd_get_mac_addr_list);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	/* use first MAC address */

	memcpy(netdev->dev_addr, eurus_cmd_get_mac_addr_list->mac_addr, ETH_ALEN);

	dev_info(&udev->dev, "MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    netdev->dev_addr[0], netdev->dev_addr[1], netdev->dev_addr[2],
	    netdev->dev_addr[3], netdev->dev_addr[4], netdev->dev_addr[5]);

	/* set MAC address */

	eurus_cmd_set_mac_addr = (struct ps3_eurus_cmd_set_mac_addr *) buf;
	memset(eurus_cmd_set_mac_addr, 0, sizeof(*eurus_cmd_set_mac_addr));
	memcpy(eurus_cmd_set_mac_addr->mac_addr, netdev->dev_addr, ETH_ALEN);

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_SET_MAC_ADDR,
	    eurus_cmd_set_mac_addr, sizeof(*eurus_cmd_set_mac_addr), &status, NULL, NULL);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	strcpy(netdev->name, "wlan%d");

	netdev->ethtool_ops = &ps3_jupiter_sta_ethtool_ops;
	netdev->netdev_ops = &ps3_jupiter_sta_net_device_ops;
	netdev->wireless_data = &jstad->wireless_data;
	netdev->wireless_handlers = &ps3_jupiter_sta_iw_handler_def;

	err = register_netdev(netdev);
	if (err) {
		dev_dbg(&udev->dev, "could not register network device %s (%d)\n", netdev->name, err);
		goto done;
	}

	err = 0;

done:

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_sta_get_channel_info
 */
static int ps3_jupiter_sta_get_channel_info(struct ps3_jupiter_sta_dev *jstad)
{
	struct ps3_eurus_cmd_get_channel_info *eurus_cmd_get_channel_info;
	unsigned char *buf = NULL;
	unsigned int status, response_length;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	eurus_cmd_get_channel_info = (struct ps3_eurus_cmd_get_channel_info *) buf;
	memset(eurus_cmd_get_channel_info, 0, sizeof(*eurus_cmd_get_channel_info));

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_GET_CHANNEL_INFO,
	    eurus_cmd_get_channel_info, sizeof(*eurus_cmd_get_channel_info), &status,
	    &response_length, eurus_cmd_get_channel_info);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	jstad->channel_info = eurus_cmd_get_channel_info->channel_info;

	err = 0;

done:

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_sta_reset_state
 */
static void ps3_jupiter_sta_reset_state(struct ps3_jupiter_sta_dev *jstad)
{
	jstad->scan_status = PS3_JUPITER_STA_SCAN_INVALID;

	jstad->config_status = 0;

	jstad->opmode = PS3_JUPITER_STA_OPMODE_11G;

	jstad->auth_mode = PS3_JUPITER_STA_AUTH_OPEN;

	jstad->wpa_mode = PS3_JUPITER_STA_WPA_MODE_NONE;
	jstad->group_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;
	jstad->pairwise_cipher_mode = PS3_JUPITER_STA_CIPHER_NONE;

	memset(jstad->essid, 0, sizeof(jstad->essid));
	jstad->essid_length = 0;

	memset(jstad->bssid, 0, sizeof(jstad->bssid));

	jstad->key_config_status = 0;
	jstad->curr_key_index = 0;

	jstad->assoc_status = PS3_JUPITER_STA_ASSOC_INVALID;
}

/*
 * ps3_jupiter_sta_create_assoc_worker
 */
static int ps3_jupiter_sta_create_assoc_worker(struct ps3_jupiter_sta_dev *jstad)
{
	jstad->assoc_queue = create_singlethread_workqueue("ps3_jupiter_sta_assoc");
	if (!jstad->assoc_queue)
		return -ENOMEM;

	INIT_DELAYED_WORK(&jstad->assoc_work, ps3_jupiter_sta_assoc_worker);

	return 0;
}

/*
 * ps3_jupiter_sta_destroy_assoc_worker
 */
static void ps3_jupiter_sta_destroy_assoc_worker(struct ps3_jupiter_sta_dev *jstad)
{
	if (jstad->assoc_queue) {
		cancel_delayed_work(&jstad->assoc_work);
		flush_workqueue(jstad->assoc_queue);
		destroy_workqueue(jstad->assoc_queue);
		jstad->assoc_queue = NULL;
	}
}

/*
 * ps3_jupiter_sta_probe
 */
static int ps3_jupiter_sta_probe(struct usb_interface *interface,
	const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	struct ps3_jupiter_sta_dev *jstad;
	struct net_device *netdev;
	int err;

	netdev = alloc_etherdev(sizeof(struct ps3_jupiter_sta_dev));
	if (!netdev)
		return -ENOMEM;

	jstad = netdev_priv(netdev);
	jstad->netdev = netdev;

	jstad->udev = usb_get_dev(udev);
	usb_set_intfdata(interface, jstad);

	spin_lock_init(&jstad->lock);

	jstad->event_listener.function = ps3_jupiter_sta_event_handler;
	jstad->event_listener.data = (unsigned long) jstad;

	err = ps3_jupiter_register_event_listener(&jstad->event_listener);
	if (err) {
		dev_err(&udev->dev, "could not register event listener (%d)\n", err);
		goto fail;
	}

	mutex_init(&jstad->scan_lock);
	INIT_LIST_HEAD(&jstad->scan_result_list);

	err = ps3_jupiter_sta_get_channel_info(jstad);
	if (err) {
		dev_err(&udev->dev, "could not get channel info (%d)\n", err);
		goto fail;
	}

	mutex_init(&jstad->assoc_lock);

	err = ps3_jupiter_sta_create_assoc_worker(jstad);
	if (err) {
		dev_err(&udev->dev, "could not create assoc work queue (%d)\n", err);
		goto fail;
	}

	err = ps3_jupiter_sta_setup_netdev(jstad);
	if (err) {
		dev_err(&udev->dev, "could not setup network device (%d)\n", err);
		goto fail;
	}

	ps3_jupiter_sta_reset_state(jstad);

	return 0;

fail:

	ps3_jupiter_sta_destroy_assoc_worker(jstad);

	ps3_jupiter_unregister_event_listener(&jstad->event_listener);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(udev);

	free_netdev(netdev);

	return err;
}

/*
 * ps3_jupiter_sta_disconnect
 */
static void ps3_jupiter_sta_disconnect(struct usb_interface *interface)
{
	struct ps3_jupiter_sta_dev *jstad = usb_get_intfdata(interface);
	struct usb_device *udev = jstad->udev;
	struct net_device *netdev = jstad->netdev;

	if (jstad->assoc_status == PS3_JUPITER_STA_ASSOC_OK)
		ps3_jupiter_sta_disassoc(jstad);

	ps3_jupiter_sta_destroy_assoc_worker(jstad);

	ps3_jupiter_sta_free_scan_results(jstad);

	ps3_jupiter_unregister_event_listener(&jstad->event_listener);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(udev);

	unregister_netdev(netdev);

	free_netdev(netdev);
}

#ifdef CONFIG_PM
/*
 * ps3_jupiter_sta_suspend
 */
static int ps3_jupiter_sta_suspend(struct usb_interface *interface, pm_message_t state)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_resume
 */
static int ps3_jupiter_sta_resume(struct usb_interface *interface)
{
	/*XXX: implement */

	return 0;
}
#endif /* CONFIG_PM */

static struct usb_device_id ps3_jupiter_sta_devtab[] = {
	{
		.match_flags = USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_INT_INFO,
		.idVendor = 0x054c,
		.idProduct = 0x036f,
		.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceSubClass = 2,
		.bInterfaceProtocol = 2
	},
	{ }
};

static struct usb_driver ps3_jupiter_sta_drv = {
	.name		= KBUILD_MODNAME,
	.id_table	= ps3_jupiter_sta_devtab,
	.probe		= ps3_jupiter_sta_probe,
	.disconnect	= ps3_jupiter_sta_disconnect,
#ifdef CONFIG_PM
	.suspend	= ps3_jupiter_sta_suspend,
	.resume		= ps3_jupiter_sta_resume,
#endif /* CONFIG_PM */
};

/*
 * ps3_jupiter_sta_init
 */
static int __init ps3_jupiter_sta_init(void)
{
	return usb_register(&ps3_jupiter_sta_drv);
}

/*
 * ps3_jupiter_sta_exit
 */
static void __exit ps3_jupiter_sta_exit(void)
{
	usb_deregister(&ps3_jupiter_sta_drv);
}

module_init(ps3_jupiter_sta_init);
module_exit(ps3_jupiter_sta_exit);

MODULE_DESCRIPTION("PS3 Jupiter STA");
MODULE_SUPPORTED_DEVICE("PS3 Jupiter STA");
MODULE_DEVICE_TABLE(usb, ps3_jupiter_sta_devtab);
MODULE_DESCRIPTION("PS3 Jupiter STA");
MODULE_AUTHOR("glevand");
MODULE_LICENSE("GPL");
