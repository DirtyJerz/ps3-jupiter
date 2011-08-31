
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

#define PS3_JUPITER_STA_CMD_BUFSIZE	2048

#define PS3_JUPITER_STA_EP		0x6

#define PS3_JUPITER_STA_RX_URBS		4

enum ps3_jupiter_sta_scan_status {
	PS3_JUPITER_STA_SCAN_FAILED = 0,
	PS3_JUPITER_STA_SCAN_IN_PROGRESS,
	PS3_JUPITER_STA_SCAN_SUCCESS
};

struct ps3_jupiter_sta_dev {
	struct net_device *netdev;

	struct iw_public_data wireless_data;
	struct iw_statistics wireless_stat;

	struct usb_device *udev;

	struct ps3_jupiter_event_listener event_listener;

	u16 channel_info;

	struct ps3_eurus_cmd_get_scan_results *scan_results;
	enum ps3_jupiter_sta_scan_status scan_status;

	struct mutex scan_lock;

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

static int ps3_jupiter_sta_start_scan(struct ps3_jupiter_sta_dev *jstad,
	u8 *essid, size_t essid_length, u16 channels);

static char *ps3_jupiter_sta_translate_scan_result(struct ps3_jupiter_sta_dev *jstad,
	struct ps3_eurus_scan_result *scan_result,
	size_t scan_result_length, struct iw_request_info *info, char *stream, char *ends);

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
	struct ps3_eurus_scan_result *scan_result;
	size_t scan_result_length;
	char *stream = extra;
	char *ends = stream + wrqu->data.length;
	unsigned int i;
	int err;

	if (mutex_lock_interruptible(&jstad->scan_lock))
		return -EAGAIN;

	if (jstad->scan_status == PS3_JUPITER_STA_SCAN_IN_PROGRESS) {
		err = -EAGAIN;
		goto done;
	} else if (jstad->scan_status == PS3_JUPITER_STA_SCAN_FAILED) {
		err = -ENODEV;
		goto done;
	}

	/* translate scan results */

	for (i = 0, scan_result = jstad->scan_results->result;
	     i < jstad->scan_results->count; i++) {
		scan_result_length = le16_to_cpu(scan_result->length) + sizeof(scan_result->length);

		stream = ps3_jupiter_sta_translate_scan_result(jstad, scan_result, scan_result_length,
		    info, stream, ends);

		if ((ends - stream) <= IW_EV_ADDR_LEN) {
			err = -E2BIG;
			goto done;
		}

		/* move to next scan result */

		scan_result = (struct ps3_eurus_scan_result *) ((u8 *) scan_result + scan_result_length);
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
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_auth
 */
static int ps3_jupiter_sta_get_auth(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_essid
 */
static int ps3_jupiter_sta_set_essid(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_essid
 */
static int ps3_jupiter_sta_get_essid(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_encode
 */
static int ps3_jupiter_sta_set_encode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_encode
 */
static int ps3_jupiter_sta_get_encode(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_ap
 */
static int ps3_jupiter_sta_set_ap(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_ap
 */
static int ps3_jupiter_sta_get_ap(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_set_encodeext
 */
static int ps3_jupiter_sta_set_encodeext(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

	return 0;
}

/*
 * ps3_jupiter_sta_get_encodeext
 */
static int ps3_jupiter_sta_get_encodeext(struct net_device *netdev,
	struct iw_request_info *info, union iwreq_data *wrqu, char *extra)
{
	/*XXX: implement */

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
	/*XXX: implement */

	netif_start_queue(netdev);

	return 0;
}

/*
 * ps3_jupiter_sta_stop
 */
static int ps3_jupiter_sta_stop(struct net_device *netdev)
{
	/*XXX: implement */

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
	IW_HANDLER(SIOCGIWRANGE,	ps3_jupiter_sta_get_range),
	IW_HANDLER(SIOCSIWSCAN,		ps3_jupiter_sta_set_scan),
	IW_HANDLER(SIOCGIWSCAN,		ps3_jupiter_sta_get_scan),
	IW_HANDLER(SIOCSIWAUTH,		ps3_jupiter_sta_set_auth),
	IW_HANDLER(SIOCGIWAUTH,		ps3_jupiter_sta_get_auth),
	IW_HANDLER(SIOCSIWESSID,	ps3_jupiter_sta_set_essid),
	IW_HANDLER(SIOCGIWESSID,	ps3_jupiter_sta_get_essid),
	IW_HANDLER(SIOCSIWENCODE,	ps3_jupiter_sta_set_encode),
	IW_HANDLER(SIOCGIWENCODE,	ps3_jupiter_sta_get_encode),
	IW_HANDLER(SIOCSIWAP,		ps3_jupiter_sta_set_ap),
	IW_HANDLER(SIOCGIWAP,		ps3_jupiter_sta_get_ap),
	IW_HANDLER(SIOCSIWENCODEEXT,	ps3_jupiter_sta_set_encodeext),
	IW_HANDLER(SIOCGIWENCODEEXT,	ps3_jupiter_sta_get_encodeext),
	IW_HANDLER(SIOCSIWMODE,		ps3_jupiter_sta_set_mode),
	IW_HANDLER(SIOCGIWMODE,		ps3_jupiter_sta_get_mode),
	IW_HANDLER(SIOCGIWNICKN,	ps3_jupiter_sta_get_nick),
};

static const struct iw_handler_def ps3_jupiter_sta_iw_handler_def = {
	.num_standard		= ARRAY_SIZE(ps3_jupiter_sta_iw_handler),
	.standard		= ps3_jupiter_sta_iw_handler,
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
 * ps3_jupiter_sta_start_scan
 */
static int ps3_jupiter_sta_start_scan(struct ps3_jupiter_sta_dev *jstad,
	u8 *essid, size_t essid_length, u16 channels)
{
	struct ps3_eurus_cmd_start_scan *eurus_cmd_start_scan;
	struct usb_device *udev = jstad->udev;
	unsigned char *buf;
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
		essid_ie = chan_ie + chan_ie[1];
		essid_ie[0] = WLAN_EID_SSID; 	/* ie id */
		essid_ie[1] = essid_length;	/* ie length */
		memcpy(essid_ie + 2, essid, essid_length);
	
		payload_length += 2 + essid_ie[1];
	}

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
		jstad->scan_status = PS3_JUPITER_STA_SCAN_FAILED;

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
	unsigned int status, response_length;
	int err;

	if (!jstad->scan_results) {
		jstad->scan_results = kmalloc(0x5b0, GFP_KERNEL);
		if (!jstad->scan_results)
			return -ENOMEM;
	}

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_GET_SCAN_RESULTS,
	    jstad->scan_results, 0x5b0, &status, &response_length, jstad->scan_results);
	if (err)
		goto done;

	if (status != PS3_EURUS_CMD_OK) {
		err = -EIO;
		goto done;
	}

	jstad->scan_status = PS3_JUPITER_STA_SCAN_SUCCESS;

	err = 0;

done:

	if (err)
		jstad->scan_status = PS3_JUPITER_STA_SCAN_FAILED;

	return err;
}

/*
 * ps3_jupiter_sta_translate_scan_result
 */
static char *ps3_jupiter_sta_translate_scan_result(struct ps3_jupiter_sta_dev *jstad,
	struct ps3_eurus_scan_result *scan_result,
	size_t scan_result_length, struct iw_request_info *info, char *stream, char *ends)
{
	struct usb_device *udev = jstad->udev;
	struct iw_event iwe;
	u8 *ie;

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWAP;
	iwe.u.ap_addr.sa_family = ARPHRD_ETHER;
	memcpy(iwe.u.ap_addr.sa_data, scan_result->bssid, ETH_ALEN);
	stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_ADDR_LEN);

	for (ie = scan_result->ie; ie < ((u8 *) scan_result + scan_result_length); ie += (2 + ie[1])) {
		switch (ie[0]) {
		case WLAN_EID_SSID:
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWESSID;
			iwe.u.data.flags = 1;
			iwe.u.data.length = ie[1];
			stream = iwe_stream_add_point(info, stream, ends, &iwe, &ie[2]);
		break;
		case WLAN_EID_SUPP_RATES:
			/*XXX: implement */
		break;
		case WLAN_EID_DS_PARAMS:
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = SIOCGIWFREQ;
			iwe.u.freq.m = be16_to_cpu(ie[2]);
			iwe.u.freq.e = 0;
			iwe.u.freq.i = 0;
			stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_FREQ_LEN);
		break;
		case WLAN_EID_RSN:
			memset(&iwe, 0, sizeof(iwe));
			iwe.cmd = IWEVGENIE;
			iwe.u.data.length = 2 + ie[1];
			stream = iwe_stream_add_point(info, stream, ends, &iwe, ie);
		break;
		/* extended supported rates */
		case 0x32:
			/*XXX: implement */
		break;
		case WLAN_EID_GENERIC:
		{
			/* WPA */

			static const u8 wpa_oui[] = { 0x00, 0x50, 0xf2 };

			if (((sizeof(wpa_oui) + 1) <= ie[1]) &&
			    !memcmp(&ie[2], wpa_oui, sizeof(wpa_oui)) &&
			    (ie[2 + sizeof(wpa_oui)] == 0x1)) {
				memset(&iwe, 0, sizeof(iwe));
				iwe.cmd = IWEVGENIE;
				iwe.u.data.length = 2 + ie[1];
				stream = iwe_stream_add_point(info, stream, ends, &iwe, ie);
			}
		}
		break;
		default:
			dev_dbg(&udev->dev, "ignore ie with id 0x%02x length %d\n", ie[0], ie[1]);
		}
	}

	iwe.cmd = SIOCGIWMODE;
	if (le16_to_cpu(scan_result->capability) & (WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_IBSS)) {
		if (le16_to_cpu(scan_result->capability) & WLAN_CAPABILITY_ESS)
			iwe.u.mode = IW_MODE_MASTER;
		else
			iwe.u.mode = IW_MODE_ADHOC;
		stream = iwe_stream_add_event(info, stream, ends, &iwe, IW_EV_UINT_LEN);
	}

	memset(&iwe, 0, sizeof(iwe));
	iwe.cmd = SIOCGIWENCODE;
	if (le16_to_cpu(scan_result->capability) & WLAN_CAPABILITY_PRIVACY)
		iwe.u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
	else
		iwe.u.data.flags = IW_ENCODE_DISABLED;
	iwe.u.data.length = 0;
	stream = iwe_stream_add_point(info, stream, ends, &iwe, scan_result->bssid);

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
 * ps3_jupiter_sta_event_handler
 */
static void ps3_jupiter_sta_event_handler(struct ps3_jupiter_event_listener *listener,
	struct ps3_eurus_event *event)
{
	struct ps3_jupiter_sta_dev *jstad = (struct ps3_jupiter_sta_dev *) listener->data;
	struct usb_device *udev = jstad->udev;
	int err;

	dev_dbg(&udev->dev, "got event (0x%08x 0x%08x 0x%08x 0x%08x 0x%08x)\n",
	    event->hdr.type, event->hdr.id, event->hdr.unknown1, event->hdr.payload_length, event->hdr.unknown2);

	if (event->hdr.type == PS3_EURUS_EVENT_TYPE_0x80) {
		if (event->hdr.id == PS3_EURUS_EVENT_SCAN_COMPLETED) {
			/* get scan results */

			err = ps3_jupiter_sta_get_scan_results(jstad);
			if (!err) {
				union iwreq_data data;

				mutex_lock(&jstad->scan_lock);
				memset(&data, 0, sizeof(data));
				wireless_send_event(jstad->netdev, SIOCGIWSCAN, &data, NULL);
				mutex_unlock(&jstad->scan_lock);
			}
		}
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
	unsigned char *buf;
	unsigned int status, response_length;
	int err;

	buf = kmalloc(PS3_JUPITER_STA_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* get MAC address list */

	eurus_cmd_get_mac_addr_list = (struct ps3_eurus_cmd_get_mac_addr_list *) buf;
	memset(eurus_cmd_get_mac_addr_list, 0, 0xc2);

	err = ps3_jupiter_exec_eurus_cmd(PS3_EURUS_CMD_GET_MAC_ADDR_LIST,
	    eurus_cmd_get_mac_addr_list, 0xc2, &status, &response_length, eurus_cmd_get_mac_addr_list);
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
	unsigned char *buf;
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

	jstad->event_listener.function = ps3_jupiter_sta_event_handler;
	jstad->event_listener.data = (unsigned long) jstad;

	err = ps3_jupiter_register_event_listener(&jstad->event_listener);
	if (err) {
		dev_err(&udev->dev, "could not register event listener (%d)\n", err);
		goto fail;
	}

	mutex_init(&jstad->scan_lock);
	jstad->scan_status = PS3_JUPITER_STA_SCAN_FAILED;

	err = ps3_jupiter_sta_get_channel_info(jstad);
	if (err) {
		dev_err(&udev->dev, "could not get channel info (%d)\n", err);
		goto fail;
	}

	err = ps3_jupiter_sta_setup_netdev(jstad);
	if (err) {
		dev_err(&udev->dev, "could not setup network device (%d)\n", err);
		goto fail;
	}

	return 0;

fail:

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

	if (jstad->scan_results)
		kfree(jstad->scan_results);

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
