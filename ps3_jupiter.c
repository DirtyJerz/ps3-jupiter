
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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/usb.h>
#include <linux/rculist.h>

#include <linux/etherdevice.h>
#include <linux/if_ether.h>

#include <asm/byteorder.h>
#include <asm/ps3.h>
#include <asm/lv1call.h>

#include "ps3_jupiter.h"

#define PS3_JUPITER_EP			0x5

#define PS3_JUPITER_IRQ_BUFSIZE		2048
#define PS3_JUPITER_CMD_BUFSIZE		2048

#define LV1_GET_MAC_ADDRESS		0x1

enum ps3_jupiter_pkt_type {
	PS3_JUPITER_PKT_CMD	= 6,
	PS3_JUPITER_PKT_EVENT	= 8,
};

struct ps3_jupiter_dev {
	struct usb_device *udev;
	struct urb *irq_urb, *cmd_urb;
	void *irq_buf, *cmd_buf;

	u16 cmd_tag, eurus_cmd, eurus_tag;
	struct completion cmd_done_comp;
	spinlock_t cmd_lock;
	int cmd_busy, cmd_err;

	struct workqueue_struct *event_queue;
	struct delayed_work event_work;
	struct list_head event_listeners;
	spinlock_t event_listeners_lock;
	struct list_head event_list;
	spinlock_t event_list_lock;

	struct ps3_jupiter_event_listener event_listener;
	struct completion event_comp;

	unsigned char mac_addr[ETH_ALEN];

	u16 dev_status;
	int dev_ready;
};

struct ps3_jupiter_pkt_hdr {
	u8 unknown1;
	u8 unknown2;
	u8 type;
} __packed;

struct ps3_jupiter_cmd_hdr {
	u8 unknown1;
	__le16 unknown2;
	u8 res1[2];
	__le16 tag;
	u8 res2[14];
} __packed;

struct ps3_jupiter_event_hdr {
	u8 count;
} __packed;

struct ps3_jupiter_list_event {
	struct list_head list;
	struct ps3_jupiter_event event;
};

static struct ps3_jupiter_dev *ps3jd;

static unsigned char ps3_jupiter_devkey[] = {
	0x76, 0x4e, 0x4b, 0x07, 0x24, 0x42, 0x53, 0xfb, 0x5a, 0xc7, 0xcc, 0x1d, 0xae, 0x00, 0xc6, 0xd8,
	0x14, 0x40, 0x61, 0x8b, 0x13, 0x17, 0x4d, 0x7c, 0x3b, 0xb6, 0x90, 0xb8, 0x6e, 0x8b, 0xbb, 0x1d,
};

/*
 * ps3_jupiter_event_worker
 */
static void ps3_jupiter_event_worker(struct work_struct *work)
{
	struct ps3_jupiter_dev *jd = container_of(work, struct ps3_jupiter_dev, event_work.work);
	struct ps3_jupiter_list_event *list_event;
	struct ps3_jupiter_event_listener *listener;
	unsigned long flags;

	while (1) {
		spin_lock_irqsave(&jd->event_list_lock, flags);

		if (list_empty(&jd->event_list)) {
			spin_unlock_irqrestore(&jd->event_list_lock, flags);
			break;
		}

		list_event = list_entry(jd->event_list.next, struct ps3_jupiter_list_event, list);
		list_del(&list_event->list);

		spin_unlock_irqrestore(&jd->event_list_lock, flags);

		rcu_read_lock();

		list_for_each_entry_rcu(listener, &jd->event_listeners, list) {
			if (listener->function)
				listener->function(listener, &list_event->event);
		}

		rcu_read_unlock();

		kfree(list_event);
	}
}

/*
 * ps3_jupiter_event_irq
 */
static void ps3_jupiter_event_irq(struct ps3_jupiter_dev *jd,
	void *buf, unsigned int length)
{
	struct usb_device *udev = jd->udev;
	struct ps3_jupiter_pkt_hdr *pkt_hdr;
	struct ps3_jupiter_event_hdr *event_hdr;
	struct ps3_jupiter_list_event *list_event;
	unsigned long flags;
	int i;

	dev_dbg(&udev->dev, "got event IRQ packet\n");

	if (length < sizeof(*pkt_hdr) + sizeof(*event_hdr)) {
		dev_err(&udev->dev, "got event IRQ packet with invalid length (%d)\n",
			length);
		return;
	}

	pkt_hdr = (struct ps3_jupiter_pkt_hdr *) buf;
	event_hdr = (struct ps3_jupiter_event_hdr *) (pkt_hdr + 1);

	if (length < sizeof(*pkt_hdr) + sizeof(*event_hdr) +
		event_hdr->count * sizeof(struct ps3_jupiter_event)) {
		dev_err(&udev->dev, "got event IRQ packet with invalid length (%d)\n",
			length);
		return;
	}

	dev_dbg(&udev->dev, "got %d event(s)\n", event_hdr->count);

	for (i = 0; i < event_hdr->count; i++) {
		list_event = kmalloc(sizeof(*list_event), GFP_ATOMIC);
		if (!list_event) {
			dev_err(&udev->dev, "could not allocate memory for new event\n");
			continue;
		}

		memcpy(&list_event->event, (unsigned char *) event_hdr + sizeof(*event_hdr) +
			i * sizeof(struct ps3_jupiter_event), sizeof(struct ps3_jupiter_event));
		list_event->event.unknown1 = le32_to_cpu(list_event->event.unknown1);
		list_event->event.unknown2 = le32_to_cpu(list_event->event.unknown2);
		list_event->event.unknown3 = le32_to_cpu(list_event->event.unknown3);
		list_event->event.unknown4 = le32_to_cpu(list_event->event.unknown4);

		spin_lock_irqsave(&jd->event_list_lock, flags);
		list_add_tail(&list_event->list, &jd->event_list);
		spin_unlock_irqrestore(&jd->event_list_lock, flags);
	}

	if (event_hdr->count)
		queue_delayed_work(jd->event_queue, &jd->event_work, 0);
}

/*
 * ps3_jupiter_cmd_irq
 */
static void ps3_jupiter_cmd_irq(struct ps3_jupiter_dev *jd,
	void *buf, unsigned int length)
{
	struct usb_device *udev = jd->udev;
	struct ps3_jupiter_pkt_hdr *pkt_hdr;
	struct ps3_jupiter_cmd_hdr *cmd_hdr;
	struct ps3_eurus_hdr *eurus_hdr;
	u16 cmd_tag, eurus_cmd, eurus_tag, payload_length;

	dev_dbg(&udev->dev, "got command IRQ packet\n");

	if (length < sizeof(*pkt_hdr) + sizeof(*cmd_hdr) + sizeof(*eurus_hdr)) {
		dev_err(&udev->dev, "got command IRQ packet with invalid length (%d)\n",
			length);
		return;
	}

	pkt_hdr = (struct ps3_jupiter_pkt_hdr *) buf;
	cmd_hdr = (struct ps3_jupiter_cmd_hdr *) (pkt_hdr + 1);
	eurus_hdr = (struct ps3_eurus_hdr *) (cmd_hdr + 1);
	payload_length = le16_to_cpu(eurus_hdr->payload_length);

	if (length < sizeof(*pkt_hdr) + sizeof(*cmd_hdr) + sizeof(*eurus_hdr) + payload_length) {
		dev_err(&udev->dev, "got command IRQ packet with invalid length (%d)\n",
			length);
		return;
	}

	cmd_tag = le16_to_cpu(cmd_hdr->tag);

	if (jd->cmd_tag != cmd_tag)
		dev_err(&udev->dev, "got command IRQ packet with invalid command tag, "
			"got (0x%04x), expected (0x%04x)\n", cmd_tag, jd->cmd_tag);

	eurus_cmd = le16_to_cpu(eurus_hdr->cmd);

	if ((jd->eurus_cmd + 1) != eurus_cmd)
		dev_err(&udev->dev, "got command IRQ packet with invalid EURUS command, "
			"got (0x%04x), expected (0x%04x)\n", eurus_cmd, jd->eurus_cmd);

	eurus_tag = le16_to_cpu(eurus_hdr->tag);

	if (jd->eurus_tag != eurus_tag)
		dev_err(&udev->dev, "got command IRQ packet with invalid EURUS tag, "
			"got (0x%04x), expected (0x%04x)\n", eurus_tag, jd->eurus_tag);

	memcpy(jd->cmd_buf, buf, length);

	jd->cmd_err = 0;
	complete(&jd->cmd_done_comp);
}

/*
 * ps3_jupiter_irq_urb_complete
 */
static void ps3_jupiter_irq_urb_complete(struct urb *urb)
{
	struct ps3_jupiter_dev *jd = urb->context;
	struct usb_device *udev = jd->udev;
	struct ps3_jupiter_pkt_hdr *pkt_hdr;
	int err;

	dev_dbg(&udev->dev, "IRQ URB completed (%d)\n", urb->status);

	switch (urb->status) {
	case 0:
		if (urb->actual_length < sizeof(*pkt_hdr)) {
			dev_err(&udev->dev, "got IRQ packet with invalid length (%d)\n",
				urb->actual_length);
			break;
		}

		pkt_hdr = (struct ps3_jupiter_pkt_hdr *) jd->irq_buf;

		switch (pkt_hdr->type) {
		case PS3_JUPITER_PKT_CMD:
			ps3_jupiter_cmd_irq(jd, pkt_hdr, urb->actual_length);
		break;
		case PS3_JUPITER_PKT_EVENT:
			ps3_jupiter_event_irq(jd, pkt_hdr, urb->actual_length);
		break;
		default:
			dev_err(&udev->dev, "got unknown IRQ packet type (%d)\n",
				pkt_hdr->type);
		break;
		}
	break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
	return;
	default:
		dev_err(&udev->dev, "IRQ URB failed (%d)\n", urb->status);
	break;
	}

	err = usb_submit_urb(jd->irq_urb, GFP_ATOMIC);
	if (err)
		dev_err(&udev->dev, "could not submit IRQ URB (%d)\n", err);
}

/*
 * ps3_jupiter_cmd_urb_complete
 */
static void ps3_jupiter_cmd_urb_complete(struct urb *urb)
{
	struct ps3_jupiter_dev *jd = urb->context;
	struct usb_device *udev = jd->udev;

	dev_dbg(&udev->dev, "command URB completed (%d)\n", urb->status);

	switch (urb->status) {
	case 0:
	break;
	case -ECONNRESET:
	case -ENOENT:
	case -ESHUTDOWN:
	default:
		dev_err(&udev->dev, "command URB failed (%d)\n", urb->status);
		jd->cmd_err = urb->status;
		complete(&jd->cmd_done_comp);
	break;
	}
}

/*
 * _ps3_jupiter_register_event_listener
 */
static int _ps3_jupiter_register_event_listener(struct ps3_jupiter_dev *jd,
	struct ps3_jupiter_event_listener *listener)
{
	struct ps3_jupiter_event_listener *entry;
	unsigned long flags;

	BUG_ON(!jd);

	rcu_read_lock();

	list_for_each_entry_rcu(entry, &jd->event_listeners, list) {
		if (entry == listener) {
			rcu_read_unlock();
			return -EINVAL;
		}
	}

	rcu_read_unlock();

	spin_lock_irqsave(&jd->event_listeners_lock, flags);
	list_add_tail_rcu(&listener->list, &jd->event_listeners);
	spin_unlock_irqrestore(&jd->event_listeners_lock, flags);

	synchronize_rcu();

	return 0;
}

/*
 * ps3_jupiter_register_event_listener
 */
int ps3_jupiter_register_event_listener(struct ps3_jupiter_event_listener *listener)
{
	struct ps3_jupiter_dev *jd = ps3jd;
	int err;

	if (!jd || !jd->dev_ready)
		return -ENODEV;

	err = _ps3_jupiter_register_event_listener(jd, listener);

	return err;
}

EXPORT_SYMBOL_GPL(ps3_jupiter_register_event_listener);

/*
 * _ps3_jupiter_unregister_event_listener
 */
static int _ps3_jupiter_unregister_event_listener(struct ps3_jupiter_dev *jd,
	struct ps3_jupiter_event_listener *listener)
{
	struct ps3_jupiter_event_listener *entry;
	unsigned long flags;

	BUG_ON(!jd);

	rcu_read_lock();

	list_for_each_entry_rcu(entry, &jd->event_listeners, list) {
		if (entry == listener) {
			rcu_read_unlock();
			spin_lock_irqsave(&jd->event_listeners_lock, flags);
			list_del_rcu(&listener->list);
			spin_unlock_irqrestore(&jd->event_listeners_lock, flags);
			synchronize_rcu();
			return 0;
		}
	}

	rcu_read_unlock();

	return -EINVAL;
}

/*
 * ps3_jupiter_unregister_event_listener
 */
int ps3_jupiter_unregister_event_listener(struct ps3_jupiter_event_listener *listener)
{
	struct ps3_jupiter_dev *jd = ps3jd;
	int err;

	if (!jd || !jd->dev_ready)
		return -ENODEV;

	err = _ps3_jupiter_unregister_event_listener(jd, listener);

	return err;
}

EXPORT_SYMBOL_GPL(ps3_jupiter_unregister_event_listener);

/*
 * _ps3_jupiter_exec_eurus_cmd
 */
static int _ps3_jupiter_exec_eurus_cmd(struct ps3_jupiter_dev *jd,
	enum ps3_eurus_cmd cmd,
	void *payload, unsigned int payload_length,
	unsigned int *response_status,
	unsigned int *response_length, void *response)
{
	struct usb_device *udev = jd->udev;
	struct ps3_jupiter_pkt_hdr *pkt_hdr;
	struct ps3_jupiter_cmd_hdr *cmd_hdr;
	struct ps3_eurus_hdr *eurus_hdr;
	unsigned long flags;
	int err;

	BUG_ON(!jd);

	if (!payload && payload_length)
		return -EINVAL;

	spin_lock_irqsave(&jd->cmd_lock, flags);

	if (jd->cmd_busy) {
		spin_unlock_irqrestore(&jd->cmd_lock, flags);
		dev_dbg(&udev->dev,
			"trying to execute multiple commands at the same time\n");
		return -EAGAIN;
	}

	jd->cmd_busy = 1;

	spin_unlock_irqrestore(&jd->cmd_lock, flags);

	dev_dbg(&udev->dev, "EURUS command 0x%02x payload length %d\n",
		cmd, payload_length);

	pkt_hdr = (struct ps3_jupiter_pkt_hdr *) jd->cmd_buf;
	memset(pkt_hdr, 0, sizeof(*pkt_hdr));
	pkt_hdr->unknown1 = 1;
	pkt_hdr->unknown2 = 1;
	pkt_hdr->type = PS3_JUPITER_PKT_CMD;

	cmd_hdr = (struct ps3_jupiter_cmd_hdr *) (pkt_hdr + 1);
	memset(cmd_hdr, 0, sizeof(*cmd_hdr));
	jd->cmd_tag++;
	cmd_hdr->unknown1 = 0;
	cmd_hdr->unknown2 = cpu_to_le16(1);
	cmd_hdr->tag = cpu_to_le16(jd->cmd_tag);

	eurus_hdr = (struct ps3_eurus_hdr *) (cmd_hdr + 1);
	memset(eurus_hdr, 0, sizeof(*eurus_hdr));
	jd->eurus_cmd = cmd;
	eurus_hdr->cmd = cpu_to_le16(cmd);
	jd->eurus_tag++;
	eurus_hdr->tag = cpu_to_le16(jd->eurus_tag);
	eurus_hdr->status = cpu_to_le16(0xa);
	eurus_hdr->payload_length = cpu_to_le16(payload_length);

	if (payload_length)
		memcpy(eurus_hdr + 1, payload, payload_length);

	init_completion(&jd->cmd_done_comp);

	usb_fill_int_urb(jd->cmd_urb, udev, usb_sndintpipe(udev, PS3_JUPITER_EP),
		jd->cmd_buf, sizeof(*pkt_hdr) + sizeof(*cmd_hdr) + sizeof(*eurus_hdr) + payload_length,
		ps3_jupiter_cmd_urb_complete, jd, 1);

	err = usb_submit_urb(jd->cmd_urb, GFP_KERNEL);
	if (err) {
		dev_err(&udev->dev, "could not submit command URB (%d)\n", err);
		goto done;
	}

	err = wait_for_completion_timeout(&jd->cmd_done_comp, HZ);
	if (!err) {
		err = -ETIMEDOUT;
		goto done;
	}

	err = jd->cmd_err;
	if (!err) {
		if (response_status)
			*response_status = le16_to_cpu(eurus_hdr->status);

		if (response_length && response) {
			*response_length = le16_to_cpu(eurus_hdr->payload_length);
			memcpy(response, eurus_hdr + 1, *response_length);
		}
	}

done:

	if (err)
		dev_err(&udev->dev, "EURUS command 0x%02x failed (%d)\n", cmd, err);

	jd->cmd_busy = 0;

	return err;
}

/*
 * _ps3_jupiter_exec_eurus_cmd
 */
int ps3_jupiter_exec_eurus_cmd(enum ps3_eurus_cmd cmd,
	void *payload, unsigned int payload_length,
	unsigned int *response_status,
	unsigned int *response_length, void *response)
{
	struct ps3_jupiter_dev *jd = ps3jd;
	int err;

	if (!jd || !jd->dev_ready)
		return -ENODEV;

	err = _ps3_jupiter_exec_eurus_cmd(jd, cmd, payload, payload_length,
		response_status, response_length, response);

	return err;
}

EXPORT_SYMBOL_GPL(ps3_jupiter_exec_eurus_cmd);

/*
 * ps3_jupiter_create_event_worker
 */
static int ps3_jupiter_create_event_worker(struct ps3_jupiter_dev *jd)
{
	jd->event_queue = create_singlethread_workqueue("ps3_jupiter_event");
	if (!jd->event_queue)
		return -ENOMEM;

	INIT_DELAYED_WORK(&jd->event_work, ps3_jupiter_event_worker);

	return 0;
}

/*
 * ps3_jupiter_destroy_event_worker
 */
static void ps3_jupiter_destroy_event_worker(struct ps3_jupiter_dev *jd)
{
	if (jd->event_queue) {
		cancel_delayed_work(&jd->event_work);
		flush_workqueue(jd->event_queue);
		destroy_workqueue(jd->event_queue);
		jd->event_queue = NULL;
	}
}

/*
 * ps3_jupiter_free_event_list
 */
static void ps3_jupiter_free_event_list(struct ps3_jupiter_dev *jd)
{
	struct ps3_jupiter_list_event *event, *tmp;

	list_for_each_entry_safe(event, tmp, &jd->event_list, list) {
		list_del(&event->list);
		kfree(event);
	}
}

/*
 * ps3_jupiter_alloc_urbs
 */
static int ps3_jupiter_alloc_urbs(struct ps3_jupiter_dev *jd)
{
	struct usb_device *udev = jd->udev;

	jd->irq_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!jd->irq_urb)
		return -ENOMEM;

	jd->irq_buf = usb_alloc_coherent(udev, PS3_JUPITER_IRQ_BUFSIZE,
		GFP_KERNEL, &jd->irq_urb->transfer_dma);
	if (!jd->irq_buf)
		return -ENOMEM;

	usb_fill_int_urb(jd->irq_urb, udev, usb_rcvintpipe(udev, PS3_JUPITER_EP),
		jd->irq_buf, PS3_JUPITER_IRQ_BUFSIZE, ps3_jupiter_irq_urb_complete, jd, 1);
	jd->irq_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	jd->cmd_urb = usb_alloc_urb(0, GFP_KERNEL);
	if (!jd->cmd_urb)
		return -ENOMEM;

	jd->cmd_buf = usb_alloc_coherent(udev, PS3_JUPITER_CMD_BUFSIZE,
		GFP_KERNEL, &jd->cmd_urb->transfer_dma);
	if (!jd->cmd_buf)
		return -ENOMEM;

	usb_fill_int_urb(jd->cmd_urb, udev, usb_sndintpipe(udev, PS3_JUPITER_EP),
		jd->cmd_buf, PS3_JUPITER_CMD_BUFSIZE, ps3_jupiter_cmd_urb_complete, jd, 1);
	jd->cmd_urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;

	return 0;
}

/*
 * ps3_jupiter_free_urbs
 */
static void ps3_jupiter_free_urbs(struct ps3_jupiter_dev *jd)
{
	struct usb_device *udev = jd->udev;

	if (jd->irq_urb) {
		usb_kill_urb(jd->irq_urb);

		if (jd->irq_buf)
			usb_free_coherent(udev, PS3_JUPITER_IRQ_BUFSIZE,
				jd->irq_buf, jd->irq_urb->transfer_dma);

		usb_free_urb(jd->irq_urb);
	}

	if (jd->cmd_urb) {
		usb_kill_urb(jd->cmd_urb);

		if (jd->cmd_buf)
			usb_free_coherent(udev, PS3_JUPITER_CMD_BUFSIZE,
				jd->cmd_buf, jd->cmd_urb->transfer_dma);

		usb_free_urb(jd->cmd_urb);
	}
}

/*
 * ps3_jupiter_dev_auth
 */
static int ps3_jupiter_dev_auth(struct ps3_jupiter_dev *jd)
{
	struct usb_device *udev = jd->udev;
	void *buf;
	int err;

	buf = kmalloc(sizeof(ps3_jupiter_devkey), GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, ps3_jupiter_devkey, sizeof(ps3_jupiter_devkey));

	err = usb_control_msg(udev, usb_sndctrlpipe(udev, 0),
		0x1, USB_TYPE_VENDOR | USB_DIR_OUT | USB_RECIP_DEVICE, 0x9, 0x0,
		buf, sizeof(ps3_jupiter_devkey), USB_CTRL_SET_TIMEOUT);
	if (err < 0) {
		dev_dbg(&udev->dev, "could not send device key (%d)\n", err);
		return err;
	}

	kfree(buf);

	err = usb_control_msg(udev, usb_rcvctrlpipe(udev, 0),
		0x0, USB_TYPE_VENDOR | USB_DIR_IN | USB_RECIP_DEVICE, 0x2, 0x0,
		&jd->dev_status, sizeof(jd->dev_status), USB_CTRL_GET_TIMEOUT);
	if (err < 0) {
		dev_dbg(&udev->dev, "could not read device status (%d)\n", err);
		return err;
	}

	dev_info(&udev->dev, "device status (0x%04x)\n", jd->dev_status);

	return 0;
}

/*
 * ps3_jupiter_event_handler
 */
static void ps3_jupiter_event_handler(struct ps3_jupiter_event_listener *listener,
	struct ps3_jupiter_event *event)
{
	struct ps3_jupiter_dev *jd = (struct ps3_jupiter_dev *) listener->data;
	struct usb_device *udev = jd->udev;

	dev_dbg(&udev->dev, "got event (0x%08x 0x%08x 0x%08x 0x%08x)\n",
		event->unknown1, event->unknown2, event->unknown3, event->unknown4);

	if (event->unknown1 == 0x400) {
		if ((event->unknown2 == 0x8) || (event->unknown2 == 0x10))
			complete(&jd->event_comp);
	}
}

/*
 * ps3_jupiter_dev_init
 */
static int ps3_jupiter_dev_init(struct ps3_jupiter_dev *jd)
{
	struct usb_device *udev = jd->udev;
	unsigned char *buf;
	unsigned int status;
	int err;

	buf = kmalloc(PS3_JUPITER_CMD_BUFSIZE, GFP_KERNEL);
	if (!buf) {
		err = -ENOMEM;
		goto done;
	}

	/* state 1 */

	memset(buf, 0, sizeof(buf));

	err = _ps3_jupiter_exec_eurus_cmd(jd, 0x114f, buf, 0x518, &status, NULL, NULL);
	if (err)
		goto done;

	dev_dbg(&udev->dev, "EURUS command 0x114f status (0x%04x)\n", status);

	/* state 2 */

	init_completion(&jd->event_comp);

	err = _ps3_jupiter_exec_eurus_cmd(jd, 0x1171, NULL, 0, &status, NULL, NULL);
	if (err)
		goto done;

	dev_dbg(&udev->dev, "EURUS command 0x1171 status (0x%04x)\n", status);

	if (status != 1) {
		err = -ENODEV;
		goto done;
	}

	/* state 3 */

	err = wait_for_completion_timeout(&jd->event_comp, HZ);
	if (!err) {
		err = -ETIMEDOUT;
		goto done;
	}

	err = 0;

done:

	kfree(buf);

	return err;
}

/*
 * ps3_jupiter_probe
 */
static int ps3_jupiter_probe(struct usb_interface *interface,
	const struct usb_device_id *id)
{
	struct usb_device *udev = interface_to_usbdev(interface);
	struct ps3_jupiter_dev *jd;
	u64 v1, v2;
	int err;

	if (ps3jd) {
		dev_err(&udev->dev, "only one device is supported\n");
		return -EBUSY;
	}

	ps3jd = jd = kzalloc(sizeof(struct ps3_jupiter_dev), GFP_KERNEL);
	if (!jd)
		return -ENOMEM;

	jd->udev = usb_get_dev(udev);
	usb_set_intfdata(interface, jd);

	spin_lock_init(&jd->cmd_lock);

	INIT_LIST_HEAD(&jd->event_listeners);
	spin_lock_init(&jd->event_listeners_lock);
	INIT_LIST_HEAD(&jd->event_list);
	spin_lock_init(&jd->event_list_lock);

	jd->event_listener.function = ps3_jupiter_event_handler;
	jd->event_listener.data = (unsigned long) jd;

	err = _ps3_jupiter_register_event_listener(jd, &jd->event_listener);
	if (err) {
		dev_err(&udev->dev, "could not register event listener (%d)\n", err);
		goto fail;
	}

	err = ps3_jupiter_create_event_worker(jd);
	if (err) {
		dev_err(&udev->dev, "could not create event work queue (%d)\n", err);
		goto fail;
	}

	err = ps3_jupiter_alloc_urbs(jd);
	if (err) {
		dev_err(&udev->dev, "could not allocate URBs (%d)\n", err);
		goto fail;
	}

	err = usb_submit_urb(jd->irq_urb, GFP_KERNEL);
	if (err) {
		dev_err(&udev->dev, "could not submit IRQ URB (%d)\n", err);
		goto fail;
	}

	err = ps3_jupiter_dev_auth(jd);
	if (err) {
		dev_err(&udev->dev, "could not authenticate device (%d)\n", err);
		goto fail;
	}

	/* get MAC address */

	err = lv1_net_control(1 /* bus id */, 0 /* device id */,
		LV1_GET_MAC_ADDRESS, 0, 0, 0, &v1, &v2);
	if (err) {
		dev_err(&udev->dev, "could not get MAC address (%d)\n", err);
		err = -ENODEV;
		goto fail;
	}

	v1 <<= 16;

	if (!is_valid_ether_addr((unsigned char *) &v1)) {
		dev_err(&udev->dev, "got invalid MAC address\n");
		err = -ENODEV;
		goto fail;
	}

	memcpy(jd->mac_addr, &v1, ETH_ALEN);

	err = ps3_jupiter_dev_init(jd);
	if (err) {
		dev_err(&udev->dev, "could not initialize device (%d)\n", err);
		goto fail;
	}

	jd->dev_ready = 1;

	return 0;

fail:

	ps3_jupiter_free_urbs(jd);

	ps3_jupiter_destroy_event_worker(jd);

	ps3_jupiter_free_event_list(jd);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(udev);

	kfree(jd);
	ps3jd = NULL;

	return err;
}

/*
 * ps3_jupiter_disconnect
 */
static void ps3_jupiter_disconnect(struct usb_interface *interface)
{
	struct ps3_jupiter_dev *jd = usb_get_intfdata(interface);
	struct usb_device *udev = jd->udev;

	jd->dev_ready = 0;

	ps3_jupiter_free_urbs(jd);

	ps3_jupiter_destroy_event_worker(jd);

	ps3_jupiter_free_event_list(jd);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(udev);

	kfree(jd);
	ps3jd = NULL;
}

#ifdef CONFIG_PM
/*
 * ps3_jupiter_suspend
 */
static int ps3_jupiter_suspend(struct usb_interface *interface, pm_message_t state)
{
	return 0;
}

/*
 * ps3_jupiter_resume
 */
static int ps3_jupiter_resume(struct usb_interface *interface)
{
	return 0;
}
#endif /* CONFIG_PM */

static struct usb_device_id ps3_jupiter_devtab[] = {
	{
		.match_flags = USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_INT_INFO,
		.idVendor = 0x054c,
		.idProduct = 0x036f,
		.bInterfaceClass = USB_CLASS_VENDOR_SPEC,
		.bInterfaceSubClass = 2,
		.bInterfaceProtocol = 1
	},
	{ }
};

static struct usb_driver ps3_jupiter_drv = {
	.name		= KBUILD_MODNAME,
	.id_table	= ps3_jupiter_devtab,
	.probe		= ps3_jupiter_probe,
	.disconnect	= ps3_jupiter_disconnect,
#ifdef CONFIG_PM
	.suspend	= ps3_jupiter_suspend,
	.resume		= ps3_jupiter_resume,
#endif /* CONFIG_PM */
};

/*
 * ps3_jupiter_init
 */
static int __init ps3_jupiter_init(void)
{
	return usb_register(&ps3_jupiter_drv);
}

/*
 * ps3_jupiter_exit
 */
static void __exit ps3_jupiter_exit(void)
{
	usb_deregister(&ps3_jupiter_drv);
}

module_init(ps3_jupiter_init);
module_exit(ps3_jupiter_exit);

MODULE_DESCRIPTION("PS3 Jupiter");
MODULE_SUPPORTED_DEVICE("PS3 Jupiter");
MODULE_DEVICE_TABLE(usb, ps3_jupiter_devtab);
MODULE_DESCRIPTION("PS3 Jupiter");
MODULE_AUTHOR("glevand");
MODULE_LICENSE("GPL");
