/*
 * drivers/usb/sunxi_usb/manager/usbc0_platform.c
 * (C) Copyright 2010-2015
 * Allwinner Technology Co., Ltd. <www.allwinnertech.com>
 * javen, 2011-4-14, create this file
 *
 * usb controller0 device info.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/clk.h>

#include <linux/debugfs.h>
#include <linux/seq_file.h>

#include <asm/byteorder.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/system.h>
#include <asm/unaligned.h>
#include <mach/irqs.h>
#include <mach/platform.h>

#include  "../include/sunxi_usb_config.h"
#include  "usb_hw_scan.h"

int usb_hw_scan_debug = 0;

/* device info description */
#ifndef CONFIG_ARCH_SUN9IW1
static struct sunxi_udc_mach_info sunxi_udc_cfg;

static u64 sunxi_udc_dmamask = 0xffffffffUL;

static struct platform_device sunxi_udc_device = {
	.name	= "sunxi_usb_udc",
	.id	= -1,

	.dev = {
		.dma_mask		= &sunxi_udc_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data		= &sunxi_udc_cfg,
	},
};

/* host info description */
static struct sunxi_hcd_eps_bits sunxi_hcd_eps[] = {
	{ "ep1_tx", 8, },
	{ "ep1_rx", 8, },
	{ "ep2_tx", 8, },
	{ "ep2_rx", 8, },
	{ "ep3_tx", 8, },
	{ "ep3_rx", 8, },
	{ "ep4_tx", 8, },
	{ "ep4_rx", 8, },
	{ "ep5_tx", 8, },
	{ "ep5_rx", 8, },
};

static struct sunxi_hcd_config sunxi_hcd_config = {
	.multipoint	= 1,
	.dyn_fifo	= 1,
	.soft_con	= 1,
	.dma		= 0,

	.num_eps	= USBC_MAX_EP_NUM,
	.dma_channels	= 0,
	.ram_size	= USBC0_MAX_FIFO_SIZE,
	.eps_bits	= sunxi_hcd_eps,
};

static struct sunxi_hcd_platform_data sunxi_hcd_plat = {
	.mode		= SW_HCD_HOST,
	.config		= &sunxi_hcd_config,
};

//static u64 sunxi_hcd_dmamask = DMA_BIT_MASK(32);
static struct platform_device sunxi_hcd_device = {
	.name		= "sunxi_hcd_host0",
	.id		= -1,

	.dev = {
		//.dma_mask		= &sunxi_hcd_dmamask,
		//.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data		= &sunxi_hcd_plat,
	},
};
#else

#include "../usb3/osal.h"

static u64 sunxi_otg_dmamask = 0xffffffffUL;

static struct resource sunxi_otg_resources[] = {
	/* order is significant! */
	{		/* registers */
		.start		= 0,
		.end		= 0 + 0xfffff,
		.flags		= IORESOURCE_MEM,
	}, {		/* general IRQ */
		.start		= SUNXI_IRQ_USB_OTG,
		.flags		= IORESOURCE_IRQ,
	},
};

static struct platform_device sunxi_otg = {
	.name				= "sunxi_otg",
	.id				= -1,

	.dev = {
		.dma_mask		= &sunxi_otg_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data		= NULL,
	},
	.num_resources	= ARRAY_SIZE(sunxi_otg_resources),
	.resource	= sunxi_otg_resources,
};

#endif

#ifdef  SUNXI_USB_FPGA
static ssize_t device_chose(struct device * dev,struct device_attribute * attr,char * buf)
{
	set_vbus_id_state(3);

	return sprintf(buf, "%s\n", "device_chose finished!");
}

static ssize_t host_chose(struct device * dev,struct device_attribute * attr,char * buf)
{
	set_vbus_id_state(2);

	return sprintf(buf, "%s\n", "host_chose finished!");
}

static ssize_t null_chose(struct device * dev,struct device_attribute * attr,char * buf)
{
	set_vbus_id_state(1);

	return sprintf(buf, "%s\n", "null_chose finished!");
}

static struct device_attribute chose_attrs[] = {
	__ATTR(usb_null, 0400, null_chose, NULL),
	__ATTR(usb_host, 0400, host_chose, NULL),
	__ATTR(usb_device, 0400, device_chose, NULL),
};
#endif

static ssize_t show_otg_hw_scan_debug(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", usb_hw_scan_debug);
}

static ssize_t otg_hw_scan_debug(struct device *dev, struct device_attribute *attr,
							const char *buf, size_t count)
{
	int debug = 0;

	sscanf(buf, "%d", &debug);
	usb_hw_scan_debug = debug;

	return count;
}
static DEVICE_ATTR(hw_scan_debug, 0644, show_otg_hw_scan_debug, otg_hw_scan_debug);


__s32 usbc0_platform_device_init(struct usb_port_info *port_info)
{
	/* device */
#ifndef CONFIG_ARCH_SUN9IW1
	sunxi_udc_cfg.port_info = port_info;
	sunxi_udc_cfg.usbc_base = (unsigned int __force)SUNXI_USB_OTG_VBASE;

	/* host */
	sunxi_hcd_config.port_info = port_info;

	switch(port_info->port_type) {
	case USB_PORT_TYPE_DEVICE:
		platform_device_register(&sunxi_udc_device);
		break;

	case USB_PORT_TYPE_HOST:
		platform_device_register(&sunxi_hcd_device);
		break;

	case USB_PORT_TYPE_OTG:
		platform_device_register(&sunxi_udc_device);
		platform_device_register(&sunxi_hcd_device);

		device_create_file(&sunxi_udc_device.dev, &dev_attr_hw_scan_debug);

#ifdef  SUNXI_USB_FPGA
{
	int ret = 0;
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(chose_attrs); i++) {
		ret = device_create_file(&sunxi_hcd_device.dev, &chose_attrs[i]);
		if (ret)
			printk("create_host_attrs_file fail\n");
	}
}
#endif
		break;

	default:
		DMSG_PANIC("ERR: unkown port_type(%d)\n", port_info->port_type);
	}
#else

	sunxi_otg.resource[0].start =  sunxi_otgc_base();
	sunxi_otg.resource[0].end =  sunxi_otgc_base() + 0xfffff;
	platform_device_register(&sunxi_otg);
	device_create_file(&sunxi_otg.dev, &dev_attr_hw_scan_debug);

#ifdef  SUNXI_USB_FPGA
{
	int ret = 0;
	int i = 0;
	for (i = 0; i < ARRAY_SIZE(chose_attrs); i++) {
		ret = device_create_file(&sunxi_otg.dev, &chose_attrs[i]);
		if (ret)
			printk("create_host_attrs_file fail\n");
	}
}
#endif

#endif

	return 0;
}

__s32 usbc0_platform_device_exit(struct usb_port_info *info)
{

#ifndef CONFIG_ARCH_SUN9IW1
	switch(info->port_type){
		case USB_PORT_TYPE_DEVICE:
			platform_device_unregister(&sunxi_udc_device);
		break;

		case USB_PORT_TYPE_HOST:
			platform_device_unregister(&sunxi_hcd_device);
		break;

		case USB_PORT_TYPE_OTG:
			platform_device_unregister(&sunxi_udc_device);
			platform_device_unregister(&sunxi_hcd_device);
		break;

		default:
			DMSG_PANIC("ERR: unkown port_type(%d)\n", info->port_type);
	}
#else
	platform_device_unregister(&sunxi_otg);
#endif
	return 0;
}

