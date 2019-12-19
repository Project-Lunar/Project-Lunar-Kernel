/*
 *  HID support for Linux
 *
 *  Copyright (c) 1999 Andreas Gal
 *  Copyright (c) 2000-2005 Vojtech Pavlik <vojtech@suse.cz>
 *  Copyright (c) 2005 Michael Haboustak <mike-@cinci.rr.com> for Concept2, Inc
 *  Copyright (c) 2006-2012 Jiri Kosina
 */

/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <asm/unaligned.h>
#include <asm/byteorder.h>
#include <linux/input.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/semaphore.h>

#include <linux/hid.h>
#include <linux/hiddev.h>
#include <linux/hid-debug.h>
#include <linux/hidraw.h>

#include "hid-ids.h"

/*
 * Version Information
 */

#define DRIVER_DESC "HID core driver"
#define DRIVER_LICENSE "GPL"

#ifdef CONFIG_HID_CRYPTO
#define RAND_LENGTH (40)
u8 const crc8_table[256] = {
	0x00, 0x31, 0x62, 0x53, 0xC4, 0xF5, 0xA6, 0x97,
	0xB9, 0x88, 0xDB, 0xEA, 0x7D, 0x4C, 0x1F, 0x2E,
	0x43, 0x72, 0x21, 0x10, 0x87, 0xB6, 0xE5, 0xD4,
	0xFA, 0xCB, 0x98, 0xA9, 0x3E, 0x0F, 0x5C, 0x6D,
	0x86, 0xB7, 0xE4, 0xD5, 0x42, 0x73, 0x20, 0x11,
	0x3F, 0x0E, 0x5D, 0x6C, 0xFB, 0xCA, 0x99, 0xA8,
	0xC5, 0xF4, 0xA7, 0x96, 0x01, 0x30, 0x63, 0x52,
	0x7C, 0x4D, 0x1E, 0x2F, 0xB8, 0x89, 0xDA, 0xEB,
	0x3D, 0x0C, 0x5F, 0x6E, 0xF9, 0xC8, 0x9B, 0xAA,
	0x84, 0xB5, 0xE6, 0xD7, 0x40, 0x71, 0x22, 0x13,
	0x7E, 0x4F, 0x1C, 0x2D, 0xBA, 0x8B, 0xD8, 0xE9,
	0xC7, 0xF6, 0xA5, 0x94, 0x03, 0x32, 0x61, 0x50,
	0xBB, 0x8A, 0xD9, 0xE8, 0x7F, 0x4E, 0x1D, 0x2C,
	0x02, 0x33, 0x60, 0x51, 0xC6, 0xF7, 0xA4, 0x95,
	0xF8, 0xC9, 0x9A, 0xAB, 0x3C, 0x0D, 0x5E, 0x6F,
	0x41, 0x70, 0x23, 0x12, 0x85, 0xB4, 0xE7, 0xD6,
	0x7A, 0x4B, 0x18, 0x29, 0xBE, 0x8F, 0xDC, 0xED,
	0xC3, 0xF2, 0xA1, 0x90, 0x07, 0x36, 0x65, 0x54,
	0x39, 0x08, 0x5B, 0x6A, 0xFD, 0xCC, 0x9F, 0xAE,
	0x80, 0xB1, 0xE2, 0xD3, 0x44, 0x75, 0x26, 0x17,
	0xFC, 0xCD, 0x9E, 0xAF, 0x38, 0x09, 0x5A, 0x6B,
	0x45, 0x74, 0x27, 0x16, 0x81, 0xB0, 0xE3, 0xD2,
	0xBF, 0x8E, 0xDD, 0xEC, 0x7B, 0x4A, 0x19, 0x28,
	0x06, 0x37, 0x64, 0x55, 0xC2, 0xF3, 0xA0, 0x91,
	0x47, 0x76, 0x25, 0x14, 0x83, 0xB2, 0xE1, 0xD0,
	0xFE, 0xCF, 0x9C, 0xAD, 0x3A, 0x0B, 0x58, 0x69,
	0x04, 0x35, 0x66, 0x57, 0xC0, 0xF1, 0xA2, 0x93,
	0xBD, 0x8C, 0xDF, 0xEE, 0x79, 0x48, 0x1B, 0x2A,
	0xC1, 0xF0, 0xA3, 0x92, 0x05, 0x34, 0x67, 0x56,
	0x78, 0x49, 0x1A, 0x2B, 0xBC, 0x8D, 0xDE, 0xEF,
	0x82, 0xB3, 0xE0, 0xD1, 0x46, 0x77, 0x24, 0x15,
	0x3B, 0x0A, 0x59, 0x68, 0xFF, 0xCE, 0x9D, 0xAC
};

static u8 crc8(u8 *pdata, size_t nbytes, u8 crc)
{
	/* loop over the buffer data */
	while (nbytes-- > 0)
		crc = crc8_table[(crc ^ *pdata++) & 0xff];

	return crc;
}
#endif

static int hid_num=0;
int hid_debug = 0;
module_param_named(debug, hid_debug, int, 0600);
MODULE_PARM_DESC(debug, "toggle HID debugging messages");
EXPORT_SYMBOL_GPL(hid_debug);

static int hid_ignore_special_drivers = 0;
module_param_named(ignore_special_drivers, hid_ignore_special_drivers, int, 0600);
MODULE_PARM_DESC(debug, "Ignore any special drivers and handle all devices by generic driver");

/*
 * Register a new report for a device.
 */

struct hid_report *hid_register_report(struct hid_device *device, unsigned type, unsigned id)
{
	struct hid_report_enum *report_enum = device->report_enum + type;
	struct hid_report *report;

	if (id >= HID_MAX_IDS)
		return NULL;
	if (report_enum->report_id_hash[id])
		return report_enum->report_id_hash[id];

	report = kzalloc(sizeof(struct hid_report), GFP_KERNEL);
	if (!report)
		return NULL;

	if (id != 0)
		report_enum->numbered = 1;

	report->id = id;
	report->type = type;
	report->size = 0;
	report->device = device;
	report_enum->report_id_hash[id] = report;

	list_add_tail(&report->list, &report_enum->report_list);

	return report;
}
EXPORT_SYMBOL_GPL(hid_register_report);

/*
 * Register a new field for this report.
 */

static struct hid_field *hid_register_field(struct hid_report *report, unsigned usages, unsigned values)
{
	struct hid_field *field;

	if (report->maxfield == HID_MAX_FIELDS) {
		hid_err(report->device, "too many fields in report\n");
		return NULL;
	}

	field = kzalloc((sizeof(struct hid_field) +
			 usages * sizeof(struct hid_usage) +
			 values * sizeof(unsigned)), GFP_KERNEL);
	if (!field)
		return NULL;

	field->index = report->maxfield++;
	report->field[field->index] = field;
	field->usage = (struct hid_usage *)(field + 1);
	field->value = (s32 *)(field->usage + usages);
	field->report = report;

	return field;
}

/*
 * Open a collection. The type/usage is pushed on the stack.
 */

static int open_collection(struct hid_parser *parser, unsigned type)
{
	struct hid_collection *collection;
	unsigned usage;

	usage = parser->local.usage[0];
	if (parser->collection_stack_ptr == HID_COLLECTION_STACK_SIZE) {
		hid_err(parser->device, "collection stack overflow\n");
		return -1;
	}

	if (parser->device->maxcollection == parser->device->collection_size) {
		collection = kmalloc(sizeof(struct hid_collection) *
				parser->device->collection_size * 2, GFP_KERNEL);
		if (collection == NULL) {
			hid_err(parser->device, "failed to reallocate collection array\n");
			return -1;
		}
		memcpy(collection, parser->device->collection,
			sizeof(struct hid_collection) *
			parser->device->collection_size);
		memset(collection + parser->device->collection_size, 0,
			sizeof(struct hid_collection) *
			parser->device->collection_size);
		kfree(parser->device->collection);
		parser->device->collection = collection;
		parser->device->collection_size *= 2;
	}

	parser->collection_stack[parser->collection_stack_ptr++] =
		parser->device->maxcollection;

	collection = parser->device->collection +
		parser->device->maxcollection++;
	collection->type = type;
	collection->usage = usage;
	collection->level = parser->collection_stack_ptr - 1;

	if (type == HID_COLLECTION_APPLICATION)
		parser->device->maxapplication++;

	return 0;
}

/*
 * Close a collection.
 */

static int close_collection(struct hid_parser *parser)
{
	if (!parser->collection_stack_ptr) {
		hid_err(parser->device, "collection stack underflow\n");
		return -1;
	}
	parser->collection_stack_ptr--;
	return 0;
}

/*
 * Climb up the stack, search for the specified collection type
 * and return the usage.
 */

static unsigned hid_lookup_collection(struct hid_parser *parser, unsigned type)
{
	struct hid_collection *collection = parser->device->collection;
	int n;

	for (n = parser->collection_stack_ptr - 1; n >= 0; n--) {
		unsigned index = parser->collection_stack[n];
		if (collection[index].type == type)
			return collection[index].usage;
	}
	return 0; /* we know nothing about this usage type */
}

/*
 * Add a usage to the temporary parser table.
 */

static int hid_add_usage(struct hid_parser *parser, unsigned usage)
{
	dbg_hid("%s,%d,usage=%x,index=%x\n",__func__,__LINE__,usage,parser->local.usage_index);
	if (parser->local.usage_index >= HID_MAX_USAGES) {
		hid_err(parser->device, "usage index exceeded\n");
		return -1;
	}
	parser->local.usage[parser->local.usage_index] = usage;
	parser->local.collection_index[parser->local.usage_index] =
		parser->collection_stack_ptr ?
		parser->collection_stack[parser->collection_stack_ptr - 1] : 0;
	parser->local.usage_index++;
	return 0;
}

/*
 * Register a new field for this report.
 */

static int hid_add_field(struct hid_parser *parser, unsigned report_type, unsigned flags)
{
	struct hid_report *report;
	struct hid_field *field;
	unsigned usages;
	unsigned offset;
	unsigned i;

	report = hid_register_report(parser->device, report_type, parser->global.report_id);
	if (!report) {
		hid_err(parser->device, "hid_register_report failed\n");
		return -1;
	}

	if (parser->global.logical_maximum < parser->global.logical_minimum) {
		hid_err(parser->device, "logical range invalid %d %d\n",
				parser->global.logical_minimum, parser->global.logical_maximum);
		return -1;
	}

	offset = report->size;
	report->size += parser->global.report_size * parser->global.report_count;

	if (!parser->local.usage_index) /* Ignore padding fields */
		return 0;

	usages = max_t(unsigned, parser->local.usage_index,
				 parser->global.report_count);

	field = hid_register_field(report, usages, parser->global.report_count);
	if (!field)
		return 0;

	field->physical = hid_lookup_collection(parser, HID_COLLECTION_PHYSICAL);
	field->logical = hid_lookup_collection(parser, HID_COLLECTION_LOGICAL);
	field->application = hid_lookup_collection(parser, HID_COLLECTION_APPLICATION);

	for (i = 0; i < usages; i++) {
		unsigned j = i;
		/* Duplicate the last usage we parsed if we have excess values */
		if (i >= parser->local.usage_index)
			j = parser->local.usage_index - 1;
		field->usage[i].hid = parser->local.usage[j];
		field->usage[i].collection_index =
			parser->local.collection_index[j];
	}

	field->maxusage = usages;
	field->flags = flags;
	field->report_offset = offset;
	field->report_type = report_type;
	field->report_size = parser->global.report_size;
	field->report_count = parser->global.report_count;
	field->logical_minimum = parser->global.logical_minimum;
	field->logical_maximum = parser->global.logical_maximum;
	field->physical_minimum = parser->global.physical_minimum;
	field->physical_maximum = parser->global.physical_maximum;
	field->unit_exponent = parser->global.unit_exponent;
	field->unit = parser->global.unit;

	return 0;
}

/*
 * Read data value from item.
 */

static u32 item_udata(struct hid_item *item)
{
	switch (item->size) {
	case 1: return item->data.u8;
	case 2: return item->data.u16;
	case 4: return item->data.u32;
	}
	return 0;
}

static s32 item_sdata(struct hid_item *item)
{
	switch (item->size) {
	case 1: return item->data.s8;
	case 2: return item->data.s16;
	case 4: return item->data.s32;
	}
	return 0;
}

/*
 * Process a global item.
 */

static int hid_parser_global(struct hid_parser *parser, struct hid_item *item)
{
	switch (item->tag) {
	case HID_GLOBAL_ITEM_TAG_PUSH:

		if (parser->global_stack_ptr == HID_GLOBAL_STACK_SIZE) {
			hid_err(parser->device, "global environment stack overflow\n");
			return -1;
		}

		memcpy(parser->global_stack + parser->global_stack_ptr++,
			&parser->global, sizeof(struct hid_global));
		return 0;

	case HID_GLOBAL_ITEM_TAG_POP:

		if (!parser->global_stack_ptr) {
			hid_err(parser->device, "global environment stack underflow\n");
			return -1;
		}

		memcpy(&parser->global, parser->global_stack +
			--parser->global_stack_ptr, sizeof(struct hid_global));
		return 0;

	case HID_GLOBAL_ITEM_TAG_USAGE_PAGE:
		parser->global.usage_page = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_LOGICAL_MINIMUM:
		parser->global.logical_minimum = item_sdata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_LOGICAL_MAXIMUM:
		if (parser->global.logical_minimum < 0)
			parser->global.logical_maximum = item_sdata(item);
		else
			parser->global.logical_maximum = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_PHYSICAL_MINIMUM:
		parser->global.physical_minimum = item_sdata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_PHYSICAL_MAXIMUM:
		if (parser->global.physical_minimum < 0)
			parser->global.physical_maximum = item_sdata(item);
		else
			parser->global.physical_maximum = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_UNIT_EXPONENT:
		parser->global.unit_exponent = item_sdata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_UNIT:
		parser->global.unit = item_udata(item);
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_SIZE:
		parser->global.report_size = item_udata(item);
		if (parser->global.report_size > 96) {
			hid_err(parser->device, "invalid report_size %d\n",
					parser->global.report_size);
			return -1;
		}
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_COUNT:
		parser->global.report_count = item_udata(item);
		if (parser->global.report_count > HID_MAX_USAGES) {
			hid_err(parser->device, "invalid report_count %d\n",
					parser->global.report_count);
			return -1;
		}
		return 0;

	case HID_GLOBAL_ITEM_TAG_REPORT_ID:
		parser->global.report_id = item_udata(item);
		if (parser->global.report_id == 0 ||
		    parser->global.report_id >= HID_MAX_IDS) {
			hid_err(parser->device, "report_id %u is invalid\n",
				parser->global.report_id);
			return -1;
		}
		return 0;

	default:
		hid_err(parser->device, "unknown global tag 0x%x\n", item->tag);
		return -1;
	}
}

/*
 * Process a local item.
 */

static int hid_parser_local(struct hid_parser *parser, struct hid_item *item)
{
	__u32 data;
	unsigned n;

	data = item_udata(item);

	switch (item->tag) {
	case HID_LOCAL_ITEM_TAG_DELIMITER:

		if (data) {
			/*
			 * We treat items before the first delimiter
			 * as global to all usage sets (branch 0).
			 * In the moment we process only these global
			 * items and the first delimiter set.
			 */
			if (parser->local.delimiter_depth != 0) {
				hid_err(parser->device, "nested delimiters\n");
				return -1;
			}
			parser->local.delimiter_depth++;
			parser->local.delimiter_branch++;
		} else {
			if (parser->local.delimiter_depth < 1) {
				hid_err(parser->device, "bogus close delimiter\n");
				return -1;
			}
			parser->local.delimiter_depth--;
		}
		return 1;

	case HID_LOCAL_ITEM_TAG_USAGE:

		if (parser->local.delimiter_branch > 1) {
			dbg_hid("alternative usage ignored\n");
			return 0;
		}

		if (item->size <= 2)
			data = (parser->global.usage_page << 16) + data;

		return hid_add_usage(parser, data);

	case HID_LOCAL_ITEM_TAG_USAGE_MINIMUM:

		if (parser->local.delimiter_branch > 1) {
			dbg_hid("alternative usage ignored\n");
			return 0;
		}

		if (item->size <= 2)
			data = (parser->global.usage_page << 16) + data;

		parser->local.usage_minimum = data;
		return 0;

	case HID_LOCAL_ITEM_TAG_USAGE_MAXIMUM:

		if (parser->local.delimiter_branch > 1) {
			dbg_hid("alternative usage ignored\n");
			return 0;
		}

		if (item->size <= 2)
			data = (parser->global.usage_page << 16) + data;

		for (n = parser->local.usage_minimum; n <= data; n++)
			if (hid_add_usage(parser, n)) {
				dbg_hid("hid_add_usage failed\n");
				return -1;
			}
		return 0;

	default:

		dbg_hid("unknown local item tag 0x%x\n", item->tag);
		return 0;
	}
	return 0;
}

/*
 * Process a main item.
 */

static int hid_parser_main(struct hid_parser *parser, struct hid_item *item)
{
	__u32 data;
	int ret;

	data = item_udata(item);

	switch (item->tag) {
	case HID_MAIN_ITEM_TAG_BEGIN_COLLECTION:
		ret = open_collection(parser, data & 0xff);
		break;
	case HID_MAIN_ITEM_TAG_END_COLLECTION:
		ret = close_collection(parser);
		break;
	case HID_MAIN_ITEM_TAG_INPUT:
		ret = hid_add_field(parser, HID_INPUT_REPORT, data);
		break;
	case HID_MAIN_ITEM_TAG_OUTPUT:
		ret = hid_add_field(parser, HID_OUTPUT_REPORT, data);
		break;
	case HID_MAIN_ITEM_TAG_FEATURE:
		ret = hid_add_field(parser, HID_FEATURE_REPORT, data);
		break;
	default:
		hid_err(parser->device, "unknown main item tag 0x%x\n", item->tag);
		ret = 0;
	}

	memset(&parser->local, 0, sizeof(parser->local));	/* Reset the local parser environment */

	return ret;
}

/*
 * Process a reserved item.
 */

static int hid_parser_reserved(struct hid_parser *parser, struct hid_item *item)
{
	dbg_hid("reserved item type, tag 0x%x\n", item->tag);
	return 0;
}

/*
 * Free a report and all registered fields. The field->usage and
 * field->value table's are allocated behind the field, so we need
 * only to free(field) itself.
 */

static void hid_free_report(struct hid_report *report)
{
	unsigned n;

	for (n = 0; n < report->maxfield; n++)
		kfree(report->field[n]);
	kfree(report);
}

/*
 * Free a device structure, all reports, and all fields.
 */

static void hid_device_release(struct device *dev)
{
	struct hid_device *device = container_of(dev, struct hid_device, dev);
	unsigned i, j;

	for (i = 0; i < HID_REPORT_TYPES; i++) {
		struct hid_report_enum *report_enum = device->report_enum + i;

		for (j = 0; j < HID_MAX_IDS; j++) {
			struct hid_report *report = report_enum->report_id_hash[j];
			if (report)
				hid_free_report(report);
		}
	}

	kfree(device->rdesc);
	kfree(device->collection);
	kfree(device);
}

/*
 * Fetch a report description item from the data stream. We support long
 * items, though they are not used yet.
 */

static u8 *fetch_item(__u8 *start, __u8 *end, struct hid_item *item)
{
	u8 b;

	if ((end - start) <= 0)
		return NULL;

	b = *start++;

	item->type = (b >> 2) & 3;
	item->tag  = (b >> 4) & 15;

	if (item->tag == HID_ITEM_TAG_LONG) {

		item->format = HID_ITEM_FORMAT_LONG;

		if ((end - start) < 2)
			return NULL;

		item->size = *start++;
		item->tag  = *start++;

		if ((end - start) < item->size)
			return NULL;

		item->data.longdata = start;
		start += item->size;
		return start;
	}

	item->format = HID_ITEM_FORMAT_SHORT;
	item->size = b & 3;

	switch (item->size) {
	case 0:
		return start;

	case 1:
		if ((end - start) < 1)
			return NULL;
		item->data.u8 = *start++;
		return start;

	case 2:
		if ((end - start) < 2)
			return NULL;
		item->data.u16 = get_unaligned_le16(start);
		start = (__u8 *)((__le16 *)start + 1);
		return start;

	case 3:
		item->size++;
		if ((end - start) < 4)
			return NULL;
		item->data.u32 = get_unaligned_le32(start);
		start = (__u8 *)((__le32 *)start + 1);
		return start;
	}

	return NULL;
}

/**
 * hid_parse_report - parse device report
 *
 * @device: hid device
 * @start: report start
 * @size: report size
 *
 * Parse a report description into a hid_device structure. Reports are
 * enumerated, fields are attached to these reports.
 * 0 returned on success, otherwise nonzero error value.
 */
int hid_parse_report(struct hid_device *device, __u8 *start,
		unsigned size)
{
	struct hid_parser *parser;
	struct hid_item item;
	__u8 *end;
	int ret;
	static int (*dispatch_type[])(struct hid_parser *parser,
				      struct hid_item *item) = {
		hid_parser_main,
		hid_parser_global,
		hid_parser_local,
		hid_parser_reserved
	};

	if (device->driver->report_fixup)
		start = device->driver->report_fixup(device, start, &size);

	device->rdesc = kmemdup(start, size, GFP_KERNEL);
	if (device->rdesc == NULL)
		return -ENOMEM;
	device->rsize = size;

	parser = vzalloc(sizeof(struct hid_parser));
	if (!parser) {
		ret = -ENOMEM;
		goto err;
	}

	parser->device = device;

	end = start + size;
	ret = -EINVAL;
	while ((start = fetch_item(start, end, &item)) != NULL) {

		if (item.format != HID_ITEM_FORMAT_SHORT) {
			hid_err(device, "unexpected long global item\n");
			goto err;
		}

		if (dispatch_type[item.type](parser, &item)) {
			hid_err(device, "item %u %u %u %u parsing failed\n",
				item.format, (unsigned)item.size,
				(unsigned)item.type, (unsigned)item.tag);
			goto err;
		}

		if (start == end) {
			if (parser->collection_stack_ptr) {
				hid_err(device, "unbalanced collection at end of report description\n");
				goto err;
			}
			if (parser->local.delimiter_depth) {
				hid_err(device, "unbalanced delimiter at end of report description\n");
				goto err;
			}
			vfree(parser);
			return 0;
		}
	}

	hid_err(device, "item fetching failed at offset %d\n", (int)(end - start));
err:
	vfree(parser);
	return ret;
}
EXPORT_SYMBOL_GPL(hid_parse_report);

/*
 * Convert a signed n-bit integer to signed 32-bit integer. Common
 * cases are done through the compiler, the screwed things has to be
 * done by hand.
 */

static s32 snto32(__u32 value, unsigned n)
{
	switch (n) {
	case 8:  return ((__s8)value);
	case 16: return ((__s16)value);
	case 32: return ((__s32)value);
	}
	return value & (1 << (n - 1)) ? value | (-1 << n) : value;
}

/*
 * Convert a signed 32-bit integer to a signed n-bit integer.
 */

static u32 s32ton(__s32 value, unsigned n)
{
	s32 a = value >> (n - 1);
	if (a && a != -1)
		return value < 0 ? 1 << (n - 1) : (1 << (n - 1)) - 1;
	return value & ((1 << n) - 1);
}

/*
 * Extract/implement a data field from/to a little endian report (bit array).
 *
 * Code sort-of follows HID spec:
 *     http://www.usb.org/developers/devclass_docs/HID1_11.pdf
 *
 * While the USB HID spec allows unlimited length bit fields in "report
 * descriptors", most devices never use more than 16 bits.
 * One model of UPS is claimed to report "LINEV" as a 32-bit field.
 * Search linux-kernel and linux-usb-devel archives for "hid-core extract".
 */

static __u32 extract(const struct hid_device *hid, __u8 *report,
		     unsigned offset, unsigned n)
{
	u64 x;

	if (n > 32)
		hid_warn(hid, "extract() called with n (%d) > 32! (%s)\n",
			 n, current->comm);

	report += offset >> 3;  /* adjust byte index */
	offset &= 7;            /* now only need bit offset into one byte */
	x = get_unaligned_le64(report);
	x = (x >> offset) & ((1ULL << n) - 1);  /* extract bit field */
	return (u32) x;
}

/*
 * "implement" : set bits in a little endian bit stream.
 * Same concepts as "extract" (see comments above).
 * The data mangled in the bit stream remains in little endian
 * order the whole time. It make more sense to talk about
 * endianness of register values by considering a register
 * a "cached" copy of the little endiad bit stream.
 */
static void implement(const struct hid_device *hid, __u8 *report,
		      unsigned offset, unsigned n, __u32 value)
{
	u64 x;
	u64 m = (1ULL << n) - 1;

	if (n > 32)
		hid_warn(hid, "%s() called with n (%d) > 32! (%s)\n",
			 __func__, n, current->comm);

	if (value > m)
		hid_warn(hid, "%s() called with too large value %d! (%s)\n",
			 __func__, value, current->comm);
	WARN_ON(value > m);
	value &= m;

	report += offset >> 3;
	offset &= 7;

	x = get_unaligned_le64(report);
	x &= ~(m << offset);
	x |= ((u64)value) << offset;
	put_unaligned_le64(x, report);
}

/*
 * Search an array for a value.
 */

static int search(__s32 *array, __s32 value, unsigned n)
{
	while (n--) {
		if (*array++ == value)
			return 0;
	}
	return -1;
}

static const char * const hid_report_names[] = {
	"HID_INPUT_REPORT",
	"HID_OUTPUT_REPORT",
	"HID_FEATURE_REPORT",
};
/**
 * hid_validate_values - validate existing device report's value indexes
 *
 * @device: hid device
 * @type: which report type to examine
 * @id: which report ID to examine (0 for first)
 * @field_index: which report field to examine
 * @report_counts: expected number of values
 *
 * Validate the number of values in a given field of a given report, after
 * parsing.
 */
struct hid_report *hid_validate_values(struct hid_device *hid,
				       unsigned int type, unsigned int id,
				       unsigned int field_index,
				       unsigned int report_counts)
{
	struct hid_report *report;

	if (type > HID_FEATURE_REPORT) {
		hid_err(hid, "invalid HID report type %u\n", type);
		return NULL;
	}

	if (id >= HID_MAX_IDS) {
		hid_err(hid, "invalid HID report id %u\n", id);
		return NULL;
	}

	/*
	 * Explicitly not using hid_get_report() here since it depends on
	 * ->numbered being checked, which may not always be the case when
	 * drivers go to access report values.
	 */
	if (id == 0) {
		/*
		 * Validating on id 0 means we should examine the first
		 * report in the list.
		 */
		report = list_entry(
				hid->report_enum[type].report_list.next,
				struct hid_report, list);
	} else {
		report = hid->report_enum[type].report_id_hash[id];
	}
	if (!report) {
		hid_err(hid, "missing %s %u\n", hid_report_names[type], id);
		return NULL;
	}
	if (report->maxfield <= field_index) {
		hid_err(hid, "not enough fields in %s %u\n",
			hid_report_names[type], id);
		return NULL;
	}
	if (report->field[field_index]->report_count < report_counts) {
		hid_err(hid, "not enough values in %s %u field %u\n",
			hid_report_names[type], id, field_index);
		return NULL;
	}
	return report;
}
EXPORT_SYMBOL_GPL(hid_validate_values);

/**
 * hid_match_report - check if driver's raw_event should be called
 *
 * @hid: hid device
 * @report_type: type to match against
 *
 * compare hid->driver->report_table->report_type to report->type
 */
static int hid_match_report(struct hid_device *hid, struct hid_report *report)
{
	const struct hid_report_id *id = hid->driver->report_table;

	if (!id) /* NULL means all */
		return 1;

	for (; id->report_type != HID_TERMINATOR; id++)
		if (id->report_type == HID_ANY_ID ||
				id->report_type == report->type)
			return 1;
	return 0;
}

/**
 * hid_match_usage - check if driver's event should be called
 *
 * @hid: hid device
 * @usage: usage to match against
 *
 * compare hid->driver->usage_table->usage_{type,code} to
 * usage->usage_{type,code}
 */
static int hid_match_usage(struct hid_device *hid, struct hid_usage *usage)
{
	const struct hid_usage_id *id = hid->driver->usage_table;

	if (!id) /* NULL means all */
		return 1;

	for (; id->usage_type != HID_ANY_ID - 1; id++)
		if ((id->usage_hid == HID_ANY_ID ||
				id->usage_hid == usage->hid) &&
				(id->usage_type == HID_ANY_ID ||
				id->usage_type == usage->type) &&
				(id->usage_code == HID_ANY_ID ||
				 id->usage_code == usage->code))
			return 1;
	return 0;
}

static void hid_process_event(struct hid_device *hid, struct hid_field *field,
		struct hid_usage *usage, __s32 value, int interrupt)
{
	struct hid_driver *hdrv = hid->driver;
	int ret;

	hid_dump_input(hid, usage, value);

	if (hdrv && hdrv->event && hid_match_usage(hid, usage)) {
		ret = hdrv->event(hid, field, usage, value);
		if (ret != 0) {
			if (ret < 0)
				hid_err(hid, "%s's event failed with %d\n",
						hdrv->name, ret);
			return;
		}
	}

	if (hid->claimed & HID_CLAIMED_INPUT)
		hidinput_hid_event(hid, field, usage, value);
	if (hid->claimed & HID_CLAIMED_HIDDEV && interrupt && hid->hiddev_hid_event)
		hid->hiddev_hid_event(hid, field, usage, value);
}

/*
 * Analyse a received field, and fetch the data from it. The field
 * content is stored for next report processing (we do differential
 * reporting to the layer).
 */
#ifdef CONFIG_HID_CRYPTO
const u8 rand_table[256] = {
	0xA9, 0xBD, 0xBE, 0xBF, 0x8C, 0xA1, 0x8D, 0x9D,
	0x89, 0x8A, 0xFD, 0xA0, 0xA2, 0xFE, 0x84, 0xA8,
	0xB4, 0xB5, 0xB8, 0xC6, 0xB9, 0xBA, 0xAF, 0xB0,
	0x4E, 0x75, 0x3D, 0x01, 0x1F, 0x68, 0x40, 0x5E,
	0x2B, 0x02, 0x4A, 0x3F, 0x47, 0x3C, 0x0C, 0x64,
	0xFA, 0xFC, 0x85, 0xC0, 0xFB, 0xC1, 0x93, 0xE1,
	0xE4, 0xF9, 0xFF, 0x96, 0x86, 0x8F, 0x91, 0xF8,
	0x94, 0x87, 0xBC, 0xAD, 0x88, 0xC2, 0x92, 0xBB,
	0x28, 0x34, 0x00, 0x25, 0x50, 0x0F, 0x35, 0x7D,
	0xEB, 0xDF, 0xE0, 0xE6, 0xE9, 0xD4, 0xEA, 0xF5,
	0x79, 0x33, 0x6F, 0x4B, 0x22, 0x60, 0x23, 0x44,
	0x41, 0x14, 0x1C, 0x70, 0x12, 0x31, 0x43, 0x65,
	0x04, 0x18, 0x51, 0x7B, 0x30, 0x36, 0x52, 0x13,
	0x09, 0x0A, 0x16, 0x62, 0x3A, 0x5C, 0x6E, 0x7A,
	0xA6, 0x80, 0x8B, 0x81, 0xF1, 0x82, 0xF2, 0x83,
	0xA7, 0xC7, 0xCC, 0xDA, 0xD1, 0xC8, 0xC3, 0xB2,
	0xC4, 0xB6, 0xB7, 0xC5, 0xC9, 0xCA, 0xD0, 0xD6,
	0x7E, 0x6D, 0x76, 0x4F, 0x0D, 0x6C, 0x2E, 0x07,
	0x9C, 0xF0, 0xE2, 0x90, 0xE3, 0xF3, 0xF4, 0x99,
	0x54, 0x5D, 0x1A, 0x2C, 0x05, 0x1E, 0x06, 0x7F,
	0x38, 0x5F, 0x2A, 0x59, 0x24, 0x5A, 0x37, 0x46,
	0xD7, 0xCB, 0xD2, 0xD9, 0xD3, 0xDD, 0xD5, 0xCD,
	0x27, 0x0B, 0x56, 0x78, 0x67, 0x77, 0x2F, 0x55,
	0x71, 0x19, 0x29, 0x49, 0x32, 0x21, 0x5B, 0x2D,
	0x4C, 0x11, 0x57, 0x58, 0x15, 0x61, 0x17, 0x20,
	0x53, 0x74, 0x26, 0x10, 0x63, 0x48, 0x42, 0x6A,
	0xEC, 0xF6, 0xEE, 0xF7, 0xEF, 0x98, 0xED, 0x97,
	0x9E, 0x9F, 0xA3, 0x9B, 0xE5, 0x95, 0x8E, 0xA4,
	0xA5, 0xAB, 0x9A, 0xAC, 0xB1, 0xAA, 0xB3, 0xAE,
	0x6B, 0x1B, 0x4D, 0x0E, 0x1D, 0x45, 0x03, 0x08,
	0xCE, 0xCF, 0xD8, 0xDB, 0xE7, 0xE8, 0xDC, 0xDE,
	0x39, 0x3E, 0x3B, 0x72, 0x7C, 0x73, 0x66, 0x69
};
#endif

static void hid_input_field(struct hid_device *hid, struct hid_field *field,
			    __u8 *data, int interrupt)
{
	unsigned n;
	unsigned count = field->report_count;
	unsigned offset = field->report_offset;
	unsigned size = field->report_size;
	__s32 min = field->logical_minimum;
	__s32 max = field->logical_maximum;
	__s32 *value;

	dbg_hid("field->index=%d,min=%d,max=%d,report_count=%d,offset=%d,size=%d,flags=%d\n", \
			field->index,min,max,count,offset,size,field->flags);
	value = kmalloc(sizeof(__s32) * count, GFP_ATOMIC);
	if (!value)
		return;
	for (n = 0; n < count; n++) {
		value[n] = min < 0 ?
			snto32(extract(hid, data, offset + n * size, size),
				size) :
			extract(hid, data, offset + n * size, size);
		/* Ignore report if ErrorRollOver */
		if (!(field->flags & HID_MAIN_ITEM_VARIABLE) &&
			value[n] >= min && value[n] <= max &&
			field->usage[value[n] - min].hid == HID_UP_KEYBOARD + 1)
			goto exit;
	}

	for (n = 0; n < count; n++) {

		if (HID_MAIN_ITEM_VARIABLE & field->flags) {
			hid_process_event(hid, field, &field->usage[n], value[n], interrupt);
			continue;
		}

		if (field->value[n] >= min && field->value[n] <= max
			&& field->usage[field->value[n] - min].hid
			&& search(value, field->value[n], count))
				hid_process_event(hid, field, &field->usage[field->value[n] - min], 0, interrupt);

		if (value[n] >= min && value[n] <= max
			&& field->usage[value[n] - min].hid
			&& search(field->value, value[n], count))
				hid_process_event(hid, field, &field->usage[value[n] - min], 1, interrupt);
	}

	memcpy(field->value, value, count * sizeof(__s32));
exit:
	kfree(value);
}

/*
 * Output the field into the report.
 */

static void hid_output_field(const struct hid_device *hid,
			     struct hid_field *field, __u8 *data)
{
	unsigned count = field->report_count;
	unsigned offset = field->report_offset;
	unsigned size = field->report_size;
	unsigned n;

	for (n = 0; n < count; n++) {
		if (field->logical_minimum < 0)	/* signed values */
			implement(hid, data, offset + n * size, size,
				  s32ton(field->value[n], size));
		else				/* unsigned values */
			implement(hid, data, offset + n * size, size,
				  field->value[n]);
	}
}

/*
 * Create a report.
 */

void hid_output_report(struct hid_report *report, __u8 *data)
{
	unsigned n;

	if (report->id > 0)
		*data++ = report->id;

	memset(data, 0, ((report->size - 1) >> 3) + 1);
	for (n = 0; n < report->maxfield; n++)
		hid_output_field(report->device, report->field[n], data);
}
EXPORT_SYMBOL_GPL(hid_output_report);

/*
 * Set a field value. The report this field belongs to has to be
 * created and transferred to the device, to set this value in the
 * device.
 */

int hid_set_field(struct hid_field *field, unsigned offset, __s32 value)
{
	unsigned size;

	if (!field)
		return -1;

	size = field->report_size;

	hid_dump_input(field->report->device, field->usage + offset, value);

	if (offset >= field->report_count) {
		hid_err(field->report->device, "offset (%d) exceeds report_count (%d)\n",
				offset, field->report_count);
		return -1;
	}
	if (field->logical_minimum < 0) {
		if (value != snto32(s32ton(value, size), size)) {
			hid_err(field->report->device, "value %d is out of range\n", value);
			return -1;
		}
	}
	field->value[offset] = value;
	return 0;
}
EXPORT_SYMBOL_GPL(hid_set_field);

static struct hid_report *hid_get_report(struct hid_report_enum *report_enum,
		const u8 *data)
{
	struct hid_report *report;
	unsigned int n = 0;	/* Normally report number is 0 */

	/* Device uses numbered reports, data[0] is report number */
	if (report_enum->numbered)
		n = *data;

	report = report_enum->report_id_hash[n];
	if (report == NULL)
		dbg_hid("undefined report_id %u received\n", n);

	return report;
}

int hid_report_raw_event(struct hid_device *hid, int type, u8 *data, int size,
		int interrupt)
{
	struct hid_report_enum *report_enum = hid->report_enum + type;
	struct hid_report *report;
	unsigned int a;
	int rsize, csize = size;
	u8 *cdata = data;
	int ret = 0;

#ifdef CONFIG_HID_CRYPTO
	__u8 temp=0;
	unsigned j=0,k=0;
	__u8 rand[5]={0};
	__u8 fake_data[6]={0};
	__u8 key_data[6]={0};
	unsigned off;
	__u8 value[2] = {0};
	u8 *r_data;
	u8 *ptr;
//	u8 *ptr1;
	__u8 pre_data[3] = {0x01,0x7f,0x7f};
#endif
	report = hid_get_report(report_enum, data);
	if (!report)
		goto out;

	if (report_enum->numbered) {
		cdata++;
		csize--;
	}

	dbg_hid("report->size:%d bits\n",report->size);
	rsize = ((report->size - 1) >> 3) + 1;

	if (rsize > HID_MAX_BUFFER_SIZE)
		rsize = HID_MAX_BUFFER_SIZE;

	if (csize < rsize) {
		dbg_hid("report %d is too short, (%d < %d)\n", report->id,
				csize, rsize);
		memset(cdata + csize, 0, rsize - csize);
	}

	if ((hid->claimed & HID_CLAIMED_HIDDEV) && hid->hiddev_report_event)
		hid->hiddev_report_event(hid, report);

	if (hid->claimed & HID_CLAIMED_HIDRAW) {
		ret = hidraw_report_event(hid, data, size);
		if (ret)
			goto out;
	}

#ifdef CONFIG_HID_CRYPTO
	r_data = kzalloc(rsize, GFP_KERNEL);
	if (!r_data)
		return -1;
	memcpy(r_data,pre_data,3); //拷贝3bytes数据，这三bytes数据基本上是固定的

	ptr = r_data+3;
	for(j=0;j<5;j++) {
		//获取首5byte 的随机数
		rand[j] = extract(hid, cdata, j*8, 8);
	}

	//step2: 获取data0-data5 (byte5-byte10) 6byte的数据值
	for(j=0;j<6;j++) {
		fake_data[j] = extract(hid,cdata,RAND_LENGTH + j*8, 8);
	}

	//计算获取真实的data0-data5的值
	for(j=0;j<6;j++) {
		temp = 0;
		if(j == 5)
			temp = fake_data[j] ^ rand[0];
		else
			temp = fake_data[j] ^ rand[j];

			for(k=0;k<256;k++) {
				if(rand_table[k]== temp)
				{
					if(j==5)
						key_data[j] = k ^ rand[0];
					else
						key_data[j] = k ^ rand[j];
				}
			}
			dbg_hid("key_data[%d]:0x%02x\n",j,key_data[j]);
	}


	//1.获取field[0] X轴数据 构建byte4
	*ptr++ = key_data[2];
	//2.获取field[0] y轴数据 构建byte5
	*ptr++ = key_data[3];
	//3.field[2] 4bits default:0xf
	//4.field[3] 10bit a-z(first 4 bits)
	//01:Y, 02:B, 03:A, 04:X, 05:Z, 06:C, 09:mode, a:start
	*ptr++ = 0x0f | (((key_data[1]>>1) & 0x01) << 4) | (((key_data[0]>>1) & 0x01) << 5) |
		((key_data[0]&0x01) << 6) | ((key_data[1]&0x01) << 7);
	//5.file[3] the last 6 bits
	*ptr = ((key_data[1]>>2) & 0x01) | (((key_data[0]>>2)&0x01) << 1) |
		(((key_data[0]>>3) & 0x1) << 4) | (((key_data[1]>>3) & 0x01) << 5);
/*
	ptr1=r_data;
	for(k=0;k<rsize;k++) {
		printk("r_data%d:0x%02x\n",k,*ptr1);
		ptr1++;
	}
*/
	for (a = 0; a < report->maxfield; a++)
		hid_input_field(hid, report->field[a], r_data, interrupt);
	kfree(r_data);
#else
	for (a = 0; a < report->maxfield; a++)
		hid_input_field(hid, report->field[a], cdata, interrupt);
#endif
	if (hid->claimed & HID_CLAIMED_INPUT)
		hidinput_report_event(hid, report);
out:
	return ret;
}
EXPORT_SYMBOL_GPL(hid_report_raw_event);

/**
 * hid_input_report - report data from lower layer (usb, bt...)
 *
 * @hid: hid device
 * @type: HID report type (HID_*_REPORT)
 * @data: report contents
 * @size: size of data parameter
 * @interrupt: distinguish between interrupt and control transfers
 *
 * This is data entry for lower layers.
 */
int hid_input_report(struct hid_device *hid, int type, u8 *data, int size, int interrupt)
{
	struct hid_report_enum *report_enum;
	struct hid_driver *hdrv;
	struct hid_report *report;
	char *buf;
	unsigned int i;
	int ret = 0;
#ifdef CONFIG_HID_CRYPTO
	u8 crc;
#endif

	if (!hid)
		return -ENODEV;

	if (down_trylock(&hid->driver_lock))
		return -EBUSY;

	if (!hid->driver) {
		ret = -ENODEV;
		goto unlock;
	}
	report_enum = hid->report_enum + type;
	hdrv = hid->driver;

	if (!size) {
		dbg_hid("empty report\n");
		ret = -1;
		goto unlock;
	}
#ifdef CONFIG_HID_CRYPTO
	crc = crc8(data,size-1,0);
	if(crc != *(data+11)) {
		hid_err(hid, "checksum error\n");
		ret = -1;
		goto unlock;
	}
#endif
	buf = kmalloc(sizeof(char) * HID_DEBUG_BUFSIZE, GFP_ATOMIC);

	if (!buf)
		goto nomem;

	/* dump the report */
	snprintf(buf, HID_DEBUG_BUFSIZE - 1,
			"\nreport (size %u) (%snumbered) = ", size, report_enum->numbered ? "" : "un");
	hid_debug_event(hid, buf);

	for (i = 0; i < size; i++) {
		snprintf(buf, HID_DEBUG_BUFSIZE - 1,
				" %02x", data[i]);
		hid_debug_event(hid, buf);
	}
	hid_debug_event(hid, "\n");
	kfree(buf);

nomem:
	report = hid_get_report(report_enum, data);

	if (!report) {
		ret = -1;
		goto unlock;
	}

	if (hdrv && hdrv->raw_event && hid_match_report(hid, report)) {
		ret = hdrv->raw_event(hid, report, data, size);
		if (ret != 0) {
			ret = ret < 0 ? ret : 0;
			goto unlock;
		}
	}

	ret = hid_report_raw_event(hid, type, data, size, interrupt);

unlock:
	up(&hid->driver_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(hid_input_report);

static bool hid_match_one_id(struct hid_device *hdev,
		const struct hid_device_id *id)
{
	return id->bus == hdev->bus &&
		(id->vendor == HID_ANY_ID || id->vendor == hdev->vendor) &&
		(id->product == HID_ANY_ID || id->product == hdev->product);
}

const struct hid_device_id *hid_match_id(struct hid_device *hdev,
		const struct hid_device_id *id)
{
	for (; id->bus; id++)
		if (hid_match_one_id(hdev, id))
			return id;

	return NULL;
}

static const struct hid_device_id hid_hiddev_list[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_MGE, USB_DEVICE_ID_MGE_UPS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MGE, USB_DEVICE_ID_MGE_UPS1) },
	{ }
};

static bool hid_hiddev(struct hid_device *hdev)
{
	return !!hid_match_id(hdev, hid_hiddev_list);
}


static ssize_t
read_report_descriptor(struct file *filp, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t off, size_t count)
{
	struct device *dev = container_of(kobj, struct device, kobj);
	struct hid_device *hdev = container_of(dev, struct hid_device, dev);

	if (off >= hdev->rsize)
		return 0;

	if (off + count > hdev->rsize)
		count = hdev->rsize - off;

	memcpy(buf, hdev->rdesc + off, count);

	return count;
}

static struct bin_attribute dev_bin_attr_report_desc = {
	.attr = { .name = "report_descriptor", .mode = 0444 },
	.read = read_report_descriptor,
	.size = HID_MAX_DESCRIPTOR_SIZE,
};

int hid_connect(struct hid_device *hdev, unsigned int connect_mask)
{
	static const char *types[] = { "Device", "Pointer", "Mouse", "Device",
		"Joystick", "Gamepad", "Keyboard", "Keypad",
		"Multi-Axis Controller"
	};
	const char *type, *bus;
	char buf[64] = "";
	unsigned int i;
	int len;
	int ret;

	if (hdev->quirks & HID_QUIRK_HIDDEV_FORCE)
		connect_mask |= (HID_CONNECT_HIDDEV_FORCE | HID_CONNECT_HIDDEV);
	if (hdev->quirks & HID_QUIRK_HIDINPUT_FORCE)
		connect_mask |= HID_CONNECT_HIDINPUT_FORCE;
	if (hdev->bus != BUS_USB)
		connect_mask &= ~HID_CONNECT_HIDDEV;
	if (hid_hiddev(hdev))
		connect_mask |= HID_CONNECT_HIDDEV_FORCE;

	if ((connect_mask & HID_CONNECT_HIDINPUT) && !hidinput_connect(hdev,
				connect_mask & HID_CONNECT_HIDINPUT_FORCE))
		hdev->claimed |= HID_CLAIMED_INPUT;

	if (hdev->quirks & HID_QUIRK_MULTITOUCH) {
		/* this device should be handled by hid-multitouch, skip it */
		return -ENODEV;
	}

	if ((connect_mask & HID_CONNECT_HIDDEV) && hdev->hiddev_connect &&
			!hdev->hiddev_connect(hdev,
				connect_mask & HID_CONNECT_HIDDEV_FORCE))
		hdev->claimed |= HID_CLAIMED_HIDDEV;

	if ((connect_mask & HID_CONNECT_HIDRAW) && !hidraw_connect(hdev))
		hdev->claimed |= HID_CLAIMED_HIDRAW;

	if (!hdev->claimed) {
		hid_err(hdev, "claimed by neither input, hiddev nor hidraw\n");
		return -ENODEV;
	}

	if ((hdev->claimed & HID_CLAIMED_INPUT) &&
			(connect_mask & HID_CONNECT_FF) && hdev->ff_init)
		hdev->ff_init(hdev);

	len = 0;
	if (hdev->claimed & HID_CLAIMED_INPUT)
		len += sprintf(buf + len, "input");
	if (hdev->claimed & HID_CLAIMED_HIDDEV)
		len += sprintf(buf + len, "%shiddev%d", len ? "," : "",
				hdev->minor);
	if (hdev->claimed & HID_CLAIMED_HIDRAW)
		len += sprintf(buf + len, "%shidraw%d", len ? "," : "",
				((struct hidraw *)hdev->hidraw)->minor);

	type = "Device";
	for (i = 0; i < hdev->maxcollection; i++) {
		struct hid_collection *col = &hdev->collection[i];
		if (col->type == HID_COLLECTION_APPLICATION &&
		   (col->usage & HID_USAGE_PAGE) == HID_UP_GENDESK &&
		   (col->usage & 0xffff) < ARRAY_SIZE(types)) {
			type = types[col->usage & 0xffff];
			break;
		}
	}

	switch (hdev->bus) {
	case BUS_USB:
		bus = "USB";
		break;
	case BUS_BLUETOOTH:
		bus = "BLUETOOTH";
		break;
	default:
		bus = "<UNKNOWN>";
	}

	ret = device_create_bin_file(&hdev->dev, &dev_bin_attr_report_desc);
	if (ret)
		hid_warn(hdev,
			 "can't create sysfs report descriptor attribute err: %d\n", ret);

	hid_info(hdev, "%s: %s HID v%x.%02x %s [%s] on %s\n",
		 buf, bus, hdev->version >> 8, hdev->version & 0xff,
		 type, hdev->name, hdev->phys);

	return 0;
}
EXPORT_SYMBOL_GPL(hid_connect);

void hid_disconnect(struct hid_device *hdev)
{
	device_remove_bin_file(&hdev->dev, &dev_bin_attr_report_desc);
	if (hdev->claimed & HID_CLAIMED_INPUT)
		hidinput_disconnect(hdev);
	if (hdev->claimed & HID_CLAIMED_HIDDEV)
		hdev->hiddev_disconnect(hdev);
	if (hdev->claimed & HID_CLAIMED_HIDRAW)
		hidraw_disconnect(hdev);
}
EXPORT_SYMBOL_GPL(hid_disconnect);

/* a list of devices for which there is a specialized driver on HID bus */
static const struct hid_device_id hid_have_special_driver[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_3M, USB_DEVICE_ID_3M1968) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_3M, USB_DEVICE_ID_3M2256) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_A4TECH, USB_DEVICE_ID_A4TECH_WCP32PU) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_A4TECH, USB_DEVICE_ID_A4TECH_X5_005D) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_A4TECH, USB_DEVICE_ID_A4TECH_RP_649) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ACRUX, 0x0802) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ACTIONSTAR, USB_DEVICE_ID_ACTIONSTAR_1011) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ATV_IRCONTROL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_IRCONTROL4) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_MIGHTYMOUSE) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_MAGICMOUSE) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_MAGICTRACKPAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_MINI_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_MINI_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_MINI_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_JIS) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_ANSI) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_ISO) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_REVB_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_REVB_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_REVB_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_JIS) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ANSI) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_ISO) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_2009_JIS) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ANSI) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_ALU_WIRELESS_2011_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_TP_ONLY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER1_TP_ONLY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUS, USB_DEVICE_ID_ASUS_T91MT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUS, USB_DEVICE_ID_ASUSTEK_MULTITOUCH_YFO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_BELKIN, USB_DEVICE_ID_FLIP_KVM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_BAANTO, USB_DEVICE_ID_BAANTO_MT_190W2), },
	{ HID_USB_DEVICE(USB_VENDOR_ID_BTC, USB_DEVICE_ID_BTC_EMPREX_REMOTE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_BTC, USB_DEVICE_ID_BTC_EMPREX_REMOTE_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CANDO, USB_DEVICE_ID_CANDO_PIXCIR_MULTI_TOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CANDO, USB_DEVICE_ID_CANDO_MULTI_TOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CANDO, USB_DEVICE_ID_CANDO_MULTI_TOUCH_10_1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CANDO, USB_DEVICE_ID_CANDO_MULTI_TOUCH_11_6) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CANDO, USB_DEVICE_ID_CANDO_MULTI_TOUCH_15_6) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHERRY, USB_DEVICE_ID_CHERRY_CYMOTION) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHERRY, USB_DEVICE_ID_CHERRY_CYMOTION_SOLAR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHICONY, USB_DEVICE_ID_CHICONY_TACTICAL_PAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHICONY, USB_DEVICE_ID_CHICONY_WIRELESS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHICONY, USB_DEVICE_ID_CHICONY_WIRELESS2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHICONY, USB_DEVICE_ID_CHICONY_AK1D) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CHUNGHWAT, USB_DEVICE_ID_CHUNGHWAT_MULTITOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CREATIVELABS, USB_DEVICE_ID_PRODIKEYS_PCMIDI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CVTOUCH, USB_DEVICE_ID_CVTOUCH_SCREEN) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_BARCODE_1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_BARCODE_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_BARCODE_3) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_BARCODE_4) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_MOUSE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_TRUETOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DRAGONRISE, 0x0006) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DRAGONRISE, 0x0011) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SEGA, 0x0024) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SEGA, 0x0025) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_480D) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_480E) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_720C) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_7224) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_725E) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_726B) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_72A1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_7302) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DWAV, USB_DEVICE_ID_DWAV_EGALAX_MULTITOUCH_A001) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_ELECOM, USB_DEVICE_ID_ELECOM_BM084) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ELO, USB_DEVICE_ID_ELO_TS2515) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_EMS, USB_DEVICE_ID_EMS_TRIO_LINKER_PLUS_II) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_EZKEY, USB_DEVICE_ID_BTC_8193) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_FRUCTEL, USB_DEVICE_ID_GAMETEL_MT_MODE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GAMERON, USB_DEVICE_ID_GAMERON_DUAL_PSX_ADAPTOR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GAMERON, USB_DEVICE_ID_GAMERON_DUAL_PCS_ADAPTOR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GENERAL_TOUCH, USB_DEVICE_ID_GENERAL_TOUCH_WIN7_TWOFINGERS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GOODTOUCH, USB_DEVICE_ID_GOODTOUCH_000f) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GREENASIA, 0x0003) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GREENASIA, 0x0012) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GYRATION, USB_DEVICE_ID_GYRATION_REMOTE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GYRATION, USB_DEVICE_ID_GYRATION_REMOTE_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GYRATION, USB_DEVICE_ID_GYRATION_REMOTE_3) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_HANVON, USB_DEVICE_ID_HANVON_MULTITOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_HANVON_ALT, USB_DEVICE_ID_HANVON_ALT_MULTITOUCH) },
 	{ HID_USB_DEVICE(USB_VENDOR_ID_IDEACOM, USB_DEVICE_ID_IDEACOM_IDC6650) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_HOLTEK, USB_DEVICE_ID_HOLTEK_ON_LINE_GRIP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ILITEK, USB_DEVICE_ID_ILITEK_MULTITOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_IRTOUCHSYSTEMS, USB_DEVICE_ID_IRTOUCH_INFRARED_USB) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KENSINGTON, USB_DEVICE_ID_KS_SLIMBLADE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KEYTOUCH, USB_DEVICE_ID_KEYTOUCH_IEC) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KYE, USB_DEVICE_ID_KYE_ERGO_525V) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KYE, USB_DEVICE_ID_KYE_EASYPEN_I405X) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KYE, USB_DEVICE_ID_KYE_MOUSEPEN_I608X) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KYE, USB_DEVICE_ID_KYE_EASYPEN_M610X) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LABTEC, USB_DEVICE_ID_LABTEC_WIRELESS_KEYBOARD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LCPOWER, USB_DEVICE_ID_LCPOWER_LC1000 ) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LG, USB_DEVICE_ID_LG_MULTITOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_MX3000_RECEIVER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_S510_RECEIVER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_S510_RECEIVER_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_RECEIVER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_DINOVO_DESKTOP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_DINOVO_EDGE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_DINOVO_MINI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_ELITE_KBD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_CORDLESS_DESKTOP_LX500) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_EXTREME_3D) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_RUMBLEPAD_CORD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_RUMBLEPAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_RUMBLEPAD2_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_WINGMAN_F3D) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_WINGMAN_FFG ) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_FORCE3D_PRO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_FLIGHT_SYSTEM_G940) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_MOMO_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_MOMO_WHEEL2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_DFP_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_DFGT_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_G25_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_G27_WHEEL) },
#if IS_ENABLED(CONFIG_HID_LOGITECH_DJ)
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_UNIFYING_RECEIVER_2) },
#endif
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_WII_WHEEL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_LOGITECH_RUMBLEPAD2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_SPACETRAVELLER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LOGITECH, USB_DEVICE_ID_SPACENAVIGATOR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LUMIO, USB_DEVICE_ID_CRYSTALTOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LUMIO, USB_DEVICE_ID_CRYSTALTOUCH_DUAL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROCHIP, USB_DEVICE_ID_PICOLCD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROCHIP, USB_DEVICE_ID_PICOLCD_BOOTLOADER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_COMFORT_MOUSE_4500) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_SIDEWINDER_GV) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_NE4K) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_LK6K) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_PRESENTER_8K_USB) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_DIGITAL_MEDIA_3K) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_WIRELESS_OPTICAL_DESKTOP_3_0) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MONTEREY, USB_DEVICE_ID_GENIUS_KB29E) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_3) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_4) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_5) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_6) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_7) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_8) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_9) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_10) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_11) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_12) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_13) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_14) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_15) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_16) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_17) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NTRIG, USB_DEVICE_ID_NTRIG_TOUCH_SCREEN_18) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ORTEK, USB_DEVICE_ID_ORTEK_PKB1700) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ORTEK, USB_DEVICE_ID_ORTEK_WKB2000) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANASONIC, USB_DEVICE_ID_PANABOARD_UBT780) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANASONIC, USB_DEVICE_ID_PANABOARD_UBT880) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PENMOUNT, USB_DEVICE_ID_PENMOUNT_PCI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PETALYNX, USB_DEVICE_ID_PETALYNX_MAXTER_REMOTE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PIXART, USB_DEVICE_ID_PIXART_OPTICAL_TOUCH_SCREEN) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PIXART, USB_DEVICE_ID_PIXART_OPTICAL_TOUCH_SCREEN1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PIXART, USB_DEVICE_ID_PIXART_OPTICAL_TOUCH_SCREEN2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PRIMAX, USB_DEVICE_ID_PRIMAX_KEYBOARD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_QUANTA, USB_DEVICE_ID_QUANTA_OPTICAL_TOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_QUANTA, USB_DEVICE_ID_PIXART_IMAGING_INC_OPTICAL_TOUCH_SCREEN) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_KONE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_ARVO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_ISKU) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_KONEPLUS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_KOVAPLUS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_PYRA_WIRED) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ROCCAT, USB_DEVICE_ID_ROCCAT_PYRA_WIRELESS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SAITEK, USB_DEVICE_ID_SAITEK_PS1000) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SAMSUNG, USB_DEVICE_ID_SAMSUNG_IR_REMOTE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SAMSUNG, USB_DEVICE_ID_SAMSUNG_WIRELESS_KBD_MOUSE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SKYCABLE, USB_DEVICE_ID_SKYCABLE_WIRELESS_PRESENTER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SONY, USB_DEVICE_ID_SONY_PS3_CONTROLLER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SONY, USB_DEVICE_ID_SONY_NAVIGATION_CONTROLLER) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_SONY, USB_DEVICE_ID_SONY_PS3_CONTROLLER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SONY, USB_DEVICE_ID_SONY_VAIO_VGX_MOUSE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SONY, USB_DEVICE_ID_SONY_VAIO_VGP_MOUSE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_STANTUM, USB_DEVICE_ID_MTP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_STANTUM_STM, USB_DEVICE_ID_MTP_STM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_STANTUM_SITRONIX, USB_DEVICE_ID_MTP_SITRONIX) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SUNPLUS, USB_DEVICE_ID_SUNPLUS_WDESKTOP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb300) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb304) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb323) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb324) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb651) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb653) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb654) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_THRUSTMASTER, 0xb65a) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_TIVO, USB_DEVICE_ID_TIVO_SLIDE_BT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TIVO, USB_DEVICE_ID_TIVO_SLIDE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TOPSEED, USB_DEVICE_ID_TOPSEED_CYBERLINK) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TOPSEED2, USB_DEVICE_ID_TOPSEED2_RF_COMBO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TOUCH_INTL, USB_DEVICE_ID_TOUCH_INTL_MULTI_TOUCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TWINHAN, USB_DEVICE_ID_TWINHAN_IR_REMOTE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_TURBOX, USB_DEVICE_ID_TURBOX_TOUCHSCREEN_MOSART) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UCLOGIC, USB_DEVICE_ID_UCLOGIC_TABLET_PF1209) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UCLOGIC, USB_DEVICE_ID_UCLOGIC_TABLET_WP4030U) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UCLOGIC, USB_DEVICE_ID_UCLOGIC_TABLET_WP5540U) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UCLOGIC, USB_DEVICE_ID_UCLOGIC_TABLET_WP8060U) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UCLOGIC, USB_DEVICE_ID_UCLOGIC_TABLET_WP1062) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UNITEC, USB_DEVICE_ID_UNITEC_USB_TOUCH_0709) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_UNITEC, USB_DEVICE_ID_UNITEC_USB_TOUCH_0A19) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_SMARTJOY_PLUS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_SUPER_JOY_BOX_3) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_DUAL_USB_JOYPAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP_LTD, USB_DEVICE_ID_SUPER_JOY_BOX_3_PRO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP_LTD, USB_DEVICE_ID_SUPER_DUAL_BOX_PRO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP_LTD, USB_DEVICE_ID_SUPER_JOY_BOX_5_PRO) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_WACOM, USB_DEVICE_ID_WACOM_GRAPHIRE_BLUETOOTH) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_WACOM, USB_DEVICE_ID_WACOM_INTUOS4_BLUETOOTH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_SLIM_TABLET_5_8_INCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_SLIM_TABLET_12_1_INCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_Q_PAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_PID_0038) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_MEDIA_TABLET_10_6_INCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WALTOP, USB_DEVICE_ID_WALTOP_MEDIA_TABLET_14_1_INCH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XAT, USB_DEVICE_ID_XAT_CSR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_SPX) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_MPX) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_CSR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_SPX1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_MPX1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_CSR1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_SPX2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_MPX2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_XIROKU, USB_DEVICE_ID_XIROKU_CSR2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_X_TENSIONS, USB_DEVICE_ID_SPEEDLINK_VAD_CEZANNE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ZEROPLUS, 0x0005) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ZEROPLUS, 0x0030) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ZYDACRON, USB_DEVICE_ID_ZYDACRON_REMOTE_CONTROL) },

	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_MICROSOFT, USB_DEVICE_ID_MS_PRESENTER_8K_BT) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_NINTENDO, USB_DEVICE_ID_NINTENDO_WIIMOTE) },
	{ }
};

struct hid_dynid {
	struct list_head list;
	struct hid_device_id id;
};

/**
 * store_new_id - add a new HID device ID to this driver and re-probe devices
 * @driver: target device driver
 * @buf: buffer for scanning device ID data
 * @count: input size
 *
 * Adds a new dynamic hid device ID to this driver,
 * and causes the driver to probe for all devices again.
 */
static ssize_t store_new_id(struct device_driver *drv, const char *buf,
		size_t count)
{
	struct hid_driver *hdrv = container_of(drv, struct hid_driver, driver);
	struct hid_dynid *dynid;
	__u32 bus, vendor, product;
	unsigned long driver_data = 0;
	int ret;

	ret = sscanf(buf, "%x %x %x %lx",
			&bus, &vendor, &product, &driver_data);
	if (ret < 3)
		return -EINVAL;

	dynid = kzalloc(sizeof(*dynid), GFP_KERNEL);
	if (!dynid)
		return -ENOMEM;

	dynid->id.bus = bus;
	dynid->id.vendor = vendor;
	dynid->id.product = product;
	dynid->id.driver_data = driver_data;

	spin_lock(&hdrv->dyn_lock);
	list_add_tail(&dynid->list, &hdrv->dyn_list);
	spin_unlock(&hdrv->dyn_lock);

	ret = driver_attach(&hdrv->driver);

	return ret ? : count;
}
static DRIVER_ATTR(new_id, S_IWUSR, NULL, store_new_id);

static void hid_free_dynids(struct hid_driver *hdrv)
{
	struct hid_dynid *dynid, *n;

	spin_lock(&hdrv->dyn_lock);
	list_for_each_entry_safe(dynid, n, &hdrv->dyn_list, list) {
		list_del(&dynid->list);
		kfree(dynid);
	}
	spin_unlock(&hdrv->dyn_lock);
}

static const struct hid_device_id *hid_match_device(struct hid_device *hdev,
		struct hid_driver *hdrv)
{
	struct hid_dynid *dynid;

	spin_lock(&hdrv->dyn_lock);
	list_for_each_entry(dynid, &hdrv->dyn_list, list) {
		if (hid_match_one_id(hdev, &dynid->id)) {
			spin_unlock(&hdrv->dyn_lock);
			return &dynid->id;
		}
	}
	spin_unlock(&hdrv->dyn_lock);

	return hid_match_id(hdev, hdrv->id_table);
}

static int hid_bus_match(struct device *dev, struct device_driver *drv)
{
	struct hid_driver *hdrv = container_of(drv, struct hid_driver, driver);
	struct hid_device *hdev = container_of(dev, struct hid_device, dev);

	if ((hdev->quirks & HID_QUIRK_MULTITOUCH) &&
		!strncmp(hdrv->name, "hid-multitouch", 14))
		return 1;

	if (!hid_match_device(hdev, hdrv))
		return 0;

	/* generic wants all that don't have specialized driver */
	if (!strncmp(hdrv->name, "generic-", 8) && !hid_ignore_special_drivers)
		return !hid_match_id(hdev, hid_have_special_driver);

	return 1;
}

static int hid_device_probe(struct device *dev)
{
	struct hid_driver *hdrv = container_of(dev->driver,
			struct hid_driver, driver);
	struct hid_device *hdev = container_of(dev, struct hid_device, dev);
	const struct hid_device_id *id;
	int ret = 0;

	if (down_interruptible(&hdev->driver_lock))
		return -EINTR;

	if (hid_num > HID_NUM_MAX)
		goto unlock;

	if (!hdev->driver) {
		id = hid_match_device(hdev, hdrv);
		if (id == NULL) {
			if (!((hdev->quirks & HID_QUIRK_MULTITOUCH) &&
				!strncmp(hdrv->name, "hid-multitouch", 14))) {
				ret = -ENODEV;
				goto unlock;
			}
		}

		hdev->driver = hdrv;
		if (hdrv->probe) {
			ret = hdrv->probe(hdev, id);
		} else { /* default probe */
			ret = hid_parse(hdev);
			if (!ret)
				ret = hid_hw_start(hdev, HID_CONNECT_DEFAULT);
		}
		if (ret)
			hdev->driver = NULL;
	}
	hid_num++;
unlock:
	up(&hdev->driver_lock);
	return ret;
}

static int hid_device_remove(struct device *dev)
{
	struct hid_device *hdev = container_of(dev, struct hid_device, dev);
	struct hid_driver *hdrv;

	if (down_interruptible(&hdev->driver_lock))
		return -EINTR;

	hdrv = hdev->driver;
	if (hdrv) {
		if (hdrv->remove)
			hdrv->remove(hdev);
		else /* default remove */
			hid_hw_stop(hdev);
		hdev->driver = NULL;
	}

	if(hid_num > HID_NUM_MIN)
		hid_num--;

	up(&hdev->driver_lock);
	return 0;
}

static int hid_uevent(struct device *dev, struct kobj_uevent_env *env)
{
	struct hid_device *hdev = container_of(dev, struct hid_device, dev);

	if (add_uevent_var(env, "HID_ID=%04X:%08X:%08X",
			hdev->bus, hdev->vendor, hdev->product))
		return -ENOMEM;

	if (add_uevent_var(env, "HID_NAME=%s", hdev->name))
		return -ENOMEM;

	if (add_uevent_var(env, "HID_PHYS=%s", hdev->phys))
		return -ENOMEM;

	if (add_uevent_var(env, "HID_UNIQ=%s", hdev->uniq))
		return -ENOMEM;

	if (add_uevent_var(env, "MODALIAS=hid:b%04Xv%08Xp%08X",
			hdev->bus, hdev->vendor, hdev->product))
		return -ENOMEM;

	return 0;
}

static struct bus_type hid_bus_type = {
	.name		= "hid",
	.match		= hid_bus_match,
	.probe		= hid_device_probe,
	.remove		= hid_device_remove,
	.uevent		= hid_uevent,
};

/* a list of devices that shouldn't be handled by HID core at all */
static const struct hid_device_id hid_ignore_list[] = {
	{ HID_USB_DEVICE(USB_VENDOR_ID_ACECAD, USB_DEVICE_ID_ACECAD_FLAIR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ACECAD, USB_DEVICE_ID_ACECAD_302) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ADS_TECH, USB_DEVICE_ID_ADS_TECH_RADIO_SI470X) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_01) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_10) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_20) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_21) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_22) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_23) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIPTEK, USB_DEVICE_ID_AIPTEK_24) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_AIRCABLE, USB_DEVICE_ID_AIRCABLE1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ALCOR, USB_DEVICE_ID_ALCOR_USBRS232) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUSTEK, USB_DEVICE_ID_ASUSTEK_LCM)},
	{ HID_USB_DEVICE(USB_VENDOR_ID_ASUSTEK, USB_DEVICE_ID_ASUSTEK_LCM2)},
	{ HID_USB_DEVICE(USB_VENDOR_ID_AVERMEDIA, USB_DEVICE_ID_AVER_FM_MR800) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_BERKSHIRE, USB_DEVICE_ID_BERKSHIRE_PCWD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CIDC, 0x0103) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYGNAL, USB_DEVICE_ID_CYGNAL_RADIO_SI470X) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CMEDIA, USB_DEVICE_ID_CM109) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_HIDCOM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_CYPRESS, USB_DEVICE_ID_CYPRESS_ULTRAMOUSE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DEALEXTREAME, USB_DEVICE_ID_DEALEXTREAME_RADIO_SI4701) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DELORME, USB_DEVICE_ID_DELORME_EARTHMATE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DELORME, USB_DEVICE_ID_DELORME_EM_LT20) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DREAM_CHEEKY, 0x0004) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_DREAM_CHEEKY, 0x000a) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ESSENTIAL_REALITY, USB_DEVICE_ID_ESSENTIAL_REALITY_P5) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ETT, USB_DEVICE_ID_TC5UH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ETT, USB_DEVICE_ID_TC4UM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GENERAL_TOUCH, 0x0001) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GENERAL_TOUCH, 0x0002) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GENERAL_TOUCH, 0x0004) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_4_PHIDGETSERVO_30) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_1_PHIDGETSERVO_30) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_0_0_4_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_0_16_16_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_8_8_8_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_0_8_7_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_0_8_8_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GLAB, USB_DEVICE_ID_PHIDGET_MOTORCONTROL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GOTOP, USB_DEVICE_ID_SUPER_Q2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GOTOP, USB_DEVICE_ID_GOGOPEN) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GOTOP, USB_DEVICE_ID_PENPOWER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GRETAGMACBETH, USB_DEVICE_ID_GRETAGMACBETH_HUEY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GRIFFIN, USB_DEVICE_ID_POWERMATE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GRIFFIN, USB_DEVICE_ID_SOUNDKNOB) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_90) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_100) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_101) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_103) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_104) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_105) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_106) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_107) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_108) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_200) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_201) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_202) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_203) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_204) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_205) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_206) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_207) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_300) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_301) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_302) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_303) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_304) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_305) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_306) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_307) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_308) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_309) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_400) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_401) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_402) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_403) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_404) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_405) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_500) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_501) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_502) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_503) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_504) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1000) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1001) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1002) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1003) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1004) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1005) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1006) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_GTCO, USB_DEVICE_ID_GTCO_1007) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_IMATION, USB_DEVICE_ID_DISC_STAKKA) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KBGEAR, USB_DEVICE_ID_KBGEAR_JAMSTUDIO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KWORLD, USB_DEVICE_ID_KWORLD_RADIO_FM700) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_KYE, USB_DEVICE_ID_KYE_GPEN_560) },
	{ HID_BLUETOOTH_DEVICE(USB_VENDOR_ID_KYE, 0x0058) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_CASSY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_CASSY2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_POCKETCASSY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_POCKETCASSY2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MOBILECASSY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MOBILECASSY2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MICROCASSYVOLTAGE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MICROCASSYCURRENT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MICROCASSYTIME) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MICROCASSYTEMPERATURE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MICROCASSYPH) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_JWM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_DMMP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_UMIP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_UMIC) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_UMIB) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_XRAY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_XRAY2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_VIDEOCOM) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MOTOR) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_COM3LAB) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_TELEPORT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_NETWORKANALYSER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_POWERCONTROL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MACHINETEST) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MOSTANALYSER) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MOSTANALYSER2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_ABSESP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_AUTODATABUS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_MCT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_HYBRID) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_LD, USB_DEVICE_ID_LD_HEATCONTROL) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MADCATZ, USB_DEVICE_ID_MADCATZ_BEATPAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MASTERKIT, USB_DEVICE_ID_MASTERKIT_MA901RADIO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MCC, USB_DEVICE_ID_MCC_PMD1024LS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MCC, USB_DEVICE_ID_MCC_PMD1208LS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROCHIP, USB_DEVICE_ID_PICKIT1) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_MICROCHIP, USB_DEVICE_ID_PICKIT2) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_NATIONAL_SEMICONDUCTOR, USB_DEVICE_ID_N_S_HARMONY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 20) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 30) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 100) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 108) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 118) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 200) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 300) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 400) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_ONTRAK, USB_DEVICE_ID_ONTRAK_ADU100 + 500) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANJIT, 0x0001) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANJIT, 0x0002) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANJIT, 0x0003) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PANJIT, 0x0004) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_PHILIPS, USB_DEVICE_ID_PHILIPS_IEEE802154_DONGLE) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_POWERCOM, USB_DEVICE_ID_POWERCOM_UPS) },
#if defined(CONFIG_MOUSE_SYNAPTICS_USB) || defined(CONFIG_MOUSE_SYNAPTICS_USB_MODULE)
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_TP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_INT_TP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_CPAD) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_STICK) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_WP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_COMP_TP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_WTP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_SYNAPTICS, USB_DEVICE_ID_SYNAPTICS_DPAD) },
#endif
	{ HID_USB_DEVICE(USB_VENDOR_ID_VERNIER, USB_DEVICE_ID_VERNIER_LABPRO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_VERNIER, USB_DEVICE_ID_VERNIER_GOTEMP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_VERNIER, USB_DEVICE_ID_VERNIER_SKIP) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_VERNIER, USB_DEVICE_ID_VERNIER_CYCLOPS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_VERNIER, USB_DEVICE_ID_VERNIER_LCSPEC) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WACOM, HID_ANY_ID) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_4_PHIDGETSERVO_20) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_1_PHIDGETSERVO_20) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_WISEGROUP, USB_DEVICE_ID_8_8_4_IF_KIT) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_YEALINK, USB_DEVICE_ID_YEALINK_P1K_P4K_B2K) },
	{ }
};

/**
 * hid_mouse_ignore_list - mouse devices which should not be handled by the hid layer
 *
 * There are composite devices for which we want to ignore only a certain
 * interface. This is a list of devices for which only the mouse interface will
 * be ignored. This allows a dedicated driver to take care of the interface.
 */
static const struct hid_device_id hid_mouse_ignore_list[] = {
	/* appletouch driver */
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER3_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER4_HF_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING2_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING3_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING4A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING5A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING6A_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_ANSI) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_ISO) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_WELLSPRING7_JIS) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_FOUNTAIN_TP_ONLY) },
	{ HID_USB_DEVICE(USB_VENDOR_ID_APPLE, USB_DEVICE_ID_APPLE_GEYSER1_TP_ONLY) },
	{ }
};

static bool hid_ignore(struct hid_device *hdev)
{
	switch (hdev->vendor) {
	case USB_VENDOR_ID_CODEMERCS:
		/* ignore all Code Mercenaries IOWarrior devices */
		if (hdev->product >= USB_DEVICE_ID_CODEMERCS_IOW_FIRST &&
				hdev->product <= USB_DEVICE_ID_CODEMERCS_IOW_LAST)
			return true;
		break;
	case USB_VENDOR_ID_LOGITECH:
		if (hdev->product >= USB_DEVICE_ID_LOGITECH_HARMONY_FIRST &&
				hdev->product <= USB_DEVICE_ID_LOGITECH_HARMONY_LAST)
			return true;
		/*
		 * The Keene FM transmitter USB device has the same USB ID as
		 * the Logitech AudioHub Speaker, but it should ignore the hid.
		 * Check if the name is that of the Keene device.
		 * For reference: the name of the AudioHub is
		 * "HOLTEK  AudioHub Speaker".
		 */
		if (hdev->product == USB_DEVICE_ID_LOGITECH_AUDIOHUB &&
			!strcmp(hdev->name, "HOLTEK  B-LINK USB Audio  "))
				return true;
		break;
	case USB_VENDOR_ID_SOUNDGRAPH:
		if (hdev->product >= USB_DEVICE_ID_SOUNDGRAPH_IMON_FIRST &&
		    hdev->product <= USB_DEVICE_ID_SOUNDGRAPH_IMON_LAST)
			return true;
		break;
	case USB_VENDOR_ID_HANWANG:
		if (hdev->product >= USB_DEVICE_ID_HANWANG_TABLET_FIRST &&
		    hdev->product <= USB_DEVICE_ID_HANWANG_TABLET_LAST)
			return true;
		break;
	case USB_VENDOR_ID_JESS:
		if (hdev->product == USB_DEVICE_ID_JESS_YUREX &&
				hdev->type == HID_TYPE_USBNONE)
			return true;
	break;
	}

	if (hdev->type == HID_TYPE_USBMOUSE &&
			hid_match_id(hdev, hid_mouse_ignore_list))
		return true;

	return !!hid_match_id(hdev, hid_ignore_list);
}

int hid_add_device(struct hid_device *hdev)
{
	static atomic_t id = ATOMIC_INIT(0);
	int ret;

	if (WARN_ON(hdev->status & HID_STAT_ADDED))
		return -EBUSY;

	/* we need to kill them here, otherwise they will stay allocated to
	 * wait for coming driver */
	if (!(hdev->quirks & HID_QUIRK_NO_IGNORE)
            && (hid_ignore(hdev) || (hdev->quirks & HID_QUIRK_IGNORE)))
		return -ENODEV;

	/* XXX hack, any other cleaner solution after the driver core
	 * is converted to allow more than 20 bytes as the device name? */
	dev_set_name(&hdev->dev, "%04X:%04X:%04X.%04X", hdev->bus,
		     hdev->vendor, hdev->product, atomic_inc_return(&id));

	hid_debug_register(hdev, dev_name(&hdev->dev));
	ret = device_add(&hdev->dev);
	if (!ret)
		hdev->status |= HID_STAT_ADDED;
	else
		hid_debug_unregister(hdev);

	return ret;
}
EXPORT_SYMBOL_GPL(hid_add_device);

/**
 * hid_allocate_device - allocate new hid device descriptor
 *
 * Allocate and initialize hid device, so that hid_destroy_device might be
 * used to free it.
 *
 * New hid_device pointer is returned on success, otherwise ERR_PTR encoded
 * error value.
 */
struct hid_device *hid_allocate_device(void)
{
	struct hid_device *hdev;
	unsigned int i;
	int ret = -ENOMEM;

	hdev = kzalloc(sizeof(*hdev), GFP_KERNEL);
	if (hdev == NULL)
		return ERR_PTR(ret);

	device_initialize(&hdev->dev);
	hdev->dev.release = hid_device_release;
	hdev->dev.bus = &hid_bus_type;

	hdev->collection = kcalloc(HID_DEFAULT_NUM_COLLECTIONS,
			sizeof(struct hid_collection), GFP_KERNEL);
	if (hdev->collection == NULL)
		goto err;
	hdev->collection_size = HID_DEFAULT_NUM_COLLECTIONS;

	for (i = 0; i < HID_REPORT_TYPES; i++)
		INIT_LIST_HEAD(&hdev->report_enum[i].report_list);

	init_waitqueue_head(&hdev->debug_wait);
	INIT_LIST_HEAD(&hdev->debug_list);
	sema_init(&hdev->driver_lock, 1);

	return hdev;
err:
	put_device(&hdev->dev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(hid_allocate_device);

static void hid_remove_device(struct hid_device *hdev)
{
	if (hdev->status & HID_STAT_ADDED) {
		device_del(&hdev->dev);
		hid_debug_unregister(hdev);
		hdev->status &= ~HID_STAT_ADDED;
	}
}

/**
 * hid_destroy_device - free previously allocated device
 *
 * @hdev: hid device
 *
 * If you allocate hid_device through hid_allocate_device, you should ever
 * free by this function.
 */
void hid_destroy_device(struct hid_device *hdev)
{
	hid_remove_device(hdev);
	put_device(&hdev->dev);
}
EXPORT_SYMBOL_GPL(hid_destroy_device);

int __hid_register_driver(struct hid_driver *hdrv, struct module *owner,
		const char *mod_name)
{
	int ret;

	hdrv->driver.name = hdrv->name;
	hdrv->driver.bus = &hid_bus_type;
	hdrv->driver.owner = owner;
	hdrv->driver.mod_name = mod_name;

	INIT_LIST_HEAD(&hdrv->dyn_list);
	spin_lock_init(&hdrv->dyn_lock);

	ret = driver_register(&hdrv->driver);
	if (ret)
		return ret;

	ret = driver_create_file(&hdrv->driver, &driver_attr_new_id);
	if (ret)
		driver_unregister(&hdrv->driver);

	return ret;
}
EXPORT_SYMBOL_GPL(__hid_register_driver);

void hid_unregister_driver(struct hid_driver *hdrv)
{
	driver_remove_file(&hdrv->driver, &driver_attr_new_id);
	driver_unregister(&hdrv->driver);
	hid_free_dynids(hdrv);
}
EXPORT_SYMBOL_GPL(hid_unregister_driver);

int hid_check_keys_pressed(struct hid_device *hid)
{
	struct hid_input *hidinput;
	int i;

	if (!(hid->claimed & HID_CLAIMED_INPUT))
		return 0;

	list_for_each_entry(hidinput, &hid->inputs, list) {
		for (i = 0; i < BITS_TO_LONGS(KEY_MAX); i++)
			if (hidinput->input->key[i])
				return 1;
	}

	return 0;
}

EXPORT_SYMBOL_GPL(hid_check_keys_pressed);

static int __init hid_init(void)
{
	int ret;

	if (hid_debug)
		pr_warn("hid_debug is now used solely for parser and driver debugging.\n"
			"debugfs is now used for inspecting the device (report descriptor, reports)\n");

	ret = bus_register(&hid_bus_type);
	if (ret) {
		pr_err("can't register hid bus\n");
		goto err;
	}

	ret = hidraw_init();
	if (ret)
		goto err_bus;

	hid_debug_init();

	return 0;
err_bus:
	bus_unregister(&hid_bus_type);
err:
	return ret;
}

static void __exit hid_exit(void)
{
	hid_debug_exit();
	hidraw_exit();
	bus_unregister(&hid_bus_type);
}

module_init(hid_init);
module_exit(hid_exit);

MODULE_AUTHOR("Andreas Gal");
MODULE_AUTHOR("Vojtech Pavlik");
MODULE_AUTHOR("Jiri Kosina");
MODULE_LICENSE(DRIVER_LICENSE);

