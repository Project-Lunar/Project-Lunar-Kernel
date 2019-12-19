/* linux/drivers/video/sunxi/disp/dev_disp.c
 *
 * Copyright (c) 2013 Allwinnertech Co., Ltd.
 * Author: Tyle <tyle@allwinnertech.com>
 *
 * Display driver for sunxi platform
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#include "dev_disp.h"

disp_drv_info g_disp_drv;

#define MY_BYTE_ALIGN(x) ( ( (x + (4*1024-1)) >> 12) << 12)             /* alloc based on 4K byte */

static u32 suspend_output_type[2] = {0,0};
static u32 suspend_status = 0;//0:normal; suspend_status&1 != 0:in early_suspend; suspend_status&2 != 0:in suspend;
static u32 suspend_prestep = 0; //0:after early suspend; 1:after suspend; 2:after resume; 3 :after late resume

//static unsigned int gbuffer[4096];
static struct info_mm  g_disp_mm[10];

static struct cdev *my_cdev;
static dev_t devid ;
static struct class *disp_class;
static struct device *display_dev;

static u32 DISP_print = 0xffff;   //print cmd which eq DISP_print
#if defined(CONFIG_ARCH_SUN8IW6P1)
static struct sunxi_disp_mod disp_mod[] = {
	{DISP_MOD_DE      ,    "de"   },
	{DISP_MOD_LCD0    ,    "lcd0" },
	{DISP_MOD_LCD1    ,    "lcd1" },
};

static struct resource disp_resource[] =
{
	/*            name          start                        end                                 flags    */
	DISP_RESOURCE(de       ,SUNXI_DE_VBASE           , SUNXI_DE_VBASE     + SUNXI_DE_SIZE   , IORESOURCE_MEM)
	DISP_RESOURCE(lcd0     ,SUNXI_LCD0_VBASE          , SUNXI_LCD0_VBASE          + 0x3fc   , IORESOURCE_MEM)
	DISP_RESOURCE(lcd1     ,SUNXI_LCD1_VBASE          , SUNXI_LCD1_VBASE          + 0x3fc   , IORESOURCE_MEM)

	/*            name    irq_no                  flags     */
	DISP_RESOURCE(lcd0, SUNXI_IRQ_LCD0    , 0, IORESOURCE_IRQ)
	DISP_RESOURCE(lcd1, SUNXI_IRQ_LCD1    , 0, IORESOURCE_IRQ)
};
#elif defined(CONFIG_ARCH_SUN9IW1)
static struct sunxi_disp_mod disp_mod[] = {
	{DISP_MOD_DE      ,    "de"   },
	{DISP_MOD_LCD0    ,    "lcd0" },
	{DISP_MOD_LCD1    ,    "lcd1" },
};

static struct resource disp_resource[] =
{
	/*            name          start                        end                                 flags    */
	DISP_RESOURCE(de       ,SUNXI_BE0_VBASE           , SUNXI_BE0_VBASE     + 0xfc   , IORESOURCE_MEM)
	DISP_RESOURCE(lcd0     ,SUNXI_LCD0_VBASE          , SUNXI_LCD0_VBASE    + 0x3fc   , IORESOURCE_MEM)
	DISP_RESOURCE(lcd1     ,SUNXI_LCD1_VBASE          , SUNXI_LCD1_VBASE    + 0x3fc   , IORESOURCE_MEM)

	/*            name    irq_no                  flags     */
	DISP_RESOURCE(lcd0, SUNXI_IRQ_LCD0    , 0, IORESOURCE_IRQ)
	DISP_RESOURCE(lcd1, SUNXI_IRQ_LCD1    , 0, IORESOURCE_IRQ)
};

#else
static struct resource disp_resource[] =
{
};
#endif

#ifdef FB_RESERVED_MEM
void *disp_malloc(u32 num_bytes, u32 *phys_addr)
{
	u32 actual_bytes;
	void* address = NULL;

	if(num_bytes != 0) {
		actual_bytes = MY_BYTE_ALIGN(num_bytes);

		address = sunxi_buf_alloc(actual_bytes, phys_addr);
		if (address) {
			__inf("disp_malloc ok, address=0x%x, size=0x%x\n", *phys_addr, num_bytes);
			return address;
		} else {
			__wrn("disp_malloc fail, size=0x%x\n", num_bytes);
			return NULL;
		}
#if 0
		*phys_addr = sunxi_mem_alloc(actual_bytes);
		if(*phys_addr) {
			__inf("sunxi_mem_alloc ok, address=0x%x, size=0x%x\n", *phys_addr, num_bytes);
			address = sunxi_map_kernel(*phys_addr, actual_bytes);
			if(address) {
				__wrn("sunxi_map_kernel ok, phys_addr=0x%x, size=0x%x, virt_addr=0x%x\n", (unsigned int)*phys_addr, (unsigned int)num_bytes, (unsigned int)address);
			} else {
				__wrn("sunxi_map_kernel fail, phys_addr=0x%x, size=0x%x, virt_addr=0x%x\n", (unsigned int)*phys_addr, (unsigned int)num_bytes, (unsigned int)address);
			}
			return address;
		}
		__wrn("%s fail, size=0x%x\n", __func__, num_bytes);
#endif
	} else {
		__wrn("%s size is zero\n", __func__);
	}

	return NULL;
}

void  disp_free(void *virt_addr, void* phys_addr, u32 num_bytes)
{
	u32 actual_bytes;

	actual_bytes = MY_BYTE_ALIGN(num_bytes);
	if(virt_addr)
		sunxi_buf_free(virt_addr, (unsigned int)phys_addr, actual_bytes);
#if 0
	if(virt_addr) {
		sunxi_unmap_kernel((void*)virt_addr);
	}
	if(phys_addr) {
		sunxi_mem_free((unsigned int)phys_addr, actual_bytes);
	}
#endif

	return ;
}
#endif

static s32 drv_lcd_enable(u32 sel)
{
//FIXME
#if 0
	u32 i = 0;
	disp_lcd_flow *flow;
	mutex_lock(&g_disp_drv.mlock);
	if(bsp_disp_lcd_is_used(sel) && (g_disp_drv.b_lcd_enabled[sel] == 0))	{
		bsp_disp_lcd_pre_enable(sel);

		flow = bsp_disp_lcd_get_open_flow(sel);
		for(i=0; i<flow->func_num; i++)	{
			flow->func[i].func(sel);
			pr_info("[LCD]open, step %d finish\n", i);

			msleep_interruptible(flow->func[i].delay);
		}
		bsp_disp_lcd_post_enable(sel);

		g_disp_drv.b_lcd_enabled[sel] = 1;
	}
	mutex_unlock(&g_disp_drv.mlock);
#endif
	return 0;
}

static s32 drv_lcd_disable(u32 sel)
{
//FIXME
#if 0
	u32 i = 0;
	disp_lcd_flow *flow;
	mutex_lock(&g_disp_drv.mlock);
	if(bsp_disp_lcd_is_used(sel) && (g_disp_drv.b_lcd_enabled[sel] == 1))	{
		bsp_disp_lcd_pre_disable(sel);

		flow = bsp_disp_lcd_get_close_flow(sel);
		for(i=0; i<flow->func_num; i++)	{
			flow->func[i].func(sel);
			pr_info("[LCD]close, step %d finish\n", i);

			msleep_interruptible(flow->func[i].delay);
		}
		bsp_disp_lcd_post_disable(sel);

		g_disp_drv.b_lcd_enabled[sel] = 0;
	}
	mutex_unlock(&g_disp_drv.mlock);
#endif
	return 0;
}

#ifdef CONFIG_SUNXI_HDMI
s32 disp_set_hdmi_func(u32 screen_id, disp_hdmi_func * func)
{
	return bsp_disp_set_hdmi_func(screen_id, func);
}
#endif

static void resume_work_0(struct work_struct *work)
{
	drv_lcd_enable(0);
}

static void resume_work_1(struct work_struct *work)
{
	drv_lcd_enable(1);
}

static void resume_work_2(struct work_struct *work)
{
	drv_lcd_enable(2);
}

static void start_work(struct work_struct *work)
{
	int num_screens;
	//FIXME
	//int screen_id;

	num_screens = bsp_disp_feat_get_num_screens();
#if 0
	for(screen_id = 0; screen_id<num_screens; screen_id++) {
		__inf("sel=%d, output_type=%d, lcd_reg=%d, hdmi_reg=%d\n", screen_id,
		g_disp_drv.disp_init.output_type[screen_id], bsp_disp_get_lcd_registered(), bsp_disp_get_hdmi_registered());
		if(((g_disp_drv.disp_init.disp_mode	== DISP_INIT_MODE_SCREEN0) && (screen_id == 0))
			|| ((g_disp_drv.disp_init.disp_mode	== DISP_INIT_MODE_SCREEN1) && (screen_id == 1))) {
			if((g_disp_drv.disp_init.output_type[screen_id] == DISP_OUTPUT_TYPE_LCD)) {
				if(bsp_disp_get_lcd_registered() && bsp_disp_get_output_type(screen_id) != DISP_OUTPUT_TYPE_LCD) {
					drv_lcd_enable(screen_id);
				}
			}
			else if(g_disp_drv.disp_init.output_type[screen_id] == DISP_OUTPUT_TYPE_HDMI) {
				if(bsp_disp_get_hdmi_registered() && bsp_disp_get_output_type(screen_id) != DISP_OUTPUT_TYPE_HDMI) {
					__inf("hdmi register\n");
					bsp_disp_hdmi_set_mode(screen_id, g_disp_drv.disp_init.output_mode[screen_id]);
					bsp_disp_hdmi_enable(screen_id);
				}
			}
		}
		else if((g_fbi.disp_init.disp_mode == DISP_INIT_MODE_SCREEN2) && (screen_id == 2)
				&& (bsp_disp_get_output_type(screen_id) != DISP_OUTPUT_TYPE_LCD)) {
				drv_lcd_enable(screen_id);
		}
	}
#endif
}

static s32 start_process(void)
{
	flush_work(&g_disp_drv.start_work);
	schedule_work(&g_disp_drv.start_work);

	return 0;
}

s32 disp_register_sync_proc(void (*proc)(u32))
{
	struct proc_list *new_proc;

	new_proc = (struct proc_list*)disp_sys_malloc(sizeof(struct proc_list));
	if(new_proc) {
		new_proc->proc = proc;
		list_add_tail(&(new_proc->list), &(g_disp_drv.sync_proc_list.list));
	} else {
		pr_warn("malloc fail in %s\n", __func__);
	}

	return 0;
}

s32 disp_unregister_sync_proc(void (*proc)(u32))
{
	struct proc_list *ptr;

	if((NULL == proc)) {
		pr_warn("hdl is NULL in %s\n", __func__);
		return -1;
	}
	list_for_each_entry(ptr, &g_disp_drv.sync_proc_list.list, list) {
		if(ptr->proc == proc) {
			list_del(&ptr->list);
			disp_sys_free((void*)ptr);
			return 0;
		}
	}

	return -1;
}

s32 disp_register_sync_finish_proc(void (*proc)(u32))
{
	struct proc_list *new_proc;

	new_proc = (struct proc_list*)disp_sys_malloc(sizeof(struct proc_list));
	if(new_proc) {
		new_proc->proc = proc;
		list_add_tail(&(new_proc->list), &(g_disp_drv.sync_finish_proc_list.list));
	} else {
		pr_warn("malloc fail in %s\n", __func__);
	}

	return 0;
}

s32 disp_unregister_sync_finish_proc(void (*proc)(u32))
{
	struct proc_list *ptr;

	if((NULL == proc)) {
		pr_warn("hdl is NULL in %s\n", __func__);
		return -1;
	}
	list_for_each_entry(ptr, &g_disp_drv.sync_finish_proc_list.list, list) {
		if(ptr->proc == proc) {
			list_del(&ptr->list);
			disp_sys_free((void*)ptr);
			return 0;
		}
	}

	return -1;
}

static s32 disp_sync_finish_process(u32 screen_id)
{
	struct proc_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.sync_finish_proc_list.list, list) {
		if(ptr->proc)
			ptr->proc(screen_id);
	}

	return 0;
}

s32 disp_register_ioctl_func(unsigned int cmd, int (*proc)(unsigned int cmd, unsigned long arg))
{
	struct ioctl_list *new_proc;

	new_proc = (struct ioctl_list*)disp_sys_malloc(sizeof(struct ioctl_list));
	if(new_proc) {
		new_proc->cmd = cmd;
		new_proc->func = proc;
		list_add_tail(&(new_proc->list), &(g_disp_drv.ioctl_extend_list.list));
	} else {
		pr_warn("malloc fail in %s\n", __func__);
	}

	return 0;
}

s32 disp_unregister_ioctl_func(unsigned int cmd)
{
	struct ioctl_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.ioctl_extend_list.list, list) {
		if(ptr->cmd == cmd) {
			list_del(&ptr->list);
			disp_sys_free((void*)ptr);
			return 0;
		}
	}

	pr_warn("no ioctl found(cmd:0x%x) in %s\n", cmd, __func__);
	return -1;
}

static s32 disp_ioctl_extend(unsigned int cmd, unsigned long arg)
{
	struct ioctl_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.ioctl_extend_list.list, list) {
		if(cmd == ptr->cmd)
			return ptr->func(cmd, arg);
	}

	return -1;
}

s32 disp_register_standby_func(int (*suspend)(void), int (*resume)(void))
{
	struct standby_cb_list *new_proc;

	new_proc = (struct standby_cb_list*)disp_sys_malloc(sizeof(struct standby_cb_list));
	if(new_proc) {
		new_proc->suspend = suspend;
		new_proc->resume = resume;
		list_add_tail(&(new_proc->list), &(g_disp_drv.stb_cb_list.list));
	} else {
		pr_warn("malloc fail in %s\n", __func__);
	}

	return 0;
}

s32 disp_unregister_standby_func(int (*suspend)(void), int (*resume)(void))
{
	struct standby_cb_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.stb_cb_list.list, list) {
		if((ptr->suspend == suspend) && (ptr->resume == resume)) {
			list_del(&ptr->list);
			disp_sys_free((void*)ptr);
			return 0;
		}
	}

	return -1;
}

static s32 disp_suspend_cb(void)
{
	struct standby_cb_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.stb_cb_list.list, list) {
		if(ptr->suspend)
			return ptr->suspend();
	}

	return -1;
}

static s32 disp_resume_cb(void)
{
	struct standby_cb_list *ptr;

	list_for_each_entry(ptr, &g_disp_drv.stb_cb_list.list, list) {
		if(ptr->resume)
			return ptr->resume();
	}

	return -1;
}

static s32 disp_init(void)
{
	disp_bsp_init_para para;
	int i, disp, num_screens;

	__inf("%s !\n", __func__);

	INIT_WORK(&g_disp_drv.resume_work[0], resume_work_0);
	INIT_WORK(&g_disp_drv.resume_work[1], resume_work_1);
	INIT_WORK(&g_disp_drv.resume_work[2], resume_work_2);
	INIT_WORK(&g_disp_drv.start_work, start_work);
	INIT_LIST_HEAD(&g_disp_drv.sync_proc_list.list);
	INIT_LIST_HEAD(&g_disp_drv.sync_finish_proc_list.list);
	INIT_LIST_HEAD(&g_disp_drv.ioctl_extend_list.list);
	INIT_LIST_HEAD(&g_disp_drv.stb_cb_list.list);
	mutex_init(&g_disp_drv.mlock);

	memset(&para, 0, sizeof(disp_bsp_init_para));

	for(i=0; i<DISP_MOD_NUM; i++)	{
		para.reg_base[i] = (u32)g_disp_drv.reg_base[i];
		para.reg_size[i] = (u32)g_disp_drv.reg_size[i];
		para.irq_no[i]   = g_disp_drv.irq_no[i];
		__inf("mod %d, base=0x%x, size=0x%x, irq=%d\n", i, para.reg_base[i], para.reg_size[i], para.irq_no[i]);
	}
#if defined(CONFIG_ARCH_SUN9IW1)
{
	u32 phy_address;
	para.reg_base[DISP_MOD_DE] = (u32)disp_malloc(4*1024*1024, &phy_address);
	para.reg_size[DISP_MOD_DE] = 4*1024*1024;
	memset((void*)para.reg_base[DISP_MOD_DE], 0, 4*1024*1024);
	__inf("DE_BASE: 0x%0x\n", para.reg_base[DISP_MOD_DE]);
}
#endif

	para.disp_int_process       = disp_sync_finish_process;
	//para.vsync_event            = drv_disp_vsync_event;
	para.start_process          = start_process;
	//para.capture_event          = capture_event;

	bsp_disp_init(&para);
	num_screens = bsp_disp_feat_get_num_screens();
	for(disp=0; disp<num_screens; disp++) {
		g_disp_drv.mgr[disp] = disp_get_layer_manager(disp);
	}
	lcd_init();
	bsp_disp_open();
	//FIXME
	if(g_disp_drv.mgr[0] && g_disp_drv.mgr[0]->device)
		g_disp_drv.mgr[0]->device->enable(g_disp_drv.mgr[0]->device);

	//start_process();

	__inf("%s finish\n", __func__);
	return 0;
}

static s32 disp_exit(void)
{
	fb_exit();
	bsp_disp_close();
	bsp_disp_exit(g_disp_drv.exit_mode);
	return 0;
}


static int disp_mem_request(int sel,u32 size)
{
#ifndef FB_RESERVED_MEM
	unsigned map_size = 0;
	struct page *page;

	if(g_disp_mm[sel].info_base != 0)
	return -EINVAL;

	g_disp_mm[sel].mem_len = size;
	map_size = PAGE_ALIGN(g_disp_mm[sel].mem_len);

	page = alloc_pages(GFP_KERNEL,get_order(map_size));
	if(page != NULL) {
		g_disp_mm[sel].info_base = page_address(page);
		if(g_disp_mm[sel].info_base == 0)	{
			free_pages((unsigned long)(page),get_order(map_size));
			__wrn("page_address fail!\n");
			return -ENOMEM;
		}
		g_disp_mm[sel].mem_start = virt_to_phys(g_disp_mm[sel].info_base);
		memset(g_disp_mm[sel].info_base,0,size);

		__inf("pa=0x%08lx va=0x%p size:0x%x\n",g_disp_mm[sel].mem_start, g_disp_mm[sel].info_base, size);
		return 0;
	}	else {
		__wrn("alloc_pages fail!\n");
		return -ENOMEM;
	}
#else
	u32 ret = 0;
	u32 phy_addr;

	ret = (u32)disp_malloc(size, &phy_addr);
	if(ret != 0) {
		g_disp_mm[sel].info_base = (void*)ret;
		g_disp_mm[sel].mem_start = phy_addr;
		g_disp_mm[sel].mem_len = size;
		memset(g_disp_mm[sel].info_base,0,size);
		__inf("pa=0x%08lx va=0x%p size:0x%x\n",g_disp_mm[sel].mem_start, g_disp_mm[sel].info_base, size);

		return 0;
	}	else {
		__wrn("disp_malloc fail!\n");
		return -ENOMEM;
	}
#endif
}

static int disp_mem_release(int sel)
{
#ifndef FB_RESERVED_MEM
	unsigned map_size = PAGE_ALIGN(g_disp_mm[sel].mem_len);
	unsigned page_size = map_size;

	if(g_disp_mm[sel].info_base == 0)
		return -EINVAL;

	free_pages((unsigned long)(g_disp_mm[sel].info_base),get_order(page_size));
	memset(&g_disp_mm[sel],0,sizeof(struct info_mm));
#else
	if(g_disp_mm[sel].info_base == NULL)
		return -EINVAL;

	__inf("disp_mem_release, mem_id=%d, phy_addr=0x%x\n", sel, (unsigned int)g_disp_mm[sel].mem_start);
	disp_free((void *)g_disp_mm[sel].info_base, (void*)g_disp_mm[sel].mem_start, g_disp_mm[sel].mem_len);
	memset(&g_disp_mm[sel],0,sizeof(struct info_mm));
#endif
  return 0;
}

int sunxi_disp_get_source_ops(struct sunxi_disp_source_ops *src_ops)
{
	src_ops->sunxi_lcd_register_panel = bsp_disp_lcd_register_panel;
	src_ops->sunxi_lcd_delay_ms = disp_delay_ms;
	src_ops->sunxi_lcd_delay_us = disp_delay_us;
	src_ops->sunxi_lcd_backlight_enable = bsp_disp_lcd_backlight_enable;
	src_ops->sunxi_lcd_backlight_disable = bsp_disp_lcd_backlight_disable;
	src_ops->sunxi_lcd_power_enable = bsp_disp_lcd_power_enable;
	src_ops->sunxi_lcd_power_disable = bsp_disp_lcd_power_disable;
#if 0
	src_ops->sunxi_lcd_tcon_enable = bsp_disp_lcd_tcon_enable;
	src_ops->sunxi_lcd_tcon_disable = bsp_disp_lcd_tcon_disable;
	src_ops->sunxi_lcd_dsi_write = dsi_dcs_wr;
	src_ops->sunxi_lcd_dsi_clk_enable = dsi_clk_enable;
	src_ops->sunxi_lcd_pin_cfg = bsp_disp_lcd_pin_cfg;
	src_ops->sunxi_lcd_gpio_set_value = bsp_disp_lcd_gpio_set_value;
	src_ops->sunxi_lcd_gpio_set_direction = bsp_disp_lcd_gpio_set_direction;
#endif
	return 0;
}

int disp_mmap(struct file *file, struct vm_area_struct * vma)
{
	unsigned long mypfn = vma->vm_pgoff;
	unsigned long vmsize = vma->vm_end-vma->vm_start;
	vma->vm_pgoff = 0;

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	if(remap_pfn_range(vma,vma->vm_start,mypfn,vmsize,vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

int disp_open(struct inode *inode, struct file *file)
{
	return 0;
}

int disp_release(struct inode *inode, struct file *file)
{
	return 0;
}
ssize_t disp_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

ssize_t disp_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	return 0;
}

static int __devinit disp_probe(struct platform_device *pdev)
{
	int i;
	struct resource	*res;

	pr_info("[DISP]disp_probe\n");
	memset(&g_disp_drv, 0, sizeof(disp_drv_info));

	//FIXME, set manager to data
	//platform_set_drvdata(pdev,g_disp_drv);
	g_disp_drv.dev = &pdev->dev;

	for(i=0; i<sizeof(disp_mod)/sizeof(struct sunxi_disp_mod); i++)	{
		res = platform_get_resource_byname(pdev, IORESOURCE_MEM, disp_mod[i].name);
		if(res != NULL) {
			g_disp_drv.reg_base[disp_mod[i].id] = res->start;
			g_disp_drv.reg_size[disp_mod[i].id] = res->end - res->start;
			__inf("%s(%d), reg_base=0x%x\n", disp_mod[i].name, disp_mod[i].id, g_disp_drv.reg_base[disp_mod[i].id]);
		}
	}

	for(i=0; i<sizeof(disp_mod)/sizeof(struct sunxi_disp_mod); i++) {
		res = platform_get_resource_byname(pdev, IORESOURCE_IRQ, disp_mod[i].name);
		if(res != NULL)	{
			g_disp_drv.irq_no[disp_mod[i].id] = res->start;
			__inf("%s(%d), irq_no=%d\n", disp_mod[i].name, disp_mod[i].id, g_disp_drv.irq_no[disp_mod[i].id]);
		}
	}
	disp_init();
	fb_init(pdev);

	pr_info("[DISP]disp_probe finish\n");

	return 0;
}

static int disp_remove(struct platform_device *pdev)
{
	pr_info("disp_remove call\n");

	platform_set_drvdata(pdev, NULL);

	return 0;
}

#if defined(CONFIG_HAS_EARLYSUSPEND)
void backlight_early_suspend(struct early_suspend *h)
{
	u32 screen_id = 0;
	int num_screens;

	pr_info("%s\n", __func__);

	num_screens = bsp_disp_feat_get_num_screens();

	for(screen_id=0; screen_id<num_screens; screen_id++) {
		suspend_output_type[screen_id] = bsp_disp_get_output_type(screen_id);
		if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_LCD) {
				drv_lcd_disable(screen_id);
		} else if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_HDMI) {
			//FIXME
		}
	}
	//FIXME: hdmi suspend

	suspend_status |= DISPLAY_LIGHT_SLEEP;
	suspend_prestep = 0;

	disp_suspend_cb();

	pr_info("%s finish\n", __func__);
}

void backlight_late_resume(struct early_suspend *h)
{
	u32 screen_id = 0;
	int num_screens;

	pr_info("%s\n", __func__);

	//FIXME: hdmi resmue
	num_screens = bsp_disp_feat_get_num_screens();

	for(screen_id=0; screen_id<num_screens; screen_id++) {
		if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_LCD) {
			if(0 == suspend_prestep) {
				/* early_suspend -->  late_remsu */
				drv_lcd_enable(screen_id);
			} else {
				flush_work(&g_disp_drv.resume_work[screen_id]);
			}
		} else if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_HDMI) {
			//FIXME
		}
	}

	suspend_status &= (~DISPLAY_LIGHT_SLEEP);
	suspend_prestep = 3;

	disp_resume_cb();

	pr_info("%s finish\n", __func__);
}

static struct early_suspend backlight_early_suspend_handler =
{
  .level   = EARLY_SUSPEND_LEVEL_DISABLE_FB + 200,
	.suspend = backlight_early_suspend,
	.resume = backlight_late_resume,
};
#endif

static int disp_suspend(struct platform_device *pdev, pm_message_t state)
{
	//FIXME
	//u32 screen_id = 0;
	int num_screens;

	pr_info("%s\n", __func__);

	num_screens = bsp_disp_feat_get_num_screens();
//FIXME
	drv_lcd_disable(0);
#if 0
	for(screen_id=0; screen_id<num_screens; screen_id++) {
#if !defined(CONFIG_HAS_EARLYSUSPEND)
		suspend_output_type[screen_id] = bsp_disp_get_output_type(screen_id);
#endif
		if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_LCD) {
			if(2 == suspend_prestep)
				flush_work(&g_disp_drv.resume_work[screen_id]);
			drv_lcd_disable(screen_id);
		} else if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_HDMI) {
			//FIXME
		}
	}
	//FIXME: hdmi suspend
#endif
	suspend_status |= DISPLAY_DEEP_SLEEP;
	suspend_prestep = 1;
#if !defined(CONFIG_HAS_EARLYSUSPEND)
	disp_suspend_cb();
#endif
	pr_info("%s finish\n", __func__);

	return 0;
}


static int disp_resume(struct platform_device *pdev)
{
	u32 screen_id = 0;
	int num_screens;

	pr_info("%s\n", __func__);

	//FIXME: hdmi resmue
	num_screens = bsp_disp_feat_get_num_screens();
#if !defined(CONFIG_HAS_EARLYSUSPEND)
	//FIXME: hdmi resmue

	for(screen_id=0; screen_id<num_screens; screen_id++) {
		if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_LCD) {
		}
	}
#else
	for(screen_id=0; screen_id<num_screens; screen_id++) {
		if(suspend_output_type[screen_id] == DISP_OUTPUT_TYPE_LCD) {
			schedule_work(&g_disp_drv.resume_work[screen_id]);
		}
	}
#endif

	suspend_status &= (~DISPLAY_DEEP_SLEEP);
	suspend_prestep = 2;

#if !defined(CONFIG_HAS_EARLYSUSPEND)
	disp_resume_cb();
#endif

	pr_info("%s\n", __func__);

	return 0;
}

static void disp_shutdown(struct platform_device *pdev)
{
	u32 screen_id = 0;
	int num_screens;

	num_screens = bsp_disp_feat_get_num_screens();

	for(screen_id=0; screen_id<num_screens; screen_id++) {
		struct disp_manager *mgr = g_disp_drv.mgr[screen_id];

		if(mgr && mgr->device && mgr->device->is_enabled && mgr->device->disable) {
			if(mgr->device->is_enabled(mgr->device)) {
				mgr->device->disable(mgr->device);
			}
		}
	}

	return ;
}

long disp_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long karg[4];
	unsigned long ubuffer[4] = {0};
	s32 ret = 0;
	int num_screens = 2;
	struct disp_manager *mgr = NULL;
	struct disp_device *dispdev = NULL;

	num_screens = bsp_disp_feat_get_num_screens();

	if (copy_from_user((void*)karg,(void __user*)arg,4*sizeof(unsigned long))) {
		__wrn("copy_from_user fail\n");
		return -EFAULT;
	}

	ubuffer[0] = *(unsigned long*)karg;
	ubuffer[1] = (*(unsigned long*)(karg+1));
	ubuffer[2] = (*(unsigned long*)(karg+2));
	ubuffer[3] = (*(unsigned long*)(karg+3));

	if(ubuffer[0] < num_screens)
		mgr = g_disp_drv.mgr[ubuffer[0]];
	if(mgr)
		dispdev = mgr->device;

	if(cmd < DISP_FB_REQUEST)	{
		if(ubuffer[0] >= num_screens) {
			__wrn("para err in disp_ioctl, cmd = 0x%x,screen id = %d\n", cmd, (int)ubuffer[0]);
			return -1;
		}
	}
	if(DISPLAY_DEEP_SLEEP == suspend_status) {
		__wrn("ioctl:%x fail when in suspend!\n", cmd);
		return -1;
	}

	if(cmd == DISP_print) {
		pr_warn("cmd:0x%x,%ld,%ld\n",cmd, ubuffer[0], ubuffer[1]);
	}

	switch(cmd)	{
	//----disp global----
	case DISP_SET_BKCOLOR:
	{
		disp_color para;

		if(copy_from_user(&para, (void __user *)ubuffer[1],sizeof(disp_color)))	{
			__wrn("copy_from_user fail\n");
			return  -EFAULT;
		}
		if(mgr && (mgr->set_back_color != NULL))
			ret = mgr->set_back_color(mgr, &para);
		break;
	}

	case DISP_GET_SCN_WIDTH:
	{
		unsigned int width = 0,height = 0;
		if(mgr && mgr->device && mgr->device->get_resolution)
			mgr->device->get_resolution(mgr->device, &width, &height);
		ret = width;
		break;
	}

	case DISP_GET_SCN_HEIGHT:
	{
		unsigned int width = 0,height = 0;
		if(mgr && mgr->device && mgr->device->get_resolution)
			mgr->device->get_resolution(mgr->device, &width, &height);
		ret = height;
		break;
	}

	case DISP_GET_OUTPUT_TYPE:
	{
		if(mgr && mgr->device)
			ret = mgr->device->type;
		break;
	}

	case DISP_VSYNC_EVENT_EN:
	{
		ret = bsp_disp_vsync_event_enable(ubuffer[0], ubuffer[1]);
		break;
	}

	case DISP_SHADOW_PROTECT:
	{
		ret = bsp_disp_shadow_protect(ubuffer[0], ubuffer[1]);
		break;
	}

	//----layer----
	case DISP_LAYER_SET_CONFIG:
	{
		disp_layer_config para;

		if(copy_from_user(&para, (void __user *)ubuffer[1],sizeof(disp_layer_config)))	{
			__wrn("copy_from_user fail\n");
			return  -EFAULT;
		}
		if(mgr && mgr->set_layer_config)
			ret = mgr->set_layer_config(mgr, &para, ubuffer[2]);
		break;
	}

	case DISP_LAYER_GET_CONFIG:
	{
		disp_layer_config para;

		if(copy_from_user(&para, (void __user *)ubuffer[1],sizeof(disp_layer_config)))	{
			__wrn("copy_from_user fail\n");
			return  -EFAULT;
		}
		if(mgr && mgr->get_layer_config)
			ret = mgr->get_layer_config(mgr, &para, ubuffer[2]);
		if(copy_to_user((void __user *)ubuffer[1], &para, sizeof(disp_layer_config)))	{
			__wrn("copy_to_user fail\n");
			return  -EFAULT;
		}
		break;
	}

	//----for test----
	case DISP_MEM_REQUEST:
		ret =  disp_mem_request(ubuffer[0],ubuffer[1]);
		break;

	case DISP_MEM_RELEASE:
		ret =  disp_mem_release(ubuffer[0]);
		break;

	case DISP_MEM_GETADR:
		return g_disp_mm[ubuffer[0]].mem_start;

	default:
		ret = disp_ioctl_extend(cmd, (unsigned long)ubuffer);
		break;
	}

  return ret;
}

static const struct file_operations disp_fops = {
	.owner    = THIS_MODULE,
	.open     = disp_open,
	.release  = disp_release,
	.write    = disp_write,
	.read     = disp_read,
	.unlocked_ioctl = disp_ioctl,
	.mmap     = disp_mmap,
};

static struct platform_driver disp_driver = {
	.probe    = disp_probe,
	.remove   = disp_remove,
	.suspend  = disp_suspend,
	.resume   = disp_resume,
	.shutdown = disp_shutdown,
	.driver   =
	{
		.name   = "disp",
		.owner  = THIS_MODULE,
	},
};


static struct platform_device disp_device = {
	.name           = "disp",
	.id             = -1,
	.num_resources  = ARRAY_SIZE(disp_resource),
	.resource       = disp_resource,
	.dev            =
	{
		.power        =
		{
			.async_suspend = 1,
		}
	}
};

extern int disp_attr_node_init(void);
extern int capture_module_init(void);
extern void  capture_module_exit(void);
static int __init disp_module_init(void)
{
	int ret = 0, err;

	pr_info("[DISP]%s\n", __func__);

	alloc_chrdev_region(&devid, 0, 1, "disp");
	my_cdev = cdev_alloc();
	cdev_init(my_cdev, &disp_fops);
	my_cdev->owner = THIS_MODULE;
	err = cdev_add(my_cdev, devid, 1);
	if (err) {
		__wrn("cdev_add fail\n");
		return -1;
	}

	disp_class = class_create(THIS_MODULE, "disp");
	if (IS_ERR(disp_class))	{
		__wrn("class_create fail\n");
		return -1;
	}

	display_dev = device_create(disp_class, NULL, devid, NULL, "disp");

	ret = platform_device_register(&disp_device);

	if (ret == 0) {
		ret = platform_driver_register(&disp_driver);
	}
#ifdef CONFIG_HAS_EARLYSUSPEND
	register_early_suspend(&backlight_early_suspend_handler);
#endif

	pr_info("[DISP]%s finish\n", __func__);

	return ret;
}

static void __exit disp_module_exit(void)
{
	__inf("disp_module_exit\n");

#ifdef CONFIG_HAS_EARLYSUSPEND
	unregister_early_suspend(&backlight_early_suspend_handler);
#endif
	disp_exit();

	platform_driver_unregister(&disp_driver);
	platform_device_unregister(&disp_device);

	device_destroy(disp_class,  devid);
	class_destroy(disp_class);

	cdev_del(my_cdev);
}

//FIXME
//EXPORT_SYMBOL(sunxi_disp_get_source_ops);

module_init(disp_module_init);
module_exit(disp_module_exit);

MODULE_AUTHOR("tyle");
MODULE_DESCRIPTION("display driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:disp");


