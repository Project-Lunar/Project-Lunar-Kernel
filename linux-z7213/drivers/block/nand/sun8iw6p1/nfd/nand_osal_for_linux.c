/*
*********************************************************************************************************
*											        eBIOS
*						            the Easy Portable/Player Develop Kits
*									           dma sub system
*
*						        (c) Copyright 2006-2008, David China
*											All	Rights Reserved
*
* File    : clk_for_nand.c
* By      : Richard
* Version : V1.00
*********************************************************************************************************
*/
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/blkpg.h>
#include <linux/spinlock.h>
#include <linux/hdreg.h>
#include <linux/init.h>
#include <linux/semaphore.h>
#include <linux/platform_device.h>
#include <linux/clk.h>
#include <linux/interrupt.h>
#include <asm/uaccess.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/clk.h>
#include <linux/mutex.h>
#include <mach/platform.h> 
#include <mach/sys_config.h>
#include <linux/dma-mapping.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <asm/cacheflush.h>
#include <mach/gpio.h>
#include <linux/pinctrl/consumer.h>
#include <linux/pinctrl/pinconf-sunxi.h>
#include <linux/gpio.h>
#include "nand_blk.h"
#include <linux/regulator/consumer.h>
#include <linux/of.h>
#include <mach/sunxi-chip.h>

#ifdef CONFIG_DMA_ENGINE
#include <linux/dmaengine.h>
#include <linux/dma-mapping.h>
#include <linux/dma/sunxi-dma.h>
#endif

#define  NAND_DRV_VERSION_0		0x03
#define  NAND_DRV_VERSION_1		0x6001
#define  NAND_DRV_DATE			0x20161228
#define  NAND_DRV_TIME			0x1726

struct clk *pll6;
struct clk *nand0_clk;
struct clk *ahb_nand0;
struct regulator *regu1;


int seq;
int nand_handle;

static __u32 PRINT_LEVEL;

struct dma_chan *dma_hdl;
__u32 NAND_Print_level(void);

int NAND_Print(const char *fmt, ...)
{
	va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);

	return r;
}

int NAND_Print_DBG(const char *fmt, ...)
{

	va_list args;
	int r;

	if ((PRINT_LEVEL == 0) || (PRINT_LEVEL == 0xffffffff))
		return 0;
	else {
		va_start(args, fmt);
		r = vprintk(fmt, args);
		va_end(args);

		return r;
	}
}

int NAND_ClkRequest(__u32 nand_index)
{
	long rate;

	pll6 = clk_get(NULL, "pll6");
	if (NULL == pll6 || IS_ERR(pll6)) {
		printk("%s: pll6 clock handle invalid!\n", __func__);
		return -1;
	}

	rate = clk_get_rate(pll6);
	NAND_Print_DBG("%s: get pll6 rate %dHZ\n", __func__, (__u32) rate);

	if (nand_index == 0) {

		nand0_clk = clk_get(NULL, "nand");

		if (NULL == nand0_clk || IS_ERR(nand0_clk)) {
			printk("%s: nand0 clock handle invalid!\n", __func__);
			return -1;
		}

		if (clk_set_parent(nand0_clk, pll6))
			printk("%s: set nand0_clk parent to pll6 failed!\n", __func__);

		rate = clk_round_rate(nand0_clk, 20000000);
		if(clk_set_rate(nand0_clk, rate))
			printk("%s: set nand0_clk rate to %dHZ failed!\n", __func__, (__u32)rate);

		if(clk_prepare_enable(nand0_clk))
			printk("%s: enable nand0_clk failed!\n", __func__);
	} else {
		printk("NAND_ClkRequest, nand_index error: 0x%x\n", nand_index);
		return -1;
	}

	return 0;
}

void NAND_ClkRelease(__u32 nand_index)
{
	if (nand_index == 0) {
		if (NULL != nand0_clk && !IS_ERR(nand0_clk)) {

			clk_disable_unprepare(nand0_clk);

			clk_put(nand0_clk);
			nand0_clk = NULL;
		}
	} else {
		printk("NAND_ClkRequest, nand_index error: 0x%x\n", nand_index);
	}

	if (NULL != pll6 && !IS_ERR(pll6)) {
		clk_put(pll6);
		pll6 = NULL;
	}
	
}

int NAND_SetClk(__u32 nand_index, __u32 nand_clk0, __u32 nand_clk1)
{
	long rate;

	if (nand_index == 0) {

		if (NULL == nand0_clk || IS_ERR(nand0_clk)) {
			printk("%s: clock handle invalid!\n", __func__);
			return -1;
		}

		rate = clk_round_rate(nand0_clk, nand_clk0 * 2000000);
		if (clk_set_rate(nand0_clk, rate))
			printk("%s: set nand0_clk rate to %dHZ failed! nand_clk: 0x%x\n", __func__, (__u32)rate, nand_clk0);	
	} else {
		printk("NAND_SetClk, nand_index error: 0x%x\n", nand_index);
		return -1;
	}

	return 0;
}

int NAND_GetClk(__u32 nand_index, __u32 *pnand_clk0, __u32 *pnand_clk1)
{
	long rate;

	if (nand_index == 0) {
		if (NULL == nand0_clk || IS_ERR(nand0_clk)) {
			printk("%s: clock handle invalid!\n", __func__);
			return -1;
		}
		rate = clk_get_rate(nand0_clk);
	} else {
		printk("NAND_GetClk, nand_index error: 0x%x\n", nand_index);
		return -1;
	}

	*pnand_clk0 = (rate / 2000000);
	*pnand_clk1 = 0;

	return 0;
}

void eLIBs_CleanFlushDCacheRegion_nand(void *adr, size_t bytes)
{
/*  __flush_dcache_area(adr, bytes + (1 << 5) * 2 - 2);*/
}

__s32 NAND_CleanFlushDCacheRegion(void *buff_addr, __u32 len)
{
	eLIBs_CleanFlushDCacheRegion_nand((void *)buff_addr, (size_t) len);
	return 0;
}

__s32 NAND_InvaildDCacheRegion(__u32 rw, __u32 buff_addr, __u32 len)
{
	return 0;
}

void *NAND_DMASingleMap(__u32 rw, void *buff_addr, __u32 len)
{
	void *mem_addr;

	if (rw == 1) {
		mem_addr = (void *)dma_map_single(NULL, (void *)buff_addr, len,DMA_TO_DEVICE);
	} else {
		mem_addr = (void *)dma_map_single(NULL, (void *)buff_addr, len,DMA_FROM_DEVICE);
	}
	return mem_addr;
}

void *NAND_DMASingleUnmap(__u32 rw, void *buff_addr, __u32 len)
{
	void *mem_addr = buff_addr;

	if (rw == 1) {
		dma_unmap_single(NULL, (dma_addr_t) mem_addr, len,DMA_TO_DEVICE);
	} else {
		dma_unmap_single(NULL, (dma_addr_t) mem_addr, len,DMA_FROM_DEVICE);
	}

	return mem_addr;
}

void *NAND_VA_TO_PA(void *buff_addr)
{
	return (void *)(__pa((void *)buff_addr));
}

__s32 NAND_PIORequest(__u32 nand_index)
{

	script_item_u  *pin_list;
	int 		   pin_count;
	int 		   pin_index;

	PRINT_LEVEL = NAND_Print_level();

	/* get pin sys_config info */
	if(nand_index == 0)
	{
		pin_count = script_get_pio_list("nand0_para", &pin_list);
		NAND_Print_DBG("pin count:%d \n",pin_count);
	}
	else if(nand_index == 1)
		pin_count = script_get_pio_list("nand1_para", &pin_list);
	else
		return -1;
	if (pin_count == 0) {
		/* "lcd0" have no pin configuration */
		printk("pin count 0\n");
		return -1;
	}

	/* request pin individually */
	for (pin_index = 0; pin_index < pin_count; pin_index++) {
		struct gpio_config *pin_cfg = &(pin_list[pin_index].gpio);
		char			   pin_name[SUNXI_PIN_NAME_MAX_LEN];
		unsigned long	   config;
		
		/* valid pin of sunxi-pinctrl, 
		 * config pin attributes individually.
		 */
		sunxi_gpio_to_name(pin_cfg->gpio, pin_name);
		config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_FUNC, pin_cfg->mul_sel);
		pin_config_set(SUNXI_PINCTRL, pin_name, config);
		if (pin_cfg->pull != GPIO_PULL_DEFAULT) {
			config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_PUD, pin_cfg->pull);
			pin_config_set(SUNXI_PINCTRL, pin_name, config);
		}
		if (pin_cfg->drv_level != GPIO_DRVLVL_DEFAULT) {
			config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_DRV, pin_cfg->drv_level);
			pin_config_set(SUNXI_PINCTRL, pin_name, config);
		}
		if (pin_cfg->data != GPIO_DATA_DEFAULT) {
			config = SUNXI_PINCFG_PACK(SUNXI_PINCFG_TYPE_DAT, pin_cfg->data);
			pin_config_set(SUNXI_PINCTRL, pin_name, config);
		}
	}
	
	return 0;
}

void NAND_PIORelease(__u32 nand_index)
{

	int	cnt;
	script_item_u *list = NULL;

	if(nand_index == 0)
	{
		//printk("[NAND] nand gpio_release\n");
	
		/* ???gpio list */
		cnt = script_get_pio_list("nand0_para", &list);
		if(0 == cnt) {
			printk("get nand0_para gpio list failed\n");
			return;
		}

		/* ???gpio */
		while(cnt--)
			gpio_free(list[cnt].gpio.gpio);
	}
	else if(nand_index == 1)
	{
		cnt = script_get_pio_list("nand1_para", &list);
		if(0 == cnt) {
			printk("get nand1_para gpio list failed\n");
			return;
		}

		/* ???gpio */
		while(cnt--)
			gpio_free(list[cnt].gpio.gpio);
	}
	else
	{
		printk("NAND_PIORelease, nand_index error: 0x%x\n", nand_index);
	}	
}

void NAND_Memset(void *pAddr, unsigned char value, unsigned int len)
{
	memset(pAddr, value, len);
}

void NAND_Memcpy(void *pAddr_dst, void *pAddr_src, unsigned int len)
{
	memcpy(pAddr_dst, pAddr_src, len);
}

void *NAND_Malloc(unsigned int Size)
{
	return kmalloc(Size, GFP_KERNEL);
}

void NAND_Free(void *pAddr, unsigned int Size)
{
	kfree(pAddr);
}

void *NAND_IORemap(void *base_addr, unsigned int size)
{
	return base_addr;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
DEFINE_SEMAPHORE(nand_physic_mutex);

int NAND_PhysicLockInit(void)
{
	return 0;
}

int NAND_PhysicLock(void)
{
	down(&nand_physic_mutex);
	return 0;
}

int NAND_PhysicUnLock(void)
{
	up(&nand_physic_mutex);
	return 0;
}

int NAND_PhysicLockExit(void)
{
	return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
__u32 nand_dma_callback(void *para);

int nand_dma_config_start(__u32 rw, dma_addr_t addr, __u32 length)
{
	struct dma_slave_config dma_conf = { 0 };
	struct dma_async_tx_descriptor *dma_desc = NULL;

	dma_conf.direction = DMA_DEV_TO_MEM;
	dma_conf.src_addr = 0x01c03300;
	dma_conf.dst_addr = 0x01c03300;
	dma_conf.src_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf.dst_addr_width = DMA_SLAVE_BUSWIDTH_4_BYTES;
	dma_conf.src_maxburst = 1;
	dma_conf.dst_maxburst = 1;
	dma_conf.slave_id =rw ? sunxi_slave_id(DRQDST_NAND0,DRQSRC_SDRAM) : sunxi_slave_id(DRQDST_SDRAM,DRQSRC_NAND0);
	dmaengine_slave_config(dma_hdl, &dma_conf);

	dma_desc = dmaengine_prep_slave_single(dma_hdl, addr, length,
	             (rw ? DMA_TO_DEVICE :DMA_FROM_DEVICE),DMA_PREP_INTERRUPT |DMA_CTRL_ACK);
	if (!dma_desc) {
		printk("dmaengine prepare failed!\n");
		return -1;
	}

	dma_desc->callback =(void *) nand_dma_callback;
	if(rw == 0)
	{
	    dma_desc->callback_param = NULL;
	}
	else
	{
	    dma_desc->callback_param = (void*)(dma_desc);
	}
	dmaengine_submit(dma_desc);

	dma_async_issue_pending(dma_hdl);

	return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
__u32 NAND_GetNdfcDmaMode(void)
{
	/*
	   0: General DMA;
	   1: MBUS DMA

	   Only support MBUS DMA!!!!
	 */
	return 1;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
__u32 NAND_GetNandExtPara(__u32 para_num)
{
	script_item_u nand_para;
    script_item_value_type_e type;
    char str[8];

    str[0] = 'n';
    str[1] = 'a';
    str[2] = 'n';
    str[3] = 'd';
    str[4] = '_';
    str[5] = 'p';
    str[6] = '0';
    str[7] = '\0';

    if(para_num == 0)//frequency
    {
        str[6] = '0';
    }
    else if(para_num == 1)//SUPPORT_TWO_PLANE
    {
        str[6] = '1';
    }
    else if(para_num == 2)//SUPPORT_VERTICAL_INTERLEAVE
    {
        str[6] = '2';
    }
    else if(para_num == 3)//SUPPORT_DUAL_CHANNEL
    {
        str[6] = '3';
    }
    else if(para_num == 4)
    {
        str[6] = '4';
    }
    else if(para_num == 5)
    {
        str[6] = '5';
    }
    else
    {
		printk("NAND_GetNandExtPara: wrong para num: %d\n", para_num);
		return 0xffffffff;
    }

    type = script_get_item("nand0_para", str, &nand_para);
    if(SCIRPT_ITEM_VALUE_TYPE_INT != type)
    {
        printk("nand0_para, %d, nand type err! %d\n",para_num,type);
        return 0xffffffff;
    }
    else
    {
        return nand_para.val;
    }
}

__u32 NAND_GetNandIDNumCtrl(void)
{
    script_item_u id_number_ctl;
    script_item_value_type_e type;

    type = script_get_item("nand0_para", "id_number_ctl", &id_number_ctl);
    if(SCIRPT_ITEM_VALUE_TYPE_INT != type)
    {
        NAND_Print_DBG("nand_para0, id_number_ctl, nand type err! %d\n", type);
		return 0x0;
    } else {
    	NAND_Print_DBG("nand : get id_number_ctl from script,%x \n",id_number_ctl.val);	
    	return id_number_ctl.val;
    }	
}
/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
__u32 NAND_GetMaxChannelCnt(void)
{
	return 1;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_request_dma(void)
{
	dma_cap_mask_t mask;

	printk("request DMA");

	/* Try to acquire a generic DMA engine slave channel */
	dma_cap_zero(mask);
	dma_cap_set(DMA_SLAVE, mask);

	if (dma_hdl == NULL) {
		dma_hdl = dma_request_channel(mask, NULL, NULL);
		if (dma_hdl == NULL) {
			printk("Request DMA failed!\n");
			return -EINVAL;
		}
	}
	printk("chan_id: %d", dma_hdl->chan_id);

	return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int NAND_ReleaseDMA(__u32 nand_index)
{
	if (dma_hdl != NULL) {
		printk("nand release dma\n");
		dma_release_channel(dma_hdl);
		dma_hdl = NULL;
		return 0;
	}
	return 0;

}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
__u32 NAND_GetNdfcVersion(void)
{
	/*
	   0:
	   1: A31/A31s/A21/A23
	   2:
	 */
	return 1;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
void *NAND_GetIOBaseAddrCH0(void)
{
	return (void *)0xf1c03000;
}

void *NAND_GetIOBaseAddrCH1(void)
{
	return (void *)0xf1c05000;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
/*
__u32 nand_support_two_plane(void)
{
#if SUPPORT_TWO_PLANE
    return  1;
#else
    return  0;
#endif
}
__u32 nand_support_vertical_interleave(void)
{
#if SUPPORT_VERTICAL_INTERLEAVE
    return  1;
#else
    return  0;
#endif
}

__u32 nand_support_dual_channel(void)
{
#if SUPPORT_DUAL_CHANNEL
    return  1;
#else
    return  0;
#endif
}
*/
/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
/*
__u32 nand_wait_rb_before(void)
{
#if WAIT_RB_BEFORE
    return  1;
#else
    return  0;
#endif
}
*/
/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
/*
__u32 nand_wait_rb_mode(void)
{
#if WAIT_RB_INTERRRUPT
    return  1;
#else
    return  0;
#endif
}
*/
/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
/*
__u32 nand_wait_dma_mode(void)
{
#if WAIT_DMA_INTERRRUPT
    return  1;
#else
    return  0;
#endif
}
*/
/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         : wait rb
*****************************************************************************/
static DECLARE_WAIT_QUEUE_HEAD(NAND_RB_WAIT_CH0);
static DECLARE_WAIT_QUEUE_HEAD(NAND_RB_WAIT_CH1);

__s32 nand_rb_wait_time_out(__u32 no, __u32 *flag)
{
	__s32 ret;
	if (no == 0)
		ret = wait_event_timeout(NAND_RB_WAIT_CH0, *flag, HZ >> 1);
	else
		ret = wait_event_timeout(NAND_RB_WAIT_CH1, *flag, HZ >> 1);

	return ret;
}

__s32 nand_rb_wake_up(__u32 no)
{
	if (no == 0)
		wake_up(&NAND_RB_WAIT_CH0);
	else
		wake_up(&NAND_RB_WAIT_CH1);

	return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         : wait dma
*****************************************************************************/
static DECLARE_WAIT_QUEUE_HEAD(NAND_DMA_WAIT_CH0);
static DECLARE_WAIT_QUEUE_HEAD(NAND_DMA_WAIT_CH1);

__s32 nand_dma_wait_time_out(__u32 no, __u32 *flag)
{
	__s32 ret;
	if (no == 0)
		ret = wait_event_timeout(NAND_DMA_WAIT_CH0, *flag, HZ >> 1);
	else
		ret = wait_event_timeout(NAND_DMA_WAIT_CH1, *flag, HZ >> 1);

	return ret;
}

__s32 nand_dma_wake_up(__u32 no)
{
	if (no == 0)
		wake_up(&NAND_DMA_WAIT_CH0);
	else
		wake_up(&NAND_DMA_WAIT_CH1);

	return 0;
}

__u32 nand_dma_callback(void *para)
{
	//wake_up( &NAND_DMA_WAIT_CH0 );
//	printk("dma transfer finish\n");
    if(para == NULL)
    {
        //printk("1n2\n");
    }
	return 0;
}

int NAND_get_storagetype(void)
{
#if 1
    script_item_value_type_e script_ret;
    script_item_u storage_type;
    
    script_ret = script_get_item("target","storage_type", &storage_type);
    if(script_ret!=SCIRPT_ITEM_VALUE_TYPE_INT)
    {
           NAND_Print_DBG("nand init fetch storage_type failed\n");
           storage_type.val=0;
           return storage_type.val;
    }

    return (int)storage_type.val;
#else
	return 1;
#endif
    
}

int NAND_GetVoltage(void)
{
	int ret = 0;

#if 1
	if (regu1 == NULL) {
		regu1 = regulator_get(NULL, "vcc-nand");
		if (IS_ERR(regu1)) {
			printk("nand:some error happen, fail to get regulator vcc-nand!");
			return -1;
		}

		/*enable regulator*/
		ret = regulator_enable(regu1);
		if (IS_ERR(regu1)) {
			printk("nand:some error happen, fail to enable regulator vcc-nand!");
			return -1;
		}
		NAND_Print_DBG("nand:get voltage vcc-nand ok:%x\n", (__u32) regu1);
	} else
		printk("nand:has already get voltage\n");
#endif

	return ret;
}

int NAND_ReleaseVoltage(void)
{
	int ret = 0;

#if 1
	if (regu1 != NULL) {
		printk("nand release voltage vcc-nand\n");
		ret = regulator_disable(regu1);
		if (ret)
			printk("nand:regulator disable fail ret is %x\n", ret);
		if (IS_ERR(regu1)) {
			printk("nand:some error happen, fail to disable regulator vcc-nand!");
			return -1;
		}
		/*put regulator when module exit*/
		regulator_put(regu1);
		regu1 = NULL;
	} else
		printk("nand had already release voltage vcc-nand\n");
#endif

	return ret;
}

int NAND_IS_Secure_sys(void)
{
	if(sunxi_soc_is_secure())
		return 1;
	else
		return 0;
}

__u32 NAND_Print_level(void)
{
	script_item_u print_level;
    script_item_value_type_e type;
	
    type = script_get_item("nand0_para", "print_level", &print_level);
    if(SCIRPT_ITEM_VALUE_TYPE_INT != type)
    {
        return 0xffffffff;
    }
	else
		return print_level.val;
}

void NAND_Print_Version(void)
{
	int val[4] = { 0 };

	val[0] = NAND_DRV_VERSION_0;
	val[1] = NAND_DRV_VERSION_1;
	val[2] = NAND_DRV_DATE;
	val[3] = NAND_DRV_TIME;

	printk("kernel: nand version: %x %x %x %x\n", val[0],
	       val[1], val[2], val[3]);
}

int NAND_Get_Version(void)
{
    return NAND_DRV_DATE;
}

void nand_cond_resched(void)
{
	cond_resched();
}
