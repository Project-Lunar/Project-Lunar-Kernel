/*********************************************************************************
*                                           NAND FLASH DRIVER
*								(c) Copyright 2008, SoftWinners Co,Ld.
*                                          All Right Reserved
*file : nfc_r.c
*description : this file provides some physic functions for upper nand driver layer.
*history :
*	v0.1  2008-03-26 Richard
*	        offer direct accsee read method to nand flash control machine.
*   v0.2  2009.09.09 penggang
**********************************************************************************/
#include "nfc.h"
#include "nfc_reg.h"
#include "nand_physic.h"
#include "nand_physic_interface.h"

__u32 NandIOBase[2] = {0, 0};
__u32 NandIndex = 0;
__u32 nand_reg_address = 0;
__u32 nand_board_version = 0;
__u32 pagesize = 0;

__u32 Retry_value_ok_flag = 0;


volatile __u32 irq_value = 0;


__u8 read_retry_reg_adr[READ_RETRY_MAX_REG_NUM] = {0};
__u8 read_retry_default_val[1][MAX_CHIP_SELECT_CNT][READ_RETRY_MAX_REG_NUM] = {0};
__s16 read_retry_val[READ_RETRY_MAX_CYCLE][READ_RETRY_MAX_REG_NUM] = {0};
__u8 hynix_read_retry_otp_value[1][MAX_CHIP_SELECT_CNT][8][8] = {0};
__u8 read_retry_mode = {0};
__u8 read_retry_cycle = {0};
__u8 read_retry_reg_num = {0};

__u8 hynix16nm_read_retry_otp_value[1][MAX_CHIP_SELECT_CNT][8][4] = {0};

__u32 toshiba15nm_rr_start_flag = 0;

const __s16 para0[6][4] = {	{0x00,  0x06,  0x0A,  0x06},
    						{0x00, -0x03, -0x07, -0x08},
    						{0x00, -0x06, -0x0D, -0x0F},
    						{0x00, -0x0B, -0x14, -0x17},
    						{0x00,  0x00, -0x1A, -0x1E},
    						{0x00,  0x00, -0x20, -0x25}
					};
const __s16 para1[6][4] = {	{0x00,  0x06,  0x0a,  0x06},
    						{0x00, -0x03, -0x07, -0x08},
    						{0x00, -0x06, -0x0d, -0x0f},
    						{0x00, -0x09, -0x14, -0x17},
    						{0x00,  0x00, -0x1a, -0x1e},
    						{0x00,  0x00, -0x20, -0x25}
					};
const __s16 para0x10[5] = {0x04, 0x7c, 0x78, 0x74, 0x08};
const __s16 para0x11[7][5] = {	{0x04,  0x04,  0x7c,  0x7e, 0x00},
    						{0x00, 0x7c, 0x78, 0x78, 0x00},
    						{0x7c, 0x76, 0x74, 0x72, 0x00},
    						{0x08, 0x08, 0x00, 0x00, 0x00},
    						{0x0b, 0x7e, 0x76, 0x74, 0x00},
    						{0x10, 0x76, 0x72, 0x70, 0x00},
    						{0x02, 0x00, 0x7e, 0x7c, 0x00},
					};
const __s16 para0x12[10][5] = {	{0x00, 0x00, 0x00, 0x00, 0x00},
								{0x02, 0x04, 0x02, 0x00, 0x00},
								{0x7c, 0x00, 0x7c, 0x7c, 0x00},
								{0x7a, 0x00, 0x7a, 0x7a, 0x00},
								{0x78, 0x02, 0x78, 0x7a, 0x00},
								{0x7e, 0x04, 0x7e, 0x7a, 0x00},
								{0x76, 0x04, 0x76, 0x78, 0x00},
								{0x04, 0x04, 0x04, 0x76, 0x00},
								{0x06, 0x0a, 0x06, 0x02, 0x00},
								{0x74, 0x7c, 0x74, 0x76, 0x00}
					};
const __s16 para0x20[15][4] ={{0x00, 0x00, 0x00, 0x00},    //0
                         {0x05, 0x0A, 0x00, 0x00},    //1
                         {0x28, 0x00, 0xEC, 0xD8},    //2
                         {0xED, 0xF5, 0xED, 0xE6},    //3
                         {0x0A, 0x0F, 0x05, 0x00},    //4
                         {0x0F, 0x0A, 0xFB, 0xEC},    //5
                         {0xE8, 0xEF, 0xE8, 0xDC},    //6
                         {0xF1, 0xFB, 0xFE, 0xF0},    //7
                         {0x0A, 0x00, 0xFB, 0xEC},    //8
                         {0xD0, 0xE2, 0xD0, 0xC2},    //9
                         {0x14, 0x0F, 0xFB, 0xEC},    //10
                         {0xE8, 0xFB, 0xE8, 0xDC},    //11
                         {0x1E, 0x14, 0xFB, 0xEC},    //12
                         {0xFB, 0xFF, 0xFB, 0xF8},    //13
                         {0x07, 0x0C, 0x02, 0x00}     //14
	                    };
const __s16 param0x30low[16][2] ={{0xF0,0XF0},
									{0xE0,0XE0},
									{0xD0,0XD0},
									{0x10,0X10},
									{0x20,0X20},
									{0x30,0X30},
									{0xC0,0XD0},
									{0x00,0X10},
									{0x00,0X20},
									{0x10,0X20},
									{0xB0,0XD0},
									{0xA0,0XD0},
									{0x90,0XD0},
									{0xB0,0XC0},
									{0xA0,0XC0},
									{0x90,0XC0}
									};
const __s16 param0x30high[20][2] ={{0x00,0XF0},
									{0x0F,0XE0},
									{0x0F,0XD0},
									{0x0E,0XE0},
									{0x0E,0XD0},
									{0x0D,0XF0},
									{0x0D,0XE0},
									{0x0D,0XD0},
									{0x01,0X10},
									{0x02,0X20},
									{0x02,0X10},
									{0x03,0X20},
									{0x0F,0X00},
									{0x0E,0XF0},
									{0x0D,0XC0},
									{0x0F,0XF0},
									{0x01,0X00},
									{0x02,0X00},
									{0x0D,0XB0},
									{0x0C,0XA0}
									};
const __s16 param0x31[9][3] =	   {{0x00,0XF0,0x00},
									{0x00,0XE0,0x00},
									{0xFF,0XF0,0xF0},
									{0xEE,0XE0,0xE0},
									{0xDE,0XD0,0xD0},
									{0xCD,0XC0,0xC0},
									{0x01,0X00,0x00},
									{0x02,0X00,0x00},
									{0x03,0X00,0x00},
									};
const __s16 param0x32[32][4] ={{0x00,0x00,0x00,0x00},  //0
								 {0x7C,0x00,0x00,0x7C},// 1
								 {0x04,0x00,0x7C,0x78},// 2
								 {0x78,0x00,0x78,0x74},// 3
								 {0x08,0x7C,0x00,0x7C},// 4
								 {0x00,0x7C,0x7C,0x78},// 5
								 {0x7C,0x7C,0x78,0x74},// 6
								 {0x00,0x7C,0x74,0x70},// 7
								 {0x00,0x78,0x00,0x7C},// 8
								 {0x00,0x78,0x7C,0x78},// 9
								 {0x00,0x78,0x78,0x74},// 10
								 {0x00,0x78,0x74,0x70},// 11
								 {0x00,0x78,0x70,0x6C},// 12
								 {0x00,0x04,0x04,0x00},// 13
								 {0x00,0x04,0x00,0x7C},// 14
								 {0x0C,0x04,0x7C,0x78},// 15
								 {0x0C,0x04,0x78,0x74},// 16
								 {0x10,0x08,0x00,0x7C},// 17
								 {0x10,0x08,0x04,0x00},// 18
								 {0x78,0x74,0x78,0x74},// 19
								 {0x78,0x74,0x74,0x70},// 20
								 {0x78,0x74,0x70,0x6C},// 21
								 {0x78,0x74,0x6C,0x68},// 22
								 {0x78,0x70,0x78,0x74},// 23
								 {0x78,0x70,0x74,0x70},// 24
								 {0x78,0x70,0x6C,0x68},// 25
								 {0x78,0x70,0x70,0x6C},// 26
								 {0x78,0x6C,0x70,0x6C},// 27
								 {0x78,0x6C,0x6C,0x68},// 28
								 {0x78,0x6C,0x68,0x64},// 29
								 {0x74,0x68,0x6C,0x68},// 30
								 {0x74,0x68,0x68,0x64} // 31
									};
const	__s16 param0x40[10] = {0x0,0x0,0x0,0x1,0x2,0x3,0x04,0x05,0x06,0x07};
const	__s16 param0x41[12] = {0x0,0x0,0x0,0x1,0x2,0x3,0x04,0x05,0x06,0x07,0x08,0x0C};

const	__s16 param0x50[7] = {0x1,0x2,0x3,0x0,0x1,0x2,0x3};
__u32 ddr_param[8] = {0};

/*
static void dumphex32(char* name, char* base, int len)
{
	__u32 i;

	PHY_ERR("dump %s registers:", name);
	for (i=0; i<len*4; i+=4) {
		if (!(i&0xf))
			PHY_ERR("\n0x%p : ", base + i);
		PHY_ERR("0x%08x ", *((volatile unsigned int *)(base + i)));
	}
	PHY_ERR("\n");
}
*/

void NFC_InitDDRParam(__u32 chip, __u32 param)
{
    if(chip<8)
        ddr_param[chip] = param;
}

void nfc_repeat_mode_enable(void)
{
    __u32 reg_val;

	reg_val = NDFC_READ_REG_CTL();
	if(((reg_val>>18)&0x3)>1)   //ddr type
	{
    	reg_val |= 0x1<<20;
    	NDFC_WRITE_REG_CTL(reg_val);
    }
}

void nfc_repeat_mode_disable(void)
{
    __u32 reg_val;

    reg_val = NDFC_READ_REG_CTL();
	if(((reg_val>>18)&0x3)>1)   //ddr type
	{
    	reg_val &= (~(0x1<<20));
    	NDFC_WRITE_REG_CTL(reg_val);
    }
}

/*******************wait nfc********************************************/
__s32 _wait_cmdfifo_free(void)
{
	__s32 timeout = 0xffffff;

	while ( (timeout--) && (NDFC_READ_REG_ST() & NDFC_CMD_FIFO_STATUS) );
	if (timeout <= 0)
	{
	    PHY_ERR("nand _wait_cmdfifo_free time out, status:0x%x\n", NDFC_READ_REG_ST());

		NAND_DumpReg();
	    
		return -ERR_TIMEOUT;
    }
	return 0;
}

__s32 _wait_cmd_finish(void)
{
	__s32 timeout = 0xffffff;
	
	while( (timeout--) && !(NDFC_READ_REG_ST()& NDFC_CMD_INT_FLAG) );
	if (timeout <= 0)
	{
	    PHY_ERR("nand _wait_cmd_finish time out, NandIndex %d, status:0x%x\n", (__u32)NandIndex, NDFC_READ_REG_ST());

		NAND_DumpReg();

        return -ERR_TIMEOUT;
   }
   
	NDFC_WRITE_REG_ST(NDFC_READ_REG_ST() & NDFC_CMD_INT_FLAG);
	
	return 0;
}

void _show_desc_list_cfg(void)
{

#if 0
	__u32 ind;
	_ndfc_dma_desc_t *pdesc;

	ind = 0;
	//pdesc = (_ndfc_dma_desc_t *)NFC_READ_REG(NFC_REG_DMA_DL_BASE);
	pdesc = &ndfc_dma_desc_cpu[0];

	do {
		PHY_DBG("desc %d - 0x%08x:  cfg: 0x%04x,  size: 0x%04x,  buff: 0x%08x,  next: 0x%x\n",
			ind, (__u32)pdesc, pdesc->cfg, pdesc->bcnt, pdesc->buff, (__u32)(pdesc->next));

		if (pdesc->cfg & NDFC_DESC_LAST_FLAG)
			break;

		ind++;
		if (ind > 4) {
			PHY_ERR("wrong desc list cfg.\n");
			break;
		}
		pdesc = &ndfc_dma_desc_cpu[ind];
	} while(1);
#endif

	return ;
}

__u32 nand_dma_addr[2][5] = {{0}, {0}};
void _dma_config_start(__u8 rw, __u32 buff_addr, __u32 len)
{
	__u32 reg_val;

	if ( NdfcVersion == NDFC_VERSION_V1 ) {
		
		if (NdfcDmaMode == 1) {
			/*
				MBUS DMA
			*/
			NAND_CleanFlushDCacheRegion(buff_addr, len);
		
			nand_dma_addr[NandIndex][0] = NAND_DMASingleMap(rw, buff_addr, len);
		
			//set mbus dma mode
			reg_val = NDFC_READ_REG_CTL();
			reg_val &= (~(0x1<<15));
			NDFC_WRITE_REG_CTL(reg_val);
			NDFC_WRITE_REG_MDMA_ADDR(nand_dma_addr[NandIndex][0]);
			NDFC_WRITE_REG_DMA_CNT(len);
		} else if (NdfcDmaMode == 0) {
			/*
				General DMA
			*/
			NAND_CleanFlushDCacheRegion(buff_addr, len);

			reg_val = NDFC_READ_REG_CTL();
			reg_val |=(0x1 << 15); 
			NDFC_WRITE_REG_CTL(reg_val);			
			NDFC_WRITE_REG_DMA_CNT(len);
			
			nand_dma_addr[NandIndex][0] = NAND_DMASingleMap(rw, buff_addr, len);
			//NDFC_WRITE_REG_MDMA_ADDR(nand_dma_addr[NandIndex][0]);
			//PHY_ERR("buff_addr 0x%x  nand_dma_addr[NandIndex][0] 0x%x\n", buff_addr, nand_dma_addr[NandIndex][0]);
			nand_dma_config_start( rw, nand_dma_addr[NandIndex][0], len);	
		} else {
			PHY_ERR("_dma_config_start, wrong dma mode, %d\n", NdfcDmaMode);	
		}		
		
	} else if ( NdfcVersion == NDFC_VERSION_V2 ) {
		
		if (NdfcDmaMode == 1) {
		
			if (buff_addr & 0x3) {
				PHY_ERR("_dma_config_start: buff addr(0x%x) is not 32bit aligned, "
						"and it will be clipped to 0x%x", buff_addr, (buff_addr & 0x3));
			}
	
			NAND_CleanFlushDCacheRegion(buff_addr, len);
			nand_dma_addr[NandIndex][0] = NAND_DMASingleMap(rw, buff_addr, len);
	
			reg_val = NDFC_READ_REG_CTL();
			reg_val &= (~(0x1<<15));
			NDFC_WRITE_REG_CTL(reg_val);
	
			ndfc_dma_desc_cpu[0].bcnt = 0;
			ndfc_dma_desc_cpu[0].bcnt |= NDFC_DESC_BSIZE(len);
			ndfc_dma_desc_cpu[0].buff = nand_dma_addr[NandIndex][0]; //buff_addr;
	
			ndfc_dma_desc_cpu[0].cfg = 0;
			ndfc_dma_desc_cpu[0].cfg |= NDFC_DESC_FIRST_FLAG;
			ndfc_dma_desc_cpu[0].cfg |= NDFC_DESC_LAST_FLAG;
	
			ndfc_dma_desc_cpu[0].next = (struct _ndfc_dma_desc_t *)&(ndfc_dma_desc[0]);
	
			NAND_CleanFlushDCacheRegion((__u32)&(ndfc_dma_desc_cpu[0]), sizeof(ndfc_dma_desc_cpu[0]));
			NDFC_WRITE_REG_DMA_DL_BASE( (__u32)ndfc_dma_desc );
	
			_show_desc_list_cfg();
		} else {
			PHY_ERR("_dma_config_start, wrong dma mode, %d\n", NdfcDmaMode);	
		}
	} else {
		PHY_ERR("_dma_config_start: wrong ndfc version, %d\n", NdfcVersion);
	}

	return ;
}

__s32 _wait_dma_end(__u8 rw, __u32 buff_addr, __u32 len)
{
	__s32 timeout = 0xffffff;
	_ndfc_dma_desc_t *pdesc;

	while ( (timeout--) && (!(NDFC_READ_REG_ST() & NDFC_DMA_INT_FLAG)) );
	if (timeout <= 0)
	{
	    PHY_ERR("nand _wait_dma_end time out, NandIndex: 0x%x, rw: 0x%x, status:0x%x\n", NandIndex, (__u32)rw, NDFC_READ_REG_ST());
	    
	    if ( NdfcVersion == NDFC_VERSION_V1 ) {
	    	PHY_ERR("DMA addr: 0x%x, DMA len: 0x%x\n", NDFC_READ_REG_MDMA_ADDR(), NDFC_READ_REG_DMA_CNT());
	    	
			NAND_DumpReg();
	    	
	    	return -ERR_TIMEOUT;
	    	
	    } else if ( NdfcVersion == NDFC_VERSION_V2 ) {
	    	pdesc = &ndfc_dma_desc_cpu[0];
	    	PHY_ERR("DMA addr: 0x%x, DMA len: 0x%x, Desc CFG: 0x%x\n", pdesc->buff, pdesc->bcnt, pdesc->cfg);
	    	
	    	NAND_DumpReg();	    	
	    	_show_desc_list_cfg();
			PHY_ERR("while 1 stop\n");
			while(1);
			return -ERR_TIMEOUT;
	    	
	    } else {
	    	PHY_ERR("_dma_config_start: wrong ndfc version, %d\n", NdfcVersion);
	    }
    }

	NDFC_WRITE_REG_ST(NDFC_READ_REG_ST() & NDFC_DMA_INT_FLAG);
	NAND_DMASingleUnmap(rw, nand_dma_addr[NandIndex][0], len);

	return 0;
}

void _dma_config_start_v2(__u8 rw, __u32 buf_cnt, __u32 buf_addr[], __u32 buf_size[])
{
	__s32 i;
	__u32 reg_val;

	if ( NdfcVersion == NDFC_VERSION_V2)
	{
		if (buf_cnt > 4)
		{
			PHY_ERR("buf cnt error: %d\n", buf_cnt);
		}

		reg_val = NDFC_READ_REG_CTL();
		reg_val &= (~(0x1<<15));
		NDFC_WRITE_REG_CTL(reg_val);

		for (i=0; i<buf_cnt; i++)
		{
			if (buf_addr[i] & 0x3) {
				PHY_ERR("%s: buff addr(0x%x) is not 32bit aligned, "
						"and it will be clipped to 0x%x ----- while(1)", __func__, buf_addr[i], (buf_addr[i] & 0x3));
				while(1);
			}
			if (buf_size[i]%1024) {
				PHY_ERR("%s: wrong buffer size: 0x%x\n ---- while(1)\n", __func__, buf_size[i]);
				while(1);
			}

			NAND_CleanFlushDCacheRegion(buf_addr[i], buf_size[i]);
			nand_dma_addr[NandIndex][i] = NAND_DMASingleMap(rw, buf_addr[i], buf_size[i]);

			ndfc_dma_desc_cpu[i].bcnt = 0;
			ndfc_dma_desc_cpu[i].bcnt |= NDFC_DESC_BSIZE(buf_size[i]);
			ndfc_dma_desc_cpu[i].buff = nand_dma_addr[NandIndex][i]; //buf_addr[i];
			ndfc_dma_desc_cpu[i].cfg = 0;

			ndfc_dma_desc_cpu[i].next = 0;
			ndfc_dma_desc_cpu[i].next = (struct _ndfc_dma_desc_t *)&(ndfc_dma_desc[i+1]);
		}

		ndfc_dma_desc_cpu[0].cfg = 0;
		ndfc_dma_desc_cpu[buf_cnt-1].cfg = 0;
		ndfc_dma_desc_cpu[0].cfg |= NDFC_DESC_FIRST_FLAG;
		ndfc_dma_desc_cpu[buf_cnt-1].cfg |= NDFC_DESC_LAST_FLAG;

		ndfc_dma_desc_cpu[buf_cnt-1].next = (struct _ndfc_dma_desc_t *)&(ndfc_dma_desc[0]);

		NAND_CleanFlushDCacheRegion((__u32)&(ndfc_dma_desc_cpu[0]), sizeof(ndfc_dma_desc_cpu[0])*buf_cnt);
		NDFC_WRITE_REG_DMA_DL_BASE( (__u32)ndfc_dma_desc );
		_show_desc_list_cfg();
	} else
		PHY_ERR("_dma_config_start_v2: wrong ndfc version, %d\n", NdfcVersion);
}

__s32 _wait_dma_end_v2(__u8 rw, __u32 buf_cnt, __u32 buf_addr[], __u32 buf_size[])
{
	__s32 i, timeout = 0xfffff;
	_ndfc_dma_desc_t *pdesc;
    
    while ( (timeout--) && (!(NDFC_READ_REG_ST() & NDFC_DMA_INT_FLAG)) );
	if (timeout <= 0)
	{
	    if ( NdfcVersion == NDFC_VERSION_V2 ) {
	    	pdesc = &ndfc_dma_desc_cpu[0];
	    	PHY_ERR("DMA addr: 0x%x, DMA len: 0x%x, Desc CFG: 0x%x\n", pdesc->buff, pdesc->bcnt, pdesc->cfg);
	    	
			NAND_DumpReg();
	    	
	    	_show_desc_list_cfg();
	
			return -ERR_TIMEOUT;
		    	
	    } else {
	    	PHY_ERR("_dma_config_start: wrong ndfc version, %d\n", NdfcVersion);
	    }
	}
	    

	NDFC_WRITE_REG_ST( NDFC_READ_REG_ST() & NDFC_DMA_INT_FLAG);

	for (i=0; i<buf_cnt; i++)
	{
		NAND_DMASingleUnmap(rw, nand_dma_addr[NandIndex][i], buf_size[i]);
	}

	return 0;
}

__s32 _reset(void)
{
	__u32 cfg;

	__s32 timeout = 0xffff;

	PHY_ERR("Reset NDFC %d\n", NandIndex);

	/*reset NFC*/
	cfg = NDFC_READ_REG_CTL();
	cfg |= NDFC_RESET;
	NDFC_WRITE_REG_CTL(cfg);
	//waiting reset operation end
	while((timeout--) && (NDFC_READ_REG_CTL()&NDFC_RESET));
	if (timeout <= 0)
	{
	    PHY_ERR("nand _reset time out, status:0x%x\n", NDFC_READ_REG_ST());
		return -ERR_TIMEOUT;
    }
	return 0;
}

/***************ecc function*****************************************/
__s32 _check_ecc(__u32 eblock_cnt)
{
	__u32 i;
	__u32 ecc_mode;
	__u32 max_ecc_bit_cnt = 16;
	__u32 cfg;
	__u32 ecc_cnt_w[8];//ecc_cnt_w[4];
	__u8 *ecc_cnt;
//	__u8 ecc_tab[12] = {16, 24, 28, 32, 40, 48, 56, 60, 64};
	__u8 ecc_limit_tab[12] = {13, 20, 23, 27, 35, 42, 50, 54, 57, 64};
	__u32 ecc_limit;

	ecc_mode = (NDFC_READ_REG_ECC_CTL()>>12)&0xf;
//	max_ecc_bit_cnt = ecc_tab[ecc_mode];
//	ecc_limit = max_ecc_bit_cnt*8/10;
	ecc_limit = ecc_limit_tab[ecc_mode];

	//check ecc errro
	if (NdfcVersion == NDFC_VERSION_V1)
		cfg = NDFC_READ_REG_ECC_ST()&0xffff;
	else if (NdfcVersion == NDFC_VERSION_V2)
		cfg = NDFC_READ_REG_ERR_ST();
	else {
		PHY_ERR("_check_ecc: wrong ndfc version, %d\n", NdfcVersion);
		cfg = 0;
	}
	for (i = 0; i < eblock_cnt; i++)
	{
		if (cfg & (1<<i))
			return -ERR_ECC;
	}

    //check ecc limit
    ecc_cnt_w[0]= NDFC_READ_REG_ECC_CNT0();
    ecc_cnt_w[1]= NDFC_READ_REG_ECC_CNT1();
    ecc_cnt_w[2]= NDFC_READ_REG_ECC_CNT2();
    ecc_cnt_w[3]= NDFC_READ_REG_ECC_CNT3();
    if (NdfcVersion == NDFC_VERSION_V2) {
		ecc_cnt_w[4]= NDFC_READ_REG_ECC_CNT4();
		ecc_cnt_w[5]= NDFC_READ_REG_ECC_CNT5();
		ecc_cnt_w[6]= NDFC_READ_REG_ECC_CNT6();
		ecc_cnt_w[7]= NDFC_READ_REG_ECC_CNT7();
    }

    ecc_cnt = (__u8 *)((__u32)(ecc_cnt_w));
	for (i = 0; i < eblock_cnt; i++)
	{
		if((ecc_limit) <= ecc_cnt[i])
			return ECC_LIMIT;
	}

	return 0;
}

void _disable_ecc(void)
{
	__u32 cfg = NDFC_READ_REG_ECC_CTL();
	cfg &= ( (~NDFC_ECC_EN)&0xffffffff );
	NDFC_WRITE_REG_ECC_CTL(cfg);
}

void _enable_ecc(__u32 pipline)
{
	__u32 cfg = NDFC_READ_REG_ECC_CTL();
	if (pipline == 1)
		cfg |= NDFC_ECC_PIPELINE;
	else
		cfg &= ((~NDFC_ECC_PIPELINE)&0xffffffff);


	/*after erased, all data is 0xff, but ecc is not 0xff,
			so ecc asume it is right*/
	//if random open, disable exception
	if(cfg&(0x1<<9))
	    cfg &= (~(0x1<<4));
	else
	    cfg |= (1 << 4);

	//cfg |= (1 << 1); 16 bit ecc

	cfg |= NDFC_ECC_EN;
	NDFC_WRITE_REG_ECC_CTL(cfg);
}

__s32 _enter_nand_critical(void)
{
	return 0;
}

__s32 _exit_nand_critical(void)
{
	return 0;
}

void _set_addr(__u8 *addr, __u8 cnt)
{
	__u32 i;
	__u32 addr_low = 0;
	__u32 addr_high = 0;

	for (i = 0; i < cnt; i++) {
		if (i < 4)
			addr_low |= (addr[i] << (i*8) );
		else
			addr_high |= (addr[i] << ((i - 4)*8));
	}

	NDFC_WRITE_REG_ADDR_LOW(addr_low);
	NDFC_WRITE_REG_ADDR_HIGH(addr_high);
}

__s32 _read_in_page_mode(NFC_CMD_LIST *rcmd,void *mainbuf,void *sparebuf,__u8 dma_wait_mode)
{
	__s32 ret;
	__s32 i;
	__u32 cfg;
	NFC_CMD_LIST *cur_cmd,*read_addr_cmd;
	__u32 read_data_cmd,random_read_cmd0,random_read_cmd1;
	__u32 blk_cnt, blk_mask;

	ret = 0;
	read_addr_cmd = rcmd;
	cur_cmd = rcmd;
	cur_cmd = cur_cmd->next;
	random_read_cmd0 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	random_read_cmd1 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	read_data_cmd = cur_cmd->value;

	//access NFC internal RAM by DMA bus
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() | NDFC_RAM_METHOD);

	/*set dma and run*/
	_dma_config_start(0, (__u32)mainbuf, pagesize);

	/*wait cmd fifo free*/
	ret = _wait_cmdfifo_free();
	if (ret)
		return ret;

	/*set NFC_REG_CNT*/
	NDFC_WRITE_REG_CNT(1024);

	/*set NFC_REG_RCMD_SET*/
	cfg = 0;
	cfg |= (read_data_cmd & 0xff);
	cfg |= ((random_read_cmd0 & 0xff) << 8);
	cfg |= ((random_read_cmd1 & 0xff) << 16);
	NDFC_WRITE_REG_RCMD_SET(cfg);

	if (NdfcVersion == NDFC_VERSION_V1) {
		/*set NDFC_REG_SECTOR_NUM*/
		NDFC_WRITE_REG_SECTOR_NUM(pagesize/1024);
	} else if (NdfcVersion == NDFC_VERSION_V2) {
		/*set NFC_REG_BLOCK_MASK*/
		blk_cnt = pagesize/1024;
		blk_mask = ((1<<(blk_cnt - 1)) | ((1<<(blk_cnt - 1)) - 1));
		NDFC_WRITE_REG_BLOCK_MASK(blk_mask);
	} else
		PHY_ERR("_read_in_page_mode: wrong ndfc version, %d\n", NdfcVersion);

	/*set addr*/
	_set_addr(read_addr_cmd->addr,read_addr_cmd->addr_cycle);

	/*Gavin-20130619, clear user data*/
	for (i=0; i<16; i++)
		NDFC_WRITE_REG_USER_DATA((i), 0x99999999);

	/*set NFC_REG_CMD*/
	cfg  = 0;
	cfg |= read_addr_cmd->value;
	/*set sequence mode*/
	//cfg |= 0x1<<25;
	cfg |= ( (read_addr_cmd->addr_cycle - 1) << 16);
	cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_SEND_CMD2 | NDFC_WAIT_FLAG | NDFC_DATA_SWAP_METHOD);
	cfg |= ((__u32)0x2 << 30);//page command

	if (pagesize/1024 == 1)
		cfg |= NDFC_SEQ;

	/*enable ecc*/
	_enable_ecc(1);
	NDFC_WRITE_REG_CMD(cfg);
#if 1
    NAND_WaitDmaFinish();
    ret = _wait_dma_end(0, (__u32)mainbuf, pagesize);
	if (ret)
		return ret;

	/*wait cmd fifo free and cmd finish*/
	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if (ret){
		_disable_ecc();
		return ret;
	}
	/*get user data*/
//	if (pagesize < 4096) {
//		PHY_ERR("%s: wrong page size: %d\n", __func__, pagesize);
//	}
	for (i = 0; i < pagesize/1024;  i++){
		*(((__u32*) sparebuf)+i) = NDFC_READ_REG_USER_DATA((i));
	}

	/*ecc check and disable ecc*/
	ret = _check_ecc(pagesize/1024);
	_disable_ecc();
#endif
	return ret;
}

__s32 _read_in_page_mode_first(NFC_CMD_LIST  *rcmd,void *mainbuf,void *sparebuf,__u8 dma_wait_mode)
{
	__s32 ret;
	__u32 cfg;
	NFC_CMD_LIST *cur_cmd,*read_addr_cmd;
	__u32 read_data_cmd,random_read_cmd0,random_read_cmd1;
	__u32 blk_cnt, blk_mask;
	__s32 i;

	ret = 0;
	read_addr_cmd = rcmd;
	cur_cmd = rcmd;
	cur_cmd = cur_cmd->next;
	random_read_cmd0 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	random_read_cmd1 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	read_data_cmd = cur_cmd->value;

	//access NFC internal RAM by DMA bus
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() | NDFC_RAM_METHOD);

	/*set dma and run*/
	_dma_config_start(0, (__u32)mainbuf, pagesize);

	/*wait cmd fifo free*/
	ret = _wait_cmdfifo_free();
	if (ret)
		return ret;

	/*set NFC_REG_CNT*/
	NDFC_WRITE_REG_CNT(1024);

	/*set NFC_REG_RCMD_SET*/
	cfg = 0;
	cfg |= (read_data_cmd & 0xff);
	cfg |= ((random_read_cmd0 & 0xff) << 8);
	cfg |= ((random_read_cmd1 & 0xff) << 16);
	NDFC_WRITE_REG_RCMD_SET(cfg);

	if (NdfcVersion == NDFC_VERSION_V1) {
		/*set NDFC_REG_SECTOR_NUM*/
		NDFC_WRITE_REG_SECTOR_NUM(pagesize/1024);
	} else if (NdfcVersion == NDFC_VERSION_V2) {
		/*set NFC_REG_BLOCK_MASK*/
		blk_cnt = pagesize/1024;
		blk_mask = ((1<<(blk_cnt - 1)) | ((1<<(blk_cnt - 1)) - 1));
		NDFC_WRITE_REG_BLOCK_MASK(blk_mask);
	} else
		PHY_ERR("_read_in_page_mode_first: wrong ndfc version, %d\n", NdfcVersion);

	/*set addr*/
	_set_addr(read_addr_cmd->addr,read_addr_cmd->addr_cycle);

	/*Gavin-20130619, clear user data*/
	for (i=0; i<16; i++)
		NDFC_WRITE_REG_USER_DATA((i), 0x99999999);

	/*set NFC_REG_CMD*/
	cfg  = 0;
	cfg |= read_addr_cmd->value;
	/*set sequence mode*/
	//cfg |= 0x1<<25;
	cfg |= ( (read_addr_cmd->addr_cycle - 1) << 16);
	cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_SEND_CMD2 | NDFC_WAIT_FLAG | NDFC_DATA_SWAP_METHOD);
	cfg |= ((__u32)0x2 << 30);//page command

	if (pagesize/1024 == 1)
		cfg |= NDFC_SEQ;

	/*enable ecc*/
	_enable_ecc(1);
	NDFC_WRITE_REG_CMD(cfg);
#if 0
    NAND_WaitDmaFinish();
    ret = _wait_dma_end(0, (__u32)mainbuf, pagesize);
	if (ret)
		return ret;

	/*wait cmd fifo free and cmd finish*/
	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if (ret){
		_disable_ecc();
		return ret;
	}
	/*get user data*/
	for (i = 0; i < pagesize/1024;  i++){
		*(((__u32*) sparebuf)+i) = NDFC_READ_REG_USER_DATA(i);
	}

	/*ecc check and disable ecc*/
	ret = _check_ecc(pagesize/1024);
	_disable_ecc();
#endif
	return ret;
}


__s32 _read_in_page_mode_wait(NFC_CMD_LIST  *rcmd,void *mainbuf,void *sparebuf,__u8 dma_wait_mode)
{
	__s32 ret;
	__s32 i;

	NAND_WaitDmaFinish();
    ret = _wait_dma_end(0, (__u32)mainbuf, pagesize);
	if (ret)
		return ret;

	/*wait cmd fifo free and cmd finish*/
	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if (ret){
		_disable_ecc();
		return ret;
	}
	/*get user data*/
	/*if (pagesize < 4096) {
		PHY_ERR("%s(): wrong page size: %d\n", __func__, pagesize);
	}*/
	for (i = 0; i < pagesize/1024;  i++){
		*(((__u32*) sparebuf)+i) = NDFC_READ_REG_USER_DATA(i);
	}

	/*ecc check and disable ecc*/
	ret = _check_ecc(pagesize/1024);
	_disable_ecc();

	return ret;
}

__u32 _cal_first_valid_bit(__u32 secbitmap)
{
	__u32 firstbit = 0;

	while(!(secbitmap & 0x1))
	{
		secbitmap >>= 1;
		firstbit++;
	}

	return firstbit;
}

__u32 _cal_valid_bits(__u32 secbitmap)
{
	__u32 validbit = 0;

	while(secbitmap)
	{
		if(secbitmap & 0x1)
			validbit++;
		secbitmap >>= 1;
	}

	return validbit;
}

__u32 _check_continuous_bits(__u32 secbitmap)
{
	__u32 ret = 1; //1: bitmap is continuous, 0: bitmap is not continuous
	__u32 first_valid_bit = 0;
	__u32 flag = 0;

	while (secbitmap)
	{
		if (secbitmap & 0x1)
		{
			if (first_valid_bit == 0)
				first_valid_bit = 1;

			if (first_valid_bit && flag)
			{
				ret = 0;
				break;
			}
		}
		else
		{
			if (first_valid_bit == 1)
				flag = 1;
		}
		secbitmap >>= 1;
	}

	return ret;
}

__s32 _check_secbitmap_bit(__u32 secbitmap, __u32 firstbit, __u32 validbit)
{
	__u32 i = 0;

    for(i=firstbit; i<firstbit+validbit; i++)
    {
        if(!(secbitmap&(0x1<<i)))
        {
            PHY_ERR("secbitmap 0x%x not seq!\n", secbitmap);
            return -1;
            //while(1);
        }
    }

	return 0;
}

__s32 _read_secs_in_page_mode(NFC_CMD_LIST  *rcmd,void *mainbuf, void *cachebuf, void *sparebuf, __u32 secbitmap)
{
	__s32 ret,ret1, ecc_flag = 0;
	__s32 i, j, k;
	__u32 cfg;
	NFC_CMD_LIST *cur_cmd; //, *read_addr_cmd;
	__u32 random_read_cmd0,random_read_cmd1; //read_data_cmd,
	__u32 eccblkstart, eccblkcnt, eccblksecmap;
	__u32 spareoffsetbak;
	__u8  spairsizetab[9] = {32, 46, 54, 60, 74, 88, 102, 110, 116};
	__u32 ecc_mode, spare_size;
	__u8  addr[2] = {0, 0};
	__u32 col_addr;
	__u32 eccblk_zone_list[4][3]={{0}, {0},{0},{0}}; //[0]: starteccblk; [1]: eccblkcnt; [2]: secbitmap;
	__u32 eccblk_zone_cnt = 0;
	__u32 firstbit, validbit;
	//__u32 dma_buf;
	__u32 *oobbuf = NULL;
	__u32 blk_cnt, blk_mask;

	if(sparebuf)
	{
	    oobbuf = (__u32 *)sparebuf;
	    oobbuf[0] = 0x12345678;
	    oobbuf[1] = 0x12345678;
	}

	firstbit = _cal_first_valid_bit(secbitmap);
	validbit = _cal_valid_bits(secbitmap);

	ecc_mode = (NDFC_READ_REG_CTL()>>12)&0xf;
	spare_size = spairsizetab[ecc_mode];


	/*set NFC_REG_CNT*/
	NDFC_WRITE_REG_CNT(1024);


	//read_addr_cmd = rcmd;
	cur_cmd = rcmd;
	random_read_cmd0 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	random_read_cmd1 = cur_cmd->value;

	/*set NFC_REG_RCMD_SET*/
	cfg = 0;
	cfg |= (random_read_cmd1 & 0xff);
	cfg |= ((random_read_cmd0 & 0xff) << 8);
	cfg |= ((random_read_cmd1 & 0xff) << 16);
	NDFC_WRITE_REG_RCMD_SET(cfg);

	//access NFC internal RAM by DMA bus
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() | NDFC_RAM_METHOD);

	if(firstbit%2) //head part
	{
		eccblk_zone_cnt = 0;
		eccblk_zone_list[eccblk_zone_cnt][0] = firstbit/2;
		eccblk_zone_list[eccblk_zone_cnt][1] = 1;
		eccblk_zone_list[eccblk_zone_cnt][2] = 0x2;

		//updata value
		firstbit += 1;
		validbit -= 1;
		eccblk_zone_cnt ++;
	}

	if(validbit/2) //alingn part
	{
		eccblk_zone_list[eccblk_zone_cnt][0] = firstbit/2;
		eccblk_zone_list[eccblk_zone_cnt][1] = validbit/2;
		eccblk_zone_list[eccblk_zone_cnt][2] = 0xffffffff;

		//updata value
		firstbit += 2*eccblk_zone_list[eccblk_zone_cnt][1];
		validbit -= 2*eccblk_zone_list[eccblk_zone_cnt][1];
		eccblk_zone_cnt ++;

	}

	if(validbit>0)  //tail part
	{
		eccblk_zone_list[eccblk_zone_cnt][0] = firstbit/2;
		eccblk_zone_list[eccblk_zone_cnt][1] = 1;
		eccblk_zone_list[eccblk_zone_cnt][2] = 0x1;
		eccblk_zone_cnt ++;

	}

	//for read user data
	if((sparebuf)&&(eccblk_zone_cnt==1)&&(eccblk_zone_list[0][1]==1))
	{
		eccblk_zone_list[0][1]=2;
		eccblk_zone_list[0][2]=0x3;

	}

#if 0
	{
		PHY_DBG("read sectors: bitmap: 0x%x, mainbuf: 0x%x, sparebuf: 0x%x\n", secbitmap, mainbuf, sparebuf);
		for(j=0;j<eccblk_zone_cnt; j++)
		{
			PHY_DBG("  %d, eccblkstart: %d, eccblkcnt: %d \n", j, eccblk_zone_list[j][0], eccblk_zone_list[j][1], eccblk_zone_list[j][2]);
			PHY_DBG("     eccblkmap: 0x%x,\n", eccblk_zone_list[j][2]);
		}
	}
#endif

	for(j=0;j<eccblk_zone_cnt;j++)
	{
		eccblkstart = eccblk_zone_list[j][0];
		eccblkcnt = eccblk_zone_list[j][1];
		eccblksecmap = eccblk_zone_list[j][2];

		//PRINT(" start read %d, eccblkstart: 0x%x, eccblkcnt: 0x%x\n", j, eccblkstart, eccblkcnt);
		//PRINT("     eccblksecmap: 0x%x\n", eccblksecmap);

		//NK page mode
		if((eccblkstart==0)&&(eccblksecmap == 0xffffffff))
		{
		    //PRINT(" NK mode\n");
			ret = 0;
			ret1 = 0;

			spareoffsetbak = NDFC_READ_REG_SPARE_AREA();
			NDFC_WRITE_REG_SPARE_AREA(pagesize + spare_size*eccblkstart);
			col_addr = 1024*eccblkstart;
			addr[0] = col_addr&0xff;
			addr[1] = (col_addr>>8)&0xff;

			/*set dma and run*/
			_dma_config_start(0, (__u32)mainbuf + eccblkstart*1024, eccblkcnt*1024);
			//PRINT("  dmabuf: 0x%x, dmacnt: 0x%x\n", (__u32)mainbuf + eccblkstart*1024, eccblkcnt*1024);

			/*wait cmd fifo free*/
			ret = _wait_cmdfifo_free();
			if (ret)
			{
			    PHY_ERR(" _read_secs_in_page_mode error, NK mode, cmdfifo full \n");
				while(1);
				return ret;
            }

			if (NdfcVersion == NDFC_VERSION_V1) {
				/*set NDFC_REG_SECTOR_NUM*/
				NDFC_WRITE_REG_SECTOR_NUM(pagesize/1024);
			} else if (NdfcVersion == NDFC_VERSION_V2) {
				/*set NFC_REG_BLOCK_MASK*/
				blk_cnt = pagesize/1024;
				blk_mask = ((1<<(blk_cnt - 1)) | ((1<<(blk_cnt - 1)) - 1));
				NDFC_WRITE_REG_BLOCK_MASK(blk_mask);
			} else
				PHY_ERR("_read_in_page_mode_first: wrong ndfc version, %d\n", NdfcVersion);

			/*set addr*/
			_set_addr(addr,2);

			/*set NFC_REG_CMD*/
			cfg  = 0;
			cfg |= random_read_cmd0;
			/*set sequence mode*/
			//cfg |= 0x1<<25;
			cfg |= ( (rcmd->addr_cycle - 1) << 16);
			cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_SEND_CMD2 | NDFC_WAIT_FLAG | NDFC_DATA_SWAP_METHOD);
			cfg |= ((__u32)0x2 << 30);//page command

			/*enable ecc*/
			_enable_ecc(1);
			NDFC_WRITE_REG_CMD(cfg);

			NAND_WaitDmaFinish();
			/*if dma mode is wait*/
			if(1){
				ret1 = _wait_dma_end(0, (__u32)mainbuf + eccblkstart*1024, eccblkcnt*1024);
				if (ret1)
				{
				    PHY_ERR(" _read_secs_in_page_mode error, NK mode, dma not finish \n");
				    while(1);
					return ret1;
				}
			}

			/*wait cmd fifo free and cmd finish*/
			ret = _wait_cmdfifo_free();
			ret |= _wait_cmd_finish();
			if (ret){
				_disable_ecc();
				NDFC_WRITE_REG_SPARE_AREA(spareoffsetbak);
				//PRINT(" _read_secs_in_page_mode error, NK mode, cmd not finish \n");
				while(1);
				return ret;
			}
			/*get user data*/
			if(sparebuf)
			{
			    for (i = 0; i < eccblkcnt;  i++){
			        if(oobbuf[i%2] == 0x12345678)
			            oobbuf[i%2] = NDFC_READ_REG_USER_DATA((i));
    			}
			}


			/*ecc check and disable ecc*/
			ret = _check_ecc(eccblkcnt);
			ecc_flag |= ret;
			_disable_ecc();
			NDFC_WRITE_REG_SPARE_AREA(spareoffsetbak);


		}
		else  //1K page mode
		{
		    //PRINT(" 1K mode\n");
			for(k=0;k<eccblkcnt;k++)
			{
			    //PRINT("k= %d\n", k);
			    //PRINT("eccblk_index: %d\n", eccblkstart+k);
				ret = 0;
				ret1 = 0;

				spareoffsetbak = NDFC_READ_REG_SPARE_AREA();
				NDFC_WRITE_REG_SPARE_AREA(pagesize + spare_size*(eccblkstart+k));
				col_addr = 1024*(eccblkstart+k);
				addr[0] = col_addr&0xff;
				addr[1] = (col_addr>>8)&0xff;

				/*set dma and run*/
				if((eccblksecmap==0xffffffff)||((eccblksecmap>>k*2) == 0x3))
				{
					_dma_config_start(0, (__u32)mainbuf + 1024*(eccblkstart+k), 1024);
					//PRINT("  dmabuf: 0x%x, dmacnt: 0x%x\n", (__u32)mainbuf + 1024*(eccblkstart+k), 1024);
				}
				else
				{
					_dma_config_start(0, (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
					//PRINT("  dmabuf: 0x%x, dmacnt: 0x%x\n", (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
	                	}

				/*wait cmd fifo free*/
				ret = _wait_cmdfifo_free();
				if (ret)
				{
				    PHY_ERR(" _read_secs_in_page_mode error, 1K mode, cmdfifo full \n");
				    while(1);
					return ret;
				}
				if (NdfcVersion == NDFC_VERSION_V1) {
					/*set NDFC_REG_SECTOR_NUM*/
					NDFC_WRITE_REG_SECTOR_NUM(pagesize/1024);
				} else if (NdfcVersion == NDFC_VERSION_V2) {
					/*set NFC_REG_BLOCK_MASK*/
					blk_cnt = pagesize/1024;
					blk_mask = ((1<<(blk_cnt - 1)) | ((1<<(blk_cnt - 1)) - 1));
					NDFC_WRITE_REG_BLOCK_MASK(blk_mask);
				} else
					PHY_ERR("_read_in_page_mode_first: wrong ndfc version, %d\n", NdfcVersion);

				/*set addr*/
				_set_addr(addr,2);

				/*set NFC_REG_CMD*/
				cfg  = 0;
				cfg |= random_read_cmd0;
				/*set sequence mode*/
				//cfg |= 0x1<<25;
				cfg |= ( (rcmd->addr_cycle - 1) << 16);
				cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_SEND_CMD2 | NDFC_WAIT_FLAG | NDFC_DATA_SWAP_METHOD);
				cfg |= ((__u32)0x2 << 30);//page command

				/*enable ecc*/
				_enable_ecc(1);
				NDFC_WRITE_REG_CMD(cfg);

				/* don't user dma int in  1K mode */
				//NAND_WaitDmaFinish();
				/*if dma mode is wait*/
				if(1){
					if((eccblksecmap==0xffffffff)||((eccblksecmap>>k*2) == 0x3))
					{
						ret1 |= _wait_dma_end(0, (__u32)mainbuf + 1024*(eccblkstart+k), 1024);
						//PRINT("  dmabuf: 0x%x, dmacnt: 0x%x\n", (__u32)mainbuf + 1024*(eccblkstart+k), 1024);
					}
					else
					{
						ret1 |= _wait_dma_end(0, (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
						//PRINT("  dmabuf: 0x%x, dmacnt: 0x%x\n", (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
		                	}

					if (ret1)
					{
					    PHY_ERR(" _read_secs_in_page_mode error, 1K mode, dma not finish \n");
				        while(1);
						return ret1;
					}
				}

				/*wait cmd fifo free and cmd finish*/
				ret = _wait_cmdfifo_free();
				ret |= _wait_cmd_finish();
				if (ret){
					_disable_ecc();
					NDFC_WRITE_REG_SPARE_AREA(spareoffsetbak);
			        PHY_ERR(" _read_secs_in_page_mode error, 1K mode, cmd not finish \n");
				    while(1);
					return ret;
				}
				/*get user data*/
				if(sparebuf)
	        		{
	    		        if(oobbuf[(eccblkstart+k)%2] == 0x12345678)
	    		            oobbuf[(eccblkstart+k)%2] = NDFC_READ_REG_USER_DATA((0));
	        		}

				/*ecc check and disable ecc*/
				ret = _check_ecc(1);
				ecc_flag |= ret;
				_disable_ecc();
				NDFC_WRITE_REG_SPARE_AREA(spareoffsetbak);


				//copy main data
				if(!((eccblksecmap==0xffffffff)||((eccblksecmap>>k*2) == 0x3)))
				{
					if((eccblksecmap>>k*2)==0x1)
					    MEMCPY((__u8 *)mainbuf + 1024*(eccblkstart+k), (__u8 *)cachebuf + 1024*(eccblkstart+k), 512);
					else if((eccblksecmap>>k*2)==0x2)
						MEMCPY((__u8 *)mainbuf + 1024*(eccblkstart+k)+512, (__u8 *)cachebuf + 1024*(eccblkstart+k)+512, 512);
					//else if((eccblksecmap>>k*2)==0x3)
					//    MEMCPY((__u32)mainbuf + 1024*(eccblkstart+k), (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
				}
				//else
				//    MEMCPY((__u32)mainbuf + 1024*(eccblkstart+k), (__u32)cachebuf + 1024*(eccblkstart+k), 1024);
			}
		}
	}

	NDFC_WRITE_REG_RCMD_SET(0x003005e0);

	return ecc_flag;
}


__s32 _read_eccblks_in_page_mode(NFC_CMD_LIST *rcmd, void *sparebuf, __u32 eccblkmask, __u32 dst_buf_cnt,
										__u32 dst_buf_addr[], __u32 dst_buf_size[])
{
	__s32 ret;
	__s32 i;
	__u32 cfg;
	NFC_CMD_LIST *cur_cmd,*read_addr_cmd;
	__u32 read_data_cmd,random_read_cmd0,random_read_cmd1;
	//__u32 blk_cnt, blk_mask;

	ret = 0;
	read_addr_cmd = rcmd;
	cur_cmd = rcmd;
	cur_cmd = cur_cmd->next;
	random_read_cmd0 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	random_read_cmd1 = cur_cmd->value;
	cur_cmd = cur_cmd->next;
	read_data_cmd = cur_cmd->value;

	//access NFC internal RAM by DMA bus
	NDFC_WRITE_REG_CTL((NDFC_READ_REG_CTL()) | NDFC_RAM_METHOD);

	/*set dma and run*/
	//_dma_config_start(0, (__u32)mainbuf, pagesize);
	_dma_config_start_v2(0, dst_buf_cnt, dst_buf_addr, dst_buf_size);

	/*wait cmd fifo free*/
	ret = _wait_cmdfifo_free();
	if (ret)
		return ret;

	/*set NFC_REG_CNT*/
	NDFC_WRITE_REG_CNT(1024);

	/*set NFC_REG_RCMD_SET*/
	cfg = 0;
	cfg |= (read_data_cmd & 0xff);
	cfg |= ((random_read_cmd0 & 0xff) << 8);
	cfg |= ((random_read_cmd1 & 0xff) << 16);
	NDFC_WRITE_REG_RCMD_SET(cfg);

	/*set NFC_REG_BLOCK_MASK*/
	//blk_cnt = pagesize/1024;
	//blk_mask = ((1<<(blk_cnt - 1)) | ((1<<(blk_cnt - 1)) - 1));
	//NFC_WRITE_REG(NFC_REG_BLOCK_MASK, blk_mask);
	NDFC_WRITE_REG_BLOCK_MASK(eccblkmask);

	/*set addr*/
	_set_addr(read_addr_cmd->addr,read_addr_cmd->addr_cycle);

	/*Gavin-20130619, clear user data*/
	for (i=0; i<16; i++)
		NDFC_WRITE_REG_USER_DATA((i), 0x88888888);

	/*set NFC_REG_CMD*/
	cfg  = 0;
	cfg |= read_addr_cmd->value;
	/*set sequence mode*/
	//cfg |= 0x1<<25;
	cfg |= ( (read_addr_cmd->addr_cycle - 1) << 16);
	cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_SEND_CMD2 | NDFC_WAIT_FLAG | NDFC_DATA_SWAP_METHOD);
	cfg |= ((__u32)0x2 << 30);//page command

	if (pagesize/1024 == 1)
		cfg |= NDFC_SEQ;

	/*enable ecc*/
	_enable_ecc(1);
	NDFC_WRITE_REG_CMD(cfg);
#if 1
    NAND_WaitDmaFinish();
    //ret = _wait_dma_end(0, (__u32)mainbuf, pagesize);
    ret = _wait_dma_end_v2(0, dst_buf_cnt, dst_buf_addr, dst_buf_size);
	if (ret)
		return ret;

	/*wait cmd fifo free and cmd finish*/
	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if (ret){
		_disable_ecc();
		return ret;
	}
	/*get user data*/
	//if (pagesize < 4096) {
	//	PHY_ERR("%s: wrong page size: %d\n", __func__, pagesize);
	//}
	for (i = 0; i < pagesize/1024;  i++){
		*(((__u32*) sparebuf)+i) = NDFC_READ_REG_USER_DATA((i));
	}

	/*ecc check and disable ecc*/
	ret = _check_ecc(pagesize/1024);
	_disable_ecc();
#endif
	return ret;
}

__s32 _read_secs_in_page_mode_v2(NFC_CMD_LIST  *rcmd, void *mainbuf, void *sparebuf, __u32 secbitmap)
{
	__s32 i, ret;
	__u32 *tmpsparebuf, *tmpbuf1, *tmpbuf3; //*tmpbuf2, 
	__u32 fir_sect;
	__u32 sect_cnt;
	__u32 last_sect;
	//u32 spare_buf[64];
	//u32 *main_buf = (u32 *)0xeee;
	__u32 ind, last_ind;
	__u32 pos, mask, bitcnt;
	__u32 dst_buf_cnt;
	__u32 dst_buf_size[4];
	__u32 dst_buf_addr[4];
	__u32 main_data_size;

	__u32 fir_spare_sect = 0; //first 4 ecc blk;
	__u32 spare_sect_cnt = 8;
	__u32 last_spare_sect = fir_spare_sect+spare_sect_cnt-1;
	__u32 spare_ecc_blk_cnt = (spare_sect_cnt/2);
	__u32 spare_ecc_blk_mask = (1U<<(spare_ecc_blk_cnt-1)) | ((1U<<(spare_ecc_blk_cnt-1)) - 1);

	__u32 total_size, goal_size;
	__u8 *psrc, *pdst;


	fir_sect = _cal_first_valid_bit(secbitmap);
	sect_cnt = _cal_valid_bits(secbitmap);
	if (_check_secbitmap_bit(secbitmap, fir_sect, sect_cnt))
	{
		PHY_ERR("sect bit map error: 0x%x\n", secbitmap);
		return -ERR_TIMEOUT;
	}
	last_sect = fir_sect + sect_cnt - 1;

	tmpsparebuf = (__u32 *)(PageCachePool.PageCache4);
	tmpbuf1 = (__u32 *)(PageCachePool.PageCache1);
	//tmpbuf2 = (__u32 *)(PageCachePool.PageCache2);
	tmpbuf3 = (__u32 *)(PageCachePool.PageCache3);

	main_data_size = sect_cnt*512;
	goal_size = main_data_size;

	/*
	**********************************************
	*  Allocate dma buffer according sector bitmap
	***********************************************
	*/
	if (last_sect <= last_spare_sect)
	{
		mask = spare_ecc_blk_mask;

		dst_buf_cnt = 0;
		ind = fir_sect;
		if (fir_sect%0x2)
		{
			pos = ind/2;
			//mask = (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * (pos+1);
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf1;

			ind++;
		}
		else if (fir_sect)
		{
			pos = ind/2;

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * pos;
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf1;
		}

		last_ind = last_sect;
		bitcnt = 0;
		while (ind < last_ind)
		{
			pos = ind/2;
			//mask |= (1U << pos);

			ind += 2;
			bitcnt++;
		}
		if (bitcnt)
		{
			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * bitcnt;
			if (fir_sect%0x2)
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf + 512;
			else
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf;
		}

		if ((last_sect%0x2) == 0)
		{
			pos = last_sect/2;
			//mask = (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * (spare_ecc_blk_cnt-pos); //(4-pos) -->
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf3;
		}
		else
		{
			pos = last_sect/2;
			if (pos < 3)
			{
				dst_buf_cnt++;
				dst_buf_size[dst_buf_cnt-1] = 1024 * (spare_ecc_blk_cnt-pos-1); //(4-pos-1)
				dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf3;
			}
		}

		//PHY_DBG("all sects are in spare data area: mask 0x%x\n", mask);
		total_size = 0;
		for (i=0; i<dst_buf_cnt; i++)
		{
			//PHY_DBG("buf %d: size 0x%x    addr 0x%x\n", i, dst_buf_size[i], dst_buf_addr[i]);
			total_size += dst_buf_size[i];
		}
		//PHY_DBG("total size: 0x%x    goal size: 0x%x\n", total_size, goal_size);
	}
	else if (fir_sect > last_spare_sect)
	{
		mask = spare_ecc_blk_mask;
		dst_buf_cnt = 1;
		dst_buf_size[dst_buf_cnt-1] = spare_ecc_blk_cnt * 1024;////4*1024 -->
		dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpsparebuf;


		ind = fir_sect;
		if (fir_sect%0x2)
		{
			pos = ind/2;
			mask |= (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024;
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf1;

			ind++;
		}


		last_ind = last_sect;
		bitcnt = 0;
		while(ind < last_ind)
		{
			pos = ind/2;
			mask |= (1U << pos);

			ind += 2;
			bitcnt++;
		}
		if (bitcnt)
		{
			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * bitcnt;
			if (fir_sect%0x2)
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf + 512;
			else
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf;
		}

		if ((last_sect%0x2) == 0)
		{
			pos = last_sect/2;
			mask |= (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024;
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf3;
		}

		//PHY_DBG("mask 0x%x\n", mask);
		total_size = 0;
		for (i=0; i<dst_buf_cnt; i++)
		{
			//PHY_DBG("buf %d: size 0x%x    addr 0x%x\n", i, dst_buf_size[i], dst_buf_addr[i]);
			total_size += dst_buf_size[i];
		}
		//PHY_DBG("total size: 0x%x    goal size: 0x%x\n", total_size, goal_size);
	}
	else //( (fir_sect<=last_spare_sect) && (last_sect>last_spare_sect))
	{
		mask = spare_ecc_blk_mask;

		dst_buf_cnt = 0;
		ind = fir_sect;
		if (fir_sect%0x2)
		{
			pos = ind/2;
			mask |= (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * (pos+1);
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf1;

			ind++;
		}
		else if (fir_sect)
		{
			pos = ind/2;

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * pos;
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf1;
		}

		last_ind = last_sect;
		bitcnt = 0;
		while(ind < last_ind)
		{
			pos = ind/2;
			mask |= (1U << pos);

			ind += 2;
			bitcnt++;
		}
		if (bitcnt)
		{
			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024 * bitcnt;
			if (fir_sect%0x2)
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf + 512;
			else
				dst_buf_addr[dst_buf_cnt-1] = (__u32)mainbuf;
		}

		if ((last_sect%0x2) == 0)
		{
			pos = last_sect/2;
			mask |= (1U << pos);

			dst_buf_cnt++;
			dst_buf_size[dst_buf_cnt-1] = 1024;
			dst_buf_addr[dst_buf_cnt-1] = (__u32)tmpbuf3;
		}

		//PHY_DBG("mask 0x%x\n", mask);
		total_size = 0;
		for (i=0; i<dst_buf_cnt; i++)
		{
			//PHY_DBG("buf %d: size 0x%x    addr 0x%x\n", i, dst_buf_size[i], dst_buf_addr[i]);
			total_size += dst_buf_size[i];
		}
		//PHY_DBG("total size: 0x%x    goal size: 0x%x\n", total_size, goal_size);
	}


	/*
	***********************************************
	*  read main data and spare data
	***********************************************
	*/

	{
		ret = _read_eccblks_in_page_mode(rcmd, sparebuf, mask, dst_buf_cnt, dst_buf_addr, dst_buf_size);
	}

	/*
	***********************************************
	*  do some memory copy according sector bitmap
	***********************************************
	*/
	//memcpy for main data
	if (fir_sect > last_spare_sect)
	{
		if (fir_sect%2)
		{
			psrc = (__u8 *)(dst_buf_addr[1] + dst_buf_size[1] - 512);
			pdst = (__u8 *)(mainbuf) ;
			for (i=0; i<512; i++)
				pdst[i] = psrc[i];
		}
	}
	else
	{
		if (fir_sect%2)
		{
			psrc = (__u8 *)(dst_buf_addr[0] + dst_buf_size[0] - 512);
			pdst = (__u8 *)(mainbuf) ;
			for (i=0; i<512; i++)
				pdst[i] = psrc[i];
		}
	}

	if ((last_sect%2) == 0)
	{
		psrc = (__u8 *)(dst_buf_addr[dst_buf_cnt-1]);
		pdst = (__u8 *)((__u32)mainbuf + main_data_size - 512);
		for (i=0; i<512; i++)
			pdst[i] = psrc[i];
	}

	return ret;
}


/*******************************************************************************
*								NFC_Read
*
* Description 	: read some sectors data from flash in single plane mode.
* Arguments	: *rcmd	-- the read command sequence list head.
*			  *mainbuf	-- point to data buffer address, 	it must be four bytes align.
*                     *sparebuf	-- point to spare buffer address.
*                     dma_wait_mode	-- how to deal when dma start, 0 = wait till dma finish,
							    1 = dma interrupt was set and now sleep till interrupt occurs.
*			  page_mode  -- 0 = normal command, 1 = page mode
* Returns		: 0 = success.
			  1 = success & ecc limit.
			  -1 = too much ecc err.
* Notes		:  if align page data required��page command mode is used., if the commands do
			   not fetch data��ecc is not neccesary.
********************************************************************************/
__s32 NFC_Read(NFC_CMD_LIST  *rcmd, void *mainbuf, void *sparebuf, __u8 dma_wait_mode,__u8 page_mode )
{

	__u32 ret ;

	_enter_nand_critical();

	ret = _read_in_page_mode(rcmd, mainbuf,sparebuf, dma_wait_mode);

	/*switch to ahb*/
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

	_exit_nand_critical();


	return ret;
}

__s32 NFC_Read_First(NFC_CMD_LIST  *rcmd, void *mainbuf, void *sparebuf, __u8 dma_wait_mode,__u8 page_mode )
{

	__s32 ret ;

	_enter_nand_critical();

	ret = _read_in_page_mode_first(rcmd, mainbuf,sparebuf, dma_wait_mode);

	/*switch to ahb*/
//	NFC_WRITE_REG(NFC_REG_CTL, (NFC_READ_REG(NFC_REG_CTL)) & (~NFC_RAM_METHOD));

//	_exit_nand_critical();


	return ret;
}


__s32 NFC_Read_Wait(NFC_CMD_LIST  *rcmd, void *mainbuf, void *sparebuf, __u8 dma_wait_mode,__u8 page_mode )
{

	__s32 ret ;

//	_enter_nand_critical();

	ret = _read_in_page_mode_wait(rcmd, mainbuf,sparebuf, dma_wait_mode);

	/*switch to ahb*/
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

	_exit_nand_critical();


	return ret;
}

__s32 NFC_ReadSecs(NFC_CMD_LIST  *rcmd, void *mainbuf,  void *cachebuf, void *sparebuf,__u32 secbitmap )
{

	__s32 ret ;

	_enter_nand_critical();

	PHY_ERR("[NAND ERROR] function --NFC_ReadSecs-- is called!\n");

	ret = _read_secs_in_page_mode(rcmd, mainbuf,cachebuf, sparebuf, secbitmap);

	/*switch to ahb*/
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

	_exit_nand_critical();


	return ret;
}

__s32 NFC_ReadSecs_v2(NFC_CMD_LIST  *rcmd, void *mainbuf, void *sparebuf, __u32 secbitmap)
{

	__s32 ret ;

	_enter_nand_critical();

	//PHY_ERR("%s is called...!\n", __func__);

	ret = _read_secs_in_page_mode_v2(rcmd, mainbuf, sparebuf, secbitmap);

	/*switch to ahb*/
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

	_exit_nand_critical();


	return ret;
}

/*finish the comand list */
__s32 nfc_set_cmd_register(NFC_CMD_LIST *cmd)
{
	__u32 cfg;
	__s32 ret;

	NFC_CMD_LIST *cur_cmd = cmd;
	while(cur_cmd != NULL){
		/*wait cmd fifo free*/
		ret = _wait_cmdfifo_free();
		if (ret)
			return ret;

		cfg = 0;
		/*set addr*/
		if (cur_cmd->addr_cycle){
			_set_addr(cur_cmd->addr,cur_cmd->addr_cycle);
			cfg |= ( (cur_cmd->addr_cycle - 1) << 16);
			cfg |= NDFC_SEND_ADR;
		}

		/*set NFC_REG_CMD*/
		/*set cmd value*/
		cfg |= cur_cmd->value;
		/*set sequence mode*/
		//cfg |= 0x1<<25;
		/*wait rb?*/
		if (cur_cmd->wait_rb_flag){
			cfg |= NDFC_WAIT_FLAG;
		}
		if (cur_cmd->data_fetch_flag){
			NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));
			cfg |= NDFC_DATA_TRANS;
			NDFC_WRITE_REG_CNT(cur_cmd->bytecnt);
		}
		/*send command*/
		cfg |= NDFC_SEND_CMD1;
		NDFC_WRITE_REG_CMD(cfg);
		cur_cmd = cur_cmd ->next;
	}
	return 0;
}

__s32 NFC_SetRandomSeed(__u32 random_seed)
{
	__u32 cfg;


	  cfg = NDFC_READ_REG_ECC_CTL();
	  cfg &= 0x0000ffff;
	  cfg |= (random_seed<<16);
	  NDFC_WRITE_REG_ECC_CTL(cfg);

	return 0;
}

__s32 NFC_RandomEnable(void)
{
	__u32 cfg;

	cfg = NDFC_READ_REG_ECC_CTL();
	cfg |= (0x1<<9);
	NDFC_WRITE_REG_ECC_CTL(cfg);

	return 0;
}

__s32 NFC_RandomDisable(void)
{
	__u32 cfg;

	cfg = NDFC_READ_REG_ECC_CTL();
	cfg &= (~(0x1<<9));
	NDFC_WRITE_REG_ECC_CTL(cfg);

	return 0;
}



/*******************************************************************************
*								NFC_GetId
*
* Description 	: get chip id.
* Arguments	: *idcmd	-- the get id command sequence list head.

* Returns		: 0 = success.
			  -1 = fail.
* Notes		:
********************************************************************************/
__s32 NFC_GetId(NFC_CMD_LIST  *idcmd ,__u8 *idbuf)
{
	__u32 i;
	__s32 ret;

	_enter_nand_critical();

    nfc_repeat_mode_enable();
	ret = nfc_set_cmd_register(idcmd);
	if (ret){
		_exit_nand_critical();
		return ret;
	}

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	/*get 5 bytes id value*/
	for (i = 0; i < 6; i++){
		*(idbuf + i) = NDFC_READ_RAM0_B(i);
	}

    nfc_repeat_mode_disable();

	_exit_nand_critical();
	return ret;
}

__s32 NFC_NormalCMD(NFC_CMD_LIST  *cmd_list)
{
	//__u32 i;
	__s32 ret;

	_enter_nand_critical();

    nfc_repeat_mode_enable();
	ret = nfc_set_cmd_register(cmd_list);
	if (ret){
		_exit_nand_critical();
		return ret;
	}

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

    nfc_repeat_mode_disable();

	_exit_nand_critical();
	return ret;
}



/*******************************************************************************
*								NFC_GetStatus
*
* Description 	: get status.
* Arguments	: *scmd	-- the get status command sequence list head.

* Returns		: status result
* Notes		: some cmd must be sent with addr.
********************************************************************************/
__s32 NFC_GetStatus(NFC_CMD_LIST  *scmd)
{
	__s32 ret;

	_enter_nand_critical();
	nfc_repeat_mode_enable();
	ret = nfc_set_cmd_register(scmd);
	if (ret){
		_exit_nand_critical();
		return ret;
	}

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if(ret){
		_exit_nand_critical();
		return ret;
	}

    nfc_repeat_mode_disable();
	_exit_nand_critical();
	return (NDFC_READ_RAM0_B(0));

}
/*******************************************************************************
*								NFC_ResetChip
*
* Description 	: reset nand flash.
* Arguments	: *reset_cmd	-- the reset command sequence list head.

* Returns		: sucess or fail
* Notes		:
********************************************************************************/
__s32 NFC_ResetChip(NFC_CMD_LIST *reset_cmd)

{
	__s32 ret;

	_enter_nand_critical();

	PHY_ERR("NFC_ResetChip: 0x%x, 0x%x 0x%x\n", NDFC_READ_REG_CTL(), NDFC_READ_REG_TIMING_CTL(), NDFC_READ_REG_TIMING_CFG());
	PHY_ERR("NFC_ResetChip: 0x%x, ch: %d\n", reset_cmd->value, NandIndex);

	ret = nfc_set_cmd_register(reset_cmd);
	if (ret){
		_exit_nand_critical();
		return ret;
	}
	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	_exit_nand_critical();
	return ret;
}

/*******************************************************************************
*								NFC_SetFeature
*
* Description 	: set feature.
* Arguments	: *set_feature_cmd	-- the set feature command sequence list head.

* Returns		: sucess or fail
* Notes		:
********************************************************************************/
__s32 NFC_SetFeature(NFC_CMD_LIST *set_feature_cmd, __u8 *feature)
{
	__s32 ret;
	__u32 cfg;

	_enter_nand_critical();
	nfc_repeat_mode_enable();

	/* access NFC internal RAM by AHB bus */
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

#if 0
	// nfc_set_cmd_register() don't support write data
	ret = nfc_set_cmd_register(set_feature_cmd);
	if (ret){
		_exit_nand_critical();
		return ret;
	}
#endif

	/* set data */
	NDFC_WRITE_RAM0_B(0, feature[0]);
	NDFC_WRITE_RAM0_B(1, feature[1]);
	NDFC_WRITE_RAM0_B(2, feature[2]);
	NDFC_WRITE_RAM0_B(3, feature[3]);
	NDFC_WRITE_REG_CNT(4);

	/*wait cmd fifo free*/
	ret = _wait_cmdfifo_free();
	if (ret)
		return ret;

	cfg = 0;
	/*set addr*/
	if (set_feature_cmd->addr_cycle){
		_set_addr(set_feature_cmd->addr,set_feature_cmd->addr_cycle);
		cfg |= ( (set_feature_cmd->addr_cycle - 1) << 16);
		cfg |= NDFC_SEND_ADR;
	}

	cfg |= NDFC_ACCESS_DIR | NDFC_WAIT_FLAG | NDFC_DATA_TRANS | NDFC_SEND_CMD1;
	cfg |= (set_feature_cmd->value & 0xff);

	/*set command io */
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if(ret){
		_exit_nand_critical();
		return ret;
	}

    nfc_repeat_mode_disable();
	_exit_nand_critical();
	return ret;
}

/*******************************************************************************
*								NFC_GetFeature
*
* Description 	: get feature.
* Arguments	: *reset_cmd	-- the get feature command sequence list head.

* Returns		: sucess or fail
* Notes		:
********************************************************************************/
__s32 NFC_GetFeature(NFC_CMD_LIST *get_feature_cmd, __u8 *feature)
{
	__s32 ret;
	__u32 cfg;

	_enter_nand_critical();
	nfc_repeat_mode_enable();

	/* access NFC internal RAM by AHB bus */
	NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL() & (~NDFC_RAM_METHOD));

	/* set data cnt*/
	NDFC_WRITE_REG_CNT(4);

	/*wait cmd fifo free*/
	ret = _wait_cmdfifo_free();
	if (ret)
		return ret;

	cfg = 0;
	/*set addr*/
	if (get_feature_cmd->addr_cycle){
		_set_addr(get_feature_cmd->addr,get_feature_cmd->addr_cycle);
		cfg |= ( (get_feature_cmd->addr_cycle - 1) << 16);
		cfg |= NDFC_SEND_ADR;
	}

	cfg |= NDFC_WAIT_FLAG | NDFC_DATA_TRANS | NDFC_SEND_CMD1; //NDFC_ACCESS_DIR
	cfg |= (get_feature_cmd->value & 0xff);

	/*set command io */
	NDFC_WRITE_REG_CMD(cfg);


	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();
	if(ret) {
		_exit_nand_critical();
		return ret;
	}

	/* get data */
	feature[0] = NDFC_READ_RAM0_B(0);
	feature[1] = NDFC_READ_RAM0_B(1);
	feature[2] = NDFC_READ_RAM0_B(2);
	feature[3] = NDFC_READ_RAM0_B(3);

    nfc_repeat_mode_disable();
	_exit_nand_critical();
	return 0;
}

/*******************************************************************************
*								NFC_SelectChip
*
* Description 	: enable chip ce.
* Arguments	: chip	-- chip no.

* Returns		: 0 = sucess -1 = fail
* Notes		:
********************************************************************************/
__s32 NFC_SelectChip( __u32 chip)
{
	__u32 cfg;


    cfg = NDFC_READ_REG_CTL();
    cfg &= ( (~NDFC_CE_SEL) & 0xffffffff);
    cfg |= ((chip & 0x7) << 24);
#if 0
    if(((read_retry_mode == 0)||(read_retry_mode == 1))&&(read_retry_cycle))
        cfg |= (0x1<<6);
#endif
    NDFC_WRITE_REG_CTL(cfg);

    if((cfg>>18)&0x3) //ddr nand
    {
        //set ddr param
        NDFC_WRITE_REG_TIMING_CTL(ddr_param[0]);
    }

	return 0;
}

/*******************************************************************************
*								NFC_SelectRb
*
* Description 	: select rb.
* Arguments	: rb	-- rb no.

* Returns		: 0 = sucess -1 = fail
* Notes		:
********************************************************************************/
__s32 NFC_SelectRb( __u32 rb)
{
	__s32 cfg;

	cfg = NDFC_READ_REG_CTL();
	cfg &= ( (~NDFC_RB_SEL) & 0xffffffff);
	cfg |= ((rb & 0x1) << 3);
	NDFC_WRITE_REG_CTL(cfg);

	return 0;
}

__s32 NFC_DeSelectChip( __u32 chip)
{
#if 0
    __u32 cfg;

    if(((read_retry_mode == 0)||(read_retry_mode == 1))&&(read_retry_cycle))
    {
        cfg = NDFC_READ_REG_CTL();
        cfg &= (~(0x1<<6));
        NDFC_WRITE_REG_CTL(cfg);
    }
#endif
	return 0;
}

__s32 NFC_DeSelectRb( __u32 rb)
{
	return 0;
}


/*******************************************************************************
*								NFC_CheckRbReady
*
* Description 	: check rb if ready.
* Arguments	: rb	-- rb no.

* Returns		: 0 = sucess -1 = fail
* Notes		:
********************************************************************************/
__s32 NFC_CheckRbReady( __u32 rb)
{
	__s32 ret;
	__u32 cfg = NDFC_READ_REG_ST();

	cfg &= (NDFC_RB_STATE0 << (rb & 0x3));
	if (cfg)
		ret = 0;
	else
		ret = -1;

	return ret;
}

/*******************************************************************************
*								NFC_ChangeMode
*
* Description 	: change serial access mode when clock change.
* Arguments	: nand_info -- structure with flash bus width,pagesize ,serial access mode and other configure parametre
*
* Returns		: 0 = sucess -1 = fail
* Notes		: NFC must be reset before seial access mode changes.
********************************************************************************/
__s32 NFC_ChangMode(NFC_INIT_INFO *nand_info)
{
	__u32 cfg;

	pagesize = nand_info->pagesize * 512;

	/*reset nfc*/
	_reset();

	/*set NFC_REG_CTL*/
	cfg = 0;
	cfg |= NDFC_EN;
	cfg |= ( (nand_info->bus_width & 0x1) << 2);
	cfg |= ( (nand_info->ce_ctl & 0x1) << 6);
	cfg |= ( (nand_info->ce_ctl1 & 0x1) << 7);
	if(nand_info->pagesize == 2 )            /*  1K  */
	   cfg |= ( 0x0 << 8 );
	else if(nand_info->pagesize == 4 )       /*  2K  */
	   cfg |= ( 0x1 << 8 );
	else if(nand_info->pagesize == 8 )       /*  4K  */
	   cfg |= ( 0x2 << 8 );
    else if(nand_info->pagesize == 16 )       /*  8K  */
	   cfg |= ( 0x3 << 8 );
	else if((nand_info->pagesize > 16 )&&(nand_info->pagesize < 32 ))       /*  12K  */
	   cfg |= ( 0x4 << 8 );
	else if(nand_info->pagesize == 32 )       /*  16K  */
	   cfg |= ( 0x4 << 8 );
	else                                      /* default 4K */
	   cfg |= ( 0x2 << 8 );
	//if (first_change)
	//	cfg |= ((nand_info->ddr_type & 0x3) << 18);   //set ddr type
	cfg |= ((nand_info->debug & 0x1) << 31);
	NDFC_WRITE_REG_CTL(cfg);

	/*set NFC_SPARE_AREA */
	NDFC_WRITE_REG_SPARE_AREA(pagesize);

	return 0;
}

void NFC_GetInterfaceMode(NFC_INIT_INFO *nand_info)
{
	__u32 cfg = 0;

	/* ddr type */
	cfg = NDFC_READ_REG_CTL();
	nand_info->ddr_type = (cfg>>18) & 0x3;
	if (NdfcVersion == NDFC_VERSION_V2)
		nand_info->ddr_type |= (((cfg>>28) & 0x1) <<4);

	/* edo && delay */
	cfg = NDFC_READ_REG_TIMING_CTL();
	nand_info->serial_access_mode = (cfg>>8) & 0x3;
	nand_info->ddr_edo            = (cfg>>8) & 0xf;
	nand_info->ddr_delay          = cfg & 0x3f;

	return ;
}

/*
* Arguments	: nand_info -- structure with flash bus width,pagesize ,serial access mode and other configure parametre
*
*/
void NFC_ChangeInterfaceMode(NFC_INIT_INFO *nand_info)
{
	__u32 cfg = 0;

	if (NdfcVersion == NDFC_VERSION_V1) {
		if ((nand_info->ddr_type == 0x12) || (nand_info->ddr_type == 0x13)) {
			PHY_ERR("NFC_ChangMode: current ndfc don't support ddr2 interface, %x -> 0x!\n",
				nand_info->ddr_type, nand_info->ddr_type&0x3);
			nand_info->ddr_type &= 0x3;
		}
	}

	/* ddr type */
	cfg = NDFC_READ_REG_CTL();
	cfg &= ~(0x3U<<18);
	if (NdfcVersion == NDFC_VERSION_V2)
		cfg &= ~(0x1<<28);
	cfg |= (nand_info->ddr_type&0x3)<<18;
	if (NdfcVersion == NDFC_VERSION_V2)
		cfg |= ((nand_info->ddr_type>>4)&0x1)<<28;
	NDFC_WRITE_REG_CTL(cfg);

	/* edo && delay */
	cfg = NDFC_READ_REG_TIMING_CTL();
	if (nand_info->ddr_type == 0) {
		cfg &= ~((0xf<<8) | 0x3f);
		cfg |= (nand_info->serial_access_mode<<8);
		NDFC_WRITE_REG_TIMING_CTL(cfg);
	} else {
		cfg &= ~((0xf<<8) | 0x3f);
		cfg |= (nand_info->ddr_edo <<8);
		cfg |= nand_info->ddr_delay;
		NDFC_WRITE_REG_TIMING_CTL(cfg);
	}
	
	/*
		 ndfc's timing cfg
		 1. default value: 0x95
		 2. bit-16, tCCS=1 for micron l85a, nvddr-100mhz
	 */
	NDFC_WRITE_REG_TIMING_CFG(0x10095);

	return ;
}

__s32 NFC_SetEccMode(__u8 ecc_mode)
{
    __u32 cfg = NDFC_READ_REG_ECC_CTL();

    cfg &= ((~NDFC_ECC_MODE)&0xffffffff);
    cfg |= (NDFC_ECC_MODE & (ecc_mode<<12));

	NDFC_WRITE_REG_ECC_CTL(cfg);

	return 0;
}

__s32 NFC_GetEccMode(void)
{
 	return ((NDFC_READ_REG_ECC_CTL()>>12) & 0xf);
}
/*******************************************************************************
*								NFC_Init
*
* Description 	: init hardware, set NFC, set TIMING, request dma .
* Arguments	: nand_info -- structure with flash bus width,pagesize ,serial access mode and other configure parametre

* Returns		: 0 = sucess -1 = fail
* Notes		: .
********************************************************************************/
__s32 NFC_Init(NFC_INIT_INFO *nand_info )
{
	__s32 ret;
    __s32 i;

	if(NandIndex == 0)
	{
		//PHY_DBG("[NAND] nand driver version: 0x%x, 0x%x 0x%x 14:00\n", NAND_VERSION_0, NAND_VERSION_1, NAND_DRV_DATE);
	}

    //init ddr_param
    for(i=0;i<8;i++)
        ddr_param[i] = 0x21f;

    NandIOBase[0] = (__u32)NAND_IORemap(NAND_IO_BASE_ADDR0, 4096);
    NandIOBase[1] = (__u32)NAND_IORemap(NAND_IO_BASE_ADDR1, 4096);

    if ( ndfc_init_version() )
    	return -1;
    
    if ( ndfc_init_dma_mode() )
    	return -1;

    //init pin
    NAND_PIORequest(NandIndex);

	//request general dma channel
	if (NdfcDmaMode == 0) {
		if( 0 != nand_request_dma() ) {
			PHY_ERR("request dma fail!\n");
			return -1;
		} else
			PHY_DBG("request general dma channel ok!\n");
	}
	
    //init clk
    NAND_ClkRequest(NandIndex);
    NAND_SetClk(NandIndex, 10, 10*2);

	if(NAND_GetVoltage())
		return -1;

    //init dma
	NFC_SetEccMode(0);

	/*init nand control machine*/
	ret = NFC_ChangMode( nand_info );
	NFC_ChangeInterfaceMode( nand_info );

	return ret;
}

/*******************************************************************************
*								NFC_Exit
*
* Description 	: free hardware resource, free dma , disable NFC.
* Arguments	: nand_info -- structure with flash bus width,pagesize ,serial access mode and other configure parametre

* Returns		: 0 = sucess -1 = fail
* Notes		: .
********************************************************************************/
void NFC_Exit( void )
{
	__u32 cfg;
	/*disable NFC*/
	cfg = NDFC_READ_REG_CTL();
	cfg &= ((~NDFC_EN) & 0xffffffff);
	NDFC_WRITE_REG_CTL(cfg);

	 //init clk
    NAND_ClkRelease(NandIndex);

	NAND_ReleaseDMA(NandIndex);

    //init pin
    NAND_PIORelease(NandIndex);

	NAND_ReleaseVoltage();
	
}

/*******************************************************************************
*								NFC_QueryINT
*
* Description 	: get nand interrupt info.
* Arguments	:
* Returns		: interrupt no. 0 = RB_B2R,1 = SINGLE_CMD_FINISH,2 = DMA_FINISH,
								5 = MULTI_CMD_FINISH
* Notes		:
********************************************************************************/
__s32 _vender_get_param(__u8 *para, __u8 *addr, __u32 count)
{
    __u32 i, cfg;
    __u32 cmd_r = 0;
    __s32 ret = 0;

    _enter_nand_critical();

    if (read_retry_mode <0x10) //hynix mode
    {
        cmd_r = 0x37;
    }
    else if((read_retry_mode >=0x10)&&(read_retry_mode <0x20)) //toshiba mode
    {
        _exit_nand_critical();
		return ret;
    }

    for (i=0; i<count; i++)
	{
		_set_addr(&addr[i], 1);

        //set data cnt
		NDFC_WRITE_REG_CNT(1);

		/*set NFC_REG_CMD*/
		cfg = cmd_r;
		cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 );
		NDFC_WRITE_REG_CMD(cfg);

		ret = _wait_cmdfifo_free();
		ret |= _wait_cmd_finish();

		if(ret)
		{
			_exit_nand_critical();
			return ret;
		}

		*(para+i) = NDFC_READ_RAM0_B(0);
	}

    _exit_nand_critical();
	return ret;
}

__s32 _vender_set_param(__u8 *para, __u8 *addr, __u32 count)
{
    __u32 i, cfg;
    __u32 cmd_w=0xff, cmd_end=0xff, cmd_done0 =0xff, cmd_done1=0xff;
    __s32 ret = 0;

    _enter_nand_critical();

    if(read_retry_mode <0x10) //hynix mode
    {
        cmd_w = 0x36;
        cmd_end = 0x16;
        cmd_done0 = 0xff;
        cmd_done1 = 0xff;
    }
    else if((read_retry_mode >=0x10)&&(read_retry_mode <0x20)) //toshiba mode
    {
        cmd_w = 0x55;
        cmd_end = 0xff;
        cmd_done0 = 0x26;
        cmd_done1 = 0x5D;
    }
    else if((read_retry_mode >=0x20)&&(read_retry_mode <0x30)) //Samsung mode
    {
        cmd_w = 0xA1;
        cmd_end = 0xff;
        cmd_done0 = 0xff;
        cmd_done1 = 0xff;
    }
	else if((read_retry_mode >=0x30)&&(read_retry_mode <0x40)) //Sandisk mode
    {
		if((0x30==read_retry_mode) || (0x31==read_retry_mode))
		{
	        cmd_w = 0x53;
	        cmd_end = 0xff;
	        cmd_done0 = 0xB6;
	        cmd_done1 = 0xff;
		}
		else if((0x32==read_retry_mode)||(0x33==read_retry_mode))
		{
			cmd_w = 0xEF;
			cmd_end = 0xff;
			cmd_done0 = 0xff;
			cmd_done1 = 0xff;
		}
		else 
		{
			PHY_ERR("_vender_set_param, wrong read retry mode--1!\n");
		}
    }
	else if((read_retry_mode >=0x40)&&(read_retry_mode <0x50)) //micron mode
    {
        cmd_w = 0xef;
        cmd_end = 0xff;
        cmd_done0 = 0xff;
        cmd_done1 = 0xff;
    }
	else if((read_retry_mode >=0x50)&&(read_retry_mode <0x60)) //intel mode
    {
        cmd_w = 0xef;
        cmd_end = 0xff;
        cmd_done0 = 0xff;
        cmd_done1 = 0xff;
    }
    else
    {
		PHY_ERR("_vender_set_param, wrong read retry mode--2!\n");
        return -1;
    }

    for(i=0; i<count; i++)
	{
	    if((read_retry_mode >=0x20)&&(read_retry_mode <0x30)) //samsung mode
	    {
	        /* send cmd to set param */
	        NDFC_WRITE_RAM0_B(0, 0x00);
	        NDFC_WRITE_RAM0_B(1, addr[i]);
    		NDFC_WRITE_RAM0_B(2, para[i]);

    		NDFC_WRITE_REG_CNT(3);

    		/*set NFC_REG_CMD*/
    		cfg = cmd_w;
    		cfg |= ( NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1);
    		nfc_repeat_mode_enable();
    		NDFC_WRITE_REG_CMD(cfg);
    		nfc_repeat_mode_disable();
	    }
	    else if((read_retry_mode>=0x40)&&(read_retry_mode<0x50))  //micron read retry mode
	    {
	    	/* send cmd to set param */
	        NDFC_WRITE_RAM0_B(0, para[i]);
	        NDFC_WRITE_RAM0_B(1, 0x0);
    		NDFC_WRITE_RAM0_B(2, 0x0);
    		NDFC_WRITE_RAM0_B(3, 0x0);
    		NDFC_WRITE_REG_CNT(4);

    		/*set NFC_REG_CMD*/
    		cfg = cmd_w;
    		cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
    		_set_addr(&addr[i], 1);
    		NDFC_WRITE_REG_CMD(cfg);
	    }
		else if((read_retry_mode>=0x50)&&(read_retry_mode<0x60))  //intel read retry mode
	    {
			/* send cmd to set param */
	        NDFC_WRITE_RAM0_B(0, para[i]);
	        NDFC_WRITE_RAM0_B(1, 0x0);
    		NDFC_WRITE_RAM0_B(2, 0x0);
    		NDFC_WRITE_RAM0_B(3, 0x0);
    		NDFC_WRITE_REG_CNT(4);

    		/*set NFC_REG_CMD*/
    		cfg = cmd_w;
    		cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
    		_set_addr(&addr[i], 1);
    		NDFC_WRITE_REG_CMD(cfg);
	    }
	    else //hynix & toshiba mode
	    {
	    	if((0x32 == read_retry_mode)||(0x33 == read_retry_mode))
	    	{
		        NDFC_WRITE_RAM0_B(0, para[0]);
		        NDFC_WRITE_RAM0_B(1, para[1]);
	    		NDFC_WRITE_RAM0_B(2, para[2]);
				NDFC_WRITE_RAM0_B(3, para[3]);

	    	    _set_addr(&addr[0], 1);

	    	    NDFC_WRITE_REG_CNT(4);

	    	    cfg  = 0;
	    	    cfg |= cmd_w;

	    	    cfg |= (NDFC_SEND_ADR | NDFC_ACCESS_DIR | NDFC_DATA_TRANS | NDFC_SEND_CMD1 | NDFC_WAIT_FLAG );

	    	    //nfc_repeat_mode_enable();

	    	    NDFC_WRITE_REG_CMD(cfg);

	    		//nfc_repeat_mode_disable();

	    	}
	    	else
	    	{
		        /* send cmd to set param */
	    		NDFC_WRITE_RAM0_B(0, para[i]);
	    		_set_addr(&addr[i], 1);
	    		NDFC_WRITE_REG_CNT(1);

	    		/*set NFC_REG_CMD*/
	    		cfg = cmd_w;
	    		cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
	    		NDFC_WRITE_REG_CMD(cfg);
			}
	    }

		ret = _wait_cmdfifo_free();
		ret |= _wait_cmd_finish();

		if(ret)
		{
			_exit_nand_critical();
			return ret;
		}

		/* send cmd to end */
		if(cmd_end != 0xff)
		{
		    /*set NFC_REG_CMD*/
    		cfg = cmd_end;
    		cfg |= ( NDFC_SEND_CMD1);
    		NDFC_WRITE_REG_CMD(cfg);

    		ret = _wait_cmdfifo_free();
    		ret |= _wait_cmd_finish();

    		if(ret)
    		{
    			_exit_nand_critical();
    			return ret;
    		}
		}
	}

    if(0x11 == read_retry_mode)
    {
    	if((0x02 == para[0])&&(0x00 == para[1])&&(0x7e == para[2])&&(0x7c == para[3]))
    	{
    		/* case 7 of toshiba A19nm read retry operation */

    		cfg = 0xB3;
    		cfg |= ( NDFC_SEND_CMD1);
    		NDFC_WRITE_REG_CMD(cfg);

    		ret = _wait_cmdfifo_free();
    		ret |= _wait_cmd_finish();

    		if(ret)
    		{
    			_exit_nand_critical();
    			return ret;
    		}
    	}
    	else if((0x00 == para[0])&&(0x00 == para[1])&&(0x00 == para[2])&&(0x00 == para[3])) //??
    	{
    		/*  */
    		_exit_nand_critical();
    		return ret;
    	}
    }
    if(0x12 == read_retry_mode)
	{
		if((0x00 == para[0])&&(0x00 == para[1])&&(0x00 == para[2])&&(0x00 == para[3])&&(toshiba15nm_rr_start_flag == 0))
		{
			_exit_nand_critical();
			return ret;
		}
	}
	if(cmd_done0!=0xff)
	{
	    /*set NFC_REG_CMD*/
		cfg = cmd_done0;
		cfg |= ( NDFC_SEND_CMD1);
		NDFC_WRITE_REG_CMD(cfg);

		ret = _wait_cmdfifo_free();
		ret |= _wait_cmd_finish();

		if(ret)
		{
			_exit_nand_critical();
			return ret;
		}
	}

	if(cmd_done1!=0xff)
	{
	    /*set NFC_REG_CMD*/
		cfg = cmd_done1;
		cfg |= ( NDFC_SEND_CMD1);
		NDFC_WRITE_REG_CMD(cfg);

		ret = _wait_cmdfifo_free();
		ret |= _wait_cmd_finish();

		if(ret)
		{
			_exit_nand_critical();
			return ret;
		}
	}

	_exit_nand_critical();
	return ret;
}

__s32 _vender_pre_condition(void)
{
    __u32 i, cfg;
    __u32 cmd[2]= {0x5c, 0xc5};
    __s32 ret = 0;

    _enter_nand_critical();
    if(((read_retry_mode>=0x10)&&(read_retry_mode<0x20))||((read_retry_mode>=0x30)&&(read_retry_mode<0x40)))  //toshiba mode & sandisk mode
    {
		if((read_retry_mode>=0x10)&&(read_retry_mode<0x20))
		{
			cmd[0] = 0x5c;
			cmd[1] = 0xc5;
		}
		else if((0x30 == read_retry_mode) || (0x31 == read_retry_mode))
		{
			cmd[0] = 0x3B;
			cmd[1] = 0xB9;
		}
		for(i=0;i<2;i++)
        {
        	/*set NFC_REG_CMD*/
        	cfg = cmd[i];
        	cfg |= (NDFC_SEND_CMD1);
        	NDFC_WRITE_REG_CMD(cfg);

        	ret = _wait_cmdfifo_free();
        	ret |= _wait_cmd_finish();

        	if (ret)
        	{
        		_exit_nand_critical();
        		return ret;
        	}
        }
    }
    _exit_nand_critical();

	return ret;
}

__s32 _vender_get_param_otp_hynix(__u8 *para, __u8 *addr, __u32 count)
{
    __u32 i, j, cfg;
    __s32 error_flag,ret = 0;
    __u8 address[8];
    __u8 param_reverse[64];
    __u8 reg_addr[2] = {0x0, 0x0};
    __u8 w_data[2] = {0x0, 0x0};

    _enter_nand_critical();

	if(read_retry_mode == 2)
	{
		reg_addr[0] = 0xFF;
		reg_addr[1] = 0xCC;
		w_data[0] = 0x40;
		w_data[1] = 0x4D;
	}
	else if(read_retry_mode == 3)
	{
		reg_addr[0] = 0xAE;
		reg_addr[1] = 0xB0;
		w_data[0] = 0x00;
		w_data[1] = 0x4D;
	}
	else
	{
	    return -1;
	}

    // send 0xFF cmd
	cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG| 0xff);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();

	//send cmd 0x36, addr 0xff, data 0x40
	NDFC_WRITE_REG_CNT(1);
	NDFC_WRITE_RAM0_B(0, w_data[0]);
	address[0] = reg_addr[0];
	_set_addr(&address[0], 1);
	cfg = (NDFC_SEND_CMD1 | NDFC_DATA_TRANS |NDFC_ACCESS_DIR | NDFC_SEND_ADR |0x36);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();

	//send addr 0xCC
	address[0] = reg_addr[1];
	_set_addr(&address[0], 1);
	cfg = (NDFC_SEND_ADR);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();

	//send data 0x4D
	NDFC_WRITE_REG_CNT(1);
	NDFC_WRITE_RAM0_B(0, w_data[1]);
	cfg = (NDFC_DATA_TRANS | NDFC_ACCESS_DIR);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();

	//send cmd 0x16, 0x17, 0x04, 0x19, 0x00
    _wait_cmdfifo_free();
    cfg = (NDFC_SEND_CMD1|0x16);
    NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();
    _wait_cmdfifo_free();
    cfg = (NDFC_SEND_CMD1|0x17);
    NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();
    _wait_cmdfifo_free();
    cfg = (NDFC_SEND_CMD1|0x04);
    NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();
    _wait_cmdfifo_free();
    cfg = (NDFC_SEND_CMD1|0x19);
    NDFC_WRITE_REG_CMD(cfg);
    _wait_cmd_finish();

    _wait_cmdfifo_free();
    cfg = (NDFC_SEND_CMD1|0x00);
    NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();

    //send addr 00, 00, 00, 02, 00
	address[0] = 0x00;
	address[1] = 0x00;
	address[2] = 0x00;
	address[3] = 0x02;
	address[4] = 0x00;
	_set_addr(&address[0], 5);
	cfg = (NDFC_SEND_ADR|(0x4<<16));
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
	 _wait_cmd_finish();

	//send cmd 0x30, read data
	_wait_cmdfifo_free();

	NDFC_WRITE_REG_CNT(2);
	cfg = (NDFC_SEND_CMD1|NDFC_WAIT_FLAG|NDFC_DATA_TRANS|0x30);
	NDFC_WRITE_REG_CMD(cfg);
	_wait_cmd_finish();
	//get param data
    if ((NDFC_READ_RAM0_B(0)!=0x08)||((NDFC_READ_RAM0_B(1)!=0x08)))
    {
        PHY_ERR("hynix OTP RegCount value error: 0x%x, 0x%x \n",NDFC_READ_RAM0_B(0), NDFC_READ_RAM0_B(1) );
        ret = -1;
    }

	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CNT(1024);
    cfg = (NDFC_DATA_TRANS);
    NDFC_WRITE_REG_CMD(cfg);
    _wait_cmd_finish();

    for(j=0;j<8;j++)
    {
        error_flag = 0;
        for(i=0;i<64;i++)
        {
            para[i] = NDFC_READ_RAM0_B(128*j+i);
            param_reverse[i] = NDFC_READ_RAM0_B(128*j+64+i);
            if((para[i]+param_reverse[i])!= 0xff)
            {
                error_flag = 1;
                break;
            }
        }
        if(!error_flag)
        {
        	PHY_DBG("otp copy %d is ok!\n",j);
        	break;
        }

    }

    if(error_flag)
        ret = -1;

	// send 0xFF cmd
	cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG| 0xff);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
    _wait_cmd_finish();

	// send 0x38 cmd
	cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG | 0x38);
	_wait_cmdfifo_free();
	NDFC_WRITE_REG_CMD(cfg);
    _wait_cmd_finish();

    _exit_nand_critical();
	return ret;
}

__s32 _major_check_byte(__u8 *out, __u32 mode, __u32 level, __u8 *in, __u8 *in_inverse, __u32 len)
{
	__u32 bit, byte;
	__u32 cnt_1; /* the total number of bit '1' on specified bit position in all input bytes */
	__u32 cnt_0;
	__u32 get_bit, get_total_bit;
	__u8 byte_ok = 0;

	if (level < len/2) {
		PHY_ERR("_major_check_byte, wrong input para, level %d, len %d\n", level, len);
		*out = 0xff;
		return -1;
	}

	get_total_bit = 0;
	for (bit=0; bit<8; bit++)
	{
		cnt_1 = 0;
		cnt_0 = 0;
		get_bit = 0;
		for (byte=0; byte<len; byte++)
		{
			if ( in[byte] & (1U<<bit) )
				cnt_1++;
			else
				cnt_0++;
		}

		if (cnt_1 > level) {
			byte_ok |= (1U<<bit);
			get_bit = 1;
			//msg("%d:  '1'-'0' : %d - %d --> 1\n", bit, cnt_1, cnt_0);
		}

		if (cnt_0 > level) {
			get_bit = 1;
			//msg("%d:  '1'-'0' : %d - %d --> 0\n", bit, cnt_1, cnt_0);
		}

		if ((get_bit==0) && (mode==1)) {
			/* try 2nd group of input data */
			cnt_1 = 0;
			cnt_0 = 0;
			get_bit = 0;
			for (byte=0; byte<len; byte++)
			{
				if ( in_inverse[byte] & (1U<<bit) )
					cnt_0++;
				else
					cnt_1++;
			}

			/* get a correct bit, but it's a inverse one */
			if (cnt_0 > level) {
				//msg("inverse %d:  '1'-'0' : %d - %d --> 0\n", bit, cnt_1, cnt_0);
				get_bit = 1;
			}
			if (cnt_1 > level) {
				//msg("inverse %d:  '1'-'0' : %d - %d --> 0\n", bit, cnt_1, cnt_0);
				byte_ok |= (1U<<bit);
				get_bit = 1;
			}
		}

		if (get_bit)
			get_total_bit++;
		else {
			PHY_ERR("%d:  '1'-'0' : %d - %d\n", bit, cnt_1, cnt_0);
			PHY_ERR("get bit %d failed!\n", bit);
		}
	}

	if (get_total_bit == 8) {
		*out = byte_ok;
		//msg("get byte: 0x%x\n", *out);
		return 0;
	} else {
		*out = 0xff;
		return -1;
	}
}


__s32 _get_read_retry_cfg(__u8 *rr_cnt, __u8 *rr_reg_cnt, __u8 *rr_tab, __u8 *otp)
{
	__s32 err_flag=0, ret=0;
	__u32 i, nbyte, nset;
	__u8 buf[32]={0}, buf_inv[32]={0};
	__u32 rr_tab_size = 32; //RR_CNT_IN_OTP * RR_REG_CNT_IN_OTP

	/* read retry count */
	for (i=0; i<8; i++)
		buf[i] = otp[i];

	ret = _major_check_byte(rr_cnt, 0, 4, buf, buf_inv, 8);
	if (ret<0)
	{
		PHY_ERR("_get_read_retry_parameters, get rr count failed!\n");
		return -1;
	}

	else
		PHY_DBG("rr cnt: %d\n", (* rr_cnt));


	/* read retry register count */
	for (i=0; i<8; i++)
		buf[i] = otp[8 + i];

	ret = _major_check_byte(rr_reg_cnt, 0, 4, buf, buf_inv, 8);
	if (ret<0) {
		PHY_ERR("_get_read_retry_parameters, get rr reg count failed!\n");
		return -1;
	} else
		PHY_DBG("rr reg cnt: %d\n", (* rr_reg_cnt));

	if(((* rr_cnt) != 8) || ((* rr_reg_cnt) != 4))
	{
		PHY_ERR("read retry value from otp error: rr_cnt %d rr_reg_cnt %d!\n",(* rr_cnt),(* rr_reg_cnt));
		return -1;
	}

	/* read retry table */
	for (nbyte=0; nbyte<rr_tab_size; nbyte++)
	{
		for (nset=0; nset< 8; nset++)
		{
			buf[nset] = 0;
			buf_inv[nset] = 0;
			buf[nset] = otp[16 + nset*rr_tab_size*2 + nbyte];
			buf_inv[nset] = otp[16 + nset*rr_tab_size*2 + rr_tab_size + nbyte];
		}
		/*
		for (nset=0; nset<RR_TAB_BACKUP_CNT; nset++)
		{
			msg("%02x - %02x\n", buf[nset], buf_inv[nset]);
		}
		*/

		ret = _major_check_byte(&rr_tab[nbyte], 1, 4, buf, buf_inv, 8);
		if (ret<0) {
			PHY_ERR("_get_read_retry_parameters, get the %d-th byte of rr table failed!\n", nbyte);
			err_flag = 1;
			break;
			//return -1;
		}
	}

	for (nbyte=0; nbyte<rr_tab_size; nbyte++)
	{
		if (((nbyte%8)==0) && nbyte)
			PHY_DBG("\n");
		PHY_DBG("%02x ", rr_tab[nbyte]);
	}
	PHY_DBG("\n");

	if (err_flag)
		ret = -1;
	else
		ret = 0;

	return ret;
}

__s32 _read_otp_info_hynix(__u32 chip, __u8 *otp_chip)
{
	__u32 rb_index;
	__u32 i, j,ndie;
	__u8 *otp;
	__u8 abuf[8]={0};
	__u32 cfg;

	NFC_SelectChip(chip);
	rb_index = _cal_real_rb(chip);
	NFC_SelectRb(rb_index);

	PHY_DBG("start get read retry param from: ce %d, rb %d...\n", chip,rb_index);

	for (ndie=0; ndie<1; ndie++)
	{

		otp = otp_chip;
		if (otp == NULL) {
			PHY_ERR("invalid buffer for otp info!\n");
			return -1;
		}

		 // send 0xFF cmd
		cfg = 0;
		cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG| 0xff);
		_wait_cmdfifo_free();
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		if ((ndie==1) || (ndie==2) || (ndie==3))
		{

			abuf[0] = 0x00;
			abuf[1] = 0x00;
			if (ndie == 1)
				abuf[2] = 0x10;
			else if (ndie == 2)
				abuf[2] = 0x20;
			else if (ndie == 3)
				abuf[2] = 0x30;
			else
				PHY_ERR("=======wrong ndie %d\n", ndie);

			//send cmd 0x78, abuf
			cfg = 0;
			_set_addr(&abuf[0], 3);
			cfg = (NDFC_SEND_CMD1 | NDFC_SEND_ADR |(0x2<<16)|0x78);
			_wait_cmdfifo_free();
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();
		}

		{

			cfg = 0;
			abuf[0] = 0x38;
			//send cmd 0x36, addr 0x38, data 0x52
			NDFC_WRITE_REG_CNT(1);
			NDFC_WRITE_RAM0_B(0, 0x52);
			_set_addr(&abuf[0], 1);
			cfg = (NDFC_SEND_CMD1 | NDFC_DATA_TRANS |NDFC_ACCESS_DIR | NDFC_SEND_ADR |0x36);
			_wait_cmdfifo_free();
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();

			//send cmd 0x16, 0x17, 0x04, 0x19, 0x00
			cfg = 0;
			_wait_cmdfifo_free();
			cfg = (NDFC_SEND_CMD1|0x16);
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();
			cfg = 0;
			_wait_cmdfifo_free();
			cfg = (NDFC_SEND_CMD1|0x17);
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();
			cfg = 0;
			_wait_cmdfifo_free();
			cfg = (NDFC_SEND_CMD1|0x04);
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();
			cfg = 0;
			_wait_cmdfifo_free();
			cfg = (NDFC_SEND_CMD1|0x19);
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();

			cfg = 0;
			_wait_cmdfifo_free();
			cfg = (NDFC_SEND_CMD1|0x00);
			NDFC_WRITE_REG_CMD(cfg);
			_wait_cmd_finish();

			//send addr 00, 00, 00, 02
			cfg = 0;
			abuf[0] = 0x00;
			abuf[1] = 0x00;
			abuf[2] = 0x00;
			if(read_retry_mode == 0x4)
				abuf[3] = 0x02;
			else if(read_retry_mode == 0x5)
				abuf[3] = 0x01;
			
			_set_addr(&abuf[0], 4);
			cfg = (NDFC_SEND_ADR|(0x3<<16));
			_wait_cmdfifo_free();
			NDFC_WRITE_REG_CMD(cfg);
			 _wait_cmd_finish();
		}

		{
			if (ndie == 0)
				abuf[0] = 0x00;
			else if (ndie == 1)
				abuf[0] = 0x10;
			else if (ndie == 2)
				abuf[0] = 0x20;
			else if (ndie == 3)
				abuf[0] = 0x30;
			else
				PHY_ERR("!!!wrong ndie %d\n", ndie);
			//send addr
			cfg = 0;
			_set_addr(&abuf[0], 1);
			cfg = (NDFC_SEND_ADR);
			_wait_cmdfifo_free();
			NDFC_WRITE_REG_CMD(cfg);
			 _wait_cmd_finish();
		}

		//send cmd 0x30, read data
		_wait_cmdfifo_free();
		cfg = 0;
		NDFC_WRITE_REG_CNT(528);
		cfg = (NDFC_SEND_CMD1|NDFC_WAIT_FLAG|NDFC_DATA_TRANS|0x30);
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		/* read otp data from ndfc fifo */
		for (i=0; i<528; i++)
		{
			otp[i] = NDFC_READ_RAM0_B(i);
		}

		 // send 0xFF cmd
		cfg = 0;
		cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG| 0xff);
		_wait_cmdfifo_free();
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		abuf[0] = 0x38;
		//send cmd 0x36, addr 0x38, data 0x00
		NDFC_WRITE_REG_CNT(1);
		NDFC_WRITE_RAM0_B(0, 0x00);
		_set_addr(&abuf[0], 1);
		cfg = 0;
		cfg = (NDFC_SEND_CMD1 | NDFC_DATA_TRANS |NDFC_ACCESS_DIR | NDFC_SEND_ADR |0x36);
		_wait_cmdfifo_free();
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		//send 0x16 cmd
		 _wait_cmdfifo_free();
		cfg = 0;
		cfg = (NDFC_SEND_CMD1|0x16);
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		/* dummy read(address don't care) 0x00 cmd + 0x0 addr + 0x30 cmd*/
		abuf[0] = 0x00;
		abuf[1] = 0x00;
		abuf[2] = 0x00;
		abuf[3] = 0x00;
		abuf[4] = 0x00;
		_set_addr(&abuf[0], 5);
		cfg = 0;
		cfg = (NDFC_SEND_CMD1 | NDFC_SEND_ADR |(0x4<<16)|0x00);
		_wait_cmdfifo_free();
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();

		//send 0x30 cmd
		 _wait_cmdfifo_free();
		 cfg = 0;
		cfg = (NDFC_SEND_CMD1 | NDFC_WAIT_FLAG |0x30);
		NDFC_WRITE_REG_CMD(cfg);
		_wait_cmd_finish();
#if 0
		for (i=1; i<529; i++)
		{
			PHY_DBG(" %x ", otp[i-1]);
			if (((i%8)==0) && i)
			{
				PHY_DBG(" \n");
			}
		}
		PHY_DBG(" \n");
#endif
	}

#if 0
	{
		u32 nset, nbyte;

		for (nset=0; nset<8; nset++)
		{
			PHY_DBG("\n\n============ set %d \n", nset);
			for (nbyte=0; nbyte<32; nbyte++)
			{
				if (((nbyte%8)==0) && nbyte)
					PHY_DBG("\n");
				PHY_DBG("%02x ", otp[16+ nset*32*2 + nbyte]);
			}
		}
		PHY_DBG("\n");
		/*
		for (nset=0; nset<8; nset++)
		{
			PHY_DBG("\n\n============ inverse set %d \n", nset);
			for (nbyte=0; nbyte<32; nbyte++)
			{
				if (((nbyte%8)==0) && nbyte)
					PHY_DBG("\n");
				PHY_DBG("%02x ", otp[16+ nset*32*2 + 32 + nbyte]);
			}
		}
		PHY_DBG("\n");
		*/
	}
#endif /* #ifdef GET_OTP_INFO_DEBUG_INFO */

	return 0;
}

__s32 _get_rr_value_otp_hynix(__u32 nchip)
{
	__s32 ret = 0;

	__u8*  otp_info_hynix_16nm;
	__u8 rr_cnt_hynix_16nm;
	__u8 rr_reg_cnt_hynix_16nm;

	otp_info_hynix_16nm = MALLOC(528);
	if (!otp_info_hynix_16nm)
	{
		PHY_ERR("otp_info_hynix_16nm : allocate memory fail\n");
		return -1;
	}

	ret = _read_otp_info_hynix(nchip, otp_info_hynix_16nm);
	if (ret<0) {
		PHY_ERR("CH %d chip %d get otp info failed!\n",NandIndex,nchip);
	}

	ret = _get_read_retry_cfg(&rr_cnt_hynix_16nm,
			&rr_reg_cnt_hynix_16nm, &hynix16nm_read_retry_otp_value[NandIndex][nchip][0][0],
			otp_info_hynix_16nm);
	if (ret<0) {
		PHY_ERR("CH %d chip %d get read retry cfg from otp info failed!\n",NandIndex,nchip);
	}

	FREE(otp_info_hynix_16nm,528);

	return ret;
}

//for offset from defaul value
__s32 NFC_ReadRetry(__u32 chip, __u32 retry_count, __u32 read_retry_type)
{
    __u32 i,j;
    __s32 ret=0;
	__u32 toggle_mode_flag = 0;
    __s16 temp_val;
    __u8 param[READ_RETRY_MAX_REG_NUM];
    __u32 nand_clk_bak, nand_clk_bak1;
    __u8 addr_0x32[2];

	if(!Retry_value_ok_flag)
	{
		PRINT("retry value not ready!!\n");
		return 0;
	}

	if(retry_count >read_retry_cycle)
		return -1;

    if(read_retry_mode<0x10)  //for hynix read retry mode
    {
		if((read_retry_mode == 0)||(read_retry_mode == 1))
		{
		    if(retry_count == 0)
	            ret = _vender_set_param(&read_retry_default_val[NandIndex][chip][0], &read_retry_reg_adr[0], read_retry_reg_num);
	        else
	        {
	            for(i=0; i<read_retry_reg_num; i++)
            	{
            	    temp_val = (read_retry_default_val[NandIndex][chip][i] + read_retry_val[retry_count-1][i]);
            	    if(temp_val >255)
            	        temp_val = 0xff;
            	    else if(temp_val <0)
        				temp_val = 0;
        			else
            	        temp_val &= 0xff;

            	    param[i] = (__u8)temp_val;
            	}

    		    //fix 0
    			if((retry_count >=2)&&(retry_count<=6))
    				param[0] = 0;

    			if((retry_count == 5)||(retry_count == 6))
        	    	param[1] = 0;

        	    ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
	        }

		}
		else if((read_retry_mode == 2)||(read_retry_mode == 3))
		{
		    for(i=0; i<read_retry_reg_num; i++)
		        param[i] = hynix_read_retry_otp_value[NandIndex][chip][retry_count][i];

		    ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
    	}
		else if((read_retry_mode == 4)||(read_retry_mode == 5))
		{
			for(i=0; i<read_retry_reg_num; i++)
				param[i] = hynix16nm_read_retry_otp_value[NandIndex][chip][retry_count][i];

			ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
#if 0
			for(i=0; i<read_retry_reg_num; i++)
			{
				PHY_ERR("rr_para %x ", param[i]);
				PHY_ERR("\n");
			}
			for(j=0;j<1;j++)
			{
				_vender_get_param(&param_debug[0], &read_retry_reg_adr[0], read_retry_reg_num);
				for(i=0; i<read_retry_reg_num; i++)
				{
					PHY_ERR("rr_para_debug %x ", param_debug[i]);
					PHY_ERR("\n");
				}
			}

#endif
		}
    }
    else if((read_retry_mode>=0x10)&&(read_retry_mode<0x20))  //for toshiba readretry mode
    {
        NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
        NAND_SetClk(NandIndex, 10, 10*2);

        if(retry_count == 1)
            _vender_pre_condition();

        if(read_retry_mode == 0x12)
        {
        	if(retry_count == 1)
			{
				toshiba15nm_rr_start_flag = 1;
			}
        }

        for(i=0; i<read_retry_reg_num; i++)
            param[i] = (__u8)read_retry_val[retry_count-1][i];
		if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode  after 0x53h cmd
		{
			NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
			toggle_mode_flag = 1;
		}

        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);

		if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
			NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

		if(read_retry_mode == 0x12)
		{
			if(retry_count == 1)
			{
				toshiba15nm_rr_start_flag = 0;
			}
		}

        NAND_SetClk(NandIndex, nand_clk_bak, nand_clk_bak1);
    }
    else if((read_retry_mode>=0x20)&&(read_retry_mode<0x30))
    {
        for(i=0; i<read_retry_reg_num; i++)
            param[i] = (__u8)read_retry_val[retry_count][i];

        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
    }
	else if((read_retry_mode>=0x30)&&(read_retry_mode<0x40))  //for sandisk readretry mode
    {
		if(0x30 == read_retry_mode)//for sandisk 19nm flash
		{
	        NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

	        if(retry_count == 1)
	            _vender_pre_condition();

	        for(i=0; i<read_retry_reg_num; i++)
	            param[i] = 0x0;
			if(read_retry_cycle==16)
			{
				param[0] = (__u8)param0x30low[retry_count-1][0];
				param[3] = (__u8)param0x30low[retry_count-1][1];

			}
	        else if(read_retry_cycle==20)
			{
				param[0] = (__u8)param0x30high[retry_count-1][0];
				param[1] = (__u8)param0x30high[retry_count-1][1];

			}
			if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
			{
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
				toggle_mode_flag = 1;
			}

	        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);

			if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

	        NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
		}
		else if(0x31 == read_retry_mode)//for sandisk 24nm flash
		{
	        NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

	        if(retry_count == 1)
	            _vender_pre_condition();
			for(i=0; i<read_retry_reg_num; i++)
				param[i] = 0x0;

			param[0] = (__u8)param0x31[retry_count-1][0];
			param[1] = (__u8)param0x31[retry_count-1][1];
			param[3] = (__u8)param0x31[retry_count-1][2];

			if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
			{
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
				toggle_mode_flag = 1;
			}

	        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);

			if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));
	        NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
		}
		else if((0x32==read_retry_mode)||(0x33==read_retry_mode))
		{
			addr_0x32[0] = 0x11;

	        NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

			for(i=0; i<read_retry_reg_num; i++)
				param[i] = 0x0;

			for(i=0; i<4; i++)
			{
				param[i] = (__u8)param0x32[retry_count][i];
			}

			if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
			{
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
				toggle_mode_flag = 1;
			}

			ret =_vender_set_param(&param[0], &addr_0x32[0], 1);

			if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

			NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
		}
    }
	else if((read_retry_mode>=0x40)&&(read_retry_mode<0x50))  //for micron readretry mode
	{
		for(i=0; i<read_retry_reg_num; i++)
            param[i] = (__u8)read_retry_val[retry_count-1][i];

        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
	}
	else if((read_retry_mode>=0x50)&&(read_retry_mode<0x60))  //for intel readretry mode
	{
		for(i=0; i<read_retry_reg_num; i++)
            param[i] = (__u8)read_retry_val[retry_count-1][i];

		if(retry_count==4)
		{
			__u8 param_intel[1] ={0x01};  //enable advanced read retry
			__u8 adr_intel[1] = {0x93};
			ret = _vender_set_param(&param_intel[0], &adr_intel[0], read_retry_reg_num);

		}
        ret =_vender_set_param(&param[0], &read_retry_reg_adr[0], read_retry_reg_num);
	}
	else
	{
		PHY_ERR("NFC_ReadRetry, unknown read retry mode 0x%x\n", read_retry_mode);
		return -1;
	}
	return ret;
}

__s32 NFC_ReadRetryInit(__u32 read_retry_type)
{
	__u32 i,j;
	//init
	read_retry_mode = (read_retry_type>>16)&0xff;
	read_retry_cycle =(read_retry_type>>8)&0xff;
	read_retry_reg_num = (read_retry_type>>0)&0xff;

	//PHY_DBG("mode: 0x%x, cycle: 0x%x, reg_num: 0x%x\n", read_retry_mode, read_retry_cycle, read_retry_reg_num);

	if(read_retry_mode == 0)  //mode0  H27UCG8T2MYR
	{
		read_retry_reg_adr[0] = 0xAC;
		read_retry_reg_adr[1] = 0xAD;
		read_retry_reg_adr[2] = 0xAE;
		read_retry_reg_adr[3] = 0xAF;

		//set read retry level
		for(i=0;i<read_retry_cycle;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = para0[i][j];
			}
		}
	}
	else if(read_retry_mode == 1) //mode1  H27UBG8T2BTR
	{
		read_retry_reg_adr[0] = 0xA7;
		read_retry_reg_adr[1] = 0xAD;
		read_retry_reg_adr[2] = 0xAE;
		read_retry_reg_adr[3] = 0xAF;

		//set read retry level
		for(i=0;i<read_retry_cycle;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = para1[i][j];
			}
		}
	}
	else if(read_retry_mode == 2) //mode2  H27UCG8T2ATR
	{
		read_retry_reg_adr[0] = 0xCC;
		read_retry_reg_adr[1] = 0xBF;
		read_retry_reg_adr[2] = 0xAA;
		read_retry_reg_adr[3] = 0xAB;
		read_retry_reg_adr[4] = 0xCD;
		read_retry_reg_adr[5] = 0xAD;
		read_retry_reg_adr[6] = 0xAE;
		read_retry_reg_adr[7] = 0xAF;
	}
	else if(read_retry_mode ==3) //mode2  H27UCG8T2ATR
	{
		read_retry_reg_adr[0] = 0xB0;
		read_retry_reg_adr[1] = 0xB1;
		read_retry_reg_adr[2] = 0xB2;
		read_retry_reg_adr[3] = 0xB3;
		read_retry_reg_adr[4] = 0xB4;
		read_retry_reg_adr[5] = 0xB5;
		read_retry_reg_adr[6] = 0xB6;
		read_retry_reg_adr[7] = 0xB7;
	}
	else if((read_retry_mode ==4)||(read_retry_mode ==5)) //mode3  H27UCG8T2ETR/H27UCG8T2DTR
	{
		read_retry_reg_adr[0] = 0x38;
		read_retry_reg_adr[1] = 0x39;
		read_retry_reg_adr[2] = 0x3A;
		read_retry_reg_adr[3] = 0x3B;

	}
	else if((read_retry_mode>=0x10)&&(read_retry_mode<0x20))  //mode0x10  toshiba readretry mode0
	{
		if(0x10 == read_retry_mode)
		{
		    read_retry_reg_adr[0] = 0x04;
			read_retry_reg_adr[1] = 0x05;
			read_retry_reg_adr[2] = 0x06;
			read_retry_reg_adr[3] = 0x07;

		    //set read retry level
			for(i=0;i<read_retry_cycle;i++)
			{
				for(j=0; j<read_retry_reg_num;j++)
				{
					read_retry_val[i][j] = para0x10[i];
				}
			}
		}
		else if(0x11 == read_retry_mode)//mode0x11 toshiba 1Ynm(A19nm)
		{
			read_retry_reg_adr[0] = 0x04;
			read_retry_reg_adr[1] = 0x05;
			read_retry_reg_adr[2] = 0x06;
			read_retry_reg_adr[3] = 0x07;
			read_retry_reg_adr[4] = 0x0D;
			for(i=0;i<read_retry_cycle;i++)
			{
				for(j=0; j<read_retry_reg_num;j++)
				{
					read_retry_val[i][j] = para0x11[i][j];
				}
			}
		}
		else if(0x12 == read_retry_mode)//mode0x12 toshiba 15nm
		{
			read_retry_reg_adr[0] = 0x04;
			read_retry_reg_adr[1] = 0x05;
			read_retry_reg_adr[2] = 0x06;
			read_retry_reg_adr[3] = 0x07;
			read_retry_reg_adr[4] = 0x0D;
			for(i=0;i<read_retry_cycle;i++)
			{
				for(j=0; j<read_retry_reg_num;j++)
				{
					read_retry_val[i][j] = para0x12[i][j];
				}
			}
		}
	}
	else if(read_retry_mode == 0x20)  //mode0x10  Samsung mode0
	{
	    read_retry_reg_adr[0] = 0xA7;
		read_retry_reg_adr[1] = 0xA4;
		read_retry_reg_adr[2] = 0xA5;
		read_retry_reg_adr[3] = 0xA6;

	    //set read retry level
		for(i=0;i<read_retry_cycle+1;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = para0x20[i][j];
			}

		}
	}
	else if((read_retry_mode>=0x30)&&(read_retry_mode<0x40))
	{
		read_retry_reg_adr[0] = 0x04; //for 19nm && 24nm
		read_retry_reg_adr[1] = 0x05;
		read_retry_reg_adr[2] = 0x06;
		read_retry_reg_adr[3] = 0x07;
		read_retry_reg_adr[4] = 0x08;
		read_retry_reg_adr[5] = 0x09;
		read_retry_reg_adr[6] = 0x0a;
		read_retry_reg_adr[7] = 0x0b;
		read_retry_reg_adr[8] = 0x0c;
	}
	else if(read_retry_mode == 0x40) //mode 0x40 micron mode
	{
		read_retry_reg_adr[0] = 0x89;

		for(i=0;i<read_retry_cycle;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = param0x40[i];
			}
		}
	}
	else if (read_retry_mode == 0x41) //mode 0x41 L95B_128_256_512Gb_1Tb_2Tb_Async_Sync_NAND
	{
		read_retry_reg_adr[0] = 0x89;
		for(i=0;i<read_retry_cycle;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = param0x41[i];
			}
		}
	}
	else if(read_retry_mode == 0x50) //mode 0x50 intel mode
	{
		read_retry_reg_adr[0] = 0x89;

		for(i=0;i<read_retry_cycle;i++)
		{
			for(j=0; j<read_retry_reg_num;j++)
			{
				read_retry_val[i][j] = param0x50[i];
			}
		}
	}
	else
	{
		PHY_ERR("NFC_ReadRetryInit, unknown read retry mode 0x%x\n", read_retry_mode);
		return -1;
	}

	return 0;
}

void NFC_GetOTPValue(__u32 chip, __u8* otp_value, __u32 read_retry_type)
{
    __u8 *pdata;
    __u32 i;

    if((read_retry_mode == 0x2)||(read_retry_mode == 0x3))
    {
        pdata = (__u8 *)(&hynix_read_retry_otp_value[NandIndex][chip][0][0]);
        for(i=0; i<64; i++)
            pdata[i] = otp_value[i];
    }
    else if((read_retry_mode == 0x4)||(read_retry_mode == 0x5))
    {
		pdata = (__u8 *)(&hynix16nm_read_retry_otp_value[NandIndex][chip][0][0]);
		for(i = 0;i<32; i++)
		{
			pdata[i] = otp_value[i];
		}
    }
}

__s32 NFC_GetDefaultParam(__u32 chip,__u8* default_value, __u32 read_retry_type)
{
    __s32 ret;
    __u32 i, j, Count;
	__u32 flag;

	if(chip>=MAX_CHIP_SELECT_CNT)
	{
		PHY_ERR("NFC_GetDefaultParam, beyond chip cnt, chip= %d\n", chip);
		return -1;
	}

    if(read_retry_mode<0x10)  //hynix read retry mode
    {
        if((read_retry_mode == 0x0)||(read_retry_mode == 0x1))
        {
            ret =_vender_get_param(&read_retry_default_val[NandIndex][chip][0], &read_retry_reg_adr[0], read_retry_reg_num);
            for(i=0; i<read_retry_reg_num; i++)
            {
                default_value[i] = read_retry_default_val[NandIndex][chip][i];
            }

        	return ret;
        }
        else if((read_retry_mode == 0x2)||(read_retry_mode == 0x3))
        {
            for(Count =0; Count<5; Count++)
            {
                PHY_DBG("_vender_get_param_otp_hynix time %d!\n", Count);
                ret = _vender_get_param_otp_hynix(&hynix_read_retry_otp_value[NandIndex][chip][0][0], &read_retry_reg_adr[0], 64);
                if(!ret)
                    break;
            }
            if(ret)
            {
                PHY_ERR("_vender_get_param_otp_hynix error!\n");
				return -1;
			}
            //set read retry level
    		for(i=0;i<8;i++)
    		{
    			for(j=0; j<8;j++)
    			{
    				default_value[8*i+j] = hynix_read_retry_otp_value[NandIndex][chip][i][j];
    			}
    		}
        }
        else if((read_retry_mode == 0x4)||(read_retry_mode == 0x5))
        {
        	Count = 0;
			flag = 0;
        	//for(Count =0; Count<5; Count++)
        	while(flag == 0)
			{
				PHY_DBG("_vender_get_param_otp_hynix time %d!\n", Count);
				ret = _get_rr_value_otp_hynix((__u8)chip);
				if(ret == 0)
				{
					flag = 1;
				}
				Count ++;
			}
			//if(ret)
			//{
				//PHY_ERR("_vender_get_param_otp_hynix error!\n");
				//return ret;
			//}
				
			for(i=0;i<8;i++)
			{
				for(j=0; j<4;j++)
				{
					default_value[4*i+j] = hynix16nm_read_retry_otp_value[NandIndex][chip][i][j];
				}
			}

        }
	}

    return 0;
}

__s32 NFC_SetDefaultParam(__u32 chip,__u8* default_value,__u32 read_retry_type)
{
    __s32 ret = 0;
    __u32 i,cfg,nand_clk_bak,nand_clk_bak1;
	__u32 toggle_mode_flag = 0;
	__u8 addr_0x32[2];

	if(chip>=MAX_CHIP_SELECT_CNT)
	{
		PHY_ERR("NFC_GetDefaultParam, beyond chip cnt, chip= %d\n", chip);
		return -1;
	}

    if(read_retry_mode<0x10)  //hynix read retry mode
    {
        for(i=0; i<read_retry_reg_num; i++)
        {
            if((read_retry_mode == 0x0)||(read_retry_mode == 0x1))
                default_value[i] = read_retry_default_val[NandIndex][chip][i];
            else if((read_retry_mode == 0x2)||(read_retry_mode == 0x3))
                default_value[i] = hynix_read_retry_otp_value[NandIndex][chip][0][i];
            else if((read_retry_mode == 0x4)||(read_retry_mode == 0x5))
                default_value[i] = hynix16nm_read_retry_otp_value[NandIndex][chip][0][i];
        }
        ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);
		PHY_DBG("set retry default value: ");
		for(i=0;i<read_retry_reg_num;i++)
        {
			PHY_DBG(" %x",default_value[i]);
		}
		PHY_DBG("\n");
    	return ret;
    }
    else if((read_retry_mode>=0x10)&&(read_retry_mode<0x20)) //toshiba
    {
    	if(0x11 == read_retry_mode)
    	{
    		/* toshiba A19nm: exist read retry mode */

			NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

	        /* 20130926-Gavin, add comment.
	         *
	         * _vender_pre_condition() will send command 0x5c+0xc5 before set all read retry register to 0.
	         * This operation is only for read retry initialization. And it don't require in Toshiba's document.
	         *
	         * The function NFC_SetDefaultParam() also will be called when stop read retry operation.
	         * But exist read retry mode don't requred to send these two command.
	         */
			ret = _vender_pre_condition();
    		for(i=0; i<read_retry_reg_num; i++)
    		{
    			default_value[i] = 0x0;
    		}

    		if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
    		{
    		    NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
    		    toggle_mode_flag = 1;
    		}

    		ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);

    		if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
    		    NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

    		/* reset ? */
			cfg = 0xFF;
			cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
			NDFC_WRITE_REG_CMD(cfg);
			ret |= _wait_cmdfifo_free();
			ret |= _wait_cmd_finish();

    		NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
    		if(ret)
    		{
    			_exit_nand_critical();
    			return ret;
    		}
    	}
    	else if(0x12 == read_retry_mode)
    	{
    		/* toshiba 15nm: exit read retry mode */

			NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

	        ret = _vender_pre_condition();
    		for(i=0; i<read_retry_reg_num; i++)
    		{
    			default_value[i] = 0x0;
    		}

    		if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
    		{
    		    NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
    		    toggle_mode_flag = 1;
    		}

    		ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);

    		if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
    		    NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

    		/* reset ? */
			cfg = 0xFF;
			cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
			NDFC_WRITE_REG_CMD(cfg);
			ret |= _wait_cmdfifo_free();
			ret |= _wait_cmd_finish();

    		NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
    		if(ret)
    		{
    			_exit_nand_critical();
    			return ret;
    		}
    	}
    }
    else if((read_retry_mode>=0x20)&&(read_retry_mode<0x30))  //samsung read retry mode
    {
        for(i=0; i<read_retry_reg_num; i++)
        {
            default_value[i] = (__u8)read_retry_val[0][i];
        }
        ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);

    	return ret;
    }
	else if((read_retry_mode>=0x30)&&(read_retry_mode<0x40))  //sandisk read retry mode
	{
		if((0x30 == read_retry_mode) || (0x31 == read_retry_mode))
		{
			NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

			ret = _vender_pre_condition();
			for(i=0; i<read_retry_reg_num; i++)
	        {
	            default_value[i] = 0x0;
	        }

			if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
			{
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
				toggle_mode_flag = 1;
			}

			ret |= _vender_set_param(default_value,&read_retry_reg_adr[0],read_retry_reg_num);

			if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

			cfg = 0xD6;
			cfg |= ( NDFC_SEND_CMD1);
			NDFC_WRITE_REG_CMD(cfg);

			ret |= _wait_cmdfifo_free();
			ret |= _wait_cmd_finish();

			NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
			if(ret)
			{
				_exit_nand_critical();
				return ret;
			}
		}
		else if((0x32 == read_retry_mode)||(0x33 == read_retry_mode)) //sandisk A19nm
		{
			addr_0x32[0] = 0x11;

			NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	        NAND_SetClk(NandIndex, 10, 10*2);

			for(i=0; i<read_retry_reg_num; i++)
			{
				default_value[i] = 0x0;
			}

			if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
			{
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
				toggle_mode_flag = 1;
			}

			ret |= _vender_set_param(default_value,&addr_0x32[0],1);

			if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
				NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

			cfg = 0xFF;
			cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
			NDFC_WRITE_REG_CMD(cfg);


			ret |= _wait_cmdfifo_free();
			ret |= _wait_cmd_finish();
			NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
			if(ret)
			{
				_exit_nand_critical();
				return ret;
			}
		}
	}
	else if((read_retry_mode>=0x40)&&(read_retry_mode<0x50))  //micron read retry mode
    {
        for(i=0; i<read_retry_reg_num; i++)
        {
            default_value[i] = 0x0;
        }
        ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);

    	return ret;
    }
	else if((read_retry_mode>=0x50)&&(read_retry_mode<0x60))  //intel read retry mode
    {
        for(i=0; i<read_retry_reg_num; i++)
        {
            default_value[i] = 0x0;
        }
        ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);
		{
			__u8 param_intel[1] ={0x00};  //disable advanced read retry
			__u8 adr_intel[1] = {0x93};
			ret = _vender_set_param(&param_intel[0], &adr_intel[0], read_retry_reg_num);
        }
    	return ret;
    }
	else
    {
		PHY_ERR("NFC_SetDefaultParam, unknown read retry mode 0x%x\n", read_retry_mode);
		return 0;  ////????
    }

	return ret; 
}

__s32 NFC_ReadRetry_exit_Toshiba() //toshiba readretry exit
{
	__u32 cfg;
    __s32 ret = 0;
	__u8 default_value[64];
    __u32 i,nand_clk_bak,nand_clk_bak1;
	__u32 toggle_mode_flag = 0;

	NAND_GetClk(NandIndex, &nand_clk_bak, &nand_clk_bak1); //nand_clk_bak = NAND_GetClk(NandIndex);
	NAND_SetClk(NandIndex, 10, 10*2);

	for(i=0; i<read_retry_reg_num; i++)
	{
		default_value[i] = 0x0;
	}

	if((NDFC_READ_REG_CTL()>>18)&0x3) //change to legacy mode from toggle mode
	{
		NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()&(~(0x3<<18)));
		toggle_mode_flag = 1;
	}

	ret =_vender_set_param(default_value, &read_retry_reg_adr[0], read_retry_reg_num);

	if(toggle_mode_flag == 1) //change to toggle mode from legacy mode  after set param
		NDFC_WRITE_REG_CTL(NDFC_READ_REG_CTL()|(0x3<<18));

	/* reset ? */
	cfg = 0xFF;
	cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
	NDFC_WRITE_REG_CMD(cfg);
	ret |= _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	NAND_SetClk(NandIndex,nand_clk_bak, nand_clk_bak1);
	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return ret;
}

__s32 NFC_ReadRetry_off(__u32 chip) //sandisk readretry exit
{
	__u32 cfg;
    __s32 ret = 0;
	__u8 default_value[64];

	if((0x30 == read_retry_mode) || (0x31 == read_retry_mode))//sandisk 24nm && 19nm
	{
		cfg = 0xD6;
		cfg |= ( NDFC_SEND_CMD1);
		NDFC_WRITE_REG_CMD(cfg);
	}
	else if((0x32 == read_retry_mode)||(0x33 == read_retry_mode))
	{
		cfg = 0xFF;
		cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);//sandisk A19nm
		NDFC_WRITE_REG_CMD(cfg);
	}

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	NFC_SetDefaultParam(chip,default_value,read_retry_mode);

	return ret;
}

__s32 NFC_ReadRetry_Prefix_Sandisk_A19(void)
{
	__u32 cfg;
	__s32 ret;

	cfg = 0x25;
	cfg |= ( NDFC_SEND_CMD1);
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return 0;
}

__s32 NFC_ReadRetry_Enable_Sandisk_A19(void)
{
	__u32 cfg;
	__s32 ret;

	cfg = 0x5d;
	cfg |= ( NDFC_SEND_CMD1);
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return 0;
}


__s32 NFC_DSP_ON_Sandisk_A19(void)
{
	__u32 cfg;
	__s32 ret;

	cfg = 0x26;
	cfg |= ( NDFC_SEND_CMD1);
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return 0;
}

__s32 NFC_Test_Mode_Entry_Sandisk(void)
{
	__u32 cfg,i;
	__s32 ret;
	__u32 cmd[3]={0x5c,0xc5,0x55};
	__u8 addr;
	__u8 data;

	addr = 0x0;
	data = 0x1;

	for(i=0;i<3;i++)
    {
    	if(i==2)
		{
			/* send cmd to set param */
	        NDFC_WRITE_RAM0_B(0, data);
    		NDFC_WRITE_REG_CNT(1);
			_set_addr(&addr, 1);

    		/*set NFC_REG_CMD*/
    		cfg = cmd[i];
    		cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1);    		
    		NDFC_WRITE_REG_CMD(cfg);

	    	ret = _wait_cmdfifo_free();
	    	ret |= _wait_cmd_finish();

	    	if (ret)
	    	{
	    		_exit_nand_critical();
	    		return ret;
	    	}
		}
		else
		{
			/*set NFC_REG_CMD*/
	    	cfg = cmd[i];
	    	cfg |= (NDFC_SEND_CMD1);
	    	NDFC_WRITE_REG_CMD(cfg);

	    	ret = _wait_cmdfifo_free();
	    	ret |= _wait_cmd_finish();

	    	if (ret)
	    	{
	    		_exit_nand_critical();
	    		return ret;
	    	}
		}
    }

	return 0;
}

__s32 NFC_Test_Mode_Exit_Sandisk(void)
{
	__u32 cfg;
	__s32 ret;

	cfg = 0xFF;
	cfg |= ( NDFC_SEND_CMD1 | NDFC_WAIT_FLAG);
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return 0;
}

__s32 NFC_Change_LMFLGFIX_NEXT_Sandisk(__u8 para)
{
	__u32 cfg;
	__s32 ret;
	__u8 addr;

	addr = 0x23;

	/* send cmd to set param */
    NDFC_WRITE_RAM0_B(0, para);
	NDFC_WRITE_REG_CNT(1);
	_set_addr(&addr, 1);
			
	cfg = 0x55;
	cfg |= (NDFC_SEND_ADR | NDFC_DATA_TRANS | NDFC_ACCESS_DIR | NDFC_SEND_CMD1);
	NDFC_WRITE_REG_CMD(cfg);

	ret = _wait_cmdfifo_free();
	ret |= _wait_cmd_finish();

	if(ret)
	{
		_exit_nand_critical();
		return ret;
	}

	return 0;
}



__s32 NFC_ReadRetryExit(__u32 read_retry_type)
{
	return 0;
}


void NFC_RbIntEnable(void)
{
    //enable interrupt
	//NFC_WRITE_REG(NFC_REG_INT, NFC_READ_REG(NFC_REG_INT)|NFC_B2R_INT_ENABLE);
	NDFC_WRITE_REG_INT(NDFC_B2R_INT_ENABLE);
}

void NFC_RbIntDisable(void)
{
    //disable rb interrupt
	//NFC_WRITE_REG(NFC_REG_INT, NFC_READ_REG(NFC_REG_INT)&(~NFC_B2R_INT_ENABLE));
	NDFC_WRITE_REG_INT(0);
}

void NFC_RbIntClearStatus(void)
{
    //clear interrupt
	NDFC_WRITE_REG_ST(NDFC_RB_B2R);
}

__u32 NFC_RbIntGetStatus(void)
{
    //clear interrupt
	return (NDFC_READ_REG_ST()&NDFC_RB_B2R);
}

__u32 NFC_RbIntOccur(void)
{
	return ((NDFC_READ_REG_ST()&NDFC_RB_B2R)&&(NDFC_READ_REG_INT()&NDFC_B2R_INT_ENABLE));
}

__u32 NFC_GetRbSelect(void)
{
    return (( NDFC_READ_REG_CTL() & NDFC_RB_SEL ) >>3);
}

__u32 NFC_GetRbStatus(__u32 rb)
{
    if(rb == 0)
        return (NDFC_READ_REG_ST() & NDFC_RB_STATE0);
    else if(rb == 1)
        return (NDFC_READ_REG_ST() & NDFC_RB_STATE1);
    else
        return 0;
}

void NFC_DmaIntEnable(void)
{
    //enable interrupt
	//NFC_WRITE_REG(NFC_REG_INT, NFC_READ_REG(NFC_REG_INT)|NFC_DMA_INT_ENABLE);
	NDFC_WRITE_REG_INT(NDFC_DMA_INT_ENABLE);

}


void NFC_DmaIntDisable(void)
{
    //disable dma interrupt
	//NFC_WRITE_REG(NFC_REG_INT, NFC_READ_REG(NFC_REG_INT)&(~NFC_DMA_INT_ENABLE));
	NDFC_WRITE_REG_INT(0);
}

void NFC_DmaIntClearStatus(void)
{
    //clear interrupt
	NDFC_WRITE_REG_ST(NDFC_DMA_INT_FLAG);
}

__u32 NFC_DmaIntGetStatus(void)
{
    //clear interrupt
	return ( NDFC_READ_REG_ST()&NDFC_DMA_INT_FLAG );
}

__u32 NFC_DmaIntOccur(void)
{
	return ((NDFC_READ_REG_ST()&NDFC_DMA_INT_FLAG) && (NDFC_READ_REG_INT()&NDFC_DMA_INT_ENABLE));
}





