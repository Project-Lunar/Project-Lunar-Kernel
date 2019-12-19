/*********************************************************************************************************
*                                                                NAND FLASH DRIVER
*								(c) Copyright 2008, SoftWinners Co,Ld.
*                                          			    All Right Reserved
*file : nand_simple.c
*description : this file creates some physic basic access function based on single plane for boot .
*history :
*	v0.1  2008-03-26 Richard
* v0.2  2009-9-3 penggang modified for 1615
*			
*********************************************************************************************************/
#include "nand_type.h"
#include "nand_physic.h"
#include "nand_simple.h"
#include "nfc.h"
#include "nfc_reg.h"
#include "nand_physic_interface.h"

extern __u32 Two_Row_Addr_Flag;

extern __s32 _read_status(__u32 cmd_value, __u32 nBank);
extern void _add_cmd_list(NFC_CMD_LIST *cmd,__u32 value,__u32 addr_cycle,__u8 *addr,__u8 data_fetch_flag,
					__u8 main_data_fetch,__u32 bytecnt,__u8 wait_rb_flag);
//extern __u8 _cal_real_chip(__u32 global_bank);
extern __u8 _cal_real_rb(__u32 chip);
extern void _cal_addr_in_chip(__u32 block, __u32 page, __u32 sector,__u8 *addr, __u8 cycle);
extern void _pending_dma_irq_sem(void);
//extern void _pending_rb_irq_sem(void);
extern __u32 _cal_random_seed(__u32 page);
extern __s32 _wait_rb_ready_int(__u32 chip);

/***************************************************************************
*************************write one align single page data**************************
****************************************************************************/

__s32 _write_single_page (struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode )
{
	__s32 ret;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;
	
	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
	
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	if(SUPPORT_RANDOM)
    {
        random_seed = _cal_random_seed(writeop->page);
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
		NFC_RandomDisable();
    }
    else
    {
        ret = NFC_Write(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
    }


	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _write_single_page_first (struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode )
{
	__s32 ret = 0;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;

	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
	
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	if(SUPPORT_RANDOM)
    {
        random_seed = _cal_random_seed(writeop->page);
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write_First(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
	    //NFC_RandomDisable();
    }
    else
    {
        ret = NFC_Write_First(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
    }


	return ret;

}

__s32 _write_single_page_wait(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode )
{
	__s32 ret = 0;
	__u32 rb;

	ret = NFC_Write_Wait( NULL, writeop->mainbuf, NULL, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
	
	if(SUPPORT_RANDOM)
       NFC_RandomDisable();

	rb = _cal_real_rb(writeop->chip);
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _write_single_page_seq(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode)
{
	__s32 ret;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;

	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
	
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	if(SUPPORT_RANDOM)
	{
	    random_seed = 0x4a80;
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write_Seq(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
		NFC_RandomDisable();
	}
	else
	{
	    ret = NFC_Write_Seq(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
	}


	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _write_single_page_seq_16k(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode)
{
	__s32 ret;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;

	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
		
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	if(SUPPORT_RANDOM)
	{
	    random_seed = 0x4a80;
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write_Seq_16K(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
		NFC_RandomDisable();
	}
	else
	{
	    ret = NFC_Write_Seq_16K(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
	}


	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _write_single_page_0xff(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode)
{
	__s32 ret;
	__u32 rb;
	//__u32 random_seed;
	//__u8 *sparebuf;
	//__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;


	/*create cmd list*/
	addr_cycle = 5;

	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	NFC_RandomDisable();
	ret = NFC_Write_0xFF(cmd_list, writeop->mainbuf, NULL, dma_wait_mode, rb_wait_mode, 0);

	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();
	

	return ret;
}

__s32 _write_single_page_0xff_8K(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode)
{
	__s32 ret;
	__u32 rb;
	//__u32 random_seed;
	//__u8 *sparebuf;
	//__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;


	/*create cmd list*/
	addr_cycle = 5;

	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);
	
	NFC_RandomDisable();
	ret = NFC_Write_0xFF_8K(cmd_list, writeop->mainbuf, NULL, dma_wait_mode, rb_wait_mode, 0);

	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();
	

	return ret;
}


__s32 _write_single_page_cfg(struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode, struct boot_ndfc_cfg *cfg)
{
	__s32 ret;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;

	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
		
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	if(1)
	{
	    random_seed = 0x4a80;
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write_CFG(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE, cfg);
		NFC_RandomDisable();
	}
	else
	{
	    ret = NFC_Write_CFG(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE, cfg);
	}


	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _write_single_page_1K (struct boot_physical_param *writeop,__u32 program1,__u32 program2,__u8 dma_wait_mode, __u8 rb_wait_mode )
{
	__s32 ret;
	__u32 rb;
	__u32 random_seed;
	//__u8 *sparebuf;
	__u8 sparebuf[4*64];
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i,addr_cycle;

	MEMSET(sparebuf, 0xff, SECTOR_CNT_OF_SINGLE_PAGE * 4);
	if (writeop->oobbuf){
		MEMCPY(sparebuf,writeop->oobbuf,SECTOR_CNT_OF_SINGLE_PAGE * 4);
	}
	/*create cmd list*/
	addr_cycle = (SECTOR_CNT_OF_SINGLE_PAGE == 1)?4:5;

	if(Two_Row_Addr_Flag)
		addr_cycle = 4;
	
	/*the cammand have no corresponding feature if IGNORE was set, */
	_cal_addr_in_chip(writeop->block,writeop->page,0,addr,addr_cycle);
	_add_cmd_list(cmd_list,program1,addr_cycle,addr,NDFC_DATA_FETCH,NDFC_IGNORE,NDFC_IGNORE,NDFC_NO_WAIT_RB);
	_add_cmd_list(cmd_list + 1,0x85,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,program2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	list_len = 3;
	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(writeop->chip);

	if(1)
	{
	    random_seed = 0x4a80;
		NFC_SetRandomSeed(random_seed);
		NFC_RandomEnable();
		ret = NFC_Write_1K(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
		NFC_RandomDisable();
	}
	else
	{
	    ret = NFC_Write_1K(cmd_list, writeop->mainbuf, sparebuf, dma_wait_mode, rb_wait_mode, NDFC_PAGE_MODE);
	}


	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);
	if (dma_wait_mode)
		_pending_dma_irq_sem();

	return ret;

}

__s32 _erase_single_block(struct boot_physical_param *eraseop)
{
	__s32 ret;
	__u32 rb;
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i;

	/*create cmd list*/
	/*the cammand have no corresponding feature if IGNORE was set, */
	list_len = 2;
	_cal_addr_in_chip(eraseop->block,0,0,addr,3);
	if(Two_Row_Addr_Flag)
		_add_cmd_list(cmd_list,0x60,2,addr,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	else
		_add_cmd_list(cmd_list,0x60,3,addr,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 1,0xd0,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);

	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}

	rb = _cal_real_rb(eraseop->chip);
	NFC_SelectChip(eraseop->chip);
	NFC_SelectRb(rb);

	_wait_rb_ready_int(eraseop->chip);
	
	ret = NFC_Erase(cmd_list, 0);
	NFC_DeSelectChip(eraseop->chip);
	NFC_DeSelectRb(rb);
	return ret;
}

__s32 _check_badblock_sandisk(struct boot_physical_param *checkop)
{
	__s32 ret;
	__u32 rb;
	__s32 status;
	__u8 addr[5];
	NFC_CMD_LIST cmd_list[4];
	__u32 list_len,i;

	/*create cmd list*/
	/*the cammand have no corresponding feature if IGNORE was set, */
	#if 1
	list_len = 3;
	_cal_addr_in_chip(checkop->block,checkop->page,0,addr,5);
	_add_cmd_list(cmd_list,0xA2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 1,0x80,5,addr,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	_add_cmd_list(cmd_list + 2,0x10,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_WAIT_RB);
	#endif
	//list_len = 2;
	//_cal_addr_in_chip(checkop->block,checkop->page,0,addr,5);
	//_add_cmd_list(cmd_list,0xA2,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	//_add_cmd_list(cmd_list + 0,0x80,5,addr,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE);
	//_add_cmd_list(cmd_list + 1,0x10,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_IGNORE,NDFC_WAIT_RB);

	for(i = 0; i < list_len - 1; i++){
		cmd_list[i].next = &(cmd_list[i+1]);
	}

	rb = _cal_real_rb(checkop->chip);
	NFC_SelectChip(checkop->chip);
	NFC_SelectRb(rb);
	
	ret = NFC_CheckBadBlock_Sandisk(cmd_list);
	
	/*get status*/
	while(1){
		status = _read_status(0x70,checkop->chip);
		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -ERR_NANDFAIL;

	NFC_DeSelectChip(checkop->chip);
	NFC_DeSelectRb(rb);
	return ret;
}


__s32 PHY_SimpleWrite(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_CurCH(struct boot_physical_param * writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	//NandIndex = 0;

	ret = _write_single_page(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}


__s32 PHY_SimpleWrite_Seq(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page_seq(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_Seq_16K(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page_seq_16k(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_0xFF(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page_0xff(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_0xFF_8K(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page_0xff_8K(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_CFG(struct boot_physical_param *writeop, struct boot_ndfc_cfg *cfg)
{
	__s32 status;
	__u32 rb;

	__s32 ret;

	NandIndex = 0;

	ret = _write_single_page_cfg(writeop,0x80,0x10,0,0, cfg);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
	{
		ret = -2;
		PRINT("write fail\n");
	}
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_1K(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	NandIndex = 0;

	ret = _write_single_page_1K(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleWrite_1KCurCH(struct boot_physical_param *writeop)
{
	__s32 status;
	__u32 rb;

	__s32 ret;
	
	//NandIndex = 0;

	ret = _write_single_page_1K(writeop,0x80,0x10,0,0);
	if (ret)
		return -1;
	rb = _cal_real_rb(writeop->chip);
	NFC_SelectChip(writeop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,writeop->chip);
		if (status < 0)
			return status;

		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;
	NFC_DeSelectChip(writeop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}


//#pragma arm section code="PHY_SimpleErase"
__s32 PHY_SimpleErase(struct boot_physical_param *eraseop )
{
	__s32 status;
	__s32 ret = 0;
	__u32 rb;

	NandIndex = 0;
	ret = _erase_single_block(eraseop);
	if (ret)
		return -1;
	rb = _cal_real_rb(eraseop->chip);
	NFC_SelectChip(eraseop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,eraseop->chip);
		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;

	NFC_DeSelectChip(eraseop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}

__s32 PHY_SimpleErase_CurCH(struct boot_physical_param *eraseop )
{
	__s32 status;
	__s32 ret = 0;
	__u32 rb;

	//NandIndex = 0;
	ret = _erase_single_block(eraseop);
	if (ret)
		return -1;
	rb = _cal_real_rb(eraseop->chip);
	NFC_SelectChip(eraseop->chip);
	NFC_SelectRb(rb);
	/*get status*/
	while(1){
		status = _read_status(0x70,eraseop->chip);
		if (status & NAND_STATUS_READY)
			break;
	}
	if (status & NAND_OPERATE_FAIL)
		ret = -2;

	NFC_DeSelectChip(eraseop->chip);
	NFC_DeSelectRb(rb);

	return ret;
}


__s32 PHY_SimpleErase_2CH(struct boot_physical_param *eraseop )
{
	__s32 status;
	__s32 ret = 0;
	__u32 rb;
	__u32 err_flag = 0;

	for(NandIndex = 0; NandIndex<CHANNEL_CNT;NandIndex++)
	{
		//PHY_DBG("[PHY_DBG]%s: ch: %d  chip: %d  block: 0x%x\n", __func__, NandIndex, eraseop->chip, eraseop->block);

		ret = _erase_single_block(eraseop);
		if (ret) {
			//PHY_ERR("[PHY_ERR]%s: erase fail: ch:%d, chip:%d, block:0x%x\n", __func__, NandIndex, eraseop->chip, eraseop->block);
			err_flag = 1;
			//return -1;
		}
		rb = _cal_real_rb(eraseop->chip);
		NFC_SelectChip(eraseop->chip);
		NFC_SelectRb(rb);
		/*get status*/
		while(1){
			status = _read_status(0x70,eraseop->chip);
			if (status & NAND_STATUS_READY)
				break;
		}
		if (status & NAND_OPERATE_FAIL) {
			//PHY_ERR("[PHY_ERR]%s: erase fail: ch:%d, chip:%d, block:0x%x\n", __func__, NandIndex, eraseop->chip, eraseop->block);
			err_flag = 1;
			//return -2; //ret = -2;
		}

		NFC_DeSelectChip(eraseop->chip);
		NFC_DeSelectRb(rb);

		if(NandIndex == (CHANNEL_CNT-1))
			break;
	}

	NandIndex = 0;

	return err_flag ? -1 : 0;
}


