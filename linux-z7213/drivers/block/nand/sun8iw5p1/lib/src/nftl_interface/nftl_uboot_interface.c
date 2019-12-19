
#define _NFTL_UBOOT_INTERFACE_C_

#include "../nftl_interface/nftl_blk.h"
#include "../phy/phy.h"
#include "../nftl/nftl_inc.h"

struct _nftl_blk nftl_blk_head = {0};

extern struct _nand_partition* build_nand_partition(struct _nand_phy_partition* phy_partition);
extern int free_nand_partition(struct _nand_partition*nand_partition);

int _nand_read(struct _nftl_blk *nftl_blk,uint32 start_sector,uint32 len,unsigned char *buf);
int _nand_write(struct _nftl_blk *nftl_blk,uint32 start_sector,uint32 len,unsigned char *buf);
int _nand_flush_write_cache(struct _nftl_blk *nftl_blk,uint32 num);
uint32 nftl_flush_write_cache(void);
int recovery_panic_data(struct _nftl_blk *nftl_blk);

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nftl_build_all(struct _nand_info*nand_info)
{
	struct _nand_phy_partition*  phy_partition;

	phy_partition = nand_info->phy_partition_head;

    nftl_blk_head.nftl_blk_next = NULL;
	while(phy_partition != NULL)
	{
		if(nftl_add(phy_partition) == NULL)
		{
			NFTL_ERR("[NE]nftl_build_all error!\n");
			return NFTL_FAILURE;
		}
		phy_partition = phy_partition->next_phy_partition;
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
int nftl_build_one(struct _nand_info*nand_info,uint32 num)
{
	struct _nand_phy_partition*  phy_partition;

	phy_partition = nand_info->phy_partition_head;

	if(num == 0)
	    nftl_blk_head.nftl_blk_next = NULL;

	while(phy_partition != NULL)
	{
	    if(phy_partition->PartitionNO == num)
	    {
		    if(nftl_add(phy_partition) == NULL)
		    {
			    NFTL_ERR("[NE]nftl_build_all error!\n");
			    return NFTL_FAILURE;
		    }
		}
		phy_partition = phy_partition->next_phy_partition;
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
struct _nftl_blk * nftl_add(struct _nand_phy_partition* phy_partition)
{
    struct _nftl_blk *nftl_blk;

    nftl_blk = nftl_malloc(sizeof(struct _nftl_blk));
    if (!nftl_blk)
    {
        NFTL_ERR("[NE]====no memory!!!!!=====\n");
        return NULL;
    }

     nftl_blk->nand = build_nand_partition(phy_partition);

//    nftl_blk->nftl_lock = nftl_malloc(sizeof(struct mutex));
//    if (!nftl_blk->nftl_lock)
//        return;

//    mutex_init(nftl_blk->nftl_lock);

//    nftl_blk->nb.notifier_call = nftl_reboot_notifier;
////  nftl_blk->nb.priority = 1;
//    nftl_blk->reboot_flag = 0;
//    register_reboot_notifier(&nftl_blk->nb);
//    nftl_blk->time_flush = NFTL_FLUSH_DATA_TIME * HZ;
    if (nftl_initialize(nftl_blk,phy_partition->PartitionNO)){
        NFTL_ERR("[NE]nftl_initialize failed\n");
        return NULL;
    }

//    nftl_blk->nftl_thread = kthread_run(nftl_thread, nftl_blk, "%sd", "nftl");
//    if (IS_ERR(nftl_blk->nftl_thread))
//        return;

    add_nftl_blk_list(&nftl_blk_head,nftl_blk);
    
    recovery_panic_data(nftl_blk);
    nftl_blk->flush_write_cache(nftl_blk,0xffff);
    
    NFTL_DBG("[ND]nftl_add ok\n");
    return nftl_blk;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_ftl_exit(void)
{
    struct _nftl_blk *nftl_blk;

    nftl_blk = del_last_nftl_blk(&nftl_blk_head);
    while(nftl_blk != NULL)
    {
        nftl_exit(nftl_blk);
        nftl_free(nftl_blk);
        nftl_blk = del_last_nftl_blk(&nftl_blk_head);
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
void print_all_nftl_blk(void)
{
    struct _nftl_blk * p;

    p = &nftl_blk_head;
    while(p->nftl_blk_next != NULL)
    {
        NFTL_DBG("[ND]cap: 0x%08x.\n",p->nftl_blk_next->nftl_logic_size);
        p = p->nftl_blk_next;
    }
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_nftl_num(void)
{
    uint32 num = 0;

    struct _nftl_blk * p;

    p = &nftl_blk_head;
    while(p->nftl_blk_next != NULL)
    {
		num++;
        p = p->nftl_blk_next;
    }
	return num;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_nftl_cap(void)
{
	uint32 cap = 0;
    struct _nftl_blk * p;

    p = &nftl_blk_head;
    while(p->nftl_blk_next != NULL)
    {
		cap += p->nftl_blk_next->nftl_logic_size;
        p = p->nftl_blk_next;
    }
	return cap;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_first_nftl_cap(void)
{
	uint32 cap = 0;
    struct _nftl_blk * p;
    p = &nftl_blk_head;
    return p->nftl_blk_next->nftl_logic_size;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 nftl_read(uint32 start_sector,uint32 len,unsigned char *buf)
{
    struct _nftl_blk *nftl_blk;
    nftl_blk = nftl_blk_head.nftl_blk_next;

    if(len == 0)
    {
        return 0;
    }

    while(start_sector >= nftl_blk->nftl_logic_size)
    {
        start_sector -= nftl_blk->nftl_logic_size;
        nftl_blk = nftl_blk->nftl_blk_next;
        if(nftl_blk == NULL)
        {
            NFTL_ERR("[NE]parameter error %d,%d !\n",start_sector,len);
            return NFTL_FAILURE;
        }
    }

    return nftl_blk->read_data(nftl_blk,start_sector,len,buf);
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 nftl_write(uint32 start_sector,uint32 len,unsigned char *buf)
{
    struct _nftl_blk *nftl_blk;
    nftl_blk = nftl_blk_head.nftl_blk_next;

    if(len == 0)
    {
        return 0;
    }

    while(start_sector >= nftl_blk->nftl_logic_size)
    {
        start_sector -= nftl_blk->nftl_logic_size;
        nftl_blk = nftl_blk->nftl_blk_next;
        if(nftl_blk == NULL)
        {
            NFTL_ERR("[NE]parameter error %d,%d !\n",start_sector,len);
            return NFTL_FAILURE;
        }
    }

    return nftl_blk->write_data(nftl_blk,start_sector,len,buf);
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 nftl_discard(uint32 start_sector,uint32 len)
{
    struct _nftl_blk *nftl_blk;
    nftl_blk = nftl_blk_head.nftl_blk_next;

    if(len == 0)
    {
        return 0;
    }

    while(start_sector >= nftl_blk->nftl_logic_size)
    {
        start_sector -= nftl_blk->nftl_logic_size;
        nftl_blk = nftl_blk->nftl_blk_next;
        if(nftl_blk == NULL)
        {
            NFTL_ERR("[NE]parameter error %d,%d !\n",start_sector,len);
            return NFTL_FAILURE;
        }
    }

    return nftl_blk->discard(nftl_blk,start_sector,len);
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 nftl_flush_write_cache(void)
{
    struct _nftl_blk *nftl_blk;
    nftl_blk = nftl_blk_head.nftl_blk_next;

    while(nftl_blk != NULL)
    {
        nftl_blk->flush_write_cache(nftl_blk,0xffff);
        nftl_blk = nftl_blk->nftl_blk_next;
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
int recovery_panic_data(struct _nftl_blk *nftl_blk)
{
    int ret;
    uchar* page_buf;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uint32 start_sector,i,j,total_len,data_pages,spare_sector;
    uint16 erase_num;
    struct _nftl_zone * zone;

    zone = nftl_blk->nftl_zone;

    if(zone->panic_data.data_block_nums != zone->panic_data.block_nums)
    {
        NFTL_ERR("[ND]data_block_nums %d block_nums %d!!\n",zone->panic_data.data_block_nums,zone->panic_data.block_nums);
        for(i=0; i<MAX_PANIC_BLOCK_NUM; i++)
        {
            if(zone->panic_data.block[i] != NULL)
            {
                NFTL_ERR("[ND]erase panic block %d!\n",zone->panic_data.block[i]->phy_block.Block_NO);
                erase_num = zone->panic_data.block[i]->erase_count + 1;
                erase_block(zone,zone->panic_data.block[i],erase_num);
            }
        }
        return 1;
    }

    if(zone->panic_data.data_block_nums == 0)
    {
        NFTL_ERR("[ND]not find panic data!\n");
        return 0;
    }

    NFTL_ERR("[ND]recovery_panic_data start!\n");
    NFTL_ERR("[ND]logic_addr :%d sector_nums: %d!\n",zone->panic_data.logic_addr,zone->panic_data.sector_nums);
    NFTL_ERR("[ND]data_block_nums %d !\n",zone->panic_data.data_block_nums);
    for(i=0; i<zone->panic_data.data_block_nums; i++)
    {
        NFTL_ERR("[ND]block %d !\n",zone->panic_data.block[i]->phy_block.Block_NO);
    }

    page_buf = (uchar *)nftl_malloc(zone->nand_chip->bytes_per_page);

    total_len = 0;
    start_sector = zone->panic_data.logic_addr;

    data_pages = zone->panic_data.sector_nums / zone->nand_chip->sector_per_page;
    spare_sector = 0;
    if((zone->panic_data.sector_nums % zone->nand_chip->sector_per_page) != 0)
    {
        data_pages++;
        spare_sector = zone->panic_data.sector_nums % zone->nand_chip->sector_per_page;
    }

    for(i=0; i<zone->panic_data.data_block_nums; i++)
    {
        if(data_pages == 0)
        {
            break;
        }
        for(j=0; j<zone->nand_chip->pages_per_blk; j++)
        {
            set_physic_op_par(&phy_op_par,zone->panic_data.block[i]->phy_block.Block_NO,j,zone->nand_chip->bitmap_per_page,page_buf,spare_data);
            ret = zone->nftl_nand_read_page(zone,&phy_op_par);
            
            NFTL_ERR("[ND]read painc data block:%d page: %d  data:%d %d %d %d !\n",zone->panic_data.block[i]->phy_block.Block_NO,j,page_buf[0],page_buf[1],page_buf[2],page_buf[3]);
            
            if((data_pages == 1)&& (spare_sector != 0))
            {
                ret = nftl_write(start_sector,spare_sector,page_buf);
            }
            else
            {
                ret = nftl_write(start_sector,zone->nand_chip->sector_per_page,page_buf);
            }

            start_sector += zone->nand_chip->sector_per_page;
            data_pages--;
            if(data_pages == 0)
            {
                 break;
            }
        }
    }

    for(i=0; i<zone->panic_data.data_block_nums; i++)
    {
        erase_num = zone->panic_data.block[i]->erase_count + 1;
        erase_block(zone,zone->panic_data.block[i],erase_num);
    }

    nftl_free(page_buf);

    return ret;
}
