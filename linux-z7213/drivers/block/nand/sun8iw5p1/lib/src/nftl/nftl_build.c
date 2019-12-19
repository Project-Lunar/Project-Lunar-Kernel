
/*
 * allwinner nftl init
 *
 * (C) 2008
 */

#define _NFTL_BUILD_C_

#include "nftl_inc.h"
#include "../nftl_interface/nftl_cfg.h"
#include "../physic/nand_physic_interface.h"
#include "../physic/nand_physic.h"

struct  _nand_rebuild_cache{
    uint32        max_page;
    uint32        cache_used[512];
    uchar*        cache_addr[512];
};

uint32 get_used_page_num(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32 *ecc,struct _nand_rebuild_cache*nrc);
uint32 get_used_page_num_no_crosstalk(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32 *ecc,struct _nand_rebuild_cache* nrc);
uint32 check_cross_talk(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr);

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int zone_param_init(struct _nftl_zone *zone,uint16 start_block,uint32 logic_sects,uint32 backup_cap_in_sects)
{
    uint32 i,total_pages;

    zone->temp_page_buf = (uchar *)nftl_malloc(zone->nand_chip->bytes_per_page);
    if (zone->temp_page_buf == NULL){
        NFTL_ERR("[NE] zone_param_init error1\n");
        return -ENOMEM;
    }

    zone->logic_page_buf = (uchar *)nftl_malloc(zone->nand_chip->bytes_per_page);
    if (zone->logic_page_buf == NULL){
        NFTL_ERR("[NE] zone_param_init error1\n");
        return -ENOMEM;
    }

    zone->logic_cap_in_sects = logic_sects;
    zone->backup_cap_in_sects = backup_cap_in_sects;
    zone->zone_start_blk_NO.Block_NO = start_block;
    zone->zone_start_phy_block = get_phy_block_addr(zone,start_block);

    zone->blocks = 0;
    zone->bad_block = 0;
    zone->free_block_num = 0;
    zone->zone_end_phy_block = NULL;

    total_pages = zone->logic_cap_in_sects / zone->nand_chip->sector_per_page;
    if( malloc_logic_page_map(zone,total_pages) != 0)
    {
        NFTL_ERR("[NE] zone_param_init error2\n");
        return -ENOMEM;
    }

    zone->current_block.user_info.map_size = zone->nand_chip->pages_per_blk << 2;
    zone->current_block.user_info.smart_size = 320;
    zone->current_block.user_info.buf_size = zone->current_block.user_info.map_size + zone->current_block.user_info.smart_size;
    zone->current_block.user_info.buf = (uint32*)nftl_malloc(zone->current_block.user_info.buf_size);
    if (zone->current_block.user_info.buf == NULL)
    {
        NFTL_ERR("[NE] zone_param_init error3\n");
        return -ENOMEM;
    }

    zone->current_block.user_info.map_data = zone->current_block.user_info.buf;
    zone->current_block.user_info.smart = zone->current_block.user_info.buf + zone->current_block.user_info.map_size;
    zone->smart = zone->current_block.user_info.smart;
    MEMSET(zone->current_block.user_info.buf,0xff,zone->current_block.user_info.buf_size);

    zone->assist_block.user_info.map_size = zone->current_block.user_info.map_size;
    zone->current_block.user_info.smart_size = zone->current_block.user_info.smart_size;
    zone->assist_block.user_info.buf_size = zone->current_block.user_info.buf_size;
    zone->assist_block.user_info.buf = (uint32*)nftl_malloc(zone->assist_block.user_info.buf_size);
    if (zone->assist_block.user_info.buf == NULL)
    {
        NFTL_ERR("[NE] zone_param_init error4\n");
        return -ENOMEM;
    }
    zone->assist_block.user_info.map_data = zone->assist_block.user_info.buf;
    zone->assist_block.user_info.smart = zone->assist_block.user_info.buf + zone->assist_block.user_info.map_size;
    MEMSET(zone->assist_block.user_info.buf,0xff,zone->assist_block.user_info.buf_size);

    zone->zone_phy_page_map_for_gc.map_size = zone->current_block.user_info.map_size;
    zone->zone_phy_page_map_for_gc.smart_size = zone->current_block.user_info.smart_size;
    zone->zone_phy_page_map_for_gc.buf_size = zone->current_block.user_info.buf_size;
    zone->zone_phy_page_map_for_gc.buf = (uint32*)nftl_malloc(zone->zone_phy_page_map_for_gc.buf_size);
    if (zone->zone_phy_page_map_for_gc.buf == NULL)
    {
        NFTL_ERR("[NE] zone_param_init error5\n");
        return -ENOMEM;
    }

    zone->zone_phy_page_map_for_gc.map_data = zone->zone_phy_page_map_for_gc.buf;
    zone->zone_phy_page_map_for_gc.smart = zone->zone_phy_page_map_for_gc.buf + zone->zone_phy_page_map_for_gc.map_size;

//  zone->prio_gc.zone_phy_page_map_for_prio = (_phy_page_mapping*)nftl_malloc(sizeof(_phy_page_mapping));
//  if (zone->prio_gc.zone_phy_page_map_for_prio == NULL)
//      return -ENOMEM;
    zone->test = 0;
    zone->max_erase_num = 0;
    zone->read_reclaim_complete = 0;
    zone->already_read_flag = 0;
    zone->s_wl.erase_threshold = zone->nand_chip->max_erase_times >> 1;
    zone->s_wl.erase_span  = zone->nand_chip->max_erase_times / 6;
//    if(zone->s_wl.erase_span > 80)
//    {
//        zone->s_wl.erase_span = 80;
//    }
    zone->s_wl.s_wl_status = WL_STOP;
    zone->s_wl.s_wl_start = 0;
    zone->s_wl.block_for_s_wl = NULL;

    zone->current_block.block_info = NULL;
	zone->current_block.page_used = 0xffff;
	//zone->current_block.block_info->block_used_count = 0xffffffff;

    zone->assist_block.block_info = NULL;
	zone->assist_block.page_used = 0xffff;
	//zone->assist_block.block_info->block_used_count = 0xffffffff;

    zone->free_head.free_next = NULL;
    zone->free_head.free_prev = NULL;
    zone->free_head.invalid_page_next = NULL;
    zone->free_head.invalid_page_prev = NULL;
    zone->free_head.block_used_next = NULL;
    zone->free_head.block_used_prev = NULL;

    zone->invalid_page_head.free_next = NULL;
    zone->invalid_page_head.free_prev = NULL;
    zone->invalid_page_head.invalid_page_next = NULL;
    zone->invalid_page_head.invalid_page_prev = NULL;
    zone->invalid_page_head.block_used_next = NULL;
    zone->invalid_page_head.block_used_prev = NULL;

    zone->block_used_head.free_next = NULL;
    zone->block_used_head.free_prev = NULL;
    zone->block_used_head.invalid_page_next = NULL;
    zone->block_used_head.invalid_page_prev = NULL;
    zone->block_used_head.block_used_next = NULL;
    zone->block_used_head.block_used_prev = NULL;

    zone->prio_gc.gc_num = 0;
    for(i=0; i<MAX_PRIO_GC_NUM; i++)
    {
        zone->prio_gc.prio_gc_node[i].gc_no = i;
        zone->prio_gc.prio_gc_node[i].prio_type = PRIO_NONE;
        zone->prio_gc.prio_gc_node[i].phy_block_info = NULL;
        zone->prio_gc.prio_gc_node[i].prio_gc_next = NULL;
        zone->prio_gc.prio_gc_node[i].prio_gc_prev = NULL;
    }

    zone->prio_gc.prio_gc_head.gc_no = 0xff;
    zone->prio_gc.prio_type_now = PRIO_NONE;
    zone->prio_gc.prio_gc_head.prio_type = PRIO_NONE;
    zone->prio_gc.prio_gc_head.phy_block_info = NULL;
    zone->prio_gc.prio_gc_head.prio_gc_next = NULL;
    zone->prio_gc.prio_gc_head.prio_gc_prev = NULL;

    for(i=0; i<MAX_PANIC_BLOCK_NUM; i++)
    {
        zone->panic_data.block[i] = NULL;
    }
    zone->panic_data.logic_addr = 0;
    zone->panic_data.sector_nums = 0;
    zone->panic_data.block_nums = 0;
    zone->panic_data.data_block_nums = 0;
//  nftl_ops_init(zone);

    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int zone_param_exit(struct _nftl_zone *zone)
{
    free_logic_page_map(zone);
    nftl_free(zone->zone_phy_page_map_for_gc.buf);
    nftl_free(zone->current_block.user_info.buf);
	nftl_free(zone->assist_block.user_info.buf);
    nftl_free(zone->temp_page_buf);
    nftl_free(zone->logic_page_buf);
    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 is_no_use_device(struct _nftl_zone * zone,uint32 size)
{
    uint32 total_blocks,nsize;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _phy_block_info* p_phy_block_info;

    p_phy_block_info = zone->zone_start_phy_block;

    if(zone->logic_cap_in_sects != 0)
    {
        //���zoneָ��������
        total_blocks = (zone->logic_cap_in_sects+zone->backup_cap_in_sects) / zone->nand_chip->sector_per_page;
        total_blocks /= zone->nand_chip->pages_per_blk;
    }
    else
    {
        total_blocks = 0xffffffff;
    }

    for(zone->blocks=0; zone->blocks<total_blocks; p_phy_block_info++)
    {
        zone->zone_end_phy_block = p_phy_block_info;
        set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        if(zone->nftl_nand_is_blk_good(zone,&phy_op_par) == NFTL_YES)
        {
            //�������û����������flash����һ���ÿ�Ӧ���ǻ�����
            zone->nftl_nand_read_page(zone,&phy_op_par);
//          NFTL_ERR("[NE]block no:%d;spare data :%x,%x,%x,%x\n",p_phy_block_info->phy_block.Block_NO,spare_data[0],spare_data[1],spare_data[2],spare_data[3]);
            if(is_ftl_start_flag_page(spare_data) == NFTL_YES)
            {
                nsize = get_spare_data(spare_data,SPARE_OFFSET_NFTL_SIZE,sizeof(nsize));
                if(nsize != size)
                {
                    NFTL_ERR("[NE]mtd size changed !\n");
                    return NFTL_YES;
                }
                zone->zone_start_phy_block = (p_phy_block_info +1);
                return NFTL_NO;
            }
            else
            {
                return NFTL_YES;
            }
        }
        else
        {
            //����
            p_phy_block_info->info = BLOCK_IS_BAD;
//          zone->nand_chip->nand_mark_bad_blk(zone,&phy_op_par);
        }
        zone->blocks++;

        if(is_last_phy_block(p_phy_block_info,zone)==NFTL_YES)
        {
            break;
        }
    }
    return NFTL_YES;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_vaild_blocks(struct _nftl_zone * zone,uint32 start_block,uint32 blocks)
{
    uint32 total_blocks,i,num;
    _physic_op_par phy_op_par;
    _phy_block_info* p_phy_block_info;

    p_phy_block_info = (_phy_block_info*)(&zone->nand_chip->nand_block_info[start_block]);
    num = blocks - start_block;
    total_blocks = num;

    for(i=start_block; i<num; i++)
    {
        phy_op_par.phy_page.Block_NO = p_phy_block_info->phy_block.Block_NO;
        if(zone->nftl_nand_is_blk_good(zone,&phy_op_par) == FACTORY_BAD_BLOCK_ERROR)
        {
            total_blocks--;
            if(total_blocks == 0)
            {
                return 0;
            }
        }
        if(is_last_phy_block(p_phy_block_info,zone)==NFTL_YES)
        {
            break;
        }
        p_phy_block_info++;
    }
    return total_blocks;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 build_zone_list_first(struct _nftl_zone * zone,uint32 size)
{
    uint32 ret,total_blocks,i;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _phy_block_info* p_phy_block_info;

    NFTL_DBG("[ND]build_zone_list_first.\n");

    p_phy_block_info = zone->zone_start_phy_block;

    if(zone->logic_cap_in_sects != 0)
    {
        //���zoneָ��������
        total_blocks = (zone->logic_cap_in_sects+zone->backup_cap_in_sects) / zone->nand_chip->sector_per_page;
        total_blocks /= zone->nand_chip->pages_per_blk;
    }
    else
    {
        total_blocks = 0xffffffff;
    }

    for(zone->blocks=0; zone->blocks<total_blocks; p_phy_block_info++)
    {
        zone->zone_end_phy_block = p_phy_block_info;
        set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        if(zone->nftl_nand_is_blk_good(zone,&phy_op_par) == NFTL_YES)
        {
            //�ÿ�
            ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
            if(ret != 0)
            {
                //����
                p_phy_block_info->info = BLOCK_IS_BAD;
                zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
            }
            else
            {
                zone->blocks++;
                p_phy_block_info->info = BLOCK_NO_USED;
                p_phy_block_info->erase_count = 0;
                if(zone->blocks == 1)
                {
                    MEMSET((void*) spare_data,0xff,BYTES_OF_USER_PER_PAGE);
                    set_start_block_flag(zone,spare_data,size);
                    set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
                    for(i=0;i<zone->nand_chip->pages_per_blk;i++)
                    {
                        zone->nftl_nand_write_page(zone,&phy_op_par);
                        phy_op_par.phy_page.Page_NO++;
                    }
                    zone->zone_start_phy_block = p_phy_block_info + 1;
                }
            }
        }
        else
        {
            //����
            p_phy_block_info->info = BLOCK_IS_BAD;
        }
        p_phy_block_info->invalid_page_count = 0xffff;
        p_phy_block_info->free_next = NULL;
        p_phy_block_info->invalid_page_next = NULL;
        p_phy_block_info->invalid_page_prev = NULL;
        zone->zone_end_phy_block = p_phy_block_info;
        if(is_last_phy_block(p_phy_block_info,zone)==NFTL_YES)
        {
            break;
        }
    }

    if(zone->blocks > 1)
    {
        zone->blocks -= 1;
    }
    else
    {
        NFTL_ERR("[NE]no block %d\n",zone->blocks);
        return NFTL_FAILURE;
    }

    //��������һ��zone,���ü��½������
    if(total_blocks == 0xffffffff)
    {
        return NFTL_SUCCESS;
    }

    if(is_last_phy_block(p_phy_block_info,zone)==NFTL_YES)
    {
        return NFTL_SUCCESS;
    }

    //�ڽ�������block��,����zone�������
    for(; p_phy_block_info->phy_block.Block_NO < zone->nand_chip->blk_per_chip; p_phy_block_info++)
    {
        set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        if(zone->nftl_nand_is_blk_good(zone,&phy_op_par) == NFTL_YES)
        {
            //�ÿ�
            ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
            if(ret != 0)
            {
                //����
                p_phy_block_info->info = BLOCK_IS_BAD;
                zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
            }
            else
            {
                MEMSET((void*) spare_data,0xff,BYTES_OF_USER_PER_PAGE);
                set_end_block_flag(zone,spare_data);
                set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
                zone->nftl_nand_write_page(zone,&phy_op_par);
                break;
            }
        }
        else
        {
            //����
            p_phy_block_info->info = BLOCK_IS_BAD;
        }
    }
    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 build_zone_list(struct _nftl_zone * zone)
{
    uint32 ret;

    NFTL_DBG("[ND]first\n");
    first_scan_all_blocks(zone);

    //��ʼ��
    ret = init_zone_after_first_scan(zone,zone->blocks);
    if(ret != NFTL_SUCCESS)
    {
        NFTL_ERR("[NE]init_zone_after_first_scan error\n");
        return NFTL_FAILURE;
    }

    //�ڶ���ɨ��block,ֻɨ��blockʹ���Ⱥ������е�block
    ret = second_scan_all_blocks(zone);
    if(ret != NFTL_SUCCESS)
    {
        NFTL_ERR("[NE]second_scan_all_blocks error\n");
        return NFTL_FAILURE;
    }

    //print_free_list(zone);
//    print_block_invalid_list(zone);
    print_nftl_zone(zone);
    NFTL_ERR("[ND]nftl ok!\n");

    backup_panic_block(zone);

    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 first_scan_all_blocks(struct _nftl_zone * zone)
{
    uint32 block_used_count,ret,index;
	uint32 last_erase_count = 0;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _phy_block_info* p_phy_block_info;

    p_phy_block_info = zone->zone_start_phy_block;

    //NFTL_ERR("[NE] first_scan_all_blocks! %d!\n",zone->nand_chip->blk_per_chip);

    //��һ��ɨ��block
    for(zone->blocks = 0; p_phy_block_info->phy_block.Block_NO < zone->nand_chip->blk_per_chip; p_phy_block_info++)
    {
        //NFTL_ERR("[NE]block no: %d\n",p_phy_block_info->phy_block.Block_NO);
        set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,0,0,NULL,spare_data);
        if(zone->nftl_nand_is_blk_good(zone,&phy_op_par) == NFTL_YES) //�ÿ�
        {
            ret = zone->nftl_nand_read_page(zone,&phy_op_par);
            //NFTL_ERR("[NE]block: %d page: [0x%2x],[0x%2x],[0x%2x],[0x%2x] erase:[0x%2x],[0x%2x]count:[0x%2x],[0x%2x],[0x%2x],[0x%2x]\n",phy_op_par.phy_page.Block_NO,spare_data[0],spare_data[1],spare_data[2],spare_data[3],spare_data[4],spare_data[5],spare_data[6],spare_data[7],spare_data[8],spare_data[9]);

            zone->zone_end_phy_block = p_phy_block_info;
            block_used_count = get_block_used_count_from_oob(spare_data);
            // 1:���ǲ�������飬�������Ļ�����
            if(is_ftl_end_flag_page(spare_data) == NFTL_YES)
            {
                NFTL_ERR("[NE] ftl end block! %d!\n",p_phy_block_info->phy_block.Block_NO);
                break;
            }
            else if(is_panic_block_flag_page(spare_data) == NFTL_YES)
            {
                NFTL_ERR("[NE] panic write data !!!!\n");
                if(spare_data[SPARE_OFFSET_PANIC_NFTL] == zone->zone_no)
                {
                    index = spare_data[SPARE_OFFSET_PANIC_BLOCK_NO];
                    if(index < MAX_PANIC_BLOCK_NUM)
                    {
                        zone->panic_data.block[index] = p_phy_block_info;
                        zone->panic_data.block_nums++;
                    }
                    if(index == 0)
                    {
                        zone->panic_data.data_block_nums = spare_data[SPARE_OFFSET_PANIC_DATA_BLOCK_NUM];

                        zone->panic_data.sector_nums = spare_data[SPARE_OFFSET_PANIC_DATA_SECTORS];
                        zone->panic_data.sector_nums <<= 8;
                        zone->panic_data.sector_nums += spare_data[SPARE_OFFSET_PANIC_DATA_SECTORS+1];

                        zone->panic_data.logic_addr = spare_data[SPARE_OFFSET_PANIC_DATA_ADDR];
                        zone->panic_data.logic_addr <<= 8;
                        zone->panic_data.logic_addr += spare_data[SPARE_OFFSET_PANIC_DATA_ADDR+1];
                        zone->panic_data.logic_addr <<= 8;
                        zone->panic_data.logic_addr += spare_data[SPARE_OFFSET_PANIC_DATA_ADDR+2];
                        zone->panic_data.logic_addr <<= 8;
                        zone->panic_data.logic_addr += spare_data[SPARE_OFFSET_PANIC_DATA_ADDR+3];
                    }
                }
                NFTL_ERR("[ND]data_block_nums :%d !\n",zone->panic_data.data_block_nums);
                NFTL_ERR("[ND]sector_nums %d !\n",zone->panic_data.sector_nums);
                NFTL_ERR("[ND]logic_addr %d !\n",zone->panic_data.logic_addr);
                NFTL_ERR("[ND]block_nums %d !\n",zone->panic_data.block_nums);
				NFTL_ERR("[ND]block: %d !\n",phy_op_par.phy_page.Block_NO);
            }
            //2:�����û��д����block������free list
            else if(is_nouse_page(spare_data) == NFTL_YES)
            {
                zone->blocks++;
                p_phy_block_info->info = BLOCK_NO_USED;
                p_phy_block_info->erase_count = 0;
                p_phy_block_info->invalid_page_count = 0;
                put_phy_block_to_free_list(zone,p_phy_block_info);
            }
            //3:����block����blockʹ���Ⱥ�����
            else if(((is_ftl_logic_page_data(spare_data) == NFTL_YES) || (is_function_info_page(spare_data) == NFTL_YES)) && ((ret == 0)||(ret == ECC_LIMIT)) )   //����Чlogic page��ַ
            {
                zone->blocks++;
                p_phy_block_info->info = BLOCK_HAVE_USED;
                p_phy_block_info->erase_count = get_erase_count_from_oob(spare_data);
				last_erase_count = p_phy_block_info->erase_count;
                p_phy_block_info->invalid_page_count = 0;
                p_phy_block_info->block_used_count = block_used_count;
                p_phy_block_info->block_used_next = NULL;
                p_phy_block_info->block_used_prev = NULL;
                add_block_count_list(zone,p_phy_block_info);
                if(ret == ECC_LIMIT)
                {
                    if(zone->cfg->nftl_support_gc_read_reclaim != 0)
                    {
                        add_prio_gc(zone,p_phy_block_info,GC_READ_RECLAIM);
                        NFTL_DBG("[NE]READ_RECLAIM!\n");
                    }
                }
            }
            else if(is_ftl_start_flag_page(spare_data) == NFTL_YES)
            {
                NFTL_DBG("[NE]do nothing\n");
            }
            else if(is_fill_page(spare_data) == NFTL_YES)
            {
                //NFTL_DBG("[NE]55 block %d\n",p_phy_block_info->phy_block.Block_NO);
                zone->blocks++;
                p_phy_block_info->info = BLOCK_NO_USED;
                p_phy_block_info->erase_count = get_erase_count_from_oob(spare_data);
				last_erase_count = p_phy_block_info->erase_count;
                p_phy_block_info->invalid_page_count = zone->nand_chip->pages_per_blk;
                put_phy_block_to_free_list(zone,p_phy_block_info);
            }
            else
            {
                //page 0 ��spare������δ�����ֵ������
                NFTL_ERR("[NE]unkown page 0 spare data %x,%x,%x,%x,%x,%x,%x!!\n",spare_data[0],spare_data[1],spare_data[2],spare_data[3],spare_data[4],spare_data[5],spare_data[6]);
				p_phy_block_info->erase_count = last_erase_count+1;
                if((ret == 0)||(ret == ECC_LIMIT))
                {
                    if(spare_data[0] != 0xff)
                    {
                        NFTL_DBG("[ND]  bad block: %d\n",p_phy_block_info->phy_block.Block_NO);
				    	p_phy_block_info->info = BLOCK_IS_BAD;
				    	zone->bad_block++;
                    }
                    else
                    {
                        if(erase_block(zone,p_phy_block_info,p_phy_block_info->erase_count+1) == 0)
                        {
                            zone->blocks++;
                        }
                    }
                }
                else
                {
                    NFTL_ERR("[NE]first page ecc error ! %d!\n",p_phy_block_info->phy_block.Block_NO);
                    set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,zone->nand_chip->pages_per_blk-1,0,NULL,spare_data);
                    ret = zone->nftl_nand_read_page(zone,&phy_op_par);
                    if((ret == 0)||(ret == ECC_LIMIT))
                    {
                        if(is_phy_mapping_page(spare_data) == NFTL_YES)
                        {
                            NFTL_ERR("[NE]last page ok ! %d!\n",p_phy_block_info->phy_block.Block_NO);
                            block_used_count = get_block_used_count_from_oob(spare_data);
                            zone->blocks++;
                            p_phy_block_info->info = BLOCK_HAVE_USED;
                            p_phy_block_info->erase_count = get_erase_count_from_oob(spare_data);
				            last_erase_count = p_phy_block_info->erase_count;
                            p_phy_block_info->invalid_page_count = 0;
                            p_phy_block_info->block_used_count = block_used_count;
                            p_phy_block_info->block_used_next = NULL;
                            p_phy_block_info->block_used_prev = NULL;
                            add_block_count_list(zone,p_phy_block_info);
                            if(ret == ECC_LIMIT)
                            {
                                if(zone->cfg->nftl_support_gc_read_reclaim != 0)
                                {
                                    add_prio_gc(zone,p_phy_block_info,GC_READ_RECLAIM);
                                    NFTL_DBG("[NE]READ_RECLAIM!\n");
                                }
                            }
                        }
                        else if(is_nouse_page(spare_data) == NFTL_YES)
                        {
                            NFTL_ERR("[NE]last page blank ! %d!\n",p_phy_block_info->phy_block.Block_NO);
                            if(erase_block(zone,p_phy_block_info,p_phy_block_info->erase_count+1) == 0)
                            {
                                zone->blocks++;
                            }
                        }
                        else
                        {
                            NFTL_ERR("[NE]last page unkown ! %d!\n",p_phy_block_info->phy_block.Block_NO);
                            if(erase_block(zone,p_phy_block_info,p_phy_block_info->erase_count+1) == 0)
                            {
                                zone->blocks++;
                            }
                        }
                    }
                    else
                    {
                        NFTL_ERR("[NE]first page last page ecc error ! %d!\n",p_phy_block_info->phy_block.Block_NO);
                        zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
                    }
                }
            }
        }
        else
        {
            //����
            NFTL_DBG("[ND]bad block: %d\n",p_phy_block_info->phy_block.Block_NO);
            p_phy_block_info->info = BLOCK_IS_BAD;
            p_phy_block_info->erase_count = 0;
            //zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
            zone->bad_block++;
        }
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
uint32 init_zone_after_first_scan(struct _nftl_zone * zone,uint32 block_nums)
{
    uint32 total_blocks;

    total_blocks = zone->logic_cap_in_sects / zone->nand_chip->sector_per_page;
    total_blocks /= zone->nand_chip->pages_per_blk;

    NFTL_DBG("[ND]before second %d %d.\n",block_nums,total_blocks);

    if(block_nums <= total_blocks)
    {
        NFTL_ERR("[NE]this zone not enough data block!!\n");
        return NFTL_FAILURE;
    }

    zone->backup_cap_in_sects = (block_nums-total_blocks) * zone->nand_chip->sector_per_page * zone->nand_chip->pages_per_blk;

    if((block_nums-total_blocks) < (zone->cfg->nftl_min_free_block_num -1))
    {
        NFTL_ERR("[NE]this zone not enough free block %d , %d!!\n",block_nums,total_blocks);
        return NFTL_FAILURE;
    }
    zone->gc_strategy.start_gc_free_blocks = (block_nums-total_blocks) / GC_START_RATIO;
    if(zone->gc_strategy.start_gc_free_blocks < zone->cfg->nftl_gc_threshold_free_block_num)
    {
        zone->gc_strategy.start_gc_free_blocks = zone->cfg->nftl_gc_threshold_free_block_num;
    }

    zone->gc_strategy.stop_gc_free_blocks = ((block_nums-total_blocks) * zone->cfg->nftl_gc_threshold_ratio_numerator)/zone->cfg->nftl_gc_threshold_ratio_denominator;
    if(zone->gc_strategy.stop_gc_free_blocks < (zone->gc_strategy.start_gc_free_blocks+2))
    {
        zone->gc_strategy.stop_gc_free_blocks = zone->gc_strategy.start_gc_free_blocks + 2;
    }
    zone->gc_strategy.process = GC_STOP;
    zone->gc_strategy.flag_gc_block = 0;
    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 second_scan_all_blocks(struct _nftl_zone * zone)
{
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    uint32 last_block_used_count,dat_tmp1,ecc,ret,max_block_used_count;
    _physic_op_par phy_op_par;
    _phy_block_info* p_phy_block_info;
    _phy_block_info* p_phy_block_info_tmp;
    _phy_block_info* p_phy_block_info_error;
    _phy_block_info* p_phy_block_info_last;
    _phy_block_info* p_phy_block_info_last_full;
    _phy_block_info* current_block_first;
    _phy_block_info* current_block_second;

    current_block_first = NULL;
    current_block_second = NULL;
	p_phy_block_info_last = NULL;
	p_phy_block_info_error = NULL;
	p_phy_block_info_last_full = NULL;

    //�ڶ���ɨ��block,ֻɨ��blockʹ���Ⱥ������е�block
    last_block_used_count = 0xffffffff;
    zone->logic_cap_in_page = zone->logic_cap_in_sects / zone->nand_chip->sector_per_page;

    max_block_used_count = 0xffffffff;
    for(p_phy_block_info=zone->block_used_head.block_used_next; p_phy_block_info!=NULL; p_phy_block_info=p_phy_block_info->block_used_next)
    {
        max_block_used_count = p_phy_block_info->block_used_count;
        zone->smart->max_block_used_counter = p_phy_block_info->block_used_count;
    }

    if(zone->block_used_head.block_used_next != NULL)
    {
        zone->smart->min_block_used_counter = zone->block_used_head.block_used_next->block_used_count;
    }

    for(p_phy_block_info=zone->block_used_head.block_used_next; p_phy_block_info!=NULL; p_phy_block_info=p_phy_block_info->block_used_next)
    {
        set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,zone->nand_chip->pages_per_blk - 1,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);

        last_block_used_count = p_phy_block_info->block_used_count;
        //if((p_phy_block_info->erase_count > zone->max_erase_num) && (p_phy_block_info->erase_count < zone->nand_chip->max_erase_times))

        if((p_phy_block_info->erase_count > zone->max_erase_num) && (p_phy_block_info->erase_count < 50000))
        {
            zone->max_erase_num = p_phy_block_info->erase_count;
            zone->smart->max_block_erase_times = zone->max_erase_num;
        }

        if(p_phy_block_info->erase_count < zone->smart->min_block_erase_times)
        {
            zone->smart->min_block_erase_times = p_phy_block_info->erase_count;
        }

        if((is_phy_mapping_page(spare_data) == NFTL_YES) && ((ret == 0)||(ret == ECC_LIMIT)) )
        {
			p_phy_block_info_last = p_phy_block_info;
            p_phy_block_info->invalid_page_count++; //�Ѿ�ȷ�����һ��page���mapping����ôinvalid_page_count��1
            recover_logic_page_mapping(zone,p_phy_block_info,(uint32*)zone->temp_page_buf,zone->nand_chip->pages_per_blk-1);
            p_phy_block_info_last_full = p_phy_block_info;
        }
        else if(is_nouse_page(spare_data) == NFTL_YES)
        {
            //zone��current used block.�����2��,��������������һ��
            //NFTL_ERR("[NE]current used block :%d\n",phy_op_par.phy_page.Block_NO);
            if(current_block_first == NULL)
            {
                current_block_first = p_phy_block_info;
            }
            else if(current_block_second == NULL)
            {
                current_block_second = p_phy_block_info;
                NFTL_DBG("[NE]NAND_EVENT: 2 current used block found %d,%d!\n",current_block_first->phy_block.Block_NO,current_block_second->phy_block.Block_NO);
				if(!(zone->zone_attr&SUPPORT_COSS_TALK))
				{
					if(current_block_first->block_used_count != current_block_second->block_used_count)
					{
						NFTL_ERR("[NE]no crosstalk:2 block used count diff %d,%d %d,%d !\n",current_block_first->phy_block.Block_NO,current_block_second->phy_block.Block_NO,current_block_first->block_used_count,current_block_second->block_used_count);
						recover_phy_page_mapping(zone,current_block_first,zone->current_block.user_info.map_data);
		                recover_logic_page_mapping(zone,current_block_first,zone->current_block.user_info.map_data,zone->nand_chip->pages_per_blk-1);
		                add_prio_gc(zone,current_block_first,GC_CHANGE);
						current_block_first = current_block_second;
                		current_block_second = NULL;
					}
				}
            }
            else
            {
                //����3��current used block ? ������!
                NFTL_ERR("[NE]NAND_EVENT: muti current used block found1 %d %d!\n",current_block_first->phy_block.Block_NO,current_block_first->block_used_count);
                NFTL_ERR("[NE]NAND_EVENT: muti current used block found2 %d %d!\n",current_block_second->phy_block.Block_NO,current_block_second->block_used_count);
                NFTL_ERR("[NE]NAND_EVENT: muti current used block found3 %d %d!\n",p_phy_block_info->phy_block.Block_NO,last_block_used_count);
                p_phy_block_info_tmp = current_block_first;
                current_block_first = current_block_second;
                current_block_second = p_phy_block_info;
                add_prio_gc(zone,p_phy_block_info_tmp,GC_CHANGE);
            }
        }
        else
        {
            NFTL_ERR("[NE]NAND_EVENT: last page spare data %x,%x,%x,%x,%x,%x,%x!!\n",spare_data[0],spare_data[1],spare_data[2],spare_data[3],spare_data[4],spare_data[5],spare_data[6]);
            if((ret == 0) || (ret == ECC_LIMIT))
            {
                //ecc����
                NFTL_ERR("[NE]last page unkown ecc ok %d,%d!!\n",zone->zone_no,p_phy_block_info->phy_block.Block_NO);
            }
            else
            {
                NFTL_ERR("[NE]last page ecc error %d,%d!!\n",zone->zone_no,p_phy_block_info->phy_block.Block_NO);
            }

            if((zone->zone_attr&SUPPORT_COSS_TALK)&&(max_block_used_count==last_block_used_count))
            {
                //crosstalk�㷨����2��current block�����һ��ʹ�ÿ���ǵڶ���
                //currentblock�������õģ�����������⣬��ֱ��ɾ�������ɡ�
        		erase_block(zone,p_phy_block_info,p_phy_block_info->erase_count+1);
        		p_phy_block_info_error = p_phy_block_info;
            }
            else
            {
                p_phy_block_info_last = p_phy_block_info;
                p_phy_block_info->info = 0xaa;
                p_phy_block_info->invalid_page_count++;
                recover_block_phy_page_mapping(zone,p_phy_block_info,zone->current_block.user_info.map_data);
                recover_logic_page_mapping(zone,p_phy_block_info,zone->current_block.user_info.map_data,zone->nand_chip->pages_per_blk-1);
                add_prio_gc(zone,p_phy_block_info,GC_CHANGE);
            }
        }
    }

    init_smart_info(zone,p_phy_block_info_last_full);

    //ɨ��blockʹ���Ⱥ�����,����block����Чpage������
    for(p_phy_block_info_tmp=zone->block_used_head.block_used_next; p_phy_block_info_tmp!=NULL; p_phy_block_info_tmp=p_phy_block_info_tmp->block_used_next)
    {
        if((p_phy_block_info_tmp != current_block_first) &&(p_phy_block_info_tmp != current_block_second) && (p_phy_block_info_tmp != p_phy_block_info_error))
        {
            put_phy_block_to_invalid_page_list(zone,p_phy_block_info_tmp);
        }
    }

    //����block����Чpage��������ȫΪ��Чpage��block����free����
    adjust_invaild_list(zone);

    if((p_phy_block_info_last != NULL)&&(current_block_first != NULL))
    {
        if((p_phy_block_info_last->block_used_count + 1) != current_block_first->block_used_count)
        {//current block��used countӦ�������ģ���ֻ������block��1.
            NFTL_ERR("[ND]something strange %d,%d!!\n",p_phy_block_info_last->block_used_count,current_block_first->block_used_count);
        }
    }

    //�õ�zone_current_used_block
    zone->current_block.block_info = NULL;
    if((current_block_first == NULL)&&(current_block_second == NULL))
    {
        NFTL_DBG("[ND]all block full!!\n");
        p_phy_block_info = NULL;

        if(zone->zone_attr&SUPPORT_COSS_TALK)
        {
            if(p_phy_block_info_last != NULL)
            {
                add_prio_gc(zone,p_phy_block_info_last,GC_CHANGE);
            }
        }
        else
        {
            if((p_phy_block_info_last != NULL)&&(p_phy_block_info_last->info == 0xaa))
            {
                add_prio_gc(zone,p_phy_block_info_last,GC_CHANGE);
            }
        }
    }
    else if(current_block_second == NULL)
    {
        p_phy_block_info = current_block_first;

        if(zone->zone_attr&SUPPORT_COSS_TALK)
        {
            NFTL_DBG("[ND]corss talk rebuild 0 %d %d!!\n",current_block_first->phy_block.Block_NO,current_block_first->block_used_count);
            if((p_phy_block_info_last != NULL)&&(p_phy_block_info_last->info == 0xaa))
            {
                add_prio_gc(zone,p_phy_block_info_last,GC_CHANGE);
            }
            p_phy_block_info = cross_talk_rebuild_current_block(zone,current_block_first,NULL);
			if(p_phy_block_info==NULL)
				return NFTL_FAILURE;
        }
        else
        {
            if((p_phy_block_info_last != NULL)&&(p_phy_block_info_last->info == 0xaa))
            {
                add_prio_gc(zone,p_phy_block_info_last,GC_CHANGE);
            }
			if(zone->zone_no == 0)
			{
				p_phy_block_info = current_block_first;
				check_cross_talk(zone,p_phy_block_info);
			}
			else
			{
				p_phy_block_info = no_cross_talk_rebuild_current_block(zone,current_block_first,NULL);
			}
        }
    }
    else
    {
	    if(zone->zone_no == 0)
		{
        	NFTL_ERR("[NE]start here error! \n");
		}

        if(zone->zone_attr&SUPPORT_COSS_TALK)
        {
            p_phy_block_info = cross_talk_rebuild_current_block(zone,current_block_first,current_block_second);
			if(p_phy_block_info==NULL)
				return NFTL_FAILURE;
        }
        else
        {
            if(current_block_first->block_used_count == current_block_second->block_used_count)
            {
                //NFTL_ERR("[NE]something is error here 6!\n");
				NFTL_DBG("[NE]muti current used block 1st %d %d!\n",current_block_first->phy_block.Block_NO,current_block_first->block_used_count);
                NFTL_DBG("[NE]muti current used block 2nd %d %d!\n",current_block_second->phy_block.Block_NO,current_block_second->block_used_count);
                //p_phy_block_info = current_block_first;
				p_phy_block_info = no_cross_talk_rebuild_current_block(zone,current_block_first,current_block_second);
            }
            else
            {
                NFTL_ERR("[NE]something is error here 7!\n");
                NFTL_ERR("[NE]p_phy_block_info_last %d %d!\n",p_phy_block_info_last->phy_block.Block_NO,p_phy_block_info_last->block_used_count);
                NFTL_ERR("[NE]muti current used block 1 %d %d!\n",current_block_first->phy_block.Block_NO,current_block_first->block_used_count);
                NFTL_ERR("[NE]muti current used block 2 %d %d!\n",current_block_second->phy_block.Block_NO,current_block_second->block_used_count);
                //add_prio_gc(zone,p_phy_block_info_last,GC_CHANGE);

				recover_block_phy_page_mapping(zone,current_block_first,zone->current_block.user_info.map_data);
                recover_logic_page_mapping(zone,current_block_first,zone->current_block.user_info.map_data,zone->nand_chip->pages_per_blk-1);
                add_prio_gc(zone,current_block_first,GC_CHANGE);

				recover_block_phy_page_mapping(zone,current_block_second,zone->current_block.user_info.map_data);
                recover_logic_page_mapping(zone,current_block_second,zone->current_block.user_info.map_data,zone->nand_chip->pages_per_blk-1);
                add_prio_gc(zone,current_block_second,GC_CHANGE);
			}
        }
    }

    ret = get_current_used_block(zone,p_phy_block_info,last_block_used_count);
    if(ret != NFTL_SUCCESS)
    {
        NFTL_ERR("[NE]get_current_used_block fail!\n");
        return NFTL_FAILURE;
    }

    adjust_invaild_list(zone);

    return NFTL_SUCCESS;
}


/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int check_bit_nums(__u8* buf,int len)
{
    int  i,k,num=0;
    __u8 temp;
    for(i=0;i<len;i++)
    {
        temp = 0x01;
        for(k=0;k<8;k++)
        {
            if(temp & buf[i]) 
            {
                num++; 
            }
            temp <<= 1;     
        }
    }
    return num;
}

int is_all_bit_ff(__u8* buf,int len,int u)
{
	int num,max_num;

	max_num = len<<3;
	max_num -= u;
	num = check_bit_nums(buf,len);
	if(num >= max_num)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}


int is_all_byte_ff(__u8* buf,int len,int u)
{
	int num,max_num,i;

    num = 0;
    max_num = len - u;

	for(i=0;i<len;i++)
	{
        if(buf[i] == 0xff)     
        {
            num++; 
        }     
    }
	if(num >= max_num)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void _DumpHexData(unsigned char *buf, int len)
{
	unsigned char *ptr = buf;
	int i;

	for(i = 0; i < len; i++) {
	       if(i % 16 == 0)
	               NFTL_ERR("%4d:        ", i);
	       NFTL_ERR("%.2x ", *ptr++);
	       if(i % 16 == 15)
	               NFTL_ERR("\n");
	}
	NFTL_ERR("\n");
	return;
}

uint32 small_nand_power_off_ecc_error(struct _nftl_zone * zone,uchar* mbuf,uchar* spare_data)
{
	int flag1 = 0;
	int flag2 = 0;
	int flag3 = 0;
	int flag = 0;

	if((SECTOR_CNT_OF_SINGLE_PAGE != 4) || (zone->nand_chip->sector_per_page != 8))
	{
		return 0;
	}

	flag1 = is_all_bit_ff(spare_data,8,1);
	flag2 = is_all_bit_ff(spare_data+8,7,1);
	if(flag1 != flag2)
	{
		flag = 1;
	}

	if((flag2 == 1)&&(flag == 1))
	{
		if(mbuf != NULL)
		{
			flag3 = is_all_byte_ff(mbuf+2048,2048,7);
			if(flag3 ==0)
			{
				flag = 0;
			}
		}
	}
	if (flag == 1)
	{
		NFTL_ERR("%s %d, flag = %d\n", __FUNCTION__, __LINE__, flag);
		NFTL_ERR("OOB :");
		_DumpHexData(spare_data, 16);
	}

	return flag;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_current_used_block(struct _nftl_zone * zone,_phy_block_info* p_phy_block_info,uint32 block_used_count)
{
    uint32 dat_tmp,i,ret,flag=0;

    if(zone->current_block.block_info != NULL)
    {
        return NFTL_SUCCESS;
    }

    if(p_phy_block_info != NULL)
    {
get_current_block:
        zone->current_block.page_used = recover_phy_page_mapping(zone,p_phy_block_info,zone->current_block.user_info.map_data);
        if(zone->current_block.page_used == 0xffff)
        {
            flag = 1;
            NFTL_ERR("[NE]current_block ecc error %d!\n",p_phy_block_info->phy_block.Block_NO);
            p_phy_block_info = current_block_ecc_error(zone,p_phy_block_info);
            if(p_phy_block_info != NULL)
            {
                goto get_current_block;
            }
            else
            {
                NFTL_ERR("[NE]error! no free block!\n");
                return NFTL_FAILURE;
            }
        }
        zone->current_block.block_info = p_phy_block_info;
        NFTL_DBG("[ND]recover %d %d\n",zone->current_block.block_info->phy_block.Block_NO,zone->current_block.page_used);
        recover_logic_page_mapping(zone,zone->current_block.block_info,zone->current_block.user_info.map_data,zone->current_block.page_used);

        if(zone->current_block.page_used < zone->current_block.block_info->invalid_page_count)
        {
            NFTL_ERR("[NE]error!!\n");
        }

        if(zone->zone_attr&SUPPORT_COSS_TALK)
        {
assist_block_null:
            if(zone->assist_block.block_info == NULL)
            {
                zone->assist_block.block_info = out_phy_block_from_free_list(zone);
				if(zone->assist_block.block_info==NULL)
					return NFTL_FAILURE;
                zone->assist_block.page_used = 0;
                zone->assist_block.block_info->block_used_count = zone->current_block.block_info->block_used_count+1;

				if(new_block_init_for_write(zone,zone->assist_block.block_info,zone->assist_block.block_info->block_used_count) != NFTL_SUCCESS)
                {
                    NFTL_ERR("[NE]new_block_init_for_write error here!\n");
					zone->assist_block.block_info = NULL;
					goto assist_block_null;
                }

				dat_tmp = zone->current_block.page_used;
                for(i=0; i<dat_tmp; i++)
                {
                    ret = zone->nftl_nand_copy_page(zone,zone->current_block.block_info,zone->assist_block.block_info,zone->temp_page_buf,i);
                    if(ret != 0)
                    {
                        NFTL_ERR("[NE]something is error here 10!\n");
                    }
                }

//                uchar spare_data[16];
//                _physic_op_par phy_op_par;
//                for(i=0; i<dat_tmp; i++)
//                {
//                    set_physic_op_par(&phy_op_par,zone->assist_block.block_info->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
//                    zone->nftl_nand_read_page(zone,&phy_op_par);
//                    NFTL_ERR("[NE=============================\n",i);
//                    NFTL_ERR("[NE]assist_block  %d %d %d %d %d\n",i,zone->temp_page_buf[0],zone->temp_page_buf[1],zone->temp_page_buf[2],zone->temp_page_buf[3]);
//                    NFTL_ERR("[NE]assist_block  %d %d %d %d %d\n",i,zone->temp_page_buf[0+512*1],zone->temp_page_buf[1+512*1],zone->temp_page_buf[2+512*1],zone->temp_page_buf[3+512*1]);
//                    NFTL_ERR("[NE]assist_block  %d %d %d %d %d\n",i,zone->temp_page_buf[0+512*2],zone->temp_page_buf[1+512*2],zone->temp_page_buf[2+512*2],zone->temp_page_buf[3+512*2]);//                }


            }

            zone->assist_block.page_used = recover_phy_page_mapping(zone,zone->assist_block.block_info,zone->assist_block.user_info.map_data);
            if(zone->assist_block.page_used == 0xffff)
            {
                NFTL_ERR("[NE]something is error here 11!\n");
                //erase_block(zone,zone->assist_block.block_info,zone->nand_chip->max_erase_times);
                erase_block(zone,zone->assist_block.block_info,zone->assist_block.block_info->erase_count+1);
                zone->assist_block.block_info = NULL;
				goto assist_block_null;
            }

            zone->assist_block.block_info->block_used_count = zone->current_block.block_info->block_used_count+1;
            recover_logic_page_mapping(zone,zone->assist_block.block_info,zone->assist_block.user_info.map_data,zone->assist_block.page_used);
            if(zone->assist_block.page_used > zone->current_block.page_used)
            {
                NFTL_ERR("[NE]something is error here 12 %d,%d!\n",zone->assist_block.page_used,zone->current_block.page_used);
                if(flag != 0)
                {
					erase_block(zone,zone->current_block.block_info,zone->current_block.block_info->erase_count+1);
                    zone->current_block.block_info = zone->assist_block.block_info;
                    zone->current_block.page_used = zone->assist_block.page_used;
                    MEMCPY(zone->current_block.user_info.buf,zone->assist_block.user_info.buf,zone->current_block.user_info.buf_size);
                    zone->assist_block.block_info = NULL;
				    goto assist_block_null;
			    }
			    else
			    {
			        NFTL_ERR("[NE]something is error here 17 %d,%d!\n",zone->assist_block.page_used,zone->current_block.page_used);
			    }
            }
            else if(zone->assist_block.page_used < zone->current_block.page_used)
            {
                NFTL_ERR("[NE]something is error here 16!\n");
                erase_block(zone,zone->assist_block.block_info,zone->assist_block.block_info->erase_count+1);
                zone->assist_block.block_info = NULL;
				goto assist_block_null;
            }
            else
            {
                ;
            }
        }
    }
    else
    {
        NFTL_DBG("[ND]get a new free block\n");
        if(zone->free_head.free_next != NULL)
        {
            zone->current_block.block_info = out_phy_block_from_free_list(zone);
			if(zone->current_block.block_info==NULL)
				return NFTL_FAILURE;
            zone->current_block.page_used = 0;
            zone->current_block.block_info->block_used_count = block_used_count+1;
            if(zone->zone_attr & SUPPORT_COSS_TALK)
            {
                zone->assist_block.block_info = out_phy_block_from_free_list(zone);
				if(zone->assist_block.block_info==NULL)
					return NFTL_FAILURE;
                zone->assist_block.page_used = 0;
                zone->assist_block.block_info->block_used_count = zone->current_block.block_info->block_used_count+1;
            }
            else
            {
                zone->assist_block.block_info = NULL;
            }
        }
        else
        {
            NFTL_ERR("[NE]no free block to use!\n");
            print_free_list(zone);
            print_block_invalid_list(zone);
            return NFTL_FAILURE;
        }
    }

//    if(zone->zone_attr&SUPPORT_COSS_TALK)
//    {
//        fill_no_use_data_to_page(zone);
//    }

    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 recover_phy_page_mapping(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32* data)
{
    int i,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;

    MEMSET(data,0xff,zone->current_block.user_info.map_size);

    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if(is_nouse_page(spare_data) == NFTL_YES)
        {
            //���pageû��ʹ�ã��Ѿ��������δʹ�õ�page
            NFTL_ERR("[NE]recover_phy_page_mapping no used page %d!!\n",i);
            break;
        }

        if(is_ftl_logic_page_data(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
				if(small_nand_power_off_ecc_error(zone,zone->temp_page_buf,&spare_data[0]) != 0)
            	{
            		NFTL_ERR("[NE]slc power off ecc error 1!!\n");
            		ret = NAND_ERR_ECC;
            	}
            	else
            	{
                	data[i] = get_logic_page_from_oob(spare_data);
                }
            }
        }
        else if(is_ftl_special_data(spare_data) == NFTL_YES)
        {
//          zone->zone_current_used_block->invalid_page_count++;
//          if(zone->zone_current_used_block->invalid_page_count > zone->nand_chip->pages_per_blk)
//          {
//              NFTL_ERR("[NE]invalid_page_count more than pages_per_blk10!!\n");
//          }
            NFTL_ERR("[NE]recover_phy_page_mapping invalid page data!!\n");
        }
        else if(is_power_down_info_page(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
                data[i] = get_special_data_from_oob(spare_data);
                NFTL_ERR("[NE]power_down page %d!!\n",i);
            }
        }
        else
        {
//          zone->zone_current_used_block->invalid_page_count++;
//          if(zone->zone_current_used_block->invalid_page_count > zone->nand_chip->pages_per_blk)
//          {
//              NFTL_ERR("[NE]invalid_page_count more than pages_per_blk11!!\n");
//          }
            NFTL_ERR("[NE]recover_phy_page_mapping unkown page data %d!!\n",i);
        }

        if((ret != 0) && (ret != ECC_LIMIT))
        {
            NFTL_ERR("[NE]recover_phy_page_mapping ecc error block:%d;page:%d!!\n",phy_block_ptr->phy_block.Block_NO,i);
            return 0xffff;
        }
    }

    if(i < (zone->nand_chip->pages_per_blk-2))  //���һ����Ч����
    {
        if(!(zone->zone_attr&SUPPORT_COSS_TALK))
        {
        }
//      set_no_use_page(zone,spare_data);
//      zone->nand_write_page(zone,&phy_op_par);
//      zone->zone_current_used_block->invalid_page_count++;
//      if(zone->zone_current_used_block->invalid_page_count > zone->nand_chip->pages_per_blk)
//      {
//          NFTL_ERR("[NE]invalid_page_count more than pages_per_blk12!!\n");
//      }
//      i+=1;
    }

    return i;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 recover_block_phy_page_mapping(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32* data)
{
    int i,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;

    MEMSET(data,0xff,zone->current_block.user_info.map_size);

    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if(is_ftl_logic_page_data(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
				if(small_nand_power_off_ecc_error(zone,zone->temp_page_buf,&spare_data[0]) != 0)
            	{
            		NFTL_ERR("[NE]slc power off ecc error 3!!\n");
            	}
            	else
            	{
            		data[i] = get_logic_page_from_oob(spare_data);
            	}
            }
        }
        else if(is_nouse_page(spare_data) == NFTL_YES)
        {
            //NFTL_ERR("[NE]recover_block_phy_page_mapping no used page %d %d!!\n",phy_block_ptr->phy_block.Block_NO,i);
        }
        else
        {
            NFTL_ERR("[NE]recover_block_phy_page_mapping error page %d %d!!\n",phy_block_ptr->phy_block.Block_NO,i);
        }
    }

    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :��������Чҳ�������п�ҳ
*****************************************************************************/
uint32 recover_logic_page_mapping(struct _nftl_zone* zone,_phy_block_info* p_phy_block_info,uint32* data,uint32 phy_page_nums)
{
    uint32 logic_page,i;
    _phy_block_info* temp_phy_block_ptr;
    _mapping_page* logic_page_map;

    for(i=0; i<phy_page_nums; i++)
    {
        logic_page = data[i];
        if(logic_page < zone->logic_cap_in_page)
        {
            logic_page_map = get_logic_page_map(zone,logic_page);
            if(logic_page_map->Block_NO != 0xffff) //�Ѿ�������һ��ֵ��
            {
                temp_phy_block_ptr = get_phy_block_addr(zone,logic_page_map->Block_NO);
                if(temp_phy_block_ptr != p_phy_block_info)
                {
                    phy_block_from_invalid_page_incr(zone,temp_phy_block_ptr);
                }
                else
                {
                    temp_phy_block_ptr->invalid_page_count++;
                }
                if(temp_phy_block_ptr->invalid_page_count > zone->nand_chip->pages_per_blk)
                {
                    NFTL_ERR("[NE]invalid_page_count more than pages_per_blk! :%d\n",temp_phy_block_ptr->phy_block.Block_NO);
                }
            }
            logic_page_map->Page_NO = i;
            logic_page_map->Block_NO = p_phy_block_info->phy_block.Block_NO;
        }
        else
        {
            if(logic_page != 0xffffffff)
            {
                NFTL_ERR("[NE]invalid_page data block:%d page:%d,logic_page 0x%x!!\n",p_phy_block_info->phy_block.Block_NO,i,logic_page);
            }
            p_phy_block_info->invalid_page_count++;
            if(p_phy_block_info->invalid_page_count > zone->nand_chip->pages_per_blk)
            {
                NFTL_ERR("[NE]build invalid_page_count more than pages_per_blk!!\n");
            }
        }
    }

    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 do_write_error_in_build_list(struct _nftl_zone* zone,_phy_block_info* block1, _phy_block_info* block2,uint16 page_num)
{
    uint32 ret,i;
    _phy_block_info* p_phy_block_free;
    _physic_op_par phy_op_par;

    p_phy_block_free = block2;
    set_physic_op_par(&phy_op_par,p_phy_block_free->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
    ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
    p_phy_block_free->invalid_page_count = 0;
    p_phy_block_free->erase_count++;
    if(ret != 0)
    {
        NFTL_ERR("[NE]NAND EVENT:do_write_error erase error1!\n");
        zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
        return NFTL_FAILURE;
    }

    for(i=0; i<page_num; i++)
    {
        ret = zone->nftl_nand_copy_page(zone,block1,p_phy_block_free,zone->temp_page_buf,i);
        if(ret != 0)
        {
            NFTL_ERR("[NE]NAND EVENT:do_write_error erase error2!\n");
//          set_physic_op_par(&phy_op_par,p_phy_block_free->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,NULL);
//          zone->nand_mark_bad_blk(zone,&phy_op_par);
//          return NFTL_FAILURE;
        }
    }

    set_physic_op_par(&phy_op_par,block1->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
    zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);

    if(page_num == 0)
    {
        zone->current_block.block_info = block2;
        zone->current_block.page_used = 0;
        //zone->current_block.block_info->block_used_count = block2->block_used_count;
    }

    return NFTL_SUCCESS;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int init_nrc(struct _nftl_zone* zone,struct _nand_rebuild_cache **nrc)
{
    int i,j;

    *nrc = (struct _nand_rebuild_cache *)nftl_malloc(sizeof(struct _nand_rebuild_cache));
    if(*nrc == 0)
    {
        return -1;
    }

    MEMSET(*nrc,0,sizeof(struct _nand_rebuild_cache));

    for(i=0; i<512;i++)
    {
        (*nrc)->cache_addr[i] = (uchar*)nftl_malloc(zone->nand_chip->bytes_per_page + BYTES_OF_USER_PER_PAGE);
        if((*nrc)->cache_addr[i] == NULL)
        {
            NFTL_ERR("[NE]init_nrc no memory!\n");
            return -1;
        }
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
int free_nrc(struct _nand_rebuild_cache *nrc)
{
    int i;

    if(nrc == NULL)
    {
        return 0;
    }

    for(i=0; i<512;i++)
    {
        if(nrc->cache_addr[i] != NULL)
        {
            nftl_free(nrc->cache_addr[i]);
        }
    }
    nftl_free(nrc);
    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
_phy_block_info* cross_talk_rebuild_current_block(struct _nftl_zone* zone,_phy_block_info* block1, _phy_block_info* block2)
{
    uint32 dat_tmp1,dat_tmp2,ecc1,ecc2,i,j,m,logic_page,ret,page;
    uint32 erase_counter,erase_counter2;
    _phy_block_info* block;
    _phy_block_info* block_temp;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _physic_op_par phy_op_par2;
    struct _nand_rebuild_cache *nrc = NULL;

    if(init_nrc(zone,&nrc) != 0)
    {
        free_nrc(nrc);
        NFTL_ERR("[ND]cross_talk_rebuild_current_block fail 1\n");
        return NULL;
    }

    dat_tmp1 = get_used_page_num(zone,block1,&ecc1,nrc);
    if(block2 == NULL)
    {
        NFTL_ERR("[ND]cross_talk_rebuild_current_block!! %d,%d,%d!\n",block1->phy_block.Block_NO,dat_tmp1,block1->block_used_count);
        block = block1;
        erase_counter = block1->erase_count;
        if(nrc->max_page == 0)
        {
            free_nrc(nrc);
            NFTL_ERR("[ND]cross_talk_rebuild_current_block fail 2\n");
            erase_block(zone,block1,block1->erase_count+1);
            return NULL;
        }
        if(ecc1 != 0)
        {
            erase_counter += 20;
        }
    }
    else
    {
        dat_tmp2 = get_used_page_num(zone,block2,&ecc2,nrc);
        NFTL_ERR("[ND]cross_talk_rebuild_current_block!! %d,%d,%d,%d,%d,%d!\n",block1->phy_block.Block_NO,dat_tmp1,block1->block_used_count,block2->phy_block.Block_NO,dat_tmp2,block2->block_used_count);

        if(nrc->max_page == 0)
        {
            free_nrc(nrc);
            NFTL_ERR("[ND]cross_talk_rebuild_current_block fail 3\n");
            erase_block(zone,block1,block1->erase_count+1);
            erase_block(zone,block2,block2->erase_count+1);
            return NULL;
        }

        if(dat_tmp2 >= dat_tmp1)
        {
            erase_counter = block1->erase_count;
            erase_counter2 = block2->erase_count;
        }
        else
        {
            erase_counter = block2->erase_count;
            erase_counter2 = block1->erase_count;
        }

        if((ecc1 != 0) || (ecc2 != 0))
        {
            erase_counter += 20;
            erase_counter2 += 20;
        }

        if(dat_tmp2 > dat_tmp1)
        {
            NFTL_ERR("[ND]corss talk rebuild 1 %d %d %d!\n",dat_tmp1,dat_tmp2,nrc->max_page);
            erase_block(zone,block1,erase_counter+1);
            block = block2;
        }
        else
        {
            NFTL_ERR("[ND]corss talk rebuild 2 %d %d %d!\n",dat_tmp1,dat_tmp2,nrc->max_page);
            erase_block(zone,block2,erase_counter+1);
            block = block1;
        }
    }

request_free_block:
    block_temp = out_phy_block_from_free_list(zone);
	if(block_temp==NULL)
	{
		NFTL_ERR("[NE] get free block fail!\n");
		return NULL;
	}
	block_temp->block_used_count = block->block_used_count+1;
    if(new_block_init_for_write(zone,block_temp,block_temp->block_used_count) != NFTL_SUCCESS)
    {
        NFTL_ERR("[NE]something is error here 14!\n");
		goto request_free_block;
    }

    for(i=0,page=0; i<nrc->max_page; i++)
    {
        if(nrc->cache_used[i] != 0)
        {
//            NFTL_ERR("[NE=============================\n",i);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0],nrc->cache_addr[i][1],nrc->cache_addr[i][2],nrc->cache_addr[i][3]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*1],nrc->cache_addr[i][1+512*1],nrc->cache_addr[i][2+512*1],nrc->cache_addr[i][3+512*1]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*2],nrc->cache_addr[i][1+512*2],nrc->cache_addr[i][2+512*2],nrc->cache_addr[i][3+512*2]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*3],nrc->cache_addr[i][1+512*3],nrc->cache_addr[i][2+512*3],nrc->cache_addr[i][3+512*3]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*4],nrc->cache_addr[i][1+512*4],nrc->cache_addr[i][2+512*4],nrc->cache_addr[i][3+512*4]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*5],nrc->cache_addr[i][1+512*5],nrc->cache_addr[i][2+512*5],nrc->cache_addr[i][3+512*5]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*6],nrc->cache_addr[i][1+512*6],nrc->cache_addr[i][2+512*6],nrc->cache_addr[i][3+512*6]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*7],nrc->cache_addr[i][1+512*7],nrc->cache_addr[i][2+512*7],nrc->cache_addr[i][3+512*7]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*8],nrc->cache_addr[i][1+512*8],nrc->cache_addr[i][2+512*8],nrc->cache_addr[i][3+512*8]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*9],nrc->cache_addr[i][1+512*9],nrc->cache_addr[i][2+512*9],nrc->cache_addr[i][3+512*9]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*10],nrc->cache_addr[i][1+512*10],nrc->cache_addr[i][2+512*10],nrc->cache_addr[i][3+512*10]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*11],nrc->cache_addr[i][1+512*11],nrc->cache_addr[i][2+512*11],nrc->cache_addr[i][3+512*11]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*12],nrc->cache_addr[i][1+512*12],nrc->cache_addr[i][2+512*12],nrc->cache_addr[i][3+512*12]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*13],nrc->cache_addr[i][1+512*13],nrc->cache_addr[i][2+512*13],nrc->cache_addr[i][3+512*13]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*14],nrc->cache_addr[i][1+512*14],nrc->cache_addr[i][2+512*14],nrc->cache_addr[i][3+512*14]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*15],nrc->cache_addr[i][1+512*15],nrc->cache_addr[i][2+512*15],nrc->cache_addr[i][3+512*15]);

            MEMCPY(spare_data,nrc->cache_addr[i]+zone->nand_chip->bytes_per_page,BYTES_OF_USER_PER_PAGE);
            set_physic_op_par(&phy_op_par2,block_temp->phy_block.Block_NO,page,zone->nand_chip->bitmap_per_page,nrc->cache_addr[i],spare_data);
            logic_page = get_special_data_from_oob(spare_data);
            set_oob_special_page(zone,spare_data,logic_page,block_temp->block_used_count,block_temp->erase_count);
            zone->nftl_nand_write_page(zone,&phy_op_par2);
            page++;
        }
        else
        {
            NFTL_ERR("[NE]page lost %d %d\n",i,nrc->max_page);
        }
    }

    erase_block(zone,block,erase_counter2+1);

    free_nrc(nrc);

    return block_temp;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
_phy_block_info* no_cross_talk_rebuild_current_block(struct _nftl_zone* zone,_phy_block_info* block1, _phy_block_info* block2)
{
    uint32 dat_tmp1,dat_tmp2,ecc1,ecc2,i,j,m,logic_page,ret,page;
    uint32 erase_counter,erase_counter2;
    _phy_block_info* block;
    _phy_block_info* block_temp;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _physic_op_par phy_op_par2;
    struct _nand_rebuild_cache *nrc1 = NULL;
	struct _nand_rebuild_cache *nrc2 = NULL;
	struct _nand_rebuild_cache *nrc = NULL;

    if(init_nrc(zone,&nrc1) != 0)
    {
        free_nrc(nrc1);
        NFTL_ERR("[ND]cross_talk_rebuild_current_block fail 1\n");
        return NULL;
    }

    dat_tmp1 = get_used_page_num_no_crosstalk(zone,block1,&ecc1,nrc1);
    if(block2 == NULL)
    {
        NFTL_ERR("[ND]no_cross_talk_rebuild_current_block!! %d,%d,%d!\n",block1->phy_block.Block_NO,dat_tmp1,block1->block_used_count);
        block = block1;
        erase_counter = block1->erase_count;
        if(nrc1->max_page == 0)
        {
            free_nrc(nrc1);
            NFTL_ERR("[ND]no_cross_talk_rebuild_current_block fail 2\n");
            erase_block(zone,block1,block1->erase_count+1);
            return NULL;
        }

		nrc = nrc1;

	request_free_block:
	    block_temp = out_phy_block_from_free_list(zone);
		if(block_temp==NULL)
		{
			NFTL_ERR("[NE] get free block fail!\n");
			return NULL;
		}
		block_temp->block_used_count = block->block_used_count;
	    if(new_block_init_for_write(zone,block_temp,block_temp->block_used_count) != NFTL_SUCCESS)
	    {
	        NFTL_ERR("[NE]something is error here 14!\n");
			goto request_free_block;
	    }
    }
    else
    {
    	if(init_nrc(zone,&nrc2) != 0)
	    {
	    	free_nrc(nrc1);
	        free_nrc(nrc2);
	        NFTL_ERR("[ND]cross_talk_rebuild_current_block fail 3\n");
	        return NULL;
	    }
        dat_tmp2 = get_used_page_num_no_crosstalk(zone,block2,&ecc2,nrc2);
        NFTL_ERR("[ND]no_cross_talk_rebuild_current_block!! %d,%d,%d,%d,%d,%d!\n",block1->phy_block.Block_NO,dat_tmp1,block1->block_used_count,block2->phy_block.Block_NO,dat_tmp2,block2->block_used_count);

        if(nrc2->max_page == 0)
        {
        	free_nrc(nrc1);
            free_nrc(nrc2);
            NFTL_ERR("[ND]no_cross_talk_rebuild_current_block fail 4\n");
            erase_block(zone,block1,block1->erase_count+1);
            erase_block(zone,block2,block2->erase_count+1);
            return NULL;
        }

        if(dat_tmp2 > dat_tmp1)
        {
            block = block2;
			block_temp = block1;
			nrc = nrc2;
			NFTL_ERR("[ND]corss talk rebuild 1 %d %d %d!\n",dat_tmp1,dat_tmp2,nrc->max_page);
        }
        else
        {
            block = block1;
			block_temp = block2;
			nrc = nrc1;
			NFTL_ERR("[ND]corss talk rebuild 2 %d %d %d!\n",dat_tmp1,dat_tmp2,nrc->max_page);
        }

		set_physic_op_par(&phy_op_par,block_temp->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
	    ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
	    if(ret != 0)
	    {
	        NFTL_ERR("[NE]no_cross_talk_rebuild_current_block erase block fail %d!\n",block_temp->phy_block.Block_NO);
	        zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
	        block->invalid_page_count = 0;
			block->info = BLOCK_IS_BAD;
	        zone->bad_block++;
		request_free_block_1:
		    block_temp = out_phy_block_from_free_list(zone);
			if(block_temp==NULL)
			{
				NFTL_ERR("[NE] get free block fail!\n");
				return NULL;
			}
		    if(new_block_init_for_write(zone,block_temp,block_temp->block_used_count) != NFTL_SUCCESS)
		    {
		        NFTL_ERR("[NE]something is error here 14!\n");
				goto request_free_block_1;
		    }
	    }
		block_temp->block_used_count = block->block_used_count;
    }

	for(i=0,page=0; i<nrc->max_page; i++)
    {
        if(nrc->cache_used[i] != 0)
        {
//            NFTL_ERR("[NE=============================\n",i);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0],nrc->cache_addr[i][1],nrc->cache_addr[i][2],nrc->cache_addr[i][3]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*1],nrc->cache_addr[i][1+512*1],nrc->cache_addr[i][2+512*1],nrc->cache_addr[i][3+512*1]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*2],nrc->cache_addr[i][1+512*2],nrc->cache_addr[i][2+512*2],nrc->cache_addr[i][3+512*2]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*3],nrc->cache_addr[i][1+512*3],nrc->cache_addr[i][2+512*3],nrc->cache_addr[i][3+512*3]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*4],nrc->cache_addr[i][1+512*4],nrc->cache_addr[i][2+512*4],nrc->cache_addr[i][3+512*4]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*5],nrc->cache_addr[i][1+512*5],nrc->cache_addr[i][2+512*5],nrc->cache_addr[i][3+512*5]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*6],nrc->cache_addr[i][1+512*6],nrc->cache_addr[i][2+512*6],nrc->cache_addr[i][3+512*6]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*7],nrc->cache_addr[i][1+512*7],nrc->cache_addr[i][2+512*7],nrc->cache_addr[i][3+512*7]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*8],nrc->cache_addr[i][1+512*8],nrc->cache_addr[i][2+512*8],nrc->cache_addr[i][3+512*8]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*9],nrc->cache_addr[i][1+512*9],nrc->cache_addr[i][2+512*9],nrc->cache_addr[i][3+512*9]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*10],nrc->cache_addr[i][1+512*10],nrc->cache_addr[i][2+512*10],nrc->cache_addr[i][3+512*10]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*11],nrc->cache_addr[i][1+512*11],nrc->cache_addr[i][2+512*11],nrc->cache_addr[i][3+512*11]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*12],nrc->cache_addr[i][1+512*12],nrc->cache_addr[i][2+512*12],nrc->cache_addr[i][3+512*12]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*13],nrc->cache_addr[i][1+512*13],nrc->cache_addr[i][2+512*13],nrc->cache_addr[i][3+512*13]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*14],nrc->cache_addr[i][1+512*14],nrc->cache_addr[i][2+512*14],nrc->cache_addr[i][3+512*14]);
//            NFTL_ERR("[NE]cross %d %d %d %d %d\n",i,nrc->cache_addr[i][0+512*15],nrc->cache_addr[i][1+512*15],nrc->cache_addr[i][2+512*15],nrc->cache_addr[i][3+512*15]);

            MEMCPY(spare_data,nrc->cache_addr[i]+zone->nand_chip->bytes_per_page,BYTES_OF_USER_PER_PAGE);
            set_physic_op_par(&phy_op_par2,block_temp->phy_block.Block_NO,page,zone->nand_chip->bitmap_per_page,nrc->cache_addr[i],spare_data);
            logic_page = get_special_data_from_oob(spare_data);
            set_oob_special_page(zone,spare_data,logic_page,block_temp->block_used_count,block_temp->erase_count);
            zone->nftl_nand_write_page(zone,&phy_op_par2);
            page++;
        }
        else
        {
            NFTL_ERR("[NE]page lost %d %d\n",i,nrc->max_page);
        }
    }
	erase_block(zone,block,block->erase_count+1);

    free_nrc(nrc1);
	free_nrc(nrc2);

    return block_temp;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int erase_block(struct _nftl_zone* zone,_phy_block_info* block,uint16 erase_num)
{
    uint32 ret;
    _physic_op_par phy_op_par;

    NFTL_ERR("[NE]erase_block block %d!\n",block->phy_block.Block_NO);
    set_physic_op_par(&phy_op_par,block->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
    ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
    if(ret != 0)
    {
        NFTL_ERR("[NE]erase_block block fail %d!\n",block->phy_block.Block_NO);
        zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
        block->invalid_page_count = 0;
		block->info = BLOCK_IS_BAD;
        zone->bad_block++;
    }
    else
    {
        //block->erase_count = zone->max_erase_num + 1;
        block->erase_count = erase_num;
        block->block_used_count = 0xffffffff;
        put_phy_block_to_free_list(zone,block);
        mark_free_block(zone,block);
        block->invalid_page_count = zone->nand_chip->pages_per_blk;
		block->info = BLOCK_NO_USED;
    }

    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int mark_free_block(struct _nftl_zone* zone,_phy_block_info* block)
{
    int i;
    _physic_op_par phy_op_par;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];

    for(i=0;i<zone->nand_chip->pages_per_blk;i++)
    {
        set_physic_op_par(&phy_op_par,block->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        set_oob_special_page(zone,spare_data,PHY_FILL_PAGE,block->block_used_count,block->erase_count);
        zone->nftl_nand_write_page(zone,&phy_op_par);
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
uint32 is_last_phy_block(_phy_block_info* p_phy_block_info,struct _nftl_zone * zone)
{
    if(p_phy_block_info->phy_block.Block_NO == (zone->nand_chip->blk_per_chip-1) )
    {
        return NFTL_YES;
    }
    return NFTL_NO;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 is_phy_block_valid(_phy_block_info* p_phy_block_info,struct _nftl_zone * zone)
{
    if(p_phy_block_info->phy_block.Block_NO < zone->nand_chip->blk_per_chip)
    {
        return NFTL_YES;
    }
    return NFTL_NO;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
_phy_block_info* get_phy_block_addr(struct _nftl_zone *zone,uint16 block)
{
    return (_phy_block_info*)(&zone->nand_chip->nand_block_info[block]);
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_used_page_num(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32 *ecc,struct _nand_rebuild_cache* nrc)
{
    uint32 i,j,num,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uchar *mbuf;
    uchar *sbuf;
    uint32 flag = 0;

    *ecc = 0;
	j = 0;
    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        if((nrc != NULL) && (nrc->cache_used[i] == 0))
        {
            mbuf = nrc->cache_addr[i];
            sbuf = nrc->cache_addr[i] + zone->nand_chip->bytes_per_page;
        }
        else
        {
            mbuf = NULL;
            if(SECTOR_CNT_OF_SINGLE_PAGE == 4)
            {
            	mbuf = zone->temp_page_buf;
        	}
            sbuf = spare_data;
        }

        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,mbuf,sbuf);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if((ret != 0)&&(ret != ECC_LIMIT))
        {
            NFTL_ERR("[NE]get_used_page_num ecc error block:%d page:%d!\n",phy_block_ptr->phy_block.Block_NO,i);
            *ecc += 1;
        }
        if(is_nouse_page(sbuf) == NFTL_YES)
        {
            //���pageû��ʹ�ã��Ѿ��������δʹ�õ�page

            break;
        }
        if( ((ret == 0)||(ret == ECC_LIMIT)) && (mbuf != NULL))
        {
			if(small_nand_power_off_ecc_error(zone,mbuf,sbuf) != 0)
			{
				NFTL_ERR("[NE]slc power off ecc error 4!!\n");
			}
			else
			{
            	nrc->cache_used[i] = 1;
            	if(nrc->max_page <(i+1))
            	{
                	nrc->max_page = i+1;
            	}
        	}
        }
    }
    num = i;
    for(;i<zone->nand_chip->pages_per_blk; i++)
    {
        if((nrc != NULL) && (nrc->cache_used[i] == 0))
        {
            mbuf = nrc->cache_addr[i];
            sbuf = nrc->cache_addr[i] + zone->nand_chip->bytes_per_page;
        }
        else
        {
            mbuf = NULL;
            sbuf = spare_data;
        }
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,mbuf,sbuf);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if(is_nouse_page(sbuf) == NFTL_YES)
        {
            j++;
        }
        else
        {
            flag = 1;
            NFTL_ERR("[NE]get_used_page_num used %d %d!\n",phy_block_ptr->phy_block.Block_NO,i);
            NFTL_ERR("[NE]%x %x %x %x %x ",sbuf[0],sbuf[1],sbuf[2],sbuf[3],sbuf[4]);
            NFTL_ERR("%x %x %x %x %x!!\n",sbuf[5],sbuf[6],sbuf[7],sbuf[8],sbuf[9]);
            if( ((ret == 0)||(ret == ECC_LIMIT)) && (mbuf != NULL))
            {
                nrc->cache_used[i] = 1;
                if(nrc->max_page <(i+1))
                {
                    nrc->max_page = i+1;
                }
            }
        }
    }
/*
    if(flag != 0)
    {
        for(i=0; i<zone->nand_chip->pages_per_blk; i++)
        {
            set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,0,spare_data);
            ret = zone->nftl_nand_read_page(zone,&phy_op_par);
            NFTL_ERR("[NE]%d %x %x %x %x %x ",i,spare_data[0],spare_data[1],spare_data[2],spare_data[3],spare_data[4]);
            NFTL_ERR("%x %x %x %x %x!!\n",spare_data[5],spare_data[6],spare_data[7],spare_data[8],spare_data[9]);
        }
    }
*/
    return num;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_used_page_num_no_crosstalk(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr,uint32 *ecc,struct _nand_rebuild_cache* nrc)
{
    uint32 i,j,num,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uchar *mbuf;
    uchar *sbuf;
    int good_page_num = -1;    //[0,zone->nand_chip->pages_per_blk]
    int total_good_num = 0;
    int blank_page = 0;


    *ecc = 0;
    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        if((nrc != NULL) && (nrc->cache_used[i] == 0))
        {
            mbuf = nrc->cache_addr[i];
            sbuf = nrc->cache_addr[i] + zone->nand_chip->bytes_per_page;
        }
        else
        {
            mbuf = NULL;
            if(SECTOR_CNT_OF_SINGLE_PAGE == 4)
            {
            	mbuf = zone->temp_page_buf;
        	}
            sbuf = spare_data;
        }

        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,mbuf,sbuf);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if((ret != 0)&&(ret != ECC_LIMIT))
        {
            NFTL_ERR("[NE]get_used_page_num_no_crosstalk ecc error block:%d page:%d!\n",phy_block_ptr->phy_block.Block_NO,i);
            if(good_page_num == -1)
            {
                good_page_num = i;
            }
        }
        else if(is_nouse_page(sbuf) == NFTL_YES)
        {
            //���pageû��ʹ�ã��Ѿ��������δʹ�õ�page
            if(good_page_num == -1)
            {
                good_page_num = i;
            }
            blank_page++;
            if(blank_page == 3)
            {
                break;
            }
        }
        else
        {
			if(small_nand_power_off_ecc_error(zone,mbuf,sbuf) != 0)
			{
				NFTL_ERR("[NE]slc power off ecc error 5!!\n");
			}
			else
			{
            	total_good_num++;
            	if(good_page_num == -1)
            	{
            	    nrc->cache_used[i] = 1;
            	    if(nrc->max_page <(i+1))
            	    {
            	        nrc->max_page = i+1;
            	    }
            	}    
            }
        }
    }

    if(good_page_num == -1)
    {
        good_page_num = zone->nand_chip->pages_per_blk;
    }
    else
    {
        if(total_good_num != good_page_num)
        {
            NFTL_ERR("[NE]cross talk block:%d total_good_num %d good_page_num: %d!\n",phy_block_ptr->phy_block.Block_NO,total_good_num,good_page_num);
            zone->smart->cross_talk_times++;
            for(i=0; i<nrc->max_page; i++)
            {
                if(nrc->cache_used[i] != 0)
                {
                    sbuf = nrc->cache_addr[i] + zone->nand_chip->bytes_per_page;
                    sbuf[14] = zone->smart->cross_talk_times;
                }
            }
        }
    }

    for(i=0; i<nrc->max_page; i++)
    {
        if(nrc->cache_used[i] != 0)
        {
            sbuf = nrc->cache_addr[i] + zone->nand_chip->bytes_per_page;
            if((sbuf[14] < 100) && (zone->smart->cross_talk_times <= sbuf[14]))
            {
                zone->smart->cross_talk_times = sbuf[14];
            }
        }
    }

    num = good_page_num;

    return num;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 check_cross_talk(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr)
{
    uint32 i,j,num,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uchar *mbuf = zone->temp_page_buf;
    uchar *sbuf;

    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        mbuf = NULL;
        sbuf = spare_data;
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,mbuf,sbuf);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if(ret == 0)
        {
            if((sbuf[14] <100 ) && (zone->smart->cross_talk_times <= sbuf[14]))
            {
                zone->smart->cross_talk_times = sbuf[14];
                break;
            }
        }
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
uint32 init_smart_info(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr)
{
    int ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _user_info user_info;

    MEMSET(zone->smart,0,sizeof(struct __smart));
    zone->smart->version = SMART_VERSION;
    zone->smart->total_normal_power_cycles++;
    if(phy_block_ptr == NULL)
    {
        return 0;
    }

    set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,zone->nand_chip->pages_per_blk-1,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
    ret = zone->nftl_nand_read_page(zone,&phy_op_par);

    if(is_phy_mapping_page(spare_data) == NFTL_YES)
    {
        user_info.smart = zone->temp_page_buf + zone->current_block.user_info.map_size;
        if(user_info.smart->version == SMART_VERSION)
        {
            MEMCPY(zone->smart,user_info.smart,sizeof(_smart));
            zone->smart->total_normal_power_cycles++;
            if(zone->smart->read_reclaim_utc == 0xffffffff)
            {
                zone->smart->read_reclaim_utc = 0;
            }
        }
    }

    print_smart(zone);

    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
uint32 get_used_block_count(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr)
{
    uint32 ret;
    _physic_op_par phy_op_par;
    uint32 special_data;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];

    set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
    ret = zone->nftl_nand_read_page(zone,&phy_op_par);
    special_data = get_block_used_count_from_oob(spare_data);

    return special_data;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
_phy_block_info* current_block_ecc_error(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr)
{
    int i,j,ret;
    _phy_block_info* phy_block;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    _physic_op_par phy_op_par2;

request_new_block:
    phy_block = out_phy_block_from_free_list(zone);
    if(phy_block == NULL)
    {
        NFTL_ERR("[NE]current_block_ecc_error no free block!!!\n");
        return NULL;
    }

    phy_block->block_used_count = phy_block_ptr->block_used_count;
    if(new_block_init_for_write(zone,phy_block,phy_block->block_used_count) != NFTL_SUCCESS)
    {
        NFTL_ERR("[NE]something is error here 16!\n");
		goto request_new_block;
		return NULL;
    }

    NFTL_ERR("[NE]do current_block_ecc_error %d!!\n",phy_block_ptr->phy_block.Block_NO);

    for(i=0,j=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);

        if(is_ftl_logic_page_data(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
            	if(small_nand_power_off_ecc_error(zone,zone->temp_page_buf,&spare_data[0]) != 0)
            	{
            		NFTL_ERR("[NE]slc power off ecc error 2!!\n");
            	}
            	else
            	{
                	NFTL_ERR("[NE]current_block_ecc ok page %d %d!!\n",i,ret);
                	set_physic_op_par(&phy_op_par2,phy_block->phy_block.Block_NO,j,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
                	zone->nftl_nand_write_page(zone,&phy_op_par2);
                	j++;
            	}
            }
            else
            {
                NFTL_ERR("[NE]current_block_ecc_error page %d!!\n",i);
            }
        }
        else if(is_ftl_special_data(spare_data) == NFTL_YES)
        {
            NFTL_ERR("[NE]current_block_ecc_error invalid page data %d!!\n",i);
        }
        else if(is_nouse_page(spare_data) == NFTL_YES)
        {
            ;
        }
        else
        {
            NFTL_ERR("[NE]current_block_ecc_error unkown page data %d!!\n",i);
        }
    }

    if(zone->zone_attr&SUPPORT_COSS_TALK)
    {
        erase_block(zone,phy_block_ptr,phy_block_ptr->erase_count+1);
    }
    else
    {
        erase_block(zone,phy_block_ptr,phy_block_ptr->erase_count+1);
    }

    NFTL_ERR("[NE]do current_block_ecc_error end %d %d!!\n",i,j);

    return phy_block;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
_phy_block_info* block_last_page_ecc_error(struct _nftl_zone * zone,_phy_block_info* phy_block_ptr)
{
    int i,j,ret;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uchar** temp_buf;

    NFTL_ERR("[NE]do block_last_page_ecc_error!!\n");
    j = 0;

    temp_buf = (uchar **)nftl_malloc(sizeof(uchar*) * MAX_PAGE_PER_BLOCK);
    if(!temp_buf)
    {
        NFTL_ERR("[NE]====no memory!!!!!=====\n");
    }

    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        temp_buf[i] = (uchar *)nftl_malloc(zone->nand_chip->bytes_per_page);
        if(temp_buf[i] == NULL)
        {
            NFTL_ERR("[NE]====no memory!!!!!=====\n");
        }
    }

    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
        ret = zone->nftl_nand_read_page(zone,&phy_op_par);
        if(is_nouse_page(spare_data) == NFTL_YES)
        {
            //���pageû��ʹ�ã��Ѿ��������δʹ�õ�page
            break;
        }

        if(is_ftl_logic_page_data(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
                MEMCPY(temp_buf[i],zone->temp_page_buf,zone->nand_chip->bytes_per_page);
                j++;
            }
        }
        else if(is_ftl_special_data(spare_data) == NFTL_YES)
        {
            if((ret == 0) || (ret == ECC_LIMIT))
            {
                MEMCPY(temp_buf[i],zone->temp_page_buf,zone->nand_chip->bytes_per_page);
                j++;
            }
            NFTL_ERR("[NE]current_block_ecc_error invalid page data!!\n");
        }
        else
        {
            NFTL_ERR("[NE]current_block_ecc_error unkown page data!!\n");
        }
    }

    set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
    ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
    if(ret != 0)
    {
        zone->nftl_nand_mark_bad_blk(zone,&phy_op_par);
        phy_block_ptr = out_phy_block_from_free_list(zone);
        if(phy_block_ptr == NULL)
        {
            NFTL_ERR("[NE]current_block_ecc_error no free block!!!\n");
            phy_block_ptr = NULL;
            goto  current_block_ecc_error_exit;
        }
        else
        {
            set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,zone->temp_page_buf,spare_data);
            zone->nftl_nand_erase_superblk(zone,&phy_op_par);
        }
    }

    for(i=0;i<j;i++)
    {
        set_physic_op_par(&phy_op_par,phy_block_ptr->phy_block.Block_NO,i,zone->nand_chip->bitmap_per_page,temp_buf[i],spare_data);
        zone->nftl_nand_write_page(zone,&phy_op_par);
    }

current_block_ecc_error_exit:
    for(i=0; i<zone->nand_chip->pages_per_blk; i++)
    {
        nftl_free(temp_buf[i]);
    }
    nftl_free(temp_buf);

    NFTL_ERR("[NE]do block_last_page_ecc_error end!!\n");
    return phy_block_ptr;

}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
void print_nftl_zone(struct _nftl_zone * zone)
{
    NFTL_DBG("[ND] nand3.5 version:0001 date:%s %s\n",__DATE__,__TIME__);
    NFTL_DBG("[ND]zone->nand_chip->blk_per_chip: %d \n",zone->nand_chip->blk_per_chip);
    NFTL_DBG("[ND]zone->nand_chip->bytes_per_page: %d \n",zone->nand_chip->bytes_per_page);
    NFTL_DBG("[ND]zone->nand_chip->pages_per_blk: %d \n",zone->nand_chip->pages_per_blk);
    NFTL_DBG("[ND]zone->nand_chip->max_erase_times: %d \n",zone->nand_chip->max_erase_times);
    NFTL_DBG("[ND]zone->nand_chip->support_read_reclaim: %d \n",zone->nand_chip->support_read_reclaim);
    NFTL_DBG("[ND]zone->test: %d \n",zone->test);
    NFTL_DBG("[ND]zone->zone_no: %d \n",zone->zone_no);
    NFTL_DBG("[ND]zone->zone_attr: %d \n",zone->zone_attr);
    NFTL_DBG("[ND]zone->blocks: %d \n",zone->blocks);
    NFTL_DBG("[ND]zone->bad_block: %d \n",zone->bad_block);
    NFTL_DBG("[ND]zone->logic_cap_in_sects: %d \n",zone->logic_cap_in_sects);
    NFTL_DBG("[ND]zone->backup_cap_in_sects: %d \n",zone->backup_cap_in_sects);
    NFTL_DBG("[ND]zone->free_block_num: %d \n",zone->free_block_num);
    NFTL_DBG("[ND]zone->gc_strategy.start_gc_free_blocks: %d \n",zone->gc_strategy.start_gc_free_blocks);
    NFTL_DBG("[ND]zone->gc_strategy.stop_gc_free_blocks: %d \n",zone->gc_strategy.stop_gc_free_blocks);
    NFTL_DBG("[ND]zone->gc_strategy.gc_page: %d \n",zone->gc_strategy.gc_page);
    NFTL_DBG("[ND]zone->gc_strategy.process: %d \n",zone->gc_strategy.process);
    NFTL_DBG("[ND]zone->prio_gc.prio_type : %d \n",zone->prio_gc.prio_type_now );
    NFTL_DBG("[ND]zone->zone_start_phy_block->phy_block.Block_NO: %d \n",zone->zone_start_phy_block->phy_block.Block_NO);
    NFTL_DBG("[ND]zone->zone_end_phy_block->phy_block.Block_NO: %d \n",zone->zone_end_phy_block->phy_block.Block_NO);
    NFTL_DBG("[ND]zone->zone_phy_page_map_for_gc: %x \n",zone->zone_phy_page_map_for_gc);
    NFTL_DBG("[ND]zone->current_block.user_info: %x \n",zone->current_block.user_info);
    NFTL_DBG("[ND]zone->current_block.block_info: %x \n",zone->current_block.block_info);
    NFTL_DBG("[ND]zone->current_block.block_info->phy_block.Block_NO: %d \n",zone->current_block.block_info->phy_block.Block_NO);
    NFTL_DBG("[ND]zone->current_block.page_used: %d \n",zone->current_block.page_used);
    NFTL_DBG("[ND]zone->current_block.block_info->block_used_count: %d \n",zone->current_block.block_info->block_used_count);

    if(zone->zone_attr&SUPPORT_COSS_TALK)
    {
        NFTL_DBG("[ND]zone->assist_block.user_info: %x \n",zone->assist_block.user_info);
        NFTL_DBG("[ND]zone->assist_block.block_info: %x \n",zone->assist_block.block_info);
        NFTL_DBG("[ND]zone->assist_block.block_info->phy_block.Block_NO: %d \n",zone->assist_block.block_info->phy_block.Block_NO);
        NFTL_DBG("[ND]zone->assist_block.page_used: %d \n",zone->assist_block.page_used);
        NFTL_DBG("[ND]zone->assist_block.block_info->block_used_count: %d \n",zone->assist_block.block_info->block_used_count);
    }
    NFTL_DBG("[ND]zone->read_reclaim_complete: %x \n",zone->read_reclaim_complete);
    NFTL_DBG("[ND]zone->temp_page_buf: %x \n",zone->temp_page_buf);
    NFTL_DBG("[ND]zone->max_erase_num: %d \n",zone->max_erase_num);
    NFTL_DBG("[ND]zone->cache.cache_totals: %x \n",zone->cache.cache_totals);

    NFTL_DBG("[ND]zone->cfg->nftl_dont_use_cache: %x \n",zone->cfg->nftl_dont_use_cache);
    NFTL_DBG("[ND]zone->cfg->nftl_use_cache_sort: %x \n",zone->cfg->nftl_use_cache_sort);
    NFTL_DBG("[ND]zone->cfg->nftl_support_gc_read_reclaim: %x \n",zone->cfg->nftl_support_gc_read_reclaim);
    NFTL_DBG("[ND]zone->cfg->nftl_support_wear_leveling: %x \n",zone->cfg->nftl_support_wear_leveling);
    NFTL_DBG("[ND]zone->cfg->nftl_need_erase: %x \n",zone->cfg->nftl_need_erase);
    NFTL_DBG("[ND]zone->cfg->nftl_min_free_block_num: %x \n",zone->cfg->nftl_min_free_block_num);
    NFTL_DBG("[ND]zone->cfg->nftl_gc_threshold_free_block_num: %x \n",zone->cfg->nftl_gc_threshold_free_block_num);
    NFTL_DBG("[ND]zone->cfg->nftl_min_free_block: %x \n",zone->cfg->nftl_min_free_block);
    NFTL_DBG("[ND]zone->cfg->nftl_gc_threshold_ratio_numerator: %x \n",zone->cfg->nftl_gc_threshold_ratio_numerator);
    NFTL_DBG("[ND]zone->cfg->nftl_gc_threshold_ratio_denominator: %x \n",zone->cfg->nftl_gc_threshold_ratio_denominator);
    NFTL_DBG("[ND]zone->cfg->nftl_max_cache_num: %d \n",zone->cfg->nftl_max_cache_num);
    NFTL_DBG("[ND]zone->cfg->nftl_max_cache_write_num: %d \n",zone->cfg->nftl_max_cache_write_num);
    NFTL_DBG("[ND]zone->cfg->nftl_cross_talk: %x \n",zone->cfg->nftl_cross_talk);
    NFTL_DBG("[ND]zone->cfg->nftl_read_claim_interval: %d \n",zone->cfg->nftl_read_claim_interval);
    print_smart(zone);

}


/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_phy_read(unsigned short nDieNum, unsigned short nBlkNum, unsigned short nPage)
{
    int ret;
    unsigned char *buf;
    unsigned char spare[16];

    buf = (unsigned char *)nftl_malloc(4096);

    ret = PageRead(nDieNum,nBlkNum,nPage,8,buf,spare);

    NFTL_ERR("[NE]%x %x %x %x %x ",spare[0],spare[1],spare[2],spare[3],spare[4]);
    NFTL_ERR("%x %x %x %x %x!!\n",spare[5],spare[6],spare[7],spare[8],spare[9]);

    NFTL_ERR("buf:%x %x %x %x %x ",buf[0],buf[1],buf[2],buf[3],buf[4]);
    NFTL_ERR("%x %x %x %x %x %x!!\n",buf[5],buf[6],buf[7],buf[8],buf[9],buf[10]);

    nftl_free(buf);

    return ret;
}


/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_phy_read2(unsigned short nDieNum, unsigned short nBlkNum, unsigned short nPage)
{
    int ret;
    unsigned char *buf;
    struct boot_physical_param  para;
    unsigned char spare[64];

    buf = (unsigned char *)nftl_malloc(16384);

    NAND_PhysicLock();

    para.chip  = nDieNum;
    para.block = nBlkNum;
    para.page  = nPage;
    para.mainbuf = (void *) buf;
    para.oobbuf = spare;

    ret = PHY_SimpleRead( &para );

    NAND_PhysicUnLock();


    NFTL_ERR("[NE]%x %x %x %x %x ",spare[0],spare[1],spare[2],spare[3],spare[4]);
    NFTL_ERR("%x %x %x %x %x!!\n",spare[5],spare[6],spare[7],spare[8],spare[9]);

    NFTL_ERR("buf:%x %x %x %x %x ",buf[0],buf[1],buf[2],buf[3],buf[4]);
    NFTL_ERR("%x %x %x %x %x %x!!\n",buf[5],buf[6],buf[7],buf[8],buf[9],buf[10]);


    nftl_free(buf);

    return ret;

}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_zone_phy_read(struct _nftl_zone *zone,uint16 block,uint16 page)
{
    _phy_block_info*    p_phy_block_info;
    _physic_op_par phy_op_par;
    int ret;
    unsigned char *buf;
    unsigned char spare[16];

    buf = (unsigned char *)nftl_malloc(4096);
    p_phy_block_info = get_phy_block_addr(zone,block);

    set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,page,8,buf,spare);
    ret = zone->nftl_nand_read_page(zone,&phy_op_par);

    NFTL_ERR("[NE]%x %x %x %x %x ",spare[0],spare[1],spare[2],spare[3],spare[4]);
    NFTL_ERR("%x %x %x %x %x!!\n",spare[5],spare[6],spare[7],spare[8],spare[9]);

    NFTL_ERR("buf:%x %x %x %x %x ",buf[0],buf[1],buf[2],buf[3],buf[4]);
    NFTL_ERR("%x %x %x %x %x %x!!\n",buf[5],buf[6],buf[7],buf[8],buf[9],buf[10]);

    nftl_free(buf);

    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_zone_phy_write(struct _nftl_zone *zone,uint16 block,uint16 page)
{
    _phy_block_info*    p_phy_block_info;
    _physic_op_par phy_op_par;
    int ret;
    unsigned char *buf;
    unsigned char spare[16];

    buf = (unsigned char *)nftl_malloc(8192);
    p_phy_block_info = get_phy_block_addr(zone,block);

    MEMSET(buf,0xa5,4096);
    spare[0] = 0xff;
    spare[1] = 0xff;
    spare[2] = 0xff;
    spare[3] = 0xff;
    spare[4] = 0xff;
    spare[5] = 0xa5;
    spare[6] = 0xa5;
    spare[7] = 0xff;
    spare[8] = 0xff;
    spare[9] = 0xff;
    spare[10] = 0xff;

    set_physic_op_par(&phy_op_par,p_phy_block_info->phy_block.Block_NO,page,zone->nand_chip->bitmap_per_page,buf,spare);
    ret = zone->nftl_nand_write_page(zone,&phy_op_par);

    nftl_free(buf);

    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_phy_write(unsigned short nDieNum, unsigned short nBlkNum, unsigned short nPage)
{
    int ret;
    unsigned char *buf;
    unsigned char spare[16];

    buf = (unsigned char *)nftl_malloc(8192);

    MEMSET(buf,0xa5,4096);
    spare[0] = 0xff;
    spare[1] = 0xff;
    spare[2] = 0xff;
    spare[3] = 0xff;
    spare[4] = 0xff;
    spare[5] = 0xa5;
    spare[6] = 0xa5;
    spare[7] = 0xff;
    spare[8] = 0xff;
    spare[9] = 0xff;
    spare[10] = 0xff;

    ret = PageWrite(nDieNum,nBlkNum,nPage,8,buf,&spare);

    nftl_free(buf);

    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_zone_erase(struct _nftl_zone *zone,uint16 block,uint16 erase_num)
{
    int ret;
    _phy_block_info*    p_phy_block_info;
    p_phy_block_info = get_phy_block_addr(zone,block);

    p_phy_block_info = out_phy_block_from_free_list_by_block(zone,p_phy_block_info);

    ret = erase_block(zone,p_phy_block_info,erase_num);
    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_phy_erase(unsigned short nDieNum, unsigned short nBlkNum)
{
    int ret;

    ret = BlockErase(nDieNum,nBlkNum);

    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_dbg_single_phy_erase(unsigned short nDieNum, unsigned short nBlkNum)
{
    int ret;
	unsigned short block_num;
    //ret = nand_physic_erase_block(nDieNum,nBlkNum);
    block_num = nBlkNum / 2;
    ret = BlockErase(nDieNum,block_num);
    return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
void clean_block_list(struct _nftl_zone* zone)
{
    _phy_block_info* p;

    while(1)
    {
        p = out_phy_block_from_free_list(zone);
        if(p == NULL)
        {
            break;
        }
        p->invalid_page_count = 0;
        p->info = 0;
        p->block_used_count = 0xffffffff;
        p->invalid_page_next = NULL;
        p->invalid_page_prev = NULL;
        p->free_next = NULL;
        p->free_prev = NULL;
        p->block_used_next = NULL;
        p->block_used_prev = NULL;
    }

    while(1)
    {
        p = out_phy_block_from_invalid_page_list(zone);
        if(p == NULL)
        {
            break;
        }
        p->invalid_page_count = 0;
        p->info = 0;
        p->block_used_count = 0xffffffff;
        p->invalid_page_next = NULL;
        p->invalid_page_prev = NULL;
        p->free_next = NULL;
        p->free_prev = NULL;
        p->block_used_next = NULL;
        p->block_used_prev = NULL;
    }
    return;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_clean_zone_table2(struct _nftl_zone *zone)
{
    uint32 i,buf_nums,total_pages,len,bytes,total_bytes;

    total_pages = zone->logic_cap_in_sects / zone->nand_chip->sector_per_page;
    total_bytes = total_pages * sizeof(_mapping_page);

    NFTL_ERR("zoneNO:%d total_pages: %d\n",zone->zone_no,total_pages);

#if   MALLOC_FLAG

    buf_nums = total_bytes / MAX_MALLOC_BYTES;

    for(i=0; i<buf_nums; i++)
    {
        MEMSET((void*) zone->zone_logic_page_map[i],0xff,MAX_MALLOC_BYTES);
        NFTL_ERR("MEMSET bytes: %d\n",MAX_MALLOC_BYTES);
    }

    bytes = total_bytes % MAX_MALLOC_BYTES;

    if(bytes != 0)
    {
        MEMSET((void*) zone->zone_logic_page_map[i],0xff,bytes);
        NFTL_ERR("MEMSET bytes: %d\n",bytes);
    }

#else

    MEMSET((void*) zone->zone_logic_page_map,0xff,total_bytes);

#endif

    zone->current_block.block_info = NULL;
	zone->current_block.page_used = 0xffff;
	//zone->current_block.block_info->block_used_count = 0xffffffff;

    zone->assist_block.block_info = NULL;
	zone->assist_block.page_used = 0xffff;
	//zone->assist_block.block_info->block_used_count = 0xffffffff;

    zone->free_head.free_next = NULL;
    zone->free_head.free_prev = NULL;
    zone->free_head.invalid_page_next = NULL;
    zone->free_head.invalid_page_prev = NULL;
    zone->free_head.block_used_next = NULL;
    zone->free_head.block_used_prev = NULL;

    zone->invalid_page_head.free_next = NULL;
    zone->invalid_page_head.free_prev = NULL;
    zone->invalid_page_head.invalid_page_next = NULL;
    zone->invalid_page_head.invalid_page_prev = NULL;
    zone->invalid_page_head.block_used_next = NULL;
    zone->invalid_page_head.block_used_prev = NULL;

    zone->block_used_head.free_next = NULL;
    zone->block_used_head.free_prev = NULL;
    zone->block_used_head.invalid_page_next = NULL;
    zone->block_used_head.invalid_page_prev = NULL;
    zone->block_used_head.block_used_next = NULL;
    zone->block_used_head.block_used_prev = NULL;

    zone->bad_block = 0;
    zone->free_block_num = 0;

    zone->prio_gc.gc_num = 0;
    for(i=0; i<MAX_PRIO_GC_NUM; i++)
    {
        zone->prio_gc.prio_gc_node[i].gc_no = i;
        zone->prio_gc.prio_gc_node[i].prio_type = PRIO_NONE;
        zone->prio_gc.prio_gc_node[i].phy_block_info = NULL;
        zone->prio_gc.prio_gc_node[i].prio_gc_next = NULL;
        zone->prio_gc.prio_gc_node[i].prio_gc_prev = NULL;
    }

    zone->prio_gc.prio_gc_head.gc_no = 0xff;
    zone->prio_gc.prio_type_now = PRIO_NONE;
    zone->prio_gc.prio_gc_head.prio_type = PRIO_NONE;
    zone->prio_gc.prio_gc_head.phy_block_info = NULL;
    zone->prio_gc.prio_gc_head.prio_gc_next = NULL;
    zone->prio_gc.prio_gc_head.prio_gc_prev = NULL;

    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_clean_zone_table(void *p)
{
    struct _nftl_zone *zone = (struct _nftl_zone *)p;

    uint32 i,buf_nums,total_pages,len,bytes,total_bytes;

    __nand_flush_write_cache(zone,1000);

    clean_block_list(zone);

    nand_clean_zone_table2(zone);

    nftl_cache_exit(zone);

    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int nand_find_zone_table(void *p)
{
    struct _nftl_zone *zone = (struct _nftl_zone *)p;

    clean_block_list(zone);

    nand_clean_zone_table2(zone);

    NFTL_ERR("build_zone_list start\n");
    build_zone_list(zone);

    NFTL_ERR("nftl_cache_init start\n");
    nftl_cache_init(zone);

    NFTL_ERR("=================================2=======================================\n");
    print_block_invalid_list(zone);
    print_free_list(zone);
    NFTL_ERR("=================================2=======================================\n");

    NFTL_ERR("nand_find_zone_table end\n");
}



/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
extern uint32 __nand_write(struct _nftl_zone* zone,uint32 start_sector,uint32 len,uchar *buf);
int write_data_to_nand(struct _nftl_zone* zone)
{
    uchar * buf;
    int i;

    buf = (uchar *)nftl_malloc(512);

    MEMSET(buf,0xaa,512);

    for(i=0;i<0x9800;i++)  //19M
    {
        __nand_write(zone,i,1,buf);
    }
    nftl_free(buf);
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/

int nand_check_table(void *zone_addr)
{
    struct _nftl_zone *zone = (struct _nftl_zone *)zone_addr;

    __nand_flush_write_cache(zone,1000);

NFTL_ERR("[ND]==========================\n");
    print_nftl_zone(zone);

NFTL_ERR("[ND]==========================\n");

    nand_clean_zone_table((void*)zone);

NFTL_ERR("[ND]==========================\n");

    nand_find_zone_table((void*)zone);

    write_data_to_nand(zone);

NFTL_ERR("[ND]==========================\n");

    return 0;
}

struct panic_info {
	uint32 block;
	uint32 start_pages;
	uint32 pages;
	uint32 order;
	uint32 start_sector;
	uint32 sector_num;
	uint32 resver[2];
};
struct panic_info _panic_info[4] = {0};
uint32	g_panic_count = 0;
uint32	g_use_block = 0;
uint32	g_erase_flag = 0;

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
static int write_panic_info(struct _nftl_blk *nftl_blk, uchar *buf)
{
	struct _nftl_zone * zone;
	_phy_block_info* block_free;
	uint32 i, j;
	_physic_op_par phy_op_par;
	uchar spare_data[BYTES_OF_USER_PER_PAGE];
	int ret;
	unsigned char *ptr = buf;
	
	zone = nftl_blk->nftl_zone;

	MEMCPY(buf, _panic_info, sizeof(struct panic_info) * 4);
	block_free = zone->panic_data.block[MAX_PANIC_BLOCK_NUM - 1];
	spare_data[SPARE_OFFSET_BAD_FLAG] = 0xff;
	spare_data[SPARE_OFFSET_SPECIAL_FLAG] = SPARE_SPECIAL_DATA;
	spare_data[SPARE_OFFSET_PANIC_FLAG] = BLOCK_FOR_PANIC_INFO_BLK;
	set_physic_op_par(&phy_op_par,block_free->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
	if(g_panic_count == 0)
	{
		ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
		block_free->invalid_page_count = 0;
		block_free->erase_count++;
		set_spare_data(spare_data, block_free->erase_count, SPARE_OFFSET_PANIC_BLOCK__ERASE_TIMES, 2);
	}
	
//for debug
/*
	NFTL_ERR("g_use_block = %d ! g_panic_count = %d\n", g_use_block, g_panic_count);
	NFTL_ERR("[ND]write_panic_info !\n");
	for(i = 0; i < sizeof(struct panic_info) * 4; i++) 
	{		
		if(i % 16 == 0)
			NFTL_ERR("%4d:	", i);		
		NFTL_ERR("%.2x ", *ptr++);		
		if(i % 16 == 15)			
			NFTL_ERR("\n"); 
	}
*/

	for (i = g_panic_count * 4; i < g_panic_count * 4 + 4; i++)
	{
//		NFTL_ERR("[ND]write panic info data block: %d page %d !\n",block_free->phy_block.Block_NO, i);
		set_physic_op_par(&phy_op_par,block_free->phy_block.Block_NO, i, zone->nand_chip->bitmap_per_page, buf, spare_data);
		ret = zone->nftl_nand_write_page(zone,&phy_op_par);
		PHY_WaitAllRbReady();
	}

	return ret;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int write_panic_data(struct _nftl_blk *nftl_blk,uint32 start_sector, uint32 sector_num, uchar *buf)
{
    int ret;
    struct _nftl_zone * zone;
    uint32 total_pages,blocks,pages,i,j,k;
    _phy_block_info* block_free;
    uchar spare_data[BYTES_OF_USER_PER_PAGE];
    _physic_op_par phy_op_par;
    uchar* data_buf;

    pages = 0;
    zone = nftl_blk->nftl_zone;
    total_pages = sector_num / zone->nand_chip->sector_per_page;

    if((sector_num % zone->nand_chip->sector_per_page) != 0)
    {
        total_pages++;
    }

    blocks = total_pages / zone->nand_chip->pages_per_blk;
    if((total_pages % zone->nand_chip->pages_per_blk) != 0)
    {
        blocks++;
    }

//    NFTL_ERR("[ND]write panic data logic addr: %d lens %d !\n",start_sector,sector_num);

    if(blocks > MAX_PANIC_BLOCK_NUM - 1 || g_panic_count > 3)
    {
    	NFTL_ERR("[NE]param error panic call cnt = %d over 4\n", g_panic_count);
        return 1;
    }

    for(i=0; i<blocks; i++)
    {
//        NFTL_ERR("[ND]block %d !\n",zone->panic_data.block[i]->phy_block.Block_NO);
    }

    data_buf = buf;
    MEMSET(spare_data,0xa5,BYTES_OF_USER_PER_PAGE);
//////
	j = _panic_info[g_panic_count].start_pages;
	block_free = zone->panic_data.block[g_use_block];
	_panic_info[g_panic_count].block = block_free->phy_block.Block_NO;
	_panic_info[g_panic_count].start_sector = start_sector;
	_panic_info[g_panic_count].sector_num= sector_num;
//////	
    for(i = g_use_block; i < MAX_PANIC_BLOCK_NUM - 1; i++)
    {
        block_free = zone->panic_data.block[i];
        if(block_free == NULL)
        {
            NFTL_ERR("[ND]not panic block !\n");
            return 1;
        }
        if(pages >= total_pages)
        {
            break;
        }

		if (g_use_block == g_erase_flag)
		{
			set_physic_op_par(&phy_op_par,block_free->phy_block.Block_NO,0,zone->nand_chip->bitmap_per_page,NULL,NULL);
		    ret = zone->nftl_nand_erase_superblk(zone,&phy_op_par);
		    block_free->invalid_page_count = 0;
			block_free->erase_count++;
			g_erase_flag++;
		}

        for(j; j<zone->nand_chip->pages_per_blk; j++)
        {
//            NFTL_ERR("[ND]write panic data block: %d page %d !\n",block_free->phy_block.Block_NO,j);
            spare_data[SPARE_OFFSET_BAD_FLAG] = 0xff;
            spare_data[SPARE_OFFSET_SPECIAL_FLAG] = SPARE_SPECIAL_DATA;
            spare_data[SPARE_OFFSET_PANIC_FLAG] = BLOCK_FOR_PANIC_FLAG;
            spare_data[SPARE_OFFSET_PANIC_NFTL] = zone->zone_no;
            spare_data[SPARE_OFFSET_PANIC_DATA_BLOCK_NUM] = blocks;
            set_spare_data(spare_data,block_free->erase_count,SPARE_OFFSET_PANIC_BLOCK__ERASE_TIMES,2);
            spare_data[SPARE_OFFSET_PANIC_BLOCK_NO] = i;
            set_spare_data(spare_data,sector_num,SPARE_OFFSET_PANIC_DATA_SECTORS,2);
            set_spare_data(spare_data,start_sector,SPARE_OFFSET_PANIC_DATA_ADDR,4);

            set_physic_op_par(&phy_op_par,block_free->phy_block.Block_NO,j,zone->nand_chip->bitmap_per_page,data_buf,spare_data);
            ret = zone->nftl_nand_write_page(zone,&phy_op_par);
            PHY_WaitAllRbReady();

            data_buf += zone->nand_chip->bytes_per_page;
            pages++;
            if(pages >= total_pages)
            {
                break;
            }
        }
        j++;
		/*
		* dummy data
		*/
        for(k=0; k<3; k++)
        {
            if(j < zone->nand_chip->pages_per_blk)
            {
 //           	NFTL_ERR("[ND]write panic dummy data block: %d page %d !\n",block_free->phy_block.Block_NO,j);
                set_physic_op_par(&phy_op_par,block_free->phy_block.Block_NO,j,zone->nand_chip->bitmap_per_page,data_buf,spare_data);
                ret = zone->nftl_nand_write_page(zone,&phy_op_par);
                PHY_WaitAllRbReady();
                j++;
            }
        }
		if (j >= zone->nand_chip->pages_per_blk)
		{
			g_use_block++;
			j = 0;
		}
    }
	/*
	*	
	*/
	_panic_info[g_panic_count].pages = total_pages;
	if (g_panic_count + 1 < 4)
	{
		if (j == 0)
			_panic_info[g_panic_count + 1].start_pages = 0;
		else
			_panic_info[g_panic_count + 1].start_pages = j;
	}

	_panic_info[g_panic_count].order = g_panic_count;
	/*
	*	write info block
	*/
	write_panic_info(nftl_blk, data_buf);
	g_panic_count ++;

    return 0;
}

/*****************************************************************************
*Name         :
*Description  :
*Parameter    :
*Return       :
*Note         :
*****************************************************************************/
int backup_panic_block(struct _nftl_zone * zone)
{
    int ret,i;

    for(i=0; i<MAX_PANIC_BLOCK_NUM; i++)
    {
        zone->panic_data.block[i] = out_phy_block_from_free_list(zone);
        if(zone->panic_data.block[i] != NULL)
        {
            NFTL_ERR("[ND] panic block %d!\n",zone->panic_data.block[i]->phy_block.Block_NO);
        }
        else
        {
            NFTL_ERR("[ND]not panic block!!!\n");
        }
    }

    return ret;
}
