/*
 * arch/arm/mach-sunxi/include/mach/sun8i/memory-sun8iw5p1.h
 *
 * Copyright(c) 2013-2015 Allwinnertech Co., Ltd.
 *      http://www.allwinnertech.com
 *
 * Author: liugang <liugang@allwinnertech.com>
 *
 * sun8i memory header file
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __MEMORY_SUN8I_W5P1_H
#define __MEMORY_SUN8I_W5P1_H

#define PLAT_PHYS_OFFSET         UL(0x40000000)
#ifdef CONFIG_EVB_PLATFORM
#define PLAT_MEM_SIZE            SZ_2G
#else
#define PLAT_MEM_SIZE            SZ_256M
#endif

#define SYS_CONFIG_MEMBASE       (PLAT_PHYS_OFFSET + SZ_32M + SZ_16M)        /* 0x43000000 */
#define SYS_CONFIG_MEMSIZE       (SZ_64K)                                    /* 0x00010000 */

#define SUPER_STANDBY_MEM_BASE   (SYS_CONFIG_MEMBASE + SYS_CONFIG_MEMSIZE)   /* 0x43010000 */
#define SUPER_STANDBY_MEM_SIZE   (SZ_2K)                                     /* 0x00000800 */

#define SRAM_DDRFREQ_OFFSET	0xf0000000
#define __sram	__section(.sram.text)
#define __sramdata __section(.sram.data)

#define SUNXI_DDRFREQ_SRAM_SECTION(OFFSET, align) 			\
	. = ALIGN(align);					\
	__sram_start = .;					\
	.sram_text OFFSET : AT(__sram_start) {			\
		. = ALIGN(align);				\
		__sram_text_start = .;				\
		*(.sram.text)					\
		__sram_text_end = .;				\
	}							\
	.sram_data OFFSET + SIZEOF(.sram_text) :		\
		AT(__sram_start + SIZEOF(.sram_text)) {		\
		. = ALIGN(align);				\
		__sram_data_start = .;				\
		*(.sram.data)					\
		__sram_data_end = .;				\
	}							\
	. = __sram_start + SIZEOF(.sram_text) +			\
			SIZEOF(.sram_data);			\
	__sram_end = .;

#endif /* __MEMORY_SUN8I_W5P1_H */
