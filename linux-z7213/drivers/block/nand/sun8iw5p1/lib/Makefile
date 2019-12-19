################################################################################
#
# Common Variables that already set:
#     LICHEE_KDIR
#     LICHEE_MOD_DIR
#     CROSS_COMPILE
#     ARCH
#
#################################################################################
CFLAGS = -g -c -nostdlib -march=armv7-a -marm -fno-unwind-tables \
		 -fno-asynchronous-unwind-tables -mlittle-endian -O2 -msoft-float
LIB=libnand.a
OBJ=src/nftl/nftl_list.o  \
         	src/nftl/nftl_logic.o \
         	src/nftl/nftl_gc.o \
         	src/nftl/nftl_cache.o \
         	src/nftl/nftl_sector_cache.o \
         	src/nftl/nftl_common.o \
         	src/nftl/nftl_build.o \
         	src/nftl/nftl_start.o \
         	src/nftl/nftl_interface.o \
         	src/nftl_interface/nftl_init.o \
         	src/nftl_interface/nftl_hw_interface.o \
         	src/nftl_interface/nftl_uboot_interface.o \
         	src/physic/nand_format.o \
         	src/physic/nand_id.o \
         	src/physic/nand_phy.o \
         	src/physic/nand_physic_interface.o \
         	src/physic/nand_scan.o \
         	src/physic/nand_simple_r.o \
         	src/physic/nand_simple_w.o \
         	src/physic/nfc_reg.o \
         	src/physic/nfc_r.o \
         	src/physic/nfc_w.o \
         	src/phy/build_nand_partition.o \
         	src/phy/build_phy_partition.o \
         	src/phy/hw_phy.o \
         	src/phy/nand_info_init.o \
         	src/phy/phy_input.o    	\
         	src/phy_v2/nand_info_init_v2.o \
         	src/phy_v2/build_phy_partition_v2.o \

.PHONY: install clean lib

install: $(LIB)
	cp libnand.a ../libnand_sun8iw5p1

$(OBJ) : src/nftl/nftl_type.h src/nftl/nftl.h src/nftl/nftl_inc.h src/nftl_interface/nftl_cfg.h src/nftl_interface/nftl_interface.h src/nftl_interface/nftl_blk.h src/physic/nand_drv_cfg.h src/physic/nand_drv_cfg.h src/physic/nand_drv_cfg.h src/physic/nand_format.h src/physic/nand_physic.h src/physic/nand_physic_interface.h src/physic/nand_scan.h src/physic/nand_simple.h src/physic/nand_type.h src/physic/nfc.h src/physic/nfc.h src/physic/nfc.h src/phy/mbr.h src/phy/phy.h
	$(CC) $(CFLAGS) -c $(@:%.o=%.c) -o $@

$(LIB) : $(OBJ)
	$(AR) -rcs $@ $^

clean:
	-rm $(OBJ) $(LIB)
