#use "-Os" flags.
use-flags := -Os
#Don't use "-O2" flags.
not-use-flags := -O2
KBUILD_CFLAGS := $(filter-out $(not-use-flags), $(KBUILD_CFLAGS))
KBUILD_CFLAGS += $(use-flags)

subdir- += standby
obj-y	 += pm_tmp.o 

pm_tmp-y :=	mem_mapping.o               \
		mem_divlibc.o               \
		mem_cpu.o                   \
		mem_cpu_asm.o               \
		mem_mmu_pc_asm.o            \
		mem_mmu_pc.o                \
		mem_int.o                   \
		mem_clk.o                   \
		mem_tmr.o                   \
		mem_tmstmp.o                \
		mem_twi.o                   \
		mem_gpio.o                  \
		mem_sram.o                  \
		mem_ccu.o                   \
		mem_cci400.o                \
		mem_gtbus.o                 \
		pm_debug.o                  \
		mem_timing.o                \
		mem_hwspinlock.o              \
		pm.o                        \
		extended_standby.o          \
		standby/super/super_power.o \
		standby/super/super_twi.o   \
		standby/super/super_clock.o \
		standby.o		    \
		mem.o

$(obj)/mem_mapping.o              : $(obj)/pm_tmp_xx.o
$(obj)/mem_divlibc.o              : $(obj)/pm_tmp_xx.o
$(obj)/mem_cpu.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_cpu_asm.o              : $(obj)/pm_tmp_xx.o
$(obj)/mem_mmu_pc_asm.o           : $(obj)/pm_tmp_xx.o
$(obj)/mem_mmu_pc.o               : $(obj)/pm_tmp_xx.o
$(obj)/mem_int.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_clk.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_tmr.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_tmstmp.o               : $(obj)/pm_tmp_xx.o
$(obj)/mem_twi.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_gpio.o                 : $(obj)/pm_tmp_xx.o
$(obj)/mem_serial.o               : $(obj)/pm_tmp_xx.o
$(obj)/mem_sram.o                 : $(obj)/pm_tmp_xx.o
$(obj)/mem_ccu.o                  : $(obj)/pm_tmp_xx.o
$(obj)/mem_cci400.o               : $(obj)/pm_tmp_xx.o
$(obj)/mem_gtbus.o                : $(obj)/pm_tmp_xx.o
$(obj)/pm_debug.o                 : $(obj)/pm_tmp_xx.o
$(obj)/mem_timing.o               : $(obj)/pm_tmp_xx.o
$(obj)/mem_hwspinlock.o             : $(obj)/pm_tmp_xx.o
$(obj)/pm.o                       : $(obj)/pm_tmp_xx.o
$(obj)/extended_standby.o         : $(obj)/pm_tmp_xx.o
$(obj)/standby/super/super_power.o: $(obj)/pm_tmp_xx.o
$(obj)/standby/super/super_twi.o  : $(obj)/pm_tmp_xx.o
$(obj)/standby/super/super_clock.o: $(obj)/pm_tmp_xx.o
$(obj)/mem.o			  : $(obj)/pm_tmp_xx.o	

$(obj)/pm_tmp_xx.o			: $(obj)/standby/super/resume/resume1.code $(obj)/standby/standby.code FORCE
$(obj)/standby.o			: $(obj)/standby/standby.code FORCE
$(obj)/standby/super/resume/resume1.code: $(obj)/standby/standby.code FORCE

$(obj)/standby/standby.code: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/standby
	
