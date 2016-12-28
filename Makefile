
MEM_FILTER_MODULE = memfilter

ifneq ($(KERNELRELEASE),) 

ccflags-y += 

obj-m += $(MEM_FILTER_MODULE).o
$(MEM_FILTER_MODULE)-objs := filter.o vdisk.o

else

KERNELDIR ?= /lib/modules/`uname -r`/build/

PWD := $(shell pwd)
FILTER_TOOL := filter_tool

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(MAKE) -C ${FILTER_TOOL}
clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	$(RM) Modules.markers modules.order
	$(MAKE) -C ${FILTER_TOOL} clean

endif
