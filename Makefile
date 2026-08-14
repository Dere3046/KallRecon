kallrecon-objs := src/main.o lib/core.o lib/slide.o lib/anchor.o src/verify.o
test_probe-objs := test/test_main.o test/dbg.o lib/core.o lib/slide.o lib/anchor.o

 ifeq ($(TARGET),test)
 obj-m := test_probe.o
 ccflags-y += -DKALLRECON_DEBUG
 else
 obj-m := kallrecon.o
 endif

ifeq ($(CHECK),1)
ccflags-y += -DKALLRECON_CHECK
endif

ifdef KALLRECON_MODULE_LOOKUP
ccflags-y += -DKALLRECON_MODULE_LOOKUP
endif

ccflags-y += -std=gnu11
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ODIR := $(MDIR)/out/$(VER)

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))
$(info -- ODIR: $(ODIR))

all:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) modules
clean:
	make -C $(KDIR) M=$(ODIR) src=$(MDIR) clean

$(obj)/%.o: $(src)/%.c $(recordmcount_source) FORCE
	$(call if_changed_rule,cc_o_c)
	$(call cmd,force_checksrc)

$(obj)/%.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
