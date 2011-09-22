
obj-m := ps3_jupiter.o
obj-m += ps3_jupiter_sta.o

CFLAGS_ps3_jupiter.o=-DDEBUG
CFLAGS_ps3_jupiter_sta.o=-DDEBUG

ifeq ($(MAKING_MODULES),1)
-include $(TOPDIR)/Rules.make
endif
