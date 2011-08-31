
obj-m += ps3_jupiter.o
obj-m += ps3_jupiter_sta.o

CFLAGS_ps3_jupiter.o=-DDEBUG
CFLAGS_ps3_jupiter_sta.o=-DDEBUG

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
