# You can adjust the toolchain as you need
#TOOLCHAIN_PATH = ~/toolchain/asdk-4.8.1-a7-EL-3.10-0.9.33-a32nt-130828/
TOOLCHAIN_PATH = /home/flash/Realtek-1195/TRUNK/SDK/bootcode/tmp/asdk-4.8.1-a7-EL-3.10-0.9.33-a32nt-130828/

CROSS_COMPILER = arm-linux
#CROSS_COMPILER = arm-linux-gnueabihf
rm=/bin/rm -f
cp=/bin/cp -f
CC= $(TOOLCHAIN_PATH)/bin/$(CROSS_COMPILER)-g++
AR= $(TOOLCHAIN_PATH)/bin/$(CROSS_COMPILER)-ar cr
RANLIB=$(TOOLCHAIN_PATH)/bin/$(CROSS_COMPILER)-ranlib
STRIP=$(TOOLCHAIN_PATH)/bin/$(CROSS_COMPILER)-strip

#CC= g++
#AR= ar
#RANLIB= ranlib
#STRIP= strip

INCS= -I./include -I./
CFLAGS =  -g -Os -march=armv7-a -Wall -std=c++11 -static
#CFLAGS = -g -Os -Wall -std=c++11

GIT_DES := $(shell git describe --abbrev=4 --dirty --always --tags)
GIT_VER := $(shell git rev-list HEAD --count)

OBJS= src/main.o

LIBS += -lcrypt
#LIBS += -Wl,--start-group -L./lib/ -lMCP -lion -lpthread -lefuse -Wl,--end-group

DEFINES += -DGIT_VERSION=\"$(GIT_DES)\ -\ rev.$(GIT_VER)\"
CFLAGS += $(INCS) $(DEFINES)

all: subdir userctl

subdir:

userctl: $(OBJS) 
	$(CC) -o userctl $(CFLAGS) $(OBJS) $(LIBS) 
	$(STRIP) userctl

clean:
	rm -rf $(OBJS) userctl *.a *.o *.bak ./src/*.bak ./include/*.bak *.s 

%.o: %.cpp
	$(CC) -c $< $(CFLAGS) -o $@

%.o: %.c
	$(CC) -c $< $(CFLAGS) -o $@
