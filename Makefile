ON_DEVICE = yes

ifdef ON_DEVICE
TOOLCHAIN_PATH = /usr/local/cross-tool/bin/
CROSS_COMPILER_PREFIX = arm-linux-gnueabihf-
endif

rm=/bin/rm -f
cp=/bin/cp -f
CC= $(TOOLCHAIN_PATH)$(CROSS_COMPILER_PREFIX)g++
AR= $(TOOLCHAIN_PATH)$(CROSS_COMPILER_PREFIX)ar cr
RANLIB= $(TOOLCHAIN_PATH)$(CROSS_COMPILER_PREFIX)ranlib
STRIP= $(TOOLCHAIN_PATH)$(CROSS_COMPILER_PREFIX)strip

INCS= -I./include -I./

CFLAGS = -g -Os -Wall -std=c++11 
ifdef ON_DEVICE
CFLAGS += -march=armv7-a
endif

GIT_DES := $(shell git describe --abbrev=4 --dirty --always --tags)
GIT_VER := $(shell git rev-list HEAD --count)

OBJS= src/main.o

LIBS += -lcrypt
#LIBS += -Wl,--start-group -L./lib/ -lMCP -lion -lpthread -lefuse -Wl,--end-group

DEFINES += -DGIT_VERSION=\"rev.$(GIT_VER)\ -\ $(GIT_DES)\"
ifdef ON_DEVICE
DEFINES += -DON_DEVICE
endif

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
