#
# dhcp-discover - send out a DHCP discover request and wait for replies
# Author: Per Hallsmark <per@hallsmark.se>
#

SRCS=$(shell ls *\.c)
OBJS=$(subst .c,.o,$(SRCS))
APPS=$(subst .c,,$(SRCS))

CFLAGS += $(shell libnet-config --cflags)
LDLIBS += $(shell libnet-config --libs)

CFLAGS += $(shell pkg-config --cflags libpcap)
LDLIBS += $(shell pkg-config --libs libpcap)

#LDFLAGS += -static

all: $(APPS)

include libs/release.mk
include libs/sourceforge.mk

install:
	cp $(APPS) /usr/bin

clean:
	$(RM) $(APPS)
