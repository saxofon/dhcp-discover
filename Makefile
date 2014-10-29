#
# dhcp-discover - send out a DHCP discover request and wait for replies
# Author: Per Hallsmark <per@hallsmark.se>
#

SRCS=$(shell ls *\.c)
OBJS=$(subst .c,.o,$(SRCS))
APPS=$(subst .c,,$(SRCS))

CFLAGS += $(shell libnet-config --cflags --defines)
LDLIBS += $(shell libnet-config --libs)

CFLAGS += $(shell pcap-config --cflags --defines)
LDLIBS += $(shell pcap-config --libs)

#LDFLAGS += -static

all: $(APPS)

include libs/release.mk
include libs/sourceforge.mk

install:
	cp $(APPS) /usr/bin

clean:
	$(RM) $(APPS)
