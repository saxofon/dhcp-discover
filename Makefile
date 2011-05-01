#
# dhcp-discover - send out a DHCP discover request and wait for replies
# Author: Per Hallsmark <per@hallsmark.se>
#

SRCS=$(shell ls *\.c)
OBJS=$(subst .c,.o,$(SRCS))
APPS=$(subst .c,,$(SRCS))

LDFLAGS += -lnet -lpcap

all: $(APPS)

include libs/release.mk
include libs/sourceforge.mk

install:
	cp $(APPS) /usr/bin

clean:
	$(RM) $(APPS)
