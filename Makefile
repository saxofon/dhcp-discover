#
# dhcp-discover - send out a DHCP discover request and wait for replies
# Author: Per Hallsmark <per@hallsmark.se>
#

SRCS=$(shell ls *\.c)
OBJS=$(subst .c,.o,$(SRCS))
APPS=$(subst .c,,$(SRCS))

LDLIBS += -lnet -lpcap

all: $(APPS)

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp $(APPS) $(DESTDIR)/usr/bin

clean:
	$(RM) $(APPS)
