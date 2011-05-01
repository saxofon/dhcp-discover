# 
# Copyright (C) 2010 Per Hallsmark <per@hallsmark.se>
#
# Author: Per Hallsmark <per@hallsmark.se>
#
# Automated releases. Probably so generic so it applies
# to most subversion hosted projs unmodified :-)
#

ifeq ($(wildcard .svn),)

# running via tarball

else

# running via repository

SVN_ROOT    := $(shell svn info . | grep "^Repository Root" | cut -d" " -f3)
PRJ         := $(shell basename $(SVN_ROOT))
PRJ_SVN_PWD := $(shell svn info . | grep "^URL" | cut -d" " -f2)

ifeq "$(PRJ_SVN_PWD)" ""
	parentdir  := $(shell dirname $(PWD))
	base       := tags
	label      := $(shell basename $(parentdir))
else
	svn_offset := $(subst $(SVN_ROOT)/,,$(PRJ_SVN_PWD))
	base       := $(shell echo $(svn_offset) | cut -d/ -f1)
	label      := $(shell echo $(svn_offset) | cut -d/ -f2)
endif

ifeq "$(base)" "trunk"
	REL := $(PRJ)-$(base)-$(shell svn info . | grep ^Revision: | cut -d" " -f2)
else ifeq "$(base)" "branches"
	REL := $(PRJ)-$(base)-$(label)-$(shell svn info . | grep ^Revision: | cut -d" " -f2)
else ifeq "$(base)" "tags"
	REL := $(PRJ)-$(label)
else
	REL := invalid
endif

RELTMP := $(shell mktemp -d)

release-test:
	@echo "SVN_ROOT     : \"$(SVN_ROOT)\""
	@echo "PRJ          : \"$(PRJ)\""
	@echo "PRJ_SVN_PWD  : \"$(PRJ_SVN_PWD)\""
	@echo "parentdir    : \"$(parentdir)\""
	@echo "base         : \"$(base)\""
	@echo "label        : \"$(label)\""
	@echo "svn_offset   : \"$(svn_offset)\""
	@echo "REL          : \"$(REL)\""

$(REL).tar.bz2:
	svn export . $(RELTMP)/$(REL)
	(cd $(RELTMP) && tar jcf $(REL).tar.bz2 $(REL))
	mv $(RELTMP)/$(REL).tar.bz2 .
	$(RM) -r $(RELTMP)

release-tarball: $(REL).tar.bz2

release-tag:
	@read -p "svn tag label : " svntag ; \
	read -p "svn comment   : " svncomment ; \
	svn copy $(PRJ_SVN_PWD) $(SVN_ROOT)/tags/$$svntag -m "$$svncomment"

endif
