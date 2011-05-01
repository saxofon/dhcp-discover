# Username at SourceForge, used when publishing releases
USR := per_h
URL_SVN_SCP := $(USR),dhcp-discover@frs.sourceforge.net:/home/frs/project/d/dh/dhcp-discover

# Rule that publish a release at SourceForge
release2sourceforge: $(REL).tar.bz2 README.txt
	scp $< $(URL_SVN_SCP)
