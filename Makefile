# Makefile (for compiling and installing, or building a distribution)
# Copyright (C) 2003, 2014  Phil Lanch
#
# This file is part of Rephrase.
#
# Rephrase is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 3.
#
# Rephrase is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SHELL		= /bin/sh

program		= rephrase
version		= 0.2

what		= $(program)-$(version)

GPG		=
ifneq (,$(GPG))
gpg_def	= -DGPG=\"$(GPG)\"
else
gpg_def	=
endif

CRYPTSETUP	=
ifneq (,$(CRYPTSETUP))
cryptsetup_def	= -DCRYPTSETUP=\"$(CRYPTSETUP)\"
else
cryptsetup_def	=
endif

PATTERN_MAX	=
ifneq (,$(PATTERN_MAX))
pattern_max_def	= -DPATTERN_MAX=\($(PATTERN_MAX)\)
else
pattern_max_def	=
endif

ARGS_MAX	=
ifneq (,$(ARGS_MAX))
args_max_def	= -DARGS_MAX=\($(ARGS_MAX)\)
else
args_max_def	=
endif

DEFS		= -DVERSION=\"$(version)\" $(gpg_def) $(cryptsetup_def) $(pattern_max_def) $(args_max_def)
CPPFLAGS	+= $(DEFS)
CFLAGS		= -Wall

prefix		= /usr/local
exec_prefix	= ${prefix}
bindir		= ${exec_prefix}/bin

dirmode		= 755
binowner	= 0
bingroup	= 0
binmode		= 4711

files		= CHANGELOG COPYING install-sh Makefile mkinstalldirs README $(program).c

all: $(program)

dist: $(what).tar.gz $(what).tar.bz2

install: all
	./mkinstalldirs -m $(dirmode) $(DESTDIR)$(bindir)
	./install-sh -c -o $(binowner) -g $(bingroup) -m $(binmode) $(program) \
		$(DESTDIR)$(bindir)/$(program)

$(what).tar: $(files)
	rm -f $@
	rm -rf TREE
	mkdir TREE
	mkdir TREE/$(what)
	cp -p $(files) TREE/$(what)
	cd TREE && { tar -c -f ../$@ $(what) || { rm -f ../$@ && exit 1; }; }

$(what).tar.gz: $(what).tar
	rm -f $@
	gzip -c -9 $< > $@ || { rm -f $@ && exit 1; }

$(what).tar.bz2: $(what).tar
	rm -f $@
	bzip2 -k -9 $< || { rm -f $@ && exit 1; }

clean::
	rm -f $(program) $(program)-*.tar
	rm -rf TREE

distclean::
	$(MAKE) clean
	rm -f $(program)-*.tar.gz $(program)-*.tar.bz2

.PHONY: all dist install clean distclean
