# Suppress &@# "smart" (actually dumb!) quotes from GNU tools.
export LC_ALL := C

TARGETS := mdsh

# Meaningless as is, but may be activated by being exported in "test".
MDSH_DB := $(CURDIR)/mdsh_db

empty :=
space := $(empty) $(empty)

.PHONY: all
all: $(TARGETS)

%: %.c
	$(CC) -g -o $@ -Wall -Wextra $<

.PHONY: demo
demo: mdsh_temps := foo* bar* baz*
demo: export MDSH_PATHS=$(subst $(space),:,$(mdsh_temps))
demo: mdsh
	############ Testing $< path tracking with MDSH_PATHS='$(MDSH_PATHS)' ############
	$(RM) $(mdsh_temps)
	./$< -c 'uname > foo'
	./$< -c 'touch bar'
	./$< -c 'touch foo bar'
	./$< -c 'uname > foo; uname > baz'
	./$< -c 'grep -c . foo bar baz > /dev/null'
	./$< -c '$(RM) $(mdsh_temps)'

# Advanced: pass MDSH_HTTP_SERVER=<server> for this test to
# exercise HTTP cache flushing. The web server would need read
# access to files in local NFS.
.PHONY: test
test: mdsh | demo
	############ Testing $< NFS flushing ... ############
	$(strip MDSH_VERBOSE=1 MDSH_PRE_FLUSH_PATHS=. \
	  ./$< -c date)

	############ Testing $< timing ... ############
	MDSH_TIMING=1 MDSH_XTRACE=1 ./$< -c 'uname; sleep 2'

	############ Testing MDSH_DB ... ############
	$(RM) -r $(MDSH_DB) && \
	  mkdir $(MDSH_DB) && \
	  MDSH_DB=$(MDSH_DB) \
	    $(MAKE) --no-print-directory SHELL=./$< dbtest
	@head $(MDSH_DB)/FORMAT.txt $(MDSH_DB)/*.csv

.PHONY: dbtest
dbtest:
	uname -a
	sleep 2
	date

.PHONY: install
install: mdsh := $(shell bash -c "type -fp mdsh")
install: all
	$(if $(mdsh),cp -a mdsh $(mdsh))

.PHONY: clean
clean: cleanups := $(wildcard *.o *.dSYM $(TARGETS) $(MDSH_DB))
clean:
	$(if $(cleanups),$(RM) -r $(cleanups))

# vim: filetype=make shiftwidth=2 tw=80 cc=+1 noet
