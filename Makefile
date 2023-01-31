# Suppress &@# "smart" (actually dumb!) quotes from GNU tools.
export LC_ALL := C

TARGETS := mdsh

# Meaningless as is, but may be activated by being exported in "test".
MDSH_DB := $(CURDIR)/mdsh_db

.PHONY: all
all: $(TARGETS)

%: %.c
	$(CC) -g -o $@ -Wall -Wextra $<

# Consider passing MDSH_HTTP_SERVER=<server> for this test to
# exercise HTTP cache flushing. The web server would need read
# access to files in local NFS.
.PHONY: test
test: export MDSH_PATHS=foo*:bar
test: mdsh
	@$(RM) foo* bar

	# Test $< path tracking ...
	./$< -c 'uname > foo'
	./$< -c 'touch foo foobar'
	./$< -c 'uname > foo; uname > bar'
	./$< -c 'grep -c . foo bar > /dev/null'
	./$< -c '$(RM) foo* bar'

	# Test $< NFS flushing ...
	$(strip MDSH_VERBOSE=1 MDSH_PRE_FLUSH_PATHS=. \
	  ./$< -c date)

	# Test $< timing ...
	MDSH_TIMING=1 MDSH_XTRACE=1 ./$< -c 'uname; sleep 2'

	# Test MDSH_DB ...
	$(RM) -r $(MDSH_DB) && \
	  mkdir $(MDSH_DB) && \
	  MDSH_DB=$(MDSH_DB) \
	    $(MAKE) --no-print-directory _dbtest SHELL=$<
	head $(MDSH_DB)/*

.PHONY: _dbtest
_dbtest:
	sleep 1
	uname -a
	sleep 2
	date

.PHONY: install
install: mdsh := $(shell bash -c "type -fp mdsh")
install: all
	$(if $(mdsh),cp -a mdsh $(mdsh))

.PHONY: clean
clean: cleanups := $(wildcard *.o $(TARGETS) $(MDSH_DB))
clean:
	$(if $(cleanups),$(RM) -r $(cleanups))

# vim: filetype=make shiftwidth=2 tw=80 cc=+1 noet
