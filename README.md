# mdsh
		The Make Diagnostic Shell

The mdsh utility is a shell wrapper program primarily intended for use
in analyzing makefile behavior though it could be used outside of make.
Its main intended use case is to help diagnose problems in complex,
often massively parallel, builds.

The most complete and up-to-date documentation will come
from compiling it and dumping its usage message with "./mdsh --help"
but here's a brief summary:

In order to leave the option namespace free for the underlying shell
and to leave its semantics unchanged, mdsh is controlled entirely by
environment variables in the MDSH_* namespace.  Aside from the extra
fork/exec sequence it behaves *exactly* like the underlying shell
(/bin/sh by default) with one minor exception: when passed the -h|--help
flag it prints its own usage message instead of the shell's. Otherwise
it will exec the shell with an unmodified and unexamined argv.

Its value-added is in the things it can do before or after exec-ing the
shell. Typically you'd tell make to use it by passing SHELL=mdsh on the
command line and also provide MDSH_* environment variables telling it
what to so. For example this command line:

    $ MDSH_TIMING=1 make SHELL=mdsh

would print every command run by every recipe with the amount of time
it took appended in parentheses.

The original purpose of mdsh was to arrange for make (via mdsh) to
log whenever a given file is modified or accessed (see examples in the
usage message) but a number of other features have been added since then.
Again, see usage for details.

		MDSH and .ONESHELL:

Warning: using mdsh in a makefile that employs .ONESHELL: can be tricky. See

https://www.gnu.org/software/make/manual/make.html#:~:text=If%20.ONESHELL%20is%20provided

for more, but the short version is that make maintains an internal
list of POSIX-conformant shells and mdsh isn't on it, even though it
effectively is a POSIX shell since it execs /bin/sh. The only reasonable
workaround is to link it to a name that *is* recognized as a POSIX
shell. Probably "rksh -> mdsh" is the best choice since almost no one
uses rksh as an actual shell. In fact it may be best to always use it
as rksh to avoid surprises.

		Creating a .csv summary

MDSH can be used to generate a .csv database summarizing all recipe
actions with timings and so on.  See usage or "make test" for details.

		Testing

Running "make test" will exercise a few mdsh features and serve as a
demo as well.

		Experimental

Experimental features may be shown by passing -H/--HELP (upper case).
