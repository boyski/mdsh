# mdsh
The Make Diagnostic Shell

The mdsh utility is a shell wrapper program intended for use in
makefiles.  It's tested with and documented in terms of GNU make but
there's nothing known to be incompatible with other make programs.
The most complete and up-to-date documentation will come from compiling
the program and dumping its usage message with "./mdsh --help" but
here's a brief summary.

In order to leave the option namespace free for the shell to use mdsh is
controlled entirely by environment variables in the MDSH_* namespace.
Aside from the additional fork/exec sequence it behaves *exactly*
like the underlying shell (/bin/sh by default) with one exception:
when passed the --help flag it will print its own usage message instead
of the shell's. Otherwise it execs the shell with the unmodified and
unexamined argv.

The value added is in the things it can do before or after exec-ing
the shell. The idea is that you would tell make to use mdsh by passing
SHELL=mdsh on the command line, and also provide MDSH_* environment
variables telling it what to so. For example this command line:

    $ MDSH_TIMING=1 make SHELL=mdsh

would print every command run by every recipe with the amount of time
it took appended in parentheses.

It's also possible to arrange for make (via mdsh) to tell you whenever a
given file is modified, and there are a number of other things it can do
too. The main intended use case is to help diagnose problems in complex,
often massively parallel, builds.

Perhaps stretching the definition of "diagnosis" a bit, mdsh can also
trigger NFS cache flushing behavior. This can help make distrubuted
parallel builds more robust.

Running "make test" will exercise a few mdsh features and thus serve
as a demo as well.
