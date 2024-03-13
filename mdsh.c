/******************************************************************************
 * Copyright (C) 2018-2020 David Boyce
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more detail.
 *
 * You may have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *****************************************************************************/

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <libgen.h>
#include <limits.h>
#include <netdb.h>
#include <regex.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

typedef struct {
    const char *path;
    struct timespec times[2];
} pathtimes_s;

static char **argv_;
static char prog[PATH_MAX] = "??";
static char *shell;
static void *stash;
static int fixup = 1;
static int verbose;

#define PFX "MDSH"
#define EV_PS1 PFX ">> "
#define EV_CMDRE PFX "_CMDRE"
#define EV_DB PFX "_DB"
#define EV_DBGSH PFX "_DBGSH"
#define EV_EFLAG PFX "_EFLAG"
#define EV_PRE_FLUSH_PATHS PFX "_PRE_FLUSH_PATHS"
#define EV_POST_FLUSH_PATHS PFX "_POST_FLUSH_PATHS"
#define EV_HTTP_SERVER PFX "_HTTP_SERVER"
#define EV_XTEVS PFX "_XTEVS"
#define EV_PATHS PFX "_PATHS"
#define EV_MARKER PFX "_MARKER"
#define EV_NOFIXUP PFX "_NOFIXUP"
#define EV_PWD PFX "_PWD"
#define EV_SHELL PFX "_SHELL"
#define EV_TIMING PFX "_TIMING"
#define EV_VERBOSE PFX "_VERBOSE"
#define EV_XTRACE PFX "_XTRACE"

// start time,pid,ppid,status,elapsed,user time,sys time,$(MAKELEVEL),pwd,cmd
#define CSV_FMT "%ld.%09ld,%d,%d,%d,%f,%ld.%06ld,%ld.%06ld,%s,%s,%s\n"

#define DEFAULT_MARKER "==-=="
#define SEP ":"

#define endof(str) strchr(str, '\0')

// Nanoseconds per second.
#define NSECS_PER_SEC 1000000000.0

#define TIME_GT(left, right) ((left.tv_sec > right.tv_sec) || \
        (left.tv_sec == right.tv_sec && left.tv_nsec > right.tv_nsec))

// Get first argument of __VA_ARGS__ if any.
#define _INSIST_FIRST_ARG(...) _INSIST_FIRST_HELPER(__VA_ARGS__, throwaway)
#define _INSIST_FIRST_HELPER(first, ...) "" #first

// Print caller function name, file name, line_number, error message
// and optional supporting arguments. Exit with failure code.
// Supporting arguments are a printf() format string followed
// by respective printf() arguments.
#define _INSIST_DIE(err_msg, ...) if (1) { \
        fprintf(stderr, "%s: Error: %s() %s:%d %s", \
        prog, __FUNCTION__, __FILE__, __LINE__, err_msg); \
        if (errno) fprintf(stderr, " %s", strerror(errno)); \
        if (strcmp(_INSIST_FIRST_ARG(__VA_ARGS__), "")) \
                fprintf(stderr, ": " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
}

// Check the condition to be true, otherwise call _INSIST_DIE above with
// condition as string and optional supporting arguments.
#define INSIST(cond, ...) if (!(cond)) {_INSIST_DIE(#cond, ##__VA_ARGS__);}

#define LASTCHAR(str) (strrchr(str, '\0') - 1)

static void
usage(int rc, int helplevel)
{
    FILE *f = (rc == EXIT_SUCCESS) ? stdout : stderr;

    fprintf(f, "\
%s: The 'Make Diagnosis Shell'.\n\n\
This program execs the shell and passes its argv directly to it\n\
unparsed. It prints this usage message with {-h,-H,--help,--HELP}\n\
but in all other ways it's a pass-through to the shell and\n\
thus behaves exactly the same. Its only value-added comes\n\
from the env variables listed below which can trigger pre-\n\
and post-actions. The idea is that setting GNU make's\n\
SHELL=%s along with some subset of the %s_* environment\n\
variables below may help diagnose complex make problems.\n",
    prog, prog, PFX);

    fprintf(f, "\n\
However, note that you may actually need SHELL=rksh or similar\n\
for makefiles operating in .ONESHELL mode. See details below.\n");

    fprintf(f, "\nPass -H|--HELP for advanced/experimental options.\n");

    fprintf(f, "\nENVIRONMENT VARIABLES:\n");

    fprintf(f, "\n%s: override the default shell [/bin/sh] invoked by %s.\n",
        EV_SHELL, prog);

    fprintf(f, "\n\
%s: a colon-separated list of glob patterns representing file\n\
paths to keep an eye on and report when the shell process changes\n\
any of their states (created, removed, written, or accessed/read).\n\
This feature depends on Linux 'inotify' kernel extensions.\n",
        EV_PATHS);

    fprintf(f, "\n\
%s: if set (nonzero), the command line will be printed\n\
along with each %s change message.\n",
        EV_VERBOSE, EV_PATHS);

    fprintf(f, "\n\
%s: optional string added to verbosity to aid later grepping.\n",
        EV_MARKER);

    fprintf(f, "\n\
%s: if set, printed command lines will not have whitespace\n\
cleaned up.\n",
        EV_NOFIXUP);

    fprintf(f, "\n\
%s: if set, the current working directory will be printed\n\
before each shell command.\n",
        EV_PWD);

    fprintf(f, "\n\
%s: if set, the shell command will be printed a la set -x.\n",
        EV_XTRACE);

    fprintf(f, "\n\
%s: similar to %s but the command is printed\n\
along with its run time. Can be used to profile a build to find\n\
the longest poles. After running make with this enabled, plus\n\
-Orecurse for recursive parallel builds, use something like\n\
'grep %s: sample.log | sort -n -k3,3' to sort recipes\n\
by run time. Alternatively, timings are also kept by %s.\n",
        EV_TIMING, EV_XTRACE, EV_TIMING, EV_DB);

    fprintf(f, "\n\
%s: if present, points to a writable directory. Each shell command\n\
will drop a file into that directory, named by its start time in\n\
nanoseconds and pid, summarizing the command in .csv format:\n\
[start time,pid,ppid,retcode,run time,user time,sys time,$(MAKELEVEL),pwd,cmd]\n",
        EV_DB);

    fprintf(f, "\n\
%s: if a regular expression is supplied here it will be\n\
compared against the shell command. If a match is found an\n\
interactive debug shell will be invoked before the command runs.\n",
        EV_CMDRE);

    fprintf(f, "\n\
%s: if the underlying shell process exits with a failure status\n\
and this is set, %s will run an interactive shell to help analyze\n\
the failing state.\n",
        EV_DBGSH, prog);

    fprintf(f, "\n\
However, be aware that starting an interactive shell can run into\n\
trouble in -j mode which generally closes stdin. Interactive shells\n\
require stdin and stdout to be available to the terminal.\n");

    fprintf(f, "\n\
GNU make maintains a compiled-in list of shells it knows to be\n\
POSIX-conformant. Unfortunately mdsh isn't known to make by name\n\
even though it wraps around /bin/sh which really is a POSIX shell.\n\
This can cause make to get confused, especially in .ONESHELL: mode.\n\
If this happens the suggested workaround is to use a symlink\n\
rksh -> mdsh since rksh IS on the list but almost no one uses it.\n");

    if (helplevel > 1) {

        fprintf(f, "\n\
    %s and %s are colon-separated\n\
    lists of paths on which to attempt NFS cache-flushing before or after\n\
    the recipe runs. The first thing done with each listed path, if it's\n\
    a directory, is to open and close it. This may flush the filehandle\n\
    cache according to http://tss.iki.fi/nfs-coding-howto.html.\n",
        EV_PRE_FLUSH_PATHS, EV_POST_FLUSH_PATHS);

        fprintf(f, "\n\
    If %s is passed it should be the name of an HTTP server\n\
    with read access to listed files. A GET request will be issued for each\n\
    path on %s whether file or directory. This is said to\n\
    force all dirty NFS caches for that path to be flushed.\n",
        EV_HTTP_SERVER, EV_PRE_FLUSH_PATHS);

        fprintf(f, "\n\
    NFS cache flushing is a very complex topic and the situation varies by\n\
    protocol (NFSvX), NFS server vendor, etc. Multiple flushing techniques\n\
    are supported and both 'pull' (flush before reading) and 'push'\n\
    (flush after writing) models are supported to allow experimental tuning.\n");

        fprintf(f, "\n\
    A hypothetical linker recipe could flush the directory containing object\n\
    files to make sure they're all present before it starts linking by\n\
    setting %s=$(@D), for instance. Or $^ could be flushed.\n\
    Generally we think pull is more correct than push but having a compile\n\
    recipe, say, use %s=$@ to push-flush the .o may be\n\
    worth experimenting with too.\n",
        EV_PRE_FLUSH_PATHS, EV_POST_FLUSH_PATHS);
    }

    fprintf(f, "\n\
EXAMPLES:\n\n\
$ MDSH_PATHS=foo:bar %s -c 'touch foo'\n\
%s: ==-== CREATED: foo\n\
\n\
$ MDSH_PATHS=foo:bar %s -c 'touch foo bar'\n\
%s: ==-== MODIFIED: foo\n\
%s: ==-== CREATED: bar\n\
\n\
$ MDSH_PATHS=foo:bar %s -c 'grep blah foo bar'\n\
%s: ==-== ACCESSED: foo\n\
%s: ==-== ACCESSED: bar\n\
\n\
$ MDSH_PATHS=foo:bar MDSH_VERBOSE=1 %s -c 'rm -f foo bar'\n\
%s: ==-== REMOVED: foo [/bin/sh -c rm -f foo bar]\n\
%s: ==-== REMOVED: bar [/bin/sh -c rm -f foo bar]\n\
\n\
$ [repeat previous command]\n\
(no state change messages, the files are already gone)\n\
\n\
$ MDSH_TIMING=1 %s -c 'sleep 2.4'\n\
- %s -c sleep 2.4 (2.4s)\n\
\n\
Real-life usage via make:\n\n\
$ MDSH_PATHS=foobar MDSH_VERBOSE=1 make -j12 SHELL=%s ...\n\
\n\
$ make SHELL=%s MDSH_DBGSH=1 ...\n\
\n\
$ rm -rf /tmp/db; mkdir /tmp/db; MDSH_DB=/tmp/db make SHELL=%s ...\n\
",\
        prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog, prog, prog,
        prog, prog, prog, prog);

    exit(rc);
}

static int
ev2int(const char *ev)
{
    char *val;

    val = getenv(ev);
    return val && *val ? atoi(val) : 0;
}

static void
error(const char *term, const char *msg)
{
    if (term && *term) {
        fprintf(stderr, "%s: Error: %s: %s\n", prog, term, msg);
    } else {
        fprintf(stderr, "%s: Error: %s\n", prog, msg);
    }
}

static int
pathcmp(const void *pa, const void *pb)
{
    return strcmp(((pathtimes_s *)pa)->path, ((pathtimes_s *)pb)->path);
}

static void
report(const char *path, const char *change)
{
    char *marker = getenv(EV_MARKER);
    char *mlev;

    marker = marker ? marker : DEFAULT_MARKER;
    if (verbose && (mlev = getenv("MAKELEVEL"))) {
        fprintf(stderr, "%s: [%s] %s %s: %s", prog, mlev, marker, change, path);
    } else {
        fprintf(stderr, "%s: %s %s: %s", prog, marker, change, path);
    }

    if (verbose) {
        char *cwd;
        int i;

        INSIST((cwd = getcwd(NULL, 0)) != NULL);
        fprintf(stderr, " [%s] (%s ", cwd, shell);
        free(cwd);
        for (i = 1; argv_[i]; i++) {
            if (strpbrk(argv_[i], " \t")) {
                fprintf(stderr, "'%s'", argv_[i]);
            } else {
                fputs(argv_[i], stderr);
            }
            if (argv_[i + 1]) {
                fputc(' ', stderr);
            }
        }
        fputc(')', stderr);
    }

    fputc('\n', stderr);
    INSIST(!fflush(stderr));
}

static void
watch_walk(const void *nodep, const VISIT which, const int depth)
{
    pathtimes_s *pt = *((pathtimes_s **)nodep);
    struct stat stbuf;
    glob_t refound;
    size_t i;

    (void)depth; // don't need this

    if (which != leaf && which != postorder) {
        return;
    }

    (void)memset(&refound, 0, sizeof(refound));
    switch (glob(pt->path, 0, NULL, &refound)) {
        case 0:
            for (i = 0; i < refound.gl_pathc; i++) {
                char *path = refound.gl_pathv[i];

                if (stat(path, &stbuf) == -1) {
                    error(path, strerror(errno));
                } else if (!pt->times[0].tv_sec) {
                    report(path, "CREATED");
                } else {
                    if (TIME_GT(stbuf.st_mtim, pt->times[1])) {
                        report(path, "MODIFIED");
                    } else if (TIME_GT(stbuf.st_atim, pt->times[0])) {
                        report(path, "ACCESSED");
                    }
                }
            }
            break;
        case GLOB_NOMATCH:
            if (pt->times[0].tv_sec) {
                report(pt->path, "REMOVED");
            }
            break;
        default:
            perror(pt->path);
            exit(1);
    }

    globfree(&refound);
}

static void
xtrace(int argc, char *argv[], const char *pfx, const char *timing)
{
    char *marker = getenv(EV_MARKER);
    int i;

    if (getenv(EV_XTEVS)) {
        char *evlist, *ev;

        INSIST((evlist = strdup(getenv(EV_XTEVS))) != NULL);
        for (ev = strtok(evlist, SEP); ev; ev = strtok(NULL, SEP)) {
            if (getenv(ev)) {
                fprintf(stderr, "+++ %s=%s\n", ev, getenv(ev));
            }
        }
        free(evlist);
    }

    fputs(pfx ? pfx : "+ ", stderr);
    if (marker) {
        fputs(marker, stderr);
        fputc(' ', stderr);
    }
    if (timing) {
        fprintf(stderr, "[%s: %s] ", EV_TIMING, timing);
    }
    for (i = 0; i < argc; i++) {
        char *original, *printable;
        int j;

        // The handling of whitespace and quoting here is rudimentary
        // but it's only for visual purposes. No commitment is made
        // that this output can be safely fed back to the shell.

        // Make a copy of the original word to be cleaned up for printing
        // and remember its location so it can be freed.
        INSIST((original = printable = strdup(argv[i])) != NULL);

        if (fixup) {
            // Treat all whitespace the same for printing purposes.
            for (j = 0; printable[j]; j++) {
                switch (printable[j]) {
                    case '\n': case '\t':
                        printable[j] = ' ';
                        break;
                }
            }

            // Trim whitespace from front and back of each printable word.
            while (*(LASTCHAR(printable)) == ' ') {
                *(LASTCHAR(printable)) = '\0';
            }
            while (*printable == ' ') {
                printable++;
            }
        }

        if (strchr(printable, ' ')) {
            fprintf(stderr, "'%s'", printable);
        } else {
            fputs(printable, stderr);
        }

        if (i < argc - 1) {
            fputc(' ', stderr);
        }

        free(original);
    }
    fputc('\n', stderr);
    INSIST(!fflush(stderr));
}

static void
dbgsh(int argc, char *argv[])
{
    static int done;

    if (!done++) {
        pid_t pid;

        xtrace(argc, argv, NULL, NULL);
        INSIST((pid = fork()) >= 0);
        if (!pid) {  // In the child.
            int fd;
            // GNU make with -j tends to close stdin, and stdout/stderr might
            // be redirected too.
            for (fd = 0; fd < 3; fd++) {
                if (!isatty(fd)) {
                    (void)close(fd);
                    INSIST(open("/dev/tty", fd ? O_WRONLY : O_RDONLY) == 0);
                }
            }
            INSIST(!setenv("PS1", EV_PS1, 1));
            (void)execlp(basename(shell), shell, "--norc", "-i", (char *)NULL);
            error(shell, strerror(errno)); // NOTREACHED
        }
        // Ignore the exit status of this debugging shell.
        INSIST(wait(NULL) != -1);
    }
}

/*
 * As I understand it, when a change is made to file or directory X on
 * host A the client may choose to cache anything (data or metadata)
 * but it always makes one synchronous round trip communication to
 * the server to say "Hey, I've got a dirty cache for X" so the server
 * will always know about the caching. Because of that, when a request
 * for X comes in on host B the server will go back to host A and say
 * "Give me what you've got" before responding to B. Thus, all cached
 * results on any other host are guaranteed to be flushed to the server
 * before the response to B.
 *
 * To make use of this we can rely on an HTTP 1.1 web server which has
 * read access to all of NFS and runs on a dedicated machine and will
 * therefore fulfill the requirements of a "host B" for any "host A".
 */
static int
http_request(const char *server, const char *path)
{
    struct addrinfo *result, hints;
    struct stat stbuf;
    int retval, srvfd, count;
    char *abspath, *slash, *request;
    char readbuf[1024];

    if (!server) {
        return 0;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((retval = getaddrinfo(server, "80", &hints, &result))) {
        error(server, gai_strerror(retval));
        return EXIT_FAILURE;
    }

    if ((srvfd = socket(result->ai_family, SOCK_STREAM, 0)) == -1) {
        error("socket()", strerror(errno));
        return EXIT_FAILURE;
    }

    if ((connect(srvfd, result->ai_addr, result->ai_addrlen) == -1)) {
        error("connect()", strerror(errno));
        return EXIT_FAILURE;
    }

    if ((abspath = realpath(path, NULL))) {
        slash = (!stat(abspath, &stbuf) && S_ISDIR(stbuf.st_mode)) ? "/" : "";
        if (asprintf(&request,
            "GET %s%s HTTP/1.1\nHost: %s\nUser-agent: %s\nRange: bytes=0-%lu\n\n",
                abspath, slash, server, prog, sizeof(readbuf) - 1) == -1) {
            error("asprintf()", strerror(errno));
            return EXIT_FAILURE;
        }
        free(abspath);
    } else {
        // Policy is to not print errors for nonexistent flush paths.
        // error(path, strerror(errno));
        return EXIT_FAILURE;
    }

    if (verbose) {
        size_t len = verbose > 1 ? strlen(request) :
            (size_t)(strchr(request, '\n') - request) + 1;
        (void)fwrite(request, sizeof(char), len, stderr);
    }

    if (write(srvfd, request, strlen(request)) == -1) {
        error("write()", strerror(errno));
        return EXIT_FAILURE;
    }

    if (shutdown(srvfd, SHUT_WR) == -1) {
        error("shutdown()", strerror(errno));
        return EXIT_FAILURE;
    }

    // We don't really need to read the whole file - it should be
    // enough to make and satisfy any read request. If the first
    // line doesn't look like "206 Partial-Content" we dump the
    // buffer as an ersatz error message.
    if ((count = read(srvfd, readbuf, sizeof(readbuf))) == -1) {
        if (write(1, readbuf, count) == -1) {
            error("read()", strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        char *nl, *ok;

        nl = strchr(readbuf, '\n');
        ok = strstr(readbuf, " 206 ");
        if (!nl || !ok || ok > nl) {
            fputs(readbuf, stderr);
            return EXIT_FAILURE;
        }
    }

    if (close(srvfd) == -1) {
        error("close()", strerror(errno));
        return EXIT_FAILURE;
    }

    free(request);

    return 0;
}

static void
create_remove(const char *path)
{
    char *tmpf;
    int fd;

    if (asprintf(&tmpf, "%s/.nfs_flush-%d.tmp", path, (int)getpid()) == -1) {
        error("asprintf()", strerror(errno));
    } else {
        if (verbose) {
            fprintf(stderr, "create(%s)\n", tmpf);
        }
        if ((fd = open(tmpf, O_CREAT | O_EXCL, 0666)) == -1) {
            error(tmpf, strerror(errno));
        } else {
            if (verbose) {
                fprintf(stderr, "remove(%s)\n", tmpf);
            }
            if (close(fd) == -1 || unlink(tmpf) == -1) {
                error(tmpf, strerror(errno));
            }
        }

        free(tmpf);
    }
}

static int
nfs_flush_dir(const char *path)
{
    DIR *odir;

    // Rather than check whether it's a directory, just run opendir
    // and let it fail if not.
    if ((odir = opendir(path))) {
        if (verbose) {
            fprintf(stderr, "opendir(\"%s\")\n", path);
            fprintf(stderr, "closedir(\"%s\")\n", path);
        }
        (void)closedir(odir);

        // Create and remove a temp file to tickle the filehandle cache.
        create_remove(path);

        return 0;
    }

    return 1;
}

// NFS-flush each path (file or directory) on the specified path.
static int
nfs_flush(const char *ev)
{
    char *paths;

    if ((paths = getenv(ev))) {
        const char *path;
        char *http_server;

        http_server = getenv(EV_HTTP_SERVER);

        INSIST((paths = strdup(paths)) != NULL);
        for (path = strtok(paths, SEP); path; path = strtok(NULL, SEP)) {
            DIR *odir;

            nfs_flush_dir(path);

            (void)http_request(http_server, path);

            /* Flush the immediate subdirs of each dir. */
            if ((odir = opendir(path))) {
                struct dirent *dp;
                char *tpath;

                while ((dp = readdir(odir))) {
                    if (!strcmp(dp->d_name, ".git") || !strcmp(dp->d_name, ".svn")) {
                        // Ignore obvious SCM/VCS subdirectories.
                    } else if (dp->d_name[0] == '.') {
                        // Ignore all "dot" files, unlikely to be used in a build.
                    } else if (strcmp(dp->d_name, "..") && strcmp(dp->d_name, ".")) {
                        if (asprintf(&tpath, "%s/%s", path, dp->d_name) == -1) {
                            error("asprintf()", strerror(errno));
                            continue;
                        }

                        nfs_flush_dir(tpath);

                        (void)http_request(http_server, tpath);

                        free(tpath);
                    }
                }
                (void)closedir(odir);
            }
        }
        free(paths);
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    int rc = EXIT_SUCCESS;
    char *watch, *pattern;
    FILE *db_fp = NULL;
    struct timespec starttime, endtime;
    pid_t pid;

    argv_ = argv; // Hack to preserve command line for later verbosity.
    fixup = ev2int(EV_NOFIXUP) ? 0 : 1;
    verbose = ev2int(EV_VERBOSE); // Global verbosity flag.

    (void)strncpy(prog, basename(argv[0]), sizeof(prog));
    prog[sizeof(prog) - 1] = '\0';

    if (!strcmp(argv[argc - 1], "-h") || !strcmp(argv[argc - 1], "--help")) {
        usage(0, 1);
    } else if (!strcmp(argv[argc - 1], "-H") || !strcmp(argv[argc - 1], "--HELP")) {
        usage(0, 2);
    }

    if (!(shell = getenv(EV_SHELL))) {
        shell = "/bin/sh";
    }

    INSIST(!clock_gettime(CLOCK_REALTIME, &starttime));

    if (ev2int(EV_XTRACE) && !ev2int(EV_TIMING)) {
        xtrace(argc, argv, NULL, NULL);
    }

    // Optionally flush NFS before the recipe.
    (void)nfs_flush(EV_PRE_FLUSH_PATHS);

    // Record the state (absence/presence and atime/mtime if present) of files.
    if ((watch = getenv(EV_PATHS))) {
        size_t i;
        glob_t found;
        int globflags = GLOB_NOCHECK;

        // Run through the patterns, deriving a list of matched paths.
        (void)memset(&found, 0, sizeof(found));
        INSIST((watch = strdup(watch)) != NULL);
        for (pattern = strtok(watch, SEP); pattern; pattern = strtok(NULL, SEP)) {
            switch (glob(pattern, globflags, NULL, &found)) {
                case 0:
                case GLOB_NOMATCH:
                    break;
                default:
                    perror(pattern);
                    break;
            }
            globflags |= GLOB_APPEND;
        }

        for (i = 0; i < found.gl_pathc; i++) {
            pathtimes_s *pt;
            struct stat stbuf;

            INSIST((pt = calloc(sizeof(pathtimes_s), 1)) != NULL);
            pt->path = strdup(found.gl_pathv[i]);
            if (stat(pt->path, &stbuf) != -1) {
                pt->times[0].tv_sec = stbuf.st_atim.tv_sec;
                pt->times[0].tv_nsec = stbuf.st_atim.tv_nsec;
                pt->times[1].tv_sec = stbuf.st_mtim.tv_sec;
                pt->times[1].tv_nsec = stbuf.st_mtim.tv_nsec;
                // Must push atime behind mtime due to "relatime".
                if (stbuf.st_atim.tv_sec >= pt->times[1].tv_nsec) {
                    pt->times[0].tv_sec = pt->times[1].tv_sec - 2;
                    pt->times[0].tv_nsec = 999;
                    if (utimensat(AT_FDCWD, pt->path, pt->times, 0) == -1) {
                        error(pt->path, strerror(errno));
                    }
                }
            } else {
                (void)memset(&stbuf, '\0', sizeof(stbuf));
            }
            INSIST(tsearch((const void *)pt, &stash, pathcmp) != NULL);
        }

        globfree(&found);
        free(watch);
    }

    if (getenv(EV_CMDRE)) {
        size_t i;
        regex_t re;

        INSIST(regcomp(&re, getenv(EV_CMDRE), REG_EXTENDED) == 0);
        for (i = 1; argv[i]; i++) {
            if (argv[i - 1][0] == '-' && strchr(argv[i - 1], 'c')) {
                if (!regexec(&re, argv[i], 0, NULL, 0)) {
                    dbgsh(argc, argv);
                    break;
                }
            }
        }
        regfree(&re);
    }

    if (ev2int(EV_PWD)) {
        char *cwd;

        INSIST((cwd = getcwd(NULL, 0)) != NULL);
        fprintf(stderr, "[%s] ", cwd);
        free(cwd);
        INSIST(!fflush(stderr));
    }

    // Fork, exec, and wait for the shell.
    {
        int status = EXIT_SUCCESS;

        INSIST((pid = fork()) >= 0);
        if (pid) {  // In the parent.
            char *db_dir, *db_file;

            if ((db_dir = getenv(EV_DB))) {
                if (asprintf(&db_file, "%s/%ld.%09ld-%05d.csv",
                        db_dir, starttime.tv_sec, starttime.tv_nsec, pid) == -1) {
                    error("asprintf()", strerror(errno));
                }
                INSIST((db_fp = fopen(db_file, "w")) != NULL);
                free(db_file);
            }
        } else {    // In the child.
            argv[0] = shell;
            INSIST(execvp(basename(shell), argv) != -1);
        }
        INSIST(wait(&status) != -1);
        rc = WEXITSTATUS(status);
    }

    // Optionally flush after the recipe.
    (void)nfs_flush(EV_POST_FLUSH_PATHS);

    if (db_fp || ev2int(EV_TIMING)) {
        char tbuf[256];
        double elapsed_nsec;

        INSIST(!clock_gettime(CLOCK_REALTIME, &endtime));
        elapsed_nsec =
            ((endtime.tv_sec * NSECS_PER_SEC) + endtime.tv_nsec) -
            ((starttime.tv_sec * NSECS_PER_SEC) + starttime.tv_nsec);
        (void)snprintf(tbuf, sizeof(tbuf), "%.1fs", elapsed_nsec / NSECS_PER_SEC);

        if (ev2int(EV_TIMING)) {
            xtrace(argc, argv, "+ ", tbuf);
        }

        if (db_fp) {
            struct rusage summary;
            char *cwd, *cmd, *cmdbuf, *makelevel, *p;

            // Strip meaningless newlines from front and back.
            INSIST((cmdbuf = cmd = strdup(argv[argc - 1])));
            while (*cmd == '\n') {
                cmd++;
            }
            while (*(endof(cmd) - 1) == '\n') {
                *(endof(cmd) - 1) = '\0';
            }

            // Convert interior newlines to semicolons in order to keep
            // all recipes on one line.
            for (p = cmd; *p; p++) {
                if (*p == '\n') {
                    *p = ';';
                }
            }

            INSIST((cwd = getcwd(NULL, 0)) != NULL);
            INSIST(!getrusage(RUSAGE_CHILDREN, &summary));
            makelevel = getenv("MAKELEVEL");
            // Note that the pid of *this* process is not shown.
            // The "pid" is our child (shell) and the ppid is our parent
            // while we insist on anonymity.
            INSIST(fprintf(db_fp, CSV_FMT,
                starttime.tv_sec,
                starttime.tv_nsec,
                pid,
                getppid(),
                rc,
                elapsed_nsec / NSECS_PER_SEC,
                summary.ru_utime.tv_sec,
                summary.ru_utime.tv_usec,
                summary.ru_stime.tv_sec,
                summary.ru_stime.tv_usec,
                makelevel ? makelevel : "-",
                cwd,
                cmd) > 0);
            (void)fclose(db_fp);
            free(cwd);
            free(cmdbuf);
        }
    }

    // Revisit the original list of files and report any changes.
    if (stash) {
        twalk(stash, watch_walk);
    }

    if (rc != EXIT_SUCCESS) {
        if (ev2int(EV_DBGSH)) {
            dbgsh(argc, argv);
        }

        if (ev2int(EV_EFLAG)) {
            fprintf(stderr, "kill -INT %d\n", getppid());
            (void)kill(getppid(), SIGINT);
        }
    }

    return rc;
}

// vim: ts=8:sw=4:tw=80:et:
