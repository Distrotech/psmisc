/*
 * timout.c	Advanced timeout handling for file system calls
 *		to avoid deadlocks on remote file shares.
 *
 * Version:	0.1 07-Sep-2011 Fink
 *
 * Copyright 2011 Werner Fink, 2011 SUSE LINUX Products GmbH, Germany.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Author:	Werner Fink <werner@suse.de>, 2011
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef USE_SOCKETPAIR
# define USE_SOCKETPAIR		1
#endif

#ifdef _FEATURES_H
# error Include local config.h before any system header file
#endif
#include "config.h"		/* For _FILE_OFFSET_BITS */

#include <errno.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>

#include <unistd.h>
#if USE_SOCKETPAIR
# include <sys/socket.h>
# include <netdb.h>
# include <netinet/in.h>
#  ifndef SHUT_RD
#   define SHUT_RD	0
# endif
# ifndef SHUT_WR
#  define SHUT_WR	1
# endif
# undef pipe
# define pipe(v)	(((socketpair(AF_UNIX,SOCK_STREAM,0,v) < 0) || \
			(shutdown((v)[1],SHUT_RD) < 0) || (shutdown((v)[0],SHUT_WR) < 0)) ? -1 : 0)
#endif
#include <wait.h>

#include "timeout.h"

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# ifndef  destructor
#  define destructor		__destructor__
# endif
# ifndef  constructor
#  define constructor		__constructor__
# endif
# ifndef  packed
#  define packed		__packed__
# endif
# ifndef  inline
#  define inline		__inline__
# endif
# ifndef  unused
#  define unused		__unused__
# endif
# ifndef  volatile
#  define volatile		__volatile__
# endif
#endif
#ifndef  attribute
# define attribute(attr)	__attribute__(attr)
#endif

#if defined __GNUC__
# undef strcpy
# define strcpy(d,s)		__builtin_strcpy((d),(s))   /* Without boundary check please */
#endif

/*
 * The structure used for communication between the processes
 */
typedef struct _handle {
	int errcode;
	struct stat argument;
	stat_t function;
	size_t len;
	char path[0];
} attribute((packed)) handle_t;

/*
 * Using a forked process for doing e.g. stat(2) system call as this
 * allows us to send e.g. SIGKILL to this process if it hangs in `D'
 * state on a file share due a stalled NFS server.  This does not work
 * with (p)threads as SIGKILL would kill all threads including main.
 */

static volatile pid_t active;
static int pipes[4] = {-1, -1, -1, -1};
static char buf[PATH_MAX + sizeof(handle_t) + 1];

static void sigchild(int sig attribute((unused)))
{
	pid_t pid = waitpid(active, NULL, WNOHANG|WUNTRACED);
	if (pid <= 0)
		return;
	if (errno == ECHILD)
		return;
	active = 0;
}

static void attribute((constructor)) start(void)
{
	sigset_t sigset, oldset;
	struct sigaction act;
	ssize_t in;

	if (pipes[1] >= 0) close(pipes[1]);
	if (pipes[2] >= 0) close(pipes[2]);

	if (pipe(&pipes[0]))
		goto error;
	if (pipe(&pipes[2]))
		goto error;

	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	act.sa_handler = sigchild;
	sigaction(SIGCHLD, &act, 0);

	if ((active = fork()) < 0)
		goto error;

	if (active) {
		close(pipes[0]);
		close(pipes[3]);
		pipes[0] = pipes[3] = -1;
		return;
	}

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_BLOCK, &sigset, &oldset);

	act.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &act, 0);

	close(pipes[1]);
	close(pipes[2]);
	dup2(pipes[0], STDIN_FILENO);
	dup2(pipes[3], STDOUT_FILENO);
	close(pipes[0]);
	close(pipes[3]);
	pipes[1] = pipes[2] = -1;
	pipes[0] = pipes[3] = -1;

	{
		handle_t *restrict handle = (void*)&buf[0];

		while ((in = read(STDIN_FILENO, handle, sizeof(buf))) > sizeof(handle_t)) {
			if (handle->function(handle->path, &handle->argument) < 0)
					handle->errcode = errno;
			write(STDOUT_FILENO, &handle->errcode, sizeof(handle->errcode)+sizeof(handle->argument));
			memset(handle, 0, sizeof(handle_t));
		}
	}
	sigprocmask(SIG_SETMASK, &oldset, NULL);
	exit(0);
error:
	if (pipes[0] >= 0) close(pipes[0]);
	if (pipes[1] >= 0) close(pipes[1]);
	if (pipes[2] >= 0) close(pipes[2]);
	if (pipes[3] >= 0) close(pipes[3]);
}

static void /* attribute((destructor)) */ stop(void)
{
	if (active && waitpid(active, NULL, WNOHANG|WUNTRACED) == 0)
		kill(active, SIGKILL);
}

static sigjmp_buf jenv;
static void sigjump(int sig attribute((unused)))
{
	siglongjmp(jenv, 1);
}

/*
 * External routine
 */
int timeout(stat_t function, const char *path, struct stat *restrict argument, time_t seconds)
{
	handle_t *restrict handle = (void*)&buf[0];
	struct sigaction alrm_act, pipe_act, new_act;
	sigset_t sigset, oldset;

	if (active <= 0)	/* Oops, last one failed therefore clear status and restart */
		start();

	memset(handle, 0, sizeof(handle_t));
	handle->len = strlen(path) + 1;
	if (handle->len >= PATH_MAX) {
		errno = ENAMETOOLONG;
		goto error;
	}
	handle->errcode = 0;
	handle->argument = *argument;
	handle->function = function;
	strcpy(handle->path, path);

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigaddset(&sigset, SIGPIPE);
	sigprocmask(SIG_UNBLOCK, &sigset, &oldset);

	memset(&new_act, 0, sizeof(new_act));
	sigemptyset(&new_act.sa_mask);
	new_act.sa_flags = SA_RESETHAND;

	if (sigsetjmp(jenv, 1))
		goto timed;

	new_act.sa_handler = sigjump;
	sigaction(SIGALRM, &new_act, &alrm_act);
	sigaction(SIGPIPE, &new_act, &pipe_act);
	alarm(seconds);

	write(pipes[1], handle, sizeof(handle_t)+handle->len);
	read(pipes[2], &handle->errcode, sizeof(handle->errcode)+sizeof(handle->argument));

	alarm(0);
	sigaction(SIGPIPE, &pipe_act, NULL);
	sigaction(SIGALRM, &alrm_act, NULL);

	if (handle->errcode) {
		errno = handle->errcode;
		goto error;
	}

	*argument = handle->argument;
	sigprocmask(SIG_SETMASK, &oldset, NULL);

	return 0;
timed:
	(void) alarm(0);
	sigaction(SIGPIPE, &pipe_act, NULL);
	sigaction(SIGALRM, &alrm_act, NULL);
	sigprocmask(SIG_SETMASK, &oldset, NULL);
	stop();
	errno = ETIMEDOUT;
error:
	return -1;
}

/*
 * End of timeout.c
 */
