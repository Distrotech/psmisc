/*
 * timout.h	Advanced timeout handling for file system calls
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

#ifndef _TIMEOUT_H
#define _TIMEOUT_H

#include "config.h"

#ifndef WITH_TIMEOUT_STAT
# define WITH_TIMEOUT_STAT 0
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>

#if !defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L)
# ifndef  restrict
#  define restrict		__restrict__
# endif
#endif

typedef int (*stat_t)(const char *, struct stat *);

#if WITH_TIMEOUT_STAT > 0
extern int timeout(stat_t, const char *, struct stat *restrict, time_t);
#else
# define timeout(func,path,buf,dummy)	(func)((path),(buf))
#endif

#endif
