/*-
 * Copyright (c) 2011-2015 Juan Romero Pardines.
 * Copyright (c) 2014 Enno Boland.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/utsname.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "xbps_api_impl.h"

/**
 * @file lib/initend.c
 * @brief Initialization and finalization routines
 * @defgroup initend Initialization and finalization functions
 *
 * Use these functions to initialize some parameters before start
 * using libxbps and finalize usage to release resources at the end.
 */

int
xbps_init(struct xbps_handle *xhp)
{
	const char *native_arch = NULL;
	int rv = 0;

	assert(xhp != NULL);

	xbps_dbg_printf(xhp, "%s\n", XBPS_RELVER);

	/* Set rootdir */
	if (xhp->rootdir[0] == '\0') {
		xhp->rootdir[0] = '/';
		xhp->rootdir[1] = '\0';
	} else if (xhp->rootdir[0] != '/') {
		char cwd[XBPS_MAXPATH];

		if (getcwd(cwd, sizeof(cwd)) == NULL)
			return ENOBUFS;
		if (xbps_path_prepend(xhp->rootdir, sizeof xhp->rootdir, cwd) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->rootdir) == -1)
		return ENOTSUP;

	/* set confdir */
	if (xhp->confdir[0] == '\0') {
		if (xbps_path_join(xhp->confdir, sizeof xhp->confdir,
		    xhp->rootdir, XBPS_SYSCONF_PATH, (char *)NULL) == -1)
			return ENOBUFS;
	} else if (xhp->confdir[0] != '/') {
		/* relative path */
		if (xbps_path_prepend(xhp->confdir, sizeof xhp->confdir,
		    xhp->rootdir) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->confdir) == -1)
		return ENOTSUP;

	/* set sysconfdir */
	if (xhp->sysconfdir[0] == '\0') {
		if (xbps_path_join(xhp->sysconfdir, sizeof xhp->sysconfdir,
		    xhp->rootdir, XBPS_SYSDEFCONF_PATH, (char *)NULL) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->sysconfdir) == -1)
		return ENOTSUP;

	/* target architecture */
	xhp->target_arch = getenv("XBPS_TARGET_ARCH");
	if (xhp->target_arch && *xhp->target_arch == '\0')
		xhp->target_arch = NULL;

	/* native architecture */
	if ((native_arch = getenv("XBPS_ARCH")) && *native_arch != '\0') {
		if (xbps_strlcpy(xhp->native_arch, native_arch,
		    sizeof xhp->native_arch) >= sizeof xhp->native_arch)
			return ENOBUFS;
	} else {
		struct utsname un;
		if (uname(&un) == -1)
			return ENOTSUP;
		if (xbps_strlcpy(xhp->native_arch, un.machine,
		    sizeof xhp->native_arch) >= sizeof xhp->native_arch)
			return ENOBUFS;
#if defined(__linux__) && !defined(__GLIBC__)
		/* musl libc on linux, just append -musl */
		if (xbps_strlcat(xhp->native_arch, "-musl",
		    sizeof xhp->native_arch) >= sizeof xhp->native_arch)
			return ENOBUFS;
#endif
	}
	assert(*xhp->native_arch);

	xbps_fetch_set_cache_connection(XBPS_FETCH_CACHECONN, XBPS_FETCH_CACHECONN_HOST);

	/* process xbps.d directories */
	if ((rv = xbps_conf_init(xhp)) != 0)
		return rv;

	/* Set hooksdir */
	if (xhp->hooksdir[0] == '\0') {
		if (xbps_path_join(xhp->hooksdir, sizeof xhp->hooksdir,
			xhp->rootdir, XBPS_HOOKS_PATH, (char *)NULL) == -1)
			return ENOBUFS;
	} else if (xhp->hooksdir[0] != '/') {
		/* relative path */
		if (xbps_path_prepend(xhp->hooksdir, sizeof xhp->hooksdir,
			xhp->rootdir) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->hooksdir) == -1)
		return ENOTSUP;

	/* Set cachedir */
	if (xhp->cachedir[0] == '\0') {
		if (xbps_path_join(xhp->cachedir, sizeof xhp->cachedir,
		    xhp->rootdir, XBPS_CACHE_PATH, (char *)NULL) == -1)
			return ENOBUFS;
	} else if (xhp->cachedir[0] != '/') {
		/* relative path */
		if (xbps_path_prepend(xhp->cachedir, sizeof xhp->cachedir,
		    xhp->rootdir) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->cachedir) == -1)
		return ENOTSUP;

	/* Set metadir */
	if (xhp->metadir[0] == '\0') {
		if (xbps_path_join(xhp->metadir, sizeof xhp->metadir,
		    xhp->rootdir, XBPS_META_PATH, (char *)NULL) == -1)
			return ENOBUFS;
	} else if (xhp->metadir[0] != '/') {
		/* relative path */
		if (xbps_path_prepend(xhp->metadir, sizeof xhp->metadir,
		    xhp->rootdir) == -1)
			return ENOBUFS;
	}
	if (xbps_path_clean(xhp->metadir) == -1)
		return ENOTSUP;

	xbps_dbg_printf(xhp, "rootdir=%s\n", xhp->rootdir);
	xbps_dbg_printf(xhp, "metadir=%s\n", xhp->metadir);
	xbps_dbg_printf(xhp, "cachedir=%s\n", xhp->cachedir);
	xbps_dbg_printf(xhp, "hooksdir=%s\n", xhp->hooksdir);
	xbps_dbg_printf(xhp, "confdir=%s\n", xhp->confdir);
	xbps_dbg_printf(xhp, "sysconfdir=%s\n", xhp->sysconfdir);
	xbps_dbg_printf(xhp, "syslog=%s\n", xhp->flags & XBPS_FLAG_DISABLE_SYSLOG ? "false" : "true");
	xbps_dbg_printf(xhp, "bestmatching=%s\n", xhp->flags & XBPS_FLAG_BESTMATCH ? "true" : "false");
	xbps_dbg_printf(xhp, "keepconf=%s\n", xhp->flags & XBPS_FLAG_KEEP_CONFIG ? "true" : "false");
	xbps_dbg_printf(xhp, "Architecture: %s\n", xhp->native_arch);
	xbps_dbg_printf(xhp, "Target Architecture: %s\n", xhp->target_arch ? xhp->target_arch : "(null)");

	if (xhp->flags & XBPS_FLAG_DEBUG) {
		const char *repodir;
		for (unsigned int i = 0; i < xbps_array_count(xhp->repositories); i++) {
			if (!xbps_array_get_cstring_nocopy(xhp->repositories, i, &repodir))
			    return errno;
			xbps_dbg_printf(xhp, "Repository[%u]=%s\n", i, repodir);
		}
	}

	return 0;
}

void
xbps_end(struct xbps_handle *xhp)
{
	assert(xhp);
	if (xhp->hooks != NULL)
		xbps_hooks_release(xhp);

	xbps_pkgdb_release(xhp);
}
