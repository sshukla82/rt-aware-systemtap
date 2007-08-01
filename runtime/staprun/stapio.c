/* -*- linux-c -*-
 *
 * stapio.c - SystemTap module io handler.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2005-2007 Red Hat, Inc.
 *
 */

#include "staprun.h"
#include <pwd.h>

int main(int argc, char **argv)
{
	setup_signals();
	
	parse_args(argc, argv);

	if (verbose) {
		if (buffer_size)
			printf ("Using a buffer of %u bytes.\n", buffer_size);
	}

	if (optind < argc) {
		if (strlen(argv[optind]) > sizeof(modpath)) {
			fprintf(stderr,
				"ERROR: Module path '%s' is larger than buffer.\n",
				argv[optind]);
			exit(-1);
		}
		/* No need to check for overflow because of check
		 * above. */
		strcpy(modpath, argv[optind++]);
		parse_modpath();
		dbug(2, "modpath=\"%s\", modname=\"%s\"\n", modpath, modname);
	}

        if (optind < argc) {
		if (attach_mod) {
			fprintf(stderr, "ERROR: Cannot have module options with attach (-A).\n");
			usage(argv[0]);
		} else {
			unsigned start_idx = 3; /* reserve three slots in modoptions[] */
			while (optind < argc && start_idx+1 < MAXMODOPTIONS)
				modoptions[start_idx++] = argv[optind++];
			modoptions[start_idx] = NULL;
		}
	}

	if (*modpath == '\0') {
		fprintf(stderr, "ERROR: Need a module name or path to load.\n");
		usage(argv[0]);
	}

	if (init_stapio())
		exit(1);
	
	initialized = 1;

	if (stp_main_loop()) {
		fprintf(stderr, "ERROR: Couldn't enter main loop. Exiting.\n");
		exit(1);
	}

	return 0;
}
