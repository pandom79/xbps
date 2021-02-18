#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include "xbps_api_impl.h"

static xbps_array_t
split_hook_file(const char *hookfile)
{
	xbps_array_t arr = NULL;
	int last_index = 0;
	xbps_string_t filepath, filename;

	/* Initialize */
	filepath = filename = NULL;

	assert(hookfile);
	last_index = xbps_string_last_index(hookfile, '/');
	if (last_index != -1) {
		arr = xbps_array_create_with_capacity(2);
		filepath = xbps_string_create_cstring(hookfile);
		assert(filepath);
		filename = xbps_string_substr(hookfile, last_index + 1, strlen(hookfile));
		assert(filename);
		xbps_array_set(arr, 0, filepath);
		xbps_array_set(arr, 1, filename);
	}

	return arr;
}

static int
file_exists(const char *hookfile)
{
	FILE *fp = NULL;
	int rv = 0;

	assert(hookfile);
	if ((fp = fopen(hookfile, "r")) == NULL)
		rv = errno;
	/* Release resources */
	if (fp)
		fclose(fp);
	fp = NULL;

	return rv;
}

static int
dir_exists(const char *hooksdir)
{
	DIR *d = NULL;
	int rv = 0;

	assert(hooksdir);
	d = opendir(hooksdir);
	if (d == NULL)
		rv = errno;
	/* Release resources */
	closedir(d);
	d = NULL;

	return rv;
}

static void __attribute__((noreturn))
usage(bool fail)
{
	fprintf(stdout,
		"This tool performs a xbps hooks validation\n"
		"Usage: xbps-hook [OPTIONS]\n\n"
		"OPTIONS\n"
		" -h, --help			Show usage\n"
		" -H, --hooksdir <dir>		Path to hooksdir\n"
		" -f, --hookfile <file>		Path to hookfile\n");
	exit(fail ? EXIT_FAILURE : EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	const char *shortopts = "hH:f:";
	const struct option longopts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "hooksdir", required_argument, NULL, 'H' },
		{ "hookfile", required_argument, NULL, 'f' },
		{ NULL, 0, NULL, 0 }
	};

	struct xbps_handle xh;
	int c, rv, hooks_size, errors_size, tot_valid, tot_notvalid, tot_errors;
	const char *hooksdir, *hookfile, *suffix, *error;
	xbps_array_t arr, errors;
	xbps_string_t filepath, filename;
	xbps_dictionary_t hook_dict = NULL;
	bool is_valid = false;

	/* Initialize */
	c = rv = hooks_size = errors_size = tot_valid = tot_notvalid = tot_errors = 0;
	hooksdir = hookfile = suffix = error = NULL;
	filepath = filename = NULL;
	arr = errors = NULL;

	while ((c = getopt_long(argc, argv, shortopts, longopts, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(false);
			break;
		case 'H':
			hooksdir = optarg;
			break;
		case 'f':
			hookfile = optarg;
			break;
		default:
			usage(true);
		}
	}

	/* Check input */
	/* Make a validation from 'XBPS_HOOKS_PATH' folder as default behaviour */
	if (!hooksdir && !hookfile)
		hooksdir = XBPS_HOOKS_PATH;
	else if (hooksdir && hookfile) {
		printf("The '-H' and '-f' options are mutually exclusive!\n");
		exit(EXIT_FAILURE);
	}
	else if (hooksdir && !hookfile) {
		if ((rv = dir_exists(hooksdir)) != 0) {
			printf("'%s' : %s \n", hooksdir, strerror(rv));
			exit(EXIT_FAILURE);
		}
	}
	else if (!hooksdir && hookfile) {
		suffix = strrchr(hookfile, '.');
		if (suffix == NULL || strcmp(suffix, ".hook") != 0) {
			printf("The xbps hook configuration file must to have the '.hook' extension!\n");
			exit(EXIT_FAILURE);
		}
		else if ((rv = file_exists(hookfile)) != 0) {
			printf("'%s' : %s \n", hookfile, strerror(rv));
			exit(EXIT_FAILURE);
		}
	}

	/* Start validation process */
	memset(&xh, 0, sizeof(xh));

	if (hooksdir) {
		/* Build complete xbps hooks path */
		xbps_hooks_load_path(hooksdir, &xh.hooks);
	}
	else if (hookfile) {
		xh.hooks = xbps_array_create_with_capacity(1);
		assert(xh.hooks);

		/* Splitting 'hookfile' in an array of 2 elements:
		 * 0: File path
		 * 1: File name
		*/
		arr = split_hook_file(hookfile);
		filepath = xbps_array_get(arr, 0);
		filename = xbps_array_get(arr, 1);
		hook_dict = xbps_dictionary_create();
		assert(hook_dict);
		/* Populate dictionary */
		xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_FPATH_KEY), xbps_string_copy(filepath));
		xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_FNAME_KEY), xbps_string_copy(filename));
		/* Add dictionary to array */
		xbps_array_add(xh.hooks, hook_dict);

		/* Release resources */
		xbps_object_release(filepath);
		filepath = NULL;
		xbps_object_release(filename);
		filename = NULL;
		xbps_object_release(arr);
		arr = NULL;
	}

	/* Show all the errors for each hook (Standalone mode) */
	hooks_size = xbps_array_count(xh.hooks);
	if (hooks_size > 0)
		printf("\n[*] Validating xbps hooks\n\n");

	for (int i = 0; i < hooks_size; i++) {

		/* Get dictionary */
		hook_dict = xbps_array_get(xh.hooks, i);

		/* Parsing file */
		xbps_hooks_parse_file(&xh, hook_dict, true);

		/* Get properties from dictionary */
		filename = xbps_dictionary_get(hook_dict, hook_dict_keystr(XBPS_HOOK_FNAME_KEY));
		errors = xbps_dictionary_get(hook_dict, hook_dict_keystr(XBPS_HOOK_ERROR_KEY));
		xbps_dictionary_get_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY), &is_valid);

		/* Computing total data */
		is_valid ? tot_valid++ : tot_notvalid++;
		errors_size = xbps_array_count(errors);
		tot_errors += errors_size;

		printf("==> %s : %s\n", xbps_string_cstring_nocopy(filename),
		                        (is_valid ? "[ PASSED ]" : "[ FAILED ]"));
		if (!is_valid) {
			printf("%d errors found\n\n", errors_size);
			for (int j = 0; j < errors_size; j++) {
				xbps_array_get_cstring_nocopy(errors, j, &error);
				printf(":: %s \n", error);
			}
		}
		printf("------------------------------------------------------\n");
	}

	printf("\nSummary\n\n");
	printf("Total xbps hooks = %d\n", hooks_size);
	printf("Total passed = %d\n", tot_valid);
	printf("Total failed = %d\n", tot_notvalid);
	printf("Total errors = %d\n\n", tot_errors);

	if (tot_errors > 0)
		printf("Please, consult the documentation to fix them\n\n");

	/* Release resources */
	xbps_end(&xh);

	exit(rv);
}
