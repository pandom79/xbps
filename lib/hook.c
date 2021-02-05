/*-
 * Copyright (c) 2019 Juan Romero Pardines.
 * Copyright (c) 2019 Duncan Overbruck <mail@duncano.de>.
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

#include "xbps_api_impl.h"
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fnmatch.h>

xbps_string_t
xbps_hooks_error_desc(const char* mess, int numline) {

    char num_linestr[1000];
    xbps_string_t error = NULL;

    if (numline > 0) {
        sprintf(num_linestr, "%d", numline);
        error = xbps_string_create_cstring("Error occurred at line : ");
        xbps_string_append_cstring(error, num_linestr);
        xbps_string_append_cstring(error, "\n");
        xbps_string_append_cstring(error, mess);
    } else {
        error = xbps_string_create_cstring(mess);
    }
    xbps_string_append_cstring(error, "\n");

    return error;
}


static hook_dict_keys_t
hook_dict_key(xbps_string_t key) {

    hook_dict_keys_t hook_dict_key = XBPS_HOOK_UNKNOWN_KEY;

    if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TRIGGER_SEC_KEY)) ){
        hook_dict_key = XBPS_HOOK_TRIGGER_SEC_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_OPERATION_KEY)) ){
        hook_dict_key = XBPS_HOOK_OPERATION_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TYPE_KEY)) ){
        hook_dict_key = XBPS_HOOK_TYPE_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TARGET_KEY)) ){
        hook_dict_key = XBPS_HOOK_TARGET_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_ACTION_SEC_KEY)) ){
        hook_dict_key = XBPS_HOOK_ACTION_SEC_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_DESCRIPTION_KEY)) ){
        hook_dict_key = XBPS_HOOK_DESCRIPTION_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_WHEN_KEY)) ){
        hook_dict_key = XBPS_HOOK_WHEN_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_EXEC_KEY)) ){
        hook_dict_key = XBPS_HOOK_EXEC_KEY;
    }
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY)) ){
        hook_dict_key = XBPS_HOOK_ABRTONFAIL_KEY;
    }

    return hook_dict_key;
}

const char*
hook_dict_keystr(enum hook_dict_keys key) {
    switch (key) {
    case XBPS_HOOK_TRIGGER_SEC_KEY:
        return "[TRIGGER]";
    case XBPS_HOOK_ACTION_SEC_KEY:
        return "[ACTION]";
    case XBPS_HOOK_DESCRIPTION_KEY:
        return "DESCRIPTION";
    case XBPS_HOOK_FNAME_KEY:
        return "FILENAME";
    case XBPS_HOOK_FPATH_KEY:
        return "FILEPATH";
    case XBPS_HOOK_OPERATION_KEY:
        return "OPERATION";
    case XBPS_HOOK_TYPE_KEY:
        return "TYPE";
    case XBPS_HOOK_TARGET_KEY:
        return "TARGET";
    case XBPS_HOOK_WHEN_KEY:
        return "WHEN";
    case XBPS_HOOK_EXEC_KEY:
        return "EXEC";
    case XBPS_HOOK_ABRTONFAIL_KEY:
        return "ABORTONFAIL";
    case XBPS_HOOK_EXEC_PRE_KEY:
        return "EXE_PRE";
    case XBPS_HOOK_EXEC_POST_KEY:
        return "EXE_POST";
    case XBPS_HOOK_SKIP_KEY:
        return "SKIP";
    case XBPS_HOOK_VALID_KEY:
        return "VALID";
    case XBPS_HOOK_ERROR_KEY:
        return "ERROR";
    default:
        return NULL;
    }
}

static const char *
hook_oper_valstr(enum hook_oper_val key) {
    switch (key) {
    case OPER_INSTALL:
        return "INSTALL";
    case OPER_REMOVE:
        return "REMOVE";
    case OPER_UPGRADE:
        return "UPGRADE";
    default:
        return NULL;
    }
}

const char *
hook_type_valstr(enum hook_type_val key) {
    switch (key) {
    case TYPE_PACKAGE:
        return "PACKAGE";
    case TYPE_PATH:
        return "PATH";
    default:
        return NULL;
    }
}

const char *
hook_when_valstr(enum hook_when_val key) {
    switch (key) {
    case WHEN_PRE_TRANSACTION:
        return "PRETRANSACTION";
    case WHEN_POST_TRANSACTION:
        return "POSTTRANSACTION";
    default:
        return NULL;
    }
}

static const char *
hook_abrtonfail_val_str(enum hook_abrtonfail_val key) {
    switch (key) {
    case ABRT_ONFAIL_FALSE:
        return "FALSE";
    case ABRT_ONFAIL_TRUE:
        return "TRUE";
    default:
        return NULL;
    }
}

const char*
ttype_val_str(enum xbps_trans_type ttype) {
    switch (ttype) {
    case XBPS_TRANS_INSTALL:
        return "INSTALL";
    case XBPS_TRANS_REINSTALL:
        return "INSTALL";
    case XBPS_TRANS_REMOVE:
        return "REMOVE";
    case XBPS_TRANS_UPDATE:
        return "UPGRADE";
    default:
        return NULL;
    }
}

void HIDDEN
xbps_hooks_sort_path(xbps_array_t* hooks) {

    xbps_dictionary_t hook_dict_a = NULL, hook_dict_b = NULL, hook_dict_sup = NULL;
    const char* filepath_a = NULL;
    const char* filepath_b = NULL;
    int size;

    size = (*hooks != NULL ? xbps_array_count(*hooks) : 0);
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < (size-i-1); j++) {
            hook_dict_a = xbps_array_get(*hooks , j);
            xbps_dictionary_get_cstring_nocopy(hook_dict_a, hook_dict_keystr(XBPS_HOOK_FPATH_KEY),
                                               &filepath_a);
            hook_dict_b = xbps_array_get(*hooks , j+1);
            xbps_dictionary_get_cstring_nocopy(hook_dict_b, hook_dict_keystr(XBPS_HOOK_FPATH_KEY),
                                               &filepath_b);
            if (strcmp(filepath_a, filepath_b) > 0) {
                hook_dict_sup = xbps_dictionary_copy(hook_dict_a);
                xbps_array_set(*hooks, j, hook_dict_b);
                xbps_array_set(*hooks, j + 1, hook_dict_sup);
            }
        }
    }

}

int HIDDEN
xbps_hooks_load_path( const char* hooks_path , xbps_array_t* hooks ) {

    DIR* d = NULL;
    struct dirent* dir = NULL;
    char* suffix = NULL;
    xbps_dictionary_t hook_dict = NULL;
    xbps_string_t filepath = NULL, filename = NULL;
    int rv = 0;

    d = opendir(hooks_path);
    if (d != NULL) {
        while ((dir = readdir(d)) != NULL) {
            suffix = strrchr(dir->d_name, '.');
            if (suffix != NULL && strcmp(suffix, ".hook") == 0) {
                filepath = xbps_string_create_cstring(hooks_path);
                assert(filepath);
                filename = xbps_string_create_cstring(dir->d_name);
                assert(filename);

                /* Building complete file path */
                xbps_string_append_cstring(filepath, "/");
                xbps_string_append_cstring(filepath, dir->d_name);

                hook_dict = xbps_dictionary_create();
                assert(hook_dict);
                xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_FNAME_KEY),
                                    filename);
                xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_FPATH_KEY),
                                    filepath);

                if (*hooks == NULL) {
                    *hooks = xbps_array_create();
                    assert(*hooks);
                }
                xbps_array_add(*hooks, hook_dict);
            }
            /* strrchr() return a const char, don't need free
             * otherwise i get an invalid pointer
             */
            suffix = NULL;
        }
        free(dir);
        closedir(d);
    }
    else {
        rv = errno;
    }

    return rv;
}

int HIDDEN
xbps_hooks_load_data(struct xbps_handle* xhp) {

    int size_hooks = 0;
    const char* filepath = NULL;
    const char* filename = NULL;
    char* error = NULL;
    xbps_dictionary_t hook_dict = NULL;
    bool valid, showvalidmsg = false;
    xbps_array_t hooks = NULL;

    assert(xhp);

    hooks = xhp->hooks;
    size_hooks = (hooks != NULL ? xbps_array_count( hooks ) : 0);
    for (int i = 0; i < size_hooks; i++) {

        /* Get filename and filepath */
        hook_dict = xbps_array_get(hooks, i);
        xbps_dictionary_get_cstring_nocopy(hook_dict , hook_dict_keystr(XBPS_HOOK_FNAME_KEY),
                                           &filename);
        xbps_dictionary_get_cstring_nocopy(hook_dict , hook_dict_keystr(XBPS_HOOK_FPATH_KEY),
                                           &filepath);
        assert(filename);
        assert(filepath);

        if (xhp->flags & XBPS_FLAG_DEBUG) {
            if (i == 0)
                xbps_dbg_printf(xhp, "[hook] Found %d xbps hooks\n", size_hooks);
            xbps_dbg_printf(xhp, "[hook] Filename %s\n", filename);
            xbps_dbg_printf(xhp, "[hook] Filepath %s\n", filepath);
        }
        /*
         * Parsing xbps hook.
         * It will populate the dictionary with remaining data
         */
        xbps_hooks_parse_file(xhp, hook_dict);

        /* Get properties */
        xbps_dictionary_get_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY) , &valid);
        xbps_dictionary_get_cstring(hook_dict, hook_dict_keystr(XBPS_HOOK_ERROR_KEY), &error);

        /* If hook is not valid then show the configuration error */
        if (!valid){
            if (!showvalidmsg) {
                xbps_set_cb_state(xhp, XBPS_STATE_VALIDATE_HOOKS, 0, NULL, NULL);
                showvalidmsg = true;
            }
            xbps_set_cb_state(xhp, XBPS_STATE_VALIDATING_HOOKS, 0, filename, NULL);
            printf("%s", error);
        }
        /* Release error */
        free(error);
        error = NULL;
    }
    return 0;
}

xbps_string_t HIDDEN
xbps_hooks_chk_keyorder(int prev_key, int current_key ) {

    xbps_string_t error = NULL;

    if (prev_key != XBPS_HOOK_TRIGGER_SEC_KEY && current_key == XBPS_HOOK_TRIGGER_SEC_KEY) {
        error = xbps_string_create_cstring("Please, move '");
        xbps_string_append_cstring(error, hook_dict_keystr(current_key));
        xbps_string_append_cstring(error, "'");
        xbps_string_append_cstring(error, " at beginning of file");
    }
    else if (prev_key > current_key) {
        error = xbps_string_create_cstring("Please, move '");
        xbps_string_append_cstring(error, hook_dict_keystr(current_key));
        xbps_string_append_cstring(error, "' after '");
        xbps_string_append_cstring(error, hook_dict_keystr(current_key-1));
        xbps_string_append_cstring(error, "'");
    }
    return error;
}


xbps_array_t HIDDEN
xbps_hooks_parse_keyval(const char *buf) {

    xbps_array_t key_val = NULL;
    int len = 0, equal_index = 0;
    char *key = NULL , *val = NULL;

    len = strlen(buf);
    for (int i = 0; i < len; i++) {
        if (buf[i] == '='){
            equal_index = i;
            break;
        }
    }
    /* Potential 2: key and value */
    key_val = xbps_array_create();
    assert(key_val);

    /* KEY */
    if (equal_index > 0) {
        key = xbps_string_substr_cstring(buf, 0, equal_index);
    }
    else {
        key = calloc(strlen(buf) + 1 , sizeof (buf));
        strcpy(key, buf);
    }
    assert(key);
    /* Trim and toupper */
    trim(key, NULL);
    toupperstr(key);
    xbps_array_add(key_val , xbps_string_create_cstring(key));
    /* Release key */
    free(key);
    key = NULL;

    /* VALUE */
    if (equal_index > 0) {
        val = xbps_string_substr_cstring(buf, equal_index + 1 , strlen(buf));
        assert(val);
        /* Trim */
        trim(val, NULL);
        xbps_array_add(key_val, xbps_string_create_cstring(val));
        /* Release val */
        free(val);
        val = NULL;
    }
    return key_val;
}

int HIDDEN
xbps_hooks_parse_file(struct xbps_handle* xhp, xbps_dictionary_t hook_dict) {

    FILE *fp;
    size_t len = 0;
    char *line = NULL, *p = NULL;
    int prev_key, num_trigger, num_action , num_operations, num_type, num_targets,
        num_whens, num_exec, num_abrtonfail, num_desc, rv, num_line;
    xbps_string_t key, val, error, errkeyord;
    const char *filepath = NULL;
    xbps_array_t key_val = NULL;
    hook_dict_keys_t hook_key;
    bool is_val = false;

    assert(xhp);
    assert(hook_dict);

    /* Initialize */
    hook_key = XBPS_HOOK_TRIGGER_SEC_KEY;
    num_trigger = num_action = num_desc = num_operations = num_type = num_targets =
    num_whens = num_exec = num_abrtonfail = rv = num_line = prev_key = 0;
    key = val = error = errkeyord = NULL;

    /* Get filepath from dictionary */
    xbps_dictionary_get_cstring_nocopy(hook_dict , hook_dict_keystr(XBPS_HOOK_FPATH_KEY),
                                       &filepath);
    assert(filepath);

    /* Open hook file */
    if ((fp = fopen(filepath, "r")) == NULL) {
        rv = errno;
        xbps_dbg_printf(xhp, "[hook] Unable open hook file '%s': "
            "%s\n", filepath, strerror(rv));
        return rv;
    }

    while (getline(&line, &len, fp) != -1) {
        p = line;
        num_line++;

        /* ignore comments or empty lines */
        if (*p == '#' || *p == '\n') {
            continue;
        }

        /* Check first Character
         * Sections and Properties can't start with 'blank' or 'tab'
         */
        if (isblank((unsigned char)*p) || *p == '\t') {
            error = xbps_hooks_error_desc("An invalid character has been found at the beginning of the line\n", num_line);
            assert(error);
            goto err;
        }

        /* Parse Key and Value */
        key_val = xbps_hooks_parse_keyval(p);
        if (key_val != NULL){

            /* Get key and value */
            key = xbps_array_get(key_val, 0);
            val = xbps_array_get(key_val, 1);

            is_val = false;
            /* If val exist */
            if (val != NULL && !xbps_string_equals_cstring(val, ""))
                is_val = true;

            /* Get key as enumerator */
            hook_key = hook_dict_key(key);

            /* Check keys */
            switch (hook_key) {
                case XBPS_HOOK_TRIGGER_SEC_KEY :
                    num_trigger++;
                    if (num_trigger > 1) {
                        error = xbps_hooks_error_desc("An incorrect occurences number for the '[Trigger]' section! "
                        "(Required, Not Repeatable)", num_line);
                        assert(error);
                        goto err;
                    }
                    break;
                case XBPS_HOOK_ACTION_SEC_KEY :
                    num_action++;
                    if (num_action > 1) {
                        error = xbps_hooks_error_desc( "An incorrect occurences number for the '[Action]' section! "
                        "(Required, Not Repeatable)", num_line);
                        assert(error);
                        goto err;
                    }
                    break;
                case XBPS_HOOK_DESCRIPTION_KEY :
                    if (is_val) {
                        num_desc++;
                        if (num_desc > 1) {
                            error = xbps_hooks_error_desc("An incorrect occurences number for the 'Description' property! "
                            "(Optional, Not Repeatable)", num_line);
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                case XBPS_HOOK_OPERATION_KEY :
                    if (is_val) {
                        num_operations++;
                        if (num_operations > OPER_MAX) {
                            error = xbps_hooks_error_desc("An incorrect occurences number for the 'Operation' property! \n"
                                    "The accepted values are <Install|Upgrade|Remove> (Required, Repeatable)", num_line);
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                case XBPS_HOOK_TYPE_KEY :
                    if (is_val) {
                        num_type++;
                        if (num_type > 1) {
                            error = xbps_hooks_error_desc("An incorrect occurences number for the 'Type' property! \n"
                            "The accepted values are <Package|Path> (Not Repeatable)", num_line);
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                case XBPS_HOOK_TARGET_KEY :
                    if (is_val) {
                        num_targets++;
                    }
                    break;
                case XBPS_HOOK_WHEN_KEY :
                    if (is_val) {
                        num_whens++;
                        if (num_whens > WHEN_MAX) {
                            error = xbps_hooks_error_desc( "An incorrect occurences number for the 'When' property! \n"
                            "The accepted values are <PreTransaction|PostTransaction> (Required, Repeatable)", num_line);
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                case XBPS_HOOK_EXEC_KEY :
                    if (is_val) {
                        num_exec++;
                        if (num_exec > 1) {
                            error = xbps_hooks_error_desc("An incorrect occurences number for the 'Exec' property! "
                            "(Required, Not Repeatable)", num_line);
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                case XBPS_HOOK_ABRTONFAIL_KEY :
                    if (is_val) {
                        num_abrtonfail++;
                        if (num_abrtonfail > 1) {
                            error = xbps_hooks_error_desc("An incorrect occurences number for the 'AbortOnFail' property! \n"
                            "The accepted values are <False|True> (Optional, Not Repeatable)", num_line );
                            assert(error);
                            goto err;
                        }
                    }
                    break;
                default:
                    error = xbps_hooks_error_desc("Not valid data!", num_line);
                    assert(error);
                    goto err;
            }

            /* Check key order */
            errkeyord = xbps_hooks_chk_keyorder(prev_key, hook_key);
            if (errkeyord != NULL) {
              error = xbps_hooks_error_desc(xbps_string_cstring_nocopy(errkeyord), num_line);
              assert(error);
              /* Release errkeyord */
              xbps_object_release(errkeyord);
              errkeyord = NULL;
              goto err;
            }
            prev_key = hook_key;

            /*
             * Add value to the dictionary.
             */
            if (is_val && !xbps_hooks_addvalue(hook_dict, key, val, num_line)) {
                goto err;
            }
            else {
                /* Release resources */
                xbps_object_release(key);
                if (val != NULL)
                    xbps_object_release(val);
                xbps_object_release(key_val);
                key = NULL;
                val = NULL;
                key_val = NULL;
            }

        }
    }

    /* Check required properties */
    if (num_trigger == 0) {
        error = xbps_hooks_error_desc("The '[Trigger]' section is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_operations == 0) {
        error = xbps_hooks_error_desc("The 'Operation' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_type == 0) {
        error = xbps_hooks_error_desc("The 'Type' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_targets == 0) {
        error = xbps_hooks_error_desc("The 'Target' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_action == 0) {
        error = xbps_hooks_error_desc("The '[Action]' section is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_desc == 0) {
        error = xbps_hooks_error_desc("The 'Description' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_whens == 0) {
        error = xbps_hooks_error_desc("The 'When' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_exec == 0) {
        error = xbps_hooks_error_desc("The 'Exec' property is required!", 0);
        assert(error);
        goto err;
    }
    else if (num_abrtonfail == 0) {
        /* Default value is FALSE */
        xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), false);
    }
    goto out;

    err:
        if (error != NULL)
            xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_ERROR_KEY), error);
        xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY), false);
        rv = 1;
        /* Release resources */
        if (key != NULL)
            xbps_object_release(key);
        if (val != NULL)
            xbps_object_release(val);
        if (key_val != NULL)
            xbps_object_release(key_val);
        key = NULL;
        val = NULL;
        key_val = NULL;

    out:
        /* All checks passed then the hook is valid */
        if (rv == 0)
            xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY), true);
        /* Release resources */
        free(line);
        line = NULL;
        fclose(fp);

    return rv;
}

bool HIDDEN
xbps_hooks_chkdefvalues(int key, xbps_string_t val, int start, int end) {

    bool found = false;

    for (int i = start; i < end; i++) {
        if (key == XBPS_HOOK_OPERATION_KEY) {
            if (xbps_string_equals_cstring(val, hook_oper_valstr(i))) {
                found = true;
                break;
            }
        }
        else if (key == XBPS_HOOK_TYPE_KEY) {
            if (xbps_string_equals_cstring(val, hook_type_valstr(i))) {
                found = true;
                break;
            }
        }
        else if (key == XBPS_HOOK_WHEN_KEY) {
            if (xbps_string_equals_cstring(val, hook_when_valstr(i))) {
                found = true;
                break;
            }
        }
        else if (key == XBPS_HOOK_ABRTONFAIL_KEY) {
            if (xbps_string_equals_cstring(val, hook_abrtonfail_val_str(i))) {
                found = true;
                break;
            }
        }
    }
    if (!found) return false;

    return true;
}


bool HIDDEN
xbps_hooks_addvalue(xbps_dictionary_t hook_dict, xbps_string_t key, xbps_string_t val, int numline){

    xbps_array_t operations, targets, whens;
    const char* keystr = NULL;
    xbps_string_t error = NULL, val_upper;
    xbps_string_t desc = NULL;

    assert(hook_dict);
    assert(key);
    assert(val);

    /* Initialize */
    operations = xbps_dictionary_get(hook_dict , hook_dict_keystr(XBPS_HOOK_OPERATION_KEY));
    targets = xbps_dictionary_get(hook_dict , hook_dict_keystr(XBPS_HOOK_TARGET_KEY));
    whens = xbps_dictionary_get(hook_dict , hook_dict_keystr(XBPS_HOOK_WHEN_KEY));

    /* Description */
    keystr = hook_dict_keystr(XBPS_HOOK_DESCRIPTION_KEY);
    if (xbps_string_equals_cstring(key , keystr)) {
        /* Truncate description */
        if (xbps_string_size(val) > 70) {
            desc = xbps_string_substr(xbps_string_cstring_nocopy(val), 0, 67);
            xbps_string_append_cstring(desc, "...");
            xbps_dictionary_set(hook_dict, keystr, desc);
        }
        else {
            xbps_dictionary_set(hook_dict, keystr, xbps_string_copy(val));
        }
    }

    /* Operation */
    keystr = hook_dict_keystr(XBPS_HOOK_OPERATION_KEY);
    if (xbps_string_equals_cstring(key, keystr)) {
        if (operations == NULL) {
            operations = xbps_array_create();
            assert(operations);
            xbps_dictionary_set(hook_dict, keystr, operations);
        }
        val_upper = xbps_string_toupper(val);
        /* Check duplicate values */
        if (!xbps_hooks_isdupvalue(operations, val_upper)) {
            /* Check correctness data */
            if (xbps_hooks_chkdefvalues(XBPS_HOOK_OPERATION_KEY, val_upper,
                                        OPER_INSTALL, OPER_MAX)) {
                xbps_array_add(operations, val_upper);
            }
            else {
                error = xbps_hooks_error_desc("An incorrect value for the 'Operation' property! \n"
                "The accepted values are <Install|Upgrade|Remove> (Required, Repeatable) \n", numline);
                assert(error);
            }
        }
        else {
            error = xbps_hooks_error_desc("Duplicate value for the 'Operation' property!\n", numline);
            assert(error);
        }
    }

    /* Type */
    keystr = hook_dict_keystr(XBPS_HOOK_TYPE_KEY);
    if (xbps_string_equals_cstring(key , keystr)) {
        val_upper = xbps_string_toupper(val);
        /* Check correctness data */
        if (xbps_hooks_chkdefvalues(XBPS_HOOK_TYPE_KEY, val_upper,
                                    TYPE_PACKAGE, TYPE_MAX)) {
            xbps_dictionary_set(hook_dict, keystr, val_upper);
        }
        else {
            error = xbps_hooks_error_desc("An incorrect value for the 'Type' property! \n"
            "The accepted values are <Package|Path> (Required, Not Repeatable) \n", numline);
            assert(error);
        }
    }

    /* Target */
    keystr = hook_dict_keystr(XBPS_HOOK_TARGET_KEY);
     if (xbps_string_equals_cstring(key, keystr)) {
        if (targets == NULL) {
            targets = xbps_array_create();
            assert(targets);
            xbps_dictionary_set(hook_dict, keystr, targets);
        }
        /* Check duplicate values */
        if (!xbps_hooks_isdupvalue(targets, val)) {
            xbps_array_add(targets , xbps_string_copy(val));
        }
        else {
            error = xbps_hooks_error_desc("Duplicate value for the 'Target' property! \n", numline);
            assert(error);
        }
    }

    /* When */
    keystr = hook_dict_keystr(XBPS_HOOK_WHEN_KEY);
    if (xbps_string_equals_cstring(key , keystr)) {
        if (whens == NULL) {
            whens = xbps_array_create();
            assert(whens);
            xbps_dictionary_set(hook_dict, keystr, whens);
        }
        val_upper = xbps_string_toupper(val);
        /* Check duplicate values */
        if (!xbps_hooks_isdupvalue(whens, val_upper)) {
            /* Check correctness data */
            if (xbps_hooks_chkdefvalues(XBPS_HOOK_WHEN_KEY, val_upper,
                                        WHEN_PRE_TRANSACTION, WHEN_MAX) ) {
                xbps_array_add(whens , val_upper);
            }
            else {
                error = xbps_hooks_error_desc( "An incorrect value for the 'When' property! \n"
                "The accepted values are <PreTransaction|PostTransaction> (Required, Repeatable) \n", numline);
                assert(error);
            }
        }
        else {
            error = xbps_hooks_error_desc("Duplicate value for the 'When' property!\n", numline);
            assert(error);
        }
    }

    /* Exec */
    keystr = hook_dict_keystr(XBPS_HOOK_EXEC_KEY);
    if (xbps_string_equals_cstring(key, keystr)) {
        xbps_dictionary_set(hook_dict, keystr, xbps_string_copy(val));
    }

    /* AbortOnFail */
    keystr = hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY);
    if (xbps_string_equals_cstring( key , keystr )) {
        val_upper = xbps_string_toupper(val);
        /* Check correctness data */
        if ( xbps_hooks_chkdefvalues(XBPS_HOOK_ABRTONFAIL_KEY, val_upper,
                                     ABRT_ONFAIL_FALSE, ABRT_ONFAIL_MAX)) {

            if (xbps_string_equals_cstring( val_upper, hook_abrtonfail_val_str(ABRT_ONFAIL_FALSE))) {
                xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), false);
            }
            else if (xbps_string_equals_cstring( val_upper, hook_abrtonfail_val_str(ABRT_ONFAIL_TRUE))) {
                xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), true);
            }
        }
        else {
            error = xbps_hooks_error_desc("An incorrect value for the 'AbortOnFail' property! \n"
            "The accepted values are <False|True> (Required, Not Repeatable) \n", numline);
            assert(error);
        }
        /* Don't need 'val_upper' */
        if (val_upper != NULL) {
            xbps_object_release(val_upper);
            val_upper = NULL;
        }
    }

    if (error != NULL) {
        xbps_dictionary_set(hook_dict , hook_dict_keystr(XBPS_HOOK_ERROR_KEY), error);
        return false;
    }

    return true;
}

bool HIDDEN
xbps_hooks_isdupvalue( xbps_array_t values , xbps_string_t value) {

    xbps_string_t value_arr = NULL;
    int size = (values != NULL ? xbps_array_count(values) : 0);
    for (int i = 0; i < size; i++) {
        value_arr = xbps_array_get(values , i);
        if (xbps_string_equals(value, value_arr)) {
            return true;
        }
    }
    return false;
}

void HIDDEN
xbps_hooks_release(struct xbps_handle* xhp) {

    int size_hooks, size_keys, size;
    xbps_array_t hooks, keys;
    xbps_dictionary_t hook_dict = NULL;
    xbps_dictionary_keysym_t keysym = NULL;
    xbps_object_t obj, entry;

    assert(xhp);

    /* Initialize */
    size_hooks = size_keys = size = 0;
    hooks = keys = NULL;
    obj = entry = NULL;
    hooks = xhp->hooks;
    size_hooks = (hooks != NULL ? xbps_array_count(hooks) : 0);

    xbps_dbg_printf(xhp, "Releasing xbps hooks ...\n");
    for (int i = 0; i < size_hooks; i++) {
        if (xbps_object_type(xbps_array_get(hooks, i)) == XBPS_TYPE_DICTIONARY) {
            hook_dict = xbps_array_get(hooks, i);

            keys = xbps_dictionary_all_keys(hook_dict);
            size_keys = (keys != NULL ? xbps_array_count(keys) : 0);
            for (int j = 0; j < size_keys; j++) {
                keysym = xbps_array_get(keys, j);
                obj = xbps_dictionary_get_keysym(hook_dict, keysym);

                if (xbps_object_type(obj) == XBPS_TYPE_STRING) {
                    if (obj != NULL) {
                        xbps_object_release(obj);
                        obj = NULL;
                    }
                }
                else if (xbps_object_type(obj) == XBPS_TYPE_ARRAY) {
                    size = (obj != NULL ? xbps_array_count(obj) : 0);
                    for (int k = 0; k < size; k++) {
                        entry = xbps_array_get(obj, k);
                        if (entry != NULL) {
                            xbps_object_release(entry);
                            entry = NULL;
                        }
                    }
                    if (obj != NULL) {
                        xbps_object_release(obj);
                        obj = NULL;
                    }
                }
            }
            xbps_object_release(hook_dict);
            hook_dict = NULL;
        }
    }
    if (hooks != NULL) {
        /* Can't release hooks, only clean */
        hooks = NULL;
        xbps_dbg_printf(xhp, "Xbps hooks released successfully!\n");
    }
}

char**
xbps_hooks_split_cmdline(const char *str) {
    const char *c = str, *end;
    char **out = NULL, **outsave;
    size_t count = 0;

    if(str == NULL) {
        errno = EINVAL;
        return NULL;
    }

    for(c = str; isspace(*c); c++);
    while(*c) {
        size_t wordlen = 0;

        /* extend our array */
        outsave = out;
        if((out = realloc(out, (count + 1) * sizeof(char*))) == NULL) {
            out = outsave;
            goto error;
        }

        /* calculate word length and check for unbalanced quotes */
        for(end = c; *end && !isspace(*end); end++) {
            if(*end == '\'' || *end == '"') {
                char quote = *end;
                while(*(++end) && *end != quote) {
                    if(*end == '\\' && *(end + 1) == quote) {
                        end++;
                    }
                    wordlen++;
                }
                if(*end != quote) {
                    errno = EINVAL;
                    goto error;
                }
            } else {
                if(*end == '\\' && (end[1] == '\'' || end[1] == '"')) {
                    end++; /* skip the '\\' */
                }
                wordlen++;
            }
        }

        if(wordlen == (size_t) (end - c)) {
            /* no internal quotes or escapes, copy it the easy way */
            if((out[count++] = strndup(c, wordlen)) == NULL) {
                goto error;
            }
        } else {
            /* manually copy to remove quotes and escapes */
            char *dest = out[count++] = malloc(wordlen + 1);
            if(dest == NULL) { goto error; }
            while(c < end) {
                if(*c == '\'' || *c == '"') {
                    char quote = *c;
                    /* we know there must be a matching end quote,
                     * no need to check for '\0' */
                    for(c++; *c != quote; c++) {
                        if(*c == '\\' && *(c + 1) == quote) {
                            c++;
                        }
                        *(dest++) = *c;
                    }
                    c++;
                } else {
                    if(*c == '\\' && (c[1] == '\'' || c[1] == '"')) {
                        c++; /* skip the '\\' */
                    }
                    *(dest++) = *(c++);
                }
            }
            *dest = '\0';
        }

        if(*end == '\0') {
            break;
        } else {
            for(c = end + 1; isspace(*c); c++);
        }
    }

    outsave = out;
    if((out = realloc(out, (count + 1) * sizeof(char*))) == NULL) {
        out = outsave;
        goto error;
    }

    out[count++] = NULL;

    return out;

error:
    /* can't use xbps_hooks_rel_cmdline() here because NULL has not been appended */
    while(count) {
        free(out[--count]);
    }
    free(out);
    return NULL;
}

void HIDDEN
xbps_hooks_rel_cmdline(char **cmdline) {
    if(cmdline) {
        char **c;
        for(c = cmdline; *c; c++) {
            free(*c);
            *c = NULL;
        }
        free(cmdline);
        cmdline = NULL;
    }
}

bool HIDDEN
xbps_hooks_chk_target(struct xbps_handle* xhp, const char* target, const char* value) {

    char* newtarget = NULL;
    bool inverted = false, match = false;
    int fnmatch_res = 0;

    assert(xhp);
    assert(target);
    assert(value);

    xbps_dbg_printf(xhp, "[hook] Value : %s \n", value);
    xbps_dbg_printf(xhp, "[hook] Target : %s\n", target);

    /* If target starts with '!' then invert the result */
    if (xbps_string_starts_with(target, "!")) {
        inverted = true;
        xbps_dbg_printf(xhp, "[hook] inverted : %s \n", "true");
        /* Assigning a new target deleting first character '!' */
        newtarget = xbps_string_substr_cstring(target, 1, strlen(target));
        assert(newtarget);
        xbps_dbg_printf(xhp, "[hook] Target without exclamation mark '!' : %s\n", newtarget);
    }

    if (inverted)
        fnmatch_res = fnmatch(newtarget, value, 0);
    else
        fnmatch_res = fnmatch(target, value, 0);

    switch (fnmatch_res) {
    case 0:
        match = true;
        xbps_dbg_printf(xhp, "[hook] match true!\n" );
        break;
    case FNM_NOMATCH:
        match = false;
        xbps_dbg_printf(xhp, "[hook] match false!\n" );
        break;
    default:
        match = false;
        xbps_dbg_printf(xhp, "[hook] Error in fnmatch() rv : %d !\n", fnmatch_res );
    }
    if (inverted) {
        match = !match;
        xbps_dbg_printf(xhp, "[hook] final match : %s! \n", match ? "true" : "false");
    }

    /* Release resources */
    if (newtarget != NULL) {
        free(newtarget);
        newtarget = NULL;
    }

    return match;
}
