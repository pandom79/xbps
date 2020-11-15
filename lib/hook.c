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

const char*
hook_dict_keystr(enum hook_dict_keys key) {
    switch (key) {
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

const char *
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

const char *
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
ttype_val_str(enum xbps_trans_type ttype){
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

void HIDDEN xbps_hooks_sort_path(xbps_array_t* hooks){

    xbps_dictionary_t hook_dict_a = NULL, hook_dict_b = NULL, hook_dict_sup = NULL;
    xbps_string_t filepath_a = NULL, filepath_b = NULL;
    int size;

    size = ( *hooks!=NULL ? xbps_array_count(*hooks) : 0 );
    for (int i=0; i<size; i++) {
        for (int j=0; j<size-i-1; j++) {
            hook_dict_a = xbps_array_get(*hooks , j);
            filepath_a = xbps_dictionary_get(hook_dict_a, hook_dict_keystr(XBPS_HOOK_FPATH_KEY));
            hook_dict_b = xbps_array_get(*hooks , j+1);
            filepath_b = xbps_dictionary_get(hook_dict_b, hook_dict_keystr(XBPS_HOOK_FPATH_KEY));
            if ( strcmp( xbps_string_cstring(filepath_a) , xbps_string_cstring(filepath_b )) > 0) {
                hook_dict_sup = xbps_dictionary_copy(hook_dict_a);
                xbps_array_set(*hooks, j , hook_dict_b );
                xbps_array_set(*hooks, j+1 , hook_dict_sup );
            }
        }
    }

}

int HIDDEN
xbps_hooks_load_path( const char* hooks_path , xbps_array_t* hooks ){

    DIR* d = NULL;
    struct dirent* dir = NULL;
    char* suffix = NULL;
    xbps_dictionary_t hook_dict = NULL;
    xbps_string_t filepath = NULL, filename = NULL;
    int rv = 0;

    d = opendir(hooks_path);
    if (d != NULL ) {
        while ((dir = readdir(d)) != NULL) {
            suffix = strrchr( dir->d_name , '.' );
            if ( suffix != NULL && strcmp( suffix , ".hook" ) == 0 ){
                filepath = xbps_string_create_cstring( hooks_path );
                assert(filepath);
                filename = xbps_string_create_cstring( dir->d_name );
                assert(filename);

                /* Building complete file path */
                xbps_string_append_cstring( filepath , "/" );
                xbps_string_append_cstring( filepath , dir->d_name );

                hook_dict = xbps_dictionary_create();
                assert(hook_dict);
                xbps_dictionary_set( hook_dict , hook_dict_keystr(XBPS_HOOK_FNAME_KEY) , filename );
                xbps_dictionary_set( hook_dict , hook_dict_keystr(XBPS_HOOK_FPATH_KEY) , filepath );

                if ( *hooks == NULL ){
                    *hooks = xbps_array_create();
                }
                assert(*hooks);
                xbps_array_add( *hooks , hook_dict );

            }
            suffix = NULL;
            free(suffix);
        }
        free(dir);
        closedir(d);
    }
    else{
        rv = errno;
    }

    return rv;
}

int HIDDEN
xbps_hooks_load_data(struct xbps_handle* xhp){

    int size_hooks = 0;
    xbps_string_t filepath = NULL, filename = NULL, error = NULL;
    xbps_dictionary_t hook_dict = NULL;
    bool valid, showvalidmsg = false;

    assert(xhp);

    size_hooks = (xhp->hooks!=NULL ? xbps_array_count(xhp->hooks) : 0);
    for (int i=0; i<size_hooks ; i++) {

        /* Get filename and filepath */
        hook_dict = xbps_array_get( xhp->hooks, i );
        filename = xbps_dictionary_get(hook_dict , hook_dict_keystr(XBPS_HOOK_FNAME_KEY) );
        filepath = xbps_dictionary_get(hook_dict , hook_dict_keystr(XBPS_HOOK_FPATH_KEY) );
        assert(filename);
        assert(filepath);

        if (xhp->flags & XBPS_FLAG_DEBUG){
            if (i==0)
                xbps_dbg_printf(xhp,"[hook] Found %d xbps hooks\n",size_hooks);
            xbps_dbg_printf(xhp, "[hook] Filename %s\n" , xbps_string_cstring(filename) );
            xbps_dbg_printf(xhp, "[hook] Filepath %s\n" , xbps_string_cstring(filepath) );
        }

        /*
         * Parsing xbps hook.
         * It will populate the dictionary with remaining data
         */
        xbps_hooks_parse_file(xhp , hook_dict);

        /* Get properties */
        xbps_dictionary_get_bool( hook_dict , hook_dict_keystr(XBPS_HOOK_VALID_KEY) , &valid );
        error = xbps_dictionary_get( hook_dict , hook_dict_keystr(XBPS_HOOK_ERROR_KEY) );

        xbps_dbg_printf(xhp, "[hook] valid: %d\n" , valid );
        xbps_dbg_printf(xhp, "[hook] error %s\n" , xbps_string_cstring(error) );

        /* If hook is not valid then show the configuration error */
        if ( !valid ){
            if ( !showvalidmsg ){
                xbps_set_cb_state(xhp, XBPS_STATE_VALIDATE_HOOKS, 0, NULL, NULL);
                showvalidmsg = true;
            }
            xbps_set_cb_state(xhp, XBPS_STATE_VALIDATING_HOOKS, 0,
                              xbps_string_cstring(filename), NULL);
            printf("Error: %s", xbps_string_cstring(error));
        }
    }
    return 0;
}

xbps_array_t HIDDEN
xbps_hooks_parse_keyval(const char *buf){

    xbps_array_t key_val = NULL;
    int len = 0, index = 0, cont = 0;
    char *key = NULL , *val = NULL;

    len = strlen(buf);
    for (int i=0; i<len ; i++ ) {
        if ( buf[i] == '=' ){
            index = i;
            break;
        }
    }
    //If '=' is present
    if ( index > 0 ){
        /* Only 2: key and value */
        key_val = xbps_array_create_with_capacity(2);
        assert(key_val);

        /* KEY */
        for (int i=0; i<index; i++ ) {
            if ( key == NULL ) {
                key = calloc( strlen(buf) + 1 , sizeof(buf));
            }
            assert(key);
            key[cont] = buf[i];
            cont++;
        }
        /* Trim and toupper */
        trim(key,NULL);
        toupperstr(key);
        xbps_array_add( key_val , xbps_string_create_cstring(key) );

        /* VALUE */
        cont = 0;
        for (int i=(index+1); i<len; i++ ) {
            if ( val == NULL ) {
                val = calloc( strlen(buf) + 1 , sizeof(buf));
            }
            assert(val);
            val[cont] = buf[i];
            cont++;
        }
        /* Trim */
        trim(val,NULL);
        xbps_array_add( key_val , xbps_string_create_cstring(val) );
    }
    return key_val;
}


int HIDDEN
xbps_hooks_parse_file(struct xbps_handle* xhp, xbps_dictionary_t hook_dict){

    FILE *fp;
    size_t len = 0;
    char *line = NULL, *p = NULL;
    int rv = 0 ;
    int num_operations, num_type, num_targets,num_whens, num_exec, num_abrtonfail, num_desc;
    xbps_string_t filepath, key, val, error;
    xbps_array_t key_val = NULL;

    assert(xhp);
    assert(hook_dict);

    /* Initialize */
    num_desc = num_operations = num_type = num_targets = num_whens = num_exec = num_abrtonfail = 0;
    filepath = key = val = error = NULL;

    /* Get filepath from dictionary */
    filepath = xbps_dictionary_get( hook_dict , hook_dict_keystr(XBPS_HOOK_FPATH_KEY) );
    assert(filepath);

    /* Open hook file */
    if ((fp = fopen(xbps_string_cstring(filepath), "r")) == NULL) {
        rv = errno;
        xbps_dbg_printf(xhp, "[hook] Unable open hook file '%s': "
            "%s\n", xbps_string_cstring(filepath), strerror(rv));
        return rv;
    }

    while ( getline(&line, &len, fp) != -1 ) {
        p = line;

        /* eat blanks */
        while (isblank((unsigned char)*p)){
            p++;
        }

        /* ignore comments or empty lines */
        if (*p == '#' || *p == '\n'){
            continue;
        }

        /* Parse Key and Value */
        key_val = xbps_hooks_parse_keyval(p);
        if ( key_val != NULL ){

            /* Get key and value */
            key = xbps_array_get( key_val , 0 );
            val = xbps_array_get( key_val , 1 );

            if ( key != NULL && !xbps_string_equals_cstring(key, "") &&
                 val != NULL && !xbps_string_equals_cstring(val, "") ){

                /* Description */
                if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_DESCRIPTION_KEY)) ){
                    num_desc++;
                    if (num_desc > 1){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'Description' property! "
                        "(Optional, Not Repeatable)\n");
                        assert(error);
                        goto err;
                    }
                }
                /* Operations */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_OPERATION_KEY)) ){
                    num_operations++;
                    if ( num_operations > OPER_MAX ){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'Operation' property! \n"
                                "The accepted values are <Install|Upgrade|Remove> (Required, Repeatable) \n");
                        assert(error);
                        goto err;
                    }
                }
                /* Type */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TYPE_KEY)) ){
                    num_type++;
                    if ( num_type > 1 ){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'Type' property! \n"
                        "The accepted values are <Package|Path>. (Not Repeatable) \n");
                        assert(error);
                        goto err;
                    }
                }
                /* Target */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TARGET_KEY)) ){
                    num_targets++;
                }
                /* Whens */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_WHEN_KEY)) ){
                    num_whens++;
                    if ( num_whens > WHEN_MAX ){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'When' property! \n"
                        "The accepted values are <PreTransaction|PostTransaction>. (Required, Repeatable) \n");
                        assert(error);
                        goto err;
                    }
                }
                /* Exec */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_EXEC_KEY)) ){
                    num_exec++;
                    if ( num_exec > 1 ){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'Exec' property! "
                        "(Required, Not Repeatable) \n");
                        assert(error);
                        goto err;
                    }
                }
                /* AbortOnFail */
                else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY)) ){
                    num_abrtonfail++;
                    if ( num_abrtonfail > 1 ){
                        error = xbps_string_create_cstring( "An incorrect occurences number for the 'AbortOnFail' property! \n"
                        "The accepted values are <False|True> (Optional, Not Repeatable) \n" );
                        assert(error);
                        goto err;
                    }
                }
                /*
                 * Add value to the dictionary.
                 */
                if ( !xbps_hooks_addvalue(hook_dict, key, val) ){
                    goto err;
                }
            }
        }
    }

    /* Check required properties */
    if ( num_operations == 0 ){
        error = xbps_string_create_cstring( "The 'Operation' property is required! \n" );
        assert(error);
        goto err;
    }
    else if ((num_type == 0 && num_targets > 0 ) || (num_type > 0 && num_targets == 0 )) {
        error = xbps_string_create_cstring( "The 'Type' and 'Target' properties are complementary! \n"
        "Both must be valued or be null. \n");
        assert(error);
        goto err;
    }
    else if (num_whens == 0) {
        error = xbps_string_create_cstring( "The 'When' property is required! \n" );
        assert(error);
        goto err;
    }
    else if (num_exec == 0) {
        error = xbps_string_create_cstring( "The 'Exec' property is required! \n" );
        assert(error);
        goto err;
    }
    else if (num_abrtonfail == 0) {
        /* Default value is FALSE */
        xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), false );
    }
    goto out;

    err:
        if ( error != NULL )
            xbps_dictionary_set( hook_dict, hook_dict_keystr(XBPS_HOOK_ERROR_KEY), error );
        xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY), false );
        rv = 1;

    out:
        /* All checks passed then the hook is valid */
        if ( rv == 0 )
            xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_VALID_KEY), true );
        /* Release resources */
        line = NULL;
        free(line);
        fclose(fp);

    return rv;
}

bool HIDDEN
xbps_hooks_chkdefvalues( xbps_string_t key, xbps_string_t val ) {

    bool found = false;

    /* Operations */
    if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_OPERATION_KEY)) ){
        for (int i=OPER_INSTALL; i<OPER_MAX; i++) {
            if ( xbps_string_equals_cstring( val, hook_oper_valstr(i) ) ){
                found = true;
                break;
            }
        }
        if ( !found ) return false;
    }

    /* Type */
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_TYPE_KEY)) ){
        for (int i=TYPE_PACKAGE; i<TYPE_MAX; i++) {
            if ( xbps_string_equals_cstring( val, hook_type_valstr(i) ) ){
                found = true;
                break;
            }
        }
        if ( !found ) return false;
    }

    /* When */
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_WHEN_KEY)) ){
        for (int i=WHEN_PRE_TRANSACTION; i<WHEN_MAX; i++) {
            if ( xbps_string_equals_cstring( val, hook_when_valstr(i) ) ){
                found = true;
                break;
            }
        }
        if ( !found ) return false;
    }

    /* AbortOnFail */
    else if ( xbps_string_equals_cstring(key, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY)) ){
        for (int i=ABRT_ONFAIL_FALSE; i<ABRT_ONFAIL_MAX; i++) {
            if ( xbps_string_equals_cstring( val, hook_abrtonfail_val_str(i) )){
                found = true;
                break;
            }
        }
        if ( !found ) return false;
    }

    return true;
}


bool HIDDEN
xbps_hooks_addvalue(xbps_dictionary_t hook_dict, xbps_string_t key, xbps_string_t val){

    xbps_array_t operations, targets, whens;
    const char* keystr = NULL;
    xbps_string_t error = NULL;

    assert(hook_dict);
    assert(key);
    assert(val);

    /* Initialize */
    operations = xbps_dictionary_get( hook_dict , hook_dict_keystr(XBPS_HOOK_OPERATION_KEY ) );
    targets = xbps_dictionary_get( hook_dict , hook_dict_keystr( XBPS_HOOK_TARGET_KEY ) );
    whens = xbps_dictionary_get( hook_dict , hook_dict_keystr( XBPS_HOOK_WHEN_KEY ) );

    /* Exec */
    keystr = hook_dict_keystr(XBPS_HOOK_DESCRIPTION_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        xbps_dictionary_set(hook_dict, keystr, val );
    }

    /* Operation */
    keystr = hook_dict_keystr(XBPS_HOOK_OPERATION_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        if ( operations == NULL ){
            operations = xbps_array_create();
            assert(operations);
            xbps_dictionary_set(hook_dict, keystr, operations );
        }
        val = xbps_string_toupper(val);
        /* Check duplicate values */
        if ( !xbps_hooks_isdupvalue(operations, val  ) ){
            /* Check correctness data */
            if ( xbps_hooks_chkdefvalues( key , val ) ){
                xbps_array_add( operations , val );
            }
            else {
                error = xbps_string_create_cstring( "An incorrect value for the 'Operation' property! \n"
                "The accepted values are <Install|Upgrade|Remove> (Required, Repeatable) \n");
                assert(error);
            }
        }
        else {
            error = xbps_string_create_cstring( "Duplicate value for the 'Operation' property!\n");
            assert(error);
        }
    }

    /* Type */
    keystr = hook_dict_keystr(XBPS_HOOK_TYPE_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        val = xbps_string_toupper(val);
        if ( xbps_hooks_chkdefvalues(key, val) ){
            xbps_dictionary_set(hook_dict, hook_dict_keystr(XBPS_HOOK_TYPE_KEY), val);
        }
        else {
            error = xbps_string_create_cstring( "An incorrect value for the 'Type' property! \n"
            "The accepted values are <Package|Path> (Required, Not Repeatable) \n");
            assert(error);
        }
    }

    /* Target */
    keystr = hook_dict_keystr(XBPS_HOOK_TARGET_KEY);
     if ( xbps_string_equals_cstring( key , keystr ) ){
        if ( targets == NULL ){
            targets = xbps_array_create();
            assert(targets);
            xbps_dictionary_set(hook_dict, keystr, targets);
        }
        /* Check duplicate values */
        if ( !xbps_hooks_isdupvalue(targets, val) ){
            xbps_array_add( targets , val );
        }
        else {
            error = xbps_string_create_cstring( "Duplicate value for the 'Target' property! \n");
            assert(error);
        }
    }

    /* When */
    keystr = hook_dict_keystr(XBPS_HOOK_WHEN_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        if ( whens == NULL ){
            whens = xbps_array_create();
            assert(whens);
            xbps_dictionary_set(hook_dict, keystr, whens );
        }
        val = xbps_string_toupper(val);
        /* Check duplicate values */
        if ( !xbps_hooks_isdupvalue(whens, val) ){
            /* Check correctness data */
            if ( xbps_hooks_chkdefvalues(key, val) ){
                xbps_array_add(whens , val );
            }
            else {
                error = xbps_string_create_cstring( "An incorrect value for the 'When' property! \n"
                "The accepted values are <PreTransaction|PostTransaction>. (Required, Repeatable) \n");
                assert(error);
            }
        }
        else {
            error = xbps_string_create_cstring( "Duplicate value for the 'When' property!\n");
            assert(error);
        }
    }

    /* Exec */
    keystr = hook_dict_keystr(XBPS_HOOK_EXEC_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        xbps_dictionary_set(hook_dict, keystr, val );
    }

    /* AbortOnFail */
    keystr = hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY);
    if ( xbps_string_equals_cstring( key , keystr ) ){
        val = xbps_string_toupper(val);
        /* Check correctness data */
        if ( xbps_hooks_chkdefvalues(key, val) ){
            if ( xbps_string_equals_cstring( val, hook_abrtonfail_val_str(ABRT_ONFAIL_FALSE) ) ){
                xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), false);
            }
            else if ( xbps_string_equals_cstring( val, hook_abrtonfail_val_str(ABRT_ONFAIL_TRUE) ) ){
                xbps_dictionary_set_bool(hook_dict, hook_dict_keystr(XBPS_HOOK_ABRTONFAIL_KEY), true);
            }
        }
        else {
            error = xbps_string_create_cstring( "An incorrect value for the 'AbortOnFail' property! \n"
            "The accepted values are <False|True> (Required, Not Repeatable) \n");
            assert(error);
        }
    }

    if ( error != NULL ){
        xbps_dictionary_set(hook_dict , hook_dict_keystr(XBPS_HOOK_ERROR_KEY), error);
        return false;
    }

    return true;
}

bool HIDDEN
xbps_hooks_isdupvalue( xbps_array_t values , xbps_string_t value) {

    xbps_string_t value_arr = NULL;
    int size = ( values != NULL ? xbps_array_count(values) : 0 );
    for (int i=0; i<size; i++) {
        value_arr = xbps_array_get( values , i );
        if ( xbps_string_equals( value, value_arr ) ){
            return true;
        }
    }
    return false;
}

void HIDDEN xbps_hooks_release(struct xbps_handle* xhp){

    int size_hooks = 0, size_keys = 0, size = 0;
    xbps_array_t hooks = NULL, keys = NULL;
    xbps_dictionary_t hook_dict = NULL;
    xbps_dictionary_keysym_t keysym = NULL;
    xbps_object_t obj = NULL, entry = NULL;

    assert(xhp);

    hooks = xhp->hooks;
    size_hooks = ( hooks!=NULL ? xbps_array_count(hooks) : 0 );
    xbps_dbg_printf(xhp, "Releasing xbps hooks ...\n");
    for (int i=0; i<size_hooks; i++) {
        if (xbps_object_type(xbps_array_get(hooks,i)) == XBPS_TYPE_DICTIONARY){
            hook_dict = xbps_array_get(hooks,i);

            keys = xbps_dictionary_all_keys(hook_dict);
            size_keys = (keys!=NULL ? xbps_array_count(keys) : 0);
            for (int j=0; j<size_keys; j++) {
                keysym = xbps_array_get(keys, j);
                obj = xbps_dictionary_get_keysym(hook_dict,keysym);

                if ( (xbps_object_type(obj) == XBPS_TYPE_STRING) ||
                     (xbps_object_type(obj) == XBPS_TYPE_BOOL)){
                    xbps_object_release(obj);
                    obj = NULL;
                }
                else if ( xbps_object_type(obj) == XBPS_TYPE_ARRAY ){
                    size = ( obj!=NULL ? xbps_array_count(obj) : 0 );
                    for (int k=0; k<size; k++) {
                        entry = xbps_array_get(obj,k);
                        xbps_object_release( entry );
                        entry = NULL;
                    }
                }
            }
            xbps_object_release(hook_dict);
            hook_dict = NULL;
        }
    }
    if ( hooks != NULL ){
        hooks = NULL;
        xbps_dbg_printf(xhp, "Xbps hooks released successfully!\n");
    }
}
