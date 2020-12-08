/*
** pattern-list.c -- The implementation of wildcard pattern list.
**
** Copyright (c) 2020 FMSoft (http://www.fmsoft.cn)
**
** Author: Vincent Wei (https://github.com/VincentWei)
**
** This file is part of hiBus.
**
** hiBus is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** hiBus is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU General Public License
** along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include <glib.h>

#include <hibox/ulog.h>
#include <hibox/list.h>
#include <hibox/blobmsg.h>

#include "hibus.h"

enum {
    PT_ANY = 0,
    PT_SPEC,
    PT_NOT_SPEC,
    PT_VARIABLE,
};

struct one_pattern {
    struct list_head  list;

    int type;
    union {
        char*         var_name;
        GPatternSpec* spec;
        GPatternSpec* not_spec;
    };
};

struct _hibus_pattern_list {
    struct list_head  list;
    int nr_patterns;
};

hibus_pattern_list *hibus_create_pattern_list (const char* pattern)
{
    hibus_pattern_list *pl;

    if ((pl = calloc (1, sizeof (hibus_pattern_list))) == NULL) {
        return NULL;
    }

    INIT_LIST_HEAD (&pl->list);
    pl->nr_patterns = 0;

    return pl;
}

void hibus_destroy_pattern_list (hibus_pattern_list *pl)
{
    struct list_head *node, *tmp;
    struct one_pattern *pattern;

    list_for_each_safe (node, tmp, &pl->list) {
        pattern = (struct one_pattern *)node;

        switch (pattern->type) {
            case PT_ANY:
                break;

            case PT_SPEC:
                assert (pattern->spec);
                g_pattern_spec_free (pattern->spec);
                break;

            case PT_NOT_SPEC:
                assert (pattern->not_spec);
                g_pattern_spec_free (pattern->not_spec);
                break;

            case PT_VARIABLE:
                assert (pattern->var_name);
                free (pattern->var_name);
                break;
        }

        free (pattern);
    }

    free (pl);
}

bool hibus_pattern_match (hibus_pattern_list *pl, const char* string,
        int nr_vars, ...)
{
    va_list ap;
    struct blob_buf var_map;

    if (blob_buf_init (&var_map, 0)) {
        ULOG_ERR ("Failed to call blob_buf_init\n");
        return false;
    }

    va_start (ap, nr_vars);
    while (nr_vars > 0) {
        const char *var, *sub;

        var = va_arg (ap, const char *);
        sub = va_arg (ap, const char *);
        if (var && sub) {
            if (blobmsg_add_string (&var_map, var, sub)) {
                goto failed;
            }
        }
        else
            break;

        nr_vars--;
    }
    va_end (ap);

    // ...

    blob_buf_free (&var_map);
    return true;

failed:
    blob_buf_free (&var_map);
    return false;
}

