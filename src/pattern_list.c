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

#define _GNU_SOURCE

#include <stdarg.h>
#include <string.h>
#include <assert.h>

#include <glib.h>

#include <hibox/ulog.h>
#include <hibox/kvlist.h>

#include "endpoint.h"

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

bool init_pattern_list (pattern_list *pl, const char* pattern)
{
    char *string;
    char *str, *token, *savedptr;
    struct one_pattern* one_pattern;

    INIT_LIST_HEAD (&pl->list);
    pl->nr_patterns = 0;

    if ((string = strdup (pattern)) == NULL)
        return false;

    for (str = string; ; str = NULL) {
        token = strtok_r (str, ",; ", &savedptr);
        if (token == NULL)
            break;

        one_pattern = malloc (sizeof (struct one_pattern));
        if (one_pattern == NULL) {
            break;
        }

        if (token[0] == '*' && token[1] == '\0') {
            one_pattern->type = PT_ANY;
            one_pattern->var_name = NULL;
        }
        else if (*token == '$') {
            if (hibus_is_valid_token (token + 1, HIBUS_LEN_APP_NAME)) {
                one_pattern->type = PT_VARIABLE;
                one_pattern->var_name = strdup (token + 1);
            }
            else {
                ULOG_WARN ("Got a bad variable pattern: %s\n", token + 1);
                free (one_pattern);
                continue;
            }
        }
        else if (*token == '!') {
            one_pattern->type = PT_NOT_SPEC;
            one_pattern->not_spec = g_pattern_spec_new (token + 1);
            if (one_pattern->not_spec == NULL) {
                ULOG_WARN ("Failed to create a new spec for pattern: %s\n", token + 1);
                free (one_pattern);
                continue;
            }

        }
        else {
            one_pattern->type = PT_SPEC;
            one_pattern->spec = g_pattern_spec_new (token);
            if (one_pattern->spec == NULL) {
                ULOG_WARN ("Failed to create a new not-spec for pattern: %s\n", token + 1);
                free (one_pattern);
                continue;
            }
        }

        list_add_tail (&one_pattern->list, &pl->list);
        pl->nr_patterns++;
    }

    free (string);
    return true;
}

void cleanup_pattern_list (pattern_list *pl)
{
    struct list_head *node, *tmp;
    struct one_pattern *pattern;

    if (pl->nr_patterns == 0)
        return;

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
}

pattern_list *create_pattern_list (const char* pattern)
{
    pattern_list *pl;

    if ((pl = calloc (1, sizeof (pattern_list))) == NULL) {
        return NULL;
    }

    if (!init_pattern_list (pl, pattern)) {
        free (pl);
        return NULL;
    }

    return pl;
}

void destroy_pattern_list (pattern_list *pl)
{
    cleanup_pattern_list (pl);
    free (pl);
}

bool match_pattern (pattern_list *pl, const char* string,
        int nr_vars, ...)
{
    va_list ap;
    struct kvlist kv;
    struct list_head *node;

    kvlist_init (&kv, NULL);

    va_start (ap, nr_vars);
    while (nr_vars > 0) {
        const char *var, *sub;

        var = va_arg (ap, const char *);
        sub = va_arg (ap, const char *);
        if (var && sub) {
            if (!kvlist_set (&kv, var, &sub)) {
                goto failed;
            }
        }
        else
            break;

        nr_vars--;
    }
    va_end (ap);

    list_for_each (node, &pl->list) {
        struct one_pattern *pattern = (struct one_pattern *)node;
        void *data;
        const char *sub;
        switch (pattern->type) {
            case PT_ANY:
                goto success;

            case PT_SPEC:
                assert (pattern->spec);
                if (g_pattern_match_string (pattern->spec, string))
                    goto success;
                break;

            case PT_NOT_SPEC:
                assert (pattern->not_spec);
                if (g_pattern_match_string (pattern->not_spec, string))
                    goto failed;
                break;

            case PT_VARIABLE:
                assert (pattern->var_name);
                data = kvlist_get (&kv, pattern->var_name);
                sub = *(char **)data;
                if (sub && strcasecmp (sub, string) == 0) {
                    goto success;
                }
                else {
                    ULOG_WARN ("Not found the real value for variable: %s",
                            pattern->var_name);
                }
                break;
        }
    }

failed:
    kvlist_free (&kv);
    return false;

success:
    kvlist_free (&kv);
    return true;
}

