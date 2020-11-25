/*
** sign_verify_hmac_sha256.c -- The utilitis for sign the challenge code
**  and verify the signature with HMAC SHA256 algorithms.
**  This file will be used when OpenSSL is not available.
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

#include <string.h>
#include <errno.h>

#ifndef HAVE_LIBSSL

#include <hibox/ulog.h>
#include <hibox/sha256.h>
#include <hibox/hmac.h>

#include "hibus.h"

static int read_private_key_for_app (const char* app_name,
        unsigned char* key, unsigned int key_len)
{
    int size;
    char buff [512];
    FILE *fp = NULL;

    size = snprintf (buff, 512, HIBUS_PRIVATE_HMAC_KEY_FILE, app_name, app_name);
    if (size >= sizeof (buff)) {
        ULOG_ERR ("Too long app name in read_private_key_for_app: %s\n", app_name);
        return -1;
    }

    if ((fp = fopen (buff, "r")) == NULL) {
        ULOG_ERR ("Failed to open the private key file for app (%s): %s\n",
                app_name, strerror (errno));
        return -2;
    }

    size = fread (key, 1, key_len, fp);
    if (size < HIBUS_LEN_PRIVATE_HMAC_KEY) {
        fclose (fp);
        return -3;
    }

    fclose (fp);
    return 0;
}

unsigned char *hibus_sign_data (const char *app_name,
        const unsigned char* data, unsigned int data_len,
        unsigned int *sig_len)
{
    unsigned char key [HIBUS_LEN_PRIVATE_HMAC_KEY];
    unsigned char *sig;

    sig = NULL;
    *sig_len = 0;

    if (read_private_key_for_app (app_name, key, HIBUS_LEN_PRIVATE_HMAC_KEY)) {
        return NULL;
    }

    if ((sig = calloc (1, SHA256_DIGEST_SIZE)) == NULL) {
        return NULL;
    }

    *sig_len = SHA256_DIGEST_SIZE;
    hmac_sha256 (sig, data, data_len, key, HIBUS_LEN_PRIVATE_HMAC_KEY);

    return sig;
}

int hibus_verify_signature (const char* app_name,
        const unsigned char* data, unsigned int data_len,
        const unsigned char* sig, unsigned int sig_len)
{
    unsigned char key [HIBUS_LEN_PRIVATE_HMAC_KEY];
    unsigned char my_sig [SHA256_DIGEST_SIZE];

    if (sig_len != SHA256_DIGEST_SIZE)
        return 0;

    if (read_private_key_for_app (app_name, key, HIBUS_LEN_PRIVATE_HMAC_KEY)) {
        return 0;
    }

    hmac_sha256 (my_sig, data, data_len, key, HIBUS_LEN_PRIVATE_HMAC_KEY);

    if (memcmp (my_sig, sig, sig_len) == 0)
        return 1;

    return 0;
}

#endif /* !HAVE_LIBSSL */

