/*
** sign_verify_rsa_sha256.c -- The utilitis for sign the challenge code
**  and verify the signature with RSA and SHA256 algorithms.
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

#include <hibox/ulog.h>

#ifdef BUILD_APP_AUTH
#ifdef HAVE_LIBSSL

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

#include "hibus.h"

static int my_error_printer (const char *str, size_t len, void *u)
{
    ULOG_ERR ("%s\n", str);
    return 0;
}

static RSA* read_private_key_for_app (const char* app_name)
{
    int size;
    char buff [512];
    FILE *fp = NULL;
    RSA *pri_key = NULL;

    size = snprintf (buff, sizeof (buff), HIBUS_PRIVATE_PEM_KEY_FILE, app_name, app_name);
    if (size < 0 || (size_t)size >= sizeof (buff)) {
        ULOG_ERR ("Too long app name in read_private_key_for_app: %s\n", app_name);
        return NULL;
    }

    if ((fp = fopen (buff, "r")) == NULL) {
        ULOG_ERR ("Failed to open the private key file (%s) for app (%s): %s\n",
                buff, app_name, strerror (errno));
        return NULL;
    }

    pri_key = PEM_read_RSAPrivateKey (fp, NULL, NULL, NULL);
    if (pri_key == NULL) {
        ULOG_ERR ("Failed to read RSA private key for app (%s):\n", app_name);
        ERR_print_errors_cb (my_error_printer, NULL);
    }

    fclose(fp);
    return pri_key;
}

int hibus_sign_data (const char *app_name,
        const unsigned char* data, unsigned int data_len,
        unsigned char **sig, unsigned int *sig_len)
{
    int err_code = 0;
    RSA *priv_key = NULL;
    unsigned char md [SHA256_DIGEST_LENGTH];
    int retv = 0;

    *sig = NULL;
    *sig_len = 0;

    priv_key = read_private_key_for_app (app_name);
    if (!priv_key) {
        return HIBUS_EC_CANT_LOAD;
    }

    if ((*sig = calloc (1, 128)) == NULL) {
        err_code = HIBUS_EC_NOMEM;
        goto failed;
    }

    SHA256 (data, data_len, md);
    retv = RSA_sign (NID_sha256, md, SHA256_DIGEST_LENGTH, *sig, sig_len, priv_key);
    if (retv != 1) {
        free (*sig);
        *sig = NULL;
        *sig_len = 0;
        err_code = HIBUS_EC_BAD_KEY;
    }

failed:
    RSA_free (priv_key);
    return err_code;
}

static RSA* read_public_key_for_app (const char* app_name)
{   
    int size;
    char buff [512];
    FILE *fp; 
    RSA *pub_key = NULL;

    size = snprintf (buff, sizeof (buff), HIBUS_PUBLIC_PEM_KEY_FILE, app_name);
    if (size < 0 || (size_t)size >= sizeof (buff)) {
        ULOG_ERR ("Too long app name in read_public_key_for_app: %s\n", app_name);
        return NULL;
    }

    if ((fp = fopen (buff, "r")) == NULL) {
        ULOG_ERR ("Failed to open public key file for app (%s): %s\n",
                app_name, strerror (errno));
        return NULL;
    }

    if ((pub_key = PEM_read_RSA_PUBKEY (fp, NULL, NULL, NULL)) == NULL) {
        ULOG_ERR ("Failed to read RSA public key for app (%s):\n", app_name);
        ERR_print_errors_cb (my_error_printer, NULL);
        goto failed;
    }

failed:
    fclose (fp);
    return pub_key;
}

int hibus_verify_signature (const char* app_name,
        const unsigned char* data, unsigned int data_len,
        const unsigned char* sig, unsigned int sig_len)
{
    unsigned char md [SHA256_DIGEST_LENGTH];
    RSA *pub_key = NULL;
    int retv = 0;

    pub_key = read_public_key_for_app (app_name);  
    if (!pub_key) {
        return HIBUS_EC_CANT_LOAD;
    }

    SHA256 (data, data_len, md);

    retv = RSA_verify (NID_sha256, md, SHA256_DIGEST_LENGTH, sig, sig_len, pub_key);
    RSA_free (pub_key);
    return retv ? 1 : 0;
}

#endif /* HAVE_LIBSSL */
#endif /* BUILD_APP_AUTH */
