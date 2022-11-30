/**
 * @file
 * KidVPN configure.
 * Verification using sylixos(tm) real-time operating system
 */

/*
 * Copyright (c) 2006-2018 SylixOS Group.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 4. This code has been or is applying for intellectual property protection
 *    and can only be used with acoinfo software products.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * Author: Han.hui <hanhui@acoinfo.com>
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef PX_EOS
#define PX_EOS '\0'
#endif

/*
 * ini file key=value
 */
typedef struct ini_key_value {
    struct ini_key_value *next;
    char                 *keyword;
    char                 *value;
} ini_key_value_t;

/*
 * ini file [sector]
 */
typedef struct {
    struct ini_key_value *list;
} ini_sector_t;

/*
 * load a sector
 */
static void ini_load_sector (ini_sector_t *sec, FILE *fp)
{
#define INI_BUF_SZ        256

#define IS_WHITE(c)       (c == ' ' || c == '\t' || c == '\r' || c == '\n')
#define IS_END(c)         (c == PX_EOS)
#define SKIP_WHITE(str)   while (IS_WHITE(*str)) {  \
                              str++;  \
                          }
#define NEXT_WHITE(str)   while (!IS_WHITE(*str) && !IS_END(*str)) { \
                              str++;  \
                          }

    ini_key_value_t *pinikey;

    char buf[INI_BUF_SZ];
    char *line;
    char *end;
    char *equ;

    char *key;
    size_t key_len;
    char *value;
    size_t value_len;

    for (;;) {
        line = fgets(buf, INI_BUF_SZ, fp);
        if (!line) {
            break;
        }

        SKIP_WHITE(line);
        if (IS_END(*line) || (*line == ';') || (*line == '#')) {
            continue;
        }

        if (*line == '[') {
            break;
        }

        equ = strchr(line, '=');
        if (!equ) {
            continue;
        }
        *equ = PX_EOS;

        end  = line;
        NEXT_WHITE(end);
        *end = PX_EOS;
        key  = line;

        line = ++equ;
        SKIP_WHITE(line);
        end = line;
        NEXT_WHITE(end);
        *end  = PX_EOS;
        value = line;

        key_len   = strlen(key);
        value_len = strlen(value);

        pinikey = (ini_key_value_t *)malloc(sizeof(ini_key_value_t) + key_len + value_len + 2);
        if (!pinikey) {
            fprintf(stderr, "[KidVPN] malloc error(%d): %s\n", errno, strerror(errno));
            break;
        }

        pinikey->keyword = (char *)pinikey + sizeof(ini_key_value_t);
        strcpy(pinikey->keyword, key);

        pinikey->value = pinikey->keyword + key_len + 1;
        strcpy(pinikey->value, value);

        pinikey->next = sec->list;
        sec->list = pinikey;
    }
}

/*
 * load ini file
 */
static ini_sector_t *ini_load_file (const char *file, const char *sector)
{
    ini_sector_t *pinisec;
    FILE *fp;
    char sec[INI_BUF_SZ];
    char buf[INI_BUF_SZ];
    char *line;
    char *end;

    if (strlen(sector) > (INI_BUF_SZ - 3)) {
        return  (NULL);
    }

    pinisec = (ini_sector_t *)malloc(sizeof(ini_sector_t));
    if (!pinisec) {
        return  (NULL);
    }
    bzero(pinisec, sizeof(ini_sector_t));

    fp = fopen(file, "r");
    if (!fp) {
        free(pinisec);
        return  (NULL);
    }

    snprintf(sec, INI_BUF_SZ, "[%s]", sector);

    for (;;) {
        line = fgets(buf, INI_BUF_SZ, fp);
        if (!line) {
            goto    error;
        }

        SKIP_WHITE(line);
        if (IS_END(*line) || (*line == ';') || (*line == '#')) {
            continue;
        }

        end = line;
        NEXT_WHITE(end);
        *end = PX_EOS;

        if (strcmp(sec, line)) {
            continue;
        } else {
            break;
        }
    }

    ini_load_sector(pinisec, fp);
    fclose(fp);

    return  (pinisec);

error:
    fclose(fp);
    free(pinisec);
    return  (NULL);
}

/*
 * free sector
 */
static void ini_unload_sector (ini_sector_t *pinisec)
{
    ini_key_value_t *pinikey;

    while (pinisec->list) {
        pinikey = pinisec->list;
        pinisec->list = pinikey->next;
        free(pinikey);
    }

    free(pinisec);
}

/*
 * get a integer
 */
static int ini_get_integer (ini_sector_t *pinisec, const char *keyword, int def)
{
    ini_key_value_t *pinikey;
    int  ret = def;

    for (pinikey = pinisec->list; pinikey != NULL; pinikey = pinikey->next) {
        if (strcmp(pinikey->keyword, keyword) == 0) {
            ret = atoi(pinikey->value);
            break;
        }
    }

    return  (ret);
}

/*
 * get a string
 */
static const char *ini_get_string (ini_sector_t *pinisec, const char *keyword, const char *def)
{
    ini_key_value_t *pinikey;
    const char *ret = def;

    for (pinikey = pinisec->list; pinikey != NULL; pinikey = pinikey->next) {
        if (strcmp(pinikey->keyword, keyword) == 0) {
            ret = pinikey->value;
            break;
        }
    }

    return  (ret);
}

/*
 * config load
 */
void *kv_cfg_load (const char *file, const char *sector)
{
    ini_sector_t *pinisec;

    if (!file) {
        return  (NULL);
    }

    pinisec = ini_load_file(file, sector);
    if (!pinisec) {
        fprintf(stderr, "[KidVPN] No configure for [%s] from %s\n", sector, file);
        return  (NULL);
    }

    return  ((void *)pinisec);
}

/*
 * config unload
 */
void kv_cfg_unload (void *loadret)
{
    ini_sector_t *pinisec = (ini_sector_t *)loadret;

    if (!pinisec) {
        return;
    }

    ini_unload_sector(pinisec);
}

/*
 * config get integer
 */
int kv_cfg_getint (void *loadret, const char *keyword, int def)
{
    ini_sector_t *pinisec = (ini_sector_t *)loadret;

    if (!pinisec || !keyword) {
        return  (def);
    }

    return  (ini_get_integer(pinisec, keyword, def));
}

/*
 * config get string
 */
const char *kv_cfg_getstring (void *loadret, const char *keyword, const char *def)
{
    ini_sector_t *pinisec = (ini_sector_t *)loadret;

    if (!pinisec || !keyword) {
        return  (def);
    }

    return  (ini_get_string(pinisec, keyword, def));
}

/*
 * config get boolean
 */
int kv_cfg_getboolean (void *loadret, const char *keyword, int def)
{
    ini_sector_t *pinisec = (ini_sector_t *)loadret;
    char *str;

    if (!pinisec || !keyword) {
        return  (def);
    }

    str = (char *)ini_get_string(pinisec, keyword, def ? "true" : "false");
    if (strcasecmp(str, "true") == 0 || strcasecmp(str, "yes") == 0) {
        return  (1);
    } else {
        return  (0);
    }
}

/*
 * end
 */
