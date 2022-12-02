/**
 * @file
 * KidVPN main.
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

#include "kv_lib.h"
#include "kv_cfg.h"
#include "kv_serv.h"
#include "kv_client.h"

/* version */
#define KV_VERSION  "1.0.0"

/*
 * key code change function
 */
static int key_code_change (unsigned char *key, unsigned int *keybits, const char *keyascii)
{
    int  ascii_len = strlen(keyascii);
    int  i, loop;
    unsigned char tmp;

    if ((ascii_len >= 32) && (ascii_len <= 48)) {
        *keybits = 128;
        loop = 16;

    } else if ((ascii_len >= 48) && (ascii_len <= 64)) {
        *keybits = 192;
        loop = 24;

    } else if (ascii_len >= 64) {
        *keybits = 256;
        loop = 32;

    } else {
        fprintf(stderr, "[KidVPN] Key length error.\n");
        return  (-1);
    }

    for (i = 0; i < loop; i++) {
        if ((keyascii[0] >= '0') && (keyascii[0] <= '9')) {
            tmp = ((keyascii[0] - '0') << 4);

        } else if ((keyascii[0] >= 'a') && (keyascii[0] <= 'f')) {
            tmp = ((keyascii[0] - 'a' + 10) << 4);

        } else if ((keyascii[0] >= 'A') && (keyascii[0] <= 'F')) {
            tmp = ((keyascii[0] - 'A' + 10) << 4);

        } else {
            fprintf(stderr, "[KidVPN] Key format error.\n");
            return  (-1);
        }

        if ((keyascii[1] >= '0') && (keyascii[1] <= '9')) {
            tmp |= (keyascii[1] - '0');

        } else if ((keyascii[1] >= 'a') && (keyascii[1] <= 'f')) {
            tmp |= (keyascii[1] - 'a' + 10);

        } else if ((keyascii[1] >= 'A') && (keyascii[1] <= 'F')) {
            tmp |= (keyascii[1] - 'A' + 10);

        } else {
            fprintf(stderr, "[KidVPN] Key format error.\n");
            return  (-1);
        }

        *key = tmp;
        key++;
        keyascii += 2;
    }

    return  (0);
}

/*
 * key code add password function
 */
static void key_code_xpw (unsigned char *keycode, unsigned int keybits, const char *password)
{
    int  i, loop;
    const char *p = password;

    loop = keybits / 8;

    for (i = 0; i < loop; i++) {
        keycode[i] = keycode[i] ^ *p;
        p++;
        if (*p == '\0') {
            p = password;
        }
    }
}

#if !KV_VOLUNTARILY_QUIT
/*
 * IV update sigaction
 */
static void iv_update_handle (int signo)
{
    kv_lib_update_iv(NULL);
}

/*
 * IV update sigaction init
 */
static void iv_update_handle_init (void)
{
    struct sigaction action;

    bzero(&action, sizeof(action));
    sigaddset(&action.sa_mask, SIGUSR1);
    action.sa_flags   = SA_RESTART;
    action.sa_handler = iv_update_handle;

    sigaction(SIGUSR1, &action, NULL);
}
#endif /* !KV_VOLUNTARILY_QUIT */

/*
 * main function
 */
int main (int argc, char *argv[])
{
    FILE *fkey;
    int hole_punching;
    int i, vnd_id, rand_fd, is_serv, mtu = KV_VND_DEF_MTU;
    unsigned int port;
    void *cfg;
    const char *file;
    const char *ipaddr;
    const char *mode;
    char *straddr;
    char keyascii[65];
    unsigned char keycode[32];
    unsigned int keybits;

#ifndef SYLIXOS
    const char *tap;
#endif /* !SYLIXOS */
    char *tapname = NULL;

    if (argc < 3) {
usage:
        printf("USAGE: kidvpn [config file *.ini] [sector] [password]\n"
               "       config file like this:\n"
               "           [server_0]\n"
               "           mode=server                   # Run as server mode\n"
               "           key_file=serv.key             # AES key file\n"
               "           iv_file=serv.iv               # CBC IV file (Optional default use ECB)\n"
               "           vnd_id=0                      # Virtual network device ID (For SylixOS)\n"
               "           tap_name=tap0                 # Virtual network device name (For Linux & Windows)\n"
               "           mtu=1464                      # 1280 ~ 1472 (Optional default: 1464)\n"
               "           local_ip=192.168.0.1          # Local IP address in this system\n"
               "           port=10088                    # Local port (Optional default: 10088)\n\n"
               "           [client_0]\n"
               "           mode=client                   # Run as client mode\n"
               "           key_file=cli.key              # AES key file\n"
               "           iv_file=cli.iv                # CBC IV file (Optional default use ECB)\n"
               "           vnd_id=0                      # Virtual network device ID (For SylixOS)\n"
               "           tap_name=tap0                 # Virtual network device name (For Linux & Windows)\n"
               "           mtu=1464                      # 1280 ~ 1472 must same as server (Optional default: 1464)\n"
               "           server=123.123.123.123        # KidVPN Server address\n"
               "           port=10088                    # Server port (Optional default: 10088)\n"
               "           hole_punching=0               # UDP hole punching enable (Optional default: 0)\n\n"
               "       kidvpn -genkey 128 (Generate a AES-128 key)\n"
               "       eg. kidvpn -genkey 128\n"
               "           kidvpn -genkey 192\n"
               "           kidvpn -genkey 256\n"
               "           kidvpn -genkey 192 >keyfile\n\n"
               "[KidVPN] Current Version: %s\n", KV_VERSION);
        return  (0);
    }

    if (argc == 3) {
        if (!strcmp(argv[1], "-genkey")) {
            rand_fd = open("/dev/random", O_RDONLY);
            if (rand_fd < 0) {
                fprintf(stderr, "[KidVPN] Can not open /dev/random file, error(%d): %s\n", errno, strerror(errno));
                return  (-1);
            }

            keybits = atoi(argv[2]);
            switch (keybits) {

            case 128:
                read(rand_fd, keycode, 16);
                close(rand_fd);
                break;

            case 192:
                read(rand_fd, keycode, 24);
                close(rand_fd);
                break;

            case 256:
                read(rand_fd, keycode, 32);
                close(rand_fd);
                break;

            default:
                close(rand_fd);
                fprintf(stderr, "[KidVPN] Key bits only support: 128, 192, 256\n");
                return  (-1);
            }

            for (i = 0; i < (keybits >> 3); i++) {
                printf("%02x", keycode[i]);
            }
            printf("\n");
            return  (0);

        } else {
            goto    usage;
        }

    } else if (argc == 4) {
        cfg = kv_cfg_load(argv[1], argv[2]);
        if (!cfg) {
            fprintf(stderr, "[KidVPN] Can't load configure file %s error(%d): %s\n",
                    argv[1], errno, strerror(errno));
            return  (-1);
        }

        mode = kv_cfg_getstring(cfg, "mode", NULL);
        if (!mode) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Can't found mode setting\n");
            return  (-1);
        }

        is_serv = (*mode == 's') ? 1 : 0;

        file = kv_cfg_getstring(cfg, "key_file", NULL);
        if (!file) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Can't found key file setting\n");
            return  (-1);
        }

#ifdef SYLIXOS
        vnd_id = kv_cfg_getint(cfg, "vnd_id", -1);
        if (vnd_id < 0) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Can't found virtual network device ID setting\n");
            return  (-1);
        }

#else /* SYLIXOS */
        vnd_id = -1;
        tap = kv_cfg_getstring(cfg, "tap_name", NULL);
        if (tap) {
            tapname = strdup(tap);

        } else {
            tapname = strdup(""); /* Auto create tap interface */
        }

        if (!tapname) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] strdup() error(%d): %s\n", errno, strerror(errno));
            return  (-1);
        }
#endif /* !SYLIXOS */

        mtu = kv_cfg_getint(cfg, "mtu", KV_VND_DEF_MTU);
        if ((mtu > KV_VND_MAX_MTU) || (mtu < KV_VND_MIN_MTU)) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] MTU must in %d ~ %d\n", KV_VND_MIN_MTU, KV_VND_MAX_MTU);
            return  (-1);
        }

        port = (unsigned short)kv_cfg_getint(cfg, "port", KV_SERV_PORT);
        if (!port) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Port error\n");
            return  (-1);
        }

        if (is_serv) {
            ipaddr = kv_cfg_getstring(cfg, "local_ip", NULL);
        } else {
            ipaddr = kv_cfg_getstring(cfg, "server", NULL);
        }

        if (!ipaddr) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Can't found address setting\n");
            return  (-1);
        }

        straddr = strdup(ipaddr);
        if (!straddr) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] strdup() error(%d): %s\n", errno, strerror(errno));
            return  (-1);
        }

        fkey = fopen(file, "r"); /* open key file */
        if (!fkey) {
            kv_cfg_unload(cfg);
            fprintf(stderr, "[KidVPN] Open %s error(%d): %s\n", file, errno, strerror(errno));
            return  (-1);
        }

        if (!fgets(keyascii, 65, fkey)) { /* read aes key */
            fprintf(stderr, "[KidVPN] Key file %s error(%d): %s\n", file, errno, strerror(errno));
            fclose(fkey);
            kv_cfg_unload(cfg);
            return  (-1);
        }
        fclose(fkey);

        if (key_code_change(keycode, &keybits, keyascii)) { /* get aes key */
            kv_cfg_unload(cfg);
            return  (-1);
        }

        key_code_xpw(keycode, keybits, argv[3]);

        file = kv_cfg_getstring(cfg, "iv_file", NULL);
        if (file) {
            if (kv_lib_update_iv(file)) { /* Set IV */
                kv_cfg_unload(cfg);
                return  (-1);
            }

#if !KV_VOLUNTARILY_QUIT
            iv_update_handle_init(); /* Handle Update IV signal */
#endif
        }

        hole_punching = kv_cfg_getint(cfg, "hole_punching", 0); /* UDP hole punching enable/disable */

        if (!kv_cfg_getboolean(cfg, "no_daemon", 0)) {
            daemon(1, 1); /* make this process to a daemon mode */
        }

        kv_cfg_unload(cfg);

        if (is_serv) {
            return  (kv_serv_start(vnd_id, tapname, keycode, keybits, straddr, port, mtu));
        } else {
            return  (kv_cli_start(vnd_id, tapname, keycode, keybits, straddr, port, mtu, hole_punching));
        }

    } else {
        goto    usage;
    }
}

/*
 * end
 */
