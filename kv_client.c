/**
 * @file
 * KidVPN client.
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
#include "kv_serv.h"

/* KidVPN client fd */
static int cli_fd = -1;

/* KidVPN virtual net device fd */
static int vnd_fd = -1;

/* KidVPN virtual net MTU */
static int vnd_mtu = KV_VND_DEF_MTU;

/* KidVPN virtual net device hwaddr */
static struct kv_hello_hdr hello_hdr;

/* KidVPN server addr */
static struct sockaddr_in serv_addr;

/* KidVPN client aes key */
#ifdef USE_OPENSSL
static AES_KEY ase_enc, ase_dec;
#else /* USE_OPENSSL */
static mbedtls_aes_context ase_enc, ase_dec;
#endif /* !USE_OPENSSL */

/* KidVPN client alive */
static int cli_alive;

/* KidVPN mutex */
static pthread_mutex_t cli_mutex = PTHREAD_MUTEX_INITIALIZER;

#define KV_CLI_LOCK()      pthread_mutex_lock(&cli_mutex)
#define KV_CLI_UNLOCK()    pthread_mutex_unlock(&cli_mutex)

/* KidVPN client loop */
static int kv_cli_loop (void)
{
    int width, aes_len;
    ssize_t num;
    struct sockaddr_in addr_in;
    socklen_t slen = sizeof(struct sockaddr_in);
    fd_set fdset;

    UINT8  packet_en[KV_VND_FRAME_MAX + 16]; /* encrypt packet */
    UINT8  packet_in[KV_VND_FRAME_MAX + 16]; /* decrypt packet */

    printf("[KidVPN] Client working.\n");

    FD_ZERO(&fdset);
    width = (cli_fd > vnd_fd) ? (cli_fd + 1) : (vnd_fd + 1);

    for (;;) {
        FD_SET(cli_fd, &fdset);
        FD_SET(vnd_fd, &fdset);

        if (select(width, &fdset, NULL, NULL, NULL) <= 0) { /* wait for read */
            break; /* an error occur, exit! */
        }

        if (FD_ISSET(cli_fd, &fdset)) { /* server send a message to me */
            num = recvfrom(cli_fd, packet_en, sizeof(packet_en), 0,
                           (struct sockaddr *)&addr_in, &slen);
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Socket recvfrom() error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (addr_in.sin_addr.s_addr != serv_addr.sin_addr.s_addr) { /* not server paceket, drop! */
                continue;
            }

            kv_lib_decode(packet_in, packet_en, (int)num, &aes_len, &ase_dec); /* decode */

            if (num < ETH_ZLEN) { /* control packet */
                if (packet_in[0] == KV_CMD_WELCOME) {
                    struct kv_welcome_hdr *whdr = (struct kv_welcome_hdr *)packet_in;

                    if ((whdr->cmd_len  == KV_WELCOME_LEN) &&
                        (whdr->magic[0] == KV_CMD_MAGIC0) &&
                        (whdr->magic[1] == KV_CMD_MAGIC1) &&
                        (whdr->magic[2] == KV_CMD_MAGIC2) &&
                        (whdr->magic[3] == KV_CMD_MAGIC3)) {
                        KV_CLI_LOCK();
                        if (cli_alive == 0) {
                            printf("[KidVPN] Server connected %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                                   inet_ntoa(addr_in.sin_addr), whdr->hwaddr[0], whdr->hwaddr[1],
                                   whdr->hwaddr[2], whdr->hwaddr[3], whdr->hwaddr[4], whdr->hwaddr[5]);
                        }
                        cli_alive = KV_CLI_HELLO_TIMEOUT; /* keep alive */
                        KV_CLI_UNLOCK();
                    }

                } else if (packet_in[0] == KV_CMD_ERR) {
                    struct kv_err_hdr *ehdr = (struct kv_err_hdr *)packet_in;

                    if ((ehdr->cmd_len  == KV_ERR_LEN) &&
                        (ehdr->magic[0] == KV_CMD_MAGIC0) &&
                        (ehdr->magic[1] == KV_CMD_MAGIC1) &&
                        (ehdr->magic[2] == KV_CMD_MAGIC2) &&
                        (ehdr->magic[3] == KV_CMD_MAGIC3)) {
                        printf("[KidVPN] Connected error: %d (%d)\n", ntohs(ehdr->err), ntohs(ehdr->code));
                    }
                }

            } else {
                if (num > KV_VND_FRAME_LEN(vnd_mtu)) {
                    num = KV_VND_FRAME_LEN(vnd_mtu); /* Cut tail (The tail is AES 16Bytes align add) */
                }
                write(vnd_fd, packet_in, num); /* virtual net device recv */
            }
        }

        if (FD_ISSET(vnd_fd, &fdset)) { /* vitural net device send a message to server */
            num = read(vnd_fd, packet_in, sizeof(packet_in));
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Read virtual net device error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (num < ETH_ZLEN) {
                num = ETH_ZLEN; /* ethernet shortest length */
            }

            kv_lib_encode(packet_en, packet_in, (int)num, &aes_len, &ase_enc);

            write(cli_fd, packet_en, aes_len); /* NOTICE: send a 'aes_len' packet to server */
        }
    }

    return  (-1); /* an error occur, exit! */
}

/* KidVPN client hello thread */
static void kv_cli_hello (void)
{
    UINT32 snum = 0;
    int con_cnt = 0;
    int aes_len;
    UINT8 packet_en[32]; /* encrypt packet */

    hello_hdr.cmd      = KV_CMD_HELLO;
    hello_hdr.cmd_len  = KV_HELLO_LEN;
    hello_hdr.magic[0] = KV_CMD_MAGIC0;
    hello_hdr.magic[1] = KV_CMD_MAGIC1;
    hello_hdr.magic[2] = KV_CMD_MAGIC2;
    hello_hdr.magic[3] = KV_CMD_MAGIC3;
    hello_hdr.mtu      = htons(vnd_mtu);

    for (;;) {
        KV_CLI_LOCK();
        if (cli_alive) {
            if (cli_alive > KV_CLI_HELLO_PERIOD) {
                cli_alive -= KV_CLI_HELLO_PERIOD;

            } else {
                cli_alive = 0;
                con_cnt = 0;
                printf("[KidVPN] Server lost, re-connecting...!\n");
            }

        } else {
            con_cnt++;
            printf("[KidVPN] Try connect server <%d times>...!\n", con_cnt);
        }
        KV_CLI_UNLOCK();

        snum++;
        hello_hdr.snum = htonl(snum);

        kv_lib_encode(packet_en, (UINT8 *)&hello_hdr, KV_HELLO_LEN, &aes_len, &ase_enc);

        if (write(cli_fd, packet_en, aes_len) != aes_len) { /* send client hello period */
            fprintf(stderr, "[KidVPN] Socket write() error(%d): %s!\n", errno, strerror(errno));
        }

        sleep(KV_CLI_HELLO_PERIOD);
    }
}

/* start KidVPN client */
int kv_cli_start (int vnd_id, const char *tap_name, const unsigned char *key, unsigned int keybits,
                  const char *server, unsigned int port, int mtu)
{
    struct addrinfo hints;
    struct addrinfo *phints;
    pthread_t t_hello;

    if (!key || !server) {
        return  (-1);
    }

    if ((keybits != 128) && (keybits != 192) && (keybits != 256)) {
        fprintf(stderr, "[KidVPN] AES key bits error!\n");
        return  (-1);
    }

#ifdef USE_OPENSSL
    if (AES_set_encrypt_key(key, keybits, &ase_enc)) {
        fprintf(stderr, "[KidVPN] Set AES encode key fail!\n");
        return  (-1);
    }

    if (AES_set_decrypt_key(key, keybits, &ase_dec)) {
        fprintf(stderr, "[KidVPN] Set AES decode key fail!\n");
        return  (-1);
    }

#else /* USE_OPENSSL */
    if (mbedtls_aes_setkey_enc(&ase_enc, key, keybits)) {
        fprintf(stderr, "[KidVPN] Set AES encode key fail!\n");
        return  (-1);
    }

    if (mbedtls_aes_setkey_dec(&ase_dec, key, keybits)) {
        fprintf(stderr, "[KidVPN] Set AES decode key fail!\n");
        return  (-1);
    }
#endif /* !USE_OPENSSL */

#ifdef SYLIXOS
    serv_addr.sin_len = sizeof(struct sockaddr_in);
#endif /* SYLIXOS */

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if (!inet_aton(server, &serv_addr.sin_addr)) {
        printf("[KidVPN] Execute a DNS query...\n");

        hints.ai_family = AF_INET;
        hints.ai_flags  = AI_CANONNAME;
        getaddrinfo(server, NULL, &hints, &phints);
        if (phints == NULL) {
            fprintf(stderr, "[KidVPN] Request could not find host %s ."
                            "Please check the name and try again.\n\n", server);
            return  (-1);

        } else {
            if (phints->ai_addr->sa_family == AF_INET) {
                serv_addr.sin_addr = ((struct sockaddr_in *)(phints->ai_addr))->sin_addr;
                freeaddrinfo(phints);

            } else {
                freeaddrinfo(phints);
                fprintf(stderr, "[KidVPN] Only support AF_INET domain!\n");
                return  (-1);
            }
        }
    }

    vnd_mtu = mtu;
    if (kv_lib_init(vnd_id, tap_name, &cli_fd, &vnd_fd, hello_hdr.hwaddr, mtu)) { /* init client */
        return  (-1);
    }

    if (connect(cli_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in))) { /* connect to server */
        fprintf(stderr, "[KidVPN] Client connect() call fail(%d): %s!\n", errno, strerror(errno));
        kv_lib_deinit(cli_fd, vnd_fd);
        return  (-1);
    }

    if (pthread_create(&t_hello, NULL, (void *(*)(void *))kv_cli_hello, NULL)) {
        fprintf(stderr, "[KidVPN] Can not create hello thread error(%d): %s.\n", errno, strerror(errno));
        kv_lib_deinit(cli_fd, vnd_fd);
        return  (-1);
    }

    pthread_setname_np(t_hello, "kvc_hello");

    if (kv_cli_loop()) { /* client main loop */
        kv_lib_deinit(cli_fd, vnd_fd);
        return  (-1);
    }

    return  (0);
}

/*
 * end
 */
