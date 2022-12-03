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

/* KidVPN CBC enable */
extern int kv_cbc_en;

/* KidVPN exit flag */
#if KV_VOLUNTARILY_QUIT
static int serv_exit = 0;
#endif

/* KidVPN server fd */
static int serv_fd = -1;

/* KidVPN virtual net device fd */
static int vnd_fd = -1;

/* KidVPN virtual net MTU */
static int vnd_mtu = KV_VND_DEF_MTU;

/* KidVPN server addr */
static struct sockaddr_in serv_addr;

/* KidVPN server aes key */
#ifdef USE_OPENSSL
static AES_KEY ase_enc, ase_dec;
#else /* USE_OPENSSL */
static mbedtls_aes_context ase_enc, ase_dec;
#endif /* !USE_OPENSSL */

/* KidVPN server mac */
static UINT8 serv_hwaddr[ETH_ALEN];

/* KidVPN hello thread handle */
static pthread_t t_hello;

/* KidVPN client node list */
static struct kv_cli_node *cli_header[KV_CLI_HASH_SIZE];

/* KidVPN server lock */
static pthread_mutex_t serv_mutex = PTHREAD_MUTEX_INITIALIZER;

#define KV_SERV_LOCK()      pthread_mutex_lock(&serv_mutex)
#define KV_SERV_UNLOCK()    pthread_mutex_unlock(&serv_mutex)

/* KidVPN server send packet */
struct kv_welcome_hdr welcome_hdr __attribute__((aligned(KV_PACK_ALIGN))); /* must aligned */
struct kv_crespond_hdr crespond_hdr __attribute__((aligned(KV_PACK_ALIGN)));
struct kv_err_hdr err_hdr __attribute__((aligned(KV_PACK_ALIGN)));

/*
 * KidVPN init packet header
 */
static void kv_serv_init_hdr (void)
{
    int i;

    /* init welcome packet */
    welcome_hdr.cmd     = KV_CMD_WELCOME;
    welcome_hdr.cmd_len = KV_WELCOME_LEN;
    welcome_hdr.magic   = KV_CMD_MAGIC;

    for (i = 0; i < ETH_ALEN; i++) {
        welcome_hdr.hwaddr[i] = serv_hwaddr[i];
    }

    /* init client query respend packet */
    crespond_hdr.cmd     = KV_CMD_CRESPOND;
    crespond_hdr.cmd_len = KV_CRESPOND_LEN;
    crespond_hdr.magic   = KV_CMD_MAGIC;

    /* init error packet */
    err_hdr.cmd     = KV_CMD_ERR;
    err_hdr.cmd_len = KV_ERR_LEN;
    err_hdr.magic   = KV_CMD_MAGIC;
}

/*
 * KidVPN server hello thread
 */
static int kv_serv_loop (void)
{
#if KV_VOLUNTARILY_QUIT
    int sigfd;
    struct signalfd_siginfo fdsi;
#endif

    int i, aes_len, width, to_me;
    ssize_t num;
    UINT32 snum = 0;
    struct sockaddr_in addr_in;
    struct kv_cli_node *cli, *dest;
    socklen_t slen = sizeof(struct sockaddr_in);
    fd_set fdset;

    UINT32 packet_buf_en[(KV_VND_FRAME_BSIZE >> 2) + 1]; /* need 4 bytes aligned */
    UINT32 packet_buf_in[(KV_VND_FRAME_BSIZE >> 2) + 1];

    UINT8 *packet_en = (UINT8 *)packet_buf_en; /* encrypt packet */
    UINT8 *packet_in = (UINT8 *)packet_buf_in; /* decrypt packet */

    struct kv_input_hdr *ihdr = (struct kv_input_hdr *)packet_in;

    kv_serv_init_hdr();

    FD_ZERO(&fdset);
    width = (serv_fd > vnd_fd) ? (serv_fd + 1) : (vnd_fd + 1);

#if KV_VOLUNTARILY_QUIT
    sigfd = kv_lib_signalfd();
    if (sigfd < 0) {
        return  (-1);
    } else if (sigfd >= width) {
        width = sigfd + 1;
    }
#endif /* KV_VOLUNTARILY_QUIT */

    printf("[KidVPN] Server working.\n");

    for (;;) {
        FD_SET(serv_fd, &fdset);
        FD_SET(vnd_fd, &fdset);

#if KV_VOLUNTARILY_QUIT
        FD_SET(sigfd, &fdset);
#endif /* KV_VOLUNTARILY_QUIT */

        if (select(width, &fdset, NULL, NULL, NULL) <= 0) { /* wait for read */
            break; /* an error occur, exit! */
        }

#if KV_VOLUNTARILY_QUIT
        if (FD_ISSET(sigfd, &fdset)) { /* The specified signal arrives */
            num = read(sigfd, &fdsi, sizeof(struct signalfd_siginfo));
            if (num >= sizeof(struct signalfd_siginfo)) {
                if (fdsi.ssi_signo == SIGUSR1) {
                    kv_lib_update_iv(NULL);

                } else if (fdsi.ssi_signo == SIGTERM) {
                    serv_exit = 1;
                    pthread_kill(t_hello, SIGUSR1);
                    break;
                }
            }
        }
#endif /* KV_VOLUNTARILY_QUIT */

        if (FD_ISSET(serv_fd, &fdset)) {
            num = recvfrom(serv_fd, packet_en, KV_VND_FRAME_BSIZE, 0,
                           (struct sockaddr *)&addr_in, &slen);
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Socket recvfrom() error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (num < ETH_ZLEN) { /* control packet */
                kv_lib_decode(packet_in, packet_en, (int)num, &aes_len, &ase_dec); /* decode */

                if (ihdr->cmd == KV_CMD_HELLO) { /* hello packet */
                    struct kv_hello_hdr *hhdr = (struct kv_hello_hdr *)packet_in;

                    if ((hhdr->cmd_len == KV_HELLO_LEN) &&
                        (hhdr->magic   == KV_CMD_MAGIC)) {
                        UINT16 mtu = ntohs(hhdr->mtu);

                        if (mtu != vnd_mtu) { /* MTU not fixed */
                            err_hdr.err  = htons(KV_ERR_MTU);
                            err_hdr.code = htons(vnd_mtu);
                            printf("[KidVPN] Client error: KV_ERR_MTU %d (server: %d)\n", mtu, vnd_mtu);

                            kv_lib_encode(packet_en, (UINT8 *)&err_hdr, KV_ERR_LEN, &aes_len, &ase_enc);

                            if (sendto(serv_fd, packet_en, aes_len, 0,
                                       (struct sockaddr *)&addr_in, slen) != aes_len) { /* send server welcome */
                                fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                                break; /* an error occur, exit! */
                            }

                        } else {
                            KV_SERV_LOCK();
                            cli = kv_lib_cli_find(hhdr->hwaddr, cli_header);
                            if (cli) {
                                if (!kv_lib_addr_is_same(&cli->addr, &addr_in)) {
                                    cli->addr = addr_in; /* save new address */
                                    printf("[KidVPN] Client changed: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                                           inet_ntoa(cli->addr.sin_addr), cli->hwaddr[0], cli->hwaddr[1],
                                           cli->hwaddr[2], cli->hwaddr[3], cli->hwaddr[4], cli->hwaddr[5]);
                                }
                                cli->alive = KV_CLI_HELLO_TIMEOUT; /* refresh client alive */

                            } else {
                                cli = (struct kv_cli_node *)malloc(sizeof(struct kv_cli_node)); /* new client */
                                if (cli) {
                                    cli->alive = KV_CLI_HELLO_TIMEOUT;
                                    cli->addr = addr_in;
                                    memcpy(cli->hwaddr, hhdr->hwaddr, ETH_ALEN); /* set client mac */
                                    kv_lib_cli_add(cli, cli_header); /* add to client list */
                                    printf("[KidVPN] Client add: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                                           inet_ntoa(cli->addr.sin_addr), cli->hwaddr[0], cli->hwaddr[1],
                                           cli->hwaddr[2], cli->hwaddr[3], cli->hwaddr[4], cli->hwaddr[5]);
                                }
                            }
                            KV_SERV_UNLOCK();

                            if (cli) {
                                /* respond client keep alive */
                                snum++;
                                welcome_hdr.snum = htonl(snum);

                                kv_lib_encode(packet_en, (UINT8 *)&welcome_hdr, KV_WELCOME_LEN, &aes_len, &ase_enc);

                                if (sendto(serv_fd, packet_en, aes_len, 0,
                                           (struct sockaddr *)&addr_in, slen) != aes_len) { /* send server welcome */
                                    fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                                    break; /* an error occur, exit! */
                                }
                            }
                        }
                    }

                } else if (ihdr->cmd == KV_CMD_CQUERY) { /* client query packet */
                    struct kv_cquery_hdr *cqhdr = (struct kv_cquery_hdr *)packet_in;

                    if ((cqhdr->cmd_len == KV_CQUERY_LEN) &&
                        (cqhdr->magic   == KV_CMD_MAGIC)) {
                        KV_SERV_LOCK();
                        cli = kv_lib_cli_find(cqhdr->hwaddr, cli_header);
                        if (cli) {
                            memcpy(crespond_hdr.hwaddr, cli->hwaddr, ETH_ALEN);
                            crespond_hdr.cliaddr = cli->addr.sin_addr.s_addr;
                            crespond_hdr.cliport = cli->addr.sin_port;
                        }
                        KV_SERV_UNLOCK();

                        if (cli) {
                            kv_lib_encode(packet_en, (UINT8 *)&crespond_hdr, KV_CRESPOND_LEN, &aes_len, &ase_enc);

                            if (sendto(serv_fd, packet_en, aes_len, 0,
                                       (struct sockaddr *)&addr_in, slen) != aes_len) { /* send server welcome */
                                fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                                break; /* an error occur, exit! */
                            }
                        }
                    }
                }

            } else { /* normal packet */
                to_me = 0;

                /* Only decode 16 byte first */
                kv_lib_decode(packet_in, packet_en, KV_AES_BLK_LEN, &aes_len, &ase_dec); /* decode */

                KV_SERV_LOCK();
                cli = kv_lib_cli_find(KV_PKT_MAC_SRC(packet_in), cli_header); /* sender client must alive */
                if (cli && kv_lib_addr_is_same(&cli->addr, &addr_in)) { /* address compare */
                    if (KV_PKY_MAC_BMC(packet_in)) { /* broadcast? */
                        for (i = 0; i < KV_CLI_HASH_SIZE; i++) {
                            for (dest = cli_header[i]; dest != NULL; dest = dest->next) {
                                if (dest != cli) {
                                    sendto(serv_fd, packet_en, num, 0,
                                           (struct sockaddr *)&dest->addr, slen); /* forward to all client */
                                }
                            }
                        }
                        to_me = 1;

                    } else { /* uncast */
                        dest = kv_lib_cli_find(KV_PKT_MAC_DEST(packet_in), cli_header);
                        if (dest) {
                            sendto(serv_fd, packet_en, num, 0,
                                   (struct sockaddr *)&dest->addr, slen); /* forward to client */

                        } else if (!memcmp(KV_PKT_MAC_DEST(packet_in), serv_hwaddr, ETH_ALEN)) {
                            to_me = 1;
                        }
                    }
                }
                KV_SERV_UNLOCK();

                if (to_me) {
                    if (kv_cbc_en) {
                        kv_lib_decode(packet_in, packet_en, num, &aes_len, &ase_dec); /* decode all */
                    } else {
                        kv_lib_decode(&packet_in[KV_AES_BLK_LEN], &packet_en[KV_AES_BLK_LEN],
                                      (int)num - KV_AES_BLK_LEN, &aes_len, &ase_dec); /* decode remaining */
                    }

                    if (num > KV_VND_FRAME_LEN(vnd_mtu)) {
                        num = KV_VND_FRAME_LEN(vnd_mtu); /* Cut tail (The tail is AES 16Bytes align add) */
                    }
                    write(vnd_fd, packet_in, num); /* virtual net device recv */
                }
            }
        }

        if (FD_ISSET(vnd_fd, &fdset)) { /* vitural net device send a message to other */
            num = read(vnd_fd, packet_in, KV_VND_FRAME_BSIZE);
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Read virtual net device error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (num < ETH_ZLEN) {
                num = ETH_ZLEN; /* ethernet shortest length */
            }

            kv_lib_encode(packet_en, packet_in, (int)num, &aes_len, &ase_enc);

            KV_SERV_LOCK();
            if (KV_PKY_MAC_BMC(packet_in)) { /* broadcast? */
                for (i = 0; i < KV_CLI_HASH_SIZE; i++) {
                    for (dest = cli_header[i]; dest != NULL; dest = dest->next) {
                        sendto(serv_fd, packet_en, aes_len, 0,
                               (struct sockaddr *)&dest->addr, slen); /* NOTICE: send a 'aes_len' packet to other */
                    }
                }

            } else { /* uncast */
                dest = kv_lib_cli_find(KV_PKT_MAC_DEST(packet_in), cli_header);
                if (dest) {
                    sendto(serv_fd, packet_en, aes_len, 0,
                           (struct sockaddr *)&dest->addr, slen); /* NOTICE: send a 'aes_len' packet to other */
                }
            }
            KV_SERV_UNLOCK();
        }
    }

    return  (0); /* exit! */
}

/*
 * KidVPN server hello thread
 */
static void kv_serv_hello (void)
{
    int i;
    struct kv_cli_node *cli, *del;

    for (;;) {
        KV_SERV_LOCK();
        for (i = 0; i < KV_CLI_HASH_SIZE; i++) {
            cli = cli_header[i];
            while (cli) {
                if (cli->alive >= KV_CLI_HELLO_PERIOD) {
                    cli->alive -= KV_CLI_HELLO_PERIOD;
                } else {
                    cli->alive = 0;
                }

                if (cli->alive <= 0) { /* client dead! */
                    del = cli;
                    cli = cli->next;
                    kv_lib_cli_delete(del, cli_header); /* delete client from list */
                    printf("[KidVPN] Client lost: %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                           inet_ntoa(del->addr.sin_addr), del->hwaddr[0], del->hwaddr[1],
                           del->hwaddr[2], del->hwaddr[3], del->hwaddr[4], del->hwaddr[5]);
                    free(del);

                } else {
                    cli = cli->next;
                }
            }
        }
        KV_SERV_UNLOCK();

#if KV_VOLUNTARILY_QUIT
        if (serv_exit) {
            break;
        }
#endif /* KV_VOLUNTARILY_QUIT */

        sleep(KV_CLI_HELLO_PERIOD);
    }
}

/*
 * start KidVPN server
 */
int kv_serv_start (int vnd_id, const char *tap_name, const unsigned char *key, unsigned int keybits,
                   const char *local, unsigned int port, int mtu)
{
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

    if (!inet_aton(local, &serv_addr.sin_addr)) {
        fprintf(stderr, "[KidVPN] Local IP error.\n");
        return  (-1);
    }

    vnd_mtu = mtu;
    if (kv_lib_init(vnd_id, tap_name, &serv_fd, &vnd_fd, serv_hwaddr, mtu)) { /* init server */
        return  (-1);
    }

    if (bind(serv_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in))) { /* bind local port */
        fprintf(stderr, "[KidVPN] Socket bind() call fail(%d): %s!\n", errno, strerror(errno));
        kv_lib_deinit(serv_fd, vnd_fd);
        return  (-1);
    }

    if (pthread_create(&t_hello, NULL, (void *(*)(void *))kv_serv_hello, NULL)) {
        fprintf(stderr, "[KidVPN] Can not create hello thread error(%d): %s.\n", errno, strerror(errno));
        kv_lib_deinit(serv_fd, vnd_fd);
        return  (-1);
    }

    pthread_detach(t_hello);
    pthread_setname_np(t_hello, "kvs_hello");

    if (kv_serv_loop()) { /* server main loop */
        kv_lib_deinit(serv_fd, vnd_fd);
        return  (-1);
    }

    return  (0);
}

/*
 * end
 */
