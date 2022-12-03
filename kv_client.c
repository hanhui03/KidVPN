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

/* KidVPN client hole punching */
struct kv_cli_hp {
    struct kv_cli_node cli;
    int                stat; /* hole punching state machine */
#define KV_CLI_HPSTAT_CLOSE     0
#define KV_CLI_HPSTAT_CQUERY    1
#define KV_CLI_HPSTAT_HPQUERY   2
#define KV_CLI_HPSTAT_HPRESPOND 3
};

/* KidVPN exit flag */
#if KV_VOLUNTARILY_QUIT
static int cli_exit = 0;
#endif

/* KidVPN client fd */
static int cli_fd = -1;

/* KidVPN virtual net device fd */
static int vnd_fd = -1;

/* KidVPN virtual net MTU */
static int vnd_mtu = KV_VND_DEF_MTU;

/* KidVPN hello thread handle */
static pthread_t t_hello;

/* KidVPN virtual net device hwaddr */
static struct kv_hello_hdr hello_hdr;

/* KidVPN server addr */
static struct sockaddr_in serv_addr;

/* KidVPN server mac */
static UINT8 serv_hwaddr[ETH_ALEN];

/* KidVPN client aes key */
#ifdef USE_OPENSSL
static AES_KEY ase_enc, ase_dec;
#else /* USE_OPENSSL */
static mbedtls_aes_context ase_enc, ase_dec;
#endif /* !USE_OPENSSL */

/* KidVPN client alive */
static int cli_alive;

/* KidVPN client node list */
static struct kv_cli_node *cli_header[KV_CLI_HASH_SIZE];

/* KidVPN mutex */
static pthread_mutex_t cli_mutex = PTHREAD_MUTEX_INITIALIZER;

#define KV_CLI_LOCK()      pthread_mutex_lock(&cli_mutex)
#define KV_CLI_UNLOCK()    pthread_mutex_unlock(&cli_mutex)

/* KidVPN server send packet */
struct kv_cquery_hdr cquery_hdr __attribute__((aligned(KV_PACK_ALIGN))); /* must aligned */
struct kv_hpquery_hdr hpquery_hdr __attribute__((aligned(KV_PACK_ALIGN)));
struct kv_hprespond_hdr hprespond_hdr __attribute__((aligned(KV_PACK_ALIGN)));

/*
 * KidVPN init packet header
 */
static void kv_cli_init_hdr (void)
{
    /* init cquery packet */
    cquery_hdr.cmd     = KV_CMD_CQUERY;
    cquery_hdr.cmd_len = KV_CQUERY_LEN;
    cquery_hdr.magic   = KV_CMD_MAGIC;

    /* init hpquery packet */
    hpquery_hdr.cmd     = KV_CMD_HPQUERY;
    hpquery_hdr.cmd_len = KV_HPQUERY_LEN;
    hpquery_hdr.magic   = KV_CMD_MAGIC;

    /* init hprespond packet */
    hprespond_hdr.cmd     = KV_CMD_HPRESPOND;
    hprespond_hdr.cmd_len = KV_HPRESPOND_LEN;
    hprespond_hdr.magic   = KV_CMD_MAGIC;

    memcpy(hprespond_hdr.hwaddr, hello_hdr.hwaddr, ETH_ALEN);
}

/*
 * KidVPN client loop
 */
static int kv_cli_loop (int  hole_punching)
{
#if KV_VOLUNTARILY_QUIT
    int sigfd;
    struct signalfd_siginfo fdsi;
#endif

    int width, aes_len, to_me, cq_req, hp_req, to_serv;
    int mtu;
    ssize_t num;
    struct sockaddr_in addr_in;
    struct kv_cli_node *cli;
    struct kv_cli_hp *clihp;
    socklen_t slen = sizeof(struct sockaddr_in);
    fd_set fdset;

    UINT32 packet_buf_en[(KV_VND_FRAME_BSIZE >> 2) + 1]; /* need 4 bytes aligned */
    UINT32 packet_buf_in[(KV_VND_FRAME_BSIZE >> 2) + 1];

    UINT8 *packet_en = (UINT8 *)packet_buf_en; /* encrypt packet */
    UINT8 *packet_in = (UINT8 *)packet_buf_in; /* decrypt packet */

    struct kv_input_hdr *ihdr = (struct kv_input_hdr *)packet_in;

    kv_cli_init_hdr();

    FD_ZERO(&fdset);
    width = (cli_fd > vnd_fd) ? (cli_fd + 1) : (vnd_fd + 1);

#if KV_VOLUNTARILY_QUIT
    sigfd = kv_lib_signalfd();
    if (sigfd < 0) {
        return  (-1);
    } else if (sigfd >= width) {
        width = sigfd + 1;
    }
#endif /* KV_VOLUNTARILY_QUIT */

    printf("[KidVPN] Client working.\n");

    for (;;) {
        FD_SET(cli_fd, &fdset);
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
                    cli_exit = 1;
                    pthread_kill(t_hello, SIGUSR1);
                    break;
                }
            }
        }
#endif /* KV_VOLUNTARILY_QUIT */

        if (FD_ISSET(cli_fd, &fdset)) { /* server send a message to me */
            num = recvfrom(cli_fd, packet_en, KV_VND_FRAME_BSIZE, 0,
                           (struct sockaddr *)&addr_in, &slen);
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Socket recvfrom() error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (!hole_punching) { /* no hole punching support */
                if (addr_in.sin_addr.s_addr != serv_addr.sin_addr.s_addr) { /* not server paceket, drop! */
                    continue;
                }
            }

            kv_lib_decode(packet_in, packet_en, (int)num, &aes_len, &ase_dec); /* decode */

            if (num < ETH_ZLEN) { /* control packet */
                if (ihdr->cmd == KV_CMD_WELCOME) { /* server welcome */
                    struct kv_welcome_hdr *whdr = (struct kv_welcome_hdr *)packet_in;

                    if ((whdr->cmd_len == KV_WELCOME_LEN) &&
                        (whdr->magic   == KV_CMD_MAGIC)) {
                        KV_CLI_LOCK();
                        if (cli_alive == 0) {
                            printf("[KidVPN] Server connected %s [%02x:%02x:%02x:%02x:%02x:%02x]\n",
                                   inet_ntoa(addr_in.sin_addr), whdr->hwaddr[0], whdr->hwaddr[1],
                                   whdr->hwaddr[2], whdr->hwaddr[3], whdr->hwaddr[4], whdr->hwaddr[5]);
                        }
                        cli_alive = KV_CLI_HELLO_TIMEOUT; /* keep alive */
                        KV_CLI_UNLOCK();
                        memcpy(serv_hwaddr, whdr->hwaddr, ETH_ALEN); /* save server hwaddr */
                    }

                } else if (ihdr->cmd == KV_CMD_ERR) { /* connect error */
                    struct kv_err_hdr *ehdr = (struct kv_err_hdr *)packet_in;

                    if ((ehdr->cmd_len == KV_ERR_LEN) &&
                        (ehdr->magic   == KV_CMD_MAGIC)) {
                        if (ntohs(ehdr->err) == KV_ERR_MTU) { /* server client mtu not same */
                            mtu = ntohs(ehdr->code);
                            if (kv_lib_setmtu(cli_fd, mtu)) {
                                fprintf(stderr, "[KidVPN] Set virtual net interface MTU error!\n");
                                break; /* an error occur, exit! */
                            }
                            KV_CLI_LOCK();
                            vnd_mtu = mtu; /* save new MTU */
                            KV_CLI_UNLOCK();

                        } else {
                            printf("[KidVPN] Connected error: %d (%d)\n", ntohs(ehdr->err), ntohs(ehdr->code));
                        }
                    }

                } else if ((ihdr->cmd == KV_CMD_CRESPOND) && hole_punching) { /* server to client respond client query */
                    struct kv_crespond_hdr *crpdhdr = (struct kv_crespond_hdr *)packet_in;

                    if ((crpdhdr->cmd_len == KV_CRESPOND_LEN) &&
                        (crpdhdr->magic   == KV_CMD_MAGIC)) {
                        hp_req = 0;

                        KV_CLI_LOCK();
                        cli = kv_lib_cli_find(crpdhdr->hwaddr, cli_header);
                        if (cli) {
                            clihp = (struct kv_cli_hp *)cli;
                            if (clihp->stat == KV_CLI_HPSTAT_CQUERY) { /* client query state */
                                cli->addr.sin_family = AF_INET;
#ifdef SYLIXOS
                                cli->addr.sin_len = sizeof(struct sockaddr_in);
#endif /* SYLIXOS */
                                cli->addr.sin_addr.s_addr = crpdhdr->cliaddr;
                                cli->addr.sin_port = crpdhdr->cliport;
                                cli->alive = KV_CLI_HOLE_PUNCHING_ALIVE;

                                clihp->stat = KV_CLI_HPSTAT_HPQUERY;
                                memcpy(hpquery_hdr.hwaddr, cli->hwaddr, ETH_ALEN);
                                hp_req = 1; /* try hole punching */
                            }
                        }
                        KV_CLI_UNLOCK();

                        if (hp_req) {
                            kv_lib_encode(packet_en, (UINT8 *)&hpquery_hdr, KV_HPQUERY_LEN, &aes_len, &ase_enc);

                            /* We use 'cli' without lock, because there no delete in client list */
                            if (sendto(cli_fd, packet_en, aes_len, 0,
                                       (struct sockaddr *)&cli->addr, slen) != aes_len) { /* send to client try hole punching */
                                fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                                break; /* an error occur, exit! */
                            }
                        }
                    }

                } else if ((ihdr->cmd == KV_CMD_HPQUERY) && hole_punching) { /* client hole punching query */
                    struct kv_hpquery_hdr *hpqueryhdr = (struct kv_hpquery_hdr *)packet_in;

                    if ((hpqueryhdr->cmd_len == KV_HPQUERY_LEN) &&
                        (hpqueryhdr->magic   == KV_CMD_MAGIC)) {
                        if (!memcmp(hpqueryhdr->hwaddr, hprespond_hdr.hwaddr, ETH_ALEN)) { /* create hole punching with me? */
                            kv_lib_encode(packet_en, (UINT8 *)&hprespond_hdr, KV_HPRESPOND_LEN, &aes_len, &ase_enc);

                            if (sendto(cli_fd, packet_en, aes_len, 0,
                                       (struct sockaddr *)&addr_in, slen) != aes_len) { /* send to client */
                                fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                                break; /* an error occur, exit! */
                            }
                        }
                    }

                } else if ((ihdr->cmd == KV_CMD_HPRESPOND) && hole_punching) { /* client hole punching respond */
                    struct kv_hprespond_hdr *hprpdhdr = (struct kv_hprespond_hdr *)packet_in;

                    if ((hprpdhdr->cmd_len == KV_HPRESPOND_LEN) &&
                        (hprpdhdr->magic   == KV_CMD_MAGIC)) {
                        KV_CLI_LOCK();
                        cli = kv_lib_cli_find(hprpdhdr->hwaddr, cli_header);
                        if (cli && kv_lib_addr_is_same(&cli->addr, &addr_in)) {
                            clihp = (struct kv_cli_hp *)cli;
                            if (clihp->stat == KV_CLI_HPSTAT_HPQUERY) {
                                clihp->stat = KV_CLI_HPSTAT_HPRESPOND; /* punching respond success */
                                cli->alive = KV_CLI_HOLE_PUNCHING_ALIVE;
                            }
                        }
                        KV_CLI_UNLOCK();
                    }
                }

            } else { /* normal packet */
                if (num > KV_VND_FRAME_LEN(vnd_mtu)) {
                    num = KV_VND_FRAME_LEN(vnd_mtu); /* Cut tail (The tail is AES 16Bytes align add) */
                }

                if (!hole_punching) { /* no hole punching */
                    write(vnd_fd, packet_in, num); /* virtual net device recv */

                } else { /* hole punching enable */
                    to_me = 0;

                    if (addr_in.sin_addr.s_addr == serv_addr.sin_addr.s_addr) { /* trust server */
                        to_me = 1;

                    } else {
                        KV_CLI_LOCK();
                        cli = kv_lib_cli_find(KV_PKT_MAC_SRC(packet_in), cli_header); /* must in our client list */
                        if (cli && kv_lib_addr_is_same(&cli->addr, &addr_in)) {
                            to_me = 1; /* find neibor client */
                        }
                        KV_CLI_UNLOCK();
                    }

                    if (to_me) {
                        write(vnd_fd, packet_in, num); /* virtual net device recv */
                    }
                }
            }
        }

        if (FD_ISSET(vnd_fd, &fdset)) { /* vitural net device send a message to server or client */
            num = read(vnd_fd, packet_in, KV_VND_FRAME_BSIZE);
            if (num <= 0) {
                fprintf(stderr, "[KidVPN] Read virtual net device error(%d): %s!\n", errno, strerror(errno));
                break; /* an error occur, exit! */
            }

            if (num < ETH_ZLEN) {
                num = ETH_ZLEN; /* ethernet shortest length */
            }

            if (!hole_punching || KV_PKY_MAC_BMC(packet_in)) { /* no hole punching or broadcast? */
                kv_lib_encode(packet_en, packet_in, (int)num, &aes_len, &ase_enc);

                sendto(cli_fd, packet_en, aes_len, 0,
                       (struct sockaddr *)&serv_addr, slen); /* NOTICE: send a 'aes_len' packet to server */

            } else { /* unicast */
                if (!hole_punching || !memcmp(serv_hwaddr, KV_PKT_MAC_DEST(packet_in), ETH_ALEN)) { /* to server */
                    kv_lib_encode(packet_en, packet_in, (int)num, &aes_len, &ase_enc);

                    sendto(cli_fd, packet_en, aes_len, 0,
                           (struct sockaddr *)&serv_addr, slen);

                } else { /* to other client */
                    cq_req = 0;
                    to_serv = 0;

                    KV_CLI_LOCK();
                    cli = kv_lib_cli_find(KV_PKT_MAC_DEST(packet_in), cli_header); /* find dest client */
                    if (!cli) {
                        clihp = (struct kv_cli_hp *)malloc(sizeof(struct kv_cli_hp));
                        if (clihp) {
                            clihp->stat = KV_CLI_HPSTAT_CLOSE; /* new client */
                            cli = &clihp->cli;
                            bzero(&cli->addr, sizeof(struct sockaddr_in));
                            memcpy(cli->hwaddr, KV_PKT_MAC_DEST(packet_in), ETH_ALEN);
                            kv_lib_cli_add(cli, cli_header); /* add to client list */
                        }

                    } else {
                        clihp = (struct kv_cli_hp *)cli;
                    }

                    if (clihp) {
                        switch (clihp->stat) {

                        case KV_CLI_HPSTAT_CLOSE:
                            clihp->stat = KV_CLI_HPSTAT_CQUERY;
                            cli->alive = KV_CLI_HOLE_PUNCHING_ALIVE;
                            cq_req = 1; /* send cquery packet */
                            to_serv = 1; /* send packet to server */
                            break;

                        case KV_CLI_HPSTAT_CQUERY: /* in query state */
                        case KV_CLI_HPSTAT_HPQUERY:
                            to_serv = 1; /* send packet to server */
                            break;

                        case KV_CLI_HPSTAT_HPRESPOND: /* there is a hole punching */
                            break;

                        default:
                            to_serv = 1; /* send packet to server */
                            break;
                        }

                    } else {
                        to_serv = 1; /* send packet to server */
                    }
                    KV_CLI_UNLOCK();

                    if (cq_req) {
                        memcpy(cquery_hdr.hwaddr, KV_PKT_MAC_DEST(packet_in), ETH_ALEN);

                        kv_lib_encode(packet_en, (UINT8 *)&cquery_hdr, KV_CQUERY_LEN, &aes_len, &ase_enc);

                        if (sendto(cli_fd, packet_en, aes_len, 0,
                                   (struct sockaddr *)&serv_addr, slen) != aes_len) { /* send to server cquery */
                            fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
                            break; /* an error occur, exit! */
                        }
                    }

                    kv_lib_encode(packet_en, packet_in, (int)num, &aes_len, &ase_enc);

                    if (to_serv) {
                        sendto(cli_fd, packet_en, aes_len, 0,
                               (struct sockaddr *)&serv_addr, slen); /* NOTICE: send a 'aes_len' packet to server */
                    } else {
                        sendto(cli_fd, packet_en, aes_len, 0,
                               (struct sockaddr *)&cli->addr, slen); /* NOTICE: send a 'aes_len' packet to client */
                    }
                }
            }
        }
    }

    return  (0); /* exit! */
}

/*
 * KidVPN client hello thread
 */
static void kv_cli_hello (void)
{
    int i;
    UINT32 snum = 0;
    int con_cnt = 0;
    int aes_len;
    struct kv_cli_node *cli;
    struct kv_cli_hp *clihp;

    UINT32 packet_buf_en[32 >> 2]; /* need 4 bytes aligned */
    UINT8 *packet_en = (UINT8 *)packet_buf_en; /* encrypt packet */

    hello_hdr.cmd     = KV_CMD_HELLO;
    hello_hdr.cmd_len = KV_HELLO_LEN;
    hello_hdr.magic   = KV_CMD_MAGIC;

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

        hello_hdr.mtu = htons(vnd_mtu);
        KV_CLI_UNLOCK();

        snum++;
        hello_hdr.snum = htonl(snum);

        kv_lib_encode(packet_en, (UINT8 *)&hello_hdr, KV_HELLO_LEN, &aes_len, &ase_enc);

        if (sendto(cli_fd, packet_en, aes_len, 0,
                   (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) != aes_len) { /* send client hello period */
            fprintf(stderr, "[KidVPN] Socket sendto() error(%d): %s!\n", errno, strerror(errno));
        }

        KV_CLI_LOCK();
        for (i = 0; i < KV_CLI_HASH_SIZE; i++) {
            cli = cli_header[i];
            while (cli) {
                if (cli->alive >= KV_CLI_HELLO_PERIOD) {
                    cli->alive -= KV_CLI_HELLO_PERIOD;
                    if (cli->alive <= 0) { /* client timeout! */
                        clihp = (struct kv_cli_hp *)cli;
                        clihp->stat = KV_CLI_HPSTAT_CLOSE;
                    }
                }
                cli = cli->next;
            }
        }
        KV_CLI_UNLOCK();

#if KV_VOLUNTARILY_QUIT
        if (cli_exit) {
            break;
        }
#endif /* KV_VOLUNTARILY_QUIT */

        sleep(KV_CLI_HELLO_PERIOD);
    }
}

/*
 * start KidVPN client
 */
int kv_cli_start (int vnd_id, const char *tap_name, const unsigned char *key, unsigned int keybits,
                  const char *server, unsigned int port, int mtu, int hole_punching)
{
    struct addrinfo hints;
    struct addrinfo *phints;

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
                            "Please check the name and try again.\n", server);
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

    if (!hole_punching) {
        if (connect(cli_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in))) { /* connect to server */
            fprintf(stderr, "[KidVPN] Client connect() call fail(%d): %s!\n", errno, strerror(errno));
            kv_lib_deinit(cli_fd, vnd_fd);
            return  (-1);
        }
    }

    if (pthread_create(&t_hello, NULL, (void *(*)(void *))kv_cli_hello, NULL)) {
        fprintf(stderr, "[KidVPN] Can not create hello thread error(%d): %s.\n", errno, strerror(errno));
        kv_lib_deinit(cli_fd, vnd_fd);
        return  (-1);
    }

    pthread_detach(t_hello);
    pthread_setname_np(t_hello, "kvc_hello");

    if (kv_cli_loop(hole_punching)) { /* client main loop */
        kv_lib_deinit(cli_fd, vnd_fd);
        return  (-1);
    }

    return  (0);
}

/*
 * end
 */
