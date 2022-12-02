/**
 * @file
 * KidVPN library.
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

/* CBC enable */
int kv_cbc_en = 0;

/* CBC iv */
static unsigned char kv_cbc_iv[KV_CIPHER_IV_LEN];

/* CBC iv file */
static char *kv_cbc_iv_file = NULL;

/* vnd/tap if name */
static char kv_vnd_ifname[IFNAMSIZ];

/*
 * init vnd device
 */
int kv_lib_init (int vnd_id, const char *tap_name, int *s_fd, int *v_fd, UINT8 hwaddr[], int mtu)
{
    int i, so_fd = -1, vnd_fd = -1;
    struct ifreq  req;
#ifdef SYLIXOS
    struct ifvnd  vnd;
#endif /* SYLIXOS */

    so_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (so_fd < 0) {
        fprintf(stderr, "[KidVPN] Can not open socket error(%d): %s\n", errno, strerror(errno));
        goto    error;
    }

#ifdef SYLIXOS
    vnd_fd = open(IF_VND_PATH, O_RDWR);
    if (vnd_fd < 0) {
        fprintf(stderr, "[KidVPN] Can not open %s error(%d): %s\n", IF_VND_PATH, errno, strerror(errno));
        goto    error;
    }

    vnd.ifvnd_id = vnd_id;
    if (ioctl(vnd_fd, SIOCVNDSEL, &vnd)) {
        fprintf(stderr, "[KidVPN] Command 'SIOCVNDSEL' error(%d): %s\n", errno, strerror(errno));
        goto    error;
    }

    if (vnd.ifvnd_type != IF_VND_TYPE_ETHERNET) {
        fprintf(stderr, "[KidVPN] Virtual net device MUST a ethernet type.\n");
        goto    error;
    }

    strcpy(req.ifr_name, vnd.ifvnd_ifname);

#else /* SYLIXOS */
    vnd_fd = open("/dev/net/tun", O_RDWR);
    if (vnd_fd < 0) {
        fprintf(stderr, "[KidVPN] Can not open %s error(%d): %s\n", "/dev/net/tun", errno, strerror(errno));
        goto    error;
    }

    bzero(&req, sizeof(req));
    if (tap_name && vnd_id < 0) {
        strncpy(req.ifr_name, tap_name, IFNAMSIZ);
        req.ifr_name[IFNAMSIZ - 1] = '\0';
    } else {
        snprintf(req.ifr_name, IFNAMSIZ, "tap%d", vnd_id);
    }

    req.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(vnd_fd, TUNSETIFF, (void *)&req)) {
        fprintf(stderr, "[KidVPN] Command 'TUNSETIFF' error(%d): %s\n", errno, strerror(errno));
        goto    error;
    }
#endif /* !SYLIXOS */

    printf("[KidVPN] We use virtual net device: %s for VPN connect.\n", req.ifr_name);

    if (ioctl(so_fd, SIOCGIFHWADDR, &req)) {
        fprintf(stderr, "[KidVPN] Command 'SIOCGIFHWADDR' error(%d): %s\n", errno, strerror(errno));
        goto    error;
    }

    for (i = 0; i < ETH_ALEN; i++) {
        hwaddr[i] = req.ifr_hwaddr.sa_data[i];
    }

    if ((hwaddr[0] == 0) && (hwaddr[1] == 0) && (hwaddr[2] == 0) &&
        (hwaddr[3] == 0) && (hwaddr[4] == 0) && (hwaddr[5] == 0)) {
        fprintf(stderr, "[KidVPN] Virtual net device hwaddr error.\n");
        goto    error;
    }

    req.ifr_mtu = mtu;
    if (ioctl(so_fd, SIOCSIFMTU, &req)) {
        fprintf(stderr, "[KidVPN] Command 'SIOCSIFMTU' (%d) error(%d): %s\n", mtu, errno, strerror(errno));
        goto    error;
    }

    strcpy(kv_vnd_ifname, req.ifr_name);

    if (s_fd) {
        *s_fd = so_fd;
    }
    if (v_fd) {
        *v_fd = vnd_fd;
    }
    return  (0);

error:
    if (so_fd >= 0) {
        close(so_fd);
    }
    if (vnd_fd >= 0) {
        close(vnd_fd);
    }
    return  (-1);
}

/*
 * deinit vnd device
 */
void kv_lib_deinit (int s_fd, int v_fd)
{
    if (s_fd >= 0) {
        close(s_fd);
    }
    if (v_fd >= 0) {
        close(v_fd);
    }
}

/*
 * KidVPN set MTU
 */
int kv_lib_setmtu (int s_fd, int mtu)
{
    struct ifreq  req;

    strcpy(req.ifr_name, kv_vnd_ifname);

    if (ioctl(s_fd, SIOCGIFMTU, &req)) {
        fprintf(stderr, "[KidVPN] Command 'SIOCGIFMTU' (%d) error(%d): %s\n", mtu, errno, strerror(errno));
        return  (-1);
    }

    if (mtu == req.ifr_mtu) {
        return  (0);
    }

    req.ifr_mtu = mtu;
    if (ioctl(s_fd, SIOCSIFMTU, &req)) {
        fprintf(stderr, "[KidVPN] Command 'SIOCSIFMTU' (%d) error(%d): %s\n", mtu, errno, strerror(errno));
        return  (-1);
    }

    return  (0);
}

/*
 * KidVPN update iv buffer
 */
int kv_lib_update_iv (const char *iv_file)
{
    FILE *fp;
    char buf[256];

    if (iv_file) {
        kv_cbc_iv_file = strdup(iv_file);
        if (!kv_cbc_iv_file) {
            fprintf(stderr, "[KidVPN] Not enough memory.\n");
            return  (-1);
        }

    } else if (!kv_cbc_iv_file) {
        fprintf(stderr, "[KidVPN] No IV file specified.\n");
        return  (-1);
    }

    fp = fopen(kv_cbc_iv_file, "r");
    if (!fp) {
        fprintf(stderr, "[KidVPN] Open %s error(%d): %s\n", kv_cbc_iv_file, errno, strerror(errno));
        return  (-1);
    }

    if (!fgets(buf, sizeof(buf), fp)) { /* read iv */
        fprintf(stderr, "[KidVPN] IV file %s error(%d): %s\n", kv_cbc_iv_file, errno, strerror(errno));
        fclose(fp);
        return  (-1);
    }

    buf[sizeof(buf) - 1] = '\0';
    fclose(fp);

#ifdef USE_OPENSSL
    MD5((unsigned char *)buf, strlen(buf), kv_cbc_iv);
#else /* USE_OPENSSL */
    mbedtls_md5((unsigned char *)buf, strlen(buf), kv_cbc_iv);
#endif /* !USE_OPENSSL */

    kv_cbc_en = 1;
    return  (0);
}

/*
 * KidVPN encode
 */
#ifdef USE_OPENSSL
void kv_lib_encode (UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_en)
#else /* USE_OPENSSL */
void kv_lib_encode (UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_en)
#endif /* !USE_OPENSSL */
{
    int aes_len = ROUND_UP(len, KV_AES_BLK_LEN);
    int spare;
    int i, times;
    unsigned char *iv;

    if (rlen) {
        *rlen = aes_len;
    }

    if (aes_len > len) {
        spare = aes_len - len;
        bzero(out + len, spare);
        bzero(in + len, spare);
    }

    times = aes_len >> KV_AES_BLK_SHIFT; /* aes_len / 16 */

    if (kv_cbc_en) { /* CBC */
        int j;

        iv = kv_cbc_iv;

        for (i = 0; i < times; i++) {
            for (j = 0; j < KV_CIPHER_IV_LEN; j++) {
                out[j] = (unsigned char)(in[j] ^ iv[j]);
            }

#ifdef USE_OPENSSL
            AES_encrypt(out, out, aes_en);
#else /* USE_OPENSSL */
            mbedtls_aes_crypt_ecb(aes_en, MBEDTLS_AES_ENCRYPT, out, out);
#endif /* !USE_OPENSSL */

            iv = out;
            in += KV_AES_BLK_LEN;
            out += KV_AES_BLK_LEN;
        }

    } else { /* ECB */
        for (i = 0; i < times; i++) {
#ifdef USE_OPENSSL
            AES_encrypt(in, out, aes_en);
#else /* USE_OPENSSL */
            mbedtls_aes_crypt_ecb(aes_en, MBEDTLS_AES_ENCRYPT, in, out);
#endif /* !USE_OPENSSL */

            in += KV_AES_BLK_LEN;
            out += KV_AES_BLK_LEN;
        }
    }
}

/*
 * KidVPN decode
 */
#ifdef USE_OPENSSL
void kv_lib_decode (UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_de)
#else /* USE_OPENSSL */
void kv_lib_decode (UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_de)
#endif /* !USE_OPENSSL */
{
    int aes_len = ROUND_UP(len, KV_AES_BLK_LEN);
    int spare;
    int i, times;
    unsigned char *iv;

    if (rlen) {
        *rlen = aes_len;
    }

    if (aes_len > len) {
        spare = aes_len - len;
        bzero(out + len, spare);
        bzero(in + len, spare);
    }

    times = aes_len >> KV_AES_BLK_SHIFT; /* aes_len / 16 */

    if (kv_cbc_en) { /* CBC */
        int j;

        iv = kv_cbc_iv;

        for (i = 0; i < times; i++) {
#ifdef USE_OPENSSL
            AES_decrypt(in, out, aes_de);
#else /* USE_OPENSSL */
            mbedtls_aes_crypt_ecb(aes_de, MBEDTLS_AES_DECRYPT, in, out);
#endif /* !USE_OPENSSL */

            for (j = 0; j < KV_CIPHER_IV_LEN; j++) {
                out[j] = (unsigned char)(out[j] ^ iv[j]);
            }

            iv = in;
            in += KV_AES_BLK_LEN;
            out += KV_AES_BLK_LEN;
        }

    } else { /* ECB */
        for (i = 0; i < times; i++) {
#ifdef USE_OPENSSL
            AES_decrypt(in, out, aes_de);
#else /* USE_OPENSSL */
            mbedtls_aes_crypt_ecb(aes_de, MBEDTLS_AES_DECRYPT, in, out);
#endif /* !USE_OPENSSL */

            in += KV_AES_BLK_LEN;
            out += KV_AES_BLK_LEN;
        }
    }
}

/*
 * KidVPN address is same
 */
int kv_lib_addr_is_same (struct sockaddr_in *addr1, struct sockaddr_in *addr2)
{
    if ((addr1->sin_port == addr2->sin_port) &&
        (addr1->sin_addr.s_addr == addr2->sin_addr.s_addr)) {
        return  (1);
    }

    return  (0);
}

/*
 * KidVPN client hash
 */
int kv_lib_cli_hash (UINT8  hwaddr[])
{
    int hash;

    hash = hwaddr[0]
         + hwaddr[1]
         + hwaddr[2]
         + hwaddr[3]
         + hwaddr[4]
         + hwaddr[5];

    return  (hash & KV_CLI_HASH_MASK);
}

/*
 * KidVPN add a new client into list
 */
void kv_lib_cli_add (struct kv_cli_node *cli, struct kv_cli_node *header[])
{
    int hash = kv_lib_cli_hash(cli->hwaddr);

    cli->next = header[hash];
    cli->prev = NULL;
    if (header[hash]) {
        header[hash]->prev = cli;
    }
    header[hash] = cli;
}

/*
 * KidVPN delete a client from list
 */
void kv_lib_cli_delete (struct kv_cli_node *cli, struct kv_cli_node *header[])
{
    int hash = kv_lib_cli_hash(cli->hwaddr);

    if (header[hash] == cli) {
        header[hash] = cli->next;
    }
    if (cli->next) {
        cli->next->prev = cli->prev;
    }
    if (cli->prev) {
        cli->prev->next = cli->next;
    }
}

/*
 * KidVPN find client from list
 */
struct kv_cli_node *kv_lib_cli_find (UINT8  hwaddr[], struct kv_cli_node *header[])
{
    struct kv_cli_node *cli;
    int hash = kv_lib_cli_hash(hwaddr);

    for (cli = header[hash]; cli != NULL; cli = cli->next) {
        if (!memcmp(cli->hwaddr, hwaddr, ETH_ALEN)) {
            return  (cli);
        }
    }

    return  (NULL);
}

#if KV_VOLUNTARILY_QUIT
/*
 * signalfd init
 */
int kv_lib_signalfd (void)
{
    int sigfd;
    sigset_t mask;

    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sigfd < 0) {
        fprintf(stderr, "[KidVPN] Can not open signalfd, error(%d): %s\n", errno, strerror(errno));
        return  (-1);
    }

    return  (sigfd);
}
#endif /* KV_VOLUNTARILY_QUIT */

/*
 * end
 */
