/**
 * @file
 * KidVPN library.
 * as much as possible compatible with different versions of LwIP
 * Verification using sylixos(tm) real-time operating system
 */

/*
 * Copyright (c) 2006-2017 SylixOS Group.
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

/* init vnd device */
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

/* deinit vnd device */
void kv_lib_deinit (int s_fd, int v_fd)
{
    if (s_fd >= 0) {
        close(s_fd);
    }
    if (v_fd >= 0) {
        close(v_fd);
    }
}

#ifndef ROUND_UP
#define ROUND_UP(x, align)  (size_t)(((size_t)(x) +  (align - 1)) & ~(align - 1))
#endif

/* KidVPN encode */
#ifdef USE_OPENSSL
void kv_lib_encode (UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_en)
#else /* USE_OPENSSL */
void kv_lib_encode (UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_en)
#endif /* !USE_OPENSSL */
{
    int aes_len = ROUND_UP(len, 16);
    int spare;
    int i, times;

    if (rlen) {
        *rlen = aes_len;
    }

    if (aes_len > len) {
        spare = aes_len - len;
        bzero(out + len, spare);
        bzero(in + len, spare);
    }

    times = aes_len >> 4; /* aes_len / 16 */
    for (i = 0; i < times; i++) {
#ifdef USE_OPENSSL
        AES_encrypt(in, out, aes_en);
#else /* USE_OPENSSL */
        mbedtls_aes_crypt_ecb(aes_en, MBEDTLS_AES_ENCRYPT, in, out);
#endif /* !USE_OPENSSL */
        in += 16;
        out += 16;
    }
}

/* KidVPN decode */
#ifdef USE_OPENSSL
void kv_lib_decode (UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_de)
#else /* USE_OPENSSL */
void kv_lib_decode (UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_de)
#endif /* !USE_OPENSSL */
{
    int aes_len = ROUND_UP(len, 16);
    int spare;
    int i, times;

    if (rlen) {
        *rlen = aes_len;
    }

    if (aes_len > len) {
        spare = aes_len - len;
        bzero(out + len, spare);
        bzero(in + len, spare);
    }

    times = aes_len >> 4; /* aes_len / 16 */
    for (i = 0; i < times; i++) {
#ifdef USE_OPENSSL
        AES_decrypt(in, out, aes_de);
#else /* USE_OPENSSL */
        mbedtls_aes_crypt_ecb(aes_de, MBEDTLS_AES_DECRYPT, in, out);
#endif /* !USE_OPENSSL */
        in += 16;
        out += 16;
    }
}

/*
 * end
 */
