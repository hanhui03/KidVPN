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

#ifndef __KV_LIB_H
#define __KV_LIB_H

#define _GNU_SOURCE /* need some *np api */

#ifndef SYLIXOS
typedef unsigned char  UINT8;
typedef unsigned short UINT16;
typedef unsigned int   UINT32;
#endif /* !SYLIXOS */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>

#ifdef SYLIXOS
#include <net/if_vnd.h>
#include <net/if_ether.h>
#else /* SYLIXOS */
#include <linux/if_tun.h>
#include <netinet/if_ether.h>
#endif /* LINUX */

#ifdef USE_OPENSSL
#include <openssl/aes.h>
#else /* USE_OPENSSL */
#include <mbedtls/aes.h>
#endif /* !USE_OPENSSL */

/* KidVPN MTU (Try not to appear IP fragment) */
#define KV_VND_MIN_MTU          1280
#define KV_VND_MAX_MTU          (ETH_DATA_LEN - 28)  /* ETH_DATA_LEN - IP_HLEN - UDP_HLEN */
#define KV_VND_DEF_MTU          (KV_VND_MAX_MTU - 8) /* KV_VND_MAX_MTU - PPPoE Header length */

#define KV_VND_FRAME_LEN(mtu)   (mtu + 18)  /* mtu + ETH_HLEN + VLAN_HLEN */
#define KV_VND_FRAME_MAX        KV_VND_FRAME_LEN(KV_VND_MAX_MTU)

/* hello period (s) */
#define KV_CLI_HELLO_TIMEOUT    60
#define KV_CLI_HELLO_PERIOD     10

/* KidVPN core lib functions */
int  kv_lib_init(int vnd_id, const char *tap_name, int *s_fd, int *v_fd, UINT8 hwaddr[], int mtu);
void kv_lib_deinit(int s_fd, int v_fd);

#ifdef USE_OPENSSL
void kv_lib_encode(UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_en);
void kv_lib_decode(UINT8 *out, UINT8 *in, int len, int *rlen, AES_KEY *aes_de);

#else /* USE_OPENSSL */
void kv_lib_encode(UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_en);
void kv_lib_decode(UINT8 *out, UINT8 *in, int len, int *rlen, mbedtls_aes_context *aes_de);
#endif /* !USE_OPENSSL */

#endif /* __KV_LIB_H */
/*
 * end
 */
