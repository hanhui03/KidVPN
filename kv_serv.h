/**
 * @file
 * KidVPN server.
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

#ifndef __KV_SERV_H
#define __KV_SERV_H

/* server port */
#define KV_SERV_PORT    10088

/* KidVPN magic */
#define KV_CMD_MAGIC0   0x35
#define KV_CMD_MAGIC1   0x22
#define KV_CMD_MAGIC2   0xf1
#define KV_CMD_MAGIC3   0xc2

/* command */
#define KV_CMD_HELLO    0
#define KV_CMD_WELCOME  1
#define KV_CMD_BYE      2
#define KV_CMD_ERR      255

/* error */
#define KV_ERR_NONE     0
#define KV_ERR_MTU      1

/* HELLO packet */
struct kv_hello_hdr {
    UINT8   cmd;
    UINT8   cmd_len;
    UINT8   hwaddr[ETH_ALEN];
    UINT8   magic[4];
    UINT32  snum;
    UINT16  mtu;
    UINT8   pad[16]; /* for aes encode decode */
} __attribute__((packed));

#define KV_HELLO_LEN    18

/* WELCOME packet */
struct kv_welcome_hdr {
    UINT8   cmd;
    UINT8   cmd_len;
    UINT8   hwaddr[ETH_ALEN];
    UINT8   magic[4];
    UINT32  snum;
    UINT8   pad[16]; /* for aes encode decode */
} __attribute__((packed));

#define KV_WELCOME_LEN  16

/* BYE packet */
struct kv_bye_hdr {
    UINT8   cmd;
    UINT8   cmd_len;
    UINT8   magic[4];
    UINT8   pad[16]; /* for aes encode decode */
} __attribute__((packed));

#define KV_BYE_LEN      6

/* ERR packet */
struct kv_err_hdr {
    UINT8   cmd;
    UINT8   cmd_len;
    UINT8   magic[4];
    UINT16  err;
    UINT16  code;
    UINT8   pad[16]; /* for aes encode decode */
} __attribute__((packed));

#define KV_ERR_LEN      10

/* KidVPN server start */
int kv_serv_start(int vnd_id, const char *tap_name, const unsigned char *key, unsigned int keybits,
                  const char *local, unsigned int port, int mtu);

#endif /* __KV_SERV_H */
/*
 * end
 */
