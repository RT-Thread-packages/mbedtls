/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rtthread.h>

#ifdef PKG_USING_MBEDTLS_CERTS_FROM_FS
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "tls_client.h"
#ifndef PKG_USING_MBEDTLS_CERTS_FROM_FS
#include "tls_certificate.h"
#endif

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_DEBUG_C)
#define DEBUG_LEVEL (2)
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L    /* C99 or later */
#include "mbedtls/debug.h"
#endif

#define DBG_ENABLE
#define DBG_COLOR
#define DBG_SECTION_NAME    "mbedtls.clnt"
#ifdef MBEDTLS_DEBUG_C
#define DBG_LEVEL           DBG_LOG
#else
#define DBG_LEVEL           DBG_INFO
#endif /* MBEDTLS_DEBUG_C */
#include <rtdbg.h>

#ifdef PKG_USING_MBEDTLS_CERTS_FROM_FS
#ifndef PKG_MBEDTLS_CERTS_DIR
#define PKG_MBEDTLS_CERTS_DIR "/certs"
#endif

#define TLS_CERT_MAX_PATH_LEN 256

static int _mbedtls_load_one_ca_file(mbedtls_x509_crt *cacert, const char *cert_file)
{
    int ret = 0;
    FILE *fp = RT_NULL;
    long file_size = 0;
    size_t read_size = 0;
    unsigned char *buf = RT_NULL;
    size_t parse_len = 0;

    fp = fopen(cert_file, "rb");
    if (fp == RT_NULL)
    {
        LOG_W("open cert file failed: %s", cert_file);
        return -RT_ERROR;
    }

    if (fseek(fp, 0, SEEK_END) != 0)
    {
        fclose(fp);
        return -RT_ERROR;
    }

    file_size = ftell(fp);
    if (file_size <= 0)
    {
        fclose(fp);
        return -RT_ERROR;
    }

    if (fseek(fp, 0, SEEK_SET) != 0)
    {
        fclose(fp);
        return -RT_ERROR;
    }

    buf = tls_calloc(1, (size_t)file_size + 1);
    if (buf == RT_NULL)
    {
        fclose(fp);
        return -RT_ENOMEM;
    }

    read_size = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_size != (size_t)file_size)
    {
        tls_free(buf);
        return -RT_ERROR;
    }

    {
        const char pem_header[] = "-----BEGIN CERTIFICATE-----";
        const size_t pem_header_len = sizeof(pem_header) - 1;

        if (read_size >= pem_header_len && !memcmp(buf, pem_header, pem_header_len))
        {
            parse_len = read_size + 1;
        }
        else
        {
            parse_len = read_size;
        }
    }

    ret = mbedtls_x509_crt_parse(cacert, buf, parse_len);
    tls_free(buf);
    if (ret < 0)
    {
        LOG_W("parse cert file failed: %s, ret: -0x%x", cert_file, -ret);
        return ret;
    }

    return RT_EOK;
}

static int _mbedtls_load_ca_from_dir(mbedtls_x509_crt *cacert, const char *cert_dir)
{
    DIR *dir = RT_NULL;
    struct dirent *ent = RT_NULL;
    struct stat st;
    char cert_path[TLS_CERT_MAX_PATH_LEN];
    int loaded = 0;

    dir = opendir(cert_dir);
    if (dir == RT_NULL)
    {
        LOG_W("open cert directory failed: %s", cert_dir);
        return -RT_ERROR;
    }

    while ((ent = readdir(dir)) != RT_NULL)
    {
        int path_len = 0;

        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
        {
            continue;
        }

        path_len = rt_snprintf(cert_path, sizeof(cert_path), "%s/%s", cert_dir, ent->d_name);
        if (path_len <= 0 || path_len >= sizeof(cert_path))
        {
            LOG_W("cert path too long, skip: %s", ent->d_name);
            continue;
        }

        if (stat(cert_path, &st) != 0 || !S_ISREG(st.st_mode))
        {
            continue;
        }

        if (_mbedtls_load_one_ca_file(cacert, cert_path) == RT_EOK)
        {
            loaded++;
        }
    }

    closedir(dir);

    if (loaded == 0)
    {
        LOG_W("no valid certificate loaded from: %s", cert_dir);
        return -RT_ERROR;
    }

    LOG_D("loaded %d certificate(s) from %s", loaded, cert_dir);
    return RT_EOK;
}
#endif /* PKG_USING_MBEDTLS_CERTS_FROM_FS */

static void _ssl_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void) level);

    LOG_D("%s:%04d: %s", file, line, str);
}

static int mbedtls_ssl_certificate_verify(MbedTLSSession *session)
{
    int ret = 0;
    ret = mbedtls_ssl_get_verify_result(&session->ssl);
    if (ret != 0)
    {
        LOG_E("verify peer certificate fail....");
        memset(session->buffer, 0x00, session->buffer_len);
        mbedtls_x509_crt_verify_info((char *)session->buffer, session->buffer_len, "  ! ", ret);
        LOG_E("verification info: %s", session->buffer);
        return -RT_ERROR;
    }
    return RT_EOK;
}

int mbedtls_client_init(MbedTLSSession *session, void *entropy, size_t entropyLen)
{
    int ret = 0;

#if defined(MBEDTLS_DEBUG_C)
    LOG_D("Set debug level (%d)", (int) DEBUG_LEVEL);
    mbedtls_debug_set_threshold((int) DEBUG_LEVEL);
#endif

    mbedtls_net_init(&session->server_fd);
    mbedtls_ssl_init(&session->ssl);
    mbedtls_ssl_config_init(&session->conf);
    mbedtls_ctr_drbg_init(&session->ctr_drbg);
    mbedtls_entropy_init(&session->entropy);
    mbedtls_x509_crt_init(&session->cacert);
    
    ret = mbedtls_ctr_drbg_seed(&session->ctr_drbg, mbedtls_entropy_func, &session->entropy,
                                     (unsigned char *)entropy, entropyLen);
    if (ret != 0)
    {
        LOG_E("mbedtls_ctr_drbg_seed error, return -0x%x\n", -ret);
        return ret;
    }
    LOG_D("mbedtls client struct init success...");

    return RT_EOK;
}

int mbedtls_client_close(MbedTLSSession *session)
{
    if (session == RT_NULL)
    {
        return -RT_ERROR;
    }

    mbedtls_ssl_close_notify(&session->ssl);
    mbedtls_net_free(&session->server_fd);
    mbedtls_x509_crt_free(&session->cacert);
    mbedtls_entropy_free(&session->entropy);
    mbedtls_ctr_drbg_free(&session->ctr_drbg);
    mbedtls_ssl_config_free(&session->conf);
    mbedtls_ssl_free(&session->ssl);

    if (session->buffer)
    {
        tls_free(session->buffer);
    }

    if (session->host)
    {
        tls_free(session->host);
    }

    if(session->port)
    {
        tls_free(session->port);
    }

    if (session)
    {   
        tls_free(session);
        session = RT_NULL;
    }
    
    return RT_EOK;
}

int mbedtls_client_context(MbedTLSSession *session)
{
    int ret = 0;

#ifdef PKG_USING_MBEDTLS_CERTS_FROM_FS
    ret = _mbedtls_load_ca_from_dir(&session->cacert, PKG_MBEDTLS_CERTS_DIR);
    if (ret != RT_EOK)
    {
        LOG_E("load certificates from directory failed: %s", PKG_MBEDTLS_CERTS_DIR);
        return ret;
    }
#else
    ret = mbedtls_x509_crt_parse(&session->cacert, (const unsigned char *)mbedtls_root_certificate,
                                 mbedtls_root_certificate_len);
    if (ret < 0)
    {
        LOG_E("mbedtls_x509_crt_parse error,  return -0x%x", -ret);
        return ret;
    }
#endif /* PKG_USING_MBEDTLS_CERTS_FROM_FS */

    LOG_D("Loading the CA root certificate success...");

    /* Hostname set here should match CN in server certificate */
    if (session->host)
    {
        ret = mbedtls_ssl_set_hostname(&session->ssl, session->host);
        if (ret != 0)
        {
            LOG_E("mbedtls_ssl_set_hostname error, return -0x%x", -ret);
            return ret;
        }
    }

    ret = mbedtls_ssl_config_defaults(&session->conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0)
    {
        LOG_E("mbedtls_ssl_config_defaults error, return -0x%x", -ret);
        return ret;
    }

    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&session->conf, &session->cacert, NULL);
    mbedtls_ssl_conf_rng(&session->conf, mbedtls_ctr_drbg_random, &session->ctr_drbg);

    mbedtls_ssl_conf_dbg(&session->conf, _ssl_debug, NULL);

    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret != 0)
    {
        LOG_E("mbedtls_ssl_setup error, return -0x%x\n", -ret);
        return ret;
    }
    LOG_D("mbedtls client context init success...");

    return RT_EOK;
}

int mbedtls_client_connect(MbedTLSSession *session)
{
    int ret = 0;

    ret = mbedtls_net_connect(&session->server_fd, session->host, 
                                session->port, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0)
    {
        LOG_E("mbedtls_net_connect error, return -0x%x", -ret);
        return ret;
    }

    LOG_D("Connected %s:%s success...", session->host, session->port);

    mbedtls_ssl_set_bio(&session->ssl, &session->server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&session->ssl)) != 0)
    {
        if (RT_EOK != mbedtls_ssl_certificate_verify(session))
        {
            return -RT_ERROR;
        }
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            LOG_E("mbedtls_ssl_handshake error, return -0x%x", -ret);
            return ret;
        }
    }

    if (RT_EOK != mbedtls_ssl_certificate_verify(session))
    {
        return -RT_ERROR;
    }

    LOG_D("Certificate verified success...");

    return RT_EOK;
}

int mbedtls_client_read(MbedTLSSession *session, unsigned char *buf , size_t len)
{
    int ret = 0;

    if (session == RT_NULL || buf == RT_NULL)
    {
        return -RT_ERROR;
    } 

    ret = mbedtls_ssl_read(&session->ssl, (unsigned char *)buf, len);
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        LOG_E("mbedtls_client_read data error, return -0x%x", -ret);
    }

    return ret;
}

int mbedtls_client_write(MbedTLSSession *session, const unsigned char *buf , size_t len)
{
    int ret = 0;

    if (session == RT_NULL || buf == RT_NULL)
    {
        return -RT_ERROR;
    }

    ret = mbedtls_ssl_write(&session->ssl, (unsigned char *)buf, len);
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
    {
        LOG_E("mbedtls_client_write data error, return -0x%x", -ret);
    }

    return ret;
}
