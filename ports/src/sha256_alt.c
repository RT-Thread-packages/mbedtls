/*
 *  FIPS-180-2 compliant SHA-256 implementation
 *
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
/*
 *  The SHA-256 Secure Hash Standard was published by NIST in 2002.
 *
 *  http://csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf
 */

#include "common.h"

#if defined(MBEDTLS_SHA256_C)

#include "sha256_alt.h"
#include <string.h>
#include <rtthread.h>
#include <rtdevice.h>
#include <stdio.h>

#define DBG_SECTION_NAME "SHA256_ALT"
#define DBG_LEVEL DBG_INFO
#include <rtdbg.h>

#if defined(MBEDTLS_SHA256_ALT)

static int mbedtls_sha256_ensure_ctx(mbedtls_sha256_context *ctx)
{
    struct rt_hwcrypto_device *dev;

    if (ctx == RT_NULL)
    {
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    if (*ctx != RT_NULL)
    {
        return 0;
    }

    dev = rt_hwcrypto_dev_default();
    if (dev == RT_NULL)
    {
        LOG_E("sha2 dev default is null");
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    *ctx = rt_hwcrypto_hash_create(dev, HWCRYPTO_TYPE_SHA2);
    if (*ctx == RT_NULL)
    {
        LOG_E("sha2 create ctx failed");
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    return 0;
}

void mbedtls_sha256_init(mbedtls_sha256_context *ctx)
{
    if (ctx)
    {
        *ctx = RT_NULL;
        (void)mbedtls_sha256_ensure_ctx(ctx);
        LOG_D("sha2 init ctx[%08x]", *ctx);
    }
    else
    {
        LOG_E("sha2 init. but ctx is null");
    }
}

void mbedtls_sha256_free(mbedtls_sha256_context *ctx)
{
    if (ctx && (*ctx != RT_NULL))
    {
        LOG_D("sha2 free ctx[%08x]", *ctx);
        rt_hwcrypto_hash_destroy(*ctx);
        *ctx = RT_NULL;
    }
    else if (!ctx)
    {
        LOG_E("sha2 free. but ctx is null");
    }
}

void mbedtls_sha256_clone(mbedtls_sha256_context *dst,
                          const mbedtls_sha256_context *src)
{
    if (dst && src && (*src != RT_NULL))
    {
        if (mbedtls_sha256_ensure_ctx(dst) != 0)
        {
            return;
        }
        LOG_D("sha2 clone des[%08x] src[%08x]", *dst, *src);
        if (rt_hwcrypto_hash_cpy(*dst, *src) != RT_EOK)
        {
            LOG_E("sha2 clone failed");
        }
    }
    else
    {
        LOG_E("sha2 clone. but dst or src is null");
    }
}

/*
 * SHA-256 context setup
 */
int mbedtls_sha256_starts_ret(mbedtls_sha256_context *ctx, int is224)
{
    if (mbedtls_sha256_ensure_ctx(ctx) == 0)
    {
        LOG_D("sha2-%s starts ctx[%08x]", is224 ? "224" : "256", *ctx);
        if (is224)
        {
            if (rt_hwcrypto_hash_set_type(*ctx, HWCRYPTO_TYPE_SHA224) != RT_EOK)
            {
                LOG_E("sha224 set type failed");
                return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            }
        }
        else
        {
            if (rt_hwcrypto_hash_set_type(*ctx, HWCRYPTO_TYPE_SHA256) != RT_EOK)
            {
                LOG_E("sha256 set type failed");
                return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
            }
        }
        rt_hwcrypto_hash_reset(*ctx);
    }
    else
    {
        LOG_E("sha2 starts. but ctx is null");
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    return (0);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_sha256_starts(mbedtls_sha256_context *ctx,
                          int is224)
{
    return mbedtls_sha256_starts_ret(ctx, is224);
}
#endif

#if !defined(MBEDTLS_SHA256_PROCESS_ALT)
int mbedtls_internal_sha256_process(mbedtls_sha256_context *ctx,
                                    const unsigned char data[64])
{
    return mbedtls_sha256_update_ret(ctx, data, 64);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_sha256_process(mbedtls_sha256_context *ctx,
                           const unsigned char data[64])
{
    return mbedtls_internal_sha256_process(ctx, data);
}
#endif
#endif /* !MBEDTLS_SHA256_PROCESS_ALT */

/*
 * SHA-256 process buffer
 */
int mbedtls_sha256_update_ret(mbedtls_sha256_context *ctx, const unsigned char *input,
                              size_t ilen)
{
    if ((mbedtls_sha256_ensure_ctx(ctx) == 0) && (input != RT_NULL || ilen == 0))
    {
        LOG_D("sha2 update ctx[%08x] len:%d in:%08x", *ctx, ilen, input);
        if (rt_hwcrypto_hash_update(*ctx, input, ilen) != RT_EOK)
        {
            LOG_E("sha2 update failed");
            return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        }
    }
    else
    {
        LOG_E("sha2 update. but ctx is null");
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_sha256_update(mbedtls_sha256_context *ctx,
                          const unsigned char *input,
                          size_t ilen)
{
    return mbedtls_sha256_update_ret(ctx, input, ilen);
}
#endif

/*
 * SHA-256 final digest
 */
int mbedtls_sha256_finish_ret(mbedtls_sha256_context *ctx, unsigned char output[32])
{
    if ((mbedtls_sha256_ensure_ctx(ctx) == 0) && (output != RT_NULL))
    {
        LOG_D("sha2 finish ctx[%08x] out:%08x", *ctx, output);
        if (rt_hwcrypto_hash_finish(*ctx, output, 32) != RT_EOK)
        {
            LOG_E("sha2 finish failed");
            return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
        }
    }
    else
    {
        LOG_E("sha2 finish. but ctx is null");
        return MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED;
    }

    return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_sha256_finish(mbedtls_sha256_context *ctx,
                          unsigned char output[32])
{
    return mbedtls_sha256_finish_ret(ctx, output);
}
#endif

#endif /* MBEDTLS_SELF_TEST */
#endif /* MBEDTLS_SHA256_C */
