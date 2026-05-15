/*
 *  RFC 1321 compliant MD5 implementation
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
 *  The MD5 algorithm was designed by Ron Rivest in 1991.
 *
 *  http://www.ietf.org/rfc/rfc1321.txt
 */

#include "common.h"

#if defined(MBEDTLS_MD5_C)

#include "md5_alt.h"
#include <string.h>
#include <rtthread.h>
#include <rtdevice.h>
#include <stdio.h>

#define DBG_SECTION_NAME "MD5_ALT"
#define DBG_LEVEL DBG_INFO
#include <rtdbg.h>

#if defined(MBEDTLS_MD5_ALT)

static int mbedtls_md5_ensure_ctx(mbedtls_md5_context *ctx)
{
    struct rt_hwcrypto_device *dev;

    if (ctx == RT_NULL)
    {
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    if (*ctx != RT_NULL)
    {
        return 0;
    }

    dev = rt_hwcrypto_dev_default();
    if (dev == RT_NULL)
    {
        LOG_E("md5 dev default is null");
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    *ctx = rt_hwcrypto_hash_create(dev, HWCRYPTO_TYPE_MD5);
    if (*ctx == RT_NULL)
    {
        LOG_E("md5 create ctx failed");
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    return 0;
}

void mbedtls_md5_init(mbedtls_md5_context *ctx)
{
    if (ctx)
    {
        *ctx = RT_NULL;
        (void)mbedtls_md5_ensure_ctx(ctx);
        LOG_D("md5 init ctx[%08x]", *ctx);
    }
    else
    {
        LOG_E("md5 init. but ctx is null");
    }
}

void mbedtls_md5_free(mbedtls_md5_context *ctx)
{
    if (ctx && (*ctx != RT_NULL))
    {
        LOG_D("md5 free ctx[%08x]", *ctx);
        rt_hwcrypto_hash_destroy(*ctx);
        *ctx = RT_NULL;
    }
    else if (!ctx)
    {
        LOG_E("md5 free. but ctx is null");
    }
}

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src)
{
    if (dst && src && (*src != RT_NULL))
    {
        if (mbedtls_md5_ensure_ctx(dst) != 0)
        {
            return;
        }
        LOG_D("md5 clone des[%08x] src[%08x]", *dst, *src);
        if (rt_hwcrypto_hash_cpy(*dst, *src) != RT_EOK)
        {
            LOG_E("md5 clone failed");
        }
    }
    else
    {
        LOG_E("md5 clone. but dst or src is null");
    }
}

/*
 * MD5 context setup
 */
int mbedtls_md5_starts_ret(mbedtls_md5_context *ctx)
{
    if (mbedtls_md5_ensure_ctx(ctx) == 0)
    {
        LOG_D("md5 starts ctx[%08x]", *ctx);
        rt_hwcrypto_hash_reset(*ctx);
    }
    else
    {
        LOG_E("md5 starts. but ctx is null");
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_md5_starts(mbedtls_md5_context *ctx)
{
    return mbedtls_md5_starts_ret(ctx);
}
#endif

#if !defined(MBEDTLS_MD5_PROCESS_ALT)
int mbedtls_internal_md5_process(mbedtls_md5_context *ctx,
                                 const unsigned char data[64])
{
    return mbedtls_md5_update_ret(ctx, data, 64);
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_md5_process(mbedtls_md5_context *ctx,
                        const unsigned char data[64])
{
    return mbedtls_internal_md5_process(ctx, data);
}
#endif
#endif /* !MBEDTLS_MD5_PROCESS_ALT */

/*
 * MD5 process buffer
 */
int mbedtls_md5_update_ret(mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen)
{
    if ((mbedtls_md5_ensure_ctx(ctx) == 0) && (input != RT_NULL || ilen == 0))
    {
        LOG_D("md5 update ctx[%08x] len:%d in:%08x", *ctx, ilen, input);
        if (rt_hwcrypto_hash_update(*ctx, input, ilen) != RT_EOK)
        {
            LOG_E("md5 update failed");
            return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
        }
    }
    else
    {
        LOG_E("md5 update. but ctx is null");
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_md5_update(mbedtls_md5_context *ctx,
                       const unsigned char *input,
                       size_t ilen)
{
    return mbedtls_md5_update_ret(ctx, input, ilen);
}
#endif

/*
 * MD5 final digest
 */
int mbedtls_md5_finish_ret(mbedtls_md5_context *ctx, unsigned char output[16])
{
    if ((mbedtls_md5_ensure_ctx(ctx) == 0) && (output != RT_NULL))
    {
        LOG_D("md5 finish ctx[%08x] out:%08x", *ctx, output);
        if (rt_hwcrypto_hash_finish(*ctx, output, 16) != RT_EOK)
        {
            LOG_E("md5 finish failed");
            return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
        }
    }
    else
    {
        LOG_E("md5 finish. but ctx is null");
        return MBEDTLS_ERR_MD5_HW_ACCEL_FAILED;
    }

    return 0;
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
int mbedtls_md5_finish(mbedtls_md5_context *ctx,
                       unsigned char output[16])
{
    return mbedtls_md5_finish_ret(ctx, output);
}
#endif

#endif /* MBEDTLS_MD5_ALT */
#endif /* MBEDTLS_MD5_C */
