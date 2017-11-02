/*
* ***************************************************************************
* Copyright (C) 2017 Marvell International Ltd.
* ***************************************************************************
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* Redistributions of source code must retain the above copyright notice, this
* list of conditions and the following disclaimer.
*
* Redistributions in binary form must reproduce the above copyright notice,
* this list of conditions and the following disclaimer in the documentation
* and/or other materials provided with the distribution.
*
* Neither the name of Marvell nor the names of its contributors may be used
* to endorse or promote products derived from this software without specific
* prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
* LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
* SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
* INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
* CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* ***************************************************************************
*/

/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP compiler hints
 */

#ifndef ODP_API_HINTS_H_
#define ODP_API_HINTS_H_
#include <odp/api/visibility_begin.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup odp_compiler_optim
 *  Macros that will give hints to the compiler.
 *  @{
 */

#ifdef __GNUC__

/** Define a function that does not return
 */
#define ODP_NORETURN __attribute__((__noreturn__))

/** Define a weak symbol
 * This is primarily useful in defining library functions that can be
 * overridden in user code.
 */
#define ODP_WEAK_SYMBOL __attribute__((__weak__))

/**
 * Hot code section
 */
#define ODP_HOT_CODE    __attribute__((__hot__))

/**
 * Cold code section
 */
#define ODP_COLD_CODE   __attribute__((__cold__))

/**
 * Printf format attribute
 */
#define ODP_PRINTF_FORMAT(x, y) __attribute__((format(printf, (x), (y))))

/**
 * Indicate deprecated variables, functions or types
 */
#define ODP_DEPRECATED __attribute__((__deprecated__))

/**
 * Intentionally unused variables of functions
 */
#define ODP_UNUSED     __attribute__((__unused__))

/**
 * Branch likely taken
 */
#define odp_likely(x)   __builtin_expect((x), 1)

/**
 * Branch unlikely taken
 */
#define odp_unlikely(x) __builtin_expect((x), 0)


/*
 * __builtin_prefetch (const void *addr, rw, locality)
 *
 * rw 0..1       (0: read, 1: write)
 * locality 0..3 (0: dont leave to cache, 3: leave on all cache levels)
 */

/**
 * Cache prefetch address
 */
#ifdef __arch_prefetch
#define odp_prefetch(x)		__arch_prefetch(x)
#else
#define odp_prefetch(x)         __builtin_prefetch((x), 0, 3)
#endif /* __arch_prefetch */

/**
 * Cache prefetch address for storing
 */
#define odp_prefetch_store(x)   __builtin_prefetch((x), 1, 3)



#else

#define ODP_WEAK_SYMBOL
#define ODP_HOT_CODE
#define ODP_COLD_CODE
#define ODP_DEPRECATED
#define ODP_UNUSED
#define odp_likely(x)
#define odp_unlikely(x)
#define odp_prefetch(x)
#define odp_prefetch_store(x)

#endif


/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#include <odp/api/visibility_end.h>
#endif
