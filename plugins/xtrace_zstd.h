#ifndef MAMBO_XTRACE_ZSTD_H
#define MAMBO_XTRACE_ZSTD_H

#include <stddef.h>

#if defined(__has_include)
#if __has_include(<zstd.h>)
#include <zstd.h>
#define XTRACE_HAS_SYSTEM_ZSTD_H 1
#endif
#endif

#ifndef XTRACE_HAS_SYSTEM_ZSTD_H
/* Stable public zstd ABI used when the runtime library is installed without
 * its development headers. */
typedef struct ZSTD_CCtx_s ZSTD_CCtx;

ZSTD_CCtx *ZSTD_createCCtx(void);
size_t ZSTD_freeCCtx(ZSTD_CCtx *cctx);
size_t ZSTD_compressBound(size_t src_size);
size_t ZSTD_compressCCtx(ZSTD_CCtx *cctx, void *dst, size_t dst_capacity,
                         const void *src, size_t src_size,
                         int compression_level);
size_t ZSTD_decompress(void *dst, size_t dst_capacity, const void *src,
                       size_t compressed_size);
unsigned ZSTD_isError(size_t code);
#endif

#endif
