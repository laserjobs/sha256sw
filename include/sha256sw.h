#ifndef SHA256SW_H
#define SHA256SW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t  buffer[64];
} sha256sw_ctx;

void sha256sw_init(sha256sw_ctx *ctx);
void sha256sw_update(sha256sw_ctx *ctx, const uint8_t *data, size_t len);
void sha256sw_final(sha256sw_ctx *ctx, uint8_t hash[32]);
void sha256sw_compress_block(uint32_t state[8], const uint32_t block[16]);

#ifdef __cplusplus
}
#endif

#endif /* SHA256SW_H */
