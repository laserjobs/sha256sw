#include "sha256sw.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define ROTR32(x, n) \
    (((x) >> (n)) | ((x) << (32U - (n))))

#define S0(x)  (ROTR32((x), 2U)  ^ ROTR32((x), 13U) ^ ROTR32((x), 22U))
#define S1(x)  (ROTR32((x), 6U)  ^ ROTR32((x), 11U) ^ ROTR32((x), 25U))
#define WS0(x) (ROTR32((x), 7U)  ^ ROTR32((x), 18U) ^ ((x) >> 3U))
#define WS1(x) (ROTR32((x), 17U) ^ ROTR32((x), 19U) ^ ((x) >> 10U))

#define Ch(x, y, z) \
    (((x) & (y)) + (~(x) & (z)))

#define Maj(x, y, z) \
    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static inline uint32_t load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24U) |
           ((uint32_t)p[1] << 16U) |
           ((uint32_t)p[2] <<  8U) |
           ((uint32_t)p[3]);
}

static inline void store_be32(uint8_t *p, uint32_t x)
{
    p[0] = (uint8_t)(x >> 24U);
    p[1] = (uint8_t)(x >> 16U);
    p[2] = (uint8_t)(x >>  8U);
    p[3] = (uint8_t)(x);
}

static const uint32_t K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static const uint32_t IV[8] = {
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
};

void sha256sw_compress_block(uint32_t state[8], const uint32_t block[16])
{
    if (state == NULL || block == NULL)
        return;

    uint32_t w[64];
    uint32_t a_mt[68];
    uint32_t b_mt[68];

    for (unsigned t = 0U; t < 16U; ++t)
        w[t] = block[t];

    for (unsigned t = 16U; t < 64U; ++t) {
        w[t] = w[t - 16U]
             + WS0(w[t - 15U])
             + w[t - 7U]
             + WS1(w[t - 2U]);
    }

    a_mt[0] = state[3];
    a_mt[1] = state[2];
    a_mt[2] = state[1];
    a_mt[3] = state[0];

    b_mt[0] = state[7];
    b_mt[1] = state[6];
    b_mt[2] = state[5];
    b_mt[3] = state[4];

    for (unsigned i = 0U; i < 64U; ++i) {
        const uint32_t t1 =
            b_mt[i]
            + S1(b_mt[i + 3U])
            + Ch(b_mt[i + 3U], b_mt[i + 2U], b_mt[i + 1U])
            + K[i]
            + w[i];

        b_mt[i + 4U] = t1 + a_mt[i];

        const uint32_t t2 =
            S0(a_mt[i + 3U])
            + Maj(a_mt[i + 3U], a_mt[i + 2U], a_mt[i + 1U]);

        a_mt[i + 4U] = (b_mt[i + 4U] - a_mt[i]) + t2;
    }

    state[0] += a_mt[67];
    state[1] += a_mt[66];
    state[2] += a_mt[65];
    state[3] += a_mt[64];

    state[4] += b_mt[67];
    state[5] += b_mt[66];
    state[6] += b_mt[65];
    state[7] += b_mt[64];
}

void sha256sw_init(sha256sw_ctx *ctx)
{
    if (ctx == NULL)
        return;

    memcpy(ctx->state, IV, sizeof(IV));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    ctx->bit_count = 0U;
}

void sha256sw_update(sha256sw_ctx *ctx, const uint8_t *data, size_t len)
{
    if (ctx == NULL || data == NULL || len == 0U)
        return;

    if ((uint64_t)len > UINT64_MAX / UINT64_C(8))
        return;

    const uint64_t add_bits = (uint64_t)len * UINT64_C(8);
    if (ctx->bit_count > UINT64_MAX - add_bits)
        return;

    size_t buffer_idx = (size_t)((ctx->bit_count >> 3U) & UINT64_C(0x3f));
    ctx->bit_count += add_bits;

    size_t part_len = 64U - buffer_idx;
    size_t i = 0U;

    if (len >= part_len) {
        memcpy(ctx->buffer + buffer_idx, data, part_len);

        uint32_t words[16];
        for (unsigned j = 0U; j < 16U; ++j)
            words[j] = load_be32(ctx->buffer + j * 4U);

        sha256sw_compress_block(ctx->state, words);

        for (i = part_len; i + 64U <= len; i += 64U) {
            for (unsigned j = 0U; j < 16U; ++j)
                words[j] = load_be32(data + i + j * 4U);

            sha256sw_compress_block(ctx->state, words);
        }

        buffer_idx = 0U;
    }

    if (i < len) {
        memcpy(ctx->buffer + buffer_idx, data + i, len - i);
    }
}

void sha256sw_final(sha256sw_ctx *ctx, uint8_t hash[32])
{
    if (ctx == NULL || hash == NULL)
        return;

    const uint64_t bit_count = ctx->bit_count;
    const size_t buffer_idx = (size_t)((bit_count >> 3U) & UINT64_C(0x3f));
    const size_t total = (buffer_idx < 56U) ? 64U : 128U;

    uint8_t block[128];
    memset(block, 0, sizeof(block));

    if (buffer_idx > 0U) {
        memcpy(block, ctx->buffer, buffer_idx);
    }

    block[buffer_idx] = 0x80U;

    for (unsigned i = 0U; i < 8U; ++i) {
        block[total - 8U + i] = (uint8_t)(bit_count >> (56U - 8U * i));
    }

    for (size_t offset = 0U; offset < total; offset += 64U) {
        uint32_t words[16];
        for (unsigned j = 0U; j < 16U; ++j)
            words[j] = load_be32(block + offset + j * 4U);

        sha256sw_compress_block(ctx->state, words);
    }

    for (unsigned i = 0U; i < 8U; ++i)
        store_be32(hash + i * 4U, ctx->state[i]);

    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}
