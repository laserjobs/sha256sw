#include "sha256sw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed = 0;

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        unsigned int val;
        sscanf(hex + i * 2, "%02x", &val);
        out[i] = (uint8_t)val;
    }
}

static void assert_hash(const char *test_name, const uint8_t *data, size_t len, const char *expected_hex)
{
    uint8_t expected[32];
    uint8_t actual[32];
    sha256sw_ctx ctx;

    hex_to_bytes(expected_hex, expected, 32);

    sha256sw_init(&ctx);
    sha256sw_update(&ctx, data, len);
    sha256sw_final(&ctx, actual);

    if (memcmp(actual, expected, 32) != 0) {
        printf("[FAIL] %s\n", test_name);
        printf("  Expected: %s\n  Actual:   ", expected_hex);
        for (int i = 0; i < 32; ++i) printf("%02x", actual[i]);
        printf("\n");
        g_failed++;
    } else {
        printf("[PASS] %s\n", test_name);
    }
}

static void test_chunking(void)
{
    const char *msg = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    const char *exp_hex = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1";
    uint8_t expected[32];
    uint8_t actual[32];
    sha256sw_ctx ctx;

    hex_to_bytes(exp_hex, expected, 32);

    sha256sw_init(&ctx);
    for (size_t i = 0; i < strlen(msg); ++i) {
        sha256sw_update(&ctx, (const uint8_t *)&msg[i], 1);
    }
    sha256sw_final(&ctx, actual);
    if (memcmp(actual, expected, 32) != 0) {
        printf("[FAIL] Streaming 1-byte chunks\n");
        g_failed++;
    } else {
        printf("[PASS] Streaming 1-byte chunks\n");
    }
}

static void test_defensive_and_overflow(void)
{
    sha256sw_ctx ctx;
    uint8_t out[32];
    uint8_t dummy[64] = {0};

    sha256sw_init(NULL);
    sha256sw_update(NULL, dummy, 64);
    sha256sw_update(&ctx, NULL, 64);
    sha256sw_final(NULL, out);
    sha256sw_final(&ctx, NULL);
    sha256sw_compress_block(NULL, (const uint32_t *)dummy);
    printf("[PASS] Null-pointer defensive guards\n");

    sha256sw_init(&ctx);
    ctx.bit_count = UINT64_MAX - 15;
    sha256sw_update(&ctx, dummy, 2);
    if (ctx.bit_count == UINT64_MAX - 15) {
        printf("[PASS] 64-bit length counter overflow rejected\n");
    } else {
        printf("[FAIL] Counter overflow was not rejected\n");
        g_failed++;
    }
}

int main(void)
{
    printf("=== SHA-256 Sliding Window Test Suite ===\n");

    assert_hash("Empty string", (const uint8_t *)"", 0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_hash("Vector 'abc'", (const uint8_t *)"abc", 3,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_hash("Vector 56 bytes", (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    uint8_t a_pad[128];
    memset(a_pad, 'a', sizeof(a_pad));
    assert_hash("Boundary 55 'a's (1 block)", a_pad, 55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    assert_hash("Boundary 56 'a's (2 blocks)", a_pad, 56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    assert_hash("Boundary 64 'a's (2 blocks)", a_pad, 64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");

    test_chunking();
    test_defensive_and_overflow();

    printf("==========================================\n");
    return g_failed == 0 ? 0 : 1;
}
