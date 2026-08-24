#include "sha256sw.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed = 0;


static void hex_to_bytes(
    const char *hex,
    uint8_t *out,
    size_t len
)
{
    for (size_t i = 0; i < len; ++i) {
        unsigned int value = 0;

        if (sscanf(hex + i * 2, "%02x", &value) != 1) {
            fprintf(stderr,
                    "Invalid hexadecimal test vector\n");
            exit(EXIT_FAILURE);
        }

        out[i] = (uint8_t)value;
    }
}


static void assert_hash(
    const char *test_name,
    const uint8_t *data,
    size_t len,
    const char *expected_hex
)
{
    uint8_t expected[32];
    uint8_t actual[32];

    sha256sw_ctx ctx;

    hex_to_bytes(
        expected_hex,
        expected,
        sizeof(expected)
    );

    sha256sw_init(&ctx);
    sha256sw_update(&ctx, data, len);
    sha256sw_final(&ctx, actual);

    if (memcmp(
            actual,
            expected,
            sizeof(expected)
        ) != 0) {

        printf("[FAIL] %s\n", test_name);

        printf("  Expected: %s\n", expected_hex);
        printf("  Actual:   ");

        for (size_t i = 0; i < sizeof(actual); ++i) {
            printf("%02x", actual[i]);
        }

        printf("\n");

        g_failed++;
    } else {
        printf("[PASS] %s\n", test_name);
    }
}


static void test_chunking(void)
{
    const char *message =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklm"
        "ghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
        "mnopqrstnopqrstu";

    const char *expected_hex =
        "cf5b16a778af8380036ce59e7b049237"
        "0b249b11e8f07a51afac45037afee9d1";

    uint8_t expected[32];
    uint8_t actual[32];

    sha256sw_ctx ctx;

    hex_to_bytes(
        expected_hex,
        expected,
        sizeof(expected)
    );

    sha256sw_init(&ctx);

    for (size_t i = 0; i < strlen(message); ++i) {
        sha256sw_update(
            &ctx,
            (const uint8_t *)&message[i],
            1
        );
    }

    sha256sw_final(&ctx, actual);

    if (memcmp(
            actual,
            expected,
            sizeof(expected)
        ) != 0) {

        printf("[FAIL] Streaming 1-byte chunks\n");
        g_failed++;

    } else {
        printf("[PASS] Streaming 1-byte chunks\n");
    }
}


static void test_block_compression(void)
{
    /*
     * Padded SHA-256 block for "abc".
     *
     * This test exercises the compression primitive directly,
     * independently of the streaming/padding layer.
     */
    static const uint32_t block[16] = {
        0x61626380U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000000U,
        0x00000018U
    };

    static const uint32_t expected[8] = {
        0xBA7816BFU,
        0x8F01CFEAU,
        0x414140DEU,
        0x5DAE2223U,
        0xB00361A3U,
        0x96177A9CU,
        0xB410FF61U,
        0xF20015ADU
    };

    /*
     * SHA-256 initial state.
     */
    uint32_t state[8] = {
        0x6A09E667U,
        0xBB67AE85U,
        0x3C6EF372U,
        0xA54FF53AU,
        0x510E527FU,
        0x9B05688CU,
        0x1F83D9ABU,
        0x5BE0CD19U
    };

    sha256sw_compress_block(
        state,
        block
    );

    if (memcmp(
            state,
            expected,
            sizeof(expected)
        ) != 0) {

        printf("[FAIL] Direct compression vector\n");

        printf("  Expected: ");

        for (size_t i = 0; i < 8; ++i) {
            printf("%08x", expected[i]);
        }

        printf("\n  Actual:   ");

        for (size_t i = 0; i < 8; ++i) {
            printf("%08x", state[i]);
        }

        printf("\n");

        g_failed++;

    } else {
        printf("[PASS] Direct compression vector\n");
    }
}


static void test_defensive_and_overflow(void)
{
    sha256sw_ctx ctx;

    uint8_t out[32];
    uint8_t dummy[64] = {0};

    /*
     * Defensive NULL-pointer calls must not crash.
     */
    sha256sw_init(NULL);
    sha256sw_update(NULL, dummy, sizeof(dummy));
    sha256sw_update(&ctx, NULL, sizeof(dummy));
    sha256sw_final(NULL, out);
    sha256sw_final(&ctx, NULL);
    sha256sw_compress_block(
        NULL,
        (const uint32_t *)dummy
    );

    printf("[PASS] Null-pointer defensive guards\n");

    /*
     * The implementation must reject a message-length overflow
     * rather than silently wrapping the bit counter.
     */
    sha256sw_init(&ctx);

    ctx.bit_count = UINT64_MAX - 15;

    sha256sw_update(
        &ctx,
        dummy,
        2
    );

    if (ctx.bit_count == UINT64_MAX - 15) {
        printf(
            "[PASS] 64-bit length counter overflow rejected\n"
        );
    } else {
        printf(
            "[FAIL] Counter overflow was not rejected\n"
        );

        g_failed++;
    }
}


int main(void)
{
    printf(
        "=== SHA-256 Sliding Window Test Suite ===\n"
    );

    assert_hash(
        "Empty string",
        (const uint8_t *)"",
        0,
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    );

    assert_hash(
        "Vector 'abc'",
        (const uint8_t *)"abc",
        3,
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    );

    assert_hash(
        "Vector 56 bytes",
        (const uint8_t *)
        "abcdbcdecdefdefgefghfghighijhijk"
        "ijkljklmklmnlmnomnopnopq",
        56,
        "248d6a61d20638b8e5c026930c3e6039"
        "a33ce45964ff2167f6ecedd419db06c1"
    );

    {
        uint8_t a_pad[128];

        memset(
            a_pad,
            'a',
            sizeof(a_pad)
        );

        assert_hash(
            "Boundary 55 'a's (1 block)",
            a_pad,
            55,
            "9f4390f8d30c2dd92ec9f095b65e2b9a"
            "e9b0a925a5258e241c9f1e910f734318"
        );

        assert_hash(
            "Boundary 56 'a's (2 blocks)",
            a_pad,
            56,
            "b35439a4ac6f0948b6d6f9e3c6af0f5f"
            "590ce20f1bde7090ef7970686ec6738a"
        );

        assert_hash(
            "Boundary 64 'a's (2 blocks)",
            a_pad,
            64,
            "ffe054fe7ae0cb6dc65c3af9b61d5209f"
            "439851db43d0ba5997337df154668eb"
        );
    }

    test_chunking();
    test_block_compression();
    test_defensive_and_overflow();

    printf(
        "==========================================\n"
    );

    if (g_failed != 0) {
        printf(
            "FAILED: %d test group(s)\n",
            g_failed
        );

        return EXIT_FAILURE;
    }

    printf("ALL TESTS PASSED\n");

    return EXIT_SUCCESS;
}
