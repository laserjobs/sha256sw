#!/usr/bin/env python3
"""
SHA-256 Collision / Differential Research Harness

Modes:
  --self-test
      Run deterministic implementation and construction checks.

  default / SMT search
      Search for a reduced-round collision using Z3.

  --flawed-schedule
      Search the intentionally simplified/research SHA-256 schedule.

  --zero-start N --zero-rounds N
      Constrain a differential window so the two executions have identical
      internal state throughout the selected interval.

  --floyd
      Run an O(1)-memory empirical cycle search.

This is a reduced-round/research tool. It does NOT claim to find
full 64-round SHA-256 collisions.
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
import time
from typing import Iterable, Optional

try:
    import z3
except ImportError:
    print("ERROR: z3-solver is not installed.", file=sys.stderr)
    print("Install with: python3 -m pip install z3-solver", file=sys.stderr)
    sys.exit(1)


MASK32 = 0xFFFFFFFF

INITIAL_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# Published/research 39-round construction used by the supplied HTML.
COLLISION_IV = (
    0x02B19D5A,
    0x88E1DF04,
    0x5EA3C7B7,
    0xF2F7D1A4,
    0x86CB1B1F,
    0xC8EE51A5,
    0x1B4D0541,
    0x651B92E7,
)

W0_COLLISION = (
    0xC61D6DE7, 0x755336E8, 0x5E61D618, 0x18036DE6,
    0xA79F2F1D, 0xF2B44C7B, 0x4C0EF36B, 0xA85D45CF,
    0xE72B8C2F, 0x0FCF907C, 0xB0EAB159, 0x81A1BFC1,
    0x4B098611, 0x7AAD07F6, 0x33CD6902, 0x3BAD5D64,
)

W1_COLLISION = (
    0xC61D6DE7, 0x755336E8, 0x5E61D618, 0x18036DE6,
    0xA79F2F1D, 0xF2B44C7B, 0x4C0EF36B, 0xA85D45CF,
    0xF72B8C2F, 0x0DEF947C, 0xA0EAB159, 0x8021370C,
    0x4B0D8011, 0x7AAD07F6, 0x33CD6902, 0x3BAD5D64,
)

K39 = K[:39]


# ---------------------------------------------------------------------------
# Concrete SHA-256 primitives
# ---------------------------------------------------------------------------

def u32(x: int) -> int:
    return x & MASK32


def rotr(x: int, n: int) -> int:
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr(x: int, n: int) -> int:
    return (x & MASK32) >> n


def sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def big_sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x) & z)) & MASK32


def maj(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def sha256_schedule(block: Iterable[int], rounds: int) -> list[int]:
    block = [u32(x) for x in block]

    if len(block) != 16:
        raise ValueError("SHA-256 block must contain exactly 16 words")

    w = block[:]

    for i in range(16, rounds):
        w.append(
            u32(
                w[i - 16]
                + sigma0(w[i - 15])
                + w[i - 7]
                + sigma1(w[i - 2])
            )
        )

    return w


def compress_rounds(
    block: Iterable[int],
    iv: Iterable[int],
    rounds: int,
    constants: tuple[int, ...] = K,
) -> tuple[tuple[int, ...], list[tuple[int, ...]]]:
    block = tuple(u32(x) for x in block)
    iv = tuple(u32(x) for x in iv)

    if len(iv) != 8:
        raise ValueError("IV must contain exactly 8 words")

    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be in the range 1..64")

    w = sha256_schedule(block, rounds)

    a, b, c, d, e, f, g, h = iv
    states = [(a, b, c, d, e, f, g, h)]

    for i in range(rounds):
        t1 = u32(
            h
            + big_sigma1(e)
            + ch(e, f, g)
            + constants[i]
            + w[i]
        )
        t2 = u32(
            big_sigma0(a)
            + maj(a, b, c)
        )

        h = g
        g = f
        f = e
        e = u32(d + t1)
        d = c
        c = b
        b = a
        a = u32(t1 + t2)

        states.append((a, b, c, d, e, f, g, h))

    final_state = tuple(
        u32(iv[i] + states[-1][i])
        for i in range(8)
    )

    return final_state, states


# ---------------------------------------------------------------------------
# Flawed/research schedule
# ---------------------------------------------------------------------------

def flawed_forward(
    block: Iterable[int],
    iv: Iterable[int] = INITIAL_IV,
    rounds: int = 64,
) -> tuple[tuple[int, ...], list[tuple[int, ...]]]:
    """
    Research-only simplified schedule.

    The supplied HTML exposes the relationship:

        b[i + 20] = b[i + 4]

    together with additional accumulated terms.

    This implementation follows that construction directly enough for
    forward/research experimentation while retaining a normal 8-word
    compression-state representation.
    """

    block = tuple(u32(x) for x in block)
    iv = tuple(u32(x) for x in iv)

    if len(block) != 16:
        raise ValueError("block must contain 16 words")
    if len(iv) != 8:
        raise ValueError("IV must contain 8 words")
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be in 1..64")

    # The original representation uses a[0..67], b[0..67].
    a = [0] * 68
    b = [0] * 68

    for i in range(4):
        a[i] = iv[3 - i]
        b[i] = iv[7 - i]

    for i in range(16):
        b[i + 4] = block[i]

    for i in range(20, 68):
        b[i] = 0

    states = []

    for i in range(rounds):
        if i > 13 and i < 62 and i + 6 < 68:
            b[i + 6] = u32(b[i + 6] + sigma1(b[i + 4]))

        if i > 8 and i < 57 and i + 11 < 68:
            b[i + 11] = u32(b[i + 11] + b[i + 4])

        if i > 0 and i < 49 and i + 19 < 68:
            b[i + 19] = u32(b[i + 19] + sigma0(b[i + 4]))

        if i < 48 and i + 20 < 68:
            b[i + 20] = b[i + 4]

        t1 = u32(
            b[i + 4]
            + K[i]
            + a[i]
            + b[i]
            + sigma1(b[i + 3])
            + ch(b[i + 3], b[i + 2], b[i + 1])
        )

        t2 = u32(
            big_sigma0(a[i + 3])
            + maj(a[i + 3], a[i + 1], a[i + 2])
        )

        b[i + 4] = t1
        a[i + 4] = u32(t1 - a[i] + t2)

        states.append(
            (
                a[i + 4],
                a[i + 3],
                a[i + 2],
                a[i + 1],
                b[i + 4],
                b[i + 3],
                b[i + 2],
                b[i + 1],
            )
        )

    final = tuple(
        u32(iv[i] + a[67 - i])
        for i in range(4)
    ) + tuple(
        u32(iv[i + 4] + b[67 - i])
        for i in range(4)
    )

    return final, states


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def hx(x: int) -> str:
    return f"{x & MASK32:08x}"


def vector_hex(v: Iterable[int]) -> str:
    return " ".join(hx(x) for x in v)


def print_header(title: str) -> None:
    print("=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------------------
# Known 39-round construction
# ---------------------------------------------------------------------------

def verify_known_39_collision() -> bool:
    print_header("KNOWN 39-ROUND COLLISION VERIFICATION")

    print(f"Rounds : 39")
    print(f"IV     : {vector_hex(COLLISION_IV)}")
    print()

    h0, _ = compress_rounds(
        W0_COLLISION,
        COLLISION_IV,
        39,
        K39,
    )

    h1, _ = compress_rounds(
        W1_COLLISION,
        COLLISION_IV,
        39,
        K39,
    )

    different = W0_COLLISION != W1_COLLISION
    collision = h0 == h1

    print(f"M1 != M2       : {different}")
    print(f"H(M1)          : {vector_hex(h0)}")
    print(f"H(M2)          : {vector_hex(h1)}")
    print(f"Collision valid: {collision}")

    if not different:
        print("ERROR: supplied messages are identical")
        return False

    if not collision:
        print(
            "\nWARNING: the supplied 39-round construction does not "
            "match this implementation."
        )
        return False

    print("\n[+] Known 39-round construction verified.")
    return True


# ---------------------------------------------------------------------------
# Z3 symbolic model
# ---------------------------------------------------------------------------

def bv32(x: int | z3.BitVecRef) -> z3.BitVecRef:
    if isinstance(x, int):
        return z3.BitVecVal(x & MASK32, 32)
    return x


def zrotr(x: z3.BitVecRef, n: int) -> z3.BitVecRef:
    return z3.RotateRight(x, n)


def zsigma0(x: z3.BitVecRef) -> z3.BitVecRef:
    return zrotr(x, 7) ^ zrotr(x, 18) ^ z3.LShR(x, 3)


def zsigma1(x: z3.BitVecRef) -> z3.BitVecRef:
    return zrotr(x, 17) ^ zrotr(x, 19) ^ z3.LShR(x, 10)


def zbig0(x: z3.BitVecRef) -> z3.BitVecRef:
    return zrotr(x, 2) ^ zrotr(x, 13) ^ zrotr(x, 22)


def zbig1(x: z3.BitVecRef) -> z3.BitVecRef:
    return zrotr(x, 6) ^ zrotr(x, 11) ^ zrotr(x, 25)


def zch(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef):
    return (x & y) ^ (~x & z)


def zmaj(x: z3.BitVecRef, y: z3.BitVecRef, z: z3.BitVecRef):
    return (x & y) ^ (x & z) ^ (y & z)


def build_standard_symbolic(
    solver: z3.Solver,
    rounds: int,
    iv: tuple[int, ...],
    prefix: str,
):
    m = [
        z3.BitVec(f"{prefix}_m_{i}", 32)
        for i in range(16)
    ]

    w = m[:]

    for i in range(16, rounds):
        w.append(
            zsigma1(w[i - 2])
            + w[i - 7]
            + zsigma0(w[i - 15])
            + w[i - 16]
        )

    a, b, c, d, e, f, g, h = [
        z3.BitVecVal(x, 32) for x in iv
    ]

    states = [
        (a, b, c, d, e, f, g, h)
    ]

    for i in range(rounds):
        t1 = (
            h
            + zbig1(e)
            + zch(e, f, g)
            + z3.BitVecVal(K[i], 32)
            + w[i]
        )

        t2 = zbig0(a) + zmaj(a, b, c)

        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

        states.append((a, b, c, d, e, f, g, h))

    output = tuple(
        z3.BitVecVal(iv[i], 32) + states[-1][i]
        for i in range(8)
    )

    return m, w, states, output


def build_flawed_symbolic(
    solver: z3.Solver,
    rounds: int,
    iv: tuple[int, ...],
    prefix: str,
):
    """
    Symbolic version of the simplified/research schedule.

    The representation deliberately keeps the schedule dependencies explicit
    so Z3 can exploit equalities instead of treating every W[i] as independent.
    """

    if rounds > 64:
        raise ValueError("rounds must be <= 64")

    m = [
        z3.BitVec(f"{prefix}_m_{i}", 32)
        for i in range(16)
    ]

    a = [
        z3.BitVecVal(0, 32)
        for _ in range(68)
    ]

    b = [
        z3.BitVecVal(0, 32)
        for _ in range(68)
    ]

    for i in range(4):
        a[i] = z3.BitVecVal(iv[3 - i], 32)
        b[i] = z3.BitVecVal(iv[7 - i], 32)

    for i in range(16):
        b[i + 4] = m[i]

    states = [
        (
            a[0],
            a[1],
            a[2],
            a[3],
            b[0],
            b[1],
            b[2],
            b[3],
        )
    ]

    for i in range(rounds):
        if i > 13 and i < 62 and i + 6 < 68:
            b[i + 6] = b[i + 6] + zsigma1(b[i + 4])

        if i > 8 and i < 57 and i + 11 < 68:
            b[i + 11] = b[i + 11] + b[i + 4]

        if i > 0 and i < 49 and i + 19 < 68:
            b[i + 19] = b[i + 19] + zsigma0(b[i + 4])

        if i < 48 and i + 20 < 68:
            b[i + 20] = b[i + 4]

        t1 = (
            b[i + 4]
            + z3.BitVecVal(K[i], 32)
            + a[i]
            + b[i]
            + zbig1(b[i + 3])
            + zch(b[i + 3], b[i + 2], b[i + 1])
        )

        t2 = (
            zbig0(a[i + 3])
            + zmaj(a[i + 3], a[i + 1], a[i + 2])
        )

        b[i + 4] = t1
        a[i + 4] = t1 - a[i] + t2

        states.append(
            (
                a[i + 4],
                a[i + 3],
                a[i + 2],
                a[i + 1],
                b[i + 4],
                b[i + 3],
                b[i + 2],
                b[i + 1],
            )
        )

    final = tuple(
        z3.BitVecVal(iv[i], 32) + a[67 - i]
        for i in range(4)
    ) + tuple(
        z3.BitVecVal(iv[i + 4], 32) + b[67 - i]
        for i in range(4)
    )

    return m, states, final


def add_distinct_messages(
    solver: z3.Solver,
    m1,
    m2,
) -> None:
    solver.add(
        z3.Or(
            *[
                m1[i] != m2[i]
                for i in range(16)
            ]
        )
    )


def add_zero_differential_window(
    solver: z3.Solver,
    states1,
    states2,
    start: int,
    length: int,
) -> None:
    """
    Require the complete internal chaining state to be equal across the
    selected differential window.

    State indices:
        0 = input state
        1 = after round 1
        ...
    """

    if start < 0:
        raise ValueError("zero-start must be >= 0")

    if length < 1:
        raise ValueError("zero-rounds must be >= 1")

    end = start + length

    if end > min(len(states1), len(states2)) - 1:
        raise ValueError(
            f"zero window {start}..{end} exceeds available rounds"
        )

    for r in range(start, end + 1):
        for i in range(8):
            solver.add(states1[r][i] == states2[r][i])


def write_smt(solver: z3.Solver, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        f.write(solver.sexpr())
        f.write("\n")


def model_words(model: z3.ModelRef, variables) -> tuple[int, ...]:
    result = []

    for v in variables:
        value = model.eval(v, model_completion=True)
        result.append(value.as_long() & MASK32)

    return tuple(result)


def verify_candidate(
    m1: tuple[int, ...],
    m2: tuple[int, ...],
    rounds: int,
    iv: tuple[int, ...],
    flawed: bool,
) -> bool:
    if flawed:
        h1, _ = flawed_forward(m1, iv, rounds)
        h2, _ = flawed_forward(m2, iv, rounds)
    else:
        h1, _ = compress_rounds(m1, iv, rounds)
        h2, _ = compress_rounds(m2, iv, rounds)

    return m1 != m2 and h1 == h2


def run_smt_search(args) -> int:
    print_header("SHA-256 DIFFERENTIAL RESEARCH MODE")

    rounds = args.rounds
    timeout = args.timeout

    print(f"Solver       : z3")
    print(f"Rounds       : {rounds}")
    print(f"Model        : {'Flawed-Schedule' if args.flawed_schedule else 'Standard'}")

    if args.zero_rounds:
        print(f"Zero start   : {args.zero_start}")
        print(f"Zero rounds  : {args.zero_rounds}")
        print(
            f"Zero interval: "
            f"{args.zero_start}..{args.zero_start + args.zero_rounds}"
        )
    else:
        print("Zero window  : disabled")

    print(f"Timeout      : {timeout}s")

    solver = z3.Solver()

    if timeout > 0:
        solver.set(timeout=int(timeout * 1000))

    iv = tuple(args.iv) if args.iv else INITIAL_IV

    if args.flawed_schedule:
        m1, states1, out1 = build_flawed_symbolic(
            solver, rounds, iv, "m1"
        )
        m2, states2, out2 = build_flawed_symbolic(
            solver, rounds, iv, "m2"
        )
    else:
        m1, _, states1, out1 = build_standard_symbolic(
            solver, rounds, iv, "m1"
        )
        m2, _, states2, out2 = build_standard_symbolic(
            solver, rounds, iv, "m2"
        )

    add_distinct_messages(solver, m1, m2)

    # Equal compression outputs.
    for i in range(8):
        solver.add(out1[i] == out2[i])

    if args.zero_rounds:
        add_zero_differential_window(
            solver,
            states1,
            states2,
            args.zero_start,
            args.zero_rounds,
        )

    if args.dump_smt:
        write_smt(solver, args.dump_smt)
        print(f"Generated SMT problem: {args.dump_smt}")

    print("Searching...")
    started = time.perf_counter()
    result = solver.check()
    elapsed = time.perf_counter() - started

    print(f"Status : {result}")
    print(f"Time   : {elapsed:.3f}s")

    if result == z3.sat:
        model = solver.model()

        block1 = model_words(model, m1)
        block2 = model_words(model, m2)

        print()
        print("Candidate collision:")
        print(f"M1 = {vector_hex(block1)}")
        print(f"M2 = {vector_hex(block2)}")

        if args.flawed_schedule:
            h1, _ = flawed_forward(block1, iv, rounds)
            h2, _ = flawed_forward(block2, iv, rounds)
        else:
            h1, _ = compress_rounds(block1, iv, rounds)
            h2, _ = compress_rounds(block2, iv, rounds)

        print()
        print("Independent verification:")
        print(f"M1 != M2       : {block1 != block2}")
        print(f"H(M1)          : {vector_hex(h1)}")
        print(f"H(M2)          : {vector_hex(h2)}")
        print(f"Collision valid : {h1 == h2}")

        valid = verify_candidate(
            block1,
            block2,
            rounds,
            iv,
            args.flawed_schedule,
        )

        if not valid:
            print("ERROR: solver candidate failed independent verification.")
            return 3

        print("\n[+] Collision verified.")
        return 0

    if result == z3.unsat:
        print("\n[-] No collision exists under the supplied constraints.")
        return 1

    print("\n[!] Solver returned unknown/timeout.")
    return 2


# ---------------------------------------------------------------------------
# Floyd cycle search
# ---------------------------------------------------------------------------

def floyd_next(
    state: tuple[int, ...],
    flawed: bool,
    rounds: int,
) -> tuple[int, ...]:
    """
    Deterministic state transition used by the empirical cycle finder.

    A fixed block is derived from the current state so the transition is
    deterministic and Floyd's algorithm can operate with O(1) memory.
    """

    block = (
        state[0],
        state[1],
        state[2],
        state[3],
        state[4],
        state[5],
        state[6],
        state[7],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )

    if flawed:
        h, _ = flawed_forward(block, state, rounds)
    else:
        h, _ = compress_rounds(block, state, rounds)

    return h


def run_floyd(args) -> int:
    print_header("SHA-256 FLOYD CYCLE SEARCH")

    rng = random.Random(args.seed)

    if args.iv:
        start = tuple(args.iv)
    else:
        start = tuple(
            rng.getrandbits(32)
            for _ in range(8)
        )

    print(f"Rounds : {args.rounds}")
    print(f"Seed   : {args.seed}")
    print(f"Start  : {vector_hex(start)}")
    print("Searching...")

    tortoise = floyd_next(
        start,
        args.flawed_schedule,
        args.rounds,
    )

    hare = floyd_next(
        floyd_next(
            start,
            args.flawed_schedule,
            args.rounds,
        ),
        args.flawed_schedule,
        args.rounds,
    )

    started = time.perf_counter()

    for iteration in range(1, args.max_iterations + 1):
        if tortoise == hare:
            elapsed = time.perf_counter() - started

            print()
            print("Cycle detected.")
            print(f"Iteration : {iteration}")
            print(f"Time      : {elapsed:.3f}s")
            print(f"Meeting   : {vector_hex(tortoise)}")

            return 0

        tortoise = floyd_next(
            tortoise,
            args.flawed_schedule,
            args.rounds,
        )

        hare = floyd_next(
            floyd_next(
                hare,
                args.flawed_schedule,
                args.rounds,
            ),
            args.flawed_schedule,
            args.rounds,
        )

        if iteration % args.report_every == 0:
            elapsed = time.perf_counter() - started
            rate = iteration / elapsed if elapsed else 0
            print(
                f"Iteration {iteration:,} "
                f"({rate:,.1f} transitions/s)"
            )

    print()
    print(
        f"No cycle detected in {args.max_iterations:,} iterations."
    )
    return 1


# ---------------------------------------------------------------------------
# Self-tests
# ---------------------------------------------------------------------------

def self_test_sha256() -> bool:
    """
    Verify our full 64-round implementation against hashlib for a
    single-block SHA-256 message.

    The comparison deliberately normalizes our 8-word display format
    (which contains spaces) to the continuous hexadecimal format returned
    by hashlib.hexdigest().
    """

    message = b"abc"

    # Build the single 512-bit SHA-256 block for "abc".
    block_bytes = bytearray(64)
    block_bytes[:len(message)] = message
    block_bytes[len(message)] = 0x80

    bit_length = len(message) * 8
    block_bytes[56:64] = bit_length.to_bytes(8, "big")

    block = tuple(
        int.from_bytes(
            block_bytes[i:i + 4],
            "big",
        )
        for i in range(0, 64, 4)
    )

    digest, _ = compress_rounds(
        block,
        INITIAL_IV,
        64,
    )

    # vector_hex() is intentionally human-readable and inserts spaces
    # between 32-bit words. hashlib.hexdigest() does not.
    ours = "".join(
        f"{word & MASK32:08x}"
        for word in digest
    )

    reference = hashlib.sha256(message).hexdigest()

    print("SHA-256 abc:")
    print(f"  implementation: {vector_hex(digest)}")
    print(f"  hashlib       : {reference}")

    if ours != reference:
        print()
        print("ERROR: SHA-256 implementation mismatch.")
        print(f"  normalized implementation: {ours}")
        print(f"  hashlib reference        : {reference}")
        return False

    return True



def self_test_primitives() -> bool:
    tests = [
        (rotr(0x12345678, 4), 0x81234567),
        (sigma0(0), 0),
        (sigma1(0), 0),
        (big_sigma0(0), 0),
        (big_sigma1(0), 0),
        (ch(0xFFFFFFFF, 0x12345678, 0xABCDEF01), 0x12345678),
        (maj(0xFFFFFFFF, 0x12345678, 0xABCDEF01),
         0xABCDEF01 | 0x12345678),
    ]

    for got, expected in tests:
        if u32(got) != u32(expected):
            print(
                f"Primitive test failed: "
                f"{got:08x} != {expected:08x}"
            )
            return False

    return True


def self_test_solver() -> bool:
    print("Z3 version:", z3.get_version_string())

    x = z3.BitVec("selftest_x", 32)
    s = z3.Solver()
    s.add(x == z3.BitVecVal(0x12345678, 32))

    if s.check() != z3.sat:
        return False

    value = s.model().eval(x).as_long()

    return value == 0x12345678


def run_self_tests() -> int:
    print_header("SHA-256 COLLISION FINDER SELF-TEST")

    checks = []

    print("\n[1/4] Primitive tests...")
    checks.append(self_test_primitives())
    print("PASS" if checks[-1] else "FAIL")

    print("\n[2/4] SHA-256 implementation test...")
    checks.append(self_test_sha256())
    print("PASS" if checks[-1] else "FAIL")

    print("\n[3/4] Z3 test...")
    checks.append(self_test_solver())
    print("PASS" if checks[-1] else "FAIL")

    print("\n[4/4] Known 39-round construction...")
    checks.append(verify_known_39_collision())
    print("PASS" if checks[-1] else "FAIL")

    print()
    if all(checks):
        print("[+] ALL SELF-TESTS PASSED")
        return 0

    print("[-] SELF-TEST FAILURE")
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_hex_word(value: str) -> int:
    value = value.strip()

    if value.lower().startswith("0x"):
        value = value[2:]

    if not 1 <= len(value) <= 8:
        raise argparse.ArgumentTypeError(
            f"invalid 32-bit word: {value}"
        )

    try:
        number = int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid hexadecimal word: {value}"
        )

    if number > MASK32:
        raise argparse.ArgumentTypeError(
            f"word exceeds 32 bits: {value}"
        )

    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SHA-256 reduced-round collision research finder"
    )

    parser.add_argument(
        "--solver",
        choices=("z3",),
        default="z3",
        help="symbolic solver backend",
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=4,
        help="number of compression rounds (default: 4)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Z3 timeout in seconds",
    )

    parser.add_argument(
        "--iv",
        type=parse_hex_word,
        nargs=8,
        metavar="WORD",
        help="custom 8-word IV",
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=1,
        help="deterministic seed for empirical searches",
    )

    parser.add_argument(
        "--dump-smt",
        metavar="FILE",
        help="write generated SMT-LIB to FILE",
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run deterministic self-tests",
    )

    parser.add_argument(
        "--flawed-schedule",
        action="store_true",
        help="use the intentionally simplified research schedule",
    )

    parser.add_argument(
        "--zero-start",
        type=int,
        default=0,
        help="start of the zero-differential window",
    )

    parser.add_argument(
        "--zero-rounds",
        type=int,
        default=0,
        help="number of rounds in the zero-differential window",
    )

    parser.add_argument(
        "--floyd",
        action="store_true",
        help="run the O(1)-memory Floyd cycle search",
    )

    parser.add_argument(
        "--max-iterations",
        type=int,
        default=100_000,
        help="maximum Floyd iterations",
    )

    parser.add_argument(
        "--report-every",
        type=int,
        default=10_000,
        help="Floyd progress interval",
    )

    return parser


def validate_args(args) -> None:
    if not 1 <= args.rounds <= 64:
        raise ValueError("--rounds must be between 1 and 64")

    if args.timeout < 0:
        raise ValueError("--timeout cannot be negative")

    if args.zero_rounds < 0:
        raise ValueError("--zero-rounds cannot be negative")

    if args.zero_start < 0:
        raise ValueError("--zero-start cannot be negative")

    if args.zero_rounds:
        if args.zero_start + args.zero_rounds > args.rounds:
            raise ValueError(
                "zero window extends beyond requested round count"
            )

    if args.max_iterations < 1:
        raise ValueError("--max-iterations must be positive")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        validate_args(args)
    except ValueError as exc:
        parser.error(str(exc))

    if args.self_test:
        return run_self_tests()

    if args.floyd:
        return run_floyd(args)

    return run_smt_search(args)


if __name__ == "__main__":
    sys.exit(main())
