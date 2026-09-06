#!/usr/bin/env python3
"""
SHA256 reduced-round differential research / verification tool.

This program is intended for experimentation with reduced-round SHA-256
compression and verification of known constructions.

It provides:

  * A concrete reduced-round SHA-256 compression implementation.
  * The supplied 39-round collision as a known-answer regression test.
  * A Z3 model for checking a prescribed differential zero window.
  * A movable 16-round zero-difference-window experiment.
  * SMT2 export.
  * Independent concrete verification.

It deliberately does NOT attempt to construct a new full 64-round
SHA-256 collision.

Examples:

    python3 benchmark/collision_finder.py --self-test

    python3 benchmark/collision_finder.py \
        --rounds 39 \
        --zero-start 12 \
        --zero-rounds 16

    python3 benchmark/collision_finder.py \
        --rounds 39 \
        --zero-start 12 \
        --zero-rounds 16 \
        --dump-smt differential.smt2
"""

from __future__ import annotations

import argparse
import sys
import time
from dataclasses import dataclass
from typing import Iterable

try:
    import z3
except ImportError:
    print(
        "ERROR: Python package 'z3-solver' is required.\n"
        "Install it with:\n"
        "  python3 -m pip install z3-solver",
        file=sys.stderr,
    )
    raise


MASK32 = 0xFFFFFFFF

K = [
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
]

INITIAL_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

# Supplied 39-round construction.
H0_COLLISION = [
    0x02B19D5A, 0x88E1DF04, 0x5EA3C7B7, 0xF2F7D1A4,
    0x86CB1B1F, 0xC8EE51A5, 0x1B4D0541, 0x651B92E7,
]

W0_COLLISION = [
    0xC61D6DE7, 0x755336E8, 0x5E61D618, 0x18036DE6,
    0xA79F2F1D, 0xF2B44C7B, 0x4C0EF36B, 0xA85D45CF,
    0xE72B8C2F, 0x0FCF907C, 0xB0EAB159, 0x81A1BFC1,
    0x4B098611, 0x7AAD07F6, 0x33CD6902, 0x3BAD5D64,
]

W1_COLLISION = [
    0xC61D6DE7, 0x755336E8, 0x5E61D618, 0x18036DE6,
    0xA79F2F1D, 0xF2B44C7B, 0x4C0EF36B, 0xA85D45CF,
    0xF72B8C2F, 0x0DEF947C, 0xA0EAB159, 0x8021370C,
    0x4B0D8011, 0x7AAD07F6, 0x33CD6902, 0x3BAD5D64,
]


def u32(x: int) -> int:
    return x & MASK32


def rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr(x: int, n: int) -> int:
    return x >> n


def ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (~x & z)) & MASK32


def maj(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def big_sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def small_sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def expand_schedule(block: Iterable[int], rounds: int) -> list[int]:
    w = [u32(x) for x in block]

    if len(w) != 16:
        raise ValueError("SHA-256 block must contain exactly 16 words")

    for i in range(16, rounds):
        w.append(
            u32(
                w[i - 16]
                + small_sigma0(w[i - 15])
                + w[i - 7]
                + small_sigma1(w[i - 2])
            )
        )

    return w


@dataclass
class CompressionResult:
    state: list[int]
    states: list[list[int]]
    schedule: list[int]


def compress(block: Iterable[int], iv: Iterable[int], rounds: int) -> CompressionResult:
    if rounds < 1 or rounds > 64:
        raise ValueError("rounds must be between 1 and 64")

    state = [u32(x) for x in iv]
    if len(state) != 8:
        raise ValueError("IV must contain exactly 8 words")

    w = expand_schedule(block, rounds)

    a, b, c, d, e, f, g, h = state
    states = [[a, b, c, d, e, f, g, h]]

    for i in range(rounds):
        t1 = u32(
            h
            + big_sigma1(e)
            + ch(e, f, g)
            + K[i]
            + w[i]
        )
        t2 = u32(big_sigma0(a) + maj(a, b, c))

        h = g
        g = f
        f = e
        e = u32(d + t1)
        d = c
        c = b
        b = a
        a = u32(t1 + t2)

        states.append([a, b, c, d, e, f, g, h])

    final = [
        u32(state[i] + states[-1][i])
        for i in range(8)
    ]

    return CompressionResult(
        state=final,
        states=states,
        schedule=w,
    )


def fmt_words(words: Iterable[int]) -> str:
    return " ".join(f"{u32(x):08x}" for x in words)


def state_equal(a: Iterable[int], b: Iterable[int]) -> bool:
    return all(u32(x) == u32(y) for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Z3 differential helpers
# ---------------------------------------------------------------------------

def z3_rotr(x, n):
    return z3.RotateRight(x, n)


def z3_shr(x, n):
    return z3.LShR(x, n)


def z3_ch(x, y, z):
    return (x & y) ^ (~x & z)


def z3_maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def z3_sigma0(x):
    return z3_rotr(x, 2) ^ z3_rotr(x, 13) ^ z3_rotr(x, 22)


def z3_sigma1(x):
    return z3_rotr(x, 6) ^ z3_rotr(x, 11) ^ z3_rotr(x, 25)


def z3_small_sigma0(x):
    return (
        z3_rotr(x, 7)
        ^ z3_rotr(x, 18)
        ^ z3_shr(x, 3)
    )


def z3_small_sigma1(x):
    return (
        z3_rotr(x, 17)
        ^ z3_rotr(x, 19)
        ^ z3_shr(x, 10)
    )


def make_symbolic_schedule(prefix: str, rounds: int):
    w = [
        z3.BitVec(f"{prefix}_w_{i}", 32)
        for i in range(rounds)
    ]

    constraints = []

    for i in range(16, rounds):
        constraints.append(
            w[i]
            == (
                w[i - 16]
                + z3_small_sigma0(w[i - 15])
                + w[i - 7]
                + z3_small_sigma1(w[i - 2])
            )
        )

    return w, constraints


def make_symbolic_compression(prefix: str, rounds: int, iv):
    w, constraints = make_symbolic_schedule(prefix, rounds)

    states = [
        [
            z3.BitVec(f"{prefix}_s_0_{j}", 32)
            for j in range(8)
        ]
    ]

    for i in range(1, rounds + 1):
        states.append(
            [
                z3.BitVec(f"{prefix}_s_{i}_{j}", 32)
                for j in range(8)
            ]
        )

    constraints.extend(
        states[0][j] == z3.BitVecVal(u32(iv[j]), 32)
        for j in range(8)
    )

    for i in range(rounds):
        a, b, c, d, e, f, g, h = states[i]
        na, nb, nc, nd, ne, nf, ng, nh = states[i + 1]

        t1 = (
            h
            + z3_sigma1(e)
            + z3_ch(e, f, g)
            + z3.BitVecVal(K[i], 32)
            + w[i]
        )

        t2 = z3_sigma0(a) + z3_maj(a, b, c)

        constraints.extend(
            [
                na == t1 + t2,
                nb == a,
                nc == b,
                nd == c,
                ne == d + t1,
                nf == e,
                ng == f,
                nh == g,
            ]
        )

    return w, states, constraints


def build_zero_window_model(
    rounds: int,
    zero_start: int,
    zero_rounds: int,
    iv: list[int],
):
    """
    Build a differential model with two independently scheduled messages.

    The two compression states are constrained to be identical at every
    state boundary from zero_start through zero_start + zero_rounds.

    This is a verification/research model: it does not impose a complete
    construction for the unconstrained regions.
    """
    zero_end = zero_start + zero_rounds

    if zero_start < 0:
        raise ValueError("zero-start must be >= 0")

    if zero_end > rounds:
        raise ValueError(
            "zero window must fit entirely inside the selected round range"
        )

    w0, s0, c0 = make_symbolic_compression("m0", rounds, iv)
    w1, s1, c1 = make_symbolic_compression("m1", rounds, iv)

    solver = z3.Solver()

    solver.add(*(c0 + c1))

    # The two message schedules must differ somewhere.
    solver.add(
        z3.Or(
            [
                w0[i] != w1[i]
                for i in range(rounds)
            ]
        )
    )

    # Explicit zero-difference interval.
    for r in range(zero_start, zero_end + 1):
        for j in range(8):
            solver.add(s0[r][j] == s1[r][j])

    return solver, w0, w1, s0, s1


def check_zero_window(
    result0: CompressionResult,
    result1: CompressionResult,
    zero_start: int,
    zero_rounds: int,
) -> bool:
    end = zero_start + zero_rounds

    if end >= len(result0.states):
        return False

    return all(
        state_equal(result0.states[r], result1.states[r])
        for r in range(zero_start, end + 1)
    )


def run_zero_window(
    rounds: int,
    zero_start: int,
    zero_rounds: int,
    timeout: int,
    dump_smt: str | None,
    iv: list[int],
) -> int:
    print("=" * 72)
    print("SHA256 DIFFERENTIAL RESEARCH MODE")
    print("=" * 72)
    print(f"Rounds       : {rounds}")
    print(f"Zero start   : {zero_start}")
    print(f"Zero rounds  : {zero_rounds}")
    print(f"Zero interval: {zero_start}..{zero_start + zero_rounds}")
    print(f"Timeout      : {timeout}s")
    print()

    solver, w0, w1, s0, s1 = build_zero_window_model(
        rounds=rounds,
        zero_start=zero_start,
        zero_rounds=zero_rounds,
        iv=iv,
    )

    solver.set(timeout=timeout * 1000)

    if dump_smt:
        with open(dump_smt, "w", encoding="utf-8") as f:
            f.write(solver.to_smt2())

        print(f"Generated SMT problem: {dump_smt}")
        print()

    print("Searching...")
    start = time.monotonic()
    status = solver.check()
    elapsed = time.monotonic() - start

    print(f"Status : {status}")
    print(f"Time   : {elapsed:.3f}s")
    print()

    if status == z3.unknown:
        print("Solver returned unknown/timeout.")
        return 2

    if status == z3.unsat:
        print("No solution satisfies the requested differential constraints.")
        return 1

    model = solver.model()

    msg0 = [
        model.eval(w0[i], model_completion=True).as_long()
        for i in range(16)
    ]

    msg1 = [
        model.eval(w1[i], model_completion=True).as_long()
        for i in range(16)
    ]

    print("Candidate symbolic messages:")
    print(f"M1 = {fmt_words(msg0)}")
    print(f"M2 = {fmt_words(msg1)}")
    print()

    # Concrete verification.
    concrete0 = compress(msg0, iv, rounds)
    concrete1 = compress(msg1, iv, rounds)

    different = msg0 != msg1
    zero_ok = check_zero_window(
        concrete0,
        concrete1,
        zero_start,
        zero_rounds,
    )

    print("Independent verification:")
    print(f"M1 != M2       : {different}")
    print(f"Zero window    : {zero_ok}")
    print(f"H(M1)          : {fmt_words(concrete0.state)}")
    print(f"H(M2)          : {fmt_words(concrete1.state)}")

    if different and zero_ok:
        print()
        print("[+] Differential constraints independently verified.")
        return 0

    print()
    print("[-] Independent verification failed.")
    return 1


# ---------------------------------------------------------------------------
# Known 39-round construction
# ---------------------------------------------------------------------------

def run_39_round_regression() -> int:
    print("=" * 72)
    print("SHA256 39-ROUND KNOWN COLLISION REGRESSION")
    print("=" * 72)

    r0 = compress(W0_COLLISION, H0_COLLISION, 39)
    r1 = compress(W1_COLLISION, H0_COLLISION, 39)

    different = W0_COLLISION != W1_COLLISION
    collision = state_equal(r0.state, r1.state)

    print(f"Initial IV : {fmt_words(H0_COLLISION)}")
    print(f"M1         : {fmt_words(W0_COLLISION)}")
    print(f"M2         : {fmt_words(W1_COLLISION)}")
    print()
    print(f"M1 != M2   : {different}")
    print(f"H(M1)      : {fmt_words(r0.state)}")
    print(f"H(M2)      : {fmt_words(r1.state)}")
    print(f"Collision   : {collision}")

    if not different or not collision:
        print()
        print("[-] 39-round regression FAILED.")
        return 1

    print()
    print("[+] 39-round construction verified.")
    return 0


def run_self_test() -> int:
    print("Running self-tests...")
    print()

    rc = run_39_round_regression()
    if rc != 0:
        return rc

    print()
    print("Basic SHA-256 schedule test...")
    schedule = expand_schedule([0] * 16, 64)

    if len(schedule) != 64:
        print("[-] Schedule length test failed.")
        return 1

    print("[+] Schedule test passed.")
    print()
    print("[+] All self-tests passed.")
    return 0


def parse_hex_words(values: list[str], count: int) -> list[int]:
    if len(values) != count:
        raise ValueError(f"expected {count} hexadecimal words")

    result = []

    for value in values:
        value = value.strip()

        if value.lower().startswith("0x"):
            value = value[2:]

        if not value:
            raise ValueError("empty hexadecimal word")

        number = int(value, 16)

        if number < 0 or number > MASK32:
            raise ValueError(f"value out of 32-bit range: {value}")

        result.append(number)

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reduced-round SHA-256 differential research tool"
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=39,
        help="number of SHA-256 rounds to model (default: 39)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Z3 timeout in seconds (default: 60)",
    )

    parser.add_argument(
        "--zero-start",
        type=int,
        default=None,
        help="start round for the zero-difference window",
    )

    parser.add_argument(
        "--zero-rounds",
        type=int,
        default=16,
        help="width of zero-difference window (default: 16)",
    )

    parser.add_argument(
        "--iv",
        nargs=8,
        metavar="WORD",
        help="custom 8-word hexadecimal IV",
    )

    parser.add_argument(
        "--dump-smt",
        metavar="FILE",
        help="write generated differential model as SMT2",
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run known-answer and implementation self-tests",
    )

    args = parser.parse_args()

    try:
        if args.self_test:
            return run_self_test()

        iv = INITIAL_IV

        if args.iv is not None:
            iv = parse_hex_words(args.iv, 8)

        if args.rounds < 1 or args.rounds > 64:
            raise ValueError("--rounds must be between 1 and 64")

        if args.timeout < 1:
            raise ValueError("--timeout must be >= 1")

        # If no zero-start is supplied, run the known 39-round regression.
        if args.zero_start is None:
            if args.rounds != 39:
                print(
                    "No --zero-start supplied; running known 39-round "
                    "regression instead."
                )
            return run_39_round_regression()

        if args.zero_rounds < 1:
            raise ValueError("--zero-rounds must be >= 1")

        if args.zero_start + args.zero_rounds > args.rounds:
            raise ValueError(
                "--zero-start + --zero-rounds must not exceed --rounds"
            )

        return run_zero_window(
            rounds=args.rounds,
            zero_start=args.zero_start,
            zero_rounds=args.zero_rounds,
            timeout=args.timeout,
            dump_smt=args.dump_smt,
            iv=iv,
        )

    except (ValueError, OSError, z3.Z3Exception) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
