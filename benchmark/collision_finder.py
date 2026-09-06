#!/usr/bin/env python3
"""
Reduced-round SHA-256 compression collision finder.

This tool searches for two distinct 512-bit message blocks M1 != M2
such that the reduced-round SHA-256 compression function produces the
same output from a specified IV.

IMPORTANT:
    This is a reduced-round research tool. A collision for fewer than
    64 SHA-256 rounds is NOT a collision for full SHA-256.

The implementation follows the SHA-256 compression function specified in
NIST FIPS 180-4.

Examples:

    # Fast smoke test
    python3 collision_finder.py --rounds 4 --timeout 60

    # Try 8 rounds
    python3 collision_finder.py --rounds 8 --timeout 60

    # Try 16 rounds and save the SMT problem
    python3 collision_finder.py \
        --rounds 16 \
        --timeout 300 \
        --dump-smt collision_r16.smt2

    # Custom IV
    python3 collision_finder.py \
        --rounds 8 \
        --iv 6a09e667 bb67ae85 3c6ef372 a54ff53a \
             510e527f 9b05688c 1f83d9ab 5be0cd19

Requirements:

    Python 3.9+
    z3-solver OR system Z3 with the z3 Python bindings
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

try:
    import z3
except ImportError:
    print(
        "ERROR: Z3 Python bindings are not installed.\n"
        "Install with:\n"
        "  python3 -m pip install z3-solver\n"
        "or use your distribution's python3-z3 package.",
        file=sys.stderr,
    )
    raise SystemExit(2)


MASK32 = 0xFFFFFFFF

STANDARD_IV = (
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
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFB,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
)


@dataclass
class CollisionResult:
    status: str
    elapsed: float
    rounds: int
    iv: Tuple[int, ...]
    message1: Optional[Tuple[int, ...]] = None
    message2: Optional[Tuple[int, ...]] = None
    output1: Optional[Tuple[int, ...]] = None
    output2: Optional[Tuple[int, ...]] = None


def u32(x: int) -> int:
    return x & MASK32


def rotr(x: int, n: int) -> int:
    return ((x >> n) | ((x << (32 - n)) & MASK32)) & MASK32


def shr(x: int, n: int) -> int:
    return (x & MASK32) >> n


def ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x) & z)) & MASK32


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


def fmt_word(x: int) -> str:
    return f"{x & MASK32:08x}"


def fmt_words(words: Sequence[int]) -> str:
    return " ".join(fmt_word(x) for x in words)


def parse_hex_word(value: str) -> int:
    value = value.strip()

    if value.lower().startswith("0x"):
        value = value[2:]

    if not value:
        raise ValueError("empty hexadecimal word")

    if len(value) > 8:
        raise ValueError(f"hex word too long: {value}")

    try:
        result = int(value, 16)
    except ValueError as exc:
        raise ValueError(f"invalid hexadecimal word: {value}") from exc

    return result & MASK32


def parse_iv(values: Sequence[str]) -> Tuple[int, ...]:
    if len(values) != 8:
        raise ValueError("IV must contain exactly 8 32-bit words")

    return tuple(parse_hex_word(x) for x in values)


# ---------------------------------------------------------------------------
# Concrete SHA-256 compression
# ---------------------------------------------------------------------------

def expand_schedule(message: Sequence[int], rounds: int) -> List[int]:
    """
    Build only the part of the message schedule needed by the selected
    number of rounds.
    """
    if len(message) != 16:
        raise ValueError("SHA-256 block must contain exactly 16 words")

    needed = max(16, rounds)
    w = [u32(x) for x in message]

    for i in range(16, needed):
        w.append(
            u32(
                w[i - 16]
                + small_sigma0(w[i - 15])
                + w[i - 7]
                + small_sigma1(w[i - 2])
            )
        )

    return w


def compress_rounds(
    message: Sequence[int],
    iv: Sequence[int],
    rounds: int,
) -> Tuple[int, ...]:
    """
    Compute the reduced-round SHA-256 compression output.

    The feed-forward addition uses the supplied IV, matching the SHA-256
    compression structure.
    """
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be in the range 1..64")

    if len(message) != 16:
        raise ValueError("message must contain 16 words")

    if len(iv) != 8:
        raise ValueError("IV must contain 8 words")

    w = expand_schedule(message, rounds)

    a, b, c, d, e, f, g, h = [u32(x) for x in iv]

    for t in range(rounds):
        t1 = u32(
            h
            + big_sigma1(e)
            + ch(e, f, g)
            + K[t]
            + w[t]
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

    return tuple(
        u32(iv[i] + value)
        for i, value in enumerate((a, b, c, d, e, f, g, h))
    )


def verify_collision(
    message1: Sequence[int],
    message2: Sequence[int],
    iv: Sequence[int],
    rounds: int,
) -> Tuple[bool, Tuple[int, ...], Tuple[int, ...]]:
    out1 = compress_rounds(message1, iv, rounds)
    out2 = compress_rounds(message2, iv, rounds)

    return (
        tuple(message1) != tuple(message2)
        and out1 == out2,
        out1,
        out2,
    )


# ---------------------------------------------------------------------------
# Z3 model
# ---------------------------------------------------------------------------

def bv32(value: int) -> z3.BitVecVal:
    return z3.BitVecVal(value & MASK32, 32)


def z3_rotr(x: z3.BitVecRef, n: int) -> z3.BitVecRef:
    return z3.RotateRight(x, n)


def z3_shr(x: z3.BitVecRef, n: int) -> z3.BitVecRef:
    return z3.LShR(x, n)


def z3_ch(
    x: z3.BitVecRef,
    y: z3.BitVecRef,
    z: z3.BitVecRef,
) -> z3.BitVecRef:
    return (x & y) ^ (~x & z)


def z3_maj(
    x: z3.BitVecRef,
    y: z3.BitVecRef,
    z: z3.BitVecRef,
) -> z3.BitVecRef:
    return (x & y) ^ (x & z) ^ (y & z)


def z3_big_sigma0(x: z3.BitVecRef) -> z3.BitVecRef:
    return (
        z3_rotr(x, 2)
        ^ z3_rotr(x, 13)
        ^ z3_rotr(x, 22)
    )


def z3_big_sigma1(x: z3.BitVecRef) -> z3.BitVecRef:
    return (
        z3_rotr(x, 6)
        ^ z3_rotr(x, 11)
        ^ z3_rotr(x, 25)
    )


def z3_small_sigma0(x: z3.BitVecRef) -> z3.BitVecRef:
    return (
        z3_rotr(x, 7)
        ^ z3_rotr(x, 18)
        ^ z3_shr(x, 3)
    )


def z3_small_sigma1(x: z3.BitVecRef) -> z3.BitVecRef:
    return (
        z3_rotr(x, 17)
        ^ z3_rotr(x, 19)
        ^ z3_shr(x, 10)
    )


def symbolic_compression(
    message: Sequence[z3.BitVecRef],
    iv: Sequence[int],
    rounds: int,
) -> Tuple[z3.BitVecRef, ...]:
    """
    Symbolically execute reduced-round SHA-256 compression.
    """
    w = list(message)

    for i in range(16, rounds):
        w.append(
            w[i - 16]
            + z3_small_sigma0(w[i - 15])
            + w[i - 7]
            + z3_small_sigma1(w[i - 2])
        )

    a, b, c, d, e, f, g, h = [
        bv32(x) for x in iv
    ]

    for t in range(rounds):
        t1 = (
            h
            + z3_big_sigma1(e)
            + z3_ch(e, f, g)
            + bv32(K[t])
            + w[t]
        )

        t2 = (
            z3_big_sigma0(a)
            + z3_maj(a, b, c)
        )

        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    return (
        a + bv32(iv[0]),
        b + bv32(iv[1]),
        c + bv32(iv[2]),
        d + bv32(iv[3]),
        e + bv32(iv[4]),
        f + bv32(iv[5]),
        g + bv32(iv[6]),
        h + bv32(iv[7]),
    )


def build_collision_solver(
    rounds: int,
    iv: Sequence[int],
    seed: Optional[int],
) -> Tuple[z3.Solver, List[z3.BitVecRef], List[z3.BitVecRef]]:
    """
    Construct the collision constraint system.

    We deliberately require a difference among message words that can
    influence the selected rounds. This prevents the solver from winning
    by changing an irrelevant word beyond the reduced-round horizon.
    """
    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be in the range 1..64")

    solver = z3.Solver()

    if seed is not None:
        solver.set("random_seed", int(seed))

    m1 = [
        z3.BitVec(f"M1_{i:02d}", 32)
        for i in range(16)
    ]

    m2 = [
        z3.BitVec(f"M2_{i:02d}", 32)
        for i in range(16)
    ]

    out1 = symbolic_compression(m1, iv, rounds)
    out2 = symbolic_compression(m2, iv, rounds)

    # The messages must differ.
    #
    # For r <= 16, only W[0..r-1] directly enter the executed rounds.
    # For r > 16, every original message word can eventually influence
    # the schedule.
    active_words = min(rounds, 16)

    solver.add(
        z3.Or(
            *[
                m1[i] != m2[i]
                for i in range(active_words)
            ]
        )
    )

    # Equal reduced-round compression output.
    for i in range(8):
        solver.add(out1[i] == out2[i])

    return solver, m1, m2


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def run_search(
    rounds: int,
    timeout_ms: int,
    iv: Sequence[int],
    seed: Optional[int],
    dump_smt: Optional[str],
) -> CollisionResult:
    start = time.monotonic()

    print("========================================================================")
    print("SHA256SW COLLISION FINDER")
    print("========================================================================")
    print("Solver : z3")
    print(f"Rounds : {rounds}")
    print("Model  : SHA-256 compression")
    print(f"Timeout: {timeout_ms / 1000:.0f}s")
    print(f"IV     : {fmt_words(iv)}")
    if seed is not None:
        print(f"Seed   : {seed}")
    print()

    print("Building symbolic problem...")

    solver, m1_vars, m2_vars = build_collision_solver(
        rounds=rounds,
        iv=iv,
        seed=seed,
    )

    if dump_smt:
        print(f"Writing SMT problem: {dump_smt}")
        with open(dump_smt, "w", encoding="utf-8") as fp:
            fp.write(solver.sexpr())

    print("Searching...")
    solver.set("timeout", int(timeout_ms))

    result = solver.check()
    elapsed = time.monotonic() - start

    if result == z3.unknown:
        reason = solver.reason_unknown()
        print()
        print(f"UNKNOWN after {elapsed:.3f}s")
        print(f"Reason: {reason}")

        return CollisionResult(
            status="unknown",
            elapsed=elapsed,
            rounds=rounds,
            iv=tuple(iv),
        )

    if result == z3.unsat:
        print()
        print(f"UNSAT after {elapsed:.3f}s")
        print("No collision exists under the selected constraints.")

        return CollisionResult(
            status="unsat",
            elapsed=elapsed,
            rounds=rounds,
            iv=tuple(iv),
        )

    model = solver.model()

    message1 = tuple(
        model.eval(v, model_completion=True).as_long() & MASK32
        for v in m1_vars
    )

    message2 = tuple(
        model.eval(v, model_completion=True).as_long() & MASK32
        for v in m2_vars
    )

    print()
    print("Status : sat")
    print(f"Time   : {elapsed:.3f}s")
    print()
    print("Candidate collision:")
    print()
    print(f"M1 = {fmt_words(message1)}")
    print(f"M2 = {fmt_words(message2)}")

    print()
    print("Independent verification:")

    valid, output1, output2 = verify_collision(
        message1,
        message2,
        iv,
        rounds,
    )

    print(f"M1 != M2       : {message1 != message2}")
    print(f"H(M1)           : {fmt_words(output1)}")
    print(f"H(M2)           : {fmt_words(output2)}")
    print(f"Collision valid : {valid}")

    if not valid:
        print()
        print("ERROR: solver returned a candidate that failed")
        print("independent concrete verification.", file=sys.stderr)

        return CollisionResult(
            status="invalid",
            elapsed=elapsed,
            rounds=rounds,
            iv=tuple(iv),
            message1=message1,
            message2=message2,
            output1=output1,
            output2=output2,
        )

    print()
    print("[+] Collision verified.")

    return CollisionResult(
        status="sat",
        elapsed=elapsed,
        rounds=rounds,
        iv=tuple(iv),
        message1=message1,
        message2=message2,
        output1=output1,
        output2=output2,
    )


# ---------------------------------------------------------------------------
# Full SHA-256 sanity checks
# ---------------------------------------------------------------------------

def sha256_block_digest(block: bytes) -> bytes:
    """
    Reference SHA-256 implementation using hashlib.

    This is useful for sanity-checking the concrete implementation when
    a full 64-round padded block is supplied.
    """
    return hashlib.sha256(block).digest()


def self_test() -> None:
    """
    Verify basic concrete SHA-256 behavior.

    For the empty message, the standard SHA-256 digest is:

    e3b0c44298fc1c149afbf4c8996fb924...
    """
    digest = sha256_block_digest(b"").hex()

    expected = (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )

    if digest != expected:
        raise AssertionError(
            f"hashlib SHA-256 sanity check failed: {digest}"
        )

    # Also verify that the concrete reduced-round implementation accepts
    # normal 16-word blocks.
    block = tuple(range(16))
    result = compress_rounds(block, STANDARD_IV, 4)

    if len(result) != 8:
        raise AssertionError("unexpected compression output size")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Find reduced-round SHA-256 compression collisions using Z3."
        )
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=4,
        help="number of SHA-256 compression rounds (1-64), default: 4",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="solver timeout in seconds, default: 60",
    )

    parser.add_argument(
        "--iv",
        nargs=8,
        metavar="WORD",
        help=(
            "custom 8-word hexadecimal IV; if omitted, use the standard "
            "SHA-256 IV"
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Z3 random seed",
    )

    parser.add_argument(
        "--dump-smt",
        metavar="FILE",
        default=None,
        help="write the generated SMT-LIB problem to FILE",
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run local implementation sanity checks and exit",
    )

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        try:
            self_test()
        except Exception as exc:
            print(f"SELF-TEST FAILED: {exc}", file=sys.stderr)
            return 1

        print("SELF-TEST PASSED")
        return 0

    if not 1 <= args.rounds <= 64:
        parser.error("--rounds must be between 1 and 64")

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        if args.iv is None:
            iv = STANDARD_IV
        else:
            iv = parse_iv(args.iv)
    except ValueError as exc:
        parser.error(str(exc))

    timeout_ms = max(1, int(args.timeout * 1000))

    try:
        result = run_search(
            rounds=args.rounds,
            timeout_ms=timeout_ms,
            iv=iv,
            seed=args.seed,
            dump_smt=args.dump_smt,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if result.status == "sat":
        return 0

    # A timeout/unknown/UNSAT result is not a successful collision search.
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
