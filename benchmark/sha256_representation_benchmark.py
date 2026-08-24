#!/usr/bin/env python3
"""
sha256_representation_benchmark.py

Comparative benchmark for SHA-256 standard-state and sliding-window
representations.

Modes:

  collision
      Existing cryptanalytic-style collision/search benchmark.
      The solver searches for two distinct message blocks satisfying
      the configured differential constraints and producing the same
      reduced-round compression output.

  equiv
      Pure symbolic representation-equivalence benchmark.

      The solver searches for:

          Std(R, IV, W) != SW(R, IV, W)

      for arbitrary symbolic IV and message words.

      SAT   = counterexample found
      UNSAT = representations are symbolically equivalent

      This mode intentionally removes the collision-search problem so
      that solver behavior primarily reflects the representation of
      the SHA-256 transition system.

Validation structure:

  Phase 0
      Independent Python recurrence checks.

  Gate 0
      One-round symbolic equivalence check.

  Phase 1
      Selected benchmark mode.

  Phase 2
      Independent verification of SAT witnesses in collision mode.

  Phase 3
      JSON/CSV export.

IMPORTANT:

    Runtime measured here is end-to-end solver process wall-clock time,
    including SMT-LIB parsing and model generation.

    It is NOT a direct measurement of internal CDCL conflict-processing
    time.

    Equivalence mode is intended to measure symbolic representation
    complexity, not cryptanalytic hardness.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional


# ============================================================================
# FIPS 180-4 constants
# ============================================================================

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa831c66d,  # kept below by canonical list validation
    0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Correct canonical FIPS table.
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

IV = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]

MASK32 = 0xFFFFFFFF

assert len(K) == 64
assert len(IV) == 8
assert K[34] == 0x4d2c6dfc


# ============================================================================
# Independent Python reference implementation
# ============================================================================

def rotr_py(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK32


def big_sigma0(x: int) -> int:
    return rotr_py(x, 2) ^ rotr_py(x, 13) ^ rotr_py(x, 22)


def big_sigma1(x: int) -> int:
    return rotr_py(x, 6) ^ rotr_py(x, 11) ^ rotr_py(x, 25)


def small_sigma0(x: int) -> int:
    return rotr_py(x, 7) ^ rotr_py(x, 18) ^ (x >> 3)


def small_sigma1(x: int) -> int:
    return rotr_py(x, 17) ^ rotr_py(x, 19) ^ (x >> 10)


def ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x & MASK32) & z)) & MASK32


def maj(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


def sha256_reduced_compress_py(
    iv: List[int],
    words: List[int],
    rounds: int,
) -> List[int]:

    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be in [1, 64]")

    if len(iv) != 8:
        raise ValueError("iv must contain exactly 8 words")

    if len(words) < 16:
        raise ValueError("words must contain at least 16 words")

    w = [x & MASK32 for x in words[:16]]

    for i in range(16, rounds):
        w.append(
            (
                w[i - 16]
                + small_sigma0(w[i - 15])
                + w[i - 7]
                + small_sigma1(w[i - 2])
            )
            & MASK32
        )

    a, b, c, d, e, f, g, h = iv

    for i in range(rounds):
        t1 = (
            h
            + big_sigma1(e)
            + ch(e, f, g)
            + K[i]
            + w[i]
        ) & MASK32

        t2 = (
            big_sigma0(a)
            + maj(a, b, c)
        ) & MASK32

        h = g
        g = f
        f = e
        e = (d + t1) & MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK32

    return [
        (iv[0] + a) & MASK32,
        (iv[1] + b) & MASK32,
        (iv[2] + c) & MASK32,
        (iv[3] + d) & MASK32,
        (iv[4] + e) & MASK32,
        (iv[5] + f) & MASK32,
        (iv[6] + g) & MASK32,
        (iv[7] + h) & MASK32,
    ]


def check_sw_recurrence(
    rounds: int,
    trials: int = 250,
) -> None:

    rng = random.Random(0x534857 ^ rounds)

    for trial in range(trials):

        state = [
            rng.getrandbits(32)
            for _ in range(8)
        ]

        words = [
            rng.getrandbits(32)
            for _ in range(rounds)
        ]

        a, b, c, d, e, f, g, h = state

        a_mt = [d, c, b, a]
        b_mt = [h, g, f, e]

        for i in range(rounds):

            t1 = (
                h
                + big_sigma1(e)
                + ch(e, f, g)
                + K[i]
                + words[i]
            ) & MASK32

            t2 = (
                big_sigma0(a)
                + maj(a, b, c)
            ) & MASK32

            expected_a = (t1 + t2) & MASK32
            expected_e = (d + t1) & MASK32

            sw_t1 = (
                b_mt[i]
                + big_sigma1(b_mt[i + 3])
                + ch(
                    b_mt[i + 3],
                    b_mt[i + 2],
                    b_mt[i + 1],
                )
                + K[i]
                + words[i]
            ) & MASK32

            sw_b_next = (
                a_mt[i] + sw_t1
            ) & MASK32

            sw_t2 = (
                big_sigma0(a_mt[i + 3])
                + maj(
                    a_mt[i + 3],
                    a_mt[i + 2],
                    a_mt[i + 1],
                )
            ) & MASK32

            sw_a_next = (
                (sw_b_next - a_mt[i])
                + sw_t2
            ) & MASK32

            if sw_b_next != expected_e:
                raise AssertionError(
                    f"SW E recurrence mismatch at "
                    f"trial={trial}, round={i}"
                )

            if sw_a_next != expected_a:
                raise AssertionError(
                    f"SW A recurrence mismatch at "
                    f"trial={trial}, round={i}"
                )

            a_mt.append(sw_a_next)
            b_mt.append(sw_b_next)

            a, b, c, d, e, f, g, h = (
                expected_a,
                a,
                b,
                c,
                expected_e,
                e,
                f,
                g,
            )

    print(
        f" [PASS] Python recurrence: "
        f"{trials} trials x {rounds} rounds"
    )


# ============================================================================
# SMT-LIB
# ============================================================================

PREAMBLE = r"""
(set-logic QF_BV)
(set-option :produce-models true)

(define-fun rotr32
  ((x (_ BitVec 32)) (n (_ BitVec 32)))
  (_ BitVec 32)
  (bvor
    (bvlshr x n)
    (bvshl x (bvsub (_ bv32 32) n))))

(define-fun S0
  ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv2 32))
    (bvxor
      (rotr32 x (_ bv13 32))
      (rotr32 x (_ bv22 32)))))

(define-fun S1
  ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv6 32))
    (bvxor
      (rotr32 x (_ bv11 32))
      (rotr32 x (_ bv25 32)))))

(define-fun s0
  ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv7 32))
    (bvxor
      (rotr32 x (_ bv18 32))
      (bvlshr x (_ bv3 32)))))

(define-fun s1
  ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv17 32))
    (bvxor
      (rotr32 x (_ bv19 32))
      (bvlshr x (_ bv10 32)))))

(define-fun ch_std
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvand (bvnot x) z)))

(define-fun ch_sw
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvadd
    (bvand x y)
    (bvand (bvnot x) z)))

(define-fun Maj
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvxor
      (bvand x z)
      (bvand y z))))
"""


def bv32(value: int) -> str:
    return f"#x{value & MASK32:08x}"


def emit_msg_schedule(
    rounds: int,
    prefix: str,
) -> str:

    lines: List[str] = []

    for i in range(16):
        lines.append(
            f"(declare-const {prefix}w_{i} "
            f"(_ BitVec 32))"
        )

    for i in range(16, rounds):
        lines.append(
            f"(define-fun {prefix}w_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(bvadd {prefix}w_{i-16} "
            f"(s0 {prefix}w_{i-15})) "
            f"(bvadd {prefix}w_{i-7} "
            f"(s1 {prefix}w_{i-2}))))"
        )

    return "\n".join(lines)


# ============================================================================
# Collision benchmark builders
# ============================================================================

def emit_diff_constraints(
    diff_pattern: Dict[int, int],
) -> str:

    if diff_pattern:
        return "\n".join(
            f"(assert (= "
            f"(bvxor m1_w_{idx} m2_w_{idx}) "
            f"{bv32(diff)}))"
            for idx, diff
            in sorted(diff_pattern.items())
        )

    conditions = [
        f"(distinct m1_w_{i} m2_w_{i})"
        for i in range(16)
    ]

    return (
        f"(assert (or {' '.join(conditions)}))"
    )


def emit_witness_request() -> str:

    names = [
        f"m{b}_w_{i}"
        for b in (1, 2)
        for i in range(16)
    ]

    return (
        "(check-sat)\n"
        "(get-value ("
        + " ".join(names)
        + "))\n"
        "(exit)"
    )


def build_std_explicit(
    rounds: int,
    diff_pattern: Dict[int, int],
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "m1_"),
        emit_msg_schedule(rounds, "m2_"),
        emit_diff_constraints(diff_pattern),
    ]

    for prefix in ("m1_", "m2_"):

        for i in range(rounds + 1):
            for name in "abcdefgh":
                lines.append(
                    f"(declare-const "
                    f"{prefix}{name}_{i} "
                    f"(_ BitVec 32))"
                )

        for idx, name in enumerate("abcdefgh"):
            lines.append(
                f"(assert (= "
                f"{prefix}{name}_0 "
                f"{bv32(IV[idx])}))"
            )

        for i in range(rounds):

            k = bv32(K[i])

            lines.append(
                f"(define-fun {prefix}t1_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd {prefix}h_{i} "
                f"(bvadd (S1 {prefix}e_{i}) "
                f"(bvadd "
                f"(ch_std {prefix}e_{i} "
                f"{prefix}f_{i} "
                f"{prefix}g_{i}) "
                f"(bvadd {k} "
                f"{prefix}w_{i})))))"
            )

            lines.append(
                f"(define-fun {prefix}t2_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"(S0 {prefix}a_{i}) "
                f"(Maj {prefix}a_{i} "
                f"{prefix}b_{i} "
                f"{prefix}c_{i})))"
            )

            lines.extend([
                f"(assert (= "
                f"{prefix}a_{i+1} "
                f"(bvadd {prefix}t1_{i} "
                f"{prefix}t2_{i})))",

                f"(assert (= "
                f"{prefix}b_{i+1} "
                f"{prefix}a_{i}))",

                f"(assert (= "
                f"{prefix}c_{i+1} "
                f"{prefix}b_{i}))",

                f"(assert (= "
                f"{prefix}d_{i+1} "
                f"{prefix}c_{i}))",

                f"(assert (= "
                f"{prefix}e_{i+1} "
                f"(bvadd {prefix}d_{i} "
                f"{prefix}t1_{i})))",

                f"(assert (= "
                f"{prefix}f_{i+1} "
                f"{prefix}e_{i}))",

                f"(assert (= "
                f"{prefix}g_{i+1} "
                f"{prefix}f_{i}))",

                f"(assert (= "
                f"{prefix}h_{i+1} "
                f"{prefix}g_{i}))",
            ])

    for name in "abcdefgh":
        lines.append(
            f"(assert (= "
            f"(bvadd m1_{name}_0 "
            f"m1_{name}_{rounds}) "
            f"(bvadd m2_{name}_0 "
            f"m2_{name}_{rounds})))"
        )

    lines.append(emit_witness_request())

    return "\n".join(lines)


def build_sw_explicit(
    rounds: int,
    diff_pattern: Dict[int, int],
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "m1_"),
        emit_msg_schedule(rounds, "m2_"),
        emit_diff_constraints(diff_pattern),
    ]

    for prefix in ("m1_", "m2_"):

        for i in range(rounds + 4):
            lines.extend([
                f"(declare-const "
                f"{prefix}a_mt_{i} "
                f"(_ BitVec 32))",

                f"(declare-const "
                f"{prefix}b_mt_{i} "
                f"(_ BitVec 32))",
            ])

        lines.extend([
            f"(assert (= "
            f"{prefix}a_mt_0 {bv32(IV[3])}))",

            f"(assert (= "
            f"{prefix}a_mt_1 {bv32(IV[2])}))",

            f"(assert (= "
            f"{prefix}a_mt_2 {bv32(IV[1])}))",

            f"(assert (= "
            f"{prefix}a_mt_3 {bv32(IV[0])}))",

            f"(assert (= "
            f"{prefix}b_mt_0 {bv32(IV[7])}))",

            f"(assert (= "
            f"{prefix}b_mt_1 {bv32(IV[6])}))",

            f"(assert (= "
            f"{prefix}b_mt_2 {bv32(IV[5])}))",

            f"(assert (= "
            f"{prefix}b_mt_3 {bv32(IV[4])}))",
        ])

        for i in range(rounds):

            k = bv32(K[i])

            lines.append(
                f"(define-fun {prefix}t1_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd {prefix}b_mt_{i} "
                f"(bvadd "
                f"(S1 {prefix}b_mt_{i+3}) "
                f"(bvadd "
                f"(ch_sw "
                f"{prefix}b_mt_{i+3} "
                f"{prefix}b_mt_{i+2} "
                f"{prefix}b_mt_{i+1}) "
                f"(bvadd {k} "
                f"{prefix}w_{i})))))"
            )

            lines.append(
                f"(define-fun {prefix}t2_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"(S0 {prefix}a_mt_{i+3}) "
                f"(Maj "
                f"{prefix}a_mt_{i+3} "
                f"{prefix}a_mt_{i+2} "
                f"{prefix}a_mt_{i+1})))"
            )

            lines.extend([
                f"(assert (= "
                f"{prefix}b_mt_{i+4} "
                f"(bvadd "
                f"{prefix}a_mt_{i} "
                f"{prefix}t1_{i})))",

                f"(assert (= "
                f"{prefix}a_mt_{i+4} "
                f"(bvadd "
                f"(bvsub "
                f"{prefix}b_mt_{i+4} "
                f"{prefix}a_mt_{i}) "
                f"{prefix}t2_{i})))",
            ])

    mappings = [
        (IV[0], "a", rounds + 3),
        (IV[1], "a", rounds + 2),
        (IV[2], "a", rounds + 1),
        (IV[3], "a", rounds),
        (IV[4], "b", rounds + 3),
        (IV[5], "b", rounds + 2),
        (IV[6], "b", rounds + 1),
        (IV[7], "b", rounds),
    ]

    for iv_value, family, index in mappings:
        lines.append(
            f"(assert (= "
            f"(bvadd {bv32(iv_value)} "
            f"m1_{family}_mt_{index}) "
            f"(bvadd {bv32(iv_value)} "
            f"m2_{family}_mt_{index})))"
        )

    lines.append(emit_witness_request())

    return "\n".join(lines)


def build_std_inline(
    rounds: int,
    diff_pattern: Dict[int, int],
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "m1_"),
        emit_msg_schedule(rounds, "m2_"),
        emit_diff_constraints(diff_pattern),
    ]

    for prefix in ("m1_", "m2_"):

        for idx, name in enumerate("abcdefgh"):
            lines.append(
                f"(define-fun "
                f"{prefix}{name}_0 () "
                f"(_ BitVec 32) "
                f"{bv32(IV[idx])})"
            )

        for i in range(rounds):

            k = bv32(K[i])

            lines.append(
                f"(define-fun {prefix}t1_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd {prefix}h_{i} "
                f"(bvadd (S1 {prefix}e_{i}) "
                f"(bvadd "
                f"(ch_std "
                f"{prefix}e_{i} "
                f"{prefix}f_{i} "
                f"{prefix}g_{i}) "
                f"(bvadd {k} "
                f"{prefix}w_{i})))))"
            )

            lines.append(
                f"(define-fun {prefix}t2_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"(S0 {prefix}a_{i}) "
                f"(Maj "
                f"{prefix}a_{i} "
                f"{prefix}b_{i} "
                f"{prefix}c_{i})))"
            )

            lines.extend([
                f"(define-fun "
                f"{prefix}a_{i+1} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"{prefix}t1_{i} "
                f"{prefix}t2_{i}))",

                f"(define-fun "
                f"{prefix}b_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}a_{i})",

                f"(define-fun "
                f"{prefix}c_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}b_{i})",

                f"(define-fun "
                f"{prefix}d_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}c_{i})",

                f"(define-fun "
                f"{prefix}e_{i+1} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"{prefix}d_{i} "
                f"{prefix}t1_{i}))",

                f"(define-fun "
                f"{prefix}f_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}e_{i})",

                f"(define-fun "
                f"{prefix}g_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}f_{i})",

                f"(define-fun "
                f"{prefix}h_{i+1} () "
                f"(_ BitVec 32) "
                f"{prefix}g_{i})",
            ])

    for name in "abcdefgh":
        lines.append(
            f"(assert (= "
            f"(bvadd m1_{name}_0 "
            f"m1_{name}_{rounds}) "
            f"(bvadd m2_{name}_0 "
            f"m2_{name}_{rounds})))"
        )

    lines.append(emit_witness_request())

    return "\n".join(lines)


def build_sw_inline(
    rounds: int,
    diff_pattern: Dict[int, int],
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "m1_"),
        emit_msg_schedule(rounds, "m2_"),
        emit_diff_constraints(diff_pattern),
    ]

    for prefix in ("m1_", "m2_"):

        lines.extend([
            f"(define-fun {prefix}a_mt_0 () "
            f"(_ BitVec 32) {bv32(IV[3])})",

            f"(define-fun {prefix}a_mt_1 () "
            f"(_ BitVec 32) {bv32(IV[2])})",

            f"(define-fun {prefix}a_mt_2 () "
            f"(_ BitVec 32) {bv32(IV[1])})",

            f"(define-fun {prefix}a_mt_3 () "
            f"(_ BitVec 32) {bv32(IV[0])})",

            f"(define-fun {prefix}b_mt_0 () "
            f"(_ BitVec 32) {bv32(IV[7])})",

            f"(define-fun {prefix}b_mt_1 () "
            f"(_ BitVec 32) {bv32(IV[6])})",

            f"(define-fun {prefix}b_mt_2 () "
            f"(_ BitVec 32) {bv32(IV[5])})",

            f"(define-fun {prefix}b_mt_3 () "
            f"(_ BitVec 32) {bv32(IV[4])})",
        ])

        for i in range(rounds):

            k = bv32(K[i])

            lines.append(
                f"(define-fun {prefix}t1_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd {prefix}b_mt_{i} "
                f"(bvadd "
                f"(S1 {prefix}b_mt_{i+3}) "
                f"(bvadd "
                f"(ch_sw "
                f"{prefix}b_mt_{i+3} "
                f"{prefix}b_mt_{i+2} "
                f"{prefix}b_mt_{i+1}) "
                f"(bvadd {k} "
                f"{prefix}w_{i})))))"
            )

            lines.append(
                f"(define-fun {prefix}b_mt_{i+4} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"{prefix}a_mt_{i} "
                f"{prefix}t1_{i}))"
            )

            lines.append(
                f"(define-fun {prefix}t2_{i} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"(S0 {prefix}a_mt_{i+3}) "
                f"(Maj "
                f"{prefix}a_mt_{i+3} "
                f"{prefix}a_mt_{i+2} "
                f"{prefix}a_mt_{i+1})))"
            )

            lines.append(
                f"(define-fun {prefix}a_mt_{i+4} () "
                f"(_ BitVec 32) "
                f"(bvadd "
                f"(bvsub "
                f"{prefix}b_mt_{i+4} "
                f"{prefix}a_mt_{i}) "
                f"{prefix}t2_{i}))"
            )

    mappings = [
        (IV[0], "a", rounds + 3),
        (IV[1], "a", rounds + 2),
        (IV[2], "a", rounds + 1),
        (IV[3], "a", rounds),
        (IV[4], "b", rounds + 3),
        (IV[5], "b", rounds + 2),
        (IV[6], "b", rounds + 1),
        (IV[7], "b", rounds),
    ]

    for iv_value, family, index in mappings:
        lines.append(
            f"(assert (= "
            f"(bvadd {bv32(iv_value)} "
            f"m1_{family}_mt_{index}) "
            f"(bvadd {bv32(iv_value)} "
            f"m2_{family}_mt_{index})))"
        )

    lines.append(emit_witness_request())

    return "\n".join(lines)


COLLISION_BUILDERS = {
    "Std-Explicit": build_std_explicit,
    "SW-Explicit": build_sw_explicit,
    "Std-Inline": build_std_inline,
    "SW-Inline": build_sw_inline,
}


# ============================================================================
# Equivalence builders
# ============================================================================

def emit_symbolic_iv(prefix: str = "iv_") -> str:

    return "\n".join(
        f"(declare-const {prefix}{name} "
        f"(_ BitVec 32))"
        for name in "abcdefgh"
    )


def emit_std_equiv_explicit(
    rounds: int,
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "sym_"),
        emit_symbolic_iv(),
    ]

    for i in range(rounds + 1):
        for name in "abcdefgh":
            lines.append(
                f"(declare-const std_{name}_{i} "
                f"(_ BitVec 32))"
            )

    for name in "abcdefgh":
        lines.append(
            f"(assert (= std_{name}_0 iv_{name}))"
        )

    for i in range(rounds):

        k = bv32(K[i])
        w = f"sym_w_{i}"

        lines.append(
            f"(define-fun std_t1_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd std_h_{i} "
            f"(bvadd "
            f"(S1 std_e_{i}) "
            f"(bvadd "
            f"(ch_std "
            f"std_e_{i} "
            f"std_f_{i} "
            f"std_g_{i}) "
            f"(bvadd {k} {w})))))"
        )

        lines.append(
            f"(define-fun std_t2_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(S0 std_a_{i}) "
            f"(Maj "
            f"std_a_{i} "
            f"std_b_{i} "
            f"std_c_{i})))"
        )

        lines.extend([
            f"(assert (= std_a_{i+1} "
            f"(bvadd std_t1_{i} "
            f"std_t2_{i})))",

            f"(assert (= std_b_{i+1} "
            f"std_a_{i}))",

            f"(assert (= std_c_{i+1} "
            f"std_b_{i}))",

            f"(assert (= std_d_{i+1} "
            f"std_c_{i}))",

            f"(assert (= std_e_{i+1} "
            f"(bvadd std_d_{i} "
            f"std_t1_{i})))",

            f"(assert (= std_f_{i+1} "
            f"std_e_{i}))",

            f"(assert (= std_g_{i+1} "
            f"std_f_{i}))",

            f"(assert (= std_h_{i+1} "
            f"std_g_{i}))",
        ])

    return "\n".join(lines)


def emit_sw_equiv_explicit(
    rounds: int,
) -> str:

    lines = []

    for i in range(rounds + 4):
        lines.extend([
            f"(declare-const sw_a_{i} "
            f"(_ BitVec 32))",

            f"(declare-const sw_b_{i} "
            f"(_ BitVec 32))",
        ])

    lines.extend([
        "(assert (= sw_a_0 iv_d))",
        "(assert (= sw_a_1 iv_c))",
        "(assert (= sw_a_2 iv_b))",
        "(assert (= sw_a_3 iv_a))",

        "(assert (= sw_b_0 iv_h))",
        "(assert (= sw_b_1 iv_g))",
        "(assert (= sw_b_2 iv_f))",
        "(assert (= sw_b_3 iv_e))",
    ])

    for i in range(rounds):

        k = bv32(K[i])
        w = f"sym_w_{i}"

        lines.append(
            f"(define-fun sw_t1_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd sw_b_{i} "
            f"(bvadd "
            f"(S1 sw_b_{i+3}) "
            f"(bvadd "
            f"(ch_sw "
            f"sw_b_{i+3} "
            f"sw_b_{i+2} "
            f"sw_b_{i+1}) "
            f"(bvadd {k} {w})))))"
        )

        lines.append(
            f"(define-fun sw_t2_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(S0 sw_a_{i+3}) "
            f"(Maj "
            f"sw_a_{i+3} "
            f"sw_a_{i+2} "
            f"sw_a_{i+1})))"
        )

        lines.extend([
            f"(assert (= sw_b_{i+4} "
            f"(bvadd "
            f"sw_a_{i} "
            f"sw_t1_{i})))",

            f"(assert (= sw_a_{i+4} "
            f"(bvadd "
            f"(bvsub "
            f"sw_b_{i+4} "
            f"sw_a_{i}) "
            f"sw_t2_{i})))",
        ])

    return "\n".join(lines)


def build_equiv_explicit(
    rounds: int,
) -> str:

    lines = [
        emit_std_equiv_explicit(rounds),
        emit_sw_equiv_explicit(rounds),
    ]

    lines.append(
        f"""
(assert (or
  (distinct std_a_{rounds} sw_a_{rounds+3})
  (distinct std_b_{rounds} sw_a_{rounds+2})
  (distinct std_c_{rounds} sw_a_{rounds+1})
  (distinct std_d_{rounds} sw_a_{rounds})
  (distinct std_e_{rounds} sw_b_{rounds+3})
  (distinct std_f_{rounds} sw_b_{rounds+2})
  (distinct std_g_{rounds} sw_b_{rounds+1})
  (distinct std_h_{rounds} sw_b_{rounds})))

(check-sat)
(exit)
"""
    )

    return PREAMBLE + "\n" + "\n".join(lines)


def build_equiv_inline(
    rounds: int,
) -> str:

    lines = [
        PREAMBLE,
        emit_msg_schedule(rounds, "sym_"),
        emit_symbolic_iv(),
    ]

    for name in "abcdefgh":
        lines.append(
            f"(define-fun std_{name}_0 () "
            f"(_ BitVec 32) iv_{name})"
        )

    for i in range(rounds):

        k = bv32(K[i])
        w = f"sym_w_{i}"

        lines.append(
            f"(define-fun std_t1_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd std_h_{i} "
            f"(bvadd "
            f"(S1 std_e_{i}) "
            f"(bvadd "
            f"(ch_std "
            f"std_e_{i} "
            f"std_f_{i} "
            f"std_g_{i}) "
            f"(bvadd {k} {w})))))"
        )

        lines.append(
            f"(define-fun std_t2_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(S0 std_a_{i}) "
            f"(Maj "
            f"std_a_{i} "
            f"std_b_{i} "
            f"std_c_{i})))"
        )

        lines.extend([
            f"(define-fun std_a_{i+1} () "
            f"(_ BitVec 32) "
            f"(bvadd std_t1_{i} "
            f"std_t2_{i}))",

            f"(define-fun std_b_{i+1} () "
            f"(_ BitVec 32) std_a_{i})",

            f"(define-fun std_c_{i+1} () "
            f"(_ BitVec 32) std_b_{i})",

            f"(define-fun std_d_{i+1} () "
            f"(_ BitVec 32) std_c_{i})",

            f"(define-fun std_e_{i+1} () "
            f"(_ BitVec 32) "
            f"(bvadd std_d_{i} "
            f"std_t1_{i}))",

            f"(define-fun std_f_{i+1} () "
            f"(_ BitVec 32) std_e_{i})",

            f"(define-fun std_g_{i+1} () "
            f"(_ BitVec 32) std_f_{i})",

            f"(define-fun std_h_{i+1} () "
            f"(_ BitVec 32) std_g_{i})",
        ])

    lines.extend([
        "(define-fun sw_a_0 () (_ BitVec 32) iv_d)",
        "(define-fun sw_a_1 () (_ BitVec 32) iv_c)",
        "(define-fun sw_a_2 () (_ BitVec 32) iv_b)",
        "(define-fun sw_a_3 () (_ BitVec 32) iv_a)",

        "(define-fun sw_b_0 () (_ BitVec 32) iv_h)",
        "(define-fun sw_b_1 () (_ BitVec 32) iv_g)",
        "(define-fun sw_b_2 () (_ BitVec 32) iv_f)",
        "(define-fun sw_b_3 () (_ BitVec 32) iv_e)",
    ])

    for i in range(rounds):

        k = bv32(K[i])
        w = f"sym_w_{i}"

        lines.append(
            f"(define-fun sw_t1_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd sw_b_{i} "
            f"(bvadd "
            f"(S1 sw_b_{i+3}) "
            f"(bvadd "
            f"(ch_sw "
            f"sw_b_{i+3} "
            f"sw_b_{i+2} "
            f"sw_b_{i+1}) "
            f"(bvadd {k} {w})))))"
        )

        lines.append(
            f"(define-fun sw_b_{i+4} () "
            f"(_ BitVec 32) "
            f"(bvadd sw_a_{i} "
            f"sw_t1_{i}))"
        )

        lines.append(
            f"(define-fun sw_t2_{i} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(S0 sw_a_{i+3}) "
            f"(Maj "
            f"sw_a_{i+3} "
            f"sw_a_{i+2} "
            f"sw_a_{i+1})))"
        )

        lines.append(
            f"(define-fun sw_a_{i+4} () "
            f"(_ BitVec 32) "
            f"(bvadd "
            f"(bvsub sw_b_{i+4} "
            f"sw_a_{i}) "
            f"sw_t2_{i}))"
        )

    lines.append(
        f"""
(assert (or
  (distinct std_a_{rounds} sw_a_{rounds+3})
  (distinct std_b_{rounds} sw_a_{rounds+2})
  (distinct std_c_{rounds} sw_a_{rounds+1})
  (distinct std_d_{rounds} sw_a_{rounds})
  (distinct std_e_{rounds} sw_b_{rounds+3})
  (distinct std_f_{rounds} sw_b_{rounds+2})
  (distinct std_g_{rounds} sw_b_{rounds+1})
  (distinct std_h_{rounds} sw_b_{rounds})))

(check-sat)
(exit)
"""
    )

    return "\n".join(lines)


EQUIV_BUILDERS = {
    "Std-Explicit": build_equiv_explicit,
    "Std-Inline": build_equiv_inline,
}


# ============================================================================
# Solver parsing
# ============================================================================

def parse_status(
    stdout: str,
    stderr: str = "",
) -> str:

    for line in stdout.splitlines():

        token = line.strip().lower()

        if token == "sat":
            return "sat"

        if token == "unsat":
            return "unsat"

        if token == "unknown":
            return "unknown"

    combined = (
        stdout
        + "\n"
        + stderr
    ).lower()

    if "timeout" in combined:
        return "timeout"

    if "error" in combined:
        return "error"

    return "unknown"


def parse_witness(
    stdout: str,
) -> Optional[Dict[str, int]]:

    values: Dict[str, int] = {}

    pattern = re.compile(
        r"\(\s*"
        r"(m[12]_w_\d+)\s+"
        r"(#x[0-9a-fA-F]+|"
        r"\(_\s+bv([0-9]+)\s+32\))"
        r"\s*\)"
    )

    for match in pattern.finditer(stdout):

        name = match.group(1)
        token = match.group(2)

        if token.startswith("#x"):
            values[name] = int(
                token[2:],
                16,
            )
        else:
            values[name] = int(
                match.group(3),
                10,
            )

    expected = {
        f"m{branch}_w_{i}"
        for branch in (1, 2)
        for i in range(16)
    }

    if not expected.issubset(values):
        return None

    return values


# ============================================================================
# Results
# ============================================================================

@dataclass
class TrialResult:

    solver: str
    version: str
    mode: str
    rounds: int
    representation: str
    trial: int
    status: str
    runtime_seconds: float
    timeout: bool
    verified: Optional[bool]
    message_diff: str


# ============================================================================
# Solver execution
# ============================================================================

def run_collision_instance(
    model_name: str,
    rounds: int,
    trial: int,
    diff: Dict[int, int],
    solver_cmd: str,
    solver_ver: str,
    timeout: int,
    keep_smt: bool,
) -> TrialResult:

    code = COLLISION_BUILDERS[model_name](
        rounds,
        diff,
    )

    temp_handle = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".smt2",
        prefix=(
            f"sha256sw_"
            f"{model_name.replace('-', '_')}_"
            f"r{rounds}_t{trial}_"
        ),
        delete=False,
        encoding="utf-8",
    )

    filename = Path(temp_handle.name)

    try:

        temp_handle.write(code)
        temp_handle.close()

        started = time.perf_counter()

        try:

            proc = subprocess.run(
                [solver_cmd, str(filename)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            runtime = (
                time.perf_counter()
                - started
            )

            status = parse_status(
                proc.stdout,
                proc.stderr,
            )

            timed_out = False

        except subprocess.TimeoutExpired:

            runtime = float(timeout)
            status = "timeout"
            timed_out = True
            proc = None

        except OSError as exc:

            runtime = (
                time.perf_counter()
                - started
            )

            status = "error"
            timed_out = False
            proc = None

            print(
                f"[ERROR] Could not execute solver "
                f"{solver_cmd!r}: {exc}",
                file=sys.stderr,
            )

        verified: Optional[bool] = None

        if status == "sat":

            if proc is None:

                verified = False

            else:

                witness = parse_witness(
                    proc.stdout
                )

                if witness is None:

                    verified = False

                else:

                    m1_words = [
                        witness[f"m1_w_{i}"]
                        for i in range(16)
                    ]

                    m2_words = [
                        witness[f"m2_w_{i}"]
                        for i in range(16)
                    ]

                    h1 = (
                        sha256_reduced_compress_py(
                            IV,
                            m1_words,
                            rounds,
                        )
                    )

                    h2 = (
                        sha256_reduced_compress_py(
                            IV,
                            m2_words,
                            rounds,
                        )
                    )

                    verified = (
                        m1_words != m2_words
                        and h1 == h2
                    )

        return TrialResult(
            solver=solver_cmd,
            version=solver_ver,
            mode="collision",
            rounds=rounds,
            representation=model_name,
            trial=trial,
            status=status,
            runtime_seconds=runtime,
            timeout=timed_out,
            verified=verified,
            message_diff=str(diff),
        )

    finally:

        if not keep_smt:

            try:
                filename.unlink()
            except FileNotFoundError:
                pass


def run_equiv_instance(
    model_name: str,
    rounds: int,
    trial: int,
    solver_cmd: str,
    solver_ver: str,
    timeout: int,
    keep_smt: bool,
) -> TrialResult:

    code = EQUIV_BUILDERS[model_name](rounds)

    temp_handle = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".smt2",
        prefix=(
            f"sha256sw_equiv_"
            f"{model_name.replace('-', '_')}_"
            f"r{rounds}_t{trial}_"
        ),
        delete=False,
        encoding="utf-8",
    )

    filename = Path(temp_handle.name)

    try:

        temp_handle.write(code)
        temp_handle.close()

        started = time.perf_counter()

        try:

            proc = subprocess.run(
                [solver_cmd, str(filename)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            runtime = (
                time.perf_counter()
                - started
            )

            status = parse_status(
                proc.stdout,
                proc.stderr,
            )

            timed_out = False

        except subprocess.TimeoutExpired:

            runtime = float(timeout)
            status = "timeout"
            timed_out = True
            proc = None

        except OSError as exc:

            runtime = (
                time.perf_counter()
                - started
            )

            status = "error"
            timed_out = False
            proc = None

            print(
                f"[ERROR] Could not execute solver "
                f"{solver_cmd!r}: {exc}",
                file=sys.stderr,
            )

        # In equivalence mode:
        #
        #   UNSAT = proof of equivalence
        #   SAT   = counterexample
        #
        # There is no witness verification requirement here because
        # the benchmark's assertion itself is the semantic property.

        verified: Optional[bool]

        if status == "unsat":
            verified = True
        elif status == "sat":
            verified = False
        else:
            verified = None

        return TrialResult(
            solver=solver_cmd,
            version=solver_ver,
            mode="equiv",
            rounds=rounds,
            representation=model_name,
            trial=trial,
            status=status,
            runtime_seconds=runtime,
            timeout=timed_out,
            verified=verified,
            message_diff="",
        )

    finally:

        if not keep_smt:

            try:
                filename.unlink()
            except FileNotFoundError:
                pass


# ============================================================================
# Gate 0
# ============================================================================

def verify_formal_equivalence_gate(
    solver_cmd: str,
    timeout: int,
) -> None:

    print("=" * 88)
    print("GATE 0: One-Round Formal Symbolic Equivalence")
    print("=" * 88)

    code = PREAMBLE + r"""
(declare-const a (_ BitVec 32))
(declare-const b (_ BitVec 32))
(declare-const c (_ BitVec 32))
(declare-const d (_ BitVec 32))
(declare-const e (_ BitVec 32))
(declare-const f (_ BitVec 32))
(declare-const g (_ BitVec 32))
(declare-const h (_ BitVec 32))
(declare-const w (_ BitVec 32))
(declare-const k (_ BitVec 32))

(define-fun t1_std () (_ BitVec 32)
  (bvadd h
    (bvadd
      (S1 e)
      (bvadd
        (ch_std e f g)
        (bvadd k w)))))

(define-fun t2_std () (_ BitVec 32)
  (bvadd
    (S0 a)
    (Maj a b c)))

(define-fun A_std () (_ BitVec 32)
  (bvadd t1_std t2_std))

(define-fun E_std () (_ BitVec 32)
  (bvadd d t1_std))

(define-fun a_mt_0 () (_ BitVec 32) d)
(define-fun a_mt_1 () (_ BitVec 32) c)
(define-fun a_mt_2 () (_ BitVec 32) b)
(define-fun a_mt_3 () (_ BitVec 32) a)

(define-fun b_mt_0 () (_ BitVec 32) h)
(define-fun b_mt_1 () (_ BitVec 32) g)
(define-fun b_mt_2 () (_ BitVec 32) f)
(define-fun b_mt_3 () (_ BitVec 32) e)

(define-fun t1_sw () (_ BitVec 32)
  (bvadd b_mt_0
    (bvadd
      (S1 b_mt_3)
      (bvadd
        (ch_sw b_mt_3 b_mt_2 b_mt_1)
        (bvadd k w)))))

(define-fun b_mt_4 () (_ BitVec 32)
  (bvadd a_mt_0 t1_sw))

(define-fun t2_sw () (_ BitVec 32)
  (bvadd
    (S0 a_mt_3)
    (Maj a_mt_3 a_mt_2 a_mt_1)))

(define-fun a_mt_4 () (_ BitVec 32)
  (bvadd
    (bvsub b_mt_4 a_mt_0)
    t2_sw))

(assert
  (or
    (distinct A_std a_mt_4)
    (distinct E_std b_mt_4)))

(check-sat)
(exit)
"""

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".smt2",
        prefix="sha256sw_gate0_",
        delete=False,
        encoding="utf-8",
    ) as handle:

        handle.write(code)
        filename = Path(handle.name)

    try:

        started = time.perf_counter()

        try:

            proc = subprocess.run(
                [solver_cmd, str(filename)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )

        except subprocess.TimeoutExpired:

            elapsed = (
                time.perf_counter()
                - started
            )

            print(
                f" [FATAL] Gate 0 timed out "
                f"after {timeout}s "
                f"({elapsed:.3f}s)"
            )

            raise SystemExit(1)

        elapsed = (
            time.perf_counter()
            - started
        )

        result = parse_status(
            proc.stdout,
            proc.stderr,
        )

        if result != "unsat":

            print(
                f" [FATAL] Gate 0 failed: "
                f"{result}"
            )

            if proc.stdout.strip():
                print(proc.stdout)

            if proc.stderr.strip():
                print(
                    proc.stderr,
                    file=sys.stderr,
                )

            raise SystemExit(1)

        print(
            f" [PASS] One-round Std == SW: "
            f"UNSAT ({elapsed:.3f}s)"
        )

    finally:

        try:
            filename.unlink()
        except FileNotFoundError:
            pass

    print()
    print(
        "Gate 0 passed: the standard and sliding-window "
        "one-round transitions are symbolically equivalent."
    )
    print()


# ============================================================================
# Solver utilities
# ============================================================================

def get_solver_version(
    solver_cmd: str,
) -> str:

    try:

        proc = subprocess.run(
            [solver_cmd, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        text = (
            proc.stdout.strip()
            or proc.stderr.strip()
        )

        if not text:
            return "Unknown Version"

        return text.splitlines()[0]

    except Exception:
        return "Unknown Version"


# ============================================================================
# Collision benchmark
# ============================================================================

def run_collision_benchmark(
    rounds_list: List[int],
    diff_pattern: Dict[int, int],
    solver_cmd: str,
    trials: int,
    timeout: int,
    seed: int,
    keep_smt: bool,
) -> List[TrialResult]:

    solver_version = get_solver_version(
        solver_cmd
    )

    print("=" * 88)
    print("PHASE 1: Solver Representation Benchmark")
    print("=" * 88)

    print(f"Solver : {solver_cmd}")
    print(f"Version: {solver_version}")
    print(f"Mode   : collision")
    print(f"Rounds : {rounds_list}")
    print(f"Trials : {trials}")
    print(f"Timeout: {timeout}s")
    print(f"Diff   : {diff_pattern}")
    print(f"Seed   : {seed}")
    print("=" * 88)

    rng = random.Random(seed)

    results: List[TrialResult] = []

    representations = list(
        COLLISION_BUILDERS
    )

    for rounds in rounds_list:

        print(
            f"\n--- {rounds} rounds ---"
        )

        for trial in range(trials):

            order = list(
                representations
            )

            rng.shuffle(order)

            for model in order:

                result = run_collision_instance(
                    model,
                    rounds,
                    trial + 1,
                    diff_pattern,
                    solver_cmd,
                    solver_version,
                    timeout,
                    keep_smt,
                )

                results.append(result)

                verification = ""

                if result.verified is not None:
                    verification = (
                        f" verified="
                        f"{result.verified}"
                    )

                print(
                    f"  trial={trial + 1:2d}/"
                    f"{trials} "
                    f"{model:<14} "
                    f"{result.status:<8} "
                    f"{result.runtime_seconds:8.3f}s"
                    f"{verification}"
                )

                if (
                    result.status == "sat"
                    and result.verified is not True
                ):
                    print(
                        "\n[FATAL] SAT witness failed "
                        "independent verification."
                    )

                    raise SystemExit(1)

    return results


# ============================================================================
# Equivalence benchmark
# ============================================================================

def run_equiv_benchmark(
    rounds_list: List[int],
    solver_cmd: str,
    trials: int,
    timeout: int,
    seed: int,
    keep_smt: bool,
) -> List[TrialResult]:

    solver_version = get_solver_version(
        solver_cmd
    )

    print("=" * 88)
    print("PHASE 1: Symbolic Representation Equivalence")
    print("=" * 88)

    print(f"Solver : {solver_cmd}")
    print(f"Version: {solver_version}")
    print(f"Mode   : equiv")
    print(f"Rounds : {rounds_list}")
    print(f"Trials : {trials}")
    print(f"Timeout: {timeout}s")
    print(f"Seed   : {seed}")
    print()
    print(
        "Property: find Std != SW"
    )
    print(
        "UNSAT   = equivalent"
    )
    print(
        "SAT     = counterexample"
    )
    print("=" * 88)

    rng = random.Random(seed)

    results: List[TrialResult] = []

    representations = list(
        EQUIV_BUILDERS
    )

    for rounds in rounds_list:

        print(
            f"\n--- {rounds} rounds ---"
        )

        for trial in range(trials):

            order = list(
                representations
            )

            rng.shuffle(order)

            for model in order:

                result = run_equiv_instance(
                    model,
                    rounds,
                    trial + 1,
                    solver_cmd,
                    solver_version,
                    timeout,
                    keep_smt,
                )

                results.append(result)

                if result.status == "unsat":
                    interpretation = (
                        "proved-equivalent"
                    )

                elif result.status == "sat":
                    interpretation = (
                        "COUNTEREXAMPLE"
                    )

                elif result.status == "timeout":
                    interpretation = "timeout"

                else:
                    interpretation = result.status

                print(
                    f"  trial={trial + 1:2d}/"
                    f"{trials} "
                    f"{model:<14} "
                    f"{result.status:<8} "
                    f"{result.runtime_seconds:8.3f}s "
                    f"{interpretation}"
                )

    return results


# ============================================================================
# Summary
# ============================================================================

def print_summary(
    results: List[TrialResult],
    trials: int,
) -> None:

    print("\n" + "=" * 88)
    print("BENCHMARK SUMMARY")
    print("=" * 88)

    if not results:
        print("No results.")
        return

    mode = results[0].mode

    if mode == "equiv":

        representations = [
            "Std-Explicit",
            "Std-Inline",
        ]

    else:

        representations = [
            "Std-Explicit",
            "SW-Explicit",
            "Std-Inline",
            "SW-Inline",
        ]

    for rounds in sorted(
        {
            result.rounds
            for result in results
        }
    ):

        print(
            f"\n[Rounds: {rounds}]"
        )

        print(
            f"{'Model':<15} | "
            f"{'Status':<12} | "
            f"{'Median(s)':<11} | "
            f"{'Mean(s)':<11} | "
            f"{'StdDev(s)':<11} | "
            f"{'Valid':<7}"
        )

        print("-" * 88)

        medians: Dict[
            str,
            float,
        ] = {}

        for model in representations:

            model_results = [
                r
                for r in results
                if r.rounds == rounds
                and r.representation == model
            ]

            statuses = sorted(
                {
                    r.status
                    for r in model_results
                }
            )

            successful = [
                r
                for r in model_results
                if r.status in (
                    "sat",
                    "unsat",
                )
                and not r.timeout
            ]

            complete = (
                len(model_results) == trials
                and len(successful) == trials
            )

            if complete:

                times = [
                    r.runtime_seconds
                    for r in successful
                ]

                median = statistics.median(
                    times
                )

                mean = statistics.mean(
                    times
                )

                sd = (
                    statistics.stdev(times)
                    if len(times) > 1
                    else 0.0
                )

                medians[model] = median

                status = (
                    statuses[0]
                    if len(statuses) == 1
                    else "MIXED"
                )

                valid = "YES"

                print(
                    f"{model:<15} | "
                    f"{status:<12} | "
                    f"{median:<11.3f} | "
                    f"{mean:<11.3f} | "
                    f"{sd:<11.3f} | "
                    f"{valid:<7}"
                )

            else:

                status = (
                    statuses[0]
                    if len(statuses) == 1
                    else (
                        "MIXED"
                        if statuses
                        else "N/A"
                    )
                )

                print(
                    f"{model:<15} | "
                    f"{status:<12} | "
                    f"{'N/A':<11} | "
                    f"{'N/A':<11} | "
                    f"{'N/A':<11} | "
                    f"{'NO':<7}"
                )

        if mode == "equiv":

            if (
                "Std-Explicit" in medians
                and "Std-Inline" in medians
                and medians["Std-Inline"] > 0
            ):

                scaling = (
                    medians["Std-Explicit"]
                    / medians["Std-Inline"]
                )

                direction = (
                    "Std-Explicit faster"
                    if scaling > 1.0
                    else "Std-Inline faster"
                )

                print(
                    f"\nStd representation "
                    f"scaling = "
                    f"{scaling:.3f}x "
                    f"({direction})"
                )

            print(
                "\nEquivalence interpretation:"
            )

            print(
                "  UNSAT = Std and SW are "
                "symbolically equivalent."
            )

            print(
                "  SAT   = a representation "
                "mismatch exists."
            )

        else:

            if (
                "Std-Explicit" in medians
                and "SW-Explicit" in medians
                and medians["SW-Explicit"] > 0
            ):

                scaling = (
                    medians["Std-Explicit"]
                    / medians["SW-Explicit"]
                )

                direction = (
                    "SW-Explicit faster"
                    if scaling > 1.0
                    else "Std-Explicit faster"
                )

                print(
                    f"\nPrimary metric "
                    f"S_{rounds} = "
                    f"{scaling:.3f}x "
                    f"({direction})"
                )

            else:

                print(
                    "\nPrimary metric unavailable: "
                    "one or both primary "
                    "representations did not "
                    "complete all trials."
                )


# ============================================================================
# Export
# ============================================================================

def export_data(
    results: List[TrialResult],
    json_file: str,
    csv_file: str,
) -> None:

    with open(
        json_file,
        "w",
        encoding="utf-8",
    ) as handle:

        json.dump(
            [asdict(result)
             for result in results],
            handle,
            indent=2,
        )

    with open(
        csv_file,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:

        fields = [
            "solver",
            "version",
            "mode",
            "rounds",
            "representation",
            "trial",
            "status",
            "runtime_seconds",
            "timeout",
            "verified",
            "message_diff",
        ]

        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
        )

        writer.writeheader()

        for result in results:
            writer.writerow(
                asdict(result)
            )

    print(
        f"\n[+] JSON: {json_file}"
    )

    print(
        f"[+] CSV : {csv_file}"
    )


# ============================================================================
# CLI helpers
# ============================================================================

def parse_diff(
    values: Optional[List[str]],
) -> Dict[int, int]:

    if not values:

        return {
            4: 0x80000000,
            9: 0x80000000,
        }

    result: Dict[int, int] = {}

    for item in values:

        if ":" not in item:
            raise ValueError(
                f"Invalid --diff {item!r}; "
                f"expected INDEX:HEX"
            )

        index_text, value_text = (
            item.split(":", 1)
        )

        try:

            index = int(
                index_text,
                10,
            )

            value = int(
                value_text,
                16,
            )

        except ValueError as exc:

            raise ValueError(
                f"Invalid --diff {item!r}; "
                f"expected INDEX:HEX"
            ) from exc

        if not 0 <= index < 16:

            raise ValueError(
                f"Message-word index {index} "
                f"is outside [0, 15]"
            )

        if not 0 <= value <= MASK32:

            raise ValueError(
                f"Difference {value_text!r} "
                f"is not a 32-bit value"
            )

        result[index] = value

    return result


def validate_rounds(
    rounds: List[int],
) -> None:

    if not rounds:
        raise ValueError(
            "At least one round count "
            "is required."
        )

    invalid = [
        value
        for value in rounds
        if not 1 <= value <= 64
    ]

    if invalid:

        raise ValueError(
            f"Round counts must be in [1, 64]: "
            f"{invalid}"
        )


# ============================================================================
# Main
# ============================================================================

def main() -> int:

    parser = argparse.ArgumentParser(
        description=(
            "SHA-256 sliding-window "
            "representation benchmark"
        )
    )

    parser.add_argument(
        "solver",
        nargs="?",
        default="z3",
        help="SMT solver executable",
    )

    parser.add_argument(
        "--mode",
        choices=[
            "collision",
            "equiv",
        ],
        default="collision",
        help=(
            "Benchmark mode: collision "
            "or symbolic equivalence"
        ),
    )

    parser.add_argument(
        "--rounds",
        nargs="+",
        type=int,
        default=[
            16,
            20,
            24,
            28,
            30,
        ],
        help=(
            "Collision benchmark rounds"
        ),
    )

    parser.add_argument(
        "--equiv-rounds",
        nargs="+",
        type=int,
        default=[
            8,
            16,
            24,
            32,
            48,
            64,
        ],
        help=(
            "Round counts used by "
            "--mode equiv"
        ),
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help=(
            "Collision solver timeout "
            "per instance"
        ),
    )

    parser.add_argument(
        "--equiv-timeout",
        type=int,
        default=120,
        help=(
            "Equivalence solver timeout "
            "per instance"
        ),
    )

    parser.add_argument(
        "--seed",
        type=int,
        default=0x5348572026,
    )

    parser.add_argument(
        "--diff",
        nargs="+",
        metavar="INDEX:HEX",
        help=(
            "Message-word XOR constraint, "
            "e.g. --diff "
            "4:80000000 9:80000000"
        ),
    )

    parser.add_argument(
        "--keep-smt",
        action="store_true",
        help=(
            "Keep generated SMT-LIB2 files"
        ),
    )

    parser.add_argument(
        "--json",
        default="sha256sw_benchmark.json",
    )

    parser.add_argument(
        "--csv",
        default="sha256sw_benchmark.csv",
    )

    parser.add_argument(
        "--skip-gate",
        action="store_true",
        help=(
            "Skip formal equivalence gate"
        ),
    )

    args = parser.parse_args()

    try:

        validate_rounds(
            args.rounds
        )

        validate_rounds(
            args.equiv_rounds
        )

        if args.trials < 1:
            raise ValueError(
                "--trials must be >= 1"
            )

        if args.timeout < 1:
            raise ValueError(
                "--timeout must be >= 1"
            )

        if args.equiv_timeout < 1:
            raise ValueError(
                "--equiv-timeout must be >= 1"
            )

        diff = parse_diff(
            args.diff
        )

    except ValueError as exc:

        parser.error(
            str(exc)
        )

    print("=" * 88)
    print("SHA256SW REPRESENTATION BENCHMARK")
    print("=" * 88)

    print(
        f"Mode     : {args.mode}"
    )

    print(
        f"Constants: {len(K)} "
        f"FIPS 180-4 words"
    )

    print(
        f"K[34]    : {K[34]:#010x}"
    )

    print()

    # ------------------------------------------------------------------------
    # Phase 0
    # ------------------------------------------------------------------------

    for rounds in (
        16,
        32,
        64,
    ):

        check_sw_recurrence(
            rounds,
            trials=250,
        )

    # ------------------------------------------------------------------------
    # Gate 0
    # ------------------------------------------------------------------------

    if not args.skip_gate:

        verify_formal_equivalence_gate(
            args.solver,
            min(
                args.equiv_timeout,
                args.timeout,
            ),
        )

    else:

        print(
            "[WARNING] Formal equivalence "
            "gate skipped."
        )

    # ------------------------------------------------------------------------
    # Phase 1
    # ------------------------------------------------------------------------

    if args.mode == "collision":

        results = run_collision_benchmark(
            args.rounds,
            diff,
            args.solver,
            args.trials,
            args.timeout,
            args.seed,
            args.keep_smt,
        )

    else:

        results = run_equiv_benchmark(
            args.equiv_rounds,
            args.solver,
            args.trials,
            args.equiv_timeout,
            args.seed,
            args.keep_smt,
        )

    # ------------------------------------------------------------------------
    # Phase 3
    # ------------------------------------------------------------------------

    print_summary(
        results,
        args.trials,
    )

    export_data(
        results,
        args.json,
        args.csv,
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
