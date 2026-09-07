#!/usr/bin/env python3
"""
sha256sw_advanced_finder_fixed.py

Reduced-round SHA-256 sliding-window / bidirectional research harness.

This is a research/benchmark implementation. It does NOT claim to
produce a practical full-round SHA-256 collision.

The implementation contains two deliberately separate layers:

1. A concrete SHA-256 implementation used as the reference implementation.
2. A CP-SAT bit-level encoding used for reduced-round experiments.

Any solver witness is independently recomputed with the concrete
SHA-256 implementation before it is reported as valid.

Dependencies
------------
    python -m pip install ortools

Examples
--------
    python3 benchmark/sha256sw_advanced_finder_fixed.py --self-test

    python3 benchmark/sha256sw_advanced_finder_fixed.py \
        --rounds 6 --meet-k 3 --timeout 10

    python3 benchmark/sha256sw_advanced_finder_fixed.py \
        --rounds 40 --meet-k 20 --timeout 10

    python3 benchmark/sha256sw_advanced_finder_fixed.py \
        --rounds 6 --sweep 1,2,3,4,5 --timeout 10
"""

from __future__ import annotations

import argparse
import hashlib
import random
import sys
import time
from typing import Dict, List, Sequence, Tuple

try:
    from ortools.sat.python import cp_model
except ImportError:
    print(
        "ERROR: OR-Tools is required.\n"
        "Install with:\n"
        "    python -m pip install ortools",
        file=sys.stderr,
    )
    raise SystemExit(1)


# ============================================================================
# CONSTANTS
# ============================================================================

MASK32 = 0xFFFFFFFF

IV: Tuple[int, ...] = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

K: Tuple[int, ...] = (
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

assert len(K) == 64
assert K[3] == 0xE9B5DBA5


# ============================================================================
# CONCRETE SHA-256 PRIMITIVES
# ============================================================================

def u32(x: int) -> int:
    return x & MASK32


def rotr(x: int, n: int) -> int:
    x &= MASK32
    return ((x >> n) | (x << (32 - n))) & MASK32


def shr(x: int, n: int) -> int:
    return (x & MASK32) >> n


def Sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def Sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def sigma0(x: int) -> int:
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3)


def sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10)


def Ch(x: int, y: int, z: int) -> int:
    return ((x & y) ^ ((~x) & z)) & MASK32


def Maj(x: int, y: int, z: int) -> int:
    return ((x & y) ^ (x & z) ^ (y & z)) & MASK32


# ============================================================================
# CONCRETE SHA-256 COMPRESSION
# ============================================================================

State = Tuple[int, int, int, int, int, int, int, int]


def expand_schedule(
    block: Sequence[int],
    rounds: int,
) -> List[int]:
    if len(block) != 16:
        raise ValueError(
            "SHA-256 compression requires exactly 16 input words."
        )

    if not 1 <= rounds <= 64:
        raise ValueError("rounds must be between 1 and 64.")

    w = [u32(x) for x in block]

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


def sha256_compress(
    block: Sequence[int],
    rounds: int = 64,
    iv: Sequence[int] = IV,
) -> List[State]:
    if len(iv) != 8:
        raise ValueError("IV must contain eight 32-bit words.")

    w = expand_schedule(block, rounds)

    a, b, c, d, e, f, g, h = map(u32, iv)

    states: List[State] = [
        (a, b, c, d, e, f, g, h)
    ]

    for i in range(rounds):
        t1 = u32(
            h
            + Sigma1(e)
            + Ch(e, f, g)
            + K[i]
            + w[i]
        )

        t2 = u32(
            Sigma0(a)
            + Maj(a, b, c)
        )

        a, b, c, d, e, f, g, h = (
            u32(t1 + t2),
            a,
            b,
            c,
            u32(d + t1),
            e,
            f,
            g,
        )

        states.append((a, b, c, d, e, f, g, h))

    return states


# ============================================================================
# EXACT ROUND INVERSION
# ============================================================================

def invert_round(
    next_state: State,
    w_i: int,
    k_i: int,
) -> State:
    ap, bp, cp, dp, ep, fp, gp, hp = next_state

    a = bp
    b = cp
    c = dp

    e = fp
    f = gp
    g = hp

    t2 = u32(
        Sigma0(a)
        + Maj(a, b, c)
    )

    t1 = u32(ap - t2)

    d = u32(ep - t1)

    h = u32(
        t1
        - Sigma1(e)
        - Ch(e, f, g)
        - k_i
        - w_i
    )

    return (
        a, b, c, d,
        e, f, g, h,
    )


# ============================================================================
# SLIDING-WINDOW COORDINATES
# ============================================================================

def state_to_window(state: State):
    a, b, c, d, e, f, g, h = state

    return (
        [d, c, b, a],
        [h, g, f, e],
    )


def window_to_state(
    A: Sequence[int],
    E: Sequence[int],
    i: int,
) -> State:
    return (
        A[i + 3],
        A[i + 2],
        A[i + 1],
        A[i],
        E[i + 3],
        E[i + 2],
        E[i + 1],
        E[i],
    )


def forward_sw_concrete(
    block: Sequence[int],
    rounds: int,
    iv: Sequence[int] = IV,
):
    w = expand_schedule(block, rounds)

    A, E = state_to_window(tuple(iv))

    for i in range(rounds):
        a = A[i + 3]
        b = A[i + 2]
        c = A[i + 1]
        d = A[i]

        e = E[i + 3]
        f = E[i + 2]
        g = E[i + 1]
        h = E[i]

        t1 = u32(
            h
            + Sigma1(e)
            + Ch(e, f, g)
            + K[i]
            + w[i]
        )

        t2 = u32(
            Sigma0(a)
            + Maj(a, b, c)
        )

        A.append(u32(t1 + t2))
        E.append(u32(d + t1))

    return A, E


def backward_sw_concrete(
    block: Sequence[int],
    rounds: int,
    final_state: State,
):
    w = expand_schedule(block, rounds)

    A: Dict[int, int] = {}
    E: Dict[int, int] = {}

    a, b, c, d, e, f, g, h = final_state

    A[rounds] = d
    A[rounds + 1] = c
    A[rounds + 2] = b
    A[rounds + 3] = a

    E[rounds] = h
    E[rounds + 1] = g
    E[rounds + 2] = f
    E[rounds + 3] = e

    for i in range(rounds - 1, -1, -1):
        a_i4 = A[i + 4]
        e_i4 = E[i + 4]

        t2 = u32(
            Sigma0(A[i + 3])
            + Maj(A[i + 3], A[i + 2], A[i + 1])
        )

        t1 = u32(a_i4 - t2)

        a_i = u32(e_i4 - t1)

        e_i = u32(
            t1
            - Sigma1(E[i + 3])
            - Ch(E[i + 3], E[i + 2], E[i + 1])
            - K[i]
            - w[i]
        )

        A[i] = a_i
        E[i] = e_i

    return A, E


# ============================================================================
# CP-SAT MODEL
# ============================================================================

BitVector = List[cp_model.IntVar]


class CPSATSWFinder:
    """
    Bit-level CP-SAT sliding-window bidirectional model.

    A single collision boundary S_R is shared by both message paths.
    Solver assignments are independently verified with the concrete
    SHA-256 implementation.
    """

    def __init__(
        self,
        rounds: int = 40,
        meet_k: int = 20,
        iv: Sequence[int] = IV,
        difference_round: int | None = None,
    ):
        if not 1 <= rounds <= 64:
            raise ValueError("rounds must be between 1 and 64.")

        if not 1 <= meet_k < rounds:
            raise ValueError(
                "meet_k must satisfy 1 <= meet_k < rounds."
            )

        if difference_round is None:
            difference_round = (
                27 if rounds > 27
                else (rounds // 2 if rounds > 1 else 0)
            )

        if not 0 <= difference_round <= rounds:
            raise ValueError(
                "difference_round outside round range."
            )

        self.rounds = rounds
        self.meet_k = meet_k
        self.iv = tuple(iv)
        self.difference_round = difference_round

        self.model = cp_model.CpModel()

        self.iv_bits: List[BitVector] = []

        for reg_idx, value in enumerate(self.iv):
            reg: BitVector = []

            for bit in range(32):
                bv = self.model.NewBoolVar(
                    f"iv_{reg_idx}_{bit}"
                )

                self.model.Add(
                    bv == ((value >> bit) & 1)
                )

                reg.append(bv)

            self.iv_bits.append(reg)

        self.m1: List[BitVector] = []
        self.m2: List[BitVector] = []

        self.w1 = None
        self.w2 = None

        self.Af1 = None
        self.Ef1 = None
        self.Af2 = None
        self.Ef2 = None

        self.Ab1 = None
        self.Eb1 = None
        self.Ab2 = None
        self.Eb2 = None

        self.coll_A = None
        self.coll_E = None

    # ----------------------------------------------------------------------
    # Boolean / arithmetic primitives
    # ----------------------------------------------------------------------

    def _add_u32(
        self,
        addends: Sequence[BitVector],
        prefix: str,
    ) -> BitVector:
        """
        Ripple-carry addition modulo 2^32.

        Each BitVector is little-endian by bit index.

        For n binary addends, the carry can range from 0 through n-1.
        The final carry beyond bit 31 is discarded.
        """
        if not addends:
            raise ValueError("At least one addend is required.")

        for word in addends:
            if len(word) != 32:
                raise ValueError("All bit-vectors must contain 32 bits.")

        out: BitVector = []

        n = len(addends)

        # Maximum carry after adding n bits is n - 1.
        carry_max = max(0, n - 1)

        carry = 0

        for bit in range(32):
            result = self.model.NewBoolVar(
                f"{prefix}_bit_{bit}"
            )

            carry_out = self.model.NewIntVar(
                0,
                carry_max,
                f"{prefix}_carry_{bit}"
            )

            self.model.Add(
                sum(word[bit] for word in addends)
                + carry
                == result + 2 * carry_out
            )

            out.append(result)
            carry = carry_out

        return out

    def _sub_u32(
        self,
        a: BitVector,
        b: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        Ripple-borrow subtraction:

            result = a - b (mod 2^32)
        """
        if len(a) != 32 or len(b) != 32:
            raise ValueError("All bit-vectors must contain 32 bits.")

        result: BitVector = []

        borrow = 0

        for bit in range(32):
            r = self.model.NewBoolVar(
                f"{prefix}_bit_{bit}"
            )

            borrow_out = self.model.NewBoolVar(
                f"{prefix}_borrow_{bit}"
            )

            # a_bit - b_bit - borrow =
            #     r - 2*borrow_out
            #
            # Rearranged:
            #
            # r + b + borrow = a + 2*borrow_out
            self.model.Add(
                r
                + b[bit]
                + borrow
                == a[bit]
                + 2 * borrow_out
            )

            result.append(r)
            borrow = borrow_out

        return result

    def _xor3(
        self,
        a: BitVector,
        b: BitVector,
        c: BitVector,
        prefix: str,
    ) -> BitVector:
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            self.model.AddBoolXOr([
                a[bit],
                b[bit],
                c[bit],
                q.Not(),
            ])

            out.append(q)

        return out

    def _ch(
        self,
        x: BitVector,
        y: BitVector,
        z: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        SHA-256 Ch(x,y,z) = (x & y) ^ (~x & z).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            self.model.Add(
                q == y[bit]
            ).OnlyEnforceIf(x[bit])

            self.model.Add(
                q == z[bit]
            ).OnlyEnforceIf(x[bit].Not())

            out.append(q)

        return out

    def _maj(
        self,
        a: BitVector,
        b: BitVector,
        c: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        SHA-256 Maj(a,b,c).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            total = a[bit] + b[bit] + c[bit]

            self.model.Add(
                total >= 2
            ).OnlyEnforceIf(q)

            self.model.Add(
                total <= 1
            ).OnlyEnforceIf(q.Not())

            out.append(q)

        return out

    # ----------------------------------------------------------------------
    # SHA bit permutations
    # ----------------------------------------------------------------------

    def _big_sigma0(
        self,
        x: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            self.model.AddBoolXOr([
                x[(bit + 2) % 32],
                x[(bit + 13) % 32],
                x[(bit + 22) % 32],
                q.Not(),
            ])

            out.append(q)

        return out

    def _big_sigma1(
        self,
        x: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            self.model.AddBoolXOr([
                x[(bit + 6) % 32],
                x[(bit + 11) % 32],
                x[(bit + 25) % 32],
                q.Not(),
            ])

            out.append(q)

        return out

    def _small_sigma0(
        self,
        x: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            literals = [
                x[(bit + 7) % 32],
                x[(bit + 18) % 32],
            ]

            if bit + 3 < 32:
                literals.append(x[bit + 3])

            literals.append(q.Not())

            self.model.AddBoolXOr(literals)

            out.append(q)

        return out

    def _small_sigma1(
        self,
        x: BitVector,
        prefix: str,
    ) -> BitVector:
        """
        ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x).
        """
        out: BitVector = []

        for bit in range(32):
            q = self.model.NewBoolVar(
                f"{prefix}_{bit}"
            )

            literals = [
                x[(bit + 17) % 32],
                x[(bit + 19) % 32],
            ]

            if bit + 10 < 32:
                literals.append(x[bit + 10])

            literals.append(q.Not())

            self.model.AddBoolXOr(literals)

            out.append(q)

        return out

    # ----------------------------------------------------------------------
    # Message schedule
    # ----------------------------------------------------------------------

    def build_schedule(
        self,
        message_words: List[BitVector],
        prefix: str,
    ):
        if len(message_words) != 16:
            raise ValueError(
                "A SHA-256 message block must contain 16 words."
            )

        w = list(message_words)

        for t in range(16, self.rounds):
            s1 = self._small_sigma1(
                w[t - 2],
                f"{prefix}_sig1_{t}",
            )

            s0 = self._small_sigma0(
                w[t - 15],
                f"{prefix}_sig0_{t}",
            )

            wt = self._add_u32(
                [
                    w[t - 16],
                    s0,
                    w[t - 7],
                    s1,
                ],
                f"{prefix}_W_{t}",
            )

            w.append(wt)

        return w

    # ----------------------------------------------------------------------
    # Message construction
    # ----------------------------------------------------------------------

    def _new_message(
        self,
        prefix: str,
    ) -> List[BitVector]:
        return [
            [
                self.model.NewBoolVar(
                    f"{prefix}_m_{i}_{bit}"
                )
                for bit in range(32)
            ]
            for i in range(16)
        ]

    def _add_distinct_messages(
        self,
        active_words_range: Tuple[int, int],
    ):
        low, high = active_words_range

        low = max(0, low)
        high = min(16, high)

        consumed = min(self.rounds, 16)

        low = min(low, consumed)
        high = min(high, consumed)

        difference_bits = []

        for i in range(16):
            for bit in range(32):
                if low <= i < high:
                    d = self.model.NewBoolVar(
                        f"msg_diff_{i}_{bit}"
                    )

                    self.model.AddBoolXOr([
                        self.m1[i][bit],
                        self.m2[i][bit],
                        d.Not(),
                    ])

                    difference_bits.append(d)
                else:
                    self.model.Add(
                        self.m1[i][bit]
                        == self.m2[i][bit]
                    )

        if not difference_bits:
            raise ValueError(
                "active_words_range contains no consumed "
                "message words."
            )

        self.model.AddBoolOr(difference_bits)

    # ----------------------------------------------------------------------
    # Forward trajectory
    # ----------------------------------------------------------------------

    def _forward_path(
        self,
        w,
        prefix: str,
    ):
        A: List[BitVector] = [
            self.iv_bits[3],
            self.iv_bits[2],
            self.iv_bits[1],
            self.iv_bits[0],
        ]

        E: List[BitVector] = [
            self.iv_bits[7],
            self.iv_bits[6],
            self.iv_bits[5],
            self.iv_bits[4],
        ]

        for r in range(self.meet_k):
            a = A[r + 3]
            b = A[r + 2]
            c = A[r + 1]
            d = A[r]

            e = E[r + 3]
            f = E[r + 2]
            g = E[r + 1]
            h = E[r]

            k_bits = [
                ((K[r] >> bit) & 1)
                for bit in range(32)
            ]

            big1 = self._big_sigma1(
                e,
                f"{prefix}_Sigma1_{r}",
            )

            ch = self._ch(
                e,
                f,
                g,
                f"{prefix}_Ch_{r}",
            )

            t1 = self._add_u32(
                [h, big1, ch, k_bits, w[r]],
                f"{prefix}_T1_{r}",
            )

            big0 = self._big_sigma0(
                a,
                f"{prefix}_Sigma0_{r}",
            )

            maj = self._maj(
                a,
                b,
                c,
                f"{prefix}_Maj_{r}",
            )

            t2 = self._add_u32(
                [big0, maj],
                f"{prefix}_T2_{r}",
            )

            new_a = self._add_u32(
                [t1, t2],
                f"{prefix}_A_{r}",
            )

            new_e = self._add_u32(
                [d, t1],
                f"{prefix}_E_{r}",
            )

            A.append(new_a)
            E.append(new_e)

        return A, E

    # ----------------------------------------------------------------------
    # Shared final collision state
    # ----------------------------------------------------------------------

    def _make_collision_boundary(self):
        self.coll_A = {
            self.rounds + j: [
                self.model.NewBoolVar(
                    f"collision_A_{j}_{bit}"
                )
                for bit in range(32)
            ]
            for j in range(4)
        }

        self.coll_E = {
            self.rounds + j: [
                self.model.NewBoolVar(
                    f"collision_E_{j}_{bit}"
                )
                for bit in range(32)
            ]
            for j in range(4)
        }

    # ----------------------------------------------------------------------
    # Backward trajectory
    # ----------------------------------------------------------------------

    def _backward_path(
        self,
        w,
        prefix: str,
    ):
        A = dict(self.coll_A)
        E = dict(self.coll_E)

        for r in range(
            self.rounds - 1,
            self.meet_k - 1,
            -1,
        ):
            a_r4 = A[r + 4]
            e_r4 = E[r + 4]

            big0 = self._big_sigma0(
                A[r + 3],
                f"{prefix}_Sigma0_{r}",
            )

            maj = self._maj(
                A[r + 3],
                A[r + 2],
                A[r + 1],
                f"{prefix}_Maj_{r}",
            )

            t2 = self._add_u32(
                [big0, maj],
                f"{prefix}_T2_{r}",
            )

            t1 = self._sub_u32(
                a_r4,
                t2,
                f"{prefix}_T1_{r}",
            )

            a_r = self._sub_u32(
                e_r4,
                t1,
                f"{prefix}_A_{r}",
            )

            big1 = self._big_sigma1(
                E[r + 3],
                f"{prefix}_Sigma1_{r}",
            )

            ch = self._ch(
                E[r + 3],
                E[r + 2],
                E[r + 1],
                f"{prefix}_Ch_{r}",
            )

            k_bits = [
                ((K[r] >> bit) & 1)
                for bit in range(32)
            ]

            subtrahend = self._add_u32(
                [
                    big1,
                    ch,
                    k_bits,
                    w[r],
                ],
                f"{prefix}_SUB_{r}",
            )

            e_r = self._sub_u32(
                t1,
                subtrahend,
                f"{prefix}_E_{r}",
            )

            A[r] = a_r
            E[r] = e_r

        return A, E

    # ----------------------------------------------------------------------
    # State difference
    # ----------------------------------------------------------------------

    def _state_difference(
        self,
        A1,
        E1,
        A2,
        E2,
        round_number: int,
        prefix: str,
    ):
        differences = []

        for j in range(4):
            for bit in range(32):
                da = self.model.NewBoolVar(
                    f"{prefix}_A_{j}_{bit}"
                )

                self.model.AddBoolXOr([
                    A1[round_number + j][bit],
                    A2[round_number + j][bit],
                    da.Not(),
                ])

                differences.append(da)

                de = self.model.NewBoolVar(
                    f"{prefix}_E_{j}_{bit}"
                )

                self.model.AddBoolXOr([
                    E1[round_number + j][bit],
                    E2[round_number + j][bit],
                    de.Not(),
                ])

                differences.append(de)

        self.model.AddBoolOr(differences)

    # ----------------------------------------------------------------------
    # Complete model
    # ----------------------------------------------------------------------

    def build(
        self,
        active_words_range: Tuple[int, int] = (0, 4),
    ):
        self.m1 = self._new_message("path1")
        self.m2 = self._new_message("path2")

        self._add_distinct_messages(
            active_words_range
        )

        self.w1 = self.build_schedule(
            self.m1,
            "path1_schedule",
        )

        self.w2 = self.build_schedule(
            self.m2,
            "path2_schedule",
        )

        self.Af1, self.Ef1 = self._forward_path(
            self.w1,
            "path1_forward",
        )

        self.Af2, self.Ef2 = self._forward_path(
            self.w2,
            "path2_forward",
        )

        self._make_collision_boundary()

        self.Ab1, self.Eb1 = self._backward_path(
            self.w1,
            "path1_backward",
        )

        self.Ab2, self.Eb2 = self._backward_path(
            self.w2,
            "path2_backward",
        )

        for Af, Ef, Ab, Eb in (
            (self.Af1, self.Ef1, self.Ab1, self.Eb1),
            (self.Af2, self.Ef2, self.Ab2, self.Eb2),
        ):
            for j in range(4):
                for bit in range(32):
                    self.model.Add(
                        Af[self.meet_k + j][bit]
                        == Ab[self.meet_k + j][bit]
                    )

                    self.model.Add(
                        Ef[self.meet_k + j][bit]
                        == Eb[self.meet_k + j][bit]
                    )

        if self.difference_round <= self.meet_k:
            A1, E1 = self.Af1, self.Ef1
            A2, E2 = self.Af2, self.Ef2
        else:
            A1, E1 = self.Ab1, self.Eb1
            A2, E2 = self.Ab2, self.Eb2

        self._state_difference(
            A1,
            E1,
            A2,
            E2,
            self.difference_round,
            f"state_difference_{self.difference_round}",
        )

        return self

    # ----------------------------------------------------------------------
    # Model statistics
    # ----------------------------------------------------------------------

    def stats(self):
        proto = self.model.Proto()

        return {
            "variables": len(proto.variables),
            "constraints": len(proto.constraints),
            "model_stats": self.model.ModelStats(),
        }

    # ----------------------------------------------------------------------
    # Extraction helpers
    # ----------------------------------------------------------------------

    @staticmethod
    def _bits_to_word(
        solver: cp_model.CpSolver,
        bits: BitVector,
    ) -> int:
        value = 0

        for bit, bv in enumerate(bits):
            value |= int(solver.Value(bv)) << bit

        return value & MASK32

    def extract_message(
        self,
        solver: cp_model.CpSolver,
        message: List[BitVector],
    ) -> Tuple[int, ...]:
        return tuple(
            self._bits_to_word(solver, word)
            for word in message
        )

    # ----------------------------------------------------------------------
    # Solve
    # ----------------------------------------------------------------------

    def solve(
        self,
        timeout_sec: float = 10.0,
        workers: int = 4,
    ):
        solver = cp_model.CpSolver()

        solver.parameters.max_time_in_seconds = timeout_sec
        solver.parameters.num_search_workers = workers
        solver.parameters.log_search_progress = False

        print(
            "[*] CP-SAT SW-BIDIRECTIONAL BENCHMARK\n"
            f"    rounds={self.rounds} | "
            f"k={self.meet_k} | "
            f"timeout={timeout_sec}s | "
            f"difference_round={self.difference_round}"
        )

        t0 = time.perf_counter()
        status = solver.Solve(self.model)
        elapsed = time.perf_counter() - t0

        name = solver.StatusName(status)

        print(f"    Status      : {name}")
        print(f"    Solve time  : {elapsed:.3f}s")
        print(f"    Conflicts   : {solver.NumConflicts():,}")
        print(f"    Branches    : {solver.NumBranches():,}")

        if status not in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ):
            return {
                "status": name,
                "elapsed": elapsed,
                "conflicts": solver.NumConflicts(),
                "branches": solver.NumBranches(),
                "valid": False,
                "m1": None,
                "m2": None,
            }

        m1 = self.extract_message(solver, self.m1)
        m2 = self.extract_message(solver, self.m2)

        s1 = sha256_compress(
            m1,
            self.rounds,
            self.iv,
        )

        s2 = sha256_compress(
            m2,
            self.rounds,
            self.iv,
        )

        valid_collision = (
            s1[-1] == s2[-1]
            and m1 != m2
        )

        valid_difference = (
            s1[self.difference_round]
            != s2[self.difference_round]
        )

        valid = valid_collision and valid_difference

        print("\n    Independent witness verification:")
        print(f"      collision       = {valid_collision}")
        print(
            f"      S_{self.difference_round} difference = "
            f"{valid_difference}"
        )
        print(f"      valid           = {valid}")

        if valid:
            print(
                "\n    M1:",
                " ".join(f"{x:08x}" for x in m1),
            )

            print(
                "    M2:",
                " ".join(f"{x:08x}" for x in m2),
            )

        return {
            "status": name,
            "elapsed": elapsed,
            "conflicts": solver.NumConflicts(),
            "branches": solver.NumBranches(),
            "valid": valid,
            "m1": m1,
            "m2": m2,
        }


# ============================================================================
# TEST DATA
# ============================================================================

def abc_block() -> Tuple[int, ...]:
    block = bytearray(64)

    msg = b"abc"

    block[:3] = msg
    block[3] = 0x80
    block[56:64] = (24).to_bytes(8, "big")

    return tuple(
        int.from_bytes(
            block[i:i + 4],
            "big",
        )
        for i in range(0, 64, 4)
    )


def random_block(
    rng: random.Random,
) -> Tuple[int, ...]:
    return tuple(
        rng.getrandbits(32)
        for _ in range(16)
    )


# ============================================================================
# CONCRETE SELF-TESTS
# ============================================================================

def test_sha256_abc():
    block = abc_block()

    states = sha256_compress(
        block,
        rounds=64,
        iv=IV,
    )

    final = states[-1]

    digest = "".join(
        f"{u32(final[i] + IV[i]):08x}"
        for i in range(8)
    )

    expected = hashlib.sha256(
        b"abc"
    ).hexdigest()

    assert digest == expected, (
        "SHA-256 mismatch:\n"
        f"implementation = {digest}\n"
        f"hashlib       = {expected}"
    )


def test_round_inversion():
    block = abc_block()
    rounds = 40

    states = sha256_compress(
        block,
        rounds,
        IV,
    )

    w = expand_schedule(
        block,
        rounds,
    )

    for r in range(rounds - 1, -1, -1):
        recovered = invert_round(
            states[r + 1],
            w[r],
            K[r],
        )

        assert recovered == states[r], (
            f"Round inversion failed at round {r}"
        )


def test_sliding_window():
    block = abc_block()
    rounds = 40

    states = sha256_compress(
        block,
        rounds,
        IV,
    )

    A, E = forward_sw_concrete(
        block,
        rounds,
        IV,
    )

    assert len(A) == rounds + 4
    assert len(E) == rounds + 4

    for i in range(rounds + 1):
        recovered = window_to_state(
            A,
            E,
            i,
        )

        assert recovered == states[i], (
            f"Sliding-window mismatch at state {i}"
        )


def test_backward_window():
    block = abc_block()
    rounds = 40

    states = sha256_compress(
        block,
        rounds,
        IV,
    )

    A, E = backward_sw_concrete(
        block,
        rounds,
        states[-1],
    )

    for i in range(rounds + 1):
        recovered = window_to_state(
            A,
            E,
            i,
        )

        assert recovered == states[i], (
            f"Backward reconstruction mismatch at state {i}"
        )


def test_individual_inverse_rounds():
    block = abc_block()
    rounds = 40

    states = sha256_compress(
        block,
        rounds,
        IV,
    )

    w = expand_schedule(
        block,
        rounds,
    )

    for r in (
        0,
        1,
        2,
        7,
        15,
        20,
        27,
        31,
        39,
    ):
        recovered = invert_round(
            states[r + 1],
            w[r],
            K[r],
        )

        assert recovered == states[r]


def test_random_concrete_rounds():
    rng = random.Random(0x53484132)

    for rounds in (
        1,
        2,
        4,
        8,
        16,
        32,
        40,
        64,
    ):
        for _ in range(5):
            block = random_block(rng)

            states = sha256_compress(
                block,
                rounds,
                IV,
            )

            w = expand_schedule(
                block,
                rounds,
            )

            for r in range(rounds):
                assert (
                    invert_round(
                        states[r + 1],
                        w[r],
                        K[r],
                    )
                    == states[r]
                )

            A, E = forward_sw_concrete(
                block,
                rounds,
                IV,
            )

            for i in range(rounds + 1):
                assert (
                    window_to_state(
                        A,
                        E,
                        i,
                    )
                    == states[i]
                )

            Ab, Eb = backward_sw_concrete(
                block,
                rounds,
                states[-1],
            )

            for i in range(rounds + 1):
                assert (
                    window_to_state(
                        Ab,
                        Eb,
                        i,
                    )
                    == states[i]
                )


# ============================================================================
# CP-SAT PRIMITIVE EQUIVALENCE TESTS
# ============================================================================

def _make_fixed_word(
    model: cp_model.CpModel,
    value: int,
    prefix: str,
) -> BitVector:
    bits = []

    value &= MASK32

    for bit in range(32):
        b = model.NewBoolVar(
            f"{prefix}_{bit}"
        )

        model.Add(
            b == ((value >> bit) & 1)
        )

        bits.append(b)

    return bits


def _solve_model(
    model: cp_model.CpModel,
    timeout: float = 5.0,
):
    solver = cp_model.CpSolver()

    solver.parameters.max_time_in_seconds = timeout
    solver.parameters.num_search_workers = 1

    status = solver.Solve(model)

    return solver, status


def _bits_value(
    solver: cp_model.CpSolver,
    bits: BitVector,
) -> int:
    value = 0

    for bit, b in enumerate(bits):
        value |= int(solver.Value(b)) << bit

    return value & MASK32


def test_cpsat_bit_primitives():
    """
    Verify every CP-SAT primitive independently against the
    concrete SHA-256 primitive.

    Each primitive gets its own model. This makes a primitive
    encoding bug immediately identifiable instead of collapsing
    into a generic INFEASIBLE result in one giant model.
    """
    rng = random.Random(0x43505341)

    for case in range(4):
        x = rng.getrandbits(32)
        y = rng.getrandbits(32)
        z = rng.getrandbits(32)

        # --------------------------------------------------------------
        # Addition
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"add_x_{case}",
        )

        yb = _make_fixed_word(
            model,
            y,
            f"add_y_{case}",
        )

        zb = _make_fixed_word(
            model,
            z,
            f"add_z_{case}",
        )

        add = holder._add_u32(
            [xb, yb, zb],
            f"add_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT addition primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            add,
        ) == u32(x + y + z), (
            f"addition primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # Subtraction
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"sub_x_{case}",
        )

        yb = _make_fixed_word(
            model,
            y,
            f"sub_y_{case}",
        )

        sub = holder._sub_u32(
            xb,
            yb,
            f"sub_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT subtraction primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            sub,
        ) == u32(x - y), (
            f"subtraction primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # Ch
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"ch_x_{case}",
        )

        yb = _make_fixed_word(
            model,
            y,
            f"ch_y_{case}",
        )

        zb = _make_fixed_word(
            model,
            z,
            f"ch_z_{case}",
        )

        ch = holder._ch(
            xb,
            yb,
            zb,
            f"ch_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT Ch primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            ch,
        ) == Ch(x, y, z), (
            f"Ch primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # Maj
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"maj_x_{case}",
        )

        yb = _make_fixed_word(
            model,
            y,
            f"maj_y_{case}",
        )

        zb = _make_fixed_word(
            model,
            z,
            f"maj_z_{case}",
        )

        maj = holder._maj(
            xb,
            yb,
            zb,
            f"maj_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT Maj primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            maj,
        ) == Maj(x, y, z), (
            f"Maj primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # Sigma0
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"s0_x_{case}",
        )

        s0 = holder._big_sigma0(
            xb,
            f"s0_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT Sigma0 primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            s0,
        ) == Sigma0(x), (
            f"Sigma0 primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # Sigma1
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"s1_x_{case}",
        )

        s1 = holder._big_sigma1(
            xb,
            f"s1_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT Sigma1 primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            s1,
        ) == Sigma1(x), (
            f"Sigma1 primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # small sigma0
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"ss0_x_{case}",
        )

        ss0 = holder._small_sigma0(
            xb,
            f"ss0_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT small-sigma0 primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            ss0,
        ) == sigma0(x), (
            f"small sigma0 primitive mismatch at case {case}"
        )

        # --------------------------------------------------------------
        # small sigma1
        # --------------------------------------------------------------
        model = cp_model.CpModel()

        holder = CPSATSWFinder(
            rounds=2,
            meet_k=1,
        )

        holder.model = model

        xb = _make_fixed_word(
            model,
            x,
            f"ss1_x_{case}",
        )

        ss1 = holder._small_sigma1(
            xb,
            f"ss1_{case}",
        )

        solver, status = _solve_model(model)

        assert status in (
            cp_model.OPTIMAL,
            cp_model.FEASIBLE,
        ), (
            f"CP-SAT small-sigma1 primitive became "
            f"{solver.StatusName(status)} "
            f"for case {case}"
        )

        assert _bits_value(
            solver,
            ss1,
        ) == sigma1(x), (
            f"small sigma1 primitive mismatch at case {case}"
        )


def test_cpsat_trajectory_equivalence():
    """
    Pin a complete random message into the CP-SAT model and verify
    the modeled forward trajectory against concrete SHA-256.
    """
    rng = random.Random(0x5452414A)

    rounds = 6

    finder = CPSATSWFinder(
        rounds=rounds,
        meet_k=3,
        difference_round=3,
    )

    finder.m1 = finder._new_message(
        "test_path1"
    )

    finder.m2 = finder._new_message(
        "test_path2"
    )

    block = random_block(rng)

    # Pin both messages to the same concrete block.
    for i, word in enumerate(block):
        for bit in range(32):
            value = (word >> bit) & 1

            finder.model.Add(
                finder.m1[i][bit] == value
            )

            finder.model.Add(
                finder.m2[i][bit] == value
            )

    w1 = finder.build_schedule(
        finder.m1,
        "test_schedule",
    )

    Af, Ef = finder._forward_path(
        w1,
        "test_forward",
    )

    solver = cp_model.CpSolver()

    solver.parameters.max_time_in_seconds = 20.0
    solver.parameters.num_search_workers = 1

    status = solver.Solve(
        finder.model
    )

    assert status in (
        cp_model.OPTIMAL,
        cp_model.FEASIBLE,
    ), solver.StatusName(status)

    concrete = sha256_compress(
        block,
        rounds,
        IV,
    )

    for r, state in enumerate(concrete):
        modeled = (
            _bits_value(solver, Af[r + 3]),
            _bits_value(solver, Af[r + 2]),
            _bits_value(solver, Af[r + 1]),
            _bits_value(solver, Af[r]),
            _bits_value(solver, Ef[r + 3]),
            _bits_value(solver, Ef[r + 2]),
            _bits_value(solver, Ef[r + 1]),
            _bits_value(solver, Ef[r]),
        )

        assert modeled == state, (
            f"CP-SAT forward trajectory mismatch at S_{r}:\n"
            f"modeled  = {modeled}\n"
            f"concrete = {state}"
        )


def run_self_tests():
    print("=" * 78)
    print("SHA256SW SELF-TEST")
    print("=" * 78)

    assert K[3] == 0xE9B5DBA5
    print(
        "[PASS] NIST K[3] = 0xE9B5DBA5"
    )

    test_sha256_abc()
    print(
        "[PASS] SHA-256 abc matches hashlib"
    )

    test_round_inversion()
    print(
        "[PASS] Exact inversion verified across 40 rounds"
    )

    test_individual_inverse_rounds()
    print(
        "[PASS] Individual inverse-round checks passed"
    )

    test_sliding_window()
    print(
        "[PASS] Forward sliding-window coordinates verified"
    )

    test_backward_window()
    print(
        "[PASS] Backward sliding-window reconstruction verified"
    )

    test_random_concrete_rounds()
    print(
        "[PASS] Randomized concrete regression tests passed"
    )

    test_cpsat_bit_primitives()
    print(
        "[PASS] CP-SAT bit primitives match concrete functions"
    )

    test_cpsat_trajectory_equivalence()
    print(
        "[PASS] CP-SAT forward trajectory matches concrete SHA-256"
    )

    print(
        "\n[PASS] ALL SELF-TESTS PASSED"
    )


# ============================================================================
# BENCHMARK
# ============================================================================

def run_benchmark(
    rounds: int,
    meet_k: int,
    timeout: float,
    difference_round: int | None = None,
    workers: int = 4,
    active_words_range: Tuple[int, int] = (0, 4),
):
    if difference_round is None:
        difference_round = (
            27 if rounds > 27
            else (rounds // 2 if rounds > 1 else 0)
        )

    print("=" * 78)
    print("SHA256SW BIDIRECTIONAL BENCHMARK")
    print("=" * 78)

    finder = CPSATSWFinder(
        rounds=rounds,
        meet_k=meet_k,
        iv=IV,
        difference_round=difference_round,
    )

    t0 = time.perf_counter()

    finder.build(
        active_words_range=active_words_range,
    )

    build_time = time.perf_counter() - t0

    stats = finder.stats()

    print(
        f"Rounds={rounds} | "
        f"k={meet_k} | "
        f"timeout={timeout}s | "
        f"difference_round={difference_round}"
    )

    print(
        f"Build time       : {build_time:.3f}s"
    )

    print(
        f"Variables        : {stats['variables']:,}"
    )

    print(
        f"Constraints      : {stats['constraints']:,}"
    )

    return finder.solve(
        timeout_sec=timeout,
        workers=workers,
    )


# ============================================================================
# K SWEEP
# ============================================================================

def parse_sweep(
    value: str,
) -> Tuple[int, ...]:
    result = []

    for item in value.split(","):
        item = item.strip()

        if item:
            result.append(int(item))

    if not result:
        raise ValueError(
            "Empty sweep."
        )

    return tuple(result)


def run_sweep(
    rounds: int,
    sweep_points: Sequence[int],
    timeout: float,
        difference_round: int | None = None,
    workers: int = 4,
):
    if difference_round is None:
        difference_round = (
            27
            if rounds > 27
            else (rounds // 2 if rounds > 1 else None)
        )

    print("=" * 78)
    print("SHA256SW MEETING-POINT SWEEP")
    print("=" * 78)

    print(
        f"Rounds={rounds} | "
        f"timeout={timeout}s | "
        f"difference_round={difference_round}"
    )

    rows = []

    for k in sweep_points:
        if not 1 <= k < rounds:
            print(
                f"\n[skip] k={k}: "
                f"requires 1 <= k < {rounds}"
            )
            continue

        print(
            f"\n--- k={k:02d} "
            f"(forward={k}, backward={rounds-k}) ---"
        )

        finder = CPSATSWFinder(
            rounds=rounds,
            meet_k=k,
            iv=IV,
            difference_round=difference_round,
        )

        t0 = time.perf_counter()

        finder.build(
            active_words_range=(0, 4)
        )

        build = time.perf_counter() - t0

        proto = finder.model.Proto()

        result = finder.solve(
            timeout_sec=timeout,
            workers=workers,
        )

        row = {
            "k": k,
            "build": build,
            "variables": len(proto.variables),
            "constraints": len(proto.constraints),
            **result,
        }

        rows.append(row)

    print("\n" + "=" * 78)
    print("SWEEP SUMMARY")
    print("=" * 78)

    print(
        f"{'k':>3} "
        f"{'build':>8} "
        f"{'vars':>9} "
        f"{'constraints':>12} "
        f"{'time':>9} "
        f"{'conflicts':>12} "
        f"{'branches':>12} "
        f"{'status':>10}"
    )

    for row in rows:
        print(
            f"{row['k']:3d} "
            f"{row['build']:8.3f} "
            f"{row['variables']:9,d} "
            f"{row['constraints']:12,d} "
            f"{row['elapsed']:9.3f} "
            f"{row['conflicts']:12,d} "
            f"{row['branches']:12,d} "
            f"{row['status']:>10}"
        )

    return rows

