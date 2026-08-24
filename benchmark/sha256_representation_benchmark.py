#!/usr/bin/env python3
"""
sha256_representation_benchmark.py
Comparative cryptanalytic and constraint-modeling benchmark for SHA-256.

Methodological structure:
  Static Validation : Verifies FIPS 180-4 constants and state invariants.
  Phase 0           : Direct Python recurrence verification (16, 32, 64 rounds).
  Gate 0            : Formal symbolic equivalence gate via SMT (Std == SW on symbolic IV/W).
  Phase 1           : Comparative multi-trial benchmark with randomized execution order.
  Phase 2           : Independent pure-Python verification of all SAT collision witnesses.
  Phase 3           : Structured reporting and machine-readable JSON/CSV export.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# ============================================================================
# FIPS 180-4 SHA-256 Constants & Static Invariant Checks
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
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

IV = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

MASK32 = 0xFFFFFFFF

# Static assertions
assert len(K) == 64, f"Invariant violation: len(K) must be 64, got {len(K)}"
assert len(IV) == 8, f"Invariant violation: len(IV) must be 8, got {len(IV)}"
assert K[34] == 0x4d2c6dfc, f"Invariant violation: K[34] expected 0x4d2c6dfc, got {hex(K[34])}"

# ============================================================================
# Independent Python SHA-256 Engine (Non-sliding verification reference)
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

def sha256_reduced_compress_py(iv: List[int], words: List[int], rounds: int) -> List[int]:
    """Pure Python reference implementation of reduced-round SHA-256 compression."""
    if not (1 <= rounds <= 64):
        raise ValueError("rounds must be in [1, 64]")
    if len(words) < 16:
        raise ValueError("Need at least 16 base message words")

    w = [x & MASK32 for x in words[:16]]
    for i in range(16, rounds):
        w.append((w[i - 16] + small_sigma0(w[i - 15]) + w[i - 7] + small_sigma1(w[i - 2])) & MASK32)

    a, b, c, d, e, f, g, h = iv
    for i in range(rounds):
        t1 = (h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i]) & MASK32
        t2 = (big_sigma0(a) + maj(a, b, c)) & MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & MASK32

    return [
        (iv[0] + a) & MASK32, (iv[1] + b) & MASK32,
        (iv[2] + c) & MASK32, (iv[3] + d) & MASK32,
        (iv[4] + e) & MASK32, (iv[5] + f) & MASK32,
        (iv[6] + g) & MASK32, (iv[7] + h) & MASK32
    ]

def check_sw_recurrence(rounds: int, trials: int = 250) -> None:
    """Directly tests SW recurrence equations against standard recurrence in Python."""
    rng = random.Random(0x534857 ^ rounds)
    for trial in range(trials):
        state = [rng.getrandbits(32) for _ in range(8)]
        w = [rng.getrandbits(32) for _ in range(rounds)]

        a, b, c, d, e, f, g, h = state
        a_mt = [d, c, b, a]
        b_mt = [h, g, f, e]

        for i in range(rounds):
            t1 = (h + big_sigma1(e) + ch(e, f, g) + K[i] + w[i]) & MASK32
            t2 = (big_sigma0(a) + maj(a, b, c)) & MASK32
            exp_a = (t1 + t2) & MASK32
            exp_e = (d + t1) & MASK32

            sw_t1 = (b_mt[i] + big_sigma1(b_mt[i+3]) + ch(b_mt[i+3], b_mt[i+2], b_mt[i+1]) + K[i] + w[i]) & MASK32
            sw_b_next = (a_mt[i] + sw_t1) & MASK32
            sw_t2 = (big_sigma0(a_mt[i+3]) + maj(a_mt[i+3], a_mt[i+2], a_mt[i+1])) & MASK32
            sw_a_next = ((sw_b_next - a_mt[i]) + sw_t2) & MASK32

            if sw_b_next != exp_e or sw_a_next != exp_a:
                raise AssertionError(f"SW recurrence mismatch at trial {trial}, round {i}")

            a_mt.append(sw_a_next)
            b_mt.append(sw_b_next)
            a, b, c, d, e, f, g, h = exp_a, a, b, c, exp_e, e, f, g

    print(f" [PASS] Direct Python Recurrence Check: {trials} trials x {rounds} rounds -> EXACT MATCH")

# ============================================================================
# SMT-LIB2 Generation (QF_BV)
# ============================================================================

PREAMBLE = """(set-logic QF_BV)
(set-option :produce-models true)

(define-fun rotr32 ((x (_ BitVec 32)) (n (_ BitVec 32))) (_ BitVec 32)
  (bvor (bvlshr x n) (bvshl x (bvsub (_ bv32 32) n))))

(define-fun S0 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv2 32)) (bvxor (rotr32 x (_ bv13 32)) (rotr32 x (_ bv22 32)))))

(define-fun S1 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv6 32)) (bvxor (rotr32 x (_ bv11 32)) (rotr32 x (_ bv25 32)))))

(define-fun s0 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv7 32)) (bvxor (rotr32 x (_ bv18 32)) (bvlshr x (_ bv3 32)))))

(define-fun s1 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv17 32)) (bvxor (rotr32 x (_ bv19 32)) (bvlshr x (_ bv10 32)))))

(define-fun ch_std ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvxor (bvand x y) (bvand (bvnot x) z)))

(define-fun ch_sw ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvadd (bvand x y) (bvand (bvnot x) z)))

(define-fun Maj ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvxor (bvand x y) (bvxor (bvand x z) (bvand y z))))
"""

def bv32(x: int) -> str:
    return f"#x{x & MASK32:08x}"

def emit_msg_schedule(rounds: int, prefix: str) -> str:
    lines = []
    for i in range(16):
        lines.append(f"(declare-const {prefix}w_{i} (_ BitVec 32))")
    for i in range(16, rounds):
        lines.append(f"(define-fun {prefix}w_{i} () (_ BitVec 32) "
                     f"(bvadd (bvadd {prefix}w_{i-16} (s0 {prefix}w_{i-15})) "
                     f"(bvadd {prefix}w_{i-7} (s1 {prefix}w_{i-2}))))")
    return "\n".join(lines)

def emit_diff_constraints(diff_pattern: Dict[int, int]) -> str:
    lines = []
    if diff_pattern:
        for idx, diff in sorted(diff_pattern.items()):
            lines.append(f"(assert (= (bvxor m1_w_{idx} m2_w_{idx}) {bv32(diff)}))")
    else:
        conds = [f"(distinct m1_w_{i} m2_w_{i})" for i in range(16)]
        lines.append(f"(assert (or {' '.join(conds)}))")
    return "\n".join(lines)

def emit_witness_request() -> str:
    names = [f"m{b}_w_{i}" for b in (1, 2) for i in range(16)]
    return "(check-sat)\n(get-value (" + " ".join(names) + "))\n(exit)"

# 1. Standard-Explicit (Primary Baseline)
def build_std_explicit(rounds: int, diff_pattern: Dict[int, int]) -> str:
    lines = [PREAMBLE, emit_msg_schedule(rounds, "m1_"), emit_msg_schedule(rounds, "m2_"), emit_diff_constraints(diff_pattern)]
    for p in ("m1_", "m2_"):
        for i in range(rounds + 1):
            for name in "abcdefgh":
                lines.append(f"(declare-const {p}{name}_{i} (_ BitVec 32))")
        for idx, name in enumerate("abcdefgh"):
            lines.append(f"(assert (= {p}{name}_0 {bv32(IV[idx])}))")
        for i in range(rounds):
            k = bv32(K[i])
            lines.append(f"(define-fun {p}t1_{i} () (_ BitVec 32) (bvadd {p}h_{i} (bvadd (S1 {p}e_{i}) (bvadd (ch_std {p}e_{i} {p}f_{i} {p}g_{i}) (bvadd {k} {p}w_{i})))))")
            lines.append(f"(define-fun {p}t2_{i} () (_ BitVec 32) (bvadd (S0 {p}a_{i}) (Maj {p}a_{i} {p}b_{i} {p}c_{i})))")
            lines.append(f"(assert (= {p}a_{i+1} (bvadd {p}t1_{i} {p}t2_{i})))")
            lines.append(f"(assert (= {p}b_{i+1} {p}a_{i}))")
            lines.append(f"(assert (= {p}c_{i+1} {p}b_{i}))")
            lines.append(f"(assert (= {p}d_{i+1} {p}c_{i}))")
            lines.append(f"(assert (= {p}e_{i+1} (bvadd {p}d_{i} {p}t1_{i})))")
            lines.append(f"(assert (= {p}f_{i+1} {p}e_{i}))")
            lines.append(f"(assert (= {p}g_{i+1} {p}f_{i}))")
            lines.append(f"(assert (= {p}h_{i+1} {p}g_{i}))")
    for name in "abcdefgh":
        lines.append(f"(assert (= (bvadd m1_{name}_0 m1_{name}_{rounds}) (bvadd m2_{name}_0 m2_{name}_{rounds})))")
    lines.append(emit_witness_request())
    return "\n".join(lines)

# 2. SHA256SW-Explicit (Primary Evaluation Target)
def build_sw_explicit(rounds: int, diff_pattern: Dict[int, int]) -> str:
    lines = [PREAMBLE, emit_msg_schedule(rounds, "m1_"), emit_msg_schedule(rounds, "m2_"), emit_diff_constraints(diff_pattern)]
    for p in ("m1_", "m2_"):
        for i in range(rounds + 4):
            lines.append(f"(declare-const {p}a_mt_{i} (_ BitVec 32))")
            lines.append(f"(declare-const {p}b_mt_{i} (_ BitVec 32))")
        lines.extend([
            f"(assert (= {p}a_mt_0 {bv32(IV[3])}))", f"(assert (= {p}a_mt_1 {bv32(IV[2])}))",
            f"(assert (= {p}a_mt_2 {bv32(IV[1])}))", f"(assert (= {p}a_mt_3 {bv32(IV[0])}))",
            f"(assert (= {p}b_mt_0 {bv32(IV[7])}))", f"(assert (= {p}b_mt_1 {bv32(IV[6])}))",
            f"(assert (= {p}b_mt_2 {bv32(IV[5])}))", f"(assert (= {p}b_mt_3 {bv32(IV[4])}))",
        ])
        for i in range(rounds):
            k = bv32(K[i])
            lines.append(f"(define-fun {p}t1_{i} () (_ BitVec 32) (bvadd {p}b_mt_{i} (bvadd (S1 {p}b_mt_{i+3}) (bvadd (ch_sw {p}b_mt_{i+3} {p}b_mt_{i+2} {p}b_mt_{i+1}) (bvadd {k} {p}w_{i})))))")
            lines.append(f"(define-fun {p}t2_{i} () (_ BitVec 32) (bvadd (S0 {p}a_mt_{i+3}) (Maj {p}a_mt_{i+3} {p}a_mt_{i+2} {p}a_mt_{i+1})))")
            lines.append(f"(assert (= {p}b_mt_{i+4} (bvadd {p}a_mt_{i} {p}t1_{i})))")
            lines.append(f"(assert (= {p}a_mt_{i+4} (bvadd (bvsub {p}b_mt_{i+4} {p}a_mt_{i}) {p}t2_{i})))")

    # Collision mapping
    mappings = [(IV[0], "a", rounds+3), (IV[1], "a", rounds+2), (IV[2], "a", rounds+1), (IV[3], "a", rounds),
                (IV[4], "b", rounds+3), (IV[5], "b", rounds+2), (IV[6], "b", rounds+1), (IV[7], "b", rounds)]
    for iv_val, fam, idx in mappings:
        lines.append(f"(assert (= (bvadd {bv32(iv_val)} m1_{fam}_mt_{idx}) (bvadd {bv32(iv_val)} m2_{fam}_mt_{idx})))")
    lines.append(emit_witness_request())
    return "\n".join(lines)

# 3. Standard-Inline (Control Baseline)
def build_std_inline(rounds: int, diff_pattern: Dict[int, int]) -> str:
    lines = [PREAMBLE, emit_msg_schedule(rounds, "m1_"), emit_msg_schedule(rounds, "m2_"), emit_diff_constraints(diff_pattern)]
    for p in ("m1_", "m2_"):
        for idx, name in enumerate("abcdefgh"):
            lines.append(f"(define-fun {p}{name}_0 () (_ BitVec 32) {bv32(IV[idx])})")
        for i in range(rounds):
            k = bv32(K[i])
            lines.append(f"(define-fun {p}t1_{i} () (_ BitVec 32) (bvadd {p}h_{i} (bvadd (S1 {p}e_{i}) (bvadd (ch_std {p}e_{i} {p}f_{i} {p}g_{i}) (bvadd {k} {p}w_{i})))))")
            lines.append(f"(define-fun {p}t2_{i} () (_ BitVec 32) (bvadd (S0 {p}a_{i}) (Maj {p}a_{i} {p}b_{i} {p}c_{i})))")
            lines.append(f"(define-fun {p}a_{i+1} () (_ BitVec 32) (bvadd {p}t1_{i} {p}t2_{i}))")
            lines.append(f"(define-fun {p}b_{i+1} () (_ BitVec 32) {p}a_{i})")
            lines.append(f"(define-fun {p}c_{i+1} () (_ BitVec 32) {p}b_{i})")
            lines.append(f"(define-fun {p}d_{i+1} () (_ BitVec 32) {p}c_{i})")
            lines.append(f"(define-fun {p}e_{i+1} () (_ BitVec 32) (bvadd {p}d_{i} {p}t1_{i}))")
            lines.append(f"(define-fun {p}f_{i+1} () (_ BitVec 32) {p}e_{i})")
            lines.append(f"(define-fun {p}g_{i+1} () (_ BitVec 32) {p}f_{i})")
            lines.append(f"(define-fun {p}h_{i+1} () (_ BitVec 32) {p}g_{i})")
    for name in "abcdefgh":
        lines.append(f"(assert (= (bvadd m1_{name}_0 m1_{name}_{rounds}) (bvadd m2_{name}_0 m2_{name}_{rounds})))")
    lines.append(emit_witness_request())
    return "\n".join(lines)

# 4. SHA256SW-Inline (Control Target)
def build_sw_inline(rounds: int, diff_pattern: Dict[int, int]) -> str:
    lines = [PREAMBLE, emit_msg_schedule(rounds, "m1_"), emit_msg_schedule(rounds, "m2_"), emit_diff_constraints(diff_pattern)]
    for p in ("m1_", "m2_"):
        lines.extend([
            f"(define-fun {p}a_mt_0 () (_ BitVec 32) {bv32(IV[3])})", f"(define-fun {p}a_mt_1 () (_ BitVec 32) {bv32(IV[2])})",
            f"(define-fun {p}a_mt_2 () (_ BitVec 32) {bv32(IV[1])})", f"(define-fun {p}a_mt_3 () (_ BitVec 32) {bv32(IV[0])})",
            f"(define-fun {p}b_mt_0 () (_ BitVec 32) {bv32(IV[7])})", f"(define-fun {p}b_mt_1 () (_ BitVec 32) {bv32(IV[6])})",
            f"(define-fun {p}b_mt_2 () (_ BitVec 32) {bv32(IV[5])})", f"(define-fun {p}b_mt_3 () (_ BitVec 32) {bv32(IV[4])})",
        ])
        for i in range(rounds):
            k = bv32(K[i])
            lines.append(f"(define-fun {p}t1_{i} () (_ BitVec 32) (bvadd {p}b_mt_{i} (bvadd (S1 {p}b_mt_{i+3}) (bvadd (ch_sw {p}b_mt_{i+3} {p}b_mt_{i+2} {p}b_mt_{i+1}) (bvadd {k} {p}w_{i})))))")
            lines.append(f"(define-fun {p}b_mt_{i+4} () (_ BitVec 32) (bvadd {p}a_mt_{i} {p}t1_{i}))")
            lines.append(f"(define-fun {p}t2_{i} () (_ BitVec 32) (bvadd (S0 {p}a_mt_{i+3}) (Maj {p}a_mt_{i+3} {p}a_mt_{i+2} {p}a_mt_{i+1})))")
            lines.append(f"(define-fun {p}a_mt_{i+4} () (_ BitVec 32) (bvadd (bvsub {p}b_mt_{i+4} {p}a_mt_{i}) {p}t2_{i}))")
    mappings = [(IV[0], "a", rounds+3), (IV[1], "a", rounds+2), (IV[2], "a", rounds+1), (IV[3], "a", rounds),
                (IV[4], "b", rounds+3), (IV[5], "b", rounds+2), (IV[6], "b", rounds+1), (IV[7], "b", rounds)]
    for iv_val, fam, idx in mappings:
        lines.append(f"(assert (= (bvadd {bv32(iv_val)} m1_{fam}_mt_{idx}) (bvadd {bv32(iv_val)} m2_{fam}_mt_{idx})))")
    lines.append(emit_witness_request())
    return "\n".join(lines)

BUILDERS = {
    "Std-Explicit": build_std_explicit,
    "SW-Explicit":  build_sw_explicit,
    "Std-Inline":   build_std_inline,
    "SW-Inline":    build_sw_inline
}

# ============================================================================
# Witness & Output Parsing
# ============================================================================

def parse_witness(stdout: str) -> Optional[Dict[str, int]]:
    result: Dict[str, int] = {}
    for match in re.finditer(r'\(\s*(m[12]_w_\d+)\s+(#x[0-9a-fA-F]+|\(_\s+bv([0-9]+)\s+32\))\s*\)', stdout):
        name = match.group(1)
        token = match.group(2)
        if token.startswith("#x"):
            result[name] = int(token[2:], 16)
        else:
            result[name] = int(match.group(3), 10)

    expected = {f"m{b}_w_{i}" for b in (1, 2) for i in range(16)}
    return result if expected.issubset(result.keys()) else None

def parse_status(stdout: str, stderr: str = "") -> str:
    for line in stdout.splitlines():
        token = line.strip().lower()
        if token in ("sat", "unsat", "unknown"):
            return token
        if token.startswith("sat"):
            return "sat"
        if token.startswith("unsat"):
            return "unsat"
    combined = (stdout + "\n" + stderr).lower()
    if "timeout" in combined:
        return "timeout"
    if "error" in combined:
        return "error"
    return "unknown"

@dataclass
class TrialResult:
    solver: str
    version: str
    rounds: int
    representation: str
    trial: int
    status: str
    runtime_seconds: float
    timeout: bool
    verified: Optional[bool]
    message_diff: str

def run_solver_instance(model_name: str, rounds: int, trial: int, diff: Dict[int, int],
                        solver_cmd: str, solver_ver: str, timeout: int, keep_smt: bool) -> TrialResult:
    code = BUILDERS[model_name](rounds, diff)
    filename = Path(f"tmp_{model_name.replace('-', '_')}_r{rounds}_t{trial}_{random.randint(1000, 9999)}.smt2")
    filename.write_text(code)

    try:
        t0 = time.perf_counter()
        try:
            proc = subprocess.run([solver_cmd, str(filename)], capture_output=True, text=True, timeout=timeout)
            runtime = time.perf_counter() - t0
            status = parse_status(proc.stdout, proc.stderr)
            is_timeout = False
        except subprocess.TimeoutExpired:
            runtime = float(timeout)
            status = "timeout"
            is_timeout = True
            proc = None

        verified: Optional[bool] = None
        if status == "sat" and proc:
            witness = parse_witness(proc.stdout)
            if witness is not None:
                m1_words = [witness[f"m1_w_{i}"] for i in range(16)]
                m2_words = [witness[f"m2_w_{i}"] for i in range(16)]
                h1 = sha256_reduced_compress_py(IV, m1_words, rounds)
                h2 = sha256_reduced_compress_py(IV, m2_words, rounds)
                diff_ok = (m1_words != m2_words)
                hash_ok = (h1 == h2)
                verified = bool(diff_ok and hash_ok)
            else:
                verified = False

        return TrialResult(
            solver=solver_cmd,
            version=solver_ver,
            rounds=rounds,
            representation=model_name,
            trial=trial,
            status=status,
            runtime_seconds=runtime,
            timeout=is_timeout,
            verified=verified,
            message_diff=str(diff)
        )
    finally:
        if not keep_smt and filename.exists():
            try:
                filename.unlink()
            except Exception:
                pass

# ============================================================================
# Gate 0: Formal Symbolic Equivalence Gate (Std == SW on arbitrary IV/W)
# ============================================================================

def verify_formal_equivalence_gate(solver_cmd: str, rounds_to_verify: List[int]) -> None:
    print("=" * 88)
    print("GATE 0: Proving Mathematical Bit-Equivalence (Std == SW on Fully Symbolic IV/W)")
    print("=" * 88)

    check_rounds = sorted(list(set(rounds_to_verify + [1, 2, 4, 8, 16, 32, 64])))
    for r in check_rounds:
        lines = [PREAMBLE]
        for val in "abcdefgh":
            lines.append(f"(declare-const {val}_0 (_ BitVec 32))")
        for i in range(r):
            lines.append(f"(declare-const w_{i} (_ BitVec 32))")

        for i in range(r):
            k = bv32(K[i])
            lines.append(f"(define-fun t1_std_{i} () (_ BitVec 32) (bvadd h_{i} (bvadd (S1 e_{i}) (bvadd (ch_std e_{i} f_{i} g_{i}) (bvadd {k} w_{i})))))")
            lines.append(f"(define-fun t2_std_{i} () (_ BitVec 32) (bvadd (S0 a_{i}) (Maj a_{i} b_{i} c_{i})))")
            lines.append(f"(define-fun a_{i+1} () (_ BitVec 32) (bvadd t1_std_{i} t2_std_{i}))")
            lines.append(f"(define-fun b_{i+1} () (_ BitVec 32) a_{i})")
            lines.append(f"(define-fun c_{i+1} () (_ BitVec 32) b_{i})")
            lines.append(f"(define-fun d_{i+1} () (_ BitVec 32) c_{i})")
            lines.append(f"(define-fun e_{i+1} () (_ BitVec 32) (bvadd d_{i} t1_std_{i}))")
            lines.append(f"(define-fun f_{i+1} () (_ BitVec 32) e_{i})")
            lines.append(f"(define-fun g_{i+1} () (_ BitVec 32) f_{i})")
            lines.append(f"(define-fun h_{i+1} () (_ BitVec 32) g_{i})")

        lines.extend([
            "(define-fun a_mt_0 () (_ BitVec 32) d_0)", "(define-fun a_mt_1 () (_ BitVec 32) c_0)",
            "(define-fun a_mt_2 () (_ BitVec 32) b_0)", "(define-fun a_mt_3 () (_ BitVec 32) a_0)",
            "(define-fun b_mt_0 () (_ BitVec 32) h_0)", "(define-fun b_mt_1 () (_ BitVec 32) g_0)",
            "(define-fun b_mt_2 () (_ BitVec 32) f_0)", "(define-fun b_mt_3 () (_ BitVec 32) e_0)",
        ])
        for i in range(r):
            k = bv32(K[i])
            lines.append(f"(define-fun t1_sw_{i} () (_ BitVec 32) (bvadd b_mt_{i} (bvadd (S1 b_mt_{i+3}) (bvadd (ch_sw b_mt_{i+3} b_mt_{i+2} b_mt_{i+1}) (bvadd {k} w_{i})))))")
            lines.append(f"(define-fun b_mt_{i+4} () (_ BitVec 32) (bvadd a_mt_{i} t1_sw_{i}))")
            lines.append(f"(define-fun t2_sw_{i} () (_ BitVec 32) (bvadd (S0 a_mt_{i+3}) (Maj a_mt_{i+3} a_mt_{i+2} a_mt_{i+1})))")
            lines.append(f"(define-fun a_mt_{i+4} () (_ BitVec 32) (bvadd (bvsub b_mt_{i+4} a_mt_{i}) t2_sw_{i}))")

        lines.append(f"""
(assert (or
  (distinct a_{r} a_mt_{r+3}) (distinct b_{r} a_mt_{r+2})
  (distinct c_{r} a_mt_{r+1}) (distinct d_{r} a_mt_{r})
  (distinct e_{r} b_mt_{r+3}) (distinct f_{r} b_mt_{r+2})
  (distinct g_{r} b_mt_{r+1}) (distinct h_{r} b_mt_{r})))
(check-sat)
(exit)
""")
        code = "\n".join(lines)
        fn = Path(f"gate0_r{r}.smt2")
        fn.write_text(code)
        try:
            t0 = time.perf_counter()
            proc = subprocess.run([solver_cmd, str(fn)], capture_output=True, text=True, timeout=60)
            elapsed = time.perf_counter() - t0
            res = parse_status(proc.stdout, proc.stderr)
            if res == "unsat":
                print(f" [PASS] Round {r:2d} Symbolic Equivalence -> UNSAT (Proved in {elapsed:.3f}s)")
            else:
                print(f" [FATAL] Equivalence Gate Failed at round {r}: got {res}")
                sys.exit(1)
        finally:
            if fn.exists():
                fn.unlink()
    print("Gate 0 passed: Equivalence holds across all target round depths.\n")

# ============================================================================
# Main Benchmark Execution Engine
# ============================================================================

def get_solver_version(solver_cmd: str) -> str:
    try:
        proc = subprocess.run([solver_cmd, "--version"], capture_output=True, text=True, timeout=5)
        return (proc.stdout.strip() or proc.stderr.strip()).splitlines()[0]
    except Exception:
        return "Unknown Version"

def run_benchmark(rounds_list: List[int], diff_pattern: Dict[int, int], solver_cmd: str,
                  trials: int, timeout: int, seed: int, keep_smt: bool) -> List[TrialResult]:
    solver_ver = get_solver_version(solver_cmd)
    print("=" * 88)
    print(f"BENCHMARK: {len(rounds_list)} Round Configurations | {trials} Randomized Trials")
    print(f"Solver : {solver_cmd} ({solver_ver})")
    print(f"Diff   : {diff_pattern} | Timeout: {timeout}s | Seed: {hex(seed)}")
    print("=" * 88)

    rng = random.Random(seed)
    all_results: List[TrialResult] = []

    for r in rounds_list:
        print(f"\n--- Target: {r} Rounds ---")
        models = list(BUILDERS.keys())

        for trial in range(trials):
            rng.shuffle(models) # Eliminate order / thermal bias
            for model in models:
                res = run_solver_instance(model, r, trial, diff_pattern, solver_cmd, solver_ver, timeout, keep_smt)
                all_results.append(res)
                v_str = f"verified={res.verified}" if res.verified is not None else ""
                print(f"  Trial {trial+1:2d}/{trials} | {res.representation:<14} | {res.status:<7} | {res.runtime_seconds:7.3f}s | {v_str}")

                if res.status == "sat" and res.verified is False:
                    print(f"[FATAL] SAT witness from {res.representation} failed pure-Python verification!")
                    sys.exit(1)

    return all_results

def print_summary_and_scaling(results: List[TrialResult]) -> None:
    print("\n" + "=" * 88)
    print("BENCHMARK SUMMARY & PRIMARY SCALING METRIC (S_R)")
    print("=" * 88)

    rounds_set = sorted(list(set(r.rounds for r in results)))
    for r in rounds_set:
        print(f"\n[Rounds: {r}]")
        header = f"{'Model':<15} | {'Status':<7} | {'Median (s)':<10} | {'Mean (s)':<9} | {'StdDev (s)':<10} | {'Timeouts':<8} | {'Verified'}"
        print(header)
        print("-" * len(header))

        med_times: Dict[str, float] = {}

        for model in ["Std-Explicit", "SW-Explicit", "Std-Inline", "SW-Inline"]:
            m_res = [res for res in results if res.rounds == r and res.representation == model]
            valid_times = [res.runtime_seconds for res in m_res if not res.timeout]
            statuses = sorted(list(set(res.status for res in m_res)))
            stat_str = statuses[0] if len(statuses) == 1 else "MIXED"
            timeouts = sum(1 for res in m_res if res.timeout)

            verif_vals = [res.verified for res in m_res if res.verified is not None]
            ver_str = "VALID" if (verif_vals and all(verif_vals)) else ("FAIL" if False in verif_vals else "N/A")

            if valid_times:
                med_t = statistics.median(valid_times)
                mean_t = statistics.mean(valid_times)
                sd_t = statistics.stdev(valid_times) if len(valid_times) > 1 else 0.0
                med_times[model] = med_t
                print(f"{model:<15} | {stat_str:<7} | {med_t:<10.3f} | {mean_t:<9.3f} | {sd_t:<10.3f} | {timeouts:<8d} | {ver_str}")
            else:
                print(f"{model:<15} | {'TIMEOUT':<7} | {'>'+str(m_res[0].runtime_seconds):<10} | {'N/A':<9} | {'N/A':<10} | {timeouts:<8d} | {ver_str}")

        # Primary metric S_R calculation
        if "Std-Explicit" in med_times and "SW-Explicit" in med_times:
            t_std = med_times["Std-Explicit"]
            t_sw = med_times["SW-Explicit"]
            if t_sw > 0:
                s_r = t_std / t_sw
                fav = "SW-Explicit faster" if s_r > 1.0 else "Std-Explicit faster"
                print(f"  --> Primary Scaling Metric S_{r} = {s_r:.3f}x ({fav})")

def export_data(results: List[TrialResult], json_file: str, csv_file: str) -> None:
    # JSON Export
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in results], f, indent=2)
    print(f"\n[+] Results exported to JSON: {json_file}")

    # CSV Export
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "solver", "version", "rounds", "representation", "trial",
            "status", "runtime_seconds", "timeout", "verified", "message_diff"
        ])
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))
    print(f"[+] Results exported to CSV:  {csv_file}")

# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(description="Empirical & Formal Benchmark: Standard vs Sliding-Window SHA-256")
    parser.add_argument("solver", nargs="?", default="z3", help="SMT solver executable (default: z3)")
    parser.add_argument("--rounds", nargs="+", type=int, default=[16, 20, 24, 28, 30], help="Rounds to benchmark")
    parser.add_argument("--trials", type=int, default=3, help="Randomized trials per configuration")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout in seconds per trial")
    parser.add_argument("--seed", type=int, default=0x53485732, help="PRNG seed")
    parser.add_argument("--diff", action="append", default=None, metavar="INDEX:HEX", help="XOR diff e.g. --diff 4:80000000")
    parser.add_argument("--json-output", default="sha256_results.json", help="JSON output file")
    parser.add_argument("--csv-output", default="sha256_results.csv", help="CSV output file")
    parser.add_argument("--keep-smt", action="store_true", help="Retain generated SMT-LIB files")
    parser.add_argument("--no-sanity", action="store_true", help="Skip Phase 0/Gate 0 checks")

    args = parser.parse_args()

    # Parse message difference
    diff_pattern: Dict[int, int] = {}
    if args.diff:
        for item in args.diff:
            idx_s, val_s = item.split(":", 1)
            diff_pattern[int(idx_s, 10)] = int(val_s, 16)
    else:
        diff_pattern = {4: 0x80000000, 9: 0x80000000}

    print("=" * 88)
    print("SHA-256 SLIDING-WINDOW (SHA256SW) FORMAL & EMPIRICAL BENCHMARK")
    print("=" * 88)

    if not args.no_sanity:
        print("\n[PHASE 0] Direct Python Recurrence Invariant Checks...")
        for r in (16, 32, 64):
            check_sw_recurrence(r, trials=250)
        verify_formal_equivalence_gate(args.solver, args.rounds)

    results = run_benchmark(
        rounds_list=args.rounds,
        diff_pattern=diff_pattern,
        solver_cmd=args.solver,
        trials=args.trials,
        timeout=args.timeout,
        seed=args.seed,
        keep_smt=args.keep_smt
    )

    print_summary_and_scaling(results)
    export_data(results, args.json_output, args.csv_output)

if __name__ == "__main__":
    main()
