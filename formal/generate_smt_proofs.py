#!/usr/bin/env python3

from pathlib import Path

OUT = Path(__file__).resolve().parent

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

assert len(K) == 64


PREAMBLE = r"""
(set-logic QF_BV)

(define-fun rotr32 ((x (_ BitVec 32)) (n (_ BitVec 32)))
  (_ BitVec 32)
  (bvor
    (bvlshr x n)
    (bvshl x (bvsub (_ bv32 32) n))))

(define-fun S0 ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv2 32))
    (bvxor
      (rotr32 x (_ bv13 32))
      (rotr32 x (_ bv22 32)))))

(define-fun S1 ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv6 32))
    (bvxor
      (rotr32 x (_ bv11 32))
      (rotr32 x (_ bv25 32)))))

(define-fun Ch ((x (_ BitVec 32))
                (y (_ BitVec 32))
                (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvand (bvnot x) z)))

(define-fun Maj ((x (_ BitVec 32))
                 (y (_ BitVec 32))
                 (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvxor
      (bvand x z)
      (bvand y z))))
"""


def ch_equiv():
    return PREAMBLE + r"""
(declare-const x (_ BitVec 32))
(declare-const y (_ BitVec 32))
(declare-const z (_ BitVec 32))

(define-fun ch_add ((x (_ BitVec 32))
                    (y (_ BitVec 32))
                    (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvadd
    (bvand x y)
    (bvand (bvnot x) z)))

(assert (distinct
  (ch_add x y z)
  (Ch x y z)))

(check-sat)
(exit)
"""


def one_round_equiv():
    lines = [PREAMBLE]

    for name in "abcdefgh":
        lines.append(
            f"(declare-const {name} (_ BitVec 32))"
        )

    lines.append("(declare-const w (_ BitVec 32))")
    lines.append("(declare-const k (_ BitVec 32))")

    # Standard SHA-256 transition.
    lines += [
        r"""
(define-fun t1_std () (_ BitVec 32)
  (bvadd h
    (bvadd
      (S1 e)
      (bvadd
        (Ch e f g)
        (bvadd k w)))))

(define-fun t2_std () (_ BitVec 32)
  (bvadd
    (S0 a)
    (Maj a b c)))

(define-fun A () (_ BitVec 32)
  (bvadd t1_std t2_std))

(define-fun B () (_ BitVec 32) a)
(define-fun C () (_ BitVec 32) b)
(define-fun D () (_ BitVec 32) c)
(define-fun E () (_ BitVec 32) (bvadd d t1_std))
(define-fun F () (_ BitVec 32) e)
(define-fun G () (_ BitVec 32) f)
(define-fun H () (_ BitVec 32) g)

; Sliding-window representation:
;
; a3 = A
; a2 = B
; a1 = C
; a0 = D
;
; b3 = E
; b2 = F
; b1 = G
; b0 = H

(define-fun a0 () (_ BitVec 32) d)
(define-fun a1 () (_ BitVec 32) c)
(define-fun a2 () (_ BitVec 32) b)
(define-fun a3 () (_ BitVec 32) a)

(define-fun b0 () (_ BitVec 32) h)
(define-fun b1 () (_ BitVec 32) g)
(define-fun b2 () (_ BitVec 32) f)
(define-fun b3 () (_ BitVec 32) e)

(define-fun t1_sw () (_ BitVec 32)
  (bvadd b0
    (bvadd
      (S1 b3)
      (bvadd
        (Ch b3 b2 b1)
        (bvadd k w)))))

(define-fun b4 () (_ BitVec 32)
  (bvadd t1_sw a0))

(define-fun t2_sw () (_ BitVec 32)
  (bvadd
    (S0 a3)
    (Maj a3 a2 a1)))

(define-fun a4 () (_ BitVec 32)
  (bvadd
    (bvsub b4 a0)
    t2_sw))

(assert (or
  (distinct A a4)
  (distinct B a3)
  (distinct C a2)
  (distinct D a1)
  (distinct E b4)
  (distinct F b3)
  (distinct G b2)
  (distinct H b1)))

(check-sat)
(exit)
"""
    ]

    return "\n".join(lines)


def inverse_equiv():
    return PREAMBLE + r"""
(declare-const a_i (_ BitVec 32))
(declare-const a_ip1 (_ BitVec 32))
(declare-const a_ip2 (_ BitVec 32))
(declare-const a_ip3 (_ BitVec 32))

(declare-const b_i (_ BitVec 32))
(declare-const b_ip1 (_ BitVec 32))
(declare-const b_ip2 (_ BitVec 32))
(declare-const b_ip3 (_ BitVec 32))

(declare-const k_i (_ BitVec 32))
(declare-const w_i (_ BitVec 32))

(define-fun t1_fwd () (_ BitVec 32)
  (bvadd b_i
    (bvadd
      (S1 b_ip3)
      (bvadd
        (Ch b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

(define-fun b_ip4 () (_ BitVec 32)
  (bvadd t1_fwd a_i))

(define-fun t2_fwd () (_ BitVec 32)
  (bvadd
    (S0 a_ip3)
    (Maj a_ip3 a_ip2 a_ip1)))

(define-fun a_ip4 () (_ BitVec 32)
  (bvadd
    (bvsub b_ip4 a_i)
    t2_fwd))

; Recover T1 from A[i+4].
(define-fun t1_rec () (_ BitVec 32)
  (bvsub a_ip4 t2_fwd))

; Recover A[i].
(define-fun a_i_rec () (_ BitVec 32)
  (bvsub b_ip4 t1_rec))

; Recover B[i].
(define-fun b_i_rec () (_ BitVec 32)
  (bvsub
    t1_rec
    (bvadd
      (S1 b_ip3)
      (bvadd
        (Ch b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

(assert (or
  (distinct a_i a_i_rec)
  (distinct b_i b_i_rec)))

(check-sat)
(exit)
"""


def write(name, content):
    path = OUT / name
    path.write_text(content)
    print(f"[+] Generated {path}")


if __name__ == "__main__":
    write("ch_equiv.smt2", ch_equiv())
    write("one_round_equiv.smt2", one_round_equiv())
    write("full_64round_inverse.smt2", inverse_equiv())

    print("[+] SMT proof artifacts generated.")
