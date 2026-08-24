#!/usr/bin/env python3
"""
Generate SMT-LIB2 proof obligations for SHA256SW.

Generated files:

    ch_equiv.smt2
        Proves that the arithmetic and XOR formulations of Ch are
        equivalent for 32-bit bit-vectors.

    full_64round_equiv.smt2
        Proves that the standard SHA-256 eight-register recurrence and
        the SHA256SW sliding-window recurrence produce identical states
        after all 64 rounds.

    full_64round_inverse.smt2
        Proves that one SHA256SW step is algebraically invertible with
        respect to the oldest a/b coordinates when the remaining window,
        K_i and W_i, and next coordinates are known.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parent


# FIPS 180-4 SHA-256 round constants.
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

assert len(K) == 64
assert K[34] == 0x4D2C6DFC
assert K[37] == 0x766A0ABB


def write_file(name: str, content: str) -> None:
    path = ROOT / name
    path.write_text(content, encoding="utf-8")
    print(f"[+] Generated {path}")


def generate_ch_equiv() -> None:
    content = """\
; SHA-256 Ch equivalence
;
; Arithmetic:
;     (x & y) + (~x & z)
;
; XOR:
;     (x & y) ^ (~x & z)
;
; The two masked operands are bitwise disjoint, so their addition
; is identical to XOR.

(set-logic QF_BV)

(declare-const x (_ BitVec 32))
(declare-const y (_ BitVec 32))
(declare-const z (_ BitVec 32))

(define-fun ch_arith
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvadd
    (bvand x y)
    (bvand (bvnot x) z)))

(define-fun ch_xor
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvand (bvnot x) z)))

; Negate the desired theorem. UNSAT means equivalence is proven.
(assert (distinct
  (ch_arith x y z)
  (ch_xor x y z)))

(check-sat)
(exit)
"""

    write_file("ch_equiv.smt2", content)


def generate_full_64round() -> None:
    lines = [
        "; SHA-256 standard vs SHA256SW sliding-window equivalence",
        "",
        "(set-logic QF_BV)",
        "",
        "(define-fun rotr32",
        "  ((x (_ BitVec 32)) (n (_ BitVec 32)))",
        "  (_ BitVec 32)",
        "  (bvor",
        "    (bvlshr x n)",
        "    (bvshl x (bvsub (_ bv32 32) n))))",
        "",
        "(define-fun s0 ((x (_ BitVec 32))) (_ BitVec 32)",
        "  (bvxor",
        "    (rotr32 x (_ bv2 32))",
        "    (bvxor",
        "      (rotr32 x (_ bv13 32))",
        "      (rotr32 x (_ bv22 32)))))",
        "",
        "(define-fun s1 ((x (_ BitVec 32))) (_ BitVec 32)",
        "  (bvxor",
        "    (rotr32 x (_ bv6 32))",
        "    (bvxor",
        "      (rotr32 x (_ bv11 32))",
        "      (rotr32 x (_ bv25 32)))))",
        "",
        "(define-fun ch_f",
        "  ((x (_ BitVec 32))",
        "   (y (_ BitVec 32))",
        "   (z (_ BitVec 32)))",
        "  (_ BitVec 32)",
        "  (bvadd",
        "    (bvand x y)",
        "    (bvand (bvnot x) z)))",
        "",
        "(define-fun maj_f",
        "  ((x (_ BitVec 32))",
        "   (y (_ BitVec 32))",
        "   (z (_ BitVec 32)))",
        "  (_ BitVec 32)",
        "  (bvxor",
        "    (bvand x y)",
        "    (bvxor",
        "      (bvand x z)",
        "      (bvand y z))))",
        "",
    ]

    # Initial standard SHA-256 state.
    for name in "abcdefgh":
        lines.append(
            f"(declare-const {name}_0 (_ BitVec 32))"
        )

    lines.append("")

    # Arbitrary message schedule words.
    for i in range(64):
        lines.append(
            f"(declare-const w_{i} (_ BitVec 32))"
        )

    lines.append("")

    # Standard eight-register recurrence.
    for i in range(64):
        k = f"#x{K[i]:08x}"

        lines.extend([
            f"; Round {i}",
            f"(define-fun t1_std_{i} () (_ BitVec 32)",
            f"  (bvadd h_{i}",
            f"    (bvadd (s1 e_{i})",
            f"      (bvadd",
            f"        (ch_f e_{i} f_{i} g_{i})",
            f"        (bvadd {k} w_{i})))))",

            f"(define-fun t2_std_{i} () (_ BitVec 32)",
            f"  (bvadd",
            f"    (s0 a_{i})",
            f"    (maj_f a_{i} b_{i} c_{i})))",

            f"(define-fun a_{i+1} () (_ BitVec 32)",
            f"  (bvadd t1_std_{i} t2_std_{i}))",

            f"(define-fun b_{i+1} () (_ BitVec 32) a_{i})",
            f"(define-fun c_{i+1} () (_ BitVec 32) b_{i})",
            f"(define-fun d_{i+1} () (_ BitVec 32) c_{i})",

            f"(define-fun e_{i+1} () (_ BitVec 32)",
            f"  (bvadd d_{i} t1_std_{i}))",

            f"(define-fun f_{i+1} () (_ BitVec 32) e_{i})",
            f"(define-fun g_{i+1} () (_ BitVec 32) f_{i})",
            f"(define-fun h_{i+1} () (_ BitVec 32) g_{i})",
            "",
        ])

    # Initial sliding windows:
    #
    # a_mt[i+3] = A_i
    # a_mt[i+2] = B_i
    # a_mt[i+1] = C_i
    # a_mt[i]   = D_i
    #
    # b_mt[i+3] = E_i
    # b_mt[i+2] = F_i
    # b_mt[i+1] = G_i
    # b_mt[i]   = H_i
    lines.extend([
        "(define-fun a_mt_0 () (_ BitVec 32) d_0)",
        "(define-fun a_mt_1 () (_ BitVec 32) c_0)",
        "(define-fun a_mt_2 () (_ BitVec 32) b_0)",
        "(define-fun a_mt_3 () (_ BitVec 32) a_0)",
        "",
        "(define-fun b_mt_0 () (_ BitVec 32) h_0)",
        "(define-fun b_mt_1 () (_ BitVec 32) g_0)",
        "(define-fun b_mt_2 () (_ BitVec 32) f_0)",
        "(define-fun b_mt_3 () (_ BitVec 32) e_0)",
        "",
    ])

    # Sliding-window recurrence.
    for i in range(64):
        k = f"#x{K[i]:08x}"

        lines.extend([
            f"; Sliding-window round {i}",

            f"(define-fun t1_sw_{i} () (_ BitVec 32)",
            f"  (bvadd b_mt_{i}",
            f"    (bvadd",
            f"      (s1 b_mt_{i+3})",
            f"      (bvadd",
            f"        (ch_f b_mt_{i+3} b_mt_{i+2} b_mt_{i+1})",
            f"        (bvadd {k} w_{i})))))",

            f"(define-fun b_mt_{i+4} () (_ BitVec 32)",
            f"  (bvadd t1_sw_{i} a_mt_{i}))",

            f"(define-fun t2_sw_{i} () (_ BitVec 32)",
            f"  (bvadd",
            f"    (s0 a_mt_{i+3})",
            f"    (maj_f",
            f"      a_mt_{i+3}",
            f"      a_mt_{i+2}",
            f"      a_mt_{i+1})))",

            f"(define-fun a_mt_{i+4} () (_ BitVec 32)",
            f"  (bvadd",
            f"    (bvsub b_mt_{i+4} a_mt_{i})",
            f"    t2_sw_{i}))",
            "",
        ])

    # After 64 rounds:
    #
    # a_mt[67] = A_64
    # a_mt[66] = B_64
    # a_mt[65] = C_64
    # a_mt[64] = D_64
    #
    # b_mt[67] = E_64
    # b_mt[66] = F_64
    # b_mt[65] = G_64
    # b_mt[64] = H_64
    lines.extend([
        "; Negate final-state equality.",
        "; UNSAT means the representations are equivalent.",
        "(assert (or",
        "  (distinct a_64 a_mt_67)",
        "  (distinct b_64 a_mt_66)",
        "  (distinct c_64 a_mt_65)",
        "  (distinct d_64 a_mt_64)",
        "  (distinct e_64 b_mt_67)",
        "  (distinct f_64 b_mt_66)",
        "  (distinct g_64 b_mt_65)",
        "  (distinct h_64 b_mt_64)))",
        "",
        "(check-sat)",
        "(exit)",
        "",
    ])

    write_file(
        "full_64round_equiv.smt2",
        "\n".join(lines),
    )


def generate_inverse_step() -> None:
    content = """\
; SHA256SW single-step inverse proof

(set-logic QF_BV)

(define-fun rotr32
  ((x (_ BitVec 32)) (n (_ BitVec 32)))
  (_ BitVec 32)
  (bvor
    (bvlshr x n)
    (bvshl x (bvsub (_ bv32 32) n))))

(define-fun s0 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv2 32))
    (bvxor
      (rotr32 x (_ bv13 32))
      (rotr32 x (_ bv22 32)))))

(define-fun s1 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv6 32))
    (bvxor
      (rotr32 x (_ bv11 32))
      (rotr32 x (_ bv25 32)))))

(define-fun ch_f
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvadd
    (bvand x y)
    (bvand (bvnot x) z)))

(define-fun maj_f
  ((x (_ BitVec 32))
   (y (_ BitVec 32))
   (z (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (bvand x y)
    (bvxor
      (bvand x z)
      (bvand y z))))

; Old state coordinates.
(declare-const a_i (_ BitVec 32))
(declare-const b_i (_ BitVec 32))

; Known future window.
(declare-const a_ip1 (_ BitVec 32))
(declare-const a_ip2 (_ BitVec 32))
(declare-const a_ip3 (_ BitVec 32))

(declare-const b_ip1 (_ BitVec 32))
(declare-const b_ip2 (_ BitVec 32))
(declare-const b_ip3 (_ BitVec 32))

; Round constants/message word.
(declare-const k_i (_ BitVec 32))
(declare-const w_i (_ BitVec 32))

; Forward step.
(define-fun t1_fwd () (_ BitVec 32)
  (bvadd
    b_i
    (bvadd
      (s1 b_ip3)
      (bvadd
        (ch_f b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

(define-fun b_ip4 () (_ BitVec 32)
  (bvadd t1_fwd a_i))

(define-fun t2_fwd () (_ BitVec 32)
  (bvadd
    (s0 a_ip3)
    (maj_f a_ip3 a_ip2 a_ip1)))

(define-fun a_ip4 () (_ BitVec 32)
  (bvadd
    (bvsub b_ip4 a_i)
    t2_fwd))

; Recover T1 from A[i+4] and T2.
(define-fun t2_rec () (_ BitVec 32)
  (bvadd
    (s0 a_ip3)
    (maj_f a_ip3 a_ip2 a_ip1)))

(define-fun t1_rec () (_ BitVec 32)
  (bvsub a_ip4 t2_rec))

; Recover a_i and b_i.
(define-fun a_i_rec () (_ BitVec 32)
  (bvsub b_ip4 t1_rec))

(define-fun b_i_rec () (_ BitVec 32)
  (bvsub
    t1_rec
    (bvadd
      (s1 b_ip3)
      (bvadd
        (ch_f b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

; Negate inverse correctness.
; UNSAT means the recovered coordinates equal the originals.
(assert (or
  (distinct a_i a_i_rec)
  (distinct b_i b_i_rec)))

(check-sat)
(exit)
"""

    write_file(
        "full_64round_inverse.smt2",
        content,
    )


def main() -> int:
    generate_ch_equiv()
    generate_full_64round()
    generate_inverse_step()

    print("[+] SMT proof artifacts generated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
