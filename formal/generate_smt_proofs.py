#!/usr/bin/env python3
"""
generate_smt_proofs.py

Generate SMT-LIB2 proof obligations for SHA256SW.

Generated files:

    ch_equiv.smt2
        Proves arithmetic and XOR forms of Ch equivalent.

    full_64round_equiv.smt2
        Proves the complete 64-round standard and sliding-window
        state representations are equivalent for arbitrary symbolic
        IV and message words.

    full_64round_inverse.smt2
        Proves the single-step sliding-window recurrence is algebraically
        invertible with respect to the oldest state coordinates.
"""

from pathlib import Path


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
assert K[34] == 0x4d2c6dfc
assert K[37] == 0x766a0abb


ROOT = Path(__file__).resolve().parent


def write_file(name: str, content: str) -> None:
    path = ROOT / name
    path.write_text(content, encoding="utf-8")
    print(f"[+] Generated {path}")


def generate_ch_equiv() -> None:
    content = """\
; SMT-LIB2: Ch arithmetic vs bitwise equivalence

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

(assert
  (distinct
    (ch_arith x y z)
    (ch_xor x y z)))

(check-sat)
(exit)
"""
    write_file("ch_equiv.smt2", content)


def generate_full_64round() -> None:
    lines = [
        "(set-logic QF_BV)",
        "",
        "(define-fun rotr32 "
        "((x (_ BitVec 32)) "
        "(n (_ BitVec 32))) "
        "(_ BitVec 32)",
        "  (bvor "
        "    (bvlshr x n) "
        "    (bvshl x "
        "      (bvsub (_ bv32 32) n))))",
        "",
        "(define-fun s0 "
        "((x (_ BitVec 32))) "
        "(_ BitVec 32)",
        "  (bvxor "
        "    (rotr32 x (_ bv2 32)) "
        "    (bvxor "
        "      (rotr32 x (_ bv13 32)) "
        "      (rotr32 x (_ bv22 32)))))",
        "",
        "(define-fun s1 "
        "((x (_ BitVec 32))) "
        "(_ BitVec 32)",
        "  (bvxor "
        "    (rotr32 x (_ bv6 32)) "
        "    (bvxor "
        "      (rotr32 x (_ bv11 32)) "
        "      (rotr32 x (_ bv25 32)))))",
        "",
        "(define-fun ch_f "
        "((x (_ BitVec 32)) "
        "(y (_ BitVec 32)) "
        "(z (_ BitVec 32))) "
        "(_ BitVec 32)",
        "  (bvadd "
        "    (bvand x y) "
        "    (bvand (bvnot x) z)))",
        "",
        "(define-fun maj_f "
        "((x (_ BitVec 32)) "
        "(y (_ BitVec 32)) "
        "(z (_ BitVec 32))) "
        "(_ BitVec 32)",
        "  (bvxor "
        "    (bvand x y) "
        "    (bvxor "
        "      (bvand x z) "
        "      (bvand y z))))",
        "",
    ]

    for name in "abcdefgh":
        lines.append(
            f"(declare-const {name}_0 "
            "(_ BitVec 32))"
        )

    for i in range(64):
        lines.append(
            f"(declare-const w_{i} "
            "(_ BitVec 32))"
        )

    for i in range(64):
        k = f"#x{K[i]:08x}"

        lines.extend([
            f"(define-fun t1_std_{i} () "
            "(_ BitVec 32) "
            f"(bvadd h_{i} "
            f"(bvadd (s1 e_{i}) "
            f"(bvadd "
            f"(ch_f e_{i} f_{i} g_{i}) "
            f"(bvadd {k} w_{i})))))",

            f"(define-fun t2_std_{i} () "
            "(_ BitVec 32) "
            f"(bvadd "
            f"(s0 a_{i}) "
            f"(maj_f a_{i} b_{i} c_{i})))",

            f"(define-fun a_{i+1} () "
            "(_ BitVec 32) "
            f"(bvadd t1_std_{i} t2_std_{i}))",

            f"(define-fun b_{i+1} () "
            "(_ BitVec 32) a_{i})",

            f"(define-fun c_{i+1} () "
            "(_ BitVec 32) b_{i})",

            f"(define-fun d_{i+1} () "
            "(_ BitVec 32) c_{i})",

            f"(define-fun e_{i+1} () "
            "(_ BitVec 32) "
            f"(bvadd d_{i} t1_std_{i}))",

            f"(define-fun f_{i+1} () "
            "(_ BitVec 32) e_{i})",

            f"(define-fun g_{i+1} () "
            "(_ BitVec 32) f_{i})",

            f"(define-fun h_{i+1} () "
            "(_ BitVec 32) g_{i})",
        ])

    lines.extend([
        "",
        "(define-fun a_mt_0 () "
        "(_ BitVec 32) d_0)",
        "(define-fun a_mt_1 () "
        "(_ BitVec 32) c_0)",
        "(define-fun a_mt_2 () "
        "(_ BitVec 32) b_0)",
        "(define-fun a_mt_3 () "
        "(_ BitVec 32) a_0)",

        "(define-fun b_mt_0 () "
        "(_ BitVec 32) h_0)",
        "(define-fun b_mt_1 () "
        "(_ BitVec 32) g_0)",
        "(define-fun b_mt_2 () "
        "(_ BitVec 32) f_0)",
        "(define-fun b_mt_3 () "
        "(_ BitVec 32) e_0)",
        "",
    ])

    for i in range(64):
        k = f"#x{K[i]:08x}"

        lines.extend([
            f"(define-fun t1_sw_{i} () "
            "(_ BitVec 32) "
            f"(bvadd b_mt_{i} "
            f"(bvadd "
            f"(s1 b_mt_{i+3}) "
            f"(bvadd "
            f"(ch_f b_mt_{i+3} "
            f"b_mt_{i+2} "
            f"b_mt_{i+1}) "
            f"(bvadd {k} w_{i})))))",

            f"(define-fun b_mt_{i+4} () "
            "(_ BitVec 32) "
            f"(bvadd t1_sw_{i} "
            f"a_mt_{i}))",

            f"(define-fun t2_sw_{i} () "
            "(_ BitVec 32) "
            f"(bvadd "
            f"(s0 a_mt_{i+3}) "
            f"(maj_f "
            f"a_mt_{i+3} "
            f"a_mt_{i+2} "
            f"a_mt_{i+1})))",

            f"(define-fun a_mt_{i+4} () "
            "(_ BitVec 32) "
            f"(bvadd "
            f"(bvsub "
            f"b_mt_{i+4} a_mt_{i}) "
            f"t2_sw_{i}))",
        ])

    lines.extend([
        "",
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
    ])

    write_file(
        "full_64round_equiv.smt2",
        "\n".join(lines) + "\n",
    )


def generate_inverse_step() -> None:
    content = """\
; SMT-LIB2: Single-step algebraic inverse bijection

(set-logic QF_BV)

(define-fun rotr32
  ((x (_ BitVec 32))
   (n (_ BitVec 32)))
  (_ BitVec 32)
  (bvor
    (bvlshr x n)
    (bvshl x
      (bvsub (_ bv32 32) n))))

(define-fun s0
  ((x (_ BitVec 32)))
  (_ BitVec 32)
  (bvxor
    (rotr32 x (_ bv2 32))
    (bvxor
      (rotr32 x (_ bv13 32))
      (rotr32 x (_ bv22 32)))))

(define-fun s1
  ((x (_ BitVec 32)))
  (_ BitVec 32)
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

(define-fun t1_fwd
  () (_ BitVec 32)
  (bvadd b_i
    (bvadd
      (s1 b_ip3)
      (bvadd
        (ch_f b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

(define-fun b_ip4
  () (_ BitVec 32)
  (bvadd t1_fwd a_i))

(define-fun t2_fwd
  () (_ BitVec 32)
  (bvadd
    (s0 a_ip3)
    (maj_f a_ip3 a_ip2 a_ip1)))

(define-fun a_ip4
  () (_ BitVec 32)
  (bvadd
    (bvsub b_ip4 a_i)
    t2_fwd))

(define-fun t2_rec
  () (_ BitVec 32)
  (bvadd
    (s0 a_ip3)
    (maj_f a_ip3 a_ip2 a_ip1)))

(define-fun t1_rec
  () (_ BitVec 32)
  (bvsub a_ip4 t2_rec))

(define-fun a_i_rec
  () (_ BitVec 32)
  (bvsub b_ip4 t1_rec))

(define-fun b_i_rec
  () (_ BitVec 32)
  (bvsub
    t1_rec
    (bvadd
      (s1 b_ip3)
      (bvadd
        (ch_f b_ip3 b_ip2 b_ip1)
        (bvadd k_i w_i)))))

(assert
  (or
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
