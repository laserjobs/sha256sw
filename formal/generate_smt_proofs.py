#!/usr/bin/env python3
"""
generate_smt_proofs.py
Generates SMT-LIB2 verification scripts to formally prove:
  1. ch_equiv.smt2: Ch arithmetic ((x & y) + (~x & z)) == bitwise ((x & y) ^ (~x & z))
  2. full_64round_equiv.smt2: Full 64-round sliding window equivalence with FIPS 180-4
  3. full_64round_inverse.smt2: Single-step algebraic inverse bijection
"""

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

def generate_ch_equiv():
    content = """; SMT-LIB2: Ch arithmetic vs bitwise equivalence
(set-logic QF_BV)
(declare-const x (_ BitVec 32))
(declare-const y (_ BitVec 32))
(declare-const z (_ BitVec 32))

(define-fun ch_arith ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvadd (bvand x y) (bvand (bvnot x) z)))

(define-fun ch_xor ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvxor (bvand x y) (bvand (bvnot x) z)))

(assert (distinct (ch_arith x y z) (ch_xor x y z)))
(check-sat)
(exit)
"""
    with open("ch_equiv.smt2", "w") as f:
        f.write(content)

def generate_full_64round():
    lines = [
        "(set-logic QF_BV)",
        "(define-fun rotr32 ((x (_ BitVec 32)) (n (_ BitVec 32))) (_ BitVec 32)",
        "  (bvor (bvlshr x n) (bvshl x (bvsub (_ bv32 32) n))))",
        "(define-fun s0 ((x (_ BitVec 32))) (_ BitVec 32)",
        "  (bvxor (rotr32 x (_ bv2 32)) (bvxor (rotr32 x (_ bv13 32)) (rotr32 x (_ bv22 32)))))",
        "(define-fun s1 ((x (_ BitVec 32))) (_ BitVec 32)",
        "  (bvxor (rotr32 x (_ bv6 32)) (bvxor (rotr32 x (_ bv11 32)) (rotr32 x (_ bv25 32)))))",
        "(define-fun ch_f ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)",
        "  (bvadd (bvand x y) (bvand (bvnot x) z)))",
        "(define-fun maj_f ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)",
        "  (bvxor (bvand x y) (bvxor (bvand x z) (bvand y z))))",
        ""
    ]
    for v in ['a_0', 'b_0', 'c_0', 'd_0', 'e_0', 'f_0', 'g_0', 'h_0']:
        lines.append(f"(declare-const {v} (_ BitVec 32))")
    for i in range(64):
        lines.append(f"(declare-const w_{i} (_ BitVec 32))")

    for i in range(64):
        k = f"#x{K[i]:08x}"
        lines.append(f"(define-fun t1_std_{i} () (_ BitVec 32) (bvadd h_{i} (bvadd (s1 e_{i}) (bvadd (ch_f e_{i} f_{i} g_{i}) (bvadd {k} w_{i})))))")
        lines.append(f"(define-fun t2_std_{i} () (_ BitVec 32) (bvadd (s0 a_{i}) (maj_f a_{i} b_{i} c_{i})))")
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
        "(define-fun b_mt_2 () (_ BitVec 32) f_0)", "(define-fun b_mt_3 () (_ BitVec 32) e_0)"
    ])

    for i in range(64):
        k = f"#x{K[i]:08x}"
        lines.append(f"(define-fun t1_sw_{i} () (_ BitVec 32) (bvadd b_mt_{i} (bvadd (s1 b_mt_{i+3}) (bvadd (ch_f b_mt_{i+3} b_mt_{i+2} b_mt_{i+1}) (bvadd {k} w_{i})))))")
        lines.append(f"(define-fun b_mt_{i+4} () (_ BitVec 32) (bvadd t1_sw_{i} a_mt_{i}))")
        lines.append(f"(define-fun t2_sw_{i} () (_ BitVec 32) (bvadd (s0 a_mt_{i+3}) (maj_f a_mt_{i+3} a_mt_{i+2} a_mt_{i+1})))")
        lines.append(f"(define-fun a_mt_{i+4} () (_ BitVec 32) (bvadd (bvsub b_mt_{i+4} a_mt_{i}) t2_sw_{i}))")

    lines.append("""
(assert (or
  (distinct a_64 a_mt_67) (distinct b_64 a_mt_66)
  (distinct c_64 a_mt_65) (distinct d_64 a_mt_64)
  (distinct e_64 b_mt_67) (distinct f_64 b_mt_66)
  (distinct g_64 b_mt_65) (distinct h_64 b_mt_64)))
(check-sat)
(exit)
""")
    with open("full_64round_equiv.smt2", "w") as f:
        f.write("\n".join(lines))

def generate_inverse_step():
    content = """; SMT-LIB2: Single-step algebraic inverse bijection
(set-logic QF_BV)
(define-fun rotr32 ((x (_ BitVec 32)) (n (_ BitVec 32))) (_ BitVec 32)
  (bvor (bvlshr x n) (bvshl x (bvsub (_ bv32 32) n))))
(define-fun s0 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv2 32)) (bvxor (rotr32 x (_ bv13 32)) (rotr32 x (_ bv22 32)))))
(define-fun s1 ((x (_ BitVec 32))) (_ BitVec 32)
  (bvxor (rotr32 x (_ bv6 32)) (bvxor (rotr32 x (_ bv11 32)) (rotr32 x (_ bv25 32)))))
(define-fun ch_f ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvadd (bvand x y) (bvand (bvnot x) z)))
(define-fun maj_f ((x (_ BitVec 32)) (y (_ BitVec 32)) (z (_ BitVec 32))) (_ BitVec 32)
  (bvxor (bvand x y) (bvxor (bvand x z) (bvand y z))))

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

(define-fun t1_fwd () (_ BitVec 32) (bvadd b_i (bvadd (s1 b_ip3) (bvadd (ch_f b_ip3 b_ip2 b_ip1) (bvadd k_i w_i)))))
(define-fun b_ip4 () (_ BitVec 32) (bvadd t1_fwd a_i))
(define-fun t2_fwd () (_ BitVec 32) (bvadd (s0 a_ip3) (maj_f a_ip3 a_ip2 a_ip1)))
(define-fun a_ip4 () (_ BitVec 32) (bvadd (bvsub b_ip4 a_i) t2_fwd))

(define-fun t2_rec () (_ BitVec 32) (bvadd (s0 a_ip3) (maj_f a_ip3 a_ip2 a_ip1)))
(define-fun t1_rec () (_ BitVec 32) (bvsub a_ip4 t2_rec))
(define-fun a_i_rec () (_ BitVec 32) (bvsub b_ip4 t1_rec))
(define-fun b_i_rec () (_ BitVec 32) (bvsub t1_rec (bvadd (s1 b_ip3) (bvadd (ch_f b_ip3 b_ip2 b_ip1) (bvadd k_i w_i)))))

(assert (or (distinct a_i a_i_rec) (distinct b_i b_i_rec)))
(check-sat)
(exit)
"""
    with open("full_64round_inverse.smt2", "w") as f:
        f.write(content)

if __name__ == "__main__":
    generate_ch_equiv()
    generate_full_64round()
    generate_inverse_step()
    print("[+] Generated SMT files: ch_equiv.smt2, full_64round_equiv.smt2, full_64round_inverse.smt2")
