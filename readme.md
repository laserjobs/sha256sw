# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

An endian-independent, formally audited implementation of SHA-256 alongside a comparative QF_BV constraint benchmark testing the sliding-window state formulation in automated SAT/SMT collision searches.

[![CI](https://github.com/laserjobs/sha256sw/actions/workflows/ci.yml/badge.svg)](https://github.com/laserjobs/sha256sw/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. Mathematical Architecture

Standard FIPS 180-4 SHA-256 maintains 8 state words $(A, B, C, D, E, F, G, H)$ and 6 register shifts per round. The **SHA256SW** formulation maintains two sliding histories $a\_mt$ and $b\_mt$:

$$\begin{aligned}
a\_mt[i+3] &= A_i, \quad a\_mt[i+2] = B_i, \quad a\_mt[i+1] = C_i, \quad a\_mt[i] = D_i \\
b\_mt[i+3] &= E_i, \quad b\_mt[i+2] = F_i, \quad b\_mt[i+1] = G_i, \quad b\_mt[i] = H_i
\end{aligned}$$

### Recurrence Equations
$$\begin{aligned}
T_1^{(i)} &= b\_mt[i] + \Sigma_1(b\_mt[i+3]) + \text{Ch}(b\_mt[i+3], b\_mt[i+2], b\_mt[i+1]) + K_i + W_i \\
b\_mt[i+4] &= T_1^{(i)} + a\_mt[i] \\
T_2^{(i)} &= \Sigma_0(a\_mt[i+3]) + \text{Maj}(a\_mt[i+3], a\_mt[i+2], a\_mt[i+1]) \\
a\_mt[i+4] &= (b\_mt[i+4] - a\_mt[i]) + T_2^{(i)} \quad \left(\equiv T_1^{(i)} + T_2^{(i)}\right)
\end{aligned}$$

### Single-Step Exact Algebraic Inversion
Given window $a\_mt[i+1\dots i+3]$, $b\_mt[i+1\dots i+3]$, constants $K_i, W_i$, and next state $(a\_mt[i+4], b\_mt[i+4])$:
$$\begin{aligned}
T_2 &= \Sigma_0(a\_mt[i+3]) + \text{Maj}(a\_mt[i+3], a\_mt[i+2], a\_mt[i+1]) \\
T_1 &= a\_mt[i+4] - T_2 \\
a\_mt[i] &= b\_mt[i+4] - T_1 \\
b\_mt[i] &= T_1 - \left(\Sigma_1(b\_mt[i+3]) + \text{Ch}(b\_mt[i+3], b\_mt[i+2], b\_mt[i+1]) + K_i + W_i\right)
\end{aligned}$$

---

## 2. Quickstart

### Build & Run C Tests
```bash
make test
```

### Run Formal Equivalence Proofs (Z3)
```bash
make formal
```

### Run 4-Way Representation Benchmark
```bash
python3 benchmark/sha256_representation_benchmark.py z3 --rounds 16 20 24 28 30 --trials 5 --timeout 120
```

---

## 3. Pre-Registered Benchmark Metric

$$\mathcal{S}_R = \frac{\operatorname{median}\left(T_{\text{Std-Explicit},\, R}\right)}{\operatorname{median}\left(T_{\text{SW-Explicit},\, R}\right)}$$

* **`Std-Explicit`**: Standard FIPS 180-4 formulation with explicit register-copy equality assertions ($B_{i+1}=A_i, \dots$).
* **`SW-Explicit`**: Sliding-window coordinate formulation (zero register-copy equations).
* **Witness Verification**: Every `sat` model is extracted and validated against an independent pure-Python SHA-256 compression function.

---

## 4. Citation

If you use this benchmark or coordinate representation in cryptanalytic research:

```bibtex
@misc{sha256sw2026,
  author = {SHA256SW Contributors},
  title = {SHA256SW: Sliding-Window State Representation and Cryptanalytic Benchmark for SHA-256},
  year = {2026},
  url = {https://github.com/username/sha256sw}
}
```

