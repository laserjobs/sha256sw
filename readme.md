# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

An endian-independent, portable C11 implementation of SHA-256 alongside machine-checked SMT equivalence proofs (QF_BV) and an automated SAT/SMT search benchmark comparing standard vs sliding-window state formulations.

[![CI](https://github.com/laserjobs/sha256sw/actions/workflows/ci.yml/badge.svg)](https://github.com/laserjobs/sha256sw/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 1. Scope & Research Methodology

* **Machine-Checked SMT Equivalence**: The repository includes formal SMT-LIB2 bit-vector proofs (`formal/` and `Gate 0`) verifying that the sliding-window coordinate formulation $(a\_mt, b\_mt)$ is mathematically identical to FIPS 180-4 across all 64 compression rounds for arbitrary symbolic inputs.
* **Empirical Search Benchmark**: The benchmark measures empirical solver wall-clock time and completion rates on reduced-round collision instances. It evaluates whether eliminating register-copy equations improves solver search speed; it does **not** make causal claims regarding internal CDCL conflict-graph mechanics without dedicated backend instrumentation.
* **Independent Reference Verification**: All `sat` solutions represent verified collisions on the reduced-round compression function ($H_R(IV, M_1) = H_R(IV, M_2)$), checked against an independent pure-Python engine validated against `hashlib.sha256`.

---

## 2. Mathematical Architecture

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

## 3. Quickstart

### Build & Run C Test Suite
```bash
make test
```

### Run Strict Formal Equivalence Proofs (Z3)
```bash
make formal
```

### Run 4-Way Representation Benchmark
```bash
python3 benchmark/sha256_representation_benchmark.py z3 --rounds 16 20 24 28 30 --trials 5 --timeout 120
```

---

## 4. Pre-Registered Primary Metric

$$\mathcal{S}_R = \frac{\operatorname{median}\left(T_{\text{Std-Explicit},\, R}\right)}{\operatorname{median}\left(T_{\text{SW-Explicit},\, R}\right)}$$

* **`Std-Explicit`**: Standard FIPS 180-4 formulation with explicit register-copy equality assertions ($B_{i+1}=A_i, \dots$).
* **`SW-Explicit`**: Sliding-window coordinate formulation (zero register-copy equations).
* **Survival Modeling**: Timeouts are treated as right-censored observations. If $\ge 50\%$ of trials time out, medians are reported as `>{timeout}s` and $\mathcal{S}_R$ is bounded accordingly.

---

## 5. License & Citation

Licensed under the [MIT License](LICENSE).

```bibtex
@misc{sha256sw2026,
  author = {SHA256SW Contributors},
  title = {SHA256SW: Sliding-Window State Representation and Cryptanalytic Benchmark for SHA-256},
  year = {2026},
  url = {https://github.com/laserjobs/sha256sw}
}
```
