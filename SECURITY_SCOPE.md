# Security Scope and Limitations

## Summary

This project studies an alternative algebraic representation of the
SHA-256 compression-state transformation.

The sliding-window representation provides an explicit inverse for the
**working state when the message schedule is fixed and known**.

This should not be interpreted as a practical inversion, collision, or
preimage attack against standard SHA-256.

---

## What Is Established

For a fixed expanded schedule

\[
W_0,\ldots,W_{63},
\]

the 64-round SHA-256 working-state transformation is a permutation of
the 256-bit working state.

The sliding-window representation gives an explicit inverse of that
permutation.

Consequently, for any target working state \(S\), one can compute

\[
H=E_W^{-1}(S)
\]

using 64 inverse rounds.

In particular,

\[
H_{\mathrm{fix}}=E_W^{-1}(0)
\]

is a freestart Davies–Meyer fixed point for the corresponding known
message block.

---

## What Is Not Established

This construction does **not** provide an efficient algorithm for:

- finding a message that maps the standard SHA-256 IV to a chosen state;
- finding a message \(M\) satisfying
  \[
  E_{W(M)}(\mathrm{IV}_{\mathrm{FIPS}})=0;
  \]
- finding collisions in standard full SHA-256;
- finding arbitrary preimages of standard SHA-256;
- reducing the generic security bounds of SHA-256.

The critical distinction is whether the message schedule is known.

### Fixed schedule

\[
W\text{ known}
\quad\Longrightarrow\quad
\text{invert }H\mapsto E_W(H).
\]

### Unknown message

\[
M\text{ unknown}
\quad\Longrightarrow\quad
W=W(M)\text{ unknown}.
\]

The SW backward operator does not solve the second problem.

---

## Freestart Fixed Points

A custom or freestart construction may permit the chaining value to be
chosen.

For a known message block \(M\), the SW inverse can then construct

\[
H_{\mathrm{fix}}
=
E_M^{-1}(0)
\]

such that

\[
C_M(H_{\mathrm{fix}})=H_{\mathrm{fix}}.
\]

This is a property of the underlying fixed-message state permutation.

It does not imply that the canonical SHA-256 IV is such a fixed point.

---

## Complexity Language

This repository should describe the inverse as requiring

\[
O(R)
\]

round operations.

For SHA-256, \(R=64\).

The phrase "instantaneous" or "O(1)" should not be used as a cryptographic
complexity claim.

---

## Benchmark Interpretation

If the sliding-window formulation produces faster SAT/SMT solving than
the conventional register formulation, that demonstrates a modeling
or solver-performance advantage.

It does not by itself demonstrate a cryptanalytic weakness in
SHA-256.

The appropriate research question is therefore:

> Does eliminating redundant state-coordinate equations produce a
> measurable advantage for automated reasoning about reduced-round
> SHA-256?

---

## Reproducibility

Benchmark conclusions should report:

- solver and version;
- hardware;
- operating system;
- timeout;
- instance generation method;
- random seeds where applicable;
- number of instances;
- solved/unsolved counts;
- median runtime;
- runtime dispersion;
- memory consumption when available.

A benchmark should be described as controlled and reproducible rather
than "noise-free."
