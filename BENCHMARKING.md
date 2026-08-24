# Standard vs Sliding-Window Benchmark

## Objective

The benchmark measures whether the sliding-window (SW) formulation
provides a measurable solver advantage over the conventional
8-register (Std) formulation.

Define

\[
\mathcal S_R(n)
=
\frac{\operatorname{median}(T_{\mathrm{Std}})}
     {\operatorname{median}(T_{\mathrm{SW}})}.
\]

Interpretation:

- \(\mathcal S_R>1\): SW is faster;
- \(\mathcal S_R\approx1\): no meaningful speed advantage;
- \(\mathcal S_R<1\): Std is faster.

This is a solver-modeling benchmark, not a cryptanalytic security
claim.

---

## Recommended Instance Ladder

Use the parameterized widths

\[
n\in\{4,6,8,12,16\}
\]

and a range of round counts beginning at the smallest nontrivial
invertible/collision instances.

For every instance, the Std and SW encodings must represent exactly
the same mathematical problem.

---

## Controlled Variables

The following should remain identical between formulations:

- hardware;
- operating system;
- solver;
- solver version;
- timeout;
- input instance;
- arithmetic semantics;
- target condition;
- solver configuration;
- random seed, where supported.

Only the state representation should differ.

---

## Measurements

Record at minimum:

```text
instance_id
n
rounds
solver
solver_version
encoding
result
runtime_ms
memory_mb
seed
