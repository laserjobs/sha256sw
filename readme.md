# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

SHA256SW is a portable C11 implementation of SHA-256 together with
machine-checked SMT equivalence proofs and an automated SAT/SMT benchmark
for comparing conventional and sliding-window representations of the
SHA-256 working state.

The project studies a representation question:

> Can eliminating explicit register-copy equations make reduced-round
> SHA-256 SAT/SMT instances easier for automated solvers?

The mathematical construction also establishes an exact inverse for the
SHA-256 working-state transformation when the complete round-word schedule
is fixed and known.

> **Central result:** For every fixed sequence of 64 SHA-256 round words
> `W[0..63]`, the 64-round working-state map `E_W` is a permutation of the
> 256-bit working-state space. The sliding-window representation supplies an
> explicit inverse of that permutation.

This is a statement about **state inversion with a known message schedule**.

It is **not** an inversion attack on the message input of standard SHA-256.

---

## What SHA256SW Does

SHA256SW has four closely related goals:

1. Implement SHA-256 in portable C11 using the sliding-window state
   representation.
2. Machine-check equivalence between the standard eight-register and
   sliding-window formulations using SMT bit-vectors.
3. Establish and validate the exact backward inverse of the fixed-schedule
   working-state transformation.
4. Benchmark equivalent SAT/SMT representations on reduced-round collision
   instances.

The project therefore separates two questions:

```text
Mathematical equivalence
        |
        v
Do the representations compute the same function?
        |
        v
Solver representation
        |
        v
Does one encoding make equivalent SAT/SMT problems easier?
```

A solver speedup is a statement about the **encoding and solver workload**.
It is not evidence that the underlying SHA-256 primitive has become weaker.

---

# Security Boundary

The central distinction is:

```text
Known fixed schedule W
        |
        v
E_W : working state -> working state
        |
        v
E_W is a permutation
        |
        v
E_W^-1 is explicit
```

versus:

```text
Standard SHA-256 IV
        |
        v
Unknown message M
        |
        v
Unknown schedule W(M)
        |
        v
Message-search problem
```

SHA256SW directly addresses the first problem.

It does **not** provide an efficient algorithm for the second.

In particular, this project does not claim:

- a collision attack on full 64-round SHA-256;
- a preimage attack on full SHA-256;
- a second-preimage attack;
- a practical standard-IV fixed point;
- a reduction in generic collision complexity;
- a reduction in generic preimage complexity;
- inversion of SHA-256 with respect to an unknown message.

See [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md) for the complete security
boundary.

---

# Mathematical Summary

## Standard SHA-256 state

The conventional SHA-256 working state contains eight 32-bit words:

```text
A B C D E F G H
```

For round `i`:

```text
T1 = H
   + Sigma1(E)
   + Ch(E,F,G)
   + K[i]
   + W[i]

T2 = Sigma0(A)
   + Maj(A,B,C)
```

with all additions modulo `2^32`.

The next state is:

```text
A' = T1 + T2
B' = A
C' = B
D' = C

E' = D + T1
F' = E
G' = F
H' = G
```

The SHA-256 Boolean functions are:

```text
Ch(x,y,z)  = (x & y) ^ (~x & z)

Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
```

and:

```text
Sigma0(x) = ROTR^2(x)  ^ ROTR^13(x) ^ ROTR^22(x)

Sigma1(x) = ROTR^6(x)  ^ ROTR^11(x) ^ ROTR^25(x)

sigma0(x) = ROTR^7(x)  ^ ROTR^18(x) ^ SHR^3(x)

sigma1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
```

The message schedule is:

```text
W[i] = sigma1(W[i-2])
     + W[i-7]
     + sigma0(W[i-15])
     + W[i-16]
```

for:

```text
16 <= i < 64
```

---

## Sliding-window coordinates

For round `i`, SHA256SW represents the same state using two overlapping
histories:

```text
a[i+3] = A_i
a[i+2] = B_i
a[i+1] = C_i
a[i]   = D_i

b[i+3] = E_i
b[i+2] = F_i
b[i+1] = G_i
b[i]   = H_i
```

The round becomes:

```text
T1 = b[i]
   + Sigma1(b[i+3])
   + Ch(b[i+3], b[i+2], b[i+1])
   + K[i]
   + W[i]

b[i+4] = a[i] + T1

T2 = Sigma0(a[i+3])
   + Maj(a[i+3], a[i+2], a[i+1])

a[i+4] = (b[i+4] - a[i]) + T2
```

All arithmetic is modulo `2^32`.

The sliding-window representation does not change the SHA-256 round
function. It changes the coordinates used to represent the evolving state.

---

# Exact One-Round Inversion

For a fixed `K[i]` and `W[i]`, a SHA-256 round can be inverted directly.

Suppose the output is:

```text
(A', B', C', D', E', F', G', H')
```

The shifted input registers are immediately recovered:

```text
A = B'
B = C'
C = D'

E = F'
F = G'
G = H'
```

Now calculate:

```text
T2 = Sigma0(A) + Maj(A,B,C)
```

Since:

```text
A' = T1 + T2
```

we have:

```text
T1 = A' - T2
```

Since:

```text
E' = D + T1
```

we have:

```text
D = E' - T1
```

Finally:

```text
T1 = H
   + Sigma1(E)
   + Ch(E,F,G)
   + K[i]
   + W[i]
```

so:

```text
H = T1
  - Sigma1(E)
  - Ch(E,F,G)
  - K[i]
  - W[i]
```

All subtraction is modulo `2^32`.

Therefore every input register is uniquely determined by the output state
when the round word is fixed.

Consequently, every fixed-word SHA-256 round is a bijection on the 256-bit
working-state space.

The complete derivation is in [`THEORY.md`](THEORY.md).

---

# Full-Round Bijection

Let:

```text
R_i
```

be SHA-256 round `i` with fixed `K[i]` and `W[i]`.

Each round has an explicit inverse:

```text
R_i^-1
```

Therefore the composition

```text
E_W = R_63 o R_62 o ... o R_0
```

is also bijective.

Thus, for every fixed schedule:

```text
W = (W[0], W[1], ..., W[63])
```

the map

```text
E_W : (Z/2^32Z)^8 -> (Z/2^32Z)^8
```

is a permutation.

Its inverse is obtained by applying the individual round inverses in
reverse order.

---

# Sliding-Window Backward Operator

The sliding-window formulation provides a coordinate representation of the
same inverse.

For a fixed schedule `W`, let:

```text
B_W = E_W^-1
```

Then:

```text
B_W(E_W(H)) = H
```

for every working state `H`, and:

```text
E_W(B_W(S)) = S
```

for every target working state `S`.

This is a genuine two-sided inverse.

The inverse requires one inverse round per round:

```text
Time = O(R)
```

where `R` is the number of rounds.

For full SHA-256:

```text
R = 64
```

so the correct description is **O(R) round operations**, not asymptotic
`O(1)`.

---

# Freestart Fixed Points

SHA-256 compression uses Davies-Meyer-style feed-forward:

```text
C_W(H) = H + E_W(H)
```

with the addition interpreted component-wise modulo `2^32`.

Choose the target state:

```text
S = 0^256
```

Because `E_W` is a permutation, there is exactly one state:

```text
H_fix = E_W^-1(0^256)
```

such that:

```text
E_W(H_fix) = 0^256
```

Therefore:

```text
C_W(H_fix)
= H_fix + 0^256
= H_fix
```

So every fixed expanded message schedule has one corresponding Davies-Meyer
freestart fixed point.

This is a **freestart/chaining-state result**.

It does not mean that the standardized SHA-256 IV is a fixed point.

---

# Fixed Schedule vs Unknown Message

This distinction is fundamental.

## Fixed schedule

When the message block is known:

```text
M known
  |
  v
W(M) known
  |
  v
E_W known
  |
  v
H = E_W^-1(S)
```

The state preimage can be computed directly.

For:

```text
S = 0^256
```

this produces the unique freestart fixed point for the corresponding
message schedule.

## Standard-IV message problem

For standard SHA-256:

```text
H = IV_FIPS
```

is fixed while the message is unknown.

The problem becomes:

```text
Find M such that:

E_W(M)(IV_FIPS) = S
```

Now the schedule itself is unknown:

```text
W = W(M)
```

and is constrained by the SHA-256 message expansion.

The fixed-schedule inverse does not solve this message-search problem.

The essential distinction is:

```text
Known W  -> recover H
```

versus:

```text
Fixed H + unknown M -> recover M
```

These are different computational problems.

---

# Implementation

The repository contains a portable C11 implementation in:

```text
src/sha256sw.c
include/sha256sw.h
```

The implementation includes:

- SHA-256 initialization;
- streaming updates;
- SHA-256 message padding;
- big-endian word loading and storing;
- the full 64-word message schedule;
- the sliding-window working-state recurrence;
- SHA-256 compression;
- final 256-bit digest generation.

The implementation uses explicit 32-bit types and explicit big-endian
serialization rather than relying on host byte order.

The compression implementation maintains:

```text
a_mt[68]
b_mt[68]
```

and initializes them from the conventional eight-word SHA-256 state before
executing the 64 sliding-window rounds.

The final state is feed-forwarded into the conventional SHA-256 chaining
state.

---

# Verification

SHA256SW has multiple verification layers.

```text
C implementation
       |
       v
C test suite
       |
       v
SMT bit-vector models
       |
       v
64 one-round equivalence obligations
       |
       v
Compact symbolic equivalence proof
       |
       v
Inverse proof
       |
       v
SAT/SMT benchmark witnesses
       |
       v
Independent reference verification
```

The goal is to avoid relying on a single implementation or a single solver
result.

## C test suite

Run:

```text
make test
```

The Makefile builds the C implementation together with
`tests/test_sha256sw.c` and executes the resulting test binary.

## Formal proofs

Run:

```text
make formal
```

The formal target:

1. checks that Z3 is available;
2. generates SMT proof artifacts;
3. checks the `Ch` equivalence proof;
4. checks 64 one-round equivalence obligations;
5. checks the compact symbolic equivalence proof;
6. checks the inverse proof.

The quieter form is:

```text
make formal-quiet
```

The formal proof generator is:

```text
formal/generate_smt_proofs.py
```

The resulting SMT artifacts are generated rather than treated as hand-written
proof documents.

---

# Symbolic Equivalence

The formal equivalence model uses symbolic 32-bit state words and symbolic
message-schedule words.

The standard formulation explicitly models:

```text
A B C D E F G H
```

and their six direct register-copy relationships.

The sliding-window formulation models:

```text
a_mt
b_mt
```

with the register shifts encoded by the overlapping coordinate system.

The equivalence obligation asserts that the final standard state differs from
the corresponding final sliding-window state and asks Z3 for satisfiability.

A result of:

```text
unsat
```

therefore means that no symbolic counterexample to the stated equivalence
exists within the encoded bit-vector model.

The repository's formal workflow checks the one-round obligations across all
64 rounds and also checks the compact multi-round equivalence and inverse
proofs.

---

# Independent Reference Verification

SAT/SMT solver output is not treated as sufficient by itself.

The benchmark harness generates reduced-round collision witnesses and then
verifies them independently.

The intended flow is:

```text
SAT/SMT result
      |
      v
Extract M1 and M2
      |
      v
Check M1 != M2
      |
      v
Independent reference evaluation
      |
      v
Check H_R(IV,M1) == H_R(IV,M2)
```

This guards against false positives caused by incorrectly encoded benchmark
constraints.

---

# Benchmark

The repository contains a four-way representation benchmark.

The collision encodings are:

```text
Std-Explicit
SW-Explicit
Std-Inline
SW-Inline
```

## Std-Explicit

The conventional SHA-256 formulation with explicit register-copy
relationships such as:

```text
B[i+1] = A[i]
C[i+1] = B[i]
D[i+1] = C[i]

F[i+1] = E[i]
G[i+1] = F[i]
H[i+1] = G[i]
```

## SW-Explicit

The sliding-window representation in which those state shifts are represented
implicitly through the overlapping histories.

## Std-Inline

The standard representation with the round state expressed directly through
inline symbolic definitions.

## SW-Inline

The corresponding inline sliding-window representation.

The purpose of the four-way comparison is to separate the effect of the
coordinate system from the effect of explicitly asserting state-copy
relationships.

---

# Benchmark Problem

The collision benchmark asks a solver to find two distinct message inputs:

```text
M1 != M2
```

such that the reduced-round compression function satisfies:

```text
H_R(IV, M1) = H_R(IV, M2)
```

for a selected number of rounds `R`.

These are experiments on reduced-round instances.

They are **not** attacks on full 64-round SHA-256.

The benchmark script is:

```text
benchmark/sha256_representation_benchmark.py
```

---

# Primary Metric

The pre-registered primary representation metric is:

```text
S_R =
median(T_Std-Explicit,R)
------------------------
median(T_SW-Explicit,R)
```

where:

```text
Std-Explicit
```

is the conventional explicit-register encoding and:

```text
SW-Explicit
```

is the sliding-window encoding.

Interpretation:

```text
S_R > 1    SW-Explicit is faster

S_R ~= 1   little measurable difference

S_R < 1    Std-Explicit is faster
```

This is a **solver-performance metric**.

It is not a cryptographic-security metric.

---

# Timeouts and Censored Results

Solver runtimes can be right-censored by a timeout.

A timeout should therefore not be treated as a zero-duration result and should
not simply disappear from the analysis.

The benchmark records timeout outcomes explicitly.

When at least half of the observations time out, the benchmark reports the
median as a lower-bound form such as:

```text
>120s
```

rather than fabricating a finite median.

The benchmark also records solved/unsolved counts and exports JSON/CSV results
for later analysis.

See [`BENCHMARKING.md`](BENCHMARKING.md) for the detailed methodology.

---

# Benchmark Reproducibility

A benchmark result should be tied to:

- repository commit;
- solver and exact solver version;
- hardware;
- operating system;
- Python version;
- compiler/runtime configuration;
- round count;
- number of trials;
- timeout;
- generated-instance configuration;
- random seeds where applicable;
- solved/unsolved counts;
- runtime distribution.

Record the repository revision with:

```bash
git rev-parse HEAD
```

The benchmark output can be written to JSON and CSV using the corresponding
command-line options or the Makefile configuration.

---

# Quickstart

## Requirements

For the C implementation:

- C compiler with C11 support;
- `make`.

For formal verification and SAT/SMT experiments:

- Python 3;
- Z3.

Check the configured tools with:

```bash
make info
```

If Z3 is not on `PATH`, the Makefile supports supplying its location through
the `Z3` variable.

For example:

```bash
make formal Z3=/path/to/z3
```

---

## 1. Build and run the C tests

```bash
make test
```

This is the recommended first command.

---

## 2. Run the formal verification

```bash
make formal
```

For a quieter verification run:

```bash
make formal-quiet
```

---

## 3. Run the one-round gate

Before larger solver experiments, run:

```bash
make gate
```

This executes the repository's one-round equivalence gate with a short
timeout.

---

## 4. Run the symbolic equivalence benchmark

```bash
make equiv
```

The default Makefile target evaluates:

```text
2 4 8 16 32 64 rounds
```

using the configured trial count, timeout, JSON output, and CSV output.

---

## 5. Run the collision benchmark

```bash
make benchmark
```

This executes the configured four-way reduced-round collision benchmark.

For a first manual experiment, use a small round count and short timeout
rather than immediately launching a deep benchmark.

For example:

```bash
python3 benchmark/sha256_representation_benchmark.py \
    z3 \
    --rounds 8 \
    --trials 1 \
    --timeout 30
```

The larger benchmark ladder should be treated as an experiment rather than
as a quick smoke test.

---

## 6. Run the full repository validation

```bash
make verify
```

This runs:

```text
make test
make formal
```

The CI-equivalent target is:

```bash
make ci
```

---

# Repository Layout

The current repository is organized as:

```text
sha256sw/
|
+-- .github/
|   `-- workflows/
|
+-- benchmark/
|   `-- sha256_representation_benchmark.py
|
+-- formal/
|   `-- generate_smt_proofs.py
|
+-- include/
|   `-- sha256sw.h
|
+-- src/
|   `-- sha256sw.c
|
+-- tests/
|   `-- test_sha256sw.c
|
+-- BENCHMARKING.md
+-- LICENSE
+-- Makefile
+-- SECURITY_SCOPE.md
+-- THEORY.md
`-- readme.md
```

---

# Make Targets

The principal Makefile targets are:

```text
make build
    Build the C test binary.

make test
    Build and run the C test suite.

make generate-formal
    Generate SMT proof artifacts.

make formal
    Generate and check the formal proofs with Z3.

make formal-quiet
    Run the formal proofs with reduced command output.

make gate
    Run the one-round symbolic equivalence gate.

make equiv
    Run the symbolic representation-equivalence benchmark.

make benchmark
    Run the four-way collision/representation benchmark.

make verify
    Run the C tests and formal verification.

make ci
    CI-oriented alias for test + formal verification.

make info
    Display compiler, Python, Z3, benchmark, and proof configuration.

make clean
    Remove generated build, proof, and benchmark artifacts.

make distclean
    Alias for clean.
```

---

# What the Sliding Window Removes

The sliding-window representation removes the need to introduce six direct
register-copy relationships as independent per-round state equations.

Instead of explicitly encoding:

```text
B' = A
C' = B
D' = C

F' = E
G' = F
H' = G
```

the overlapping histories encode those relationships structurally.

This can change the constraint graph presented to a SAT/SMT solver.

That is the representation-level hypothesis being measured by the benchmark.

---

# What the Sliding Window Does Not Remove

The sliding-window formulation does not remove:

- modular addition;
- addition carries;
- `Ch`;
- `Maj`;
- rotations;
- logical shifts;
- the SHA-256 `Sigma` functions;
- the SHA-256 message schedule;
- the round constants;
- the 64-round computation;
- the 512-bit message-block structure;
- the underlying ARX/Boolean constraints.

Therefore:

```text
Different representation
        !=
Different cryptographic primitive
```

and:

```text
Fewer explicit state-copy equations
        !=
Elimination of SHA-256's cryptographic structure
```

---

# Reduced-Round and Reduced-Width Experiments

The benchmark infrastructure is designed for reduced-round solver experiments.

Small-width parameterized experiments can also be useful for:

- regression testing;
- debugging;
- exhaustive finite-domain experiments;
- rapid solver comparisons;
- validating collision controls.

A reduced-width ARX experiment should not be described as a full SHA-256
cryptanalytic result.

Likewise, a reduced-round collision should not be presented as a
full-round SHA-256 collision attack.

The benchmark should always report the actual:

```text
round count
word width
input constraints
solver
timeout
trial count
```

---

# Solver Interpretation

Suppose an experiment produces:

```text
S_R = 3
```

The correct interpretation is:

> Under the specified benchmark conditions, the median runtime of the
> standard explicit encoding was approximately three times the median
> runtime of the sliding-window explicit encoding.

It does **not** mean:

```text
SHA-256 is three times weaker.
```

Likewise, if:

```text
S_R ~= 1
```

that is still an informative result. It may indicate that solver
simplification or preprocessing already removes much of the representation
difference.

If:

```text
S_R < 1
```

the standard formulation may provide a more favorable constraint structure
for the tested solver.

All three outcomes are useful experimental results.

---

# No Causal Claim About Solver Internals

A wall-clock benchmark can demonstrate a performance difference.

It cannot by itself prove the precise internal reason for that difference.

For example:

```text
SW is faster
```

does not by itself establish that the speedup is caused specifically by:

- fewer CDCL conflicts;
- fewer propagations;
- improved branching;
- a smaller internal graph;
- reduced memory traffic;
- a particular preprocessing pass.

Those claims require dedicated solver instrumentation.

The primary result is therefore a representation-level empirical benchmark.

---

# Verification Philosophy

The repository deliberately separates mathematical proof from implementation
testing.

The algebraic argument establishes:

```text
Fixed-word SHA-256 round is bijective
        |
        v
Composition of fixed-word rounds is bijective
        |
        v
Fixed-schedule state transformation has an inverse
```

The formal models then machine-check the encoded relationships.

The C test suite checks the implementation.

The benchmark's independent verifier checks solver-generated witnesses.

The layers therefore have different purposes:

```text
Algebra
    -> mathematical justification

SMT
    -> machine-checked encoded obligations

C tests
    -> implementation validation

Independent reference
    -> witness validation

Benchmark
    -> empirical solver comparison
```

No single layer should be confused with the others.

---

# Standard SHA-256 vs Freestart

A standard SHA-256 hash begins from the fixed FIPS initial state:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

A freestart construction instead permits the chaining state to be selected.

For a known message block and its expanded schedule:

```text
W
```

the construction can compute:

```text
H_fix = E_W^-1(0^256)
```

and therefore:

```text
C_W(H_fix) = H_fix
```

This does not imply:

```text
E_W(IV_FIPS) = 0^256
```

and does not produce a standard-IV fixed point.

The difference is entirely due to which quantity is fixed and which is
allowed to vary.

---

# Compression Function vs Complete Hash Function

The fixed-schedule inversion result concerns the **working-state
transformation** inside SHA-256.

The complete SHA-256 hash function additionally applies:

- message padding;
- encoded message length;
- block-by-block Merkle-Damgard processing;
- final digest serialization.

An internal compression-state fixed point should therefore not be confused
with an arbitrary collision between serialized messages of different
lengths.

The project makes no such claim.

---

# Generic Security Context

For an ideal 256-bit hash, generic security is commonly described using the
scales:

```text
Collision search: approximately 2^128

Preimage search: approximately 2^256
```

These are generic security scales, not statements that every concrete
attack must take exactly those numbers of operations.

SHA256SW does not present an attack that reduces either generic scale for
standard full-round SHA-256.

The fixed-schedule inverse is a different problem because the expanded
message schedule is supplied as part of the problem.

---

# Limitations

The project has several important limitations.

## Fixed schedule

The algebraic inverse assumes that the complete round schedule is known.

## Unknown-message inversion remains different

For standard SHA-256, the message determines the schedule. The inverse does
not remove those message-schedule constraints.

## Reduced-round experiments

Solver benchmarks on reduced rounds do not establish full-round cryptanalytic
weakness.

## Reduced-width experiments

Experiments with word widths below 32 bits are parameterized ARX models, not
full SHA-256 instances.

## Solver dependence

A representation that helps one solver may not help another.

## Hardware dependence

Wall-clock measurements depend on hardware, operating system, solver version,
system load, and other environmental conditions.

## Statistical limitations

Small trial counts can produce unstable runtime estimates. Published
benchmark results should therefore include enough instances to characterize
the distribution and should report timeout counts and dispersion.

---

# Recommended Experimental Workflow

A reproducible research workflow is:

```text
1. make test
       |
       v
2. make formal
       |
       v
3. make gate
       |
       v
4. make equiv
       |
       v
5. small collision benchmark
       |
       v
6. larger reduced-round benchmark
       |
       v
7. record commit + solver + hardware + timeout
       |
       v
8. analyze solved/timeout distributions
```

Correctness should be established before performance is interpreted.

---

# Documentation

The repository intentionally separates the high-level README from the
detailed research documents.

## [`THEORY.md`](THEORY.md)

Contains the algebraic derivation of:

- fixed-schedule round invertibility;
- full-round bijection;
- sliding-window coordinates;
- inverse construction;
- O(R) inversion complexity;
- freestart Davies-Meyer fixed points;
- the distinction between state inversion and message inversion.

## [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md)

Defines:

- what the construction establishes;
- what it does not establish;
- the fixed-schedule versus unknown-message boundary;
- appropriate complexity language;
- how solver speedups should be interpreted.

## [`BENCHMARKING.md`](BENCHMARKING.md)

Contains the detailed benchmark methodology, including:

- representation definitions;
- trial structure;
- timeout treatment;
- reproducibility requirements;
- result interpretation;
- benchmark controls.

---

# Research Questions

The main empirical question is:

```text
Does eliminating redundant state-coordinate equations
produce a reproducible SAT/SMT advantage?
```

A useful experimental matrix is:

```text
Representation
    |
    +-- Std-Explicit
    +-- SW-Explicit
    +-- Std-Inline
    `-- SW-Inline

Solver
    |
    `-- Z3
        |
        +-- future: additional SMT solvers
        `-- future: direct SAT/CNF encodings

Round count
    |
    +-- low
    +-- medium
    `-- high reduced-round workloads
```

The repository currently provides the benchmark infrastructure for this
comparison; future work can extend the solver and instrumentation matrix.

---

# Future Work

Potential extensions include:

- additional SMT solvers;
- direct SAT/CNF encodings;
- clause-count measurements;
- propagation measurements;
- solver-internal instrumentation;
- branching-heuristic analysis;
- memory-use measurements;
- larger reduced-round experiments;
- larger reduced-width experiments;
- differential-analysis models;
- MILP formulations;
- message-modification models;
- hardware-oriented implementations.

The most important immediate empirical question remains whether the
representation difference produces a reproducible solver advantage across
controlled benchmark conditions.

---

# Publication-Ready Mathematical Statement

The central mathematical result can be summarized as:

> For every fixed sequence of 64 SHA-256 round words, the 64-round
> SHA-256 working-state transformation is a permutation of the 256-bit
> state space. Each individual round is invertible by algebraically
> recovering the shifted registers followed by `T1`, `T2`, and the remaining
> input registers. The sliding-window representation provides a coordinate
> form of this inverse. Consequently, for any target working state `S`, the
> unique chaining state `H = E_W^-1(S)` can be computed in O(R) round
> operations, with `R = 64` for full SHA-256. Setting `S = 0^256` gives the
> unique Davies-Meyer freestart fixed point for the corresponding fixed
> message schedule. This is inversion with respect to the chaining state
> under a known schedule and does not constitute efficient inversion with
> respect to the unknown message input at the standardized SHA-256 IV.

---

# Bottom Line

SHA256SW establishes a clean separation between **representation** and
**cryptographic security**.

```text
                     SHA-256
                        |
             +----------+----------+
             |                     |
             v                     v
      Standard state        Sliding-window state
             |                     |
             +----------+----------+
                        |
                        v
                 Exact equivalence
                        |
                        v
              Fixed W is invertible
                        |
                        v
                Exact state inverse
                        |
                        v
              Freestart fixed point
```

The essential boundary remains:

```text
Fixed W
   |
   v
Invert the working state
```

is not the same problem as:

```text
Fixed IV + unknown M
   |
   v
Invert the message
```

The sliding-window construction is therefore a structural and algebraic
property of the fixed-schedule SHA-256 working-state transformation, not a
break of standard SHA-256.

The remaining research question is empirical:

```text
Does the sliding-window encoding
produce a measurable SAT/SMT advantage?
```

That is what the benchmark harness is designed to measure.

---

# License

SHA256SW is released under the MIT License.

See [`LICENSE`](LICENSE) for the complete license text.

---

# Citation

```bibtex
@misc{sha256sw2026,
  author = {SHA256SW Contributors},
  title  = {SHA256SW: Sliding-Window State Representation and
            Cryptanalytic Benchmark for SHA-256},
  year   = {2026}
}
```

---

# Repository

The project repository is:

```text
laserjobs/sha256sw
```

The current source tree contains the C implementation, tests, formal proof
generator, benchmark harness, theory documentation, security-scope
documentation, and benchmark methodology.

```text
src/sha256sw.c
include/sha256sw.h
tests/test_sha256sw.c
formal/generate_smt_proofs.py
benchmark/sha256_representation_benchmark.py
THEORY.md
SECURITY_SCOPE.md
BENCHMARKING.md
Makefile
LICENSE
```

SHA256SW is intended to make the distinction between a mathematically exact
state-coordinate transformation and an actual cryptanalytic attack explicit,
machine-checkable, and experimentally testable.
