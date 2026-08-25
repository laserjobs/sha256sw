# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

An endian-independent, portable C11 implementation of SHA-256 with
machine-checked SMT equivalence models and an automated SAT/SMT benchmark
comparing conventional eight-register and sliding-window state formulations.

> **Central result:** For every fixed 64-word SHA-256 message schedule
> \(W=(W_0,\ldots,W_{63})\), the 64-round working-state transformation
> \(E_W\) is a permutation of the 256-bit state space. The sliding-window
> representation provides an explicit inverse \(E_W^{-1}\).
>
> This gives deterministic freestart fixed points for a **known message
> schedule**. It does **not** provide an inversion, collision, or preimage
> attack against standard SHA-256 with its fixed FIPS IV and unknown message.

SHA256SW studies whether changing the representation of the SHA-256 working
state can make reduced-round SAT/SMT problems easier to solve while
preserving exactly the same mathematical function.

The project also derives an exact algebraic inverse of the SHA-256
working-state transformation when the complete 64-word message schedule is
fixed and known.

> **Central result:** For every fixed 64-word schedule `W`, the 64-round
> SHA-256 working-state map `E_W` is a permutation of the 256-bit working
> state. The sliding-window representation provides an explicit inverse.
> This yields deterministic freestart fixed points for known schedules; it
> does **not** invert SHA-256 with respect to an unknown message at the
> standard SHA-256 IV.

---

## What This Project Is

SHA256SW has four closely related goals:

1. Establish exact equivalence between the conventional eight-register
   SHA-256 formulation and the sliding-window formulation.
2. Derive and validate an exact backward inverse for the working-state
   transformation when the round words are fixed.
3. Machine-check the representation equivalence with SMT bit-vector models
   and independently validate implementations.
4. Measure whether eliminating explicit register-copy equations produces a
   measurable SAT/SMT solver advantage on reduced-round problems.

The project therefore separates:

```text
Mathematical equivalence
        │
        ▼
Same SHA-256 function?
        │
        ▼
Representation
        │
        ▼
Different SAT/SMT constraint structure?
        │
        ▼
Empirical solver performance
```

A solver speedup is a statement about the **encoding and solver workload**.
It is not evidence that SHA-256 itself has become weaker.

---

# Security Boundary

The most important distinction in this project is between **known message
schedules** and the **unknown-message problem**.

For a fixed schedule:

```text
W[0..63] known
      │
      ▼
E_W is a permutation
      │
      ▼
E_W^-1 exists
      │
      ▼
working-state inversion
```

For standard SHA-256 message inversion:

```text
IV fixed
      │
      ▼
M unknown
      │
      ▼
W(M) unknown
      │
      ▼
message-search problem
```

The sliding-window inverse solves the first problem.

It does **not** provide an efficient inversion algorithm for the second.

In particular, SHA256SW does not claim:

- a full-round SHA-256 collision attack;
- a full-round SHA-256 preimage attack;
- a second-preimage attack;
- a practical fixed point at the standardized SHA-256 IV;
- a reduction in generic collision complexity;
- a reduction in generic preimage complexity;
- an efficient inversion of SHA-256 with respect to an unknown message.

The fixed-schedule state result is an exact algebraic property of the
compression state transformation.

---

# Quickstart

## 1. Build and run the C test suite

```bash
make test
```

This exercises the portable C11 implementation and its test vectors,
streaming behavior, compression path, and defensive checks.

## 2. Run the formal verification

```bash
make formal
```

The formal infrastructure uses SMT-LIB2 bit-vector models to check the
standard and sliding-window formulations.

## 3. Run the project verification gate

```bash
make gate
```

For the complete available verification targets:

```bash
make help
```

## 4. Run a small representation-equivalence benchmark

Start with a small reduced-round experiment rather than immediately running
the hardest benchmark cells:

```bash
python3 benchmark/sha256_representation_benchmark.py \
    z3 \
    --rounds 2 4 8 \
    --trials 3 \
    --timeout 30
```

Then increase the workload as desired:

```bash
python3 benchmark/sha256_representation_benchmark.py \
    z3 \
    --rounds 16 20 24 28 30 \
    --trials 5 \
    --timeout 120
```

Higher-round collision instances can legitimately time out. A timeout is a
benchmark observation, not a failure of the mathematical construction.

Before publishing timing results, record the exact repository revision:

```bash
git rev-parse HEAD
```

See `BENCHMARKING.md` for the full methodology.

---

# Repository Layout

```text
sha256sw/
│
├── .github/
│   └── workflows/
│
├── benchmark/
│   ├── backup/
│   └── sha256_representation_benchmark.py
│
├── formal/
│   └── generate_smt_proofs.py
│
├── include/
│
├── src/
│
├── tests/
│
├── BENCHMARKING.md
├── LICENSE
├── Makefile
├── SECURITY_SCOPE.md
├── THEORY.md
└── readme.md
```

The main components are:

| Path | Purpose |
|---|---|
| `src/` | Portable C11 SHA-256 implementation |
| `include/` | Public C interfaces |
| `tests/` | Unit, vector, streaming, and defensive tests |
| `formal/` | SMT-LIB2 generation and formal verification |
| `benchmark/` | SAT/SMT representation and collision benchmarks |
| `.github/workflows/` | Continuous integration |
| `THEORY.md` | Mathematical derivations |
| `SECURITY_SCOPE.md` | Security interpretation and boundaries |
| `BENCHMARKING.md` | Benchmark methodology and reproducibility |

---

# Mathematical Summary

SHA-256 maintains eight 32-bit working words:

```text
A B C D E F G H
```

For round `i`:

```text
T1 = H
   + Σ1(E)
   + Ch(E,F,G)
   + K[i]
   + W[i]

T2 = Σ0(A)
   + Maj(A,B,C)
```

and:

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

All additions and subtractions are modulo `2^32`.

The standard Boolean functions are:

```text
Ch(x,y,z)  = (x & y) ^ (~x & z)

Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
```

The SHA-256 big-sigma functions are:

```text
Σ0(x) = ROTR^2(x)  ^ ROTR^13(x) ^ ROTR^22(x)

Σ1(x) = ROTR^6(x)  ^ ROTR^11(x) ^ ROTR^25(x)
```

and the message-schedule functions are:

```text
σ0(x) = ROTR^7(x)  ^ ROTR^18(x) ^ SHR^3(x)

σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
```

with:

```text
W[i] = σ1(W[i-2])
     + W[i-7]
     + σ0(W[i-15])
     + W[i-16]
```

for:

```text
16 <= i < 64
```

---

# Sliding-Window Representation

For round `i`, SHA256SW uses two overlapping histories:

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
   + Σ1(b[i+3])
   + Ch(b[i+3], b[i+2], b[i+1])
   + K[i]
   + W[i]

b[i+4] = a[i] + T1

T2 = Σ0(a[i+3])
   + Maj(a[i+3], a[i+2], a[i+1])

a[i+4] = T1 + T2
```

Equivalently:

```text
a[i+4] = (b[i+4] - a[i]) + T2
```

The sliding-window formulation does not change the SHA-256 round function.

It changes the **coordinates used to represent the state**.

The six direct register-copy relations:

```text
B' = A
C' = B
D' = C

F' = E
G' = F
H' = G
```

are represented implicitly by the overlapping windows.

The Boolean functions, rotations, shifts, modular additions, message schedule,
constants, and round count remain unchanged.

---

# Exact One-Round Inversion

The fixed-schedule round is algebraically invertible.

Given:

```text
(A', B', C', D', E', F', G', H')
```

first recover:

```text
A = B'
B = C'
C = D'

E = F'
F = G'
G = H'
```

Then:

```text
T2 = Σ0(A) + Maj(A,B,C)
```

and:

```text
T1 = A' - T2
```

From:

```text
E' = D + T1
```

recover:

```text
D = E' - T1
```

Finally:

```text
H = T1
  - Σ1(E)
  - Ch(E,F,G)
  - K[i]
  - W[i]
```

All subtraction is modulo `2^32`.

Therefore every input register is uniquely determined by the output state
when `K[i]` and `W[i]` are fixed.

The sliding-window representation expresses the same inverse directly in its
coordinate system.

See `THEORY.md` for the full derivation.

---

# Fixed-Schedule Bijection

Let:

```text
R_i : (Z/2^32Z)^8 -> (Z/2^32Z)^8
```

be SHA-256 round `i` with fixed `K[i]` and `W[i]`.

Because the explicit inverse exists:

```text
R_i^-1
```

exists, so:

```text
R_i
```

is a bijection.

For a fixed schedule:

```text
W = (W[0], W[1], ..., W[63])
```

the complete transformation is:

```text
E_W = R_63 o R_62 o ... o R_0
```

A composition of bijections is a bijection.

Therefore:

```text
E_W
```

is a permutation of the 256-bit working-state space.

Equivalently:

```text
E_W : {0,1}^256 -> {0,1}^256
```

is one-to-one and onto.

The inverse is:

```text
B_W = E_W^-1
```

and satisfies:

```text
B_W(E_W(H)) = H
```

and:

```text
E_W(B_W(S)) = S
```

for every working state `H` and target state `S`.

For `R` rounds, applying the inverse takes:

```text
O(R)
```

round operations.

For full SHA-256:

```text
R = 64
```

so the full inverse is a fixed sequence of 64 inverse-round operations once
the complete schedule is known.

---

# Freestart Fixed Points

For a fixed message schedule, define the compression transformation:

```text
C_W(H) = H + E_W(H)
```

where the addition is componentwise modulo `2^32`.

A fixed point satisfies:

```text
C_W(H) = H
```

which is equivalent to:

```text
E_W(H) = 0^256
```

Because `E_W` is a permutation, exactly one such state exists:

```text
H_fix = B_W(0^256)
```

and therefore:

```text
E_W(H_fix) = 0^256
```

and:

```text
C_W(H_fix) = H_fix
```

Thus every fixed schedule has a unique corresponding Davies-Meyer
**freestart fixed point**.

This is a statement about the working/chaining state when the schedule is
known.

It is not a fixed point attack against standard SHA-256 with its fixed IV.

---

# Known Message vs Unknown Message

If a message block `M` is known:

```text
M
│
▼
W(M)
│
▼
B_W(0^256)
│
▼
H_fix
```

the corresponding freestart fixed point can be computed deterministically.

But standard SHA-256 begins from the fixed IV:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

and asks questions about an unknown message.

For example, a standard-IV fixed-point condition would require:

```text
E_W(M)(IV_FIPS) = 0^256
```

Now:

```text
M
```

is unknown and therefore:

```text
W(M)
```

is unknown and constrained by the message schedule.

The fixed-schedule inverse does not remove those message constraints.

This is the central cryptographic boundary of SHA256SW:

```text
Known W  -> invert state H
```

is not equivalent to:

```text
Fixed IV + unknown M -> invert message M
```

---

# Formal Verification

The repository contains SMT-LIB2 / bit-vector verification infrastructure
under `formal/`.

The formal models encode:

- 32-bit modular addition;
- modular subtraction;
- XOR;
- AND;
- NOT;
- rotations;
- logical shifts;
- `Ch`;
- `Maj`;
- SHA-256 sigma functions;
- SHA-256 round functions;
- message-schedule operations;
- standard/sliding-window equivalence;
- inverse relationships.

The verification strategy is compositional:

```text
SHA-256 primitives
        │
        ▼
single-round equivalence
        │
        ▼
multi-round equivalence
        │
        ▼
representation equivalence
```

The algebraic inverse is independently derived from the round equations.

Formal verification therefore serves as machine-checked validation of the
encoded implementation rather than replacing the mathematical argument.

Run:

```bash
make formal
```

---

# Independent Verification

SAT/SMT witnesses are independently checked rather than being accepted solely
because a solver returns `sat`.

The verification flow is:

```text
solver
  │
  ▼
candidate M1, M2
  │
  ▼
check M1 != M2
  │
  ▼
independent reference implementation
  │
  ▼
compute reduced-round states
  │
  ▼
verify H_R(M1) == H_R(M2)
```

The independent reference path is important because a satisfiable result
from an incorrectly encoded model would otherwise produce a false positive.

---

# Reduced-Round Collision Benchmark

The benchmark compares equivalent state representations on reduced-round
collision problems.

The target is:

```text
M1 != M2
```

such that:

```text
H_R(IV, M1) = H_R(IV, M2)
```

for a reduced number of rounds `R`.

These are experiments on a reduced-round compression function.

They are **not** attacks on full 64-round SHA-256.

---

# Reduced-Width Controls

The benchmark can also operate on reduced-width parameterized ARX models.

For example, with:

```text
n = 4
R = 9
```

nine 4-bit message words contain:

```text
9 * 4 = 36
```

input bits, while the eight-word output contains:

```text
8 * 4 = 32
```

output bits.

Therefore a collision must exist by the pigeonhole principle.

A representative control is:

```text
IV4 =
[0x7, 0x5, 0x2, 0xa, 0xf, 0xc, 0xb, 0x9]

M1 =
[0x0, 0x7, 0xa, 0x4, 0xa, 0xd, 0xb, 0x2, 0x3]

M2 =
[0xb, 0xd, 0xc, 0x6, 0x5, 0x9, 0x0, 0xb, 0x8]
```

with:

```text
M1 != M2
```

and:

```text
H_9(IV4,M1)
=
H_9(IV4,M2)
=
[0x1, 0xa, 0x6, 0x3, 0xa, 0xe, 0xf, 0x2]
```

This is an ordinary finite-domain collision in a **parameterized reduced-width
ARX model**.

It is not a collision for real 32-bit SHA-256.

---

# Inactive-Word Control

The benchmark also checks that unread message words are genuinely inactive.

For:

```text
R = 15
```

only:

```text
W[0], ..., W[14]
```

are consumed by the compression rounds.

Changing:

```text
W[15]
```

therefore cannot change the 15-round state output.

This provides a useful boundary/control test:

```text
same consumed words
different unconsumed word
        │
        ▼
same reduced-round state
```

Such controls help verify that the benchmark is measuring the intended
constraint system rather than an accidental modeling artifact.

---

# Representation Benchmark

The primary comparison is between two mathematically equivalent encodings.

## Standard explicit representation

The conventional model contains equations such as:

```text
A[i+1] = T1 + T2
B[i+1] = A[i]
C[i+1] = B[i]
D[i+1] = C[i]

E[i+1] = D[i] + T1
F[i+1] = E[i]
G[i+1] = F[i]
H[i+1] = G[i]
```

The register-copy constraints are explicit.

## Sliding-window representation

The sliding-window model instead uses:

```text
a[i+4] = T1 + T2
b[i+4] = a[i] + T1
```

with overlapping coordinates encoding the state shifts.

The cryptographic computation is unchanged.

The experiment asks whether the resulting constraint representation is easier
for a SAT/SMT solver to search.

---

# Primary Solver Metric

The pre-registered primary metric is:

```text
S_R =
median(T_Std-Explicit,R)
-------------------------
median(T_SW-Explicit,R)
```

where:

```text
Std-Explicit
```

is the standard eight-register representation with explicit copy equations,
and:

```text
SW-Explicit
```

is the sliding-window representation.

Interpretation:

```text
S_R > 1    SW is faster

S_R ~= 1   little measurable difference

S_R < 1    Standard is faster
```

`S_R` measures empirical solver performance under the specified benchmark
conditions.

It does not measure cryptographic security.

See `BENCHMARKING.md` for timeout treatment, trial selection, hardware
reporting, and statistical methodology.

---

# Timeouts and Reproducibility

SAT/SMT runtimes can be heavy-tailed and can be right-censored by timeouts.

A timeout should therefore be recorded explicitly rather than silently
treated as an ordinary runtime.

Benchmark reports should include:

- solver name;
- solver version;
- CPU model;
- available cores;
- RAM;
- operating system;
- compiler/runtime versions;
- repository commit;
- round count;
- word width;
- trial count;
- timeout;
- solved count;
- timeout count;
- median runtime;
- dispersion statistics.

Record the repository state with:

```bash
git rev-parse HEAD
```

and preserve the exact benchmark command line.

For complete methodology, see:

```text
BENCHMARKING.md
```

---

# Why the Benchmark Matters

The sliding-window representation removes explicit equations corresponding
to the six direct register copies:

```text
B' = A
C' = B
D' = C

F' = E
G' = F
H' = G
```

This can alter the constraint graph seen by a SAT/SMT solver.

However, the representation does not remove:

- modular addition;
- carry propagation;
- rotations;
- logical shifts;
- `Ch`;
- `Maj`;
- SHA-256 sigma functions;
- message-schedule constraints;
- the underlying 64-round computation.

Therefore:

```text
different representation
        !=
different cryptographic primitive
```

and:

```text
fewer explicit copy equations
        !=
elimination of SHA-256's ARX difficulty
```

---

# No Causal Claim About Solver Internals

A wall-clock benchmark can establish a performance difference between two
encodings.

It cannot, by itself, establish the exact internal reason.

For example:

```text
SW faster
```

does not by itself prove that the improvement comes specifically from:

- fewer CDCL conflicts;
- fewer propagations;
- improved branching;
- a smaller conflict graph;
- lower memory traffic.

Such claims require dedicated solver instrumentation.

The primary result is therefore an empirical representation-level benchmark.

---

# Verification Hierarchy

The recommended verification order is:

```text
1. C unit tests
       │
       ▼
2. Independent reference implementation
       │
       ▼
3. Standard/SW equivalence
       │
       ▼
4. Algebraic round inverse
       │
       ▼
5. Randomized round-trip validation
       │
       ▼
6. Reduced-round solver benchmark
```

Correctness should be established before performance is interpreted.

---

# What Is Established

For every fixed sequence:

```text
W[0..63]
```

the project establishes the following mathematical structure:

```text
each round is invertible
        │
        ▼
64-round composition is invertible
        │
        ▼
E_W is a permutation
        │
        ▼
every target state has one state preimage
        │
        ▼
B_W = E_W^-1
        │
        ▼
B_W(0^256) gives the unique freestart fixed point
```

The implementation and formal models provide independent evidence that the
software corresponds to this construction.

---

# What Is Not Established

SHA256SW does not establish:

```text
full-round SHA-256 collision attack
full-round SHA-256 preimage attack
second-preimage attack
standard-IV fixed point
message inversion algorithm
reduced generic collision complexity
reduced generic preimage complexity
```

The conventional generic security scales remain useful context:

```text
collision search  ~ 2^128
preimage search   ~ 2^256
```

These are generic security scales, not claims that every concrete attack must
take exactly those numbers of operations.

The fixed-schedule state inverse is a different problem because the message
schedule is already supplied.

---

# Reduced Rounds and Widths

Useful benchmark widths include:

```text
n = 4
n = 6
n = 8
n = 12
n = 16
n = 32
```

Small widths are particularly useful for:

- exhaustive testing;
- regression tests;
- solver controls;
- collision demonstrations;
- debugging algebraic models.

Widths below 32 are parameterized ARX models and should not be described as
ordinary SHA-256 instances.

Reduced round counts likewise provide experimental information about solver
behavior, not full-round SHA-256 security.

---

# Research Questions

The principal empirical question is:

> Does the sliding-window encoding provide a reproducible SAT/SMT advantage
> over an equivalent explicit-register encoding?

There are three scientifically useful outcomes.

### `S_R > 1`

The sliding-window representation is faster under the tested conditions.

### `S_R ~= 1`

The representations perform similarly, suggesting that solver preprocessing
or other internal mechanisms already remove much of the representation
difference.

### `S_R < 1`

The explicit-register representation is faster, showing that the apparently
more verbose encoding can sometimes provide a more favorable solver
constraint structure.

All three outcomes are informative.

---

# Limitations

## Fixed schedules

The state inverse assumes the complete round schedule is known.

## Unknown messages

The inverse does not solve the coupled problem of recovering an unknown
message and its schedule from a fixed IV.

## Reduced rounds

Reduced-round results cannot be extrapolated directly to full SHA-256
security.

## Reduced widths

Experiments with `n < 32` are parameterized ARX models.

## Solver dependence

An encoding that helps one solver may not help another.

## Hardware dependence

Wall-clock measurements depend on hardware, operating system, solver version,
and system load.

## Statistical limitations

Small trial counts can produce unstable timing estimates.

---

# Further Documentation

The README intentionally provides the central mathematical and security
picture without reproducing every derivation.

For the detailed mathematical treatment:

```text
THEORY.md
```

For the security interpretation and explicit limitations:

```text
SECURITY_SCOPE.md
```

For benchmark methodology and reproducibility:

```text
BENCHMARKING.md
```

These documents should be read together with this README when interpreting
research results.

---

# Standard SHA-256 IV

For reference, the standardized SHA-256 initial state is:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

A standard-IV fixed-point condition would require:

```text
E_W(M)(IV_FIPS) = 0^256
```

where `W(M)` is the schedule generated from the unknown message.

The fixed-schedule inverse does not solve that problem.

---

# Freestart vs Standard SHA-256

The distinction can be summarized as:

```text
FREESTART / KNOWN SCHEDULE

M known
  │
  ▼
W known
  │
  ▼
choose target S
  │
  ▼
B_W(S)
  │
  ▼
unique chaining state H
```

versus:

```text
STANDARD SHA-256 MESSAGE SEARCH

IV fixed
  │
  ▼
M unknown
  │
  ▼
W(M) unknown
  │
  ▼
message schedule constraints
  │
  ▼
message search
```

The first is deterministic state inversion.

The second remains a cryptanalytic search problem.

---

# Davies-Meyer Context

For a fixed message schedule:

```text
C_W(H) = H + E_W(H)
```

componentwise modulo `2^32`.

The state:

```text
H_fix = E_W^-1(0^256)
```

satisfies:

```text
C_W(H_fix) = H_fix
```

Therefore a corresponding freestart construction can produce:

```text
H_fix --M--> H_fix --M--> H_fix --M--> ...
```

when the same message block and compatible chaining state are repeatedly
used.

This is an internal chaining-state loop in a freestart/chosen-IV setting.

It is not a collision for standard SHA-256 beginning from the FIPS IV.

---

# Compression vs Complete Hash

The fixed-point and state-inversion results concern the SHA-256 compression
transformation.

They should not be confused with the complete serialized SHA-256 hash
function, which also includes:

- message padding;
- encoded message length;
- processing of all message blocks;
- the standardized initial state.

An internal compression fixed point therefore does not automatically imply
that arbitrary serialized messages of different lengths produce the same
final SHA-256 digest.

---

# Differential-Cryptanalysis Context

The sliding-window representation may be useful for reduced-round
differential or constraint-based models because state shifts are implicit.

It does not, however, make modular addition XOR-linear.

In general:

```text
Δ⊕(x + y) != Δ⊕x + Δ⊕y
```

because carries remain part of the computation.

The same ARX and Boolean constraints remain present.

Thus:

```text
simpler state coordinates
        !=
simpler cryptographic primitive
```

---

# Publication-Ready Statement

The central mathematical result can be summarized as:

> For every fixed sequence of 64 SHA-256 round words, the 64-round SHA-256
> working-state transformation is a permutation of the 256-bit state space.
> Each individual round is invertible by algebraically recovering the shifted
> registers, `T1`, `T2`, and the remaining input registers. The sliding-window
> representation provides an explicit coordinate form of this inverse.
> Consequently, for any target working state `S`, the unique chaining state
> `H = E_W^-1(S)` can be computed in `O(R)` round operations, where `R = 64`
> for full SHA-256. In particular, every fixed message schedule has a unique
> Davies-Meyer freestart fixed point corresponding to target state `0^256`.
> This is inversion with respect to the chaining state under a known schedule
> and does not constitute efficient inversion with respect to the unknown
> message input at the standardized SHA-256 IV.

---

# Bottom Line

SHA256SW establishes a clean separation between **representation** and
**cryptographic security**.

```text
                    SHA-256

        ┌─────────────────────────────┐
        │ Same mathematical function  │
        └──────────────┬──────────────┘
                       │
             ┌─────────┴─────────┐
             │                   │
             ▼                   ▼
       Standard model       Sliding window
             │                   │
             └─────────┬─────────┘
                       │
                       ▼
               Exact equivalence
                       │
                       ▼
              Fixed W is invertible
                       │
                       ▼
               Exact state inverse
                       │
                       ▼
             Freestart fixed point
```

The crucial distinction remains:

```text
Fixed W
  │
  ▼
invert the working state
```

is not the same problem as:

```text
Fixed IV + unknown M
  │
  ▼
invert the message
```

The sliding-window inverse is therefore a structural and algebraic property
of the fixed-schedule SHA-256 working-state transformation.

The remaining research question is empirical:

```text
Does the sliding-window encoding
produce a measurable SAT/SMT advantage?
```

That is the purpose of the benchmark harness.

---

# License

This project is released under the MIT License.

See:

```text
LICENSE
```

for the complete license text.

---

# Citation

```bibtex
@misc{sha256sw2026,
  author = {SHA256SW Contributors},
  title  = {SHA256SW: Sliding-Window State Representation and
            Cryptanalytic Benchmark for SHA-256},
  year   = {2026},
  url    = {https://github.com/laserjobs/sha256sw}
}
```

---

# Related Documentation

- `THEORY.md` — mathematical derivations and exact inversion.
- `SECURITY_SCOPE.md` — security boundaries and interpretation.
- `BENCHMARKING.md` — benchmark design, controls, timeout handling, and
  reproducibility.
- `Makefile` — build, formal-verification, equivalence, and benchmark targets.

```text
SHA256SW
   │
   ├── portable C11 implementation
   │
   ├── standard/SW equivalence
   │
   ├── formal SMT verification
   │
   ├── algebraic fixed-schedule inverse
   │
   └── SAT/SMT representation benchmark
```

**The project changes the representation of SHA-256 state; it does not claim
to break SHA-256.**
