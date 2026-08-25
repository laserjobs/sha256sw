# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

SHA256SW is a portable C11 implementation and formal/solver benchmark study
of an alternative sliding-window representation of the SHA-256 working state.

The project has two distinct goals:

1. Prove and validate that the conventional eight-register and sliding-window
   formulations compute exactly the same SHA-256 state transition.
2. Measure whether the sliding-window representation changes SAT/SMT solver
   performance on reduced-round, reduced-width benchmark problems.

> **Central result:** For every fixed 64-word SHA-256 round schedule `W`, the
> 64-round working-state transformation `E_W` is a permutation of the 256-bit
> state space. The sliding-window representation provides an explicit inverse
> `E_W⁻¹`.
>
> This gives deterministic freestart fixed points for a known message schedule.
> It does **not** provide an inversion, collision, or preimage attack against
> standard SHA-256 with its fixed FIPS IV and unknown message.

The project therefore studies a representation and solver question, not a
claimed break of SHA-256.

---

## Central Security Boundary

The key distinction is:

```text
Known message schedule W
        │
        ▼
64-round working-state map E_W
        │
        ▼
E_W is a permutation
        │
        ▼
Exact state inverse E_W⁻¹
```

versus:

```text
Standard SHA-256
        │
        ▼
Fixed FIPS IV
        │
        ▼
Unknown message M
        │
        ▼
Unknown/constrained schedule W(M)
        │
        ▼
Message-search problem
```

SHA256SW directly establishes the first result.

It does **not** provide an efficient solution to the second problem.

In particular, the project does not claim:

- a collision attack on full SHA-256;
- a preimage attack on full SHA-256;
- a second-preimage attack;
- a practical standard-IV fixed point;
- a reduction in generic collision complexity;
- a reduction in generic preimage complexity;
- an efficient inversion of SHA-256 with respect to its unknown message.

See [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md) for the expanded security
discussion.

---

## Mathematical Summary

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

with all additions performed modulo `2^32`.

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

### Sliding-window coordinates

For round `i`, define:

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

The sliding-window representation does not change SHA-256. It changes the
coordinates used to represent the same state transition.

---

## Exact One-Round Inverse

Given the output state:

```text
(A', B', C', D', E', F', G', H')
```

the shifted registers are immediately recovered:

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

T1 = A' - T2

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

where subtraction is modulo `2^32`.

Thus every fixed-word SHA-256 round is invertible.

For a fixed schedule:

```text
W = (W[0], W[1], ..., W[63])
```

the complete transformation is:

```text
E_W = R_63 ∘ R_62 ∘ ... ∘ R_1 ∘ R_0
```

and is therefore a permutation of the 256-bit working-state space.

The inverse is obtained by applying the inverse rounds in reverse order:

```text
B_W = E_W⁻¹
```

For `R` rounds, the inverse requires:

```text
O(R)
```

round operations.

For full SHA-256:

```text
R = 64
```

See [`THEORY.md`](THEORY.md) for the complete algebraic derivation.

---

## Freestart Fixed Points

For a fixed message schedule `W`, the Davies-Meyer-style compression
transformation is:

```text
C_W(H) = H + E_W(H)  mod 2^32
```

componentwise.

A fixed point satisfies:

```text
C_W(H) = H
```

which is equivalent to:

```text
E_W(H) = 0^256
```

Because `E_W` is a permutation, there is exactly one such working state:

```text
H_fix = E_W⁻¹(0^256)
```

Therefore:

```text
E_W(H_fix) = 0^256
```

and:

```text
C_W(H_fix) = H_fix
```

This is a freestart/chaining-state construction for a known schedule.

It is **not** a standard-IV SHA-256 fixed point.

---

## Standard SHA-256 IV

The standardized SHA-256 initial state is:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

A standard-IV fixed point would require finding a message `M` satisfying:

```text
E_W(M)(IV_FIPS) = 0^256
```

Here the schedule `W(M)` is unknown before the message is found.

The fixed-schedule inverse therefore does not solve this problem.

The distinction is:

```text
Known W  -> recover H
```

versus:

```text
Fixed H  -> recover M
```

SHA256SW addresses the first problem.

---

## SHA-256 Functions

The Boolean functions are:

```text
Ch(x,y,z)  = (x & y) ^ (~x & z)

Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
```

The large-sigma functions are:

```text
Σ0(x) = ROTR^2(x)  ^ ROTR^13(x) ^ ROTR^22(x)

Σ1(x) = ROTR^6(x)  ^ ROTR^11(x) ^ ROTR^25(x)
```

The small-sigma functions used by the message schedule are:

```text
σ0(x) = ROTR^7(x)  ^ ROTR^18(x) ^ SHR^3(x)

σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
```

The message schedule is:

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

All additions are modulo `2^32`.

---

## Standard vs Sliding-Window Representation

The conventional representation explicitly contains the register-copy
constraints:

```text
B' = A
C' = B
D' = C

F' = E
G' = F
H' = G
```

The sliding-window representation encodes these relationships through
overlapping coordinates.

The benchmark therefore compares two representations of the same
mathematical function.

It does not remove:

- modular addition;
- addition carries;
- `Ch`;
- `Maj`;
- rotations;
- shifts;
- SHA-256 sigma functions;
- message-schedule expansion;
- the 64-round computation;
- the underlying Boolean/ARX structure.

The scientific question is whether a different constraint representation
changes solver behavior.

---

## Formal Verification

The repository contains formal bit-vector verification infrastructure under
[`formal/`](formal/).

The formal models cover relationships between:

- the standard representation;
- the sliding-window representation;
- SHA-256 Boolean functions;
- rotations and shifts;
- modular addition/subtraction;
- one-round equivalence;
- one-round inversion;
- reduced-round equivalence.

The formal verification complements the algebraic derivation:

```text
Algebraic proof
      │
      ▼
Mathematical property
      │
      ▼
Formal SMT model
      │
      ▼
Machine-checked encoding
```

The formal models validate the encoded construction, while the explicit
algebraic inverse supplies the mathematical justification for bijectivity.

Run:

```bash
make formal
```

---

## Implementation

The implementation is portable C11 and is intended for research,
verification, and benchmarking.

It provides:

- SHA-256 initialization;
- incremental update;
- finalization;
- direct compression;
- sliding-window state processing;
- big-endian message-word handling;
- standard SHA-256 padding;
- defensive argument checks;
- overflow-aware length handling.

The public interface is under:

```text
include/
```

and implementation sources are under:

```text
src/
```

The standard SHA-256 behavior is tested independently of the reduced-width
solver models.

---

## Verification Tests

Run the complete C test suite with:

```bash
make test
```

The test suite covers standard SHA-256 behavior including:

- empty input;
- `"abc"`;
- long/padding-boundary inputs;
- streaming/chunked updates;
- direct compression;
- state handling;
- defensive checks;
- length handling.

The repository also contains equivalence and formal verification targets.

A typical validation hierarchy is:

```text
C unit tests
     │
     ▼
Reference SHA-256 behavior
     │
     ▼
Standard/SW equivalence
     │
     ▼
Formal verification
     │
     ▼
Round-inverse validation
     │
     ▼
Solver benchmark
```

Correctness should be established before solver performance is interpreted.

---

## Benchmark

SHA256SW includes a SAT/SMT benchmark comparing:

```text
Standard explicit-register encoding
```

against:

```text
Sliding-window encoding
```

on reduced-round problems.

The benchmark supports:

- representation-equivalence experiments;
- reduced-round collision experiments;
- reduced-width experiments;
- independent witness verification.

### Primary solver metric

The primary metric is:

```text
S_R =
median(T_Std-Explicit,R)
------------------------
median(T_SW-Explicit,R)
```

Interpretation:

```text
S_R > 1    SW is faster

S_R ~= 1   Little measurable difference

S_R < 1    Standard representation is faster
```

This is a solver-performance metric, not a cryptographic-security metric.

For example:

```text
S_R = 3
```

means that, under the specified benchmark conditions, the SW encoding had
approximately one-third the median runtime of the standard encoding.

It does **not** mean that SHA-256 is three times weaker.

---

## Benchmark Status

The repository provides infrastructure for measuring representation-level
solver performance.

The existence of a benchmark harness does not by itself establish a solver
speedup.

Performance claims should be based on recorded experiments including:

- repository commit;
- solver name;
- solver version;
- CPU model;
- operating system;
- compiler/runtime;
- word width;
- round count;
- number of trials;
- timeout;
- solved count;
- timeout count;
- median runtime;
- runtime dispersion.

See [`BENCHMARKING.md`](BENCHMARKING.md) for the recommended methodology and
reporting conventions.

---

## Reduced-Round Collision Experiments

The collision benchmark studies reduced-round instances of the form:

```text
M1 != M2
```

such that:

```text
H_R(IV,M1) = H_R(IV,M2)
```

for a reduced number of rounds `R`.

These experiments are benchmark controls and solver workloads.

They are **not attacks on full 64-round SHA-256**.

### Reduced-width experiments

The benchmark can use parameterized word widths such as:

```text
n = 4
n = 6
n = 8
n = 12
n = 16
n = 32
```

Reduced-width experiments are parameterized ARX models used for solver,
regression, and scaling experiments.

They are not equivalent to the 32-bit-word SHA-256 compression function and
should not be interpreted as reduced security estimates for SHA-256.

---

## Benchmark Controls

The benchmark should be understood through several controls.

### Known small collision

A small-width collision can provide a deterministic positive control.

For example, with:

```text
R = 9
n = 4
```

there are:

```text
9 * 4 = 36
```

input bits and:

```text
8 * 4 = 32
```

output bits.

The input space is therefore larger than the output space, guaranteeing that
a collision exists by the pigeonhole principle.

A representative verified collision is:

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
[0x1, 0xa, 0x6, 0x3, 0xa, 0xe, 0xf, 0x2]

H_9(IV4,M2)
=
[0x1, 0xa, 0x6, 0x3, 0xa, 0xe, 0xf, 0x2]
```

This is an ordinary finite-domain collision in a parameterized reduced-width
model.

It is **not** a collision for full SHA-256.

### Inactive-word control

For:

```text
R = 15
```

the compression rounds consume:

```text
W[0], ..., W[14]
```

Changing:

```text
W[15]
```

must therefore leave the 15-round working-state output unchanged.

This provides a useful boundary test for benchmark implementations and
message-word accounting.

---

## Timeout Handling

Solver runtimes can be right-censored by a timeout.

A timeout is therefore not equivalent to a zero runtime and should not be
silently discarded.

When timeout censoring prevents a meaningful ordinary median estimate, report
a bound rather than a fabricated finite runtime.

For example:

```text
median > 120 s
```

is preferable to treating every timeout as exactly:

```text
120 s
```

See [`BENCHMARKING.md`](BENCHMARKING.md) for the complete timeout and
reporting methodology.

---

## Why Median Runtime?

SAT/SMT runtime distributions can be heavy-tailed.

A small number of unusually difficult instances can dominate an arithmetic
mean.

The benchmark therefore uses the median as the primary summary statistic and
should report it alongside:

- quartiles;
- solved/timeout counts;
- individual trial results;
- timeout bounds.

A solver-performance claim should not be based on one exceptionally easy or
difficult instance.

---

## No Causal Claim About Solver Internals

A wall-clock benchmark can establish a performance difference.

It cannot, by itself, establish the precise internal cause.

For example:

```text
SW faster than Standard
```

does not prove that the speedup specifically results from:

- fewer conflict clauses;
- fewer propagations;
- improved branching;
- reduced graph complexity;
- reduced memory traffic.

Such claims require dedicated solver instrumentation.

The primary result should therefore be described as an empirical
representation-level solver comparison.

---

## Recommended Quickstart

Start with correctness and formal validation before running difficult solver
instances.

### 1. Build and run tests

```bash
make test
```

### 2. Run formal verification

```bash
make formal
```

### 3. Run the project gate

```bash
make gate
```

### 4. Run representation equivalence checks

```bash
make equiv
```

### 5. Run the benchmark

For the benchmark methodology, controls, width/round ladder, timeout
handling, and reproducibility requirements, see
[`BENCHMARKING.md`](BENCHMARKING.md).

The benchmark should be started with small, known-good controls before
attempting longer collision searches.

If running a specific benchmark manually, record the repository revision:

```bash
git rev-parse HEAD
```

and record the exact benchmark command.

---

## Repository Layout

The repository is organized approximately as follows:

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
├── README.md
├── SECURITY_SCOPE.md
└── THEORY.md
```

The repository contains the C implementation, tests, formal-model generation,
benchmark harness, theory documentation, security-scope documentation, and
benchmarking methodology.

---

## Verification Hierarchy

The recommended verification workflow is:

```text
1. C unit tests
       │
       ▼
2. Independent/reference behavior
       │
       ▼
3. Standard/SW equivalence
       │
       ▼
4. Algebraic round-inverse derivation
       │
       ▼
5. Randomized round-trip validation
       │
       ▼
6. Reduced-round solver benchmarks
```

Correctness should be established before performance is measured.

---

## Algebraic Proof vs Empirical Validation

The distinction between proof and experiment is important.

The following is an algebraic result:

```text
Each fixed-word SHA-256 round is invertible.
```

Therefore:

```text
The composition of fixed-word rounds is invertible.
```

The following are empirical validations:

```text
Randomized forward/backward round trips pass.
```

and:

```text
Standard and SW implementations agree on tested instances.
```

Experiments provide evidence that the implementation corresponds to the
mathematical construction, but randomized testing is not itself the proof of
bijectivity.

---

## Formal Equivalence vs Algebraic Bijection

These are related but distinct properties.

### Equivalence

The standard and sliding-window models compute the same state transition.

### Bijection

For a fixed schedule, that transition has a unique inverse with respect to
the working-state input.

The project therefore establishes two complementary facts:

```text
Standard model == SW model
```

and:

```text
Fixed-schedule state transformation is bijective
```

The first validates the representation.

The second establishes the state-inversion property.

---

## Freestart Fixed-Point Construction

For a chosen message block `M`:

```text
1. Expand M into W[0..63].
2. Choose target S = 0^256.
3. Apply B_W to S.
4. Obtain H_fix.
5. Verify E_W(H_fix) = 0^256.
6. Verify C_W(H_fix) = H_fix.
```

Conceptually:

```text
M
│
▼
W[0..63]
│
▼
B_W(0^256)
│
▼
H_fix
│
├───────────────┐
│               │
▼               ▼
E_W(H_fix)      C_W(H_fix)
│               │
▼               ▼
0^256           H_fix
```

The construction is deterministic once `M` is fixed.

---

## Repeated Freestart Blocks

If a construction allows the chaining state to be selected as:

```text
H_fix
```

and the corresponding message block is:

```text
M
```

then:

```text
C_M(H_fix) = H_fix
```

and consequently:

```text
H_fix --M--> H_fix --M--> H_fix --M--> ...
```

This is an internal chaining-state loop.

It is a property of a **freestart or chosen-IV setting**.

It is not a collision for standard SHA-256 at its fixed FIPS IV.

---

## Standard Hashing and Padding

The internal compression transformation should not be confused with the
complete SHA-256 hash function.

Standard SHA-256 applies Merkle-Damgård-style processing with padding and an
encoded message length.

Therefore an internal fixed point does not automatically imply that arbitrary
serialized messages of different lengths have the same final SHA-256 digest.

The fixed-point result concerns the selected compression-state transition.

---

## Length-Extension Context

SHA-256, as a Merkle-Damgård hash, has the conventional length-extension
property when a raw hash is incorrectly used as a MAC.

That property is separate from the freestart fixed-point construction.

The distinction is:

```text
Length extension
    =
known chaining state + additional valid blocks
```

whereas:

```text
Freestart fixed point
    =
choose a message block and construct a compatible chaining state
```

The sliding-window inverse addresses the latter fixed-schedule state problem.

It does not remove or create the standard Merkle-Damgård length-extension
property.

---

## Differential-Cryptanalysis Context

The sliding-window representation can also be useful when constructing
reduced-round differential models because the state shifts are represented
implicitly.

However, the representation does not remove the fundamental difficulty of
SHA-256 differential analysis.

In particular, modular addition is not linear with respect to XOR difference:

```text
Δ⊕(x + y) != Δ⊕x + Δ⊕y
```

in general.

Carries can propagate through multiple bit positions, and the Boolean and
ARX operations continue to impose the same constraints as in the conventional
representation.

Therefore:

```text
Different representation
        !=
Different cryptographic primitive
```

and:

```text
Simpler state coordinates
        !=
Elimination of ARX difficulty
```

---

## What the Sliding Window Removes

The SW formulation removes the need to represent the six direct register
copies explicitly at every round:

```text
B' = A
C' = B
D' = C

F' = E
G' = F
H' = G
```

These relationships are encoded by the overlapping windows.

This can change the constraint graph presented to a SAT/SMT solver.

---

## What the Sliding Window Does Not Remove

The SW formulation does not remove:

- modular addition;
- addition carries;
- `Ch`;
- `Maj`;
- rotations;
- logical shifts;
- SHA-256 sigma functions;
- SHA-256 message-schedule expansion;
- the 64-round computation;
- the 512-bit message block;
- the underlying ARX/Boolean structure.

The benchmark therefore isolates a representation-level question rather than
changing the cryptographic algorithm.

---

## Security Boundary

The central security distinction is:

```text
Known W
  │
  ▼
Invert E_W with respect to H
  │
  ▼
Deterministic state inversion
```

versus:

```text
Fixed IV
  │
  ▼
Unknown M
  │
  ▼
Unknown W(M)
  │
  ▼
Message-search problem
```

The sliding-window inverse operates only in the first regime.

It does not provide an efficient inversion algorithm for the second.

See [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md) for the complete discussion.

---

## Collision and Preimage Complexity

For an ideal 256-bit hash, conventional generic security scales are often
described approximately as:

```text
Collision search: 2^128
Preimage search:  2^256
```

These are generic security scales, not theorems that every concrete attack
must require exactly those numbers.

SHA256SW does not provide an attack that reduces either generic scale for
standard SHA-256.

The fixed-schedule state inverse is a different problem because the message
schedule is already supplied.

---

## Security Claims

### Established by the construction

For a fixed sequence `W[0..63]`:

- each SHA-256 round is invertible;
- the 64-round working-state transformation is a permutation;
- every target working state has a unique state preimage;
- the sliding-window backward operator is the exact inverse;
- the Davies-Meyer freestart fixed point exists and is unique.

### Not established by this project

The project does not establish:

- a full-round SHA-256 collision attack;
- a full-round SHA-256 preimage attack;
- a second-preimage attack;
- a standard-IV fixed point;
- a reduction in generic collision complexity;
- a reduction in generic preimage complexity.

---

## Benchmark Methodology

A meaningful solver comparison should record:

- solver name;
- exact solver version;
- CPU model;
- available cores;
- RAM;
- operating system;
- compiler/runtime versions;
- repository commit;
- round count;
- word size;
- number of trials;
- per-instance timeout;
- solved count;
- timeout count;
- median runtime;
- runtime dispersion.

Timeouts are right-censored observations and should be reported explicitly.

See [`BENCHMARKING.md`](BENCHMARKING.md) for the full methodology, controls,
benchmark ladder, and reproducibility requirements.

---

## Future Research

Potential follow-up experiments include:

- larger SAT/SMT solver comparisons;
- Z3;
- CVC5;
- Bitwuzla;
- Yices2;
- direct CNF/SAT encodings;
- clause-count analysis;
- propagation-count analysis;
- solver-internal instrumentation;
- branching-heuristic analysis;
- memory-use measurements;
- MILP differential-trail models;
- message-modification constraint models;
- larger reduced-round widths;
- hardware implementation comparisons.

The most important empirical question is whether the reduction in explicit
register-copy constraints produces a reproducible solver advantage.

---

## Limitations

The project has several important limitations.

### Reduced rounds

Reduced-round results cannot be extrapolated directly to full 64-round
SHA-256 security.

### Reduced widths

Experiments with `n < 32` are parameterized ARX models and are not equivalent
to real 32-bit SHA-256.

### Fixed schedules

The state inverse assumes that the complete schedule is known.

### Solver dependence

A representation that helps one solver may not help another.

### Hardware dependence

Wall-clock measurements depend on hardware, operating system, solver
version, and system load.

### Statistical limitations

Small trial counts can produce unstable runtime estimates.

---

## Publication-Ready Mathematical Statement

> For every fixed sequence of 64 SHA-256 round words, the 64-round SHA-256
> working-state transformation is a permutation of the 256-bit state space.
> Each individual round is invertible by algebraically recovering the six
> shifted registers followed by `T1`, `T2`, and the remaining input registers.
> The sliding-window representation provides an explicit coordinate form of
> this inverse. Consequently, for any target working state `S`, the unique
> chaining state `H = E_W⁻¹(S)` can be computed in `O(R)` round operations,
> where `R = 64` for full SHA-256. In particular, every fixed message schedule
> has a unique Davies-Meyer freestart fixed point corresponding to target
> state `0^256`. This is inversion with respect to the chaining state under a
> known schedule and does not constitute efficient inversion with respect to
> the unknown message input at the standardized SHA-256 IV.

---

## Final Mathematical Summary

For fixed:

```text
W = (W[0], ..., W[63])
```

each round is invertible:

```text
R_i⁻¹ exists
```

therefore:

```text
E_W = R_63 ∘ ... ∘ R_0
```

is invertible.

The sliding-window backward operator is:

```text
B_W = E_W⁻¹
```

and therefore:

```text
B_W(E_W(H)) = H
```

and:

```text
E_W(B_W(S)) = S
```

for all valid working states `H` and target states `S`.

Setting:

```text
S = 0^256
```

gives:

```text
H_fix = B_W(0^256)
```

and therefore:

```text
E_W(H_fix) = 0^256
```

so the Davies-Meyer compression satisfies:

```text
C_W(H_fix) = H_fix
```

under the corresponding fixed message schedule.

The essential boundary is:

```text
+------------------------------------------------------+
| FIXED MESSAGE SCHEDULE                               |
|                                                      |
| W known                                              |
|      ↓                                               |
| E_W is a permutation                                 |
|      ↓                                               |
| E_W⁻¹ is explicit                                    |
|      ↓                                               |
| State inversion is deterministic in O(R) operations |
+------------------------------------------------------+
```

versus:

```text
+------------------------------------------------------+
| STANDARD SHA-256 MESSAGE SEARCH                      |
|                                                      |
| IV fixed                                             |
|      ↓                                               |
| M unknown                                            |
|      ↓                                               |
| W(M) unknown/constrained                             |
|      ↓                                               |
| Message search remains the hard problem             |
+------------------------------------------------------+
```

---

## Bottom Line

The project establishes a clean separation between representation and
cryptographic security:

```text
                         SHA-256

             ┌─────────────────────────┐
             │ Same mathematical       │
             │ state transition        │
             └────────────┬────────────┘
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
                   Fixed W is
                    invertible
                          │
                          ▼
                   Exact state
                     inverse
                          │
                          ▼
                Freestart fixed point
```

The crucial cryptographic boundary remains:

```text
Fixed W  ->  invert the state
```

is not the same problem as:

```text
Fixed IV + unknown M  ->  invert the message
```

Therefore the sliding-window inverse is a structural and algebraic property
of the fixed-schedule SHA-256 working-state transformation, not a break of
standard SHA-256.

The remaining experimental question is empirical:

```text
Does the sliding-window encoding
produce a measurable SAT/SMT advantage?
```

That is what the benchmark harness is designed to measure.

---

## License

This project is released under the MIT License.

See [`LICENSE`](LICENSE) for the complete license text.

---

## Citation

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

## Related Documentation

- [`THEORY.md`](THEORY.md) — mathematical derivations and theoretical details.
- [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md) — security boundaries and
  interpretation of the cryptographic results.
- [`BENCHMARKING.md`](BENCHMARKING.md) — benchmark methodology,
  controls, reproducibility, and reporting conventions.
- [`LICENSE`](LICENSE) — MIT License.

---

## One-Line Summary

> **SHA256SW is an exact alternative representation of SHA-256 whose
> fixed-schedule 64-round working-state transformation is algebraically
> invertible, enabling deterministic freestart fixed-point construction
> without providing an inversion or collision attack against the unknown
> message input of standard SHA-256.**
