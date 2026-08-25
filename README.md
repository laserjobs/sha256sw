# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

SHA256SW is a portable C11 implementation and formal/solver benchmark study
of an alternative sliding-window representation of the SHA-256 working state.

The project has two distinct goals:

1. Prove and validate that the conventional eight-register and sliding-window
   formulations compute exactly the same SHA-256 state transition.
2. Measure whether the sliding-window representation changes SAT/SMT solver
   performance on reduced-round, reduced-width benchmark problems.

> **Central result:** For every fixed 64-word SHA-256 round schedule
> \(W=(W_0,\ldots,W_{63})\), the 64-round working-state transformation
> \(E_W\) is a permutation of the 256-bit state space. The sliding-window
> representation provides an explicit inverse \(E_W^{-1}\).
>
> This gives deterministic freestart fixed points for a **known message
> schedule**. It does **not** provide an inversion, collision, or preimage
> attack against standard SHA-256 with its fixed FIPS IV and unknown message.

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
Exact state inverse E_W^-1
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

For an expanded security discussion, see
[`SECURITY_SCOPE.md`](SECURITY_SCOPE.md).

---

## Mathematical Summary

SHA-256 maintains eight 32-bit working words:

```text
A B C D E F G H
```

For round \(i\), define:

```text
T1 = H
   + Σ1(E)
   + Ch(E,F,G)
   + K[i]
   + W[i]

T2 = Σ0(A)
   + Maj(A,B,C)
```

with all additions modulo \(2^{32}\).

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

For round \(i\), define:

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
   + Ch(b[i+3],b[i+2],b[i+1])
   + K[i]
   + W[i]

b[i+4] = a[i] + T1

T2 = Σ0(a[i+3])
   + Maj(a[i+3],a[i+2],a[i+1])

a[i+4] = T1 + T2
```

The sliding-window representation does not change SHA-256. It changes the
coordinates used to represent the same state transition.

### Exact one-round inverse

Given:

```text
(A',B',C',D',E',F',G',H')
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

H = T1
  - Σ1(E)
  - Ch(E,F,G)
  - K[i]
  - W[i]
```

where subtraction is modulo \(2^{32}\).

Thus every fixed-word SHA-256 round is invertible.

For a fixed schedule:

```text
W = (W[0],...,W[63])
```

the complete transformation

```text
E_W = R_63 ∘ ... ∘ R_1 ∘ R_0
```

is therefore a permutation of the 256-bit working-state space.

The inverse is obtained by applying the inverse rounds in reverse order:

```text
B_W = E_W^-1
```

For \(R\) rounds, the inverse requires:

```text
O(R)
```

round operations.

For full SHA-256, \(R=64\).

For the complete algebraic derivation, see
[`THEORY.md`](THEORY.md).

---

## Freestart Fixed Points

For a fixed message schedule \(W\), the Davies-Meyer-style compression
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

Because \(E_W\) is a permutation, there is exactly one such working state:

```text
H_fix = E_W^-1(0^256)
```

Therefore:

```text
E_W(H_fix) = 0^256
```

and:

```text
C_W(H_fix) = H_fix
```

This is a **freestart/chaining-state construction for a known schedule**.

It is not a standard-IV SHA-256 fixed point.

For the full distinction between freestart state inversion and unknown-message
inversion, see [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md).

---

## Standard SHA-256 IV

The standardized SHA-256 initial state is:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

A standard-IV fixed point would require finding a message \(M\) satisfying:

```text
E_W(M)(IV_FIPS) = 0^256
```

Here the schedule \(W(M)\) is unknown before the message is found.

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

All additions are modulo \(2^{32}\).

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

The formal models cover the relationships between:

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

The formal models are therefore validation of the encoded construction, while
the explicit algebraic inverse supplies the mathematical justification for
bijectivity.

Run:

```bash
make formal
```

---

## Implementation

The implementation is portable C11 and is intended for research,
verification, and benchmarking.

The implementation provides:

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
reference SHA-256 behavior
     │
     ▼
standard/SW equivalence
     │
     ▼
formal verification
     │
     ▼
round-inverse validation
     │
     ▼
solver benchmark
```

Correctness is established before solver performance is interpreted.

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

The benchmark supports representation-equivalence experiments and reduced-round
collision experiments.

The primary solver metric is:

\[
\mathcal{S}_R =
\frac{
\operatorname{median}(T_{\mathrm{Std\text{-}Explicit},R})
}{
\operatorname{median}(T_{\mathrm{SW\text{-}Explicit},R})
}.
\]

Interpretation:

```text
S_R > 1    SW is faster

S_R ~= 1   Little measurable difference

S_R < 1    Standard representation is faster
```

This is a **solver-performance metric**, not a cryptographic-security metric.

A measured value such as:

```text
S_R = 3
```

means that, under the specified benchmark conditions, the SW encoding had
approximately one-third the median runtime of the standard encoding.

It does not mean that SHA-256 is three times weaker.

---

## Benchmark Status

The repository provides infrastructure for measuring representation-level
solver performance.

A benchmark harness existing does not by itself establish a solver speedup.

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

The benchmark documentation defines the recommended methodology and reporting
conventions.

See [`BENCHMARKING.md`](BENCHMARKING.md).

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

for a reduced number of rounds \(R\).

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
```

```text
H_9(IV4,M2)
=
[0x1, 0xa, 0x6, 0x3, 0xa, 0xe, 0xf, 0x2]
```

This is an ordinary finite-domain collision in a parameterized reduced-width
model.

It is not a collision for full SHA-256.

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

This provides a useful boundary test for benchmark implementations and message
word accounting.

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

The complete timeout and reporting methodology is documented in
[`BENCHMARKING.md`](BENCHMARKING.md).

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

For the benchmark methodology, controls, width/round ladder, timeout handling,
and reproducibility requirements, see:

[`BENCHMARKING.md`](BENCHMARKING.md)

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
├── SECURITY_SCOPE.md
├── THEORY.md
└── README.md
```

The main components are:

```text
src/        C implementation
include/    public headers
tests/      correctness and regression tests
formal/     SMT/formal verification infrastructure
benchmark/  SAT/SMT benchmark harness
```

---

## Make Targets

The Makefile provides targets for common development and verification tasks,
including:

```text
make test
make formal
make gate
make equiv
make benchmark
make verify
make ci
make help
```

Use:

```bash
make help
```

for the current target list.

---

## Reproducibility

Benchmark results should always be tied to:

```text
repository commit
solver version
hardware
operating system
round count
word size
trial count
timeout
```

At minimum:

```bash
git rev-parse HEAD
```

should be recorded alongside the benchmark command.

A reproducible result should therefore look conceptually like:

```text
Commit:        <git revision>
Solver:        <solver and version>
CPU:           <CPU model>
OS:            <operating system>
Rounds:        <R>
Width:         <n>
Trials:        <N>
Timeout:       <seconds>
```

This prevents benchmark numbers from being detached from the environment in
which they were obtained.

---

## Scientific Interpretation

There are three useful possible outcomes.

### \( \mathcal{S}_R > 1 \)

The sliding-window encoding is faster under the tested conditions.

This supports the hypothesis that eliminating explicit register-copy
constraints can improve solver performance.

### \( \mathcal{S}_R \approx 1 \)

The representations perform similarly.

This suggests that preprocessing or other solver mechanisms may already
eliminate much of the apparent representation difference.

### \( \mathcal{S}_R < 1 \)

The conventional explicit-register representation is faster.

This demonstrates that the explicit representation can sometimes provide a
more favorable constraint structure.

All three outcomes are scientifically useful.

---

## What the Project Establishes

For a fixed sequence:

```text
W[0],...,W[63]
```

the project establishes the following mathematical property:

```text
Each fixed-word SHA-256 round is invertible.
```

Therefore:

```text
The composition of the 64 rounds is invertible.
```

Thus:

```text
E_W : {0,1}^256 -> {0,1}^256
```

is a permutation.

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

for every valid working state \(H\) and target state \(S\).

Setting:

```text
S = 0^256
```

gives the unique fixed-schedule freestart state:

```text
H_fix = B_W(0^256)
```

with:

```text
E_W(H_fix) = 0^256
```

and therefore:

```text
C_W(H_fix) = H_fix
```

This is the project's principal mathematical result.

---

## What the Project Does Not Establish

The fixed-schedule permutation property does **not** imply that standard
SHA-256 is efficiently invertible as a function of its message.

It does not establish:

- a full-round collision attack;
- a full-round preimage attack;
- a second-preimage attack;
- a standard-IV fixed point;
- a practical message inversion method;
- a reduction in generic collision complexity;
- a reduction in generic preimage complexity.

The usual generic security scales are approximately:

```text
Collision search: 2^128
Preimage search:  2^256
```

for an ideal 256-bit hash.

These are generic security scales, not claims that every concrete attack must
require exactly those numbers.

SHA256SW does not claim to reduce them.

For the complete security boundary, see
[`SECURITY_SCOPE.md`](SECURITY_SCOPE.md).

---

## Length Extension and Internal Fixed Points

The freestart fixed-point construction is separate from the conventional
Merkle-Damgård length-extension property of SHA-256.

Length extension concerns continued processing from a known chaining state
with valid additional blocks.

The freestart construction instead selects a compatible chaining state for a
known fixed schedule.

The sliding-window inverse addresses the latter state-inversion problem.

It does not remove or create the standard length-extension property.

---

## Differential-Cryptanalysis Context

The sliding-window representation can be useful for reduced-round
differential or solver models because repeated state shifts are represented
implicitly.

It does not, however, eliminate the underlying difficulty of SHA-256.

In particular, modular addition is not linear with respect to XOR differences:

```text
Δ⊕(x + y) != Δ⊕x + Δ⊕y
```

in general.

Carry propagation and the Boolean/ARX operations remain.

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

## Limitations

### Reduced rounds

Reduced-round results cannot be extrapolated directly to full 64-round
SHA-256 security.

### Reduced widths

Experiments with \(n<32\) are parameterized ARX models, not real 32-bit
SHA-256 instances.

### Fixed schedules

The state inverse assumes that the complete round schedule is already known.

### Solver dependence

A representation that helps one solver may not help another.

### Hardware dependence

Wall-clock measurements depend on hardware, operating system, solver version,
and system load.

### Statistical limitations

Small trial counts can produce unstable runtime estimates.

### Benchmark difficulty

Hard reduced-round collision instances may legitimately time out. A timeout
should be interpreted as a benchmark outcome, not automatically as evidence
of an implementation failure.

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

The central empirical question remains:

```text
Does the sliding-window encoding
produce a reproducible SAT/SMT advantage?
```

That question must be answered experimentally rather than inferred from the
existence of the alternative representation.

---

## Documentation

The project separates the detailed mathematical and experimental material
from this README.

### [`THEORY.md`](THEORY.md)

Mathematical derivations covering:

- SHA-256 state coordinates;
- sliding-window formulation;
- one-round inversion;
- full fixed-schedule bijection;
- inverse composition;
- freestart fixed points;
- complexity and algebraic interpretation.

### [`SECURITY_SCOPE.md`](SECURITY_SCOPE.md)

Security boundaries covering:

- fixed-schedule state inversion;
- standard-IV message inversion;
- freestart versus standard hashing;
- collision/preimage interpretation;
- reduced-width and reduced-round limitations;
- claims that are and are not supported by the project.

### [`BENCHMARKING.md`](BENCHMARKING.md)

Benchmark methodology covering:

- solver configurations;
- width/round ladders;
- controls;
- timeout handling;
- statistical reporting;
- reproducibility;
- interpretation of \(\mathcal{S}_R\).

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

## License

This project is released under the MIT License.

See:

```text
LICENSE
```

for the complete license text.

---

## Bottom Line

SHA256SW separates a mathematical property of a fixed-schedule compression
state transformation from the cryptographic problem of recovering an unknown
message.

The essential result is:

```text
Fixed W
   │
   ▼
E_W is a permutation
   │
   ▼
B_W = E_W^-1
   │
   ├───────────────┐
   ▼               ▼
arbitrary S       S = 0^256
   │               │
   ▼               ▼
unique H          H_fix
                   │
                   ▼
             Davies-Meyer
             freestart
             fixed point
```

The corresponding standard-message problem is different:

```text
Fixed IV
   │
   ▼
Unknown M
   │
   ▼
Unknown/constrained W(M)
   │
   ▼
Message search
```

The sliding-window inverse solves the first problem.

It does not solve the second.

The project's second major question is empirical:

```text
Does the sliding-window representation
make equivalent SAT/SMT problems easier to solve?
```

That question is measured by controlled reduced-round and reduced-width
experiments using the benchmark infrastructure.

The central scientific claim can therefore be summarized in one sentence:

> **SHA256SW provides an exact alternative representation of SHA-256 whose
> fixed-schedule 64-round working-state transformation is algebraically
> invertible, enabling deterministic freestart fixed-point construction for
> known schedules without providing an inversion or collision attack against
> the unknown message input of standard SHA-256.**
