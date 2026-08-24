# SHA256SW: Sliding-Window Representation & Cryptanalytic Benchmark

An endian-independent, portable C11 implementation of SHA-256 alongside
machine-checked SMT equivalence models and an automated SAT/SMT benchmark
comparing conventional eight-register and sliding-window state formulations.

SHA256SW studies whether a different representation of the SHA-256 working
state can make reduced-round SAT/SMT problems easier to solve, while preserving
the exact mathematical function of SHA-256.

The project also derives an exact algebraic inverse of the SHA-256 working-state
transformation when the complete message schedule is fixed and known.

> **Central result:** For every fixed sequence of 64 SHA-256 round words,
> the 64-round working-state transformation is a permutation of the 256-bit
> working state. The sliding-window representation provides an explicit inverse
> of that permutation.

This is a statement about **state inversion with a known message schedule**.
It is not an inversion attack on the message input of standard SHA-256.

---

## 1. Project Scope

SHA256SW has four primary goals:

1. Establish exact equivalence between the conventional eight-register
   SHA-256 formulation and the sliding-window formulation.
2. Derive and implement an exact backward inverse for the SHA-256
   working-state transformation when the round words are fixed.
3. Validate the equivalence and inversion properties using formal
   bit-vector models and independent implementations.
4. Measure whether eliminating explicit register-copy equations provides a
   measurable advantage to SAT/SMT solvers on reduced-round problems.

The benchmark therefore separates two questions:

```text
Mathematical equivalence
        │
        ▼
Are the two models exactly the same function?
        │
        ▼
Solver representation
        │
        ▼
Does one encoding solve equivalent problems faster?
```

A solver speedup is a statement about the **encoding and solver workload**.
It is not evidence that the underlying SHA-256 primitive has become weaker.

---

# 2. Mathematical Architecture

SHA-256 maintains eight 32-bit working words:

```text
A B C D E F G H
```

For round `i`, the standard formulation computes:

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

The sliding-window representation makes the repeated register shifts implicit.

---

# 3. Sliding-Window Coordinates

For round `i`, define two overlapping histories `a` and `b` by:

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

The SHA-256 round can then be written as:

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

where subtraction and addition are modulo `2^32`.

The sliding-window representation does not alter the SHA-256
round function. It changes the coordinates in which the state is represented.

---

# 4. Exact Equivalence

The standard and sliding-window formulations describe the same mathematical
state transition.

The correspondence is:

```text
Standard state                 Sliding-window state

A_i                            a[i+3]
B_i                            a[i+2]
C_i                            a[i+1]
D_i                            a[i]

E_i                            b[i+3]
F_i                            b[i+2]
G_i                            b[i+1]
H_i                            b[i]
```

Thus:

```text
Standard SHA-256 state
        │
        │ coordinate mapping
        ▼
Sliding-window state
        │
        │ same round function
        ▼
Standard SHA-256 state
```

No cryptographic operation is removed.

The Boolean functions, rotations, shifts, modular additions, message schedule,
round constants, and 64-round depth remain unchanged.

---

# 5. Standard SHA-256 Round Equations

For completeness, the conventional SHA-256 functions are:

```text
Ch(x,y,z)  = (x & y) ^ (~x & z)

Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
```

and:

```text
Σ0(x) = ROTR^2(x)  ^ ROTR^13(x) ^ ROTR^22(x)

Σ1(x) = ROTR^6(x)  ^ ROTR^11(x) ^ ROTR^25(x)

σ0(x) = ROTR^7(x)  ^ ROTR^18(x) ^ SHR^3(x)

σ1(x) = ROTR^17(x) ^ ROTR^19(x) ^ SHR^10(x)
```

All working-state arithmetic is performed modulo `2^32`.

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

---

# 6. Exact One-Round Inversion

The key algebraic observation is that a SHA-256 round is invertible when
`K[i]` and `W[i]` are known.

Suppose the output state is:

```text
(A', B', C', D', E', F', G', H')
```

From the shift equations:

```text
A = B'
B = C'
C = D'

E = F'
F = G'
G = H'
```

Six of the eight input registers are therefore immediately recovered.

Next compute:

```text
T2 = Σ0(A) + Maj(A,B,C)
```

Since:

```text
A' = T1 + T2
```

we obtain:

```text
T1 = A' - T2
```

Since:

```text
E' = D + T1
```

we obtain:

```text
D = E' - T1
```

Finally:

```text
T1 = H
   + Σ1(E)
   + Ch(E,F,G)
   + K[i]
   + W[i]
```

so:

```text
H = T1
  - Σ1(E)
  - Ch(E,F,G)
  - K[i]
  - W[i]
```

All subtraction is modulo `2^32`.

Thus every input register is uniquely determined by the output state and
the fixed round word.

---

# 7. Round-Level Bijection

Let:

```text
R_i : (Z/2^32Z)^8 -> (Z/2^32Z)^8
```

be SHA-256 round `i`, with `K[i]` and `W[i]` fixed.

The explicit reconstruction above provides `R_i^-1`.

Therefore:

```text
R_i
```

is a bijection of the 256-bit working-state space.

Importantly, this statement does not require the `W[i]` values to have been
generated by the SHA-256 message schedule.

They only need to be fixed values.

---

# 8. Full 64-Round Bijection

For a fixed sequence:

```text
W = (W[0], W[1], ..., W[63])
```

the complete working-state transformation is:

```text
E_W = R_63 o R_62 o ... o R_0
```

Since every round is invertible:

```text
E_W
```

is also invertible.

Therefore:

```text
+---------------------------------------------+
| For every fixed W[0..63], E_W is a         |
| permutation of the 256-bit working state.   |
+---------------------------------------------+
```

Equivalently:

```text
E_W : (Z/2^32Z)^8 -> (Z/2^32Z)^8
```

is a bijection.

---

# 9. Sliding-Window Backward Operator

The sliding-window implementation provides an explicit coordinate form of the
inverse transformation.

Let:

```text
B_W = E_W^-1
```

Then for every working state `H`:

```text
B_W(E_W(H)) = H
```

and for every target state `S`:

```text
E_W(B_W(S)) = S
```

Therefore:

```text
+--------------------------------------+
| B_W = E_W^-1                         |
+--------------------------------------+
```

This is a genuine two-sided inverse.

The randomized tests in the repository provide implementation validation;
the algebraic round inversion provides the mathematical justification.

---

# 10. Complexity of State Inversion

The inverse processes one round at a time.

For `R` rounds:

```text
Time = O(R)
```

For full SHA-256:

```text
R = 64
```

so the inverse consists of a fixed sequence of 64 inverse-round operations,
once the complete round schedule is known.

This should be described as:

> `O(R)` round operations for a fixed schedule.

It should **not** be described as `O(1)` asymptotic complexity.

For fixed full SHA-256, the number of rounds is of course a constant,
but the mathematically meaningful complexity parameter is the round count.

---

# 11. Arbitrary Target-State Preimages

Because `E_W` is a permutation, every target working state `S` has exactly
one preimage:

```text
H = B_W(S)
```

and therefore:

```text
E_W(H) = S
```

The target does not need to be zero.

The construction is:

```text
Known W[0..63]
       │
       ▼
Choose target state S
       │
       ▼
Apply B_W
       │
       ▼
Obtain unique H
       │
       ▼
E_W(H) = S
```

This is inversion with respect to the **chaining state**.

It is not inversion with respect to the message block.

---

# 12. Davies-Meyer Freestart Fixed Points

For a fixed message schedule, SHA-256's compression feed-forward can be
viewed as eight independent 32-bit additions:

```text
C_W(H)[j] = H[j] + E_W(H)[j]  mod 2^32
```

for:

```text
j = 0,...,7
```

A fixed point satisfies:

```text
C_W(H) = H
```

which requires:

```text
E_W(H) = 0^256
```

Since `E_W` is a bijection, there is exactly one such state:

```text
H_fix = B_W(0^256)
```

Therefore:

```text
E_W(H_fix) = 0^256
```

and:

```text
C_W(H_fix) = H_fix
```

Hence every fixed round schedule has a unique corresponding
Davies-Meyer freestart fixed point.

---

# 13. Freestart Fixed Point vs Standard SHA-256

This distinction is essential.

## Fixed-message / freestart problem

The message is known:

```text
M known
```

therefore:

```text
W(M) known
```

and we solve:

```text
E_W(H) = S
```

directly using:

```text
H = B_W(S)
```

For:

```text
S = 0^256
```

we obtain a freestart fixed point.

---

## Standard-IV message problem

The standard SHA-256 IV is fixed:

```text
H = IV_FIPS
```

and the message is unknown.

The corresponding problem is:

```text
Find M such that:

E_W(M)(IV_FIPS) = S
```

For a fixed point:

```text
E_W(M)(IV_FIPS) = 0^256
```

Now `W(M)` is itself unknown and constrained by the SHA-256 message
schedule.

The state inverse does not solve this problem.

The distinction is:

```text
Known W  -> recover H       = state inversion
Fixed H  -> recover M       = message inversion
```

SHA256SW directly addresses the first problem.

It does not provide an efficient algorithm for the second.

---

# 14. Standard SHA-256 IV

The standardized SHA-256 initial state is:

```text
6a09e667 bb67ae85 3c6ef372 a54ff53a
510e527f 9b05688c 1f83d9ab 5be0cd19
```

A standard-IV fixed point would require a message `M` satisfying:

```text
E_W(M)(IV_FIPS) = 0^256
```

The sliding-window inverse cannot simply be applied here because the
message schedule is not known before the message is found.

This is the fundamental boundary between the fixed-schedule state problem
and the unknown-message problem.

---

# 15. What This Result Does and Does Not Mean

The fixed-schedule permutation property is mathematically exact.

It does **not** imply that full SHA-256 can be inverted efficiently as a
function of its message input.

In particular, SHA256SW does not demonstrate:

* a collision attack on full 64-round SHA-256;
* a preimage attack on full SHA-256;
* a second-preimage attack on full SHA-256;
* a practical attack against the standardized SHA-256 IV;
* a reduction in the generic collision-search scale;
* a reduction in the generic preimage-search scale;
* a weakness in the SHA-256 message schedule;
* an inversion of SHA-256 with respect to the unknown message.

The correct boundary is:

```text
Fixed message schedule
        │
        ▼
Working-state permutation
        │
        ▼
Exact state inversion
```

versus:

```text
Fixed standard IV
        │
        ▼
Unknown message
        │
        ▼
Unknown message schedule
        │
        ▼
Message search problem
```

---

# 16. Message Schedule

SHA-256 starts with 16 message words:

```text
W[0], ..., W[15]
```

and expands them to 64 words.

For:

```text
16 <= i < 64
```

the expansion is:

```text
W[i] = σ1(W[i-2])
     + W[i-7]
     + σ0(W[i-15])
     + W[i-16]
     mod 2^32
```

When the message is known, this entire schedule is known.

When the message is unknown, the schedule introduces additional constraints
between the unknown message words and later round words.

The state inverse does not eliminate these message constraints.

---

# 17. Formal Verification

The repository contains SMT-LIB2 / bit-vector verification infrastructure
under `formal/`.

The purpose of the formal models is to machine-check the relationship between
the standard and sliding-window formulations.

The models use bit-vector operations corresponding to:

* 32-bit modular addition;
* modular subtraction;
* XOR;
* AND;
* NOT;
* rotations;
* logical shifts;
* `Ch`;
* `Maj`;
* SHA-256 `Sigma` functions;
* SHA-256 message-schedule functions.

The formal verification is complementary to the algebraic derivation:

```text
Algebraic derivation
        │
        ├── establishes the mathematical property
        │
        ▼
SMT model
        │
        └── checks the encoded equations
```

A machine-checked model should therefore be understood as implementation
validation, not as a replacement for the algebraic proof.

---

# 18. Empirical Round-Trip Validation

The implementation can validate the inverse using randomized states and
fixed schedules.

The principal identities are:

```text
B_W(E_W(H)) = H
```

and:

```text
E_W(B_W(S)) = S
```

for arbitrary states `H` and `S`.

Cross-model tests also compare the standard and sliding-window forward
implementations.

A representative randomized verification campaign uses 1,000 independent
trials and checks:

```text
Test 1:
Backward_SW(Forward_Std(H,W),W) == H

Test 2:
Backward_SW(Forward_SW(H,W),W) == H

Test 3:
Forward_Std(Backward_SW(S,W),W) == S
```

A passing randomized campaign is strong implementation evidence, but the
underlying bijection follows from the explicit algebraic inversion of each
round.

---

# 19. Independent Reference Verification

Reduced-round solver witnesses are independently checked rather than being
accepted solely because a solver reports `sat`.

The verification flow is:

```text
SAT/SMT witness
      │
      ▼
Extract M1 and M2
      │
      ▼
Check M1 != M2
      │
      ▼
Run independent reference implementation
      │
      ▼
Compute reduced-round H(M1)
and H(M2)
      │
      ▼
Compare resulting states
```

This guards against incorrectly encoded benchmark constraints producing
false positives.

---

# 20. Reduced-Round Collision Benchmark

The repository contains a benchmark harness for comparing conventional and
sliding-window representations on reduced-round collision instances.

The benchmark asks the solver to find:

```text
M1 != M2
```

such that:

```text
H_R(IV, M1) = H_R(IV, M2)
```

for a reduced number of rounds `R`.

These are experiments on the reduced-round compression function.

They should not be interpreted as attacks on full 64-round SHA-256.

---

# 21. Active-Word Collision Control

A particularly useful control is the small-width active-word collision.

For:

```text
R = 9
n = 4
```

nine 4-bit message words provide:

```text
9 * 4 = 36 input bits
```

while the eight-word output state provides:

```text
8 * 4 = 32 output bits
```

Therefore the input space is larger than the output space.

A collision must exist by the pigeonhole principle.

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

and:

```text
H_9(IV4,M2)
=
[0x1, 0xa, 0x6, 0x3, 0xa, 0xe, 0xf, 0x2]
```

Thus:

```text
H_9(IV4,M1) = H_9(IV4,M2)
```

This is an ordinary finite-domain collision and is used as a benchmark
control.

---

# 22. Inactive-Word Control

A complementary control verifies that the benchmark correctly handles
message words that are not consumed by the selected number of rounds.

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

therefore cannot affect the 15-round working-state output.

This produces a deliberately trivial collision:

```text
M1 != M2
```

while:

```text
H_15(IV,M1) = H_15(IV,M2)
```

because the differing word is outside the consumed round range.

This is an important negative/control condition: it verifies that the
benchmark distinguishes active message inputs from unread inputs.

---

# 23. Standard vs Sliding-Window Benchmark

The primary comparison is between two equivalent encodings.

## Standard formulation

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

The register-copy equations are explicit.

---

## Sliding-window formulation

The corresponding model uses:

```text
a[i+4] = T1 + T2
b[i+4] = a[i] + T1
```

with the surrounding overlapping windows providing the register relationships.

The six explicit register-copy equations do not need to be separately
introduced at each round.

The underlying SHA-256 computation remains identical.

---

# 24. Primary Solver Metric

The pre-registered primary metric is:

```text
S_R =
median(T_Std-Explicit,R)
--------------------------------
median(T_SW-Explicit,R)
```

where:

```text
Std-Explicit
```

is the standard eight-register representation with explicit register-copy
constraints, and:

```text
SW-Explicit
```

is the sliding-window representation.

Interpretation:

```text
S_R > 1    SW is faster

S_R ~= 1   Little measurable difference

S_R < 1    Standard representation is faster
```

The metric describes empirical solver performance under the specified
benchmark conditions.

It does not describe cryptographic security.

---

# 25. Benchmark Methodology

A meaningful solver comparison should record:

* solver name;
* exact solver version;
* CPU model;
* available cores;
* RAM;
* operating system;
* compiler/runtime versions;
* repository commit;
* round count;
* word size;
* number of trials;
* per-instance timeout;
* solved count;
* timeout count;
* median runtime;
* runtime dispersion.

The repository's benchmark harness is intended to make these experiments
reproducible from a particular repository state.

---

# 26. Timeout Handling

Solver runtimes can be right-censored by a timeout.

A timeout is therefore not equivalent to a runtime of zero and should not be
silently discarded.

The benchmark records timeout outcomes explicitly.

When the timeout rate is sufficiently high to prevent a meaningful ordinary
median estimate, the result should be reported as a bound rather than as a
fabricated finite runtime.

For example:

```text
median > 120 s
```

is preferable to pretending that a timed-out instance took exactly 120
seconds.

---

# 27. Why Median Runtime Is Used

SAT/SMT runtime distributions are often heavy-tailed.

A small number of difficult instances can dominate an arithmetic mean.

The median provides a more robust measure of typical solver behavior and
should be reported alongside:

* quartiles;
* solved/timeout counts;
* individual trial results;
* timeout bounds.

A benchmark claim should not be based on a single exceptionally easy or
exceptionally difficult instance.

---

# 28. Interpreting Solver Speedups

Suppose:

```text
S_R = 3
```

Then, under the stated benchmark conditions:

> The SW encoding has a median runtime approximately three times lower than
> the standard explicit encoding.

This does **not** mean:

```text
SHA-256 is three times weaker.
```

It means that the chosen solver solved that particular representation more
quickly.

Conversely:

```text
S_R ~= 1
```

would be an informative result: it would suggest that solver preprocessing,
propagation, or other internal mechanisms already eliminate much of the
representation-level overhead.

---

# 29. No Causal Claim About CDCL Internals

A wall-clock benchmark can establish a performance difference.

It cannot, by itself, establish the precise internal reason for that
difference.

For example, observing:

```text
SW faster than Standard
```

does not prove that the speedup is specifically caused by:

* fewer conflict clauses;
* reduced CDCL graph complexity;
* improved branching;
* fewer propagations;
* reduced memory traffic.

Those claims require dedicated solver instrumentation.

The repository therefore treats the primary result as an empirical
representation-level solver benchmark.

---

# 30. Benchmark Widths and Rounds

The benchmark supports parameterized reduced-width experiments.

Typical width values include:

```text
n = 4
n = 6
n = 8
n = 12
n = 16
n = 32
```

Small widths are useful for:

* regression testing;
* exhaustive experiments;
* rapid solver comparisons;
* algebraic debugging.

Larger widths provide increasingly realistic ARX behavior while remaining
tractable for reduced-round experiments.

Reduced-width experiments are not cryptographic SHA-256 instances. They are
members of a parameterized ARX model family.

---

# 31. Recommended Benchmark Ladder

A useful experimental ladder is:

```text
n = 4
  │
  ├── rapid regression and collision controls
  │
n = 6
  │
  ├── low-width solver baseline
  │
n = 8
  │
  ├── byte-oriented reduced model
  │
n = 12
  │
  ├── intermediate scaling
  │
n = 16
  │
  ├── deeper solver workload
  │
n = 32
  │
  └── full-width reduced-round experiments
```

Round counts should be selected according to the intended benchmark regime
and solver timeout budget.

---

# 32. Quickstart

Clone the repository and enter the project directory.

Build and run the C test suite:

```bash
make test
```

Run the formal verification target:

```bash
make formal
```

Run the representation benchmark, for example:

```bash
python3 benchmark/sha256_representation_benchmark.py \
    z3 \
    --rounds 16 20 24 28 30 \
    --trials 5 \
    --timeout 120
```

Record the repository revision before publishing benchmark results:

```bash
git rev-parse HEAD
```

---

# 33. Repository Structure

The current repository is organized approximately as follows:

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

The repository also contains the supporting C implementation, tests, formal
model generation, benchmark harness, theory documentation, and security
scope documentation.

---

# 34. Verification Hierarchy

The recommended verification workflow is:

```text
1. Unit tests
       │
       ▼
2. Independent reference implementation
       │
       ▼
3. Standard/SW equivalence
       │
       ▼
4. Algebraic round-inverse derivation
       │
       ▼
5. Randomized round-trip tests
       │
       ▼
6. Reduced-round solver benchmarks
```

Correctness should be established before performance is measured.

---

# 35. Algebraic Proof vs Empirical Validation

The distinction between proof and experiment is important.

The following is an algebraic result:

```text
Each fixed-word SHA-256 round is invertible.
```

Therefore:

```text
The composition of 64 fixed-word rounds is invertible.
```

The following are empirical validations:

```text
Randomized forward/backward round trips pass.
```

and:

```text
Standard and SW implementations agree on tested instances.
```

The experiments provide strong evidence that the implementation corresponds
to the mathematical construction, but the 1,000-trial result is not itself
the proof of bijectivity.

---

# 36. Formal Equivalence vs Algebraic Bijection

These are related but distinct properties.

## Equivalence

The standard and sliding-window models compute the same state transition.

## Bijection

For a fixed schedule, that transition has a unique inverse with respect to
the working-state input.

Therefore the project establishes two complementary facts:

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

# 37. Freestart Fixed-Point Construction

For a chosen message block `M`:

```text
1. Expand M into W[0..63].
2. Choose target S = 0^256.
3. Apply B_W to S.
4. Obtain H_fix.
5. Verify E_W(H_fix) = 0^256.
6. Verify C_W(H_fix) = H_fix.
```

The construction is deterministic once `M` is fixed.

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

---

# 38. Repeated Freestart Blocks

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

# 39. Standard Hashing and Padding

The internal compression transformation should not be confused with the
complete SHA-256 hash function.

Standard SHA-256 applies Merkle-Damgard-style processing with padding and a
final encoded message length.

Therefore an internal fixed point does not automatically imply that arbitrary
serialized messages of different lengths have the same final SHA-256 digest.

The fixed-point result concerns the selected compression-state transition.

---

# 40. Length Extension Context

SHA-256, as a Merkle-Damgard hash, is subject to the conventional length
extension property when a raw hash is incorrectly used as a MAC.

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

It does not remove or create the standard Merkle-Damgard length-extension
property.

---

# 41. Differential-Cryptanalysis Context

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

# 42. What the Sliding Window Removes

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

# 43. What the Sliding Window Does Not Remove

The SW formulation does not remove:

* modular addition;
* addition carries;
* `Ch`;
* `Maj`;
* rotations;
* logical shifts;
* SHA-256's `Sigma` functions;
* SHA-256's message-schedule expansion;
* the 64-round computation;
* the 512-bit message block;
* the underlying ARX/Boolean structure.

The benchmark therefore isolates a representation-level question rather than
changing the cryptographic algorithm.

---

# 44. Security Boundary

The central security distinction is:

```text
Known W
   │
   ▼
Invert E_W with respect to H
   │
   ▼
Easy / deterministic
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

---

# 45. Collision and Preimage Complexity

For an ideal 256-bit hash, the conventional generic security scales are often
described as approximately:

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

# 46. Security Claims

## Established by the construction

For a fixed sequence `W[0..63]`:

* each SHA-256 round is invertible;
* the 64-round working-state transformation is a permutation;
* every target working state has a unique state preimage;
* the sliding-window backward operator is the exact inverse;
* the Davies-Meyer freestart fixed point exists and is unique.

## Not established by this project

The project does not establish:

* a full-round SHA-256 collision attack;
* a full-round SHA-256 preimage attack;
* a second-preimage attack;
* a standard-IV fixed point;
* a reduction in generic collision complexity;
* a reduction in generic preimage complexity.

---

# 47. Benchmark Controls

The benchmark suite uses several useful controls.

## Positive control

A known valid reduced-round collision verifies that the solver can find
a genuine collision.

## Negative / boundary control

For sufficiently small round counts, the active message input/output
dimensions can establish expected satisfiability or unsatisfiability
boundaries.

## Inactive-word control

Changing an unconsumed message word must not change the reduced-round output.

## Independent verifier

Every reported collision should be checked by an independent implementation.

---

# 48. Expected Solver Outcomes

There are three useful experimental outcomes.

### Outcome A: `S_R > 1`

The SW representation is faster under the tested conditions.

This would support the hypothesis that removing explicit register-copy
constraints provides a practical solver advantage.

### Outcome B: `S_R ~= 1`

The representations perform similarly.

This would suggest that solver preprocessing or other internal mechanisms
already neutralize much of the representation difference.

### Outcome C: `S_R < 1`

The standard representation is faster.

This would demonstrate that the explicit-register formulation can sometimes
provide a more favorable constraint structure for the solver.

All three outcomes are scientifically useful.

---

# 49. Reproducibility

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

A minimal reproducibility record is:

```bash
git rev-parse HEAD
```

followed by the benchmark command.

For example:

```bash
python3 benchmark/sha256_representation_benchmark.py \
    z3 \
    --rounds 16 20 24 28 30 \
    --trials 5 \
    --timeout 120
```

The exact command line and commit should accompany published timing results.

---

# 50. Limitations

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

Wall-clock measurements depend on hardware, operating system, solver version,
and system load.

### Statistical limitations

Small trial counts can produce unstable runtime estimates.

---

# 51. Future Research

Potential follow-up experiments include:

* larger SAT/SMT solver comparisons;
* Z3;
* CVC5;
* Bitwuzla;
* Yices2;
* direct CNF/SAT encodings;
* clause-count analysis;
* propagation-count analysis;
* solver-internal instrumentation;
* branching-heuristic analysis;
* memory-use measurements;
* MILP differential-trail models;
* message-modification constraint models;
* larger reduced-round widths;
* hardware implementation comparisons.

The most important next empirical question is whether the reduction in
explicit register-copy constraints produces a reproducible solver advantage.

---

# 52. Publication-Ready Mathematical Statement

The central mathematical result can be stated as follows:

> For every fixed sequence of 64 SHA-256 round words, the 64-round SHA-256
> working-state transformation is a permutation of the 256-bit state space.
> Each individual round is invertible by algebraically recovering the six
> shifted registers followed by `T1`, `T2`, and the remaining input registers.
> The sliding-window representation provides an explicit coordinate form of
> this inverse. Consequently, for any target working state `S`, the unique
> chaining state `H = E_W^{-1}(S)` can be computed in `O(R)` round operations,
> where `R = 64` for full SHA-256. In particular, every fixed message schedule
> has a unique Davies-Meyer freestart fixed point corresponding to target
> state `0^256`. This is inversion with respect to the chaining state under a
> known schedule and does not constitute efficient inversion with respect to
> the unknown message input at the standardized SHA-256 IV.

---

# 53. Final Mathematical Summary

For fixed:

```text
W = (W[0],...,W[63])
```

each round is invertible:

```text
R_i^-1 exists
```

therefore:

```text
E_W = R_63 o ... o R_0
```

is invertible.

The sliding-window backward operator is:

```text
B_W = E_W^-1
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

The essential boundary is therefore:

```text
+------------------------------------------------------+
| FIXED MESSAGE SCHEDULE                               |
|                                                      |
| W known                                              |
|      ↓                                               |
| E_W is a permutation                                  |
|      ↓                                               |
| E_W^-1 is explicit                                    |
|      ↓                                               |
| State inversion is deterministic in O(R) operations |
+------------------------------------------------------+

                         ≠

+------------------------------------------------------+
| STANDARD SHA-256 MESSAGE SEARCH                      |
|                                                      |
| IV fixed                                             |
|      ↓                                               |
| M unknown                                            |
|      ↓                                               |
| W(M) unknown/constrained                              |
|      ↓                                               |
| Message search remains the hard problem              |
+------------------------------------------------------+
```

---

# 54. One-Line Summary

> **SHA256SW is an exact alternative representation of SHA-256 whose
> fixed-schedule 64-round working-state transformation is algebraically
> invertible, enabling deterministic freestart fixed-point construction
> without providing an inversion or collision attack against the unknown
> message input of standard SHA-256.**

---

# 55. License

This project is released under the MIT License.

See:

```text
LICENSE
```

for the complete license text.

---

# 56. Citation

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

# 57. Related Documentation

The repository also contains:

```text
THEORY.md
```

for mathematical derivations and theoretical details;

```text
BENCHMARKING.md
```

for benchmark methodology;

```text
SECURITY_SCOPE.md
```

for security boundaries and interpretation of the cryptographic results.

---

# 58. Bottom Line

The project establishes a clean separation between representation and
cryptographic security:

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

The crucial cryptographic boundary remains:

```text
Fixed W  -> invert the state
```

is not the same problem as:

```text
Fixed IV + unknown M -> invert the message
```

Therefore the sliding-window inverse is a structural and algebraic property
of the fixed-schedule SHA-256 working-state transformation, not a break of
standard SHA-256.

```text
                FIXED W
                  │
                  ▼
          E_W is a permutation
                  │
                  ▼
           B_W = E_W^-1
                  │
          ┌───────┴───────┐
          ▼               ▼
      arbitrary S       S = 0
          │               │
          ▼               ▼
    unique state H     H_fix
                          │
                          ▼
                 Davies-Meyer
                  freestart
                  fixed point
```

The remaining experimental question is empirical:

```text
Does the sliding-window encoding
produce a measurable SAT/SMT advantage?
```

That question is what the benchmark harness is designed to answer.
