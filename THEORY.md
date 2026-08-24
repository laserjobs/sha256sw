# SHA-256 Sliding-Window Theory

## 1. Scope

This document describes the algebraic relationship between the standard
8-register SHA-256 working state and the sliding-window (SW)
representation.

The results in this document concern the SHA-256 **working-state
transformation for a fixed expanded message schedule**.

They do not constitute an attack on the message input of standard
SHA-256.

---

## 2. Fixed-Schedule SHA-256 Transformation

Let

\[
W=(W_0,\ldots,W_{R-1})
\]

be a fixed sequence of 32-bit message words, and let

\[
H=(a_0,b_0,c_0,d_0,e_0,f_0,g_0,h_0)
\]

be the initial working state.

For each round, SHA-256 computes

\[
T_1 =
h+\Sigma_1(e)+\operatorname{Ch}(e,f,g)+K_i+W_i
\pmod {2^{32}}
\]

and

\[
T_2 =
\Sigma_0(a)+\operatorname{Maj}(a,b,c)
\pmod {2^{32}}.
\]

The state is then updated as

\[
(a',b',c',d',e',f',g',h')
=
(T_1+T_2,a,b,c,d+T_1,e,f,g).
\]

For a fixed schedule \(W\), denote the resulting \(R\)-round
working-state transformation by

\[
E_W.
\]

---

## 3. One-Round Invertibility

Suppose the output state of one round is

\[
(a',b',c',d',e',f',g',h').
\]

The shifted registers are immediately recovered:

\[
a=b',
\quad
b=c',
\quad
c=d',
\]

\[
e=f',
\quad
f=g',
\quad
g=h'.
\]

From the output relation

\[
a'=T_1+T_2,
\]

we obtain

\[
T_1=a'-T_2 \pmod {2^{32}},
\]

where

\[
T_2=
\Sigma_0(a)+\operatorname{Maj}(a,b,c).
\]

The remaining register is recovered from

\[
d'=d+T_1
\]

as

\[
d=d'-T_1 \pmod {2^{32}}.
\]

Finally, the input word \(h\) is obtained from

\[
T_1=
h+\Sigma_1(e)+\operatorname{Ch}(e,f,g)+K_i+W_i
\]

giving

\[
h =
T_1-\Sigma_1(e)
-\operatorname{Ch}(e,f,g)
-K_i-W_i
\pmod {2^{32}}.
\]

Thus every input register is uniquely determined by the output
registers when \(W_i\) is fixed.

Therefore every individual SHA-256 round is a bijection on the
256-bit working state.

---

## 4. Full-Round Bijection

The complete \(R\)-round transformation is the composition of the
individual round transformations:

\[
E_W = E_{W_{R-1}}\circ\cdots\circ E_{W_1}\circ E_{W_0}.
\]

Since each component is bijective, their composition is bijective.

Therefore

\[
E_W:
(\mathbb Z/2^{32}\mathbb Z)^8
\rightarrow
(\mathbb Z/2^{32}\mathbb Z)^8
\]

is a permutation.

Its inverse is obtained by applying the individual round inverses
in reverse order.

---

## 5. Sliding-Window Representation

The sliding-window representation stores the evolving state using two
sequences rather than explicitly maintaining all eight registers.

The register shifts imply relationships of the form

\[
a_{i+1}=b_i,
\]

together with the corresponding shifted relationships for the other
registers.

The SW backward recurrence is therefore a coordinate representation
of the same round inverse described above.

For a fixed schedule \(W\), denote this backward operator by

\[
B_W.
\]

The algebraic construction establishes

\[
B_W=E_W^{-1}.
\]

Consequently,

\[
B_W(E_W(H))=H
\]

and

\[
E_W(B_W(S))=S
\]

for every working state \(H\) and every target state \(S\).

---

## 6. Complexity

Backward inversion requires one inverse operation per round.

Therefore the asymptotic cost is

\[
O(R)
\]

round operations.

For standard SHA-256,

\[
R=64.
\]

Thus inversion of the chaining state for a known fixed message
schedule requires a fixed number of round operations.

The appropriate terminology is therefore **linear in the number of
rounds**, rather than asymptotically \(O(1)\).

---

## 7. Freestart Davies–Meyer Fixed Point

Davies–Meyer feedforward is

\[
C_M(H)=H+E_W(H)
\pmod {2^{256}}.
\]

Choose the target working state

\[
S=0^{256}.
\]

Because \(E_W\) is bijective, there exists exactly one state

\[
H_{\mathrm{fix}}=B_W(0^{256})
\]

such that

\[
E_W(H_{\mathrm{fix}})=0^{256}.
\]

Therefore

\[
C_M(H_{\mathrm{fix}})
=
H_{\mathrm{fix}}+0^{256}
=
H_{\mathrm{fix}}.
\]

Hence every fixed message schedule has a unique corresponding
freestart Davies–Meyer fixed point.

---

## 8. Important Security Boundary

The construction above assumes that the message schedule \(W\) is known.

It therefore solves the problem

\[
\text{given }W,\quad
\text{find }H\text{ such that }E_W(H)=S.
\]

This is fundamentally different from the standard SHA-256 problem

\[
\text{given }H_{\mathrm{FIPS}},
\quad
\text{find }M\text{ such that }
E_{W(M)}(H_{\mathrm{FIPS}})=S.
\]

In the second problem, the unknown is the message and therefore the
expanded schedule itself.

The SW inverse does not invert this message-dependent mapping.

---

## 9. Empirical Validation

Round-trip tests provide implementation validation of the algebraic
construction.

Useful tests include

\[
B_W(E_W(H))=H
\]

for random \(H,W\), and

\[
E_W(B_W(S))=S
\]

for random \(S,W\).

A large randomized test suite strengthens confidence in the
implementation but does not replace the algebraic proof of
invertibility.
