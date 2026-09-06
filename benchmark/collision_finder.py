#!/usr/bin/env python3
"""
SHA256SW collision finder.

Uses the existing SMT collision encodings from
sha256_representation_benchmark.py and returns the first
verified reduced-round collision it finds.

This is intended for reduced-round research experiments.
It is NOT a full SHA-256 collision attack.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Allow importing benchmark/sha256_representation_benchmark.py
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import sha256_representation_benchmark as bench


def parse_solver_values(stdout: str) -> dict[str, int]:
    """Parse Z3 get-value output for m1_w_* and m2_w_*."""
    values = bench.parse_witness(stdout)

    if values is None:
        raise RuntimeError(
            "Z3 reported SAT but no complete message witness was found."
        )

    return values


def words_from_witness(
    witness: dict[str, int],
    branch: int,
) -> list[int]:
    return [
        witness[f"m{branch}_w_{i}"]
        for i in range(16)
    ]


def format_words(words: list[int]) -> str:
    return " ".join(f"{x:08x}" for x in words)


def find_collision(
    rounds: int,
    solver: str,
    timeout: int,
    model: str,
    diff: dict[int, int],
    keep_smt: bool,
) -> int:
    if rounds < 1 or rounds > 64:
        raise ValueError("--rounds must be between 1 and 64")

    if model not in bench.COLLISION_BUILDERS:
        raise ValueError(
            f"Unknown model {model!r}. "
            f"Choose from: {', '.join(bench.COLLISION_BUILDERS)}"
        )

    print("=" * 72)
    print("SHA256SW COLLISION FINDER")
    print("=" * 72)
    print(f"Solver : {solver}")
    print(f"Rounds : {rounds}")
    print(f"Model  : {model}")
    print(f"Timeout: {timeout}s")
    print()

    # Build the exact same SMT model used by the repository benchmark.
    smt = bench.COLLISION_BUILDERS[model](rounds, diff)

    temp = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".smt2",
        prefix=f"sha256sw_collision_r{rounds}_",
        delete=False,
        encoding="utf-8",
    )

    filename = Path(temp.name)

    try:
        temp.write(smt)
        temp.close()

        if keep_smt:
            print(f"SMT file: {filename}")
        else:
            print(f"Generated SMT problem: {filename}")

        print()
        print("Searching...")

        started = time.perf_counter()

        try:
            proc = subprocess.run(
                [solver, str(filename)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            elapsed = time.perf_counter() - started
            print(f"\nTIMEOUT after {elapsed:.2f}s")
            return 2
        except OSError as exc:
            print(
                f"\nCould not execute solver {solver!r}: {exc}",
                file=sys.stderr,
            )
            return 3

        elapsed = time.perf_counter() - started

        status = bench.parse_status(
            proc.stdout,
            proc.stderr,
        )

        print(f"Status : {status}")
        print(f"Time   : {elapsed:.3f}s")

        if status != "sat":
            if proc.stderr.strip():
                print("\nSolver stderr:")
                print(proc.stderr)

            return 0 if status == "unsat" else 4

        witness = parse_solver_values(proc.stdout)

        m1 = words_from_witness(witness, 1)
        m2 = words_from_witness(witness, 2)

        print()
        print("Candidate collision:")
        print()
        print(f"M1 = {format_words(m1)}")
        print(f"M2 = {format_words(m2)}")

        # Independent verification using the repository's pure-Python
        # reduced-round implementation.
        h1 = bench.sha256_reduced_compress_py(
            bench.IV,
            m1,
            rounds,
        )

        h2 = bench.sha256_reduced_compress_py(
            bench.IV,
            m2,
            rounds,
        )

        verified = (
            m1 != m2
            and h1 == h2
        )

        print()
        print("Independent verification:")
        print(f"M1 != M2       : {m1 != m2}")
        print(
            "H(M1)           : "
            + " ".join(f"{x:08x}" for x in h1)
        )
        print(
            "H(M2)           : "
            + " ".join(f"{x:08x}" for x in h2)
        )
        print(f"Collision valid : {verified}")

        if not verified:
            print(
                "\nERROR: solver witness failed independent "
                "verification.",
                file=sys.stderr,
            )
            return 5

        print()
        print("[+] Collision verified.")

        return 0

    finally:
        if not keep_smt:
            try:
                filename.unlink()
            except FileNotFoundError:
                pass


def parse_diff(values: list[str] | None) -> dict[int, int]:
    """Parse INDEX:HEX differential constraints."""
    if not values:
        return {}

    result: dict[int, int] = {}

    for item in values:
        if ":" not in item:
            raise ValueError(
                f"Invalid --diff {item!r}; expected INDEX:HEX"
            )

        index_text, value_text = item.split(":", 1)

        try:
            index = int(index_text, 10)
            value = int(value_text, 16)
        except ValueError as exc:
            raise ValueError(
                f"Invalid --diff {item!r}; expected INDEX:HEX"
            ) from exc

        if not 0 <= index < 16:
            raise ValueError(
                f"Message index {index} must be in [0, 15]"
            )

        if not 0 <= value <= 0xFFFFFFFF:
            raise ValueError(
                f"Differential {value_text!r} is not 32-bit"
            )

        result[index] = value

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Find and independently verify a "
            "reduced-round SHA-256 collision using Z3."
        )
    )

    parser.add_argument(
        "--rounds",
        type=int,
        default=9,
        help="Number of SHA-256 rounds (default: 9)",
    )

    parser.add_argument(
        "--solver",
        default="z3",
        help="SMT solver executable (default: z3)",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Solver timeout in seconds (default: 120)",
    )

    parser.add_argument(
        "--model",
        choices=list(bench.COLLISION_BUILDERS),
        default="SW-Inline",
        help="SMT representation to use",
    )

    parser.add_argument(
        "--diff",
        nargs="+",
        metavar="INDEX:HEX",
        help=(
            "Optional XOR differential constraints, "
            "for example: 0:00000001 1:00000002"
        ),
    )

    parser.add_argument(
        "--keep-smt",
        action="store_true",
        help="Keep the generated .smt2 file",
    )

    args = parser.parse_args()

    try:
        diff = parse_diff(args.diff)

        return find_collision(
            rounds=args.rounds,
            solver=args.solver,
            timeout=args.timeout,
            model=args.model,
            diff=diff,
            keep_smt=args.keep_smt,
        )

    except ValueError as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
