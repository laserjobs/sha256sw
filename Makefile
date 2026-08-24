CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude
PYTHON ?= python3

all: test

build:
	@mkdir -p bin
	$(CC) $(CFLAGS) $(INCLUDES) src/sha256sw.c tests/test_sha256sw.c -o bin/test_sha256sw

test: build
	./bin/test_sha256sw

formal:
	$(PYTHON) formal/generate_smt_proofs.py
	@if command -v z3 >/dev/null 2>&1; then \
		echo "Z3 version:"; \
		z3 -version; \
		echo "==> Checking formal/ch_equiv.smt2"; \
		z3 formal/ch_equiv.smt2; \
		echo "==> Checking formal/full_64round_equiv.smt2"; \
		z3 formal/full_64round_equiv.smt2; \
		echo "==> Checking formal/full_64round_inverse.smt2"; \
		z3 formal/full_64round_inverse.smt2; \
	else \
		echo "Z3 not found. Proof artifacts generated in formal/"; \
	fi

benchmark:
	$(PYTHON) benchmark/sha256_representation_benchmark.py z3 \
		--rounds 16 20 24 28 30 \
		--trials 3 \
		--timeout 120

clean:
	rm -rf bin/ *.o *.smt2 formal/*.smt2 *.json *.csv tmp_*.smt2 gate0_*.smt2

.PHONY: all build test formal benchmark clean
