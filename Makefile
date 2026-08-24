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
	@echo "Generating formal SMT-LIB2 proof obligations..."
	@cd formal && $(PYTHON) generate_smt_proofs.py
	@if command -v z3 >/dev/null 2>&1; then \
		echo "Executing formal SMT verification via Z3..."; \
		for f in formal/ch_equiv.smt2 formal/full_64round_equiv.smt2 formal/full_64round_inverse.smt2; do \
			res=$$(z3 "$$f"); \
			echo "  $$f -> $$res"; \
			if [ "$$res" != "unsat" ]; then \
				echo "[ERROR] Formal proof failed for $$f (expected unsat, got $$res)"; \
				exit 1; \
			fi; \
		done; \
		echo "[PASS] All formal SMT proofs verified strictly (UNSAT)."; \
	else \
		echo "[!] Z3 not found in PATH. SMT-LIB2 proof obligations generated in formal/"; \
	fi

benchmark:
	$(PYTHON) benchmark/sha256_representation_benchmark.py z3 --rounds 16 20 24 28 30 --trials 3 --timeout 120

clean:
	rm -rf bin/ *.o *.smt2 formal/*.smt2 *.json *.csv tmp_*.smt2 gate0_*.smt2

.PHONY: all build test formal benchmark clean
