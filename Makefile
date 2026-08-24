CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
INCLUDES = -Iinclude
PYTHON ?= python3

Z3 ?= z3
Z3_TIMEOUT ?= 300

.PHONY: all build test formal benchmark clean

all: test

build:
	@mkdir -p bin
	$(CC) $(CFLAGS) $(INCLUDES) src/sha256sw.c tests/test_sha256sw.c -o bin/test_sha256sw

test: build
	./bin/test_sha256sw

formal:
	$(PYTHON) formal/generate_smt_proofs.py
	@if command -v $(Z3) >/dev/null 2>&1; then \
		set -e; \
		echo "Z3 version:"; \
		$(Z3) -version; \
		echo "Running formal SMT verification via Z3..."; \
		for proof in \
			formal/ch_equiv.smt2 \
			formal/full_64round_equiv.smt2 \
			formal/full_64round_inverse.smt2; do \
			echo "==> Checking $$proof"; \
			result="$$(timeout $(Z3_TIMEOUT)s $(Z3) "$$proof" 2>&1)"; \
			status=$$?; \
			printf '%s\n' "$$result"; \
			if [ "$$status" -ne 0 ]; then \
				echo "ERROR: Z3 failed for $$proof (exit=$$status)"; \
				exit "$$status"; \
			fi; \
			if [ "$$result" != "unsat" ]; then \
				echo "ERROR: $$proof did not return UNSAT"; \
				exit 1; \
			fi; \
			echo "PASS: $$proof"; \
		done; \
		echo "ALL FORMAL CHECKS PASSED"; \
	else \
		echo "Z3 not found. Proofs generated in formal/"; \
		exit 1; \
	fi

benchmark:
	$(PYTHON) benchmark/sha256_representation_benchmark.py z3 --rounds 16 20 24 28 30 --trials 3 --timeout 120

clean:
	rm -rf bin *.o *.smt2 formal/*.smt2 *.json *.csv tmp_*.smt2 gate0_*.smt2
