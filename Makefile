CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2

INCLUDES := -Iinclude

PYTHON ?= python3
SOLVER ?= z3

BIN_DIR := bin
TEST_BIN := $(BIN_DIR)/test_sha256sw

ROUNDS ?= 16 20 24 28 30
TRIALS ?= 5
TIMEOUT ?= 180

all: test


build:
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(INCLUDES) \
		src/sha256sw.c \
		tests/test_sha256sw.c \
		-o $(TEST_BIN)


test: build
	./$(TEST_BIN)


formal:
	$(PYTHON) formal/generate_smt_proofs.py
	@if command -v z3 >/dev/null 2>&1; then \
		set -e; \
		echo "Running formal SMT verification via Z3..."; \
		for proof in \
			formal/ch_equiv.smt2 \
			formal/full_64round_equiv.smt2 \
			formal/full_64round_inverse.smt2; do \
			echo "==> Checking $$proof"; \
			result="$$(z3 "$$proof")"; \
			printf '%s\n' "$$result"; \
			if [ "$$result" != "unsat" ]; then \
				echo "ERROR: $$proof did not prove UNSAT"; \
				exit 1; \
			fi; \
			echo "PASS: $$proof"; \
		done; \
		echo "ALL FORMAL CHECKS PASSED"; \
	else \
		echo "Z3 not found. Proofs generated in formal/"; \
	fi


benchmark:
	$(PYTHON) benchmark/sha256_representation_benchmark.py \
		$(SOLVER) \
		--rounds $(ROUNDS) \
		--trials $(TRIALS) \
		--timeout $(TIMEOUT)


benchmark-z3:
	$(MAKE) benchmark SOLVER=z3


benchmark-bitwuzla:
	$(MAKE) benchmark SOLVER=bitwuzla


benchmark-cvc5:
	$(MAKE) benchmark SOLVER=cvc5


clean:
	rm -rf $(BIN_DIR)
	rm -f *.o
	rm -f *.smt2
	rm -f formal/*.smt2
	rm -f *.json
	rm -f *.csv
	rm -f tmp_*.smt2
	rm -f gate0_*.smt2


.PHONY: all \
	build \
	test \
	formal \
	benchmark \
	benchmark-z3 \
	benchmark-bitwuzla \
	benchmark-cvc5 \
	clean
