.PHONY: all test formal clean

PYTHON ?= python3
CC ?= cc

CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

all: test formal

test:
	$(MAKE) -C tests test

formal:
	$(PYTHON) formal/generate_smt_proofs.py
	@echo "Z3 version:"
	@z3 -version
	@echo "Running formal SMT verification via Z3..."
	@set -e; \
	for f in \
		formal/ch_equiv.smt2 \
		formal/full_64round_equiv.smt2 \
		formal/full_64round_inverse.smt2; do \
		echo "==> Checking $$f"; \
		result="$$(z3 "$$f")"; \
		echo "$$result"; \
		if [ "$$result" != "unsat" ]; then \
			echo "FAIL: $$f"; \
			exit 1; \
		fi; \
		echo "PASS: $$f"; \
	done

clean:
	rm -f formal/*.smt2
	$(MAKE) -C tests clean
