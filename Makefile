# ============================================================================
# SHA256SW Makefile
#
# Build, test, formally verify, benchmark, and clean the SHA256SW project.
#
# Requirements:
#   - POSIX make / GNU make
#   - C11 compiler
#   - Python 3
#   - Z3 for formal verification and SMT benchmarks
#
# ============================================================================

# ----------------------------------------------------------------------------
# Toolchain
# ----------------------------------------------------------------------------

CC      ?= cc
CFLAGS  ?= -std=c11 -Wall -Wextra -Wpedantic -Werror -O2
CPPFLAGS ?= -Iinclude
PYTHON  ?= python3
Z3      ?= z3

# Optional:
#
#   make CC=clang
#   make CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -O2"
#   make PYTHON=python3
#   make Z3=z3

# ----------------------------------------------------------------------------
# Project paths
# ----------------------------------------------------------------------------

BIN_DIR     := bin
FORMAL_DIR  := formal
BENCH_DIR   := benchmark
SRC_DIR     := src
TEST_DIR    := tests
INCLUDE_DIR := include

TEST_BIN := $(BIN_DIR)/test_sha256sw

SHA256_SRC := $(SRC_DIR)/sha256sw.c
SHA256_HDR := $(INCLUDE_DIR)/sha256sw.h
TEST_SRC   := $(TEST_DIR)/test_sha256sw.c

FORMAL_GENERATOR := $(FORMAL_DIR)/generate_smt_proofs.py

# ----------------------------------------------------------------------------
# Generated formal artifacts
# ----------------------------------------------------------------------------

CH_PROOF      := $(FORMAL_DIR)/ch_equiv.smt2
SUMMARY_PROOF := $(FORMAL_DIR)/full_64round_equiv.smt2
INVERSE_PROOF := $(FORMAL_DIR)/full_64round_inverse.smt2

ROUND_PROOFS := $(foreach n,$(shell seq -w 0 63),$(FORMAL_DIR)/round_$(n)_equiv.smt2)

FORMAL_PROOFS := \
	$(CH_PROOF) \
	$(ROUND_PROOFS) \
	$(SUMMARY_PROOF) \
	$(INVERSE_PROOF)

# ----------------------------------------------------------------------------
# Benchmark
# ----------------------------------------------------------------------------

BENCH_SCRIPT := $(BENCH_DIR)/sha256_representation_benchmark.py

BENCH_ROUNDS ?= 16 20 24 28 30
BENCH_TRIALS ?= 3
BENCH_TIMEOUT ?= 120

BENCH_JSON ?= sha256sw_benchmark.json
BENCH_CSV  ?= sha256sw_benchmark.csv

# ----------------------------------------------------------------------------
# Default target
# ----------------------------------------------------------------------------

.DEFAULT_GOAL := all

.PHONY: all
all: test

# ============================================================================
# C BUILD / TEST
# ============================================================================

.PHONY: build
build: $(TEST_BIN)

$(TEST_BIN): $(SHA256_SRC) $(SHA256_HDR) $(TEST_SRC) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) \
		$(SHA256_SRC) \
		$(TEST_SRC) \
		-o $@

$(BIN_DIR):
	@mkdir -p $@

.PHONY: test
test: $(TEST_BIN)
	@echo "==> Running SHA256SW C test suite"
	./$(TEST_BIN)

# ============================================================================
# FORMAL PROOF GENERATION
# ============================================================================

.PHONY: generate-formal
generate-formal: $(FORMAL_PROOFS)

$(FORMAL_PROOFS): $(FORMAL_GENERATOR)
	@echo "==> Generating SMT proof artifacts"
	$(PYTHON) $(FORMAL_GENERATOR)

# ============================================================================
# FORMAL VERIFICATION
# ============================================================================

.PHONY: check-z3
check-z3:
	@command -v $(Z3) >/dev/null 2>&1 || { \
		echo "ERROR: Z3 not found: $(Z3)" >&2; \
		echo "Install Z3 or invoke make with Z3=/path/to/z3" >&2; \
		exit 1; \
	}

.PHONY: formal
formal: check-z3 generate-formal
	@echo
	@echo "==> Z3 version"
	$(Z3) -version
	@echo
	@echo "==> Checking Ch equivalence"
	$(Z3) $(CH_PROOF)
	@echo
	@echo "==> Checking 64 one-round equivalence obligations"
	@set -e; \
	for proof in $(ROUND_PROOFS); do \
		echo "---- $$proof"; \
		$(Z3) "$$proof"; \
	done
	@echo
	@echo "==> Checking compact symbolic equivalence proof"
	$(Z3) $(SUMMARY_PROOF)
	@echo
	@echo "==> Checking inverse proof"
	$(Z3) $(INVERSE_PROOF)
	@echo
	@echo "==> All formal proofs passed"

# A quieter formal target that suppresses the per-file command echo.
.PHONY: formal-quiet
formal-quiet: check-z3 generate-formal
	@set -e; \
	$(Z3) $(CH_PROOF) >/dev/null; \
	for proof in $(ROUND_PROOFS); do \
		$(Z3) "$$proof" >/dev/null; \
	done; \
	$(Z3) $(SUMMARY_PROOF) >/dev/null; \
	$(Z3) $(INVERSE_PROOF) >/dev/null; \
	echo "All SHA256SW formal proofs: UNSAT / PASS"

# ============================================================================
# ONE-ROUND / GATE CHECK
# ============================================================================

.PHONY: gate
gate: check-z3
	@echo "==> Running benchmark Gate 0"
	$(PYTHON) $(BENCH_SCRIPT) $(Z3) \
		--mode equiv \
		--equiv-rounds 1 \
		--trials 1 \
		--equiv-timeout 60

# ============================================================================
# SYMBOLIC EQUIVALENCE BENCHMARK
# ============================================================================

.PHONY: equiv
equiv: check-z3
	@echo "==> Running symbolic representation-equivalence benchmark"
	$(PYTHON) $(BENCH_SCRIPT) $(Z3) \
		--mode equiv \
		--equiv-rounds 2 4 8 16 32 64 \
		--trials $(BENCH_TRIALS) \
		--equiv-timeout $(BENCH_TIMEOUT) \
		--json $(BENCH_JSON) \
		--csv $(BENCH_CSV)

# ============================================================================
# COLLISION / REPRESENTATION BENCHMARK
# ============================================================================

.PHONY: benchmark
benchmark: check-z3
	@echo "==> Running 4-way SHA256SW representation benchmark"
	$(PYTHON) $(BENCH_SCRIPT) $(Z3) \
		--mode collision \
		--rounds $(BENCH_ROUNDS) \
		--trials $(BENCH_TRIALS) \
		--timeout $(BENCH_TIMEOUT) \
		--json $(BENCH_JSON) \
		--csv $(BENCH_CSV)

# ============================================================================
# FULL VALIDATION
# ============================================================================

.PHONY: verify
verify: test formal

.PHONY: ci
ci: test formal

# ============================================================================
# INFORMATION
# ============================================================================

.PHONY: info
info:
	@echo "SHA256SW build configuration"
	@echo "-----------------------------"
	@echo "CC       = $(CC)"
	@echo "CFLAGS   = $(CFLAGS)"
	@echo "CPPFLAGS = $(CPPFLAGS)"
	@echo "PYTHON   = $(PYTHON)"
	@echo "Z3       = $(Z3)"
	@echo
	@echo "Benchmark configuration"
	@echo "-----------------------"
	@echo "Rounds   = $(BENCH_ROUNDS)"
	@echo "Trials   = $(BENCH_TRIALS)"
	@echo "Timeout  = $(BENCH_TIMEOUT)"
	@echo "JSON     = $(BENCH_JSON)"
	@echo "CSV      = $(BENCH_CSV)"
	@echo
	@echo "Formal artifacts"
	@echo "----------------"
	@echo "Ch proof       = $(CH_PROOF)"
	@echo "Round proofs   = 64"
	@echo "Summary proof  = $(SUMMARY_PROOF)"
	@echo "Inverse proof  = $(INVERSE_PROOF)"

# ============================================================================
# CLEAN
# ============================================================================

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)
	rm -f $(FORMAL_DIR)/*.smt2
	rm -f $(BENCH_JSON) $(BENCH_CSV)
	rm -f *.o
	rm -f *.smt2
	rm -f tmp_*.smt2
	rm -f gate0_*.smt2
	rm -f sha256sw_benchmark.json
	rm -f sha256sw_benchmark.csv

# ============================================================================
# DISTCLEAN
# ============================================================================

.PHONY: distclean
distclean: clean

# ============================================================================
# HELP
# ============================================================================

.PHONY: help
help:
	@echo "SHA256SW targets"
	@echo
	@echo "  make                 Build the C test binary"
	@echo "  make build           Build the C test binary"
	@echo "  make test            Build and run C tests"
	@echo "  make generate-formal Generate all SMT proof artifacts"
	@echo "  make formal          Generate and verify all SMT proofs with Z3"
	@echo "  make formal-quiet    Same as formal, quieter output"
	@echo "  make gate            Run the symbolic equivalence gate"
	@echo "  make equiv           Run symbolic Std-vs-SW benchmark"
	@echo "  make benchmark       Run 4-way collision benchmark"
	@echo "  make verify          Run C tests + all formal proofs"
	@echo "  make ci              CI-equivalent validation target"
	@echo "  make info            Show build/benchmark configuration"
	@echo "  make clean           Remove generated artifacts"
	@echo "  make distclean       Alias for clean"
	@echo
	@echo "Examples:"
	@echo
	@echo "  make test"
	@echo "  make formal"
	@echo "  make benchmark BENCH_TRIALS=5"
	@echo "  make benchmark BENCH_ROUNDS='16 20 24 28 30'"
	@echo "  make equiv"
	@echo "  make verify"

# ============================================================================
# End
# ============================================================================
