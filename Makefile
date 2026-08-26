# SPDX-License-Identifier: MIT OR Apache-2.0
# This file is part of Nitr.
# See https://nitrweb.com/ for more information
# Copyright (C) 2024-present Jose Quintana <joseluisq.net>

# Local entry points mirroring what CI runs (.github/workflows/), so a
# contributor can reproduce a red check without reading the workflows.
#
# RUSTFLAGS defaults to empty (overridable): stable builds must not
# inherit nightly-only flags from a user-level cargo config, which is
# also what CI's check job pins.

RUSTFLAGS ?=
export RUSTFLAGS

# The six libfuzzer targets, same list as .github/workflows/fuzz.yml.
FUZZ_TARGETS := cookie_verify accept_negotiation path_lexical json_lua range_header multipart
# Per-target fuzz time in seconds (CI uses 90).
FUZZ_TIME ?= 60

.PHONY: all fmt lint test fuzz

all: lint test

# Apply formatting (CI only checks; run this before committing).
fmt:
	cargo fmt --all

# What the CI check job runs: formatting, then clippy over every target
# in both feature configurations, warnings denied.
lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --features all --all-targets -- -D warnings
	cargo clippy --workspace --no-default-features --all-targets -- -D warnings

# The test suite in both feature configurations, plus the resilience
# suite under the shipped release profile (its own CI job: overflow
# checks and full optimization are only on there).
test:
	cargo test --features all
	cargo test --no-default-features
	cargo test -p nitr --release --features=all --test resilience

# Every fuzz target for a bounded time, seeded like CI. Needs nightly and
# cargo-fuzz (`cargo install cargo-fuzz`); the explicit GNU target keeps
# the address sanitizer off any musl default, and the +nightly prefix is
# required — the plain invocation would use the stable default toolchain.
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		echo "== fuzz $$target ($(FUZZ_TIME)s)"; \
		mkdir -p fuzz/corpus/$$target; \
		if [ -d fuzz/seeds/$$target ]; then \
			cp -n fuzz/seeds/$$target/* fuzz/corpus/$$target/ 2>/dev/null || true; \
		fi; \
		CARGO_BUILD_TARGET= cargo +nightly fuzz run \
			--target x86_64-unknown-linux-gnu $$target -- \
			-max_total_time=$(FUZZ_TIME) || exit 1; \
	done
