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

# The libfuzzer targets, same list as .github/workflows/fuzz.yml.
FUZZ_TARGETS := cookie_verify accept_negotiation path_lexical json_lua \
                range_header multipart static_resolve url_lexical \
                cookie_header accept_encoding jwt_verify validate_formats \
                conditional_headers basic_auth tls_pem
# Per-target fuzz time in seconds (CI uses 90).
FUZZ_TIME ?= 60
# A hang is a bug: bound one execution well under the run itself, since
# libFuzzer's default (1200s) can never fire inside a 90s run — which
# made every target's "never hangs" claim unfalsifiable.
FUZZ_TIMEOUT ?= 25
# Headroom over the 2048 default: a Lua VM under ASan legitimately uses
# more than a plain parser, and a false OOM is worse than a late one.
FUZZ_RSS ?= 4096

.PHONY: all fmt lint test fuzz fuzz-check

all: lint test

# Apply formatting (CI only checks; run this before committing).
fmt:
	cargo fmt --all

# What the CI check job runs: formatting, then clippy over every target
# in both feature configurations, warnings denied.
lint: fuzz-check
	cargo fmt --all -- --check
	cargo clippy --workspace --features all --all-targets -- -D warnings
	cargo clippy --workspace --no-default-features --all-targets -- -D warnings

# The fuzz target list lives in three places — fuzz/Cargo.toml declares
# the binaries, this file drives local runs, fuzz.yml drives CI — and
# nothing enforced that they agree. They had already drifted once. This
# is pure text comparison (no nightly, no cargo-fuzz, instant), so it
# rides along with `lint` where drift gets caught by every contributor
# rather than by a silently missing CI leg.
fuzz-check:
	@bins=$$(sed -n 's/^name = "\([a-z_][a-z_]*\)"$$/\1/p' fuzz/Cargo.toml \
		| grep -vx 'nitr_fuzz' | sort | tr '\n' ' '); \
	mk=$$(echo $(FUZZ_TARGETS) | tr ' ' '\n' | sort | tr '\n' ' '); \
	ci=$$(sed -n 's/^ *- target: \([a-z_][a-z_]*\)$$/\1/p' \
		.github/workflows/fuzz.yml | sort | tr '\n' ' '); \
	fail=0; \
	if [ "$$bins" != "$$mk" ]; then \
		echo "fuzz target drift: fuzz/Cargo.toml vs Makefile"; \
		echo "  Cargo.toml: $$bins"; \
		echo "  Makefile:   $$mk"; \
		fail=1; \
	fi; \
	if [ "$$bins" != "$$ci" ]; then \
		echo "fuzz target drift: fuzz/Cargo.toml vs .github/workflows/fuzz.yml"; \
		echo "  Cargo.toml: $$bins"; \
		echo "  fuzz.yml:   $$ci"; \
		fail=1; \
	fi; \
	if [ $$fail -ne 0 ]; then exit 1; fi; \
	echo "fuzz targets agree across Cargo.toml, Makefile and fuzz.yml"

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
#
# Deliberately NOT part of `all`: a full pass is minutes of CPU per
# target, and `all` has to stay cheap enough to run before every commit.
# Run it before touching a parser, and let CI run it per PR.
#
# `-max_len` is per target because the default (4096) silently truncates
# the two targets whose inputs are bodies rather than headers: multipart
# bodies never reached multi-frame sizes and JSON never got deep enough
# to approach the depth guard.
fuzz:
	@failed=""; \
	for target in $(FUZZ_TARGETS); do \
		case $$target in \
			multipart) max_len=65536 ;; \
			json_lua|tls_pem) max_len=16384 ;; \
			jwt_verify|url_lexical) max_len=8192 ;; \
			*) max_len=4096 ;; \
		esac; \
		echo "== fuzz $$target ($(FUZZ_TIME)s, max_len=$$max_len)"; \
		mkdir -p fuzz/corpus/$$target; \
		if [ -d fuzz/seeds/$$target ]; then \
			cp -n fuzz/seeds/$$target/* fuzz/corpus/$$target/ 2>/dev/null || true; \
		fi; \
		dict=""; \
		if [ -f fuzz/dicts/$$target.dict ]; then \
			dict="-dict=fuzz/dicts/$$target.dict"; \
		fi; \
		if CARGO_BUILD_TARGET= cargo +nightly fuzz run \
			--target x86_64-unknown-linux-gnu $$target -- \
			$$dict \
			-max_len=$$max_len \
			-timeout=$(FUZZ_TIMEOUT) \
			-rss_limit_mb=$(FUZZ_RSS) \
			-max_total_time=$(FUZZ_TIME); then \
			CARGO_BUILD_TARGET= cargo +nightly fuzz cmin \
				--target x86_64-unknown-linux-gnu $$target >/dev/null 2>&1 || true; \
		else \
			failed="$$failed $$target"; \
		fi; \
	done; \
	if [ -n "$$failed" ]; then \
		echo "fuzz failures:$$failed"; \
		echo "reproducers are under fuzz/artifacts/<target>/"; \
		exit 1; \
	fi
