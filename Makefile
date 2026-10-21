# MeshMux developer entry points.
#
# `make verify` is the single gate for the CI `go` job
# (.github/workflows/ci.yml). The five commands below are exactly the steps
# that job used to run inline; keep the two in sync when either changes.

SHELL := /bin/sh

GO ?= go
# CI's install-invariant step consumes these exact paths, so the default must
# stay /tmp/meshmux and /tmp/meshmux-web.
BUILD_DIR ?= /tmp

# staticcheck is pinned. Note: the module path `honnef.co/staticcheck` no
# longer resolves (404 on go-get); the tool is published from honnef.co/go/tools.
# Bump only deliberately, never `@latest`.
STATICCHECK_VERSION ?= v0.8.2
STATICCHECK = $(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

# Findings already present on main when staticcheck was introduced
# (2026-10-21): 13x U1000, 6x ST1013, 2x SA1019, 2x S1000, 1x SA4017,
# 1x S1021, 1x S1016. They are still printed, but only these classes are
# allowed to exit 0 until the refactor pays the debt down; every other check
# is blocking. Never add a class here to silence findings in new code.
STATICCHECK_BASELINE = all,-U1000,-ST1013,-SA1019,-S1000,-SA4017,-S1021,-S1016

.DEFAULT_GOAL := verify

# Never run targets in parallel: test/race share the module cache and the
# build outputs, and parallel runs would interleave their logs.
.NOTPARALLEL:

.PHONY: verify fmt vet staticcheck test race build

verify: fmt vet staticcheck test race build

fmt:
	@unformatted="$$(gofmt -s -l ./cmd ./internal)"; \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go files (gofmt -s):"; \
		echo "$$unformatted"; \
		gofmt -s -d ./cmd ./internal; \
		exit 1; \
	fi
	@echo "gofmt -s: clean"

vet:
	$(GO) vet ./...

staticcheck:
	$(STATICCHECK) -fail '$(STATICCHECK_BASELINE)' ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

build:
	$(GO) build -o $(BUILD_DIR)/meshmux ./cmd/meshmux
	$(GO) build -o $(BUILD_DIR)/meshmux-web ./cmd/meshmux-web
