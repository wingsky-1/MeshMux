# MeshMux developer entry points.
#
# `make verify` is the single gate for the CI `go` job
# (.github/workflows/ci.yml). The commands below are exactly the steps
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

# Staticcheck runs with zero tolerance: the pre-existing findings present when
# the gate was introduced (2026-10-21) were paid down to zero by Issue #20
# (PRs #57-#60), so every check class is blocking. Never add an exemption
# here to silence findings in new code.
STATICCHECK_BASELINE = all

# dupl is pinned. Threshold 100 blocks the five t=100 groups present on
# 2026-10-26 (install apply/node_apply, subscription export/export_mesh,
# web/store self-clone, plus two handler test self-clones); templ stays
# excluded because dupl has no -exclude flag and generated views dominate hits.
DUPL_VERSION ?= v1.1.0
DUPL_THRESHOLD ?= 100
DUPL = $(GO) run github.com/mibk/dupl@$(DUPL_VERSION)

.DEFAULT_GOAL := verify

# Never run targets in parallel: test/race share the module cache and the
# build outputs, and parallel runs would interleave their logs.
.NOTPARALLEL:

.PHONY: verify fmt vet staticcheck dupl test race build

verify: fmt vet staticcheck dupl test race build

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

dupl:
	@files="$$(git ls-files '*.go' | grep -v '_templ.go$$')"; \
	out="$$(printf '%s\n' "$$files" | $(DUPL) -files -plumbing -t $(DUPL_THRESHOLD))"; \
	if [ -n "$$out" ]; then echo "$$out"; echo "duplicate code (dupl t=$(DUPL_THRESHOLD)); extract a helper or justify in review"; exit 1; fi
	@echo "dupl: clean (t $(DUPL_THRESHOLD), templ excluded)"

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

build:
	$(GO) build -o $(BUILD_DIR)/meshmux ./cmd/meshmux
	$(GO) build -o $(BUILD_DIR)/meshmux-web ./cmd/meshmux-web
