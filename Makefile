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

# Development artifacts (#12e dev lane).
#
# A dev build pins the bytes it actually produced: the executor artifact drop
# plus a sha256sum document that names it. Nothing here is a release and nothing
# here may be published as one; the artifacts only make the Hub self-upgrade
# chain testable end to end on an isolated host.
#
#   DEV_VERSION   SemVer pre-release of this build. The default is
#                 1.0.0-dev.<UTC date>.<git commit count>; override it only to
#                 reproduce an older build.
#   DEV_ARCHES    the fixed architecture matrix, from internal/cli/versions.
#   DEV_OUT_DIR   where the artifacts land before they are deployed.
DEV_ARCHES ?= amd64 arm64
DEV_OUT_DIR ?= dist/dev
DEV_VERSION ?= 1.0.0-dev.$(shell date -u +%Y%m%d).$(shell git rev-list --count HEAD)

# Reproducibility: -trimpath and -buildvcs=false keep the artifact bytes a
# function of the source tree, so the same commit and version yield the same
# digest. The version is injected exactly as a release build injects it.
DEV_BUILD_FLAGS = -trimpath -buildvcs=false
DEV_LDFLAGS = -X github.com/wingsky-1/MeshMux/internal/cli/buildinfo.Version=$(DEV_VERSION)

.DEFAULT_GOAL := verify

# Never run targets in parallel: test/race share the module cache and the
# build outputs, and parallel runs would interleave their logs.
.NOTPARALLEL:

.PHONY: verify fmt vet staticcheck dupl test race build dev-artifacts dev-checksums clean-dev-artifacts

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

# dev-artifacts builds the executor artifact of every supported architecture and
# writes the sha256sum document the dev pin reads. It refuses to run without a
# dev version: a release build must come from the 12e release pipeline, not from
# a developer's machine.
dev-artifacts:
	@case "$(DEV_VERSION)" in \
	  *-dev.*) ;; \
	  *) echo "DEV_VERSION=$(DEV_VERSION) is not a dev pre-release (want X.Y.Z-dev.N)"; exit 1 ;; \
	esac
	@mkdir -p $(DEV_OUT_DIR)
	@for arch in $(DEV_ARCHES); do \
	  echo "building $(DEV_VERSION) for linux/$$arch"; \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch $(GO) build $(DEV_BUILD_FLAGS) \
	    -ldflags "$(DEV_LDFLAGS)" -o $(DEV_OUT_DIR)/meshmuxd-linux-$$arch ./cmd/meshmux || exit 1; \
	done
	@cd $(DEV_OUT_DIR) && sha256sum $(addprefix meshmuxd-linux-,$(DEV_ARCHES)) > SHA256SUMS
	@echo "dev artifacts in $(DEV_OUT_DIR):"
	@cat $(DEV_OUT_DIR)/SHA256SUMS
	@echo "deploy with: sudo scripts/dev-artifacts-deploy.sh $(DEV_OUT_DIR)"

# dev-checksums re-derives the digest document from artifacts already in
# DEV_OUT_DIR. It is the same command the build ran, kept separate so an
# operator can re-verify a copied directory without rebuilding.
dev-checksums:
	@cd $(DEV_OUT_DIR) && sha256sum $(addprefix meshmuxd-linux-,$(DEV_ARCHES)) > SHA256SUMS
	@cat $(DEV_OUT_DIR)/SHA256SUMS

clean-dev-artifacts:
	rm -rf $(DEV_OUT_DIR)
