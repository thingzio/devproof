SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help
.ONESHELL:

# Every pinned version comes from .versions.yaml so that a local `make lint`
# and the CI job run the identical tool. Parsed with sed rather than yq to
# keep `make help` working on a machine with nothing installed yet.
VERSIONS      := .versions.yaml
version-of     = $(shell sed -n 's/^[[:space:]]*$(1):[[:space:]]*.\(.*\).[[:space:]]*$$/\1/p' $(VERSIONS) | head -1)

GO_VERSION    := $(shell cat .go-version)
GOLANGCI_LINT := $(call version-of,golangci_lint)
GOVULNCHECK   := $(call version-of,govulncheck)
SYFT          := $(call version-of,syft)
GRYPE         := $(call version-of,grype)
GITLEAKS      := $(call version-of,gitleaks)
ACTIONLINT    := $(call version-of,actionlint)
YAMLLINT      := $(call version-of,yamllint)
GORELEASER    := $(call version-of,goreleaser)

# The floor `make cover-check` enforces. Lives in .versions.yaml with every
# other pinned number so a local run and the CI job cannot disagree about what
# "enough coverage" means.
COVERAGE_THRESHOLD := $(call version-of,coverage_threshold)

MODULE        := github.com/thingzio/devproof
BIN_DIR       := bin
TOOLS_DIR     := $(CURDIR)/$(BIN_DIR)/tools
COVERAGE_FILE := coverage.out

# Stamped into the binary; never into artifact bytes (DP-012).
VERSION       := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT        := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS       := -s -w \
                 -X $(MODULE)/internal/version.version=$(VERSION) \
                 -X $(MODULE)/internal/version.commit=$(COMMIT)

export PATH := $(TOOLS_DIR):$(PATH)

# Each pinned tool is gated on a version-stamped sentinel rather than on the
# binary itself. Keying the target on bin/tools/govulncheck meant that once the
# file existed make considered it done forever: bumping the pin in
# .versions.yaml reinstalled nothing locally while CI, starting from an empty
# runner, got the new version. That is precisely the local-vs-CI drift this file
# exists to prevent, and it is invisible -- the gate still passes, just with the
# wrong tool.
#
# These must be defined above the rules that name them: make expands
# prerequisites when it reads the rule, so a stamp defined further down the file
# expands to the empty string and the tool dependency silently disappears.
GOLANGCI_LINT_STAMP := $(TOOLS_DIR)/.golangci-lint-$(GOLANGCI_LINT)
GOVULNCHECK_STAMP   := $(TOOLS_DIR)/.govulncheck-$(GOVULNCHECK)
ACTIONLINT_STAMP    := $(TOOLS_DIR)/.actionlint-$(ACTIONLINT)
GITLEAKS_STAMP      := $(TOOLS_DIR)/.gitleaks-$(GITLEAKS)
SYFT_STAMP          := $(TOOLS_DIR)/.syft-$(SYFT)
GRYPE_STAMP         := $(TOOLS_DIR)/.grype-$(GRYPE)

##@ General

.PHONY: help
help: ## Print this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} \
	  /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 } \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) }' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## Tidy and verify go.mod/go.sum
	go mod tidy
	go mod verify
	$(MAKE) notices

.PHONY: notices
notices: ## Regenerate THIRD_PARTY_NOTICES.md from the build graph
	python3 tools/gen-third-party-notices

##@ Build

# The CLI arrives in phase 5. Until then `build` compiles the library, which
# is what CI needs to gate on; pointing it at a directory that does not exist
# yet would make the job fail for a reason unrelated to the change under test.
.PHONY: build
build: ## Compile all packages, and the CLI once it exists
	go build ./...
	@if [ -d ./cmd/devproof ]; then \
	  mkdir -p $(BIN_DIR); \
	  CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/devproof ./cmd/devproof; \
	  echo "built $(BIN_DIR)/devproof"; \
	else \
	  echo "cmd/devproof is missing; compiled packages only"; \
	fi

.PHONY: clean
clean: ## Remove build and coverage output (keeps the pinned tool cache)
	rm -rf $(BIN_DIR)/devproof $(COVERAGE_FILE) coverage.html sbom.json dist

.PHONY: clean-all
clean-all: clean ## Remove build output and the pinned tool cache
	rm -rf $(TOOLS_DIR)
	go clean -cache -testcache

##@ Test

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -count=1 ./...

# The frozen DEFLATE copy is excluded from the coverage profile. It carries no
# tests by design — adding any would mean editing a copy whose value is being
# byte-identical to a known upstream revision — and its behavior is covered
# through internal/canonical's gzip tests. Counting 4k untouched lines as
# uncovered would only train everyone to ignore the number.
COVER_PKGS = $(shell go list ./... | grep -v '/internal/canonical/deflate')

# -coverpkg is what makes this number honest. Without it Go credits a
# statement only to tests in its own package, so code exercised through the
# SDK's end-to-end tests — which is most of the interesting code — reads as
# uncovered and the number stops meaning anything.
.PHONY: cover
cover: ## Run tests and write a coverage profile
	go test -race -count=1 -covermode=atomic \
	  -coverpkg=$(shell echo $(COVER_PKGS) | tr ' ' ',') \
	  -coverprofile=$(COVERAGE_FILE) $(COVER_PKGS)
	go tool cover -func=$(COVERAGE_FILE) | tail -1

.PHONY: cover-html
cover-html: cover ## Render the coverage profile as HTML
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html

# Backslash continuations rather than relying on .ONESHELL. macOS ships GNU
# Make 3.81, which predates .ONESHELL (3.82) and ignores it silently, so this
# recipe ran one line per shell and died on `for ... do` with no body. It
# worked on CI's newer make and failed on a maintainer's laptop, which is the
# exact split .versions.yaml exists to prevent. Joined into one line, it runs
# the same everywhere.
#
# FUZZTIME is overridable so a scheduled campaign can run long without a
# second target drifting out of step with this one.
.PHONY: fuzz
fuzz: ## Run every fuzz target briefly as a smoke check
	@set -euo pipefail; \
	for pkg in $$(go list ./...); do \
	  for target in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
	    echo "==> $$pkg $$target"; \
	    go test -run '^$$' -fuzz "^$${target}$$" -fuzztime "$${FUZZTIME:-30s}" $$pkg; \
	  done; \
	done

# Golden bytes are a compatibility surface (DP-015). This target is the one
# that must fail loudly when a refactor or dependency bump changes them.
.PHONY: test-golden
test-golden: ## Verify format golden vectors byte-for-byte
	go test -race -count=1 -run 'TestGolden' ./internal/canonical/... ./pkg/bundle/...

.PHONY: regen-golden
regen-golden: ## Regenerate golden vectors (only for a NEW format version)
	@echo "Golden bytes are frozen for a released format version (DP-015)."
	@echo "Regenerating is correct only when introducing a new format version."
	@read -r -p "Type the new format version to continue: " v; test -n "$$v"
	UPDATE_GOLDEN=1 go test -count=1 ./internal/canonical/... ./pkg/bundle/...

##@ Lint

.PHONY: lint
lint: $(GOLANGCI_LINT_STAMP) ## Run golangci-lint
	golangci-lint run --config .golangci.yaml

.PHONY: fmt
fmt: $(GOLANGCI_LINT_STAMP) ## Apply formatters
	golangci-lint fmt --config .golangci.yaml

.PHONY: license
license: ## Apply the license header to every first-party Go file
	python3 tools/apply-license-headers

.PHONY: license-check
license-check: ## Fail if any first-party Go file is missing its license header
	python3 tools/apply-license-headers --check

.PHONY: lint-yaml
lint-yaml: ## Lint YAML with the pinned yamllint
	@command -v yamllint >/dev/null 2>&1 \
	  || { echo "yamllint not installed: pipx install yamllint==$(YAMLLINT)"; exit 1; }
	yamllint --strict .

.PHONY: lint-actions
lint-actions: $(ACTIONLINT_STAMP) ## Lint GitHub Actions workflows
	actionlint

.PHONY: vet
vet: ## Run go vet
	go vet ./...

##@ Security

# Vulnerabilities that are known, unfixable upstream, and accepted.
#
# Each entry needs an ID, why it cannot be fixed, and why it does not apply.
# A permanently-red `make vuln` is worse than no scan at all, because it
# trains everyone to ignore the one signal that matters. Reviewing this list
# is part of reviewing a dependency bump.
#
#   GO-2026-5932  golang.org/x/crypto/openpgp is unmaintained, with no fixed
#                 version. It arrives through sigstore-go's signing package
#                 and every reported trace is a package init; DevProof calls
#                 no OpenPGP code and handles no OpenPGP material. It leaves
#                 when sigstore-go drops the dependency.
VULN_ALLOWLIST := GO-2026-5932

.PHONY: vuln
vuln: $(GOVULNCHECK_STAMP) ## Scan for known vulnerabilities
	@echo "accepted, unfixable findings: $(VULN_ALLOWLIST)"
	@report="$$(govulncheck ./... 2>&1 || true)"; \
	  found="$$(printf '%s\n' "$$report" | sed -n 's/^Vulnerability #[0-9]*: \(GO-[0-9-]*\).*/\1/p' | sort -u)"; \
	  unexpected=""; \
	  for id in $$found; do \
	    case " $(VULN_ALLOWLIST) " in *" $$id "*) ;; *) unexpected="$$unexpected $$id";; esac; \
	  done; \
	  if [ -n "$$unexpected" ]; then \
	    printf '%s\n' "$$report"; \
	    echo "unaccepted vulnerabilities:$$unexpected"; \
	    exit 1; \
	  fi; \
	  if [ -n "$$found" ]; then \
	    echo "only accepted findings present: $$(echo $$found)"; \
	  else \
	    echo "no vulnerabilities found"; \
	  fi

.PHONY: sbom
sbom: $(SYFT_STAMP) ## Generate a CycloneDX SBOM
	syft scan dir:. -o cyclonedx-json=sbom.json

.PHONY: secrets
secrets: $(GITLEAKS_STAMP) ## Scan the working tree and full history for secrets
	gitleaks dir --no-banner --redact .
	gitleaks git --no-banner --redact .

.PHONY: scan
scan: sbom $(GRYPE_STAMP) ## Scan the SBOM for vulnerabilities
	grype sbom:sbom.json --fail-on medium

.PHONY: cover-check
cover-check: cover ## Fail if coverage falls below the threshold
	@total="$$(go tool cover -func=$(COVERAGE_FILE) | awk '/^total:/ {print $$3}' | tr -d '%')"; \
	echo "coverage $${total}% (threshold $(COVERAGE_THRESHOLD)%)"; \
	awk -v got="$${total}" -v want="$(COVERAGE_THRESHOLD)" \
	  'BEGIN { exit (got + 0 >= want + 0) ? 0 : 1 }' \
	  || { echo "coverage $${total}% is below the $(COVERAGE_THRESHOLD)% threshold"; exit 1; }

##@ Gates

# What CI runs. Keep this the single definition of "green" so that a local
# run and a pull-request run cannot disagree.
.PHONY: qualify
qualify: tidy license-check fmt lint lint-actions vet test-golden cover-check vuln secrets ## Run the full pre-commit gate

##@ Release

.PHONY: info
info: ## Print repository and toolchain state
	@printf 'module        %s\n' '$(MODULE)'
	@printf 'version       %s\n' '$(VERSION)'
	@printf 'commit        %s\n' '$(COMMIT)'
	@printf 'branch        %s\n' "$$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
	@printf 'go            %s\n' "$$(go env GOVERSION)"
	@printf 'platform      %s/%s\n' "$$(go env GOOS)" "$$(go env GOARCH)"

.PHONY: release
release: ## Build a snapshot release locally without publishing anything
	goreleaser release --snapshot --clean

.PHONY: upgrade
upgrade: ## Upgrade every Go dependency to its latest release
	go get -u ./...
	$(MAKE) tidy

# Tagging is the one action that cannot be taken back: a tag names bytes other
# people will verify against. tools/bump refuses a dirty tree, refuses
# unpushed commits, and runs `make qualify` before it tags.
.PHONY: bump-major
bump-major: ## Tag and push the next major version (1.2.3 -> 2.0.0)
	tools/bump major

.PHONY: bump-minor
bump-minor: ## Tag and push the next minor version (1.2.3 -> 1.3.0)
	tools/bump minor

.PHONY: bump-patch
bump-patch: ## Tag and push the next patch version (1.2.3 -> 1.2.4)
	tools/bump patch

##@ Tools

$(TOOLS_DIR):
	mkdir -p $(TOOLS_DIR)

$(GOLANGCI_LINT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT)
	rm -f $(TOOLS_DIR)/.golangci-lint-* && touch $@

$(GOVULNCHECK_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK)
	rm -f $(TOOLS_DIR)/.govulncheck-* && touch $@

$(ACTIONLINT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT)
	rm -f $(TOOLS_DIR)/.actionlint-* && touch $@

$(GITLEAKS_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/zricethezav/gitleaks/v8@$(GITLEAKS)
	rm -f $(TOOLS_DIR)/.gitleaks-* && touch $@

$(SYFT_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT)
	rm -f $(TOOLS_DIR)/.syft-* && touch $@

$(GRYPE_STAMP): | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/anchore/grype/cmd/grype@$(GRYPE)
	rm -f $(TOOLS_DIR)/.grype-* && touch $@

.PHONY: tools
tools: $(GOLANGCI_LINT_STAMP) $(GOVULNCHECK_STAMP) $(ACTIONLINT_STAMP) ## Install pinned dev tools

.PHONY: print-versions
print-versions: ## Print resolved tool versions
	@printf 'go            %s\n' '$(GO_VERSION)'
	@printf 'golangci-lint %s\n' '$(GOLANGCI_LINT)'
	@printf 'govulncheck   %s\n' '$(GOVULNCHECK)'
	@printf 'actionlint    %s\n' '$(ACTIONLINT)'
	@printf 'syft          %s\n' '$(SYFT)'
	@printf 'grype         %s\n' '$(GRYPE)'
