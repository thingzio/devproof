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
ACTIONLINT    := $(call version-of,actionlint)

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
	  echo "cmd/devproof does not exist yet (phase 5); compiled packages only"; \
	fi

.PHONY: clean
clean: ## Remove build and coverage output
	rm -rf $(BIN_DIR) $(COVERAGE_FILE) coverage.html

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

.PHONY: cover
cover: ## Run tests and write a coverage profile
	go test -race -count=1 -covermode=atomic -coverprofile=$(COVERAGE_FILE) $(COVER_PKGS)
	go tool cover -func=$(COVERAGE_FILE) | tail -1

.PHONY: cover-html
cover-html: cover ## Render the coverage profile as HTML
	go tool cover -html=$(COVERAGE_FILE) -o coverage.html

.PHONY: fuzz
fuzz: ## Run every fuzz target briefly as a smoke check
	@for pkg in $$(go list ./... ); do
	  for target in $$(go test -list 'Fuzz.*' $$pkg 2>/dev/null | grep '^Fuzz' || true); do
	    echo "==> $$pkg $$target"
	    go test -run '^$$' -fuzz "^$${target}$$" -fuzztime 30s $$pkg
	  done
	done

# Golden bytes are a compatibility surface (DP-015). This target is the one
# that must fail loudly when a refactor or dependency bump changes them.
.PHONY: test-golden
test-golden: ## Verify format golden vectors byte-for-byte
	go test -race -count=1 -run 'TestGolden' ./internal/canonical/... ./bundle/...

.PHONY: regen-golden
regen-golden: ## Regenerate golden vectors (only for a NEW format version)
	@echo "Golden bytes are frozen for a released format version (DP-015)."
	@echo "Regenerating is correct only when introducing a new format version."
	@read -r -p "Type the new format version to continue: " v; test -n "$$v"
	UPDATE_GOLDEN=1 go test -count=1 ./internal/canonical/... ./bundle/...

##@ Lint

.PHONY: lint
lint: $(TOOLS_DIR)/golangci-lint ## Run golangci-lint
	golangci-lint run --config .golangci.yaml

.PHONY: fmt
fmt: $(TOOLS_DIR)/golangci-lint ## Apply formatters
	golangci-lint fmt --config .golangci.yaml

.PHONY: lint-actions
lint-actions: $(TOOLS_DIR)/actionlint ## Lint GitHub Actions workflows
	actionlint

.PHONY: vet
vet: ## Run go vet
	go vet ./...

##@ Security

.PHONY: vuln
vuln: $(TOOLS_DIR)/govulncheck ## Scan for known vulnerabilities
	govulncheck ./...

.PHONY: sbom
sbom: $(TOOLS_DIR)/syft ## Generate a CycloneDX SBOM
	syft scan dir:. -o cyclonedx-json=sbom.json

.PHONY: scan
scan: sbom $(TOOLS_DIR)/grype ## Scan the SBOM for vulnerabilities
	grype sbom:sbom.json --fail-on medium

##@ Gates

# What CI runs. Keep this the single definition of "green" so that a local
# run and a pull-request run cannot disagree.
.PHONY: qualify
qualify: tidy fmt lint vet test-golden cover vuln ## Run the full pre-commit gate

##@ Tools

$(TOOLS_DIR):
	mkdir -p $(TOOLS_DIR)

$(TOOLS_DIR)/golangci-lint: | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT)

$(TOOLS_DIR)/govulncheck: | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK)

$(TOOLS_DIR)/actionlint: | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT)

$(TOOLS_DIR)/syft: | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/anchore/syft/cmd/syft@$(SYFT)

$(TOOLS_DIR)/grype: | $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install github.com/anchore/grype/cmd/grype@$(GRYPE)

.PHONY: tools
tools: $(TOOLS_DIR)/golangci-lint $(TOOLS_DIR)/govulncheck $(TOOLS_DIR)/actionlint ## Install pinned dev tools

.PHONY: print-versions
print-versions: ## Print resolved tool versions
	@printf 'go            %s\n' '$(GO_VERSION)'
	@printf 'golangci-lint %s\n' '$(GOLANGCI_LINT)'
	@printf 'govulncheck   %s\n' '$(GOVULNCHECK)'
	@printf 'actionlint    %s\n' '$(ACTIONLINT)'
	@printf 'syft          %s\n' '$(SYFT)'
	@printf 'grype         %s\n' '$(GRYPE)'
