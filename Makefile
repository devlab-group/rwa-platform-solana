.DEFAULT_GOAL := help
SHELL := /bin/bash

.PHONY: help bootstrap format lint signer-test server-test web-test \
        investor-web-test vectors-check dialect-check ci up down \
        security-scan platform signer embed-check solana-test solana-anchor-build solana-anchor-test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

bootstrap: ## Install toolchains/deps for all subrepos
	@echo "==> signer";    cd signer && go mod download
	@echo "==> server";    cd server && go mod download
	@echo "==> web";       cd web && npm install
	@echo "==> investor-web"; cd investor-web && npm install

format: ## Format all code
	-cd signer && gofmt -w .
	-cd server && gofmt -w .
	-cd web && npm run format --if-present
	-cd investor-web && npm run format --if-present
	-cd solana && cargo fmt

lint: ## Lint all code (fail-closed: a lint failure fails the build)
	cd signer && go vet ./...
	cd server && go vet ./...
	cd web && npm run lint --if-present
	cd investor-web && npm run lint --if-present
	cd solana && cargo fmt --check

signer-test: ## Signer unit tests (incl. golden vectors), race detector on
	cd signer && go test -race ./...

server-test: ## Server unit/integration tests, race detector on
	cd server && go test -race ./...

web-test: ## Web (admin console) typecheck + tests + build
	cd web && npm run typecheck --if-present && npm test --if-present && npm run build

investor-web-test: ## Investor example SPA typecheck + tests + build
	cd investor-web && npm run typecheck --if-present && npm test --if-present && npm run build

solana-test: ## Solana host-testable core crates (pricing/attestation/compliance/redemption) — no SBF toolchain needed
	cd solana && cargo test --locked -p pricing-math -p compliance-core -p redemption-core -p attestation

solana-anchor-build: ## SBF-compile the Anchor programs (Agave 4.x + anchor 1.1.2 toolchain; verifies 0 stack overflows)
	cd solana && anchor build && anchor keys sync && anchor build

solana-anchor-test: ## Full Anchor integration suite. Needs a validator running Token-2022 v11 (permissioned burn) — see solana/README for the build-and-inject recipe. `anchor test` alone (bundled validator) can't run the permissioned-burn cases.
	cd solana && anchor build && anchor keys sync && anchor build && anchor test

vectors-check: dialect-check ## Verify shared golden vectors reproduce across languages
	cd signer && go test ./internal/attestation/... -run Vectors
	# Gate the Solana attestation vector Go<->Rust (the signer's
	# TestSolanaVectors above reproduces solana/tests/vectors/mint-attestation.json;
	# this asserts the on-chain Rust crate reproduces the same frozen digest).
	cd solana && cargo test --locked -p attestation

dialect-check: ## Cross-binary parity for the assetSchema dialect
	# First run fails the build on any failing case; second asserts a Dialect test
	# actually ran (guards against a rename silently matching zero tests). Package
	# globs include every package holding a Dialect* test (server: assets;
	# signer: jsonschema + profile, where the envelope differential test lives).
	cd server && go test ./internal/assets/... -run Dialect -count=1 && \
	  go test ./internal/assets/... -run Dialect -count=1 -v | grep -q -- '--- PASS: .*Dialect'
	cd signer && go test ./internal/jsonschema/... ./internal/profile/... -run Dialect -count=1 && \
	  go test ./internal/jsonschema/... ./internal/profile/... -run Dialect -count=1 -v | grep -q -- '--- PASS: .*Dialect'

platform: ## Build the release platform binary with a FRESH embedded SPA
	# Deterministic production web build (web/package.json pins NODE_ENV=production),
	# then re-embed it into the server module tree before compiling the binary, so
	# the shipped binary can never carry a stale SPA. The built SPA is NOT committed:
	# only dist/.gitkeep is tracked and assets/ are gitignored, so it is rebuilt here
	# every release. Clear everything EXCEPT the tracked
	# placeholder so a removed/renamed asset can't linger (Vite content-hashes names).
	cd web && npm install && npm run build
	find server/internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -r web/dist/. server/internal/webui/dist/
	cd server && go build -o bin/platform ./cmd/platform
	@echo "platform binary -> server/bin/platform (SPA embedded from a fresh web/dist)"

signer: ## Build the offline signer binary (signer/bin/signer)
	cd signer && go build -o bin/signer ./cmd/signer
	@echo "signer binary -> signer/bin/signer"

embed-check: platform ## Prove the release binary builds with a freshly embedded SPA (dist is built at release, not committed)
	# The built SPA is no longer committed (only dist/.gitkeep is tracked), so a
	# committed-drift diff no longer applies. `platform` rebuilds web/, embeds it
	# fresh, and compiles the binary — proving go:embed resolves the real assets.
	@echo "embed-check OK (fresh SPA embedded into server/bin/platform)"

ci: lint signer-test server-test web-test investor-web-test solana-test solana-anchor-build vectors-check embed-check ## PR gate (mirrors the fail-closed CI: lint checks formatting, it does not auto-fix — run `make format` yourself first)
	@echo "CI OK"

security-scan: ## Dependency vulnerability scan (fail-closed on reachable advisories)
	cd server && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd signer && go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	# Production deps only: dev tooling (eslint, openapi-typescript, playwright) never
	# ships in the SPA/binary. The gate keeps npm audit's floor at `high` and
	# suppresses only the reviewed, expiring advisory IDs in
	# scripts/npm-audit-allowlist.json. Mirrors the ci.yml security-scan job.
	node scripts/npm-audit-gate.mjs web
	# solana/: cargo audit is fail-closed on the Rust/SBF graph; the npm side is
	# off-chain deployment tooling that never ships in a program.
	cd solana && cargo audit
	node scripts/npm-audit-gate.mjs solana

up: ## Start local dev stack (solana-test-validator, mongo, ipfs)
	cd docker && docker compose up -d --build

down: ## Stop local dev stack
	cd docker && docker compose down -v
