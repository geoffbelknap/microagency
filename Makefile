.PHONY: build install test image engines jq-engine text-engine html-engine sql-engine minimizers redactor-minimizer

BUNDLED := cmd/microagency/bundled

# Image build (no Docker). Override the destination or CA source as needed.
IMAGE_REF ?= ghcr.io/geoffbelknap/microagency:latest
CA_BUNDLE ?= /etc/ssl/certs/ca-certificates.crt
IMAGE_WORKSPACE := microagency-image-build

# build/install bundle the engines AND minimizers into the binary, so `microagency
# up` works with nothing else to install.
build: engines minimizers
	go build ./cmd/microagency

install: engines minimizers
	go install ./cmd/microagency

test:
	go test ./...

# Build the workload OCI image with microagent (no Docker). Stages a static
# binary (wasm engines embedded) + a CA bundle into dist/, bakes them onto the
# base rootfs via image/microagency.microagent.yaml, and commits the result to
# $(IMAGE_REF). Set PUSH=1 to publish (authenticate first with
# `microagent registry login <registry> -u <user> --password-stdin`). Building
# never boots a VM — the rootfs is assembled and extracted on the host
# (mke2fs/debugfs) — so it runs anywhere microagent is installed.
image: engines minimizers
	@command -v microagent >/dev/null 2>&1 || { echo "microagent not found on PATH (brew install geoffbelknap/tap/microagent)"; exit 1; }
	@test -r "$(CA_BUNDLE)" || { echo "CA bundle not readable: $(CA_BUNDLE) (set CA_BUNDLE=<path to ca-certificates.crt>)"; exit 1; }
	mkdir -p dist
	CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags "-s -w" -o dist/microagency ./cmd/microagency
	cp "$(CA_BUNDLE)" dist/ca-certificates.crt
	microagent delete -y $(IMAGE_WORKSPACE) 2>/dev/null || true
	microagent create -name $(IMAGE_WORKSPACE) -file image/microagency.microagent.yaml
	microagent commit $(IMAGE_WORKSPACE) $(IMAGE_REF) $(if $(PUSH),--push,)
	microagent delete -y $(IMAGE_WORKSPACE)

# Build the wasm-compute engines (wasip1) into the embed dir (cmd/microagency/
# bundled/), so the binary ships with the declarative query engines.
engines: jq-engine text-engine html-engine sql-engine

jq-engine:
	cd engines/jq && GOWORK=off GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -o ../../$(BUNDLED)/jq.wasm .

text-engine:
	cd engines/text && GOWORK=off GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -o ../../$(BUNDLED)/text.wasm .

html-engine:
	cd engines/html && GOWORK=off GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -o ../../$(BUNDLED)/html.wasm .

sql-engine:
	cd engines/sql && GOWORK=off GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -o ../../$(BUNDLED)/sql.wasm .

# Build the field-minimizer modules (wasip1) into bundled/minimizers/, kept in
# their own subdir so bundledMinimizers() and bundledEngines() never cross-load.
minimizers: redactor-minimizer

redactor-minimizer:
	cd minimizers/redactor && GOWORK=off GOOS=wasip1 GOARCH=wasm go build -buildvcs=false -o ../../$(BUNDLED)/minimizers/redactor.wasm .
