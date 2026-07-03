.PHONY: build install test engines jq-engine text-engine html-engine sql-engine minimizers redactor-minimizer

BUNDLED := cmd/microagency/bundled

# build/install bundle the engines AND minimizers into the binary, so `microagency
# up` works with nothing else to install.
build: engines minimizers
	go build ./cmd/microagency

install: engines minimizers
	go install ./cmd/microagency

test:
	go test ./...

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
