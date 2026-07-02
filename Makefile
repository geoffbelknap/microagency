.PHONY: build install test engines jq-engine text-engine html-engine sql-engine

BUNDLED := cmd/microagency/bundled

# build/install bundle the engines into the binary, so `microagency up` works
# with nothing else to install.
build: engines
	go build ./cmd/microagency

install: engines
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
