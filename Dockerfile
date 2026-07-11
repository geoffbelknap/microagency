# microagency as a container image: a self-contained MCP gateway. The wasm
# reduce engines are built (wasip1) and embedded into the binary by `make
# build`, so the runtime image is just a static binary and a writable home.
#
# On a platform without nested virtualization (e.g. running inside a microVM),
# start it with --reduce-engines-only so the microVM reduce path is disabled
# and only the embedded wasm engines serve declarative reduce.

FROM golang:1.26-bookworm AS build
WORKDIR /src
# Module graph first for layer caching.
COPY go.mod go.sum ./
RUN GOWORK=off go mod download
COPY . .
# Compile the wasip1 engines + minimizers into the embed dir, then build the
# binary that embeds them. Static (CGO off) for a distroless runtime;
# GOWORK=off resolves the pinned microagent.
RUN make engines minimizers \
	&& CGO_ENABLED=0 GOWORK=off go build -trimpath -ldflags "-s -w" \
		-o /out/microagency ./cmd/microagency

FROM gcr.io/distroless/static-debian12:nonroot
# distroless nonroot is uid 65532 with a writable /home/nonroot; microagency
# keeps its state (refs, upstream tokens) under $HOME/.microagency, which on
# microplane rides the guest filesystem into the (encrypted) hibernation
# snapshot.
ENV HOME=/home/nonroot
COPY --from=build /out/microagency /usr/local/bin/microagency
EXPOSE 8080
# The microplane agent spec supplies the exact command; this default matches a
# microVM deployment: MCP on the wake-channel port, no microVM reduce, run in
# the foreground as PID 1, no Claude Code auto-registration.
ENTRYPOINT ["/usr/local/bin/microagency"]
CMD ["up", "--http", "0.0.0.0:8080", "--reduce-engines-only", "--foreground", "--no-register"]
