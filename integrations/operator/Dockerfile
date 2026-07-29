# Build the operator binary. The build context must be the integrations/
# directory, because the operator module depends on ../client via a replace
# directive:
#
#   docker build -f operator/Dockerfile -t himitsu-operator .
FROM golang:1.26 AS builder
WORKDIR /workspace

# Copy both modules' manifests first so dependency download caches independently
# of source changes.
COPY client/go.mod client/go.sum* client/
COPY operator/go.mod operator/go.sum operator/
RUN cd operator && go mod download

COPY client/ client/
COPY operator/ operator/

# CGO is disabled so the result runs on distroless static.
RUN cd operator && CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /workspace/manager .

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
