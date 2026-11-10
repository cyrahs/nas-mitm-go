# Cross-compiled on the build host for each target platform: Go needs no
# emulation, so the arm64 image (rsshub runs on the oracle node) costs only
# a second compile.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags='-s -w' -o /out/nas-mitm .

# Nothing but the binary and CA roots for the upstream side; no shell, so
# probes use `nas-mitm probe`.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/nas-mitm /usr/local/bin/nas-mitm
ENTRYPOINT ["/usr/local/bin/nas-mitm"]
