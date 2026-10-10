# syntax=docker/dockerfile:1
# Cross-compiled on the build platform with cgo off, so multi-arch builds never emulate anything.
FROM --platform=$BUILDPLATFORM golang:1.27.0-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /voice-gateway .

# No shell, no package manager: the gateway faces browsers.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /voice-gateway /voice-gateway
USER 65532:65532
ENTRYPOINT ["/voice-gateway"]
