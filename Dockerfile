# The build stage runs on the build machine and cross-compiles, so multi-arch
# images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /ssh-secret-broker .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ssh-secret-broker /ssh-secret-broker
EXPOSE 2222 8443
ENTRYPOINT ["/ssh-secret-broker"]
CMD ["-config", "/etc/ssh-secret-broker/config.yaml"]
