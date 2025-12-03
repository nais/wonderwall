FROM --platform=$BUILDPLATFORM golang:1.25 AS builder
ENV CGO_ENABLED=0
ENV GOTOOLCHAIN=auto
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall ./cmd/wonderwall

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=builder /src/bin/wonderwall /app/wonderwall
ENTRYPOINT ["/app/wonderwall"]
