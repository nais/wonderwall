FROM --platform=$BUILDPLATFORM golang:1.21-alpine as builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall cmd/wonderwall/main.go

FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /app
COPY --from=builder /src/bin/wonderwall /app/wonderwall
ENTRYPOINT ["/app/wonderwall"]
