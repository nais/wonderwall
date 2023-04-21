FROM cgr.dev/chainguard/go:1.20 as builder
ENV GOOS=linux
ENV CGO_ENABLED=0
COPY . /src
WORKDIR /src
RUN make wonderwall

FROM gcr.io/distroless/static-debian11:nonroot
WORKDIR /app
COPY --from=builder /src/bin/wonderwall /app/wonderwall
ENTRYPOINT ["/app/wonderwall"]
