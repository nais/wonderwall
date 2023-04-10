FROM golang:1.20.3-alpine as builder
RUN apk add --no-cache git make curl
ENV GOOS=linux
ENV CGO_ENABLED=0
COPY . /src
WORKDIR /src
RUN make test
RUN make check
RUN make wonderwall

FROM gcr.io/distroless/static-debian11
WORKDIR /app
COPY --from=builder /src/bin/wonderwall /app/wonderwall
ENTRYPOINT ["/app/wonderwall"]
