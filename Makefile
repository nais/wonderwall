wonderwall:
	go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall ./cmd/wonderwall

local: fmt
	OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317 go run cmd/wonderwall/main.go \
	  --openid.client-id=bogus \
	  --openid.client-secret=not-so-secret \
	  --openid.well-known-url=http://localhost:8888/default/.well-known/openid-configuration \
	  --ingress=http://localhost:3000 \
	  --bind-address=127.0.0.1:3000 \
	  --upstream-host=localhost:4000 \
	  --redis.uri=redis://localhost:6379 \
	  --log-level=info \
	  --log-format=text

test: fmt
	go test -count=1 -shuffle=on ./... -coverprofile cover.out

check:
	go vet ./...
	go tool staticcheck ./...
	go tool govulncheck -show=traces ./...

fmt:
	go tool gofumpt -w ./
