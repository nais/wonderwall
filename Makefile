wonderwall:
	go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall ./cmd/wonderwall

local: fmt
	go run cmd/wonderwall/main.go \
	  --openid.client-id=bogus \
	  --openid.client-secret=not-so-secret \
	  --openid.well-known-url=http://localhost:8888/default/.well-known/openid-configuration \
	  --ingress=http://localhost:3000 \
	  --bind-address=127.0.0.1:3000 \
	  --upstream-host=localhost:4000 \
	  --redis.uri=redis://localhost:6379 \
	  --log-level=debug \
	  --log-format=text

test: fmt
	go test -count=1 -shuffle=on ./... -coverprofile cover.out

check:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck ./...
	go run golang.org/x/vuln/cmd/govulncheck -show=traces ./...

fmt:
	go run mvdan.cc/gofumpt -w ./
