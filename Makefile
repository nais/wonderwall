wonderwall:
	go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall cmd/wonderwall/main.go

run: fmt
	go run cmd/wonderwall/main.go

test: fmt
	go test -count=1 -shuffle=on ./... -coverprofile cover.out

check:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck ./...
	go run golang.org/x/vuln/cmd/govulncheck -show=traces ./...

fmt:
	go run mvdan.cc/gofumpt -w ./
