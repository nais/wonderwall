wonderwall:
	go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall cmd/wonderwall/main.go

test:
	go test -count=1 ./... -coverprofile cover.out

check:
	go run honnef.co/go/tools/cmd/staticcheck ./...
	go run golang.org/x/vuln/cmd/govulncheck -v ./...

fmt:
	go run mvdan.cc/gofumpt -w ./
