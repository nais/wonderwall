wonderwall:
	go build -o bin/wonderwall cmd/wonderwall/*.go

test:
	go test -v -count=1 ./...
