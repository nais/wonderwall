wonderwall:
	go build -o bin/wonderwall cmd/wonderwall/*.go

test:
	go test -v -count=1 ./...

alpine:
	go build -a -installsuffix cgo -o bin/wonderwall cmd/wonderwall/main.go
