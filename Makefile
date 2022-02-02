wonderwall:
	go build -o bin/wonderwall cmd/wonderwall/*.go

test:
	go test -count=1 ./... -coverprofile cover.out

alpine:
	go build -a -installsuffix cgo -o bin/wonderwall cmd/wonderwall/main.go
