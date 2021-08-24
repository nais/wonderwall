wonderwall:
	go build -o bin/wonderwall cmd/wonderwall/*.go

test:
	go test -v -count=1 ./...

test_redis_integration:
	go test -v -count=1 -tags=integration ./pkg/session/

alpine:
	go build -a -installsuffix cgo -o bin/wonderwall cmd/wonderwall/main.go
