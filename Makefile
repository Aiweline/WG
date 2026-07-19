.PHONY: build build-go build-ui test run-core run-ui clean

build: build-ui build-go

build-go:
	mkdir -p bin
	go build -o bin/wg-core ./cmd/wg-core
	go build -o bin/wg-client-ui ./cmd/wg-client-ui
	go build -o bin/wg-proxy ./cmd/wg-proxy

build-ui:
	npm --prefix ui/client run build

test:
	go test ./cmd/... ./internal/... ./tests/...
	go test -race ./cmd/... ./internal/... ./tests/...
	go vet ./cmd/... ./internal/... ./tests/...
	npm --prefix ui/client run lint
	npm --prefix ui/client run test
	npm --prefix ui/client run build
	sh -n scripts/wg-client
	sh -n scripts/wg-server
	sh -n scripts/wg-proxy-client
	sh -n scripts/wg-proxy-server

run-core:
	WG_DEV_SAFE=1 go run ./cmd/wg-core client --dev-safe --no-host-network --management-address 127.0.0.1:47003

run-ui:
	go run ./cmd/wg-client-ui --listen 127.0.0.1:4173 --assets ui/client/dist --core http://127.0.0.1:47003

clean:
	rm -rf bin ui/client/dist
