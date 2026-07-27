VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test vet fmt lint tidy stand-up stand-down clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ztc ./cmd/ztc

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

tidy:
	go mod tidy

# Bring the docker test stand up / down (see deploy/docker/README.md).
stand-up:
	cd deploy/docker && docker compose up -d --build

stand-down:
	cd deploy/docker && docker compose down -v

clean:
	rm -rf bin
