.PHONY: all build test lint vet fmt clean install run help

BINARY := batesian
PKG := github.com/calbebop/batesian
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

all: lint vet test build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/batesian

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

vet:
	go vet ./...

fmt:
	gofmt -s -w .
	goimports -w .

clean:
	rm -rf bin/ dist/ coverage.out

install:
	go install -ldflags "$(LDFLAGS)" ./cmd/batesian

run: build
	./bin/$(BINARY) $(ARGS)

help:
	@echo "Available targets:"
	@echo "  build    - Build the batesian binary"
	@echo "  test     - Run tests with race detector and coverage"
	@echo "  lint     - Run golangci-lint"
	@echo "  vet      - Run go vet"
	@echo "  fmt      - Format Go code"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - go install batesian to GOPATH/bin"
	@echo "  run      - Build and run (use ARGS=... to pass flags)"
