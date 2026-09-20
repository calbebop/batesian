.PHONY: all build test lint vet fmt clean install run docker-check help

BINARY := batesian
PKG := github.com/calbebop/batesian
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Keep container versions aligned with ci.yml and go.mod.
GO_IMAGE := golang:1.25.13
LINT_IMAGE := golangci/golangci-lint:v2.11.4

# Reuse module and build caches across container runs.
GO_CACHE_VOLS := -v batesian-gomod:/go/pkg/mod -v batesian-gocache:/root/.cache/go-build

# Mount the repo read-write so container outputs persist on the host.
MOUNT := -v "$(CURDIR):/app" -w /app

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

# Run build, vet, race tests, and lint without requiring a local Go toolchain.
docker-check: docker-build-vet docker-test docker-lint

docker-build-vet:
	docker run --rm $(MOUNT) $(GO_CACHE_VOLS) $(GO_IMAGE) \
		sh -c "go build ./... && go vet ./..."

docker-test:
	docker run --rm $(MOUNT) $(GO_CACHE_VOLS) $(GO_IMAGE) \
		go test -race -coverprofile=coverage.out ./...

docker-lint:
	docker run --rm $(MOUNT) $(LINT_IMAGE) golangci-lint run

help:
	@echo "Available targets:"
	@echo "  build         - Build the batesian binary"
	@echo "  test          - Run tests with race detector and coverage"
	@echo "  lint          - Run golangci-lint"
	@echo "  vet           - Run go vet"
	@echo "  fmt           - Format Go code"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - go install batesian to GOPATH/bin"
	@echo "  run           - Build and run (use ARGS=... to pass flags)"
	@echo "  docker-check  - build+vet+test+lint in the pinned containers (no local Go needed)"
