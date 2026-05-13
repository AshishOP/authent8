VERSION := 3.0.0
BINARY := authent8
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build build-all clean test check

## Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/authent8/

## Build for all platforms
build-all: clean
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64     ./cmd/authent8/
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64     ./cmd/authent8/
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64    ./cmd/authent8/
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64    ./cmd/authent8/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/authent8/
	@echo "Built $(shell ls dist/ | wc -l) binaries in dist/"
	@ls -lh dist/

## Run tests
test:
	go test -v -race ./...

## Vet and security checks
check:
	go vet ./...
	@echo "✓ go vet passed"
	@if command -v gosec > /dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed — skipping (go install github.com/securego/gosec/v2/cmd/gosec@latest)"; \
	fi

## Clean build artifacts
clean:
	rm -rf dist/ $(BINARY)

## Install locally
install: build
	cp $(BINARY) $(GOPATH)/bin/ 2>/dev/null || cp $(BINARY) /usr/local/bin/
	@echo "Installed $(BINARY) v$(VERSION)"

## Show binary size
size: build
	@ls -lh $(BINARY)
	@echo "---"
	@file $(BINARY)
