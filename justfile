#
# just configuration.
#
# https://just.systems/man/en
#

# List recipes.
help:
	just --list

# Remove build artifacts.
clean:
	# Remove build artifacts.
	rm -rf build

# Create mocks.
mock:
	# Remove build artifacts.
	find -path "./internal/interfaces/**/*_mock.go" -type f -delete
	# Create mocks.
	mockery

# Run static analysis (formatters, linters).
analyze:
	# Format Go files.
	go mod tidy
	go fmt ./...
	# Lint Go files.
	golangci-lint run --fix

# Run tests.
test:
	# Remove build artifacts.
	rm -rf build/go/coverage
	# Run unit tests.
	mkdir --parents build/go/coverage
	go test -vet off -coverprofile build/go/coverage/coverage.out ./internal/implementations/...
	# Create coverage reports.
	go tool cover -html build/go/coverage/coverage.out -o build/go/coverage/coverage.html

# Build binaries.
build:
	# Remove build artifacts.
	rm -rf build/go/aarch64-linux build/go/aarch64-darwin build/go/aarch64-windows build/go/x86-64-linux build/go/x86-64-darwin build/go/x86-64-windows
	# Build AArch64 Linux binaries.
	GOARCH=arm64 GOOS=linux go build -o build/go/aarch64-linux/bin/ ./cmd/...
	# Build AArch64 macOS binaries.
	GOARCH=arm64 GOOS=darwin go build -o build/go/aarch64-darwin/bin/ ./cmd/...
	# Build AArch64 Windows binaries.
	GOARCH=arm64 GOOS=windows go build -o build/go/aarch64-windows/bin/ ./cmd/...
	# Build x86-64 Linux binaries.
	GOARCH=amd64 GOOS=linux go build -o build/go/x86-64-linux/bin/ ./cmd/...
	# Build x86-64 macOS binaries.
	GOARCH=amd64 GOOS=darwin go build -o build/go/x86-64-darwin/bin/ ./cmd/...
	# Build x86-64 Windows binaries.
	GOARCH=amd64 GOOS=windows go build -o build/go/x86-64-windows/bin/ ./cmd/...

# Release build.
release: clean mock analyze test build
