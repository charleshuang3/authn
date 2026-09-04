# List all available recipes
default:
    @just --list

# Format code with goimports
fmt: fmt-backend

# Check code formatting with goimports
fmt-check: fmt-check-backend

# Format Go code with goimports
fmt-backend:
    goimports -w -local "github.com/charleshuang3/authn" .

# Check Go code format with goimports
fmt-check-backend:
    @test -z "$(goimports -local "github.com/charleshuang3/authn" -l .)"

# Run go mod tidy
tidy:
    go mod tidy

# Update Go dependencies and tidy
update-go-deps:
    go get -u -t ./...
    @just tidy

# Update pnpm dependencies (noop for backend-only repository)
update-pnpm-deps:
    @echo "No frontend dependencies in this repository"

# Update dependencies
update-deps: update-go-deps

# Run linter
lint: lint-backend

# Run golangci-lint on backend
lint-backend:
    golangci-lint run ./...

# Build backend
build:
    mkdir -p build && go build -o build/ ./...

# Test backend
test:
    go test -v ./...

# Build Docker Image
build-image:
    docker build -t ghcr.io/charleshuang3/authn:main -f Dockerfile .
