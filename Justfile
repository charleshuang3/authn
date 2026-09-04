# List all available recipes
default:
    @just --list

module_dirs := `go list -m -json | grep '"Dir"' | cut -d'"' -f4 | tr '\n' ' '`
module_patterns := `go list -m -json | grep '"Dir"' | cut -d'"' -f4 | sed 's/$/\/.../' | tr '\n' ' '`

# Format code with goimports
fmt: fmt-backend

# Check code formatting with goimports
fmt-check: fmt-check-backend

# Format Go code with goimports
fmt-backend:
    goimports -w -local "github.com/charleshuang3/authn" {{module_dirs}}

# Check Go code format with goimports
fmt-check-backend:
    @test -z "$(goimports -local "github.com/charleshuang3/authn" -l {{module_dirs}})"

# Run go mod tidy on all modules
tidy:
    @for d in {{module_dirs}}; do \
        echo "Tidying $d..."; \
        (cd "$d" && go mod tidy) || exit 1; \
    done

# Update Go dependencies and tidy
update-go-deps:
    @for d in {{module_dirs}}; do \
        echo "Updating dependencies in $d..."; \
        (cd "$d" && go get -u -t ./...) || exit 1; \
    done
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
    golangci-lint run {{module_patterns}}

# Build backend
build:
    mkdir -p build && go build -o build/ {{module_patterns}}

# Test backend
test:
    go test -v {{module_patterns}}

# Build Docker Image
build-image:
    docker build -t ghcr.io/charleshuang3/authn:main -f Dockerfile .
